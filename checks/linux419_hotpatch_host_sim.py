#!/usr/bin/env python3
"""Exercise real EXP hotpatch C function bodies with mock Linux 4.19 kernel primitives.

Important: a host simulation is NOT an ARM64 hardware boot, MMU/TLB proof,
kernel security audit, or a guarantee that a particular kernel will boot.
"""
from pathlib import Path
import re
import subprocess
import tempfile

src = Path("kernel/base/hotpatch.c").read_text()

def extract(name):
    pattern = r"(?m)^(?:static\s+)?(?:inline\s+)?(?:bool|void|int)\s+" + name + r"\s*\([^;]*?\)\s*\{"
    m = re.search(pattern, src)
    if not m:
        raise AssertionError(f"Production function not found: {name}")
    start = m.start()
    depth = 0
    for j in range(src.index("{", m.start()), len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[start:j+1]
    raise AssertionError("Unbalanced function " + name)

fn = [extract(x) for x in (
    "hotpatch_use_legacy", "modify_entry_kernel", "hotpatch_nosync",
    "hotpatch_cb", "hotpatch", "hotpatch_init",
)]
assert "return kver < VERSION(4, 15, 0);" in fn[0], "Kernel 4.19 routing changed"
assert "stop_machine(hotpatch_cb, &patch, cpu_online_mask)" in fn[4]
assert "if (kver < VERSION(4, 6, 0))" in fn[5]
# Only architecture-specific ARM64 YIELD instruction is replaced on x86.
fn = [x.replace('asm volatile("yield" ::: "memory");', 'sched_yield();') for x in fn]

prelude = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>
#include <pthread.h>
#include <string.h>
#include <sched.h>
#include <errno.h>

#define VERSION(a,b,c) (((a)<<16) + ((b)<<8) + (c))
#define KP_EXPORT_SYMBOL(x)
#define CONT_PTES 16
#define CONT_PTE_MASK (~(uintptr_t)65535)
#define PTE_DBM ((uintptr_t)0x40)
#define PTE_RDONLY ((uintptr_t)0x80)
#define dsb(x) ((void)0)
#define isb() ((void)0)
#define ish 0
#define log_boot(...) ((void)0)
#define ATOMIC_INIT(x) ATOMIC_VAR_INIT(x)
#define atomic_inc_return(p) (atomic_fetch_add((p),1)+1)
#define atomic_dec_return(p) (atomic_fetch_sub((p),1)-1)
#define atomic_inc(p) ((void)atomic_fetch_add((p),1))
#define atomic_read(p) atomic_load((p))
#define kfunc(name) p_##name
#define kvar(name) mock_##name
#define stop_machine(...) p_stop_machine(__VA_ARGS__)

typedef _Atomic int atomic_t;
typedef uint32_t u32;
static uint32_t kver;
static uintptr_t table_pa_mask = 0xfffffffff000ULL;
static void *alias_page;
static uintptr_t *alias_entry;
static uintptr_t alias_pte;
static size_t page_size = 4096;
static uintptr_t mock_pte = 0x101;
static int fail_phys, fail_map, fail_nosync, interrupts;
static int call_stop, call_nosync, flush_icache_count;
static unsigned online_cpus=2;
static int mock_nr_cpu_ids=8;
static void *cpu_online_mask=(void*)1;
static uint32_t *patched_address;
static int pte_valid_cont(uintptr_t x){(void)x;return 0;}
static void flush_tlb_kernel_page(uintptr_t x){(void)x;}
static void flush_tlb_kernel_range(uintptr_t x,uintptr_t y){(void)x;(void)y;}
static void flush_icache_all(void){++flush_icache_count;}
static uintptr_t *pgtable_entry_kernel(uintptr_t x){(void)x;return fail_map?NULL:&mock_pte;}
static uintptr_t pgtable_phys_kernel(uintptr_t x){return !x||fail_phys?0:0x2000;}
static void *vmalloc(size_t n){return calloc(1,n);}
static unsigned num_online_cpus(void){return online_cpus;}
static inline int is_interrupt_masked(void){return interrupts;}
static int nosync(void *addr,uint32_t insn){
    ++call_nosync;
    if (fail_nosync) return -EIO;
    if (!alias_page || (uintptr_t)addr < (uintptr_t)alias_page ||
       (uintptr_t)addr >= (uintptr_t)alias_page+page_size || !patched_address) abort();
    /* Model alias remapping; there is no actual guest MMU in this harness. */
    *patched_address=insn;
    return 0;
}
static int (*p_aarch64_insn_patch_text_nosync)(void *,uint32_t)=nosync;
static int kernel_patch_text(void *addrs[],uint32_t insns[],int n){
    for(int i=0;i<n;++i) *(uint32_t*)addrs[i]=insns[i];
    return 0;
}
static int (*p_aarch64_insn_patch_text)(void*[],uint32_t[],int)=kernel_patch_text;
struct thread_work{int(*f)(void*);void *ctx;int result;};
static void *cpu_worker(void *v){struct thread_work *a=v;a->result=a->f(a->ctx);return NULL;}
static int mock_stop_machine(int(*f)(void*),void *ctx,void *mask){
    (void)mask;++call_stop;
    if(online_cpus!=2)abort();
    pthread_t a,b;
    struct thread_work x={f,ctx,-100}, y={f,ctx,-100};
    if(pthread_create(&a,0,cpu_worker,&x))abort();
    if(pthread_create(&b,0,cpu_worker,&y))abort();
    pthread_join(a,NULL);pthread_join(b,NULL);
    return x.result?x.result:y.result;
}
static int (*p_stop_machine)(int(*)(void*),void*,void*)=mock_stop_machine;
struct hotpatch_t{void **addrs;u32 *values;int cnt;atomic_t index;};
"""
tests = r"""
static void check(int ok,const char *label){
    if(!ok){fprintf(stderr,"FAIL %s\n",label);exit(2);}
}
static void reset(void){
    kver=VERSION(4,19,325);mock_pte=0x101;
    fail_phys=fail_map=fail_nosync=interrupts=0;
    call_stop=call_nosync=flush_icache_count=0;
    online_cpus=2;mock_nr_cpu_ids=8;cpu_online_mask=(void*)1;
    p_aarch64_insn_patch_text_nosync=nosync;
    p_stop_machine=mock_stop_machine;
    patched_address=0;
    alias_page=0;alias_entry=0;alias_pte=0;
}
int main(void) {
    reset();
    kver=VERSION(4,14,0); check(hotpatch_use_legacy(),"4.14 old selection");
    kver=VERSION(4,19,325);check(!hotpatch_use_legacy(),"4.19 modern selection");
    check(hotpatch_init()==0 && alias_page && alias_entry,"4.19 alias initialization");
    for(int i=0;i<40;i++){
        uint32_t op=0,v=0xd503201f+(uint32_t)i;
        void *addrs[]={&op};uint32_t vals[]={v}; patched_address=&op;
        check(hotpatch(addrs,vals,1)==0,"multi CPU hotpatch");
        check(op==v,"alias code modified");
        check(alias_entry && *alias_entry==alias_pte,"alias page entry restored");
    }
    check(call_stop==40 && call_nosync==40,"40 x two-CPU stop_machine/nosync calls");
    puts("PASS 4.19.325 SMP stop_machine alias success: 40 iterations");
    reset();hotpatch_init();
    uint32_t op=0;void *addrs[]={&op};uint32_t vals[]={0xd503201f};patched_address=&op;
    fail_nosync=1;
    check(hotpatch(addrs,vals,1)==0 && op==vals[0],"nosync failure fallback");
    check(flush_icache_count==1 && mock_pte==0x101 && *alias_entry==alias_pte,
          "fallback restores PTE + flushes icache");
    puts("PASS nosync failure: direct-write fallback/PTE restore");
    reset();hotpatch_init();op=0;patched_address=&op;
    p_stop_machine=NULL;
    check(hotpatch(addrs,vals,1)==0 && op==vals[0] && call_stop==0,
          "no stop_machine fallback");
    p_stop_machine=mock_stop_machine;interrupts=1;op=0;
    check(hotpatch(addrs,vals,1)==0 && op==vals[0] && call_stop==0,
          "IRQ masked fallback");
    puts("PASS stop_machine unavailable/interrupt-masked fallbacks");
    reset();hotpatch_init();op=0;patched_address=&op;
    check(hotpatch(addrs,vals,0)==-EINVAL,"zero instruction count");
    check(hotpatch_nosync((char*)&op+1,1)==-EINVAL,"unaligned instruction address");
    fail_phys=1;
    check(hotpatch_nosync(&op,1)==-EFAULT,"unresolvable physical page");
    check(op==0 && mock_pte==0x101,"invalid inputs preserve state");
    puts("PASS invalid count / address alignment / unmapped physical page");
    puts("RESULT: host-model tests passed; real kernel boot/stability UNVERIFIED");
    return 0;
}
"""
code = prelude + "\n".join(fn) + "\n" + tests
with tempfile.TemporaryDirectory() as tmp:
    p = Path(tmp)
    (p/"sim.c").write_text(code)
    subprocess.run(["cc", "-std=gnu11", "-O2", "-Wall", "-pthread",
                    "-o", str(p/"sim"), str(p/"sim.c")],check=True)
    subprocess.run([str(p/"sim")],check=True,timeout=25)
