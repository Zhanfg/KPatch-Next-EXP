#!/usr/bin/env python3
"""Source-level guards for the log/secret regression in KP Next EXP.

These checks deliberately do not change the KPM info/query ABI. True
runtime behavior still needs an Android kernel+KPM integration test.
"""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
mod = (root / "kernel/patch/module/module.c").read_text()
sc = (root / "kernel/patch/common/supercall.c").read_text()
ext = (root / "kernel/patch/common/kpextension.c").read_text()
hdr = (root / "kernel/include/kpsecure.h").read_text()

def check(predicate, message):
    if not predicate:
        raise AssertionError(message)

# Historical leak patterns that must not return.
for pattern in [
    r'logk\w*\("\[%s\] succeed with \[%s\]',
    r'logk\w*\("\[%s\] failed with \[%s\]',
    r'logk\w*\("name %s, args: %s',
    r'logk\w*\("name %s, a1:',
    r'logk\w*\("%s", out_info\)',
]:
    check(re.search(pattern, mod) is None, f"Sensitive kernel log reintroduced: {pattern}")

check('kp_exp_secure_wipe(mod->args,' in mod, "Must erase owned load args before free")
check(mod.count('kp_exp_secure_wipe(mod->ctl_args,') >= 2,
      "Must erase ctl0 args on replacement and unload")
check('rc = (*mod->ctl0)(mod->ctl_args, out_msg, outlen);' in mod,
      "KPM ctl0 call path must remain intact")
check('rc = (*mod->init)(mod->args, event, reserved);' in mod,
      "KPM load argument ABI must remain intact")
check('"args=%s\\n"' in mod, "Keep KPM info format for existing WebUI")
check('"load_event=%s\\n"' in mod, "Keep KPM embedded event info")
check('return uid == 0;' in ext and 'KP_EXPORT_SYMBOL(is_su_allow_uid)' in ext,
      "Preserve root-only Nohello ABI export")
check('volatile unsigned char *ptr' in hdr, "Wipe must use volatile stores")
for func in ('call_user_event', 'call_kpm_load', 'call_kpm_control', 'call_kpm_info'):
    start = sc.index('static long ' + func + '(')
    next_func = sc.find('\nstatic long ', start + 12)
    body = sc[start:next_func if next_func >= 0 else len(sc)]
    check('kp_exp_secure_wipe(' in body, f"Missing cleanup for {func}")
    check('goto out;' in body and '\nout:' in body,
          f"Missing common cleanup for {func}")
check('if (current_uid() != 0u)' in sc,
      "Do not change existing UID0-only Supercall boundary")
print('PASS: KPM log redaction, lifetime erasure and legacy Nohello ABI checks')
