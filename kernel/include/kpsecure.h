/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPatch Next EXP: scoped memory erasure for transient KPM control data.
 *
 * Volatile stores ensure that the compiler does not discard the wipe.
 * This is not a substitute for protecting the transport, persistent buffers,
 * or any copies retained by a KPM.
 */
#ifndef _KP_EXP_SECURE_H_
#define _KP_EXP_SECURE_H_

static inline void kp_exp_secure_wipe(void *memory, unsigned long length)
{
    volatile unsigned char *ptr = (volatile unsigned char *)memory;
    if (!ptr) return;
    while (length--) *ptr++ = 0;
}

#endif /* _KP_EXP_SECURE_H_ */
