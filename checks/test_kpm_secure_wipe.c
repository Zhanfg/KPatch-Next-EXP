/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Host-only regression test for the portable volatile erasure primitive. */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../kernel/include/kpsecure.h"

int main(void)
{
    unsigned char secret[64];
    memset(secret, 0xa5, sizeof(secret));
    kp_exp_secure_wipe(secret, sizeof(secret));
    for (unsigned i = 0; i < sizeof(secret); ++i)
        assert(secret[i] == 0);

    /* Null input must not dereference a pointer even for nonzero size. */
    kp_exp_secure_wipe(NULL, 16);
    puts("PASS: transient KPM buffer wipe");
    return 0;
}
