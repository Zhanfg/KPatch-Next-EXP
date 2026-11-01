/* SPDX-License-Identifier: GPL-2.0-or-later */
/* 
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include <symbol.h>
#include <kstorage.h>
#include <log.h>
#include <uapi/asm-generic/errno.h>

static int exclude_kstorage_gid = -1;

/*
 * Legacy KPatch-Next KPM ABI: older modules refer to is_su_allow_uid().
 * EXP has no per-UID SU allowlist; its supercall is restricted to UID 0.
 * Mirror that policy for the legacy read-only query, without adding any
 * privilege-granting path or reviving the obsolete allowlist.
 * Keep this aligned with supercall_before() in common/supercall.c.
 */
int is_su_allow_uid(uid_t uid)
{
    return uid == 0;
}
KP_EXPORT_SYMBOL(is_su_allow_uid);

int set_ap_mod_exclude(uid_t uid, int exclude)
{
    int rc = 0;
    if (exclude) {
        rc = write_kstorage(exclude_kstorage_gid, uid, &exclude, 0, sizeof(exclude), false);
    } else {
        rc = remove_kstorage(exclude_kstorage_gid, uid);
    }
    return rc;
}
KP_EXPORT_SYMBOL(set_ap_mod_exclude);

int get_ap_mod_exclude(uid_t uid)
{
    int exclude = 0;
    int rc = read_kstorage(exclude_kstorage_gid, uid, &exclude, 0, sizeof(exclude), false);
    if (rc < 0) return 0;
    return exclude;
}
KP_EXPORT_SYMBOL(get_ap_mod_exclude);

int kpextension_init()
{
    exclude_kstorage_gid = try_alloc_kstroage_group();
    if (exclude_kstorage_gid != KSTORAGE_EXCLUDE_LIST_GROUP) return -ENOMEM;

    return 0;
}