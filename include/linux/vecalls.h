/*
 * Copyright (c) 2000-2017 Virtuozzo International GmbH.  All rights reserved.
 */

#ifndef _LINUX_VE_CALLS_H
#define _LINUX_VE_CALLS_H

#include <uapi/linux/vzcalluser.h>

struct seq_file;

typedef void (*ve_seq_print_t)(struct seq_file *, struct ve_struct *);

extern void vzmon_register_veaddr_print_cb(ve_seq_print_t);
extern void vzmon_unregister_veaddr_print_cb(ve_seq_print_t);

#endif /*_LINUX_VE_CALLS_H */
