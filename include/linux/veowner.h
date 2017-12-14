/*
 *  include/linux/veowner.h
 *
 *  Copyright (c) 2000-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef _LINUX_VEOWNER_H
#define _LINUX_VEOWNER_H

struct proc_dir_entry;

#ifdef CONFIG_VE
extern struct proc_dir_entry *proc_vz_dir;

extern void __init init_ve_system(void);
#else
static inline void init_ve_system(void) { }
#endif

#endif /* _LINUX_VEOWNER_H */
