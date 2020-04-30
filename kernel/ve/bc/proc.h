/*
 *  kernel/ve/bc/proc.h
 *
 *  Copyright (c) 2000-2018 Virtuozzo International GmbH.
 *  All rights reserved.
 *
 */

#ifndef _KERNEL_VE_BC_PROC_H
#define _KERNEL_VE_BC_PROC_H

struct proc_dir_entry;
struct ve_struct;

extern struct proc_dir_entry *bc_proc_root;

void ub_remove_proc(struct ve_struct *ve);
int ub_create_proc(struct ve_struct *ve);

#endif
