/*
 *  kernel/ve/bc/proc.c
 *
 *  Copyright (c) 2000-2018 Virtuozzo International GmbH.
 *  All rights reserved.
 *
 */

#include <linux/proc_fs.h>
#include <linux/ve.h>

#include "proc.h"

static const char *ve_get_name(struct ve_struct *ve)
{
	static const char *ve0_name = "0";

	if (ve_is_super(ve))
		return ve0_name;
	return ve->ve_name;
}

void ub_remove_proc(struct ve_struct *ve)
{
	ub_proc_ve_resources_remove(ve);
	remove_proc_entry(ve_get_name(ve), bc_proc_root);
	ve->ub_proc = NULL;
}

int ub_create_proc(struct ve_struct *ve)
{
	int err;

	ve->ub_proc = proc_mkdir(ve_get_name(ve), bc_proc_root);
	if (!ve->ub_proc)
		return -ENOMEM;

	err = ub_proc_ve_resources_create(ve);
	if (err)
		goto remove_ub_proc;

	return 0;

remove_ub_proc:
	remove_proc_entry(ve_get_name(ve), bc_proc_root);
	return err;
}

static int __init ub_init_proc(void)
{
	int err;

	err = ub_proc_all_resources_create();
	if (err)
		return err;

	return ub_create_proc(get_ve0());
}
core_initcall(ub_init_proc);
