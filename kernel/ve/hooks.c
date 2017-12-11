/*
 *  linux/kernel/ve/hooks.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/sched.h>
#include <linux/ve.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/ve_proto.h>
#include <linux/module.h>

static struct list_head ve_hooks[VE_MAX_CHAINS];
static DECLARE_RWSEM(ve_hook_sem);

void ve_hook_register(int chain, struct ve_hook *vh)
{
	struct list_head *lh;
	struct ve_hook *tmp;

	BUG_ON(chain > VE_MAX_CHAINS);

	down_write(&ve_hook_sem);
	list_for_each(lh, &ve_hooks[chain]) {
		tmp = list_entry(lh, struct ve_hook, list);
		if (vh->priority < tmp->priority)
			break;
	}

	list_add_tail(&vh->list, lh);
	up_write(&ve_hook_sem);
}

EXPORT_SYMBOL(ve_hook_register);

void ve_hook_unregister(struct ve_hook *vh)
{
	down_write(&ve_hook_sem);
	list_del(&vh->list);
	up_write(&ve_hook_sem);
}

EXPORT_SYMBOL(ve_hook_unregister);

static inline int ve_hook_init(struct ve_hook *vh, struct ve_struct *ve)
{
	int err;

	err = 0;
	if (vh->init != NULL && try_module_get(vh->owner)) {
		err = vh->init(ve);
		module_put(vh->owner);
	}
	return err;
}

static inline void ve_hook_fini(struct ve_hook *vh, struct ve_struct *ve)
{
	if (vh->fini != NULL && try_module_get(vh->owner)) {
		vh->fini(ve);
		module_put(vh->owner);
	}
}

int ve_hook_iterate_init(int chain, void *ve)
{
	struct ve_hook *vh;
	int err;

	err = 0;

	down_read(&ve_hook_sem);
	list_for_each_entry(vh, &ve_hooks[chain], list)
		if ((err = ve_hook_init(vh, ve)) < 0)
			break;

	if (err)
		list_for_each_entry_continue_reverse(vh, &ve_hooks[chain], list)
			ve_hook_fini(vh, ve);

	up_read(&ve_hook_sem);
	return err;
}

EXPORT_SYMBOL(ve_hook_iterate_init);

void ve_hook_iterate_fini(int chain, void *ve)
{
	struct ve_hook *vh;

	down_read(&ve_hook_sem);
	list_for_each_entry_reverse(vh, &ve_hooks[chain], list)
		ve_hook_fini(vh, ve);
	up_read(&ve_hook_sem);
}

EXPORT_SYMBOL(ve_hook_iterate_fini);

static int __init ve_hooks_init(void)
{
	int i;

	for (i = 0; i < VE_MAX_CHAINS; i++)
		INIT_LIST_HEAD(&ve_hooks[i]);
	return 0;
}

core_initcall(ve_hooks_init);

