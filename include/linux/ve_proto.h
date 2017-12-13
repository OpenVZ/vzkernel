/*
 *  include/linux/ve_proto.h
 *
 *  Copyright (c) 2005-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef __VE_H__
#define __VE_H__

struct ve_struct;
struct task_struct;

#ifdef CONFIG_VE

extern struct ve_struct ve0;

static inline struct ve_struct *get_ve0(void)
{
	return &ve0;
}

static inline bool ve_is_super(struct ve_struct *ve)
{
	return ve == &ve0;
}

#define get_exec_env()		(current->task_ve)

const char *ve_name(struct ve_struct *ve);

/* must be called under rcu_read_lock if task != current */
const char *task_ve_name(struct task_struct *task);

extern struct list_head ve_list_head;
#define for_each_ve(ve)			\
	list_for_each_entry((ve), &ve_list_head, ve_list)
#define for_each_ve_continue(ve)	\
	list_for_each_entry_continue((ve), &ve_list_head, ve_list)
extern struct mutex ve_list_lock;
extern struct ve_struct *get_ve_by_id(envid_t);

enum {
	VE_SS_CHAIN,

	VE_MAX_CHAINS
};

typedef int ve_hook_init_fn(void *data);
typedef void ve_hook_fini_fn(void *data);

struct ve_hook
{
	ve_hook_init_fn *init;
	ve_hook_fini_fn *fini;
	struct module *owner;

	/* Functions are called in ascending priority */
	int priority;

	/* Private part */
	struct list_head list;
};

enum {
	HOOK_PRIO_DEFAULT = 0,

	HOOK_PRIO_AFTERALL = 127,
	HOOK_PRIO_FINISHING = 128,
};

extern int ve_hook_iterate_init(int chain, void *data);
extern void ve_hook_iterate_fini(int chain, void *data);

extern void ve_hook_register(int chain, struct ve_hook *vh);
extern void ve_hook_unregister(struct ve_hook *vh);
extern int nr_threads_ve(struct ve_struct *ve);
#else /* CONFIG_VE */
#include <linux/sched/stat.h>
#define ve_hook_register(ch, vh)	do { } while (0)
#define ve_hook_unregister(ve)		do { } while (0)

static inline struct ve_struct *get_ve0(void)
{
	return NULL;
}

static inline struct ve_struct *get_exec_env(void)
{
	return NULL;
}

static inline bool ve_is_super(struct ve_struct *ve)
{
	return true;
}

static inline const char *ve_name(struct ve_struct *ve)
{
	return "0";
}

static inline const char *task_ve_name(struct task_struct *task)
{
	return "0";
}

static inline int nr_threads_ve(struct ve_struct *ve)
{
	return nr_threads;
}
#endif /* CONFIG_VE */
#endif
