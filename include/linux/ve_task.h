/*
 *  include/linux/ve_task.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __VE_TASK_H__
#define __VE_TASK_H__

#include <linux/seqlock.h>
#include <asm/timex.h>

struct ve_task_info {
/* virtualization */
	struct ve_struct *owner_env;
	struct ve_struct *exec_env;
/* statistics: scheduling latency */
	u64 sleep_time;
	u64 sched_time;
	u64 sleep_stamp;
	u64 wakeup_stamp;
	seqcount_t wakeup_lock;
};

#define VE_TASK_INFO(task)	(&(task)->ve_task_info)

#ifdef CONFIG_VE
extern struct ve_struct ve0;
#define get_ve0()	(&ve0)

#define get_exec_env()	(current->ve_task_info.exec_env)
#define set_exec_env(ve)	({		\
		struct ve_struct *__old;	\
		__old = current->ve_task_info.exec_env;	\
		current->ve_task_info.exec_env = ve;	\
		__old;				\
	})
#define get_env_init(ve)	(ve->ve_ns->pid_ns->child_reaper)
#define task_veid(t)		((t)->ve_task_info.owner_env->veid)
#else
#define get_ve0()		(NULL)
#define get_exec_env()		(NULL)
#define set_exec_env(new_env)	(NULL)
#define get_env_init(ve)	(&init_task)
#define task_veid(t)		(0)
#endif

#endif /* __VE_TASK_H__ */
