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

#ifdef CONFIG_VE
extern struct ve_struct ve0;
#define get_ve0()	(&ve0)

#define get_exec_env()	(current->task_ve)
#define get_env_init(ve)	(ve->ve_ns->pid_ns->child_reaper)
#define task_veid(t)		((t)->task_ve->veid)
#else
#define get_ve0()		(NULL)
#define get_exec_env()		(NULL)
#define get_env_init(ve)	(&init_task)
#define task_veid(t)		(0)
#endif

#endif /* __VE_TASK_H__ */
