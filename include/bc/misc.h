/*
 *  include/bc/misc.h
 *
 *  Copyright (c) 2005-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef __BC_MISC_H_
#define __BC_MISC_H_

#include <bc/decl.h>

struct tty_struct;
struct file;
struct file_lock;
struct sigqueue;

UB_DECLARE_FUNC(int, ub_file_charge(struct file *f))
UB_DECLARE_VOID_FUNC(ub_file_uncharge(struct file *f))
UB_DECLARE_FUNC(int, ub_flock_charge(struct file_lock *fl, int hard))
UB_DECLARE_VOID_FUNC(ub_flock_uncharge(struct file_lock *fl))
UB_DECLARE_FUNC(int, ub_siginfo_charge(struct sigqueue *q,
			struct user_beancounter *ub, gfp_t gfp_mask))
UB_DECLARE_VOID_FUNC(ub_siginfo_uncharge(struct sigqueue *q))
UB_DECLARE_VOID_FUNC(ub_task_get(struct user_beancounter *ub,
			struct task_struct *task))
UB_DECLARE_VOID_FUNC(ub_task_put(struct task_struct *task))
UB_DECLARE_FUNC(int, ub_pty_charge(struct tty_struct *tty))
UB_DECLARE_VOID_FUNC(ub_pty_uncharge(struct tty_struct *tty))

#ifdef CONFIG_BEANCOUNTERS
#define set_flock_charged(fl)	do { (fl)->fl_charged = 1; } while (0)
#define unset_flock_charged(fl)	do {		\
		WARN_ON((fl)->fl_charged == 0);	\
		(fl)->fl_charged = 0;		\
	} while (0)
#else
#define set_flock_charged(fl)	do { } while (0)
#define unset_flock_charged(fl)	do { } while (0)
#endif
#endif
