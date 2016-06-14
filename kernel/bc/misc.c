/*
 *  kernel/bc/misc.c
 *
 *  Copyright (c) 2005-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/module.h>

#include <bc/beancounter.h>
#include <bc/proc.h>

/*
 * Task staff
 */

void ub_task_get(struct user_beancounter *ub, struct task_struct *task)
{
	struct task_beancounter *new_bc = &task->task_bc;

	new_bc->task_ub = get_beancounter(ub);
	new_bc->exec_ub = get_beancounter(ub);
}

void ub_task_put(struct task_struct *task)
{
	struct task_beancounter *task_bc;

	task_bc = &task->task_bc;

	put_beancounter(task_bc->exec_ub);
	put_beancounter(task_bc->task_ub);

	task_bc->exec_ub = (struct user_beancounter *)0xdeadbcbc;
	task_bc->task_ub = (struct user_beancounter *)0xdead100c;
}

int ub_file_charge(struct file *f)
{
	struct user_beancounter *ub = get_exec_ub();
	int err;

	err = charge_beancounter_fast(ub, UB_NUMFILE, 1, UB_HARD);
	if (unlikely(err))
		goto no_file;

	f->f_ub = get_beancounter(ub);

	return 0;

no_file:
	return err;
}

void ub_file_uncharge(struct file *f)
{
	struct user_beancounter *ub = f->f_ub;

	uncharge_beancounter_fast(ub, UB_NUMFILE, 1);
	put_beancounter(ub);
}

int ub_flock_charge(struct file_lock *fl, int hard)
{
	struct user_beancounter *ub;
	int err;

	ub = fl->fl_ub;
	if (ub == NULL)
		return 0;

	err = charge_beancounter(ub, UB_NUMFLOCK, 1, hard ? UB_HARD : UB_SOFT);
	if (!err)
		fl->fl_charged = 1;
	return err;
}

void ub_flock_uncharge(struct file_lock *fl)
{
	struct user_beancounter *ub;

	ub = fl->fl_ub;
	if (ub == NULL || !fl->fl_charged)
		return;

	uncharge_beancounter(ub, UB_NUMFLOCK, 1);
	fl->fl_charged = 0;
}

/*
 * Signal handling
 */

int ub_siginfo_charge(struct sigqueue *sq, struct user_beancounter *ub,
			gfp_t gfp_mask)
{
	if (charge_beancounter_fast(ub, UB_NUMSIGINFO, 1, UB_HARD))
		goto out_num;

	sq->sig_ub = get_beancounter(ub);
	return 0;

out_num:
	return -ENOMEM;
}
EXPORT_SYMBOL(ub_siginfo_charge);

void ub_siginfo_uncharge(struct sigqueue *sq)
{
	struct user_beancounter *ub;

	ub = sq->sig_ub;
	sq->sig_ub = NULL;
	uncharge_beancounter_fast(ub, UB_NUMSIGINFO, 1);
	put_beancounter(ub);
}

/*
 * PTYs
 */

int ub_pty_charge(struct tty_struct *tty)
{
	struct user_beancounter *ub = get_exec_ub();
	int retval;

	retval = 0;
	if (ub && tty->driver->subtype == PTY_TYPE_MASTER &&
			!test_bit(TTY_CHARGED, &tty->flags)) {
		retval = charge_beancounter(ub, UB_NUMPTY, 1, UB_HARD);
		if (!retval) {
			set_bit(TTY_CHARGED, &tty->flags);
			tty->ub = get_beancounter(ub);
		}
	}
	return retval;
}

void ub_pty_uncharge(struct tty_struct *tty)
{
	struct user_beancounter *ub;

	ub = tty->ub;
	if (ub && tty->driver->subtype == PTY_TYPE_MASTER &&
			test_bit(TTY_CHARGED, &tty->flags)) {
		uncharge_beancounter(ub, UB_NUMPTY, 1);
		clear_bit(TTY_CHARGED, &tty->flags);
		put_beancounter(ub);
	}
}
