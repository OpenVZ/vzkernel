/*
 *  kernel/ve/vziolimit.c
 *
 *  Copyright (C) 2010, Parallels inc.
 *  All rights reserved.
 *
 */

#include <linux/module.h>
#include <linux/sched.h>
#include <linux/virtinfo.h>
#include <linux/vzctl.h>
#include <linux/vziolimit.h>
#include <asm/uaccess.h>
#include <bc/beancounter.h>

struct throttle {
       unsigned speed;		/* maximum speed, units per second */
       unsigned burst;		/* maximum bust, units */
       unsigned latency;	/* maximum wait delay, jiffies */
       unsigned state;		/* current state */
       unsigned long time;	/* wall time in jiffies */
};

/**
 * set throttler initial state, externally serialized
 * @speed	maximum speed (1/sec)
 * @burst	maximum burst chunk
 * @latency	maximum timeout (ms)
 */
static void throttle_setup(struct throttle *th, unsigned speed,
		unsigned burst, unsigned latency)
{
	th->time = jiffies;
	th->burst = burst;
	th->latency = msecs_to_jiffies(latency);
	th->state = 0;
	wmb();
	th->speed = speed;
}

/* externally serialized */
static void throttle_charge(struct throttle *th, unsigned charge)
{
	unsigned long now = jiffies;
	u64 step;

	if (!th->speed)
		return;

	if (time_before(th->time, now)) {
		step = (u64)th->speed * (now - th->time);
		do_div(step, HZ);
		th->state = min((unsigned)step + th->state, charge + th->burst);
		th->time = now;
	}

	if (charge > th->state) {
		charge -= th->state;
		step = (u64)charge * HZ;
		if (do_div(step, th->speed))
			step++;
		th->time += step;
		step *= th->speed;
		do_div(step, HZ);
		th->state = max_t(int, (int)step - charge, 0);
	} else
		th->state -= charge;

	if (time_after(th->time, now + th->latency))
		th->time = now + th->latency;
}

/* lockless */
static unsigned long throttle_timeout(struct throttle *th, unsigned long now)
{
	unsigned long time;

	if (!th->speed)
		return 0;
	rmb();
	time = th->time;
	if (time_before(time, now))
		return 0;
	return min(time - now, (unsigned long)th->latency);
}

struct iolimit {
	struct throttle throttle;
	wait_queue_head_t wq;
};

static void iolimit_wait(struct iolimit *iolimit, unsigned long timeout)
{
	DEFINE_WAIT(wait);

	do {
		prepare_to_wait(&iolimit->wq, &wait, TASK_KILLABLE);
		timeout = schedule_timeout(timeout);
		if (fatal_signal_pending(current))
			break;
		if (unlikely(timeout))
			timeout = min(throttle_timeout(&iolimit->throttle,
						jiffies), timeout);
	} while (timeout);
	finish_wait(&iolimit->wq, &wait);
}

static int iolimit_virtinfo(struct vnotifier_block *nb,
		unsigned long cmd, void *arg, int old_ret)
{
	struct user_beancounter *ub = get_exec_ub();
	struct iolimit *iolimit = ub->private_data2;
	unsigned long flags, timeout;

	if (!iolimit)
		return old_ret;

	if (!iolimit->throttle.speed)
		return NOTIFY_OK;

	switch (cmd) {
		case VIRTINFO_IO_ACCOUNT:
			spin_lock_irqsave(&ub->ub_lock, flags);
			throttle_charge(&iolimit->throttle, *(size_t*)arg);
			spin_unlock_irqrestore(&ub->ub_lock, flags);
			break;
		case VIRTINFO_IO_PREPARE:
		case VIRTINFO_IO_JOURNAL:
			if (current->flags & PF_FLUSHER)
				break;
			timeout = throttle_timeout(&iolimit->throttle, jiffies);
			if (timeout && !fatal_signal_pending(current))
				iolimit_wait(iolimit, timeout);
			break;
		case VIRTINFO_IO_READAHEAD:
		case VIRTINFO_IO_CONGESTION:
			timeout = throttle_timeout(&iolimit->throttle, jiffies);
			if (timeout)
				return NOTIFY_FAIL;
			break;
	}

	return NOTIFY_OK;
}

static struct vnotifier_block iolimit_virtinfo_nb = {
	.notifier_call = iolimit_virtinfo,
};

static int iolimit_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct user_beancounter *ub;
	struct iolimit *iolimit, *new_iolimit = NULL;
	struct iolimit_state state;
	int err;

	if (cmd != VZCTL_SET_IOLIMIT && cmd != VZCTL_GET_IOLIMIT)
		return -ENOTTY;

	if (copy_from_user(&state, (void __user *)arg, sizeof(state)))
		return -EFAULT;

	ub = get_beancounter_byuid(state.id, 0);
	if (!ub)
		return -ENOENT;

	iolimit = ub->private_data2;

	switch (cmd) {
		case VZCTL_SET_IOLIMIT:
			if (!iolimit) {
				new_iolimit = kmalloc(sizeof(struct iolimit), GFP_KERNEL);
				err = -ENOMEM;
				if (!new_iolimit)
					break;
				init_waitqueue_head(&new_iolimit->wq);
			}

			spin_lock_irq(&ub->ub_lock);

			if (!iolimit && ub->private_data2) {
				kfree(new_iolimit);
				iolimit = ub->private_data2;
			} else if (!iolimit)
				iolimit = new_iolimit;

			throttle_setup(&iolimit->throttle, state.speed,
					state.burst, state.latency);

			if (!ub->private_data2)
				ub->private_data2 = iolimit;

			spin_unlock_irq(&ub->ub_lock);

			wake_up_all(&iolimit->wq);

			err = 0;
			break;
		case VZCTL_GET_IOLIMIT:
			err = -ENXIO;
			if (!iolimit)
				break;

			spin_lock_irq(&ub->ub_lock);
			state.speed = iolimit->throttle.speed;
			state.burst = iolimit->throttle.burst;
			state.latency = jiffies_to_msecs(iolimit->throttle.latency);
			spin_unlock_irq(&ub->ub_lock);

			err = -EFAULT;
			if (copy_to_user((void __user *)arg, &state, sizeof(state)))
				break;

			err = 0;
			break;
		default:
			err = -ENOTTY;
	}

	put_beancounter(ub);
	return err;
}

static struct vzioctlinfo iolimit_vzioctl = {
	.type		= VZIOLIMITTYPE,
	.ioctl		= iolimit_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= iolimit_ioctl,
#endif
	.owner		= THIS_MODULE,
};

static int __init iolimit_init(void)
{
	virtinfo_notifier_register(VITYPE_IO, &iolimit_virtinfo_nb);
	vzioctl_register(&iolimit_vzioctl);

	return 0;
}

static void __exit iolimit_exit(void)
{
	vzioctl_unregister(&iolimit_vzioctl);
	virtinfo_notifier_unregister(VITYPE_IO, &iolimit_virtinfo_nb);
}

module_init(iolimit_init)
module_exit(iolimit_exit)
