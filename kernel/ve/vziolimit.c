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


static int iolimit_virtinfo(struct vnotifier_block *nb,
		unsigned long cmd, void *arg, int old_ret)
{
}

static struct vnotifier_block iolimit_virtinfo_nb = {
	.notifier_call = iolimit_virtinfo,
};

static int iolimit_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
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
