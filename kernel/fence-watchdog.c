/*
 * Provide userspace with an interface to forbid kernel to work
 * without an userspace daemon.
 *
 * The daemon should write number of seconds before fencing to the
 * file /sys/kernel/watchdog_timer, and must renew it, until the
 * time elapses.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/jiffies.h>
#include <linux/reboot.h>
#include <linux/fence-watchdog.h>

#define MAX_U64			(~(u64)0)
#define MAX_JIFFIES_DELTA	(10 * 365UL * 24UL * 3600UL * HZ)

DEFINE_VVAR(volatile unsigned long, fence_wdog_jiffies64) = MAX_U64;

void fence_wdog_do_fence(void)
{
	lockdep_off();
	local_irq_enable();
	emergency_restart();
}

inline void fence_wdog_check_timer(void)
{
	if (get_jiffies_64() > fence_wdog_jiffies64)
		fence_wdog_do_fence();
}

static ssize_t fence_wdog_timer_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	ssize_t ret;
	u64 jiffies_delta = fence_wdog_jiffies64 - get_jiffies_64();
	struct timespec t;

	if (jiffies_delta > MAX_JIFFIES_DELTA) {
		ret =  sprintf(buf, "inf\n");
	} else {
		jiffies_to_timespec(jiffies_delta, &t);
		ret =  sprintf(buf, "%ld\n", t.tv_sec);
	}

	return ret;
}

static ssize_t fence_wdog_timer_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	unsigned long long val;
	unsigned long jiffies_delta;
	struct timespec t;

	if (strict_strtoull(buf, 10, &val))
		return -EINVAL;

	if (val == 0) {
		fence_wdog_jiffies64 = MAX_U64;
		return count;
	}

	t.tv_sec = val;
	t.tv_nsec = 0;

	jiffies_delta = timespec_to_jiffies(&t);
	if (jiffies_delta > MAX_JIFFIES_DELTA)
		return -EINVAL;

	fence_wdog_jiffies64 = get_jiffies_64() + jiffies_delta;

	return count;
}

static struct kobj_attribute fence_wdog_timer_attr =
	__ATTR(watchdog_timer, 0644,
		fence_wdog_timer_show, fence_wdog_timer_store);

static struct attribute *fence_wdog_attrs[] = {
	&fence_wdog_timer_attr.attr,
	NULL,
};

static struct attribute_group fence_wdog_attr_group = {
	.attrs = fence_wdog_attrs,
};

static int __init fence_wdog_init(void)
{
	sysfs_update_group(kernel_kobj, &fence_wdog_attr_group);
	return 0;
}

module_init(fence_wdog_init)
