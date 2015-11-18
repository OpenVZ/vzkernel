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
#include <linux/device.h>
#include <linux/kmsg_dump.h>

#define MAX_U64			(~(u64)0)
#define MAX_JIFFIES_DELTA	(10 * 365UL * 24UL * 3600UL * HZ)
#define ACTION_NAME_LEN		16

enum {
	FENCE_WDOG_CRASH = 0,
	FENCE_WDOG_REBOOT = 1,
	FENCE_WDOG_POWEROFF = 2,
};

const char *action_names[] = {"crash", "reboot", "poweroff", NULL};


DEFINE_VVAR(volatile unsigned long, fence_wdog_jiffies64) = MAX_U64;
static int fence_wdog_action = FENCE_WDOG_CRASH;

void fence_wdog_do_fence(void)
{
	char *killer = NULL;

	switch (fence_wdog_action) {
	case FENCE_WDOG_CRASH:
		panic_on_oops = 1;
		wmb();
		*killer = 1;
		break;
	case FENCE_WDOG_REBOOT:
		lockdep_off();
		local_irq_enable();
		emergency_restart();
		break;
	case FENCE_WDOG_POWEROFF:
		lockdep_off();
		local_irq_enable();
		sysdev_shutdown();
		printk(KERN_EMERG "System halted.\n");
		kmsg_dump(KMSG_DUMP_HALT);
		machine_halt();
		break;
	}
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

static ssize_t fence_wdog_action_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", action_names[fence_wdog_action]);
}

static ssize_t fence_wdog_action_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	char str_action[ACTION_NAME_LEN];
	int i = 0;

	if (sscanf(buf, "%15s", str_action) != 1)
		return -EINVAL;

	for (i = 0; action_names[i]; i++) {
		if ((!strnicmp(str_action, action_names[i], ACTION_NAME_LEN))) {
			fence_wdog_action = i;
			return count;
		}
	}

	return -EINVAL;
}

static ssize_t fence_wdog_available_actions_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	int i, ret = 0;

	for (i = 0; action_names[i] != NULL; i++)
		ret += sprintf(&buf[ret], "%s ", action_names[i]);

	ret += sprintf(&buf[ret], "\n");
	return ret;
}

static struct kobj_attribute fence_wdog_timer_attr =
	__ATTR(watchdog_timer, 0644,
		fence_wdog_timer_show, fence_wdog_timer_store);

static struct kobj_attribute fence_wdog_action_attr =
	__ATTR(watchdog_action, 0644,
		fence_wdog_action_show, fence_wdog_action_store);

static struct kobj_attribute fence_wdog_available_actions_attr =
	__ATTR(watchdog_available_actions, 0644,
		fence_wdog_available_actions_show, NULL);

static struct attribute *fence_wdog_attrs[] = {
	&fence_wdog_timer_attr.attr,
	&fence_wdog_action_attr.attr,
	&fence_wdog_available_actions_attr.attr,
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
