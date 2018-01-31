/*
 *  kernel/fence-watchdog.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *
 */

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
#include <linux/fs.h>
#include <linux/string.h>

#define MAX_U64			(~(u64)0)
#define MAX_JIFFIES_DELTA	(10 * 365UL * 24UL * 3600UL * HZ)
#define ACTION_NAME_LEN		16

enum {
	FENCE_WDOG_CRASH = 0,
	FENCE_WDOG_REBOOT = 1,
	FENCE_WDOG_POWEROFF = 2,
	FENCE_WDOG_NETFILTER = 3,
};

const char *action_names[] = {"crash", "reboot", "halt", "netfilter", NULL};


DEFINE_VVAR(volatile unsigned long, fence_wdog_jiffies64) = MAX_U64;
static int fence_wdog_action = FENCE_WDOG_CRASH;

enum {
	NOT_FENCED = 0,
	FENCED = 1,
	FENCED_TIMEOUT = 2,
};

static atomic_t fence_stage = ATOMIC_INIT(NOT_FENCED);
static char fence_wdog_log_path[PATH_MAX] = "/fence_wdog.log";

#define SECS_PER_MIN	60
#define PREFIX_LEN	39

static int print_prefix(char *msg) {
	struct timeval tv;
	struct tm tm;

	do_gettimeofday(&tv);
	time_to_tm(tv.tv_sec - sys_tz.tz_minuteswest * SECS_PER_MIN, 0, &tm);

	return snprintf(msg, PREFIX_LEN, "[%02d:%02d:%02d/%04ld-%02d-%02d] fence-watchdog: ",
			tm.tm_hour, tm.tm_min, tm.tm_sec,
			tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
}

#define MSG_LEN (PREFIX_LEN + 10)

void fence_wdog_log(void)
{
	char msg[MSG_LEN];
	struct file *file;
	int ret, len;

	ret = print_prefix(msg);
	if (ret < 0)
		return;

	len = strlen(msg);

	ret = snprintf(msg + len, MSG_LEN - len, "%s\n", action_names[fence_wdog_action]);
	if (ret != strlen(action_names[fence_wdog_action]) + 1) {
		printk(KERN_EMERG"fence-watchdog: Failed to sprintf msg\n");
		return;
	}

	file = filp_open(fence_wdog_log_path,
			 O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW | O_LARGEFILE,
			 0600);
	if (IS_ERR(file)) {
		printk(KERN_EMERG"fence-watchdog: Failed to open log path\n");
		return;
	}

	if (!S_ISREG(file_inode(file)->i_mode)) {
		printk(KERN_EMERG"fence-watchdog: Wrong type of log file\n");
		goto close;
	}

	ret = kernel_write(file, msg, strlen(msg), file->f_pos);
	if (ret < 0) {
		printk(KERN_EMERG"fence-watchdog: Failed to write msg, ret=%d\n", ret);
		goto close;
	}

	ret = vfs_fsync(file, 0);
	if (ret < 0)
		printk(KERN_EMERG"fence-watchdog: Failed to fsync log file ret=%d\n", ret);

close:
	ret = filp_close(file, NULL);
	if (ret < 0)
		printk(KERN_EMERG"fence-watchdog: Failed to close log file ret=%d\n", ret);

	return;
}

static void do_halt_or_reboot(struct work_struct *dummy)
{
	printk(KERN_EMERG"fence-watchdog: %s\n",
	       action_names[fence_wdog_action]);

	fence_wdog_log();

	switch (fence_wdog_action) {
	case FENCE_WDOG_REBOOT:
		emergency_restart();
		break;
	case FENCE_WDOG_POWEROFF:
		kernel_halt();
		break;
	}
}

static DECLARE_WORK(halt_or_reboot_work, do_halt_or_reboot);

void fence_wdog_do_fence(void)
{
	if (fence_wdog_action == FENCE_WDOG_CRASH ||
			atomic_read(&fence_stage) == FENCED_TIMEOUT)
		panic("fence-watchdog: %s\n",
		      action_names[fence_wdog_action]);
	else
		schedule_work(&halt_or_reboot_work);
}

#define FENCE_WDOG_TIMEOUT 30

inline int fence_wdog_check_timer(void)
{
	static unsigned long print_alive_time;

	if (fence_wdog_jiffies64 != MAX_U64)
		if (printk_timed_ratelimit(&print_alive_time, 30*60*HZ))
			printk("fence-watchdog: alive\n");

	if (unlikely(get_jiffies_64() > fence_wdog_jiffies64 &&
			fence_wdog_action != FENCE_WDOG_NETFILTER)) {
		if (atomic_cmpxchg(&fence_stage, NOT_FENCED, FENCED) == NOT_FENCED
		    || (get_jiffies_64() > fence_wdog_jiffies64
		    + FENCE_WDOG_TIMEOUT * HZ
		    && atomic_cmpxchg(&fence_stage, FENCED, FENCED_TIMEOUT) == FENCED))
			fence_wdog_do_fence();

		return 1;
	}

	return 0;
}

bool fence_wdog_tmo_match(void)
{
	return get_jiffies_64() > fence_wdog_jiffies64;
}
EXPORT_SYMBOL(fence_wdog_tmo_match);

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

static ssize_t fence_wdog_log_path_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", fence_wdog_log_path);
}

#define STORE_FORMAT_LEN 16

static ssize_t fence_wdog_log_path_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	char format[STORE_FORMAT_LEN];
	int ret;

	ret = snprintf(format, STORE_FORMAT_LEN, "%%%ds", PATH_MAX - 1);
	if (ret < 0)
		return ret;


	if (sscanf(buf, format, fence_wdog_log_path) != 1)
		return -EINVAL;
	return 0;
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

static struct kobj_attribute fence_wdog_log_path_attr =
	__ATTR(watchdog_log_path, 0644,
		fence_wdog_log_path_show, fence_wdog_log_path_store);

static struct attribute *fence_wdog_attrs[] = {
	&fence_wdog_timer_attr.attr,
	&fence_wdog_action_attr.attr,
	&fence_wdog_available_actions_attr.attr,
	&fence_wdog_log_path_attr.attr,
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
