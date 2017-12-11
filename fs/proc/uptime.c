#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/time.h>
#include <linux/kernel_stat.h>
#include <linux/cputime.h>
#include <linux/fairsched.h>
#include <linux/ve.h>
#include <linux/cgroup.h>

static inline void get_ve0_idle(struct timespec *idle)
{
	u64 idletime;
	u64 nsec;
	u32 rem;
	int i;

	idletime = 0;
	for_each_possible_cpu(i)
		idletime += (__force u64) kcpustat_cpu(i).cpustat[CPUTIME_IDLE];

	nsec = cputime64_to_jiffies64(idletime) * TICK_NSEC;
	idle->tv_sec = div_u64_rem(nsec, NSEC_PER_SEC, &rem);
	idle->tv_nsec = rem;
}

static inline void get_veX_idle(struct timespec *idle, struct cgroup* cgrp)
{
	struct kernel_cpustat kstat;

	cpu_cgroup_get_stat(cgrp, &kstat);
	*idle = ns_to_timespec(kstat.cpustat[CPUTIME_IDLE]);
}

static int uptime_proc_show(struct seq_file *m, void *v)
{
	struct timespec uptime;
	struct timespec idle;

	if (ve_is_super(get_exec_env()))
		get_ve0_idle(&idle);
	else
		get_veX_idle(&idle, task_cgroup(current, cpu_cgroup_subsys_id));

	get_monotonic_boottime(&uptime);
#ifdef CONFIG_VE
	if (!ve_is_super(get_exec_env())) {
		set_normalized_timespec(&uptime,
			uptime.tv_sec - get_exec_env()->start_timespec.tv_sec,
			uptime.tv_nsec - get_exec_env()->start_timespec.tv_nsec);
	}
#endif
	seq_printf(m, "%lu.%02lu %lu.%02lu\n",
			(unsigned long) uptime.tv_sec,
			(uptime.tv_nsec / (NSEC_PER_SEC / 100)),
			(unsigned long) idle.tv_sec,
			(idle.tv_nsec / (NSEC_PER_SEC / 100)));
	return 0;
}

static int uptime_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, uptime_proc_show, NULL);
}

static const struct file_operations uptime_proc_fops = {
	.open		= uptime_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_uptime_init(void)
{
	proc_create("uptime", 0, NULL, &uptime_proc_fops);
	return 0;
}
module_init(proc_uptime_init);
