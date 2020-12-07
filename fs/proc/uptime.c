// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/time.h>
#include <linux/kernel_stat.h>
#include <linux/cgroup.h>
#include <linux/ve.h>

static inline void get_ve0_idle(struct timespec64 *idle)
{
	u64 nsec;
	u32 rem;
	int i;

	nsec = 0;
	for_each_possible_cpu(i)
		nsec += (__force u64) kcpustat_cpu(i).cpustat[CPUTIME_IDLE];

	idle->tv_sec = div_u64_rem(nsec, NSEC_PER_SEC, &rem);
	idle->tv_nsec = rem;
}

static inline void get_veX_idle(struct ve_struct *ve, struct timespec64 *idle)
{
	struct kernel_cpustat kstat;

	ve_get_cpu_stat(ve, &kstat);
	*idle = ns_to_timespec64(kstat.cpustat[CPUTIME_IDLE]);
}

static int uptime_proc_show(struct seq_file *m, void *v)
{
	struct timespec uptime, offset;
	struct timespec64 idle;
	struct ve_struct *ve = get_exec_env();

	if (ve_is_super(ve))
		get_ve0_idle(&idle);
	else
		get_veX_idle(ve, &idle);

	get_monotonic_boottime(&uptime);
#ifdef CONFIG_VE
	if (!ve_is_super(get_exec_env())) {
		offset = ns_to_timespec(get_exec_env()->real_start_time);
		set_normalized_timespec(&uptime,
					 uptime.tv_sec - offset.tv_sec,
					 uptime.tv_nsec - offset.tv_nsec);
	}
#endif
	seq_printf(m, "%lu.%02lu %lu.%02lu\n",
			(unsigned long) uptime.tv_sec,
			(uptime.tv_nsec / (NSEC_PER_SEC / 100)),
			(unsigned long) idle.tv_sec,
			(idle.tv_nsec / (NSEC_PER_SEC / 100)));
	return 0;
}

static int __init proc_uptime_init(void)
{
	proc_net_create_single("uptime", 0, NULL, uptime_proc_show);
	return 0;
}
fs_initcall(proc_uptime_init);
