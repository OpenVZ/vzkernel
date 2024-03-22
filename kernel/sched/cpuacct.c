// SPDX-License-Identifier: GPL-2.0

/*
 * CPU accounting code for task groups.
 *
 * Based on the work by Paul Menage (menage@google.com) and Balbir Singh
 * (balbir@in.ibm.com).
 */
#include <linux/kernel_stat.h>
#include <linux/ve.h>

/* Time spent by the tasks of the CPU accounting group executing in ... */
enum cpuacct_stat_index {
	CPUACCT_STAT_USER,	/* ... user mode */
	CPUACCT_STAT_SYSTEM,	/* ... kernel mode */

	CPUACCT_STAT_NSTATS,
};

static const char * const cpuacct_stat_desc[] = {
	[CPUACCT_STAT_USER] = "user",
	[CPUACCT_STAT_SYSTEM] = "system",
};

/* track CPU usage of a group of tasks and its child groups */
struct cpuacct {
	struct cgroup_subsys_state	css;
	/* cpuusage holds pointer to a u64-type object on every CPU */
	u64 __percpu	*cpuusage;
	struct kernel_cpustat __percpu	*cpustat;
};

static inline struct cpuacct *css_ca(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct cpuacct, css) : NULL;
}

/* Return CPU accounting group to which this task belongs */
static inline struct cpuacct *task_ca(struct task_struct *tsk)
{
	return css_ca(task_css(tsk, cpuacct_cgrp_id));
}

static inline struct cpuacct *parent_ca(struct cpuacct *ca)
{
	return css_ca(ca->css.parent);
}

static DEFINE_PER_CPU(u64, root_cpuacct_cpuusage);
static struct cpuacct root_cpuacct = {
	.cpustat	= &kernel_cpustat,
	.cpuusage	= &root_cpuacct_cpuusage,
};

/* Create a new CPU accounting group */
static struct cgroup_subsys_state *
cpuacct_css_alloc(struct cgroup_subsys_state *parent_css)
{
	struct cpuacct *ca;

	if (!parent_css)
		return &root_cpuacct.css;

	ca = kzalloc(sizeof(*ca), GFP_KERNEL);
	if (!ca)
		goto out;

	ca->cpuusage = alloc_percpu(u64);
	if (!ca->cpuusage)
		goto out_free_ca;

	ca->cpustat = alloc_percpu(struct kernel_cpustat);
	if (!ca->cpustat)
		goto out_free_cpuusage;

	return &ca->css;

out_free_cpuusage:
	free_percpu(ca->cpuusage);
out_free_ca:
	kfree(ca);
out:
	return ERR_PTR(-ENOMEM);
}

/* Destroy an existing CPU accounting group */
static void cpuacct_css_free(struct cgroup_subsys_state *css)
{
	struct cpuacct *ca = css_ca(css);

	free_percpu(ca->cpustat);
	free_percpu(ca->cpuusage);
	kfree(ca);
}

static u64 cpuacct_cpuusage_read(struct cpuacct *ca, int cpu,
				 enum cpuacct_stat_index index)
{
	u64 *cpuusage = per_cpu_ptr(ca->cpuusage, cpu);
	u64 *cpustat = per_cpu_ptr(ca->cpustat, cpu)->cpustat;
	u64 data;

	/*
	 * We allow index == CPUACCT_STAT_NSTATS here to read
	 * the sum of usages.
	 */
	if (WARN_ON_ONCE(index > CPUACCT_STAT_NSTATS))
		return 0;

#ifndef CONFIG_64BIT
	/*
	 * Take rq->lock to make 64-bit read safe on 32-bit platforms.
	 */
	raw_spin_rq_lock_irq(cpu_rq(cpu));
#endif

	switch (index) {
	case CPUACCT_STAT_USER:
		data = cpustat[CPUTIME_USER] + cpustat[CPUTIME_NICE];
		break;
	case CPUACCT_STAT_SYSTEM:
		data = cpustat[CPUTIME_SYSTEM] + cpustat[CPUTIME_IRQ] +
			cpustat[CPUTIME_SOFTIRQ];
		break;
	case CPUACCT_STAT_NSTATS:
		data = *cpuusage;
		break;
	}

#ifndef CONFIG_64BIT
	raw_spin_rq_unlock_irq(cpu_rq(cpu));
#endif

	return data;
}

static void cpuacct_cpuusage_write(struct cpuacct *ca, int cpu)
{
	u64 *cpuusage = per_cpu_ptr(ca->cpuusage, cpu);
	u64 *cpustat = per_cpu_ptr(ca->cpustat, cpu)->cpustat;

	/* Don't allow to reset global kernel_cpustat */
	if (ca == &root_cpuacct)
		return;

#ifndef CONFIG_64BIT
	/*
	 * Take rq->lock to make 64-bit write safe on 32-bit platforms.
	 */
	raw_spin_rq_lock_irq(cpu_rq(cpu));
#endif
	*cpuusage = 0;
	cpustat[CPUTIME_USER] = cpustat[CPUTIME_NICE] = 0;
	cpustat[CPUTIME_SYSTEM] = cpustat[CPUTIME_IRQ] = 0;
	cpustat[CPUTIME_SOFTIRQ] = 0;

#ifndef CONFIG_64BIT
	raw_spin_rq_unlock_irq(cpu_rq(cpu));
#endif
}

/* Return total CPU usage (in nanoseconds) of a group */
static u64 __cpuusage_read(struct cgroup_subsys_state *css,
			   enum cpuacct_stat_index index)
{
	struct cpuacct *ca = css_ca(css);
	u64 totalcpuusage = 0;
	int i;

	for_each_possible_cpu(i)
		totalcpuusage += cpuacct_cpuusage_read(ca, i, index);

	return totalcpuusage;
}

static u64 cpuusage_user_read(struct cgroup_subsys_state *css,
			      struct cftype *cft)
{
	return __cpuusage_read(css, CPUACCT_STAT_USER);
}

static u64 cpuusage_sys_read(struct cgroup_subsys_state *css,
			     struct cftype *cft)
{
	return __cpuusage_read(css, CPUACCT_STAT_SYSTEM);
}

static u64 cpuusage_read(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return __cpuusage_read(css, CPUACCT_STAT_NSTATS);
}

static int cpuusage_write(struct cgroup_subsys_state *css, struct cftype *cft,
			  u64 val)
{
	struct cpuacct *ca = css_ca(css);
	int cpu;

	/*
	 * Only allow '0' here to do a reset.
	 */
	if (val)
		return -EINVAL;

	for_each_possible_cpu(cpu)
		cpuacct_cpuusage_write(ca, cpu);

	return 0;
}

static int __cpuacct_percpu_seq_show(struct seq_file *m,
				     enum cpuacct_stat_index index)
{
	struct cpuacct *ca = css_ca(seq_css(m));
	u64 percpu;
	int i;

	for_each_possible_cpu(i) {
		percpu = cpuacct_cpuusage_read(ca, i, index);
		seq_printf(m, "%llu ", (unsigned long long) percpu);
	}
	seq_printf(m, "\n");
	return 0;
}

static int cpuacct_percpu_user_seq_show(struct seq_file *m, void *V)
{
	return __cpuacct_percpu_seq_show(m, CPUACCT_STAT_USER);
}

static int cpuacct_percpu_sys_seq_show(struct seq_file *m, void *V)
{
	return __cpuacct_percpu_seq_show(m, CPUACCT_STAT_SYSTEM);
}

static int cpuacct_percpu_seq_show(struct seq_file *m, void *V)
{
	return __cpuacct_percpu_seq_show(m, CPUACCT_STAT_NSTATS);
}

static int cpuacct_all_seq_show(struct seq_file *m, void *V)
{
	struct cpuacct *ca = css_ca(seq_css(m));
	int index;
	int cpu;

	seq_puts(m, "cpu");
	for (index = 0; index < CPUACCT_STAT_NSTATS; index++)
		seq_printf(m, " %s", cpuacct_stat_desc[index]);
	seq_puts(m, "\n");

	for_each_possible_cpu(cpu) {
		seq_printf(m, "%d", cpu);
		for (index = 0; index < CPUACCT_STAT_NSTATS; index++)
			seq_printf(m, " %llu",
				   cpuacct_cpuusage_read(ca, cpu, index));
		seq_puts(m, "\n");
	}
	return 0;
}

static int cpuacct_stats_show(struct seq_file *sf, void *v)
{
	struct cpuacct *ca = css_ca(seq_css(sf));
	struct task_cputime cputime;
	u64 val[CPUACCT_STAT_NSTATS];
	int cpu;
	int stat;

	memset(&cputime, 0, sizeof(cputime));
	for_each_possible_cpu(cpu) {
		u64 *cpustat = per_cpu_ptr(ca->cpustat, cpu)->cpustat;

		cputime.utime += cpustat[CPUTIME_USER];
		cputime.utime += cpustat[CPUTIME_NICE];
		cputime.stime += cpustat[CPUTIME_SYSTEM];
		cputime.stime += cpustat[CPUTIME_IRQ];
		cputime.stime += cpustat[CPUTIME_SOFTIRQ];

		cputime.sum_exec_runtime += *per_cpu_ptr(ca->cpuusage, cpu);
	}

	cputime_adjust(&cputime, &seq_css(sf)->cgroup->prev_cputime,
		&val[CPUACCT_STAT_USER], &val[CPUACCT_STAT_SYSTEM]);

	for (stat = 0; stat < CPUACCT_STAT_NSTATS; stat++) {
		seq_printf(sf, "%s %llu\n", cpuacct_stat_desc[stat],
			nsec_to_clock_t(val[stat]));
	}

	return 0;
}

static struct cftype files[] = {
	{
		.name = "usage",
		.read_u64 = cpuusage_read,
		.write_u64 = cpuusage_write,
	},
	{
		.name = "usage_user",
		.read_u64 = cpuusage_user_read,
	},
	{
		.name = "usage_sys",
		.read_u64 = cpuusage_sys_read,
	},
	{
		.name = "usage_percpu",
		.seq_show = cpuacct_percpu_seq_show,
	},
	{
		.name = "usage_percpu_user",
		.seq_show = cpuacct_percpu_user_seq_show,
	},
	{
		.name = "usage_percpu_sys",
		.seq_show = cpuacct_percpu_sys_seq_show,
	},
	{
		.name = "usage_all",
		.seq_show = cpuacct_all_seq_show,
	},
	{
		.name = "stat",
		.seq_show = cpuacct_stats_show,
	},
	{ }	/* terminate */
};

/*
 * charge this task's execution time to its accounting group.
 *
 * called with rq->lock held.
 */
void cpuacct_charge(struct task_struct *tsk, u64 cputime)
{
	unsigned int cpu = task_cpu(tsk);
	struct cpuacct *ca;

	lockdep_assert_rq_held(cpu_rq(cpu));

	for (ca = task_ca(tsk); ca; ca = parent_ca(ca))
		*per_cpu_ptr(ca->cpuusage, cpu) += cputime;
}

/*
 * Add user/system time to cpuacct.
 *
 * Note: it's the caller that updates the account of the root cgroup.
 */
void cpuacct_account_field(struct task_struct *tsk, int index, u64 val)
{
	struct cpuacct *ca;

	for (ca = task_ca(tsk); ca != &root_cpuacct; ca = parent_ca(ca))
		__this_cpu_add(ca->cpustat->cpustat[index], val);
}

struct cgroup_subsys cpuacct_cgrp_subsys = {
	.css_alloc	= cpuacct_css_alloc,
	.css_free	= cpuacct_css_free,
	.legacy_cftypes	= files,
	.early_init	= true,

	.implicit_on_dfl = true,
	.threaded       = true,
};

extern struct task_group *css_tg(struct cgroup_subsys_state *css);

static struct task_group *ve_root_tg(struct task_group *tg) {
	struct cgroup_subsys_state *css;

	if (!tg)
		return NULL;

	css = css_ve_root1(&tg->css);
	return css ? css_tg(css) : NULL;
}

unsigned int tg_cpu_rate(struct task_group *tg)
{
	unsigned int cpu_rate = 0;
#ifdef CONFIG_CFS_CPULIMIT
	tg = ve_root_tg(tg);
	if (tg)
		cpu_rate = tg->cpu_rate;
#endif
	return cpu_rate;
}

static unsigned int tg_nr_cpus(struct task_group *tg)
{
	unsigned int nr_cpus = 0;
	unsigned int max_nr_cpus = num_online_cpus();

#ifdef CONFIG_CFS_CPULIMIT
	tg = ve_root_tg(tg);
	if (tg)
		nr_cpus = tg->nr_cpus;
#endif
	if (!nr_cpus || nr_cpus > max_nr_cpus)
		nr_cpus = max_nr_cpus;

	return nr_cpus;
}

struct kernel_cpustat *cpuacct_cpustat(struct cgroup_subsys_state *css, int cpu)
{
	return per_cpu_ptr(css_ca(css)->cpustat, cpu);
}

static void cpu_cgroup_update_stat(struct cgroup_subsys_state *cpu_css,
				   struct cgroup_subsys_state *cpuacct_css,
				   int i)
{
#if defined(CONFIG_SCHEDSTATS) && defined(CONFIG_FAIR_GROUP_SCHED)
	struct task_group *tg = css_tg(cpu_css);
	struct sched_entity *se = tg->se[i];
	struct sched_statistics *stats;
	u64 *cpustat = cpuacct_cpustat(cpuacct_css, i)->cpustat;
	u64 now = cpu_clock(i);
	u64 delta, idle, iowait, steal, used;

	/* root_task_group has not sched entities */
	if (tg == &root_task_group)
		return;

	stats = __schedstats_from_se(se);

	iowait = stats->iowait_sum;
	idle = stats->sum_sleep_runtime;
	steal = stats->wait_sum;
	used = se->sum_exec_runtime;

	if (idle > iowait)
		idle -= iowait;
	else
		idle = 0;

	if (stats->sleep_start) {
		delta = now - stats->sleep_start;
		if ((s64)delta > 0)
			idle += delta;
	} else if (stats->block_start) {
		delta = now - stats->block_start;
		if ((s64)delta > 0)
			iowait += delta;
	} else if (stats->wait_start) {
		delta = now - stats->wait_start;
		if ((s64)delta > 0)
			steal += delta;
	}

	cpustat[CPUTIME_IDLE]	= max(cpustat[CPUTIME_IDLE], idle);
	cpustat[CPUTIME_IOWAIT]	= max(cpustat[CPUTIME_IOWAIT], iowait);
	cpustat[CPUTIME_STEAL]	= steal;
	cpustat[CPUTIME_USED]	= used;
#endif
}

static void fixup_vcpustat_delta_usage(struct kernel_cpustat *cur,
				       struct kernel_cpustat *rem, int ind,
				       u64 cur_usage, u64 target_usage,
				       u64 rem_usage)
{
	s64 scaled_val;
	u32 scale_pct = 0;

	/* distribute the delta among USER, NICE, and SYSTEM proportionally */
	if (cur_usage < target_usage) {
		if ((s64)rem_usage > 0) /* sanity check to avoid div/0 */
			scale_pct = div64_u64(100 * rem->cpustat[ind],
					      rem_usage);
	} else {
		if ((s64)cur_usage > 0) /* sanity check to avoid div/0 */
			scale_pct = div64_u64(100 * cur->cpustat[ind],
					      cur_usage);
	}

	scaled_val = div_s64(scale_pct * (target_usage - cur_usage), 100);

	cur->cpustat[ind] += scaled_val;
	if ((s64)cur->cpustat[ind] < 0)
		cur->cpustat[ind] = 0;

	rem->cpustat[ind] -= scaled_val;
	if ((s64)rem->cpustat[ind] < 0)
		rem->cpustat[ind] = 0;
}

static void calc_vcpustat_delta_idle(struct kernel_cpustat *cur,
				     int ind, u64 cur_idle, u64 target_idle)
{
	/* distribute target_idle between IDLE and IOWAIT proportionally to
	 * what we initially had on this vcpu */
	if ((s64)cur_idle > 0) {
		u32 scale_pct = div64_u64(100 * cur->cpustat[ind], cur_idle);
		cur->cpustat[ind] = div_u64(scale_pct * target_idle, 100);
	} else {
		cur->cpustat[ind] = ind == CPUTIME_IDLE ? target_idle : 0;
	}
}

static void fixup_vcpustat_delta(struct kernel_cpustat *cur,
				 struct kernel_cpustat *rem,
				 u64 max_usage)
{
	u64 cur_usage, target_usage, rem_usage;
	u64 cur_idle, target_idle;

	cur_usage = kernel_cpustat_total_usage(cur);
	rem_usage = kernel_cpustat_total_usage(rem);

	target_usage = min(cur_usage + rem_usage,
			max_usage);

	if (cur_usage != target_usage) {
		fixup_vcpustat_delta_usage(cur, rem, CPUTIME_USER,
				cur_usage, target_usage, rem_usage);
		fixup_vcpustat_delta_usage(cur, rem, CPUTIME_NICE,
				cur_usage, target_usage, rem_usage);
		fixup_vcpustat_delta_usage(cur, rem, CPUTIME_SYSTEM,
				cur_usage, target_usage, rem_usage);
	}

	cur_idle = kernel_cpustat_total_idle(cur);
	target_idle = max_usage - target_usage;

	if (cur_idle != target_idle) {
		calc_vcpustat_delta_idle(cur, CPUTIME_IDLE,
					 cur_idle, target_idle);
		calc_vcpustat_delta_idle(cur, CPUTIME_IOWAIT,
					 cur_idle, target_idle);
	}

	cur->cpustat[CPUTIME_USED] = target_usage;

	/* do not show steal time inside ve */
	cur->cpustat[CPUTIME_STEAL] = 0;
}

static void cpu_cgroup_update_vcpustat(struct cgroup_subsys_state *cpu_css,
				       struct cgroup_subsys_state *cpuacct_css)
{
	int i, j;
	int nr_vcpus;
	int vcpu_rate;
	ktime_t now;
	u64 max_usage;
	struct kernel_cpustat stat_delta, stat_rem;
	struct task_group *tg = css_tg(cpu_css);
	int first_pass = 1;

	spin_lock(&tg->vcpustat_lock);

	now = ktime_get();
	nr_vcpus = tg_nr_cpus(tg);
	vcpu_rate = DIV_ROUND_UP(tg_cpu_rate(tg), nr_vcpus);
	if (!vcpu_rate || vcpu_rate > MAX_CPU_RATE)
		vcpu_rate = MAX_CPU_RATE;

	if (!ktime_to_ns(tg->vcpustat_last_update)) {
		/* on the first read initialize vcpu i stat as a sum of stats
		 * over pcpus j such that j % nr_vcpus == i */
		for (i = 0; i < nr_vcpus; i++) {
			for (j = i; j < nr_cpu_ids; j += nr_vcpus) {
				if (!cpu_possible(j))
					continue;
				kernel_cpustat_add(tg->vcpustat + i,
						cpuacct_cpustat(cpuacct_css, j),
						tg->vcpustat + i);
			}
		}
		goto out_update_last;
	}

	max_usage = ktime_to_ns(ktime_sub(now, tg->vcpustat_last_update));
	max_usage = div_u64(max_usage * vcpu_rate, MAX_CPU_RATE);
	/* don't allow to update stats too often to avoid calculation errors */
	if (max_usage < 10)
		goto out_unlock;

	/* temporarily copy per cpu usage delta to tg->cpustat_last */
	for_each_possible_cpu(i)
		kernel_cpustat_sub(cpuacct_cpustat(cpuacct_css, i),
				   tg->cpustat_last + i,
				   tg->cpustat_last + i);

	/* proceed to calculating per vcpu delta */
	kernel_cpustat_zero(&stat_rem);

again:
	for (i = 0; i < nr_vcpus; i++) {
		int exceeds_max;

		kernel_cpustat_zero(&stat_delta);
		for (j = i; j < nr_cpu_ids; j += nr_vcpus) {
			if (!cpu_possible(j))
				continue;
			kernel_cpustat_add(&stat_delta,
					   tg->cpustat_last + j, &stat_delta);
		}

		exceeds_max = kernel_cpustat_total_usage(&stat_delta) >=
			      max_usage;
		/*
		 * On the first pass calculate delta for vcpus with usage >
		 * max_usage in order to accumulate excess in stat_rem.
		 *
		 * Once the remainder is accumulated, proceed to the rest of
		 * vcpus so that it will be distributed among them.
		 */
		if (exceeds_max != first_pass)
			continue;

		fixup_vcpustat_delta(&stat_delta, &stat_rem, max_usage);
		kernel_cpustat_add(tg->vcpustat + i, &stat_delta,
				   tg->vcpustat + i);
	}

	if (first_pass) {
		first_pass = 0;
		goto again;
	}
out_update_last:
	for_each_possible_cpu(i)
		tg->cpustat_last[i] = *cpuacct_cpustat(cpuacct_css, i);
	tg->vcpustat_last_update = now;
out_unlock:
	spin_unlock(&tg->vcpustat_lock);
}

int cpu_cgroup_proc_stat(struct cgroup_subsys_state *cpu_css,
			 struct cgroup_subsys_state *cpuacct_css,
			 struct seq_file *p)
{
	int i;
	u64 user, nice, system, idle, iowait, steal;
	struct time_namespace *time_ns;
	struct timespec64 boottime;
	struct task_group *tg = css_tg(cpu_css);
	bool virt = !ve_is_super(get_exec_env()) && tg != &root_task_group;
	int nr_vcpus = tg_nr_cpus(tg);
	struct kernel_cpustat *kcpustat;
	unsigned long tg_nr_running = 0;
	unsigned long tg_nr_iowait = 0;
	unsigned long long tg_nr_switches = 0;
	unsigned long tg_nr_forks = 0;

	time_ns = ve_get_time_ns(get_exec_env());
	if (time_ns) {
		getboottime64(&boottime);
		/* time_ns->offsets.boottime is (ve_uptime - host_uptime), i.e.
		 * negative for ve created on this host. Shall subtract that
		 * from the timestamp of host's boot to get the timestamp of
		 * ve's boot */
		boottime = timespec64_sub(boottime, time_ns->offsets.boottime);
		put_time_ns(time_ns);
	} else {
		/* for not yet started ve, use current time as the timestamp of
		 * ve's boot */
		ktime_get_real_ts64(&boottime);
	}

	for_each_possible_cpu(i) {
		cpu_cgroup_update_stat(cpu_css, cpuacct_css, i);

		/* root task group has autogrouping, so this doesn't hold */
#ifdef CONFIG_FAIR_GROUP_SCHED
		tg_nr_running += tg->cfs_rq[i]->h_nr_running;
		tg_nr_iowait  += tg->cfs_rq[i]->nr_iowait;
		tg_nr_switches += tg->cfs_rq[i]->nr_switches;
		tg_nr_forks   += tg->cfs_rq[i]->nr_forks;
#endif
#ifdef CONFIG_RT_GROUP_SCHED
		tg_nr_running += tg->rt_rq[i]->rt_nr_running;
#endif
	}

	if (virt)
		cpu_cgroup_update_vcpustat(cpu_css, cpuacct_css);

	user = nice = system = idle = iowait = steal = 0;

	for (i = 0; i < (virt ? nr_vcpus : nr_cpu_ids); i++) {
		if (!virt && !cpu_possible(i))
			continue;

		kcpustat = virt ? tg->vcpustat + i :
				  cpuacct_cpustat(cpuacct_css, i);

		user	+= kcpustat->cpustat[CPUTIME_USER];
		nice	+= kcpustat->cpustat[CPUTIME_NICE];
		system	+= kcpustat->cpustat[CPUTIME_SYSTEM];
		idle	+= kcpustat->cpustat[CPUTIME_IDLE];
		iowait	+= kcpustat->cpustat[CPUTIME_IOWAIT];
		steal	+= kcpustat->cpustat[CPUTIME_STEAL];
	}
	/* Don't scare CT users with high steal time */
	if (!ve_is_super(get_exec_env()))
		steal = 0;

	seq_printf(p, "cpu  %llu %llu %llu %llu %llu 0 0 %llu\n",
		   (unsigned long long)nsec_to_clock_t(user),
		   (unsigned long long)nsec_to_clock_t(nice),
		   (unsigned long long)nsec_to_clock_t(system),
		   (unsigned long long)nsec_to_clock_t(idle),
		   (unsigned long long)nsec_to_clock_t(iowait),
		   virt ? 0ULL :
		   (unsigned long long)nsec_to_clock_t(steal));

	for (i = 0; i < (virt ? nr_vcpus : nr_cpu_ids); i++) {
		if (!virt && !cpu_online(i))
			continue;
		kcpustat = virt ? tg->vcpustat + i :
				  cpuacct_cpustat(cpuacct_css, i);

		user	= kcpustat->cpustat[CPUTIME_USER];
		nice	= kcpustat->cpustat[CPUTIME_NICE];
		system	= kcpustat->cpustat[CPUTIME_SYSTEM];
		idle	= kcpustat->cpustat[CPUTIME_IDLE];
		iowait	= kcpustat->cpustat[CPUTIME_IOWAIT];
		steal	= kcpustat->cpustat[CPUTIME_STEAL];
		/* Don't scare CT users with high steal time */
		if (!ve_is_super(get_exec_env()))
			steal = 0;

		seq_printf(p,
			   "cpu%d %llu %llu %llu %llu %llu 0 0 %llu\n",
			   i,
			   (unsigned long long)nsec_to_clock_t(user),
			   (unsigned long long)nsec_to_clock_t(nice),
			   (unsigned long long)nsec_to_clock_t(system),
			   (unsigned long long)nsec_to_clock_t(idle),
			   (unsigned long long)nsec_to_clock_t(iowait),
			   virt ? 0ULL :
			   (unsigned long long)nsec_to_clock_t(steal));
	}
	seq_printf(p, "intr 0");

	seq_printf(p,
		   "\nctxt %llu\n"
		   "btime %llu\n"
		   "processes %lu\n"
		   "procs_running %lu\n"
		   "procs_blocked %lu\n",
		   tg_nr_switches,
		   (unsigned long long)boottime.tv_sec,
		   tg_nr_forks,
		   tg_nr_running,
		   tg_nr_iowait);

	return 0;
}

int cpu_cgroup_get_stat(struct cgroup_subsys_state *cpu_css,
			struct cgroup_subsys_state *cpuacct_css,
			struct kernel_cpustat *kstat)
{
	struct task_group *tg = css_tg(cpu_css);
	int nr_vcpus = tg_nr_cpus(tg);
	int i;

	kernel_cpustat_zero(kstat);

	if (tg == &root_task_group)
		return -ENOENT;

	for_each_possible_cpu(i)
		cpu_cgroup_update_stat(cpu_css, cpuacct_css, i);

	cpu_cgroup_update_vcpustat(cpu_css, cpuacct_css);

	for (i = 0; i < nr_vcpus; i++)
		kernel_cpustat_add(tg->vcpustat + i, kstat, kstat);

	return 0;
}

int cpu_cgroup_proc_stat_show(struct seq_file *sf, void *v)
{
	struct cgroup_subsys_state *cpu_css = seq_css(sf);
	struct cgroup_subsys_state *cpuacct_css;
	int ret;

	/*
	 * The cgroup the file is associated with should not disappear from
	 * under us (the file is open, after all). Still, it won't hurt to
	 * use RCU read-side lock as cgroup->subsys[] might need it.
	 */
	rcu_read_lock();
	/*
	 * Data from both 'cpu' and 'cpuacct' subsystems are needed. These
	 * subsystems are often used together, but let us check if 'cpuacct'
	 * is available for the cgroup, just in case.
	 */
	cpuacct_css = rcu_dereference(cpu_css->cgroup->subsys[cpuacct_cgrp_id]);
	if (!cpuacct_css) {
		rcu_read_unlock();
		return -ENOENT;
	}
	css_get(cpuacct_css);
	rcu_read_unlock();

	ret = cpu_cgroup_proc_stat(cpu_css, cpuacct_css, sf);
	css_put(cpuacct_css);
	return ret;
}
