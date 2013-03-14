// SPDX-License-Identifier: GPL-2.0
/*
 * CPU accounting code for task groups.
 *
 * Based on the work by Paul Menage (menage@google.com) and Balbir Singh
 * (balbir@in.ibm.com).
 */
#include <linux/kernel_stat.h>
#include "sched.h"

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

struct cpuacct_usage {
	u64	usages[CPUACCT_STAT_NSTATS];
};

/* track CPU usage of a group of tasks and its child groups */
struct cpuacct {
	struct cgroup_subsys_state	css;
	/* cpuusage holds pointer to a u64-type object on every CPU */
	struct cpuacct_usage __percpu	*cpuusage;
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

static DEFINE_PER_CPU(struct cpuacct_usage, root_cpuacct_cpuusage);
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

	ca->cpuusage = alloc_percpu(struct cpuacct_usage);
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
	struct cpuacct_usage *cpuusage = per_cpu_ptr(ca->cpuusage, cpu);
	u64 data;

	/*
	 * We allow index == CPUACCT_STAT_NSTATS here to read
	 * the sum of suages.
	 */
	BUG_ON(index > CPUACCT_STAT_NSTATS);

#ifndef CONFIG_64BIT
	/*
	 * Take rq->lock to make 64-bit read safe on 32-bit platforms.
	 */
	raw_spin_lock_irq(&cpu_rq(cpu)->lock);
#endif

	if (index == CPUACCT_STAT_NSTATS) {
		int i = 0;

		data = 0;
		for (i = 0; i < CPUACCT_STAT_NSTATS; i++)
			data += cpuusage->usages[i];
	} else {
		data = cpuusage->usages[index];
	}

#ifndef CONFIG_64BIT
	raw_spin_unlock_irq(&cpu_rq(cpu)->lock);
#endif

	return data;
}

static void cpuacct_cpuusage_write(struct cpuacct *ca, int cpu, u64 val)
{
	struct cpuacct_usage *cpuusage = per_cpu_ptr(ca->cpuusage, cpu);
	int i;

#ifndef CONFIG_64BIT
	/*
	 * Take rq->lock to make 64-bit write safe on 32-bit platforms.
	 */
	raw_spin_lock_irq(&cpu_rq(cpu)->lock);
#endif

	for (i = 0; i < CPUACCT_STAT_NSTATS; i++)
		cpuusage->usages[i] = val;

#ifndef CONFIG_64BIT
	raw_spin_unlock_irq(&cpu_rq(cpu)->lock);
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
		cpuacct_cpuusage_write(ca, cpu, 0);

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
		struct cpuacct_usage *cpuusage = per_cpu_ptr(ca->cpuusage, cpu);

		seq_printf(m, "%d", cpu);

		for (index = 0; index < CPUACCT_STAT_NSTATS; index++) {
#ifndef CONFIG_64BIT
			/*
			 * Take rq->lock to make 64-bit read safe on 32-bit
			 * platforms.
			 */
			raw_spin_lock_irq(&cpu_rq(cpu)->lock);
#endif

			seq_printf(m, " %llu", cpuusage->usages[index]);

#ifndef CONFIG_64BIT
			raw_spin_unlock_irq(&cpu_rq(cpu)->lock);
#endif
		}
		seq_puts(m, "\n");
	}
	return 0;
}

static int cpuacct_stats_show(struct seq_file *sf, void *v)
{
	struct cpuacct *ca = css_ca(seq_css(sf));
	s64 val[CPUACCT_STAT_NSTATS];
	int cpu;
	int stat;

	memset(val, 0, sizeof(val));
	for_each_possible_cpu(cpu) {
		u64 *cpustat = per_cpu_ptr(ca->cpustat, cpu)->cpustat;

		val[CPUACCT_STAT_USER]   += cpustat[CPUTIME_USER];
		val[CPUACCT_STAT_USER]   += cpustat[CPUTIME_NICE];
		val[CPUACCT_STAT_SYSTEM] += cpustat[CPUTIME_SYSTEM];
		val[CPUACCT_STAT_SYSTEM] += cpustat[CPUTIME_IRQ];
		val[CPUACCT_STAT_SYSTEM] += cpustat[CPUTIME_SOFTIRQ];
	}

	for (stat = 0; stat < CPUACCT_STAT_NSTATS; stat++) {
		seq_printf(sf, "%s %lld\n",
			   cpuacct_stat_desc[stat],
			   (long long)nsec_to_clock_t(val[stat]));
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
	struct cpuacct *ca;
	int index = CPUACCT_STAT_SYSTEM;
	struct pt_regs *regs = task_pt_regs(tsk);

	if (regs && user_mode(regs))
		index = CPUACCT_STAT_USER;

	rcu_read_lock();

	for (ca = task_ca(tsk); ca; ca = parent_ca(ca))
		this_cpu_ptr(ca->cpuusage)->usages[index] += cputime;

	rcu_read_unlock();
}

/*
 * Add user/system time to cpuacct.
 *
 * Note: it's the caller that updates the account of the root cgroup.
 */
void cpuacct_account_field(struct task_struct *tsk, int index, u64 val)
{
	struct cpuacct *ca;

	rcu_read_lock();
	for (ca = task_ca(tsk); ca != &root_cpuacct; ca = parent_ca(ca))
		this_cpu_ptr(ca->cpustat)->cpustat[index] += val;
	rcu_read_unlock();
}

struct cgroup_subsys cpuacct_cgrp_subsys = {
	.css_alloc	= cpuacct_css_alloc,
	.css_free	= cpuacct_css_free,
	.legacy_cftypes	= files,
	.early_init	= true,
};

extern inline struct task_group *css_tg(struct cgroup_subsys_state *css);

static struct task_group *ve_root_tg(struct task_group *tg) {
	struct cgroup *cg;

	if (!tg)
		return NULL;

	cg = cgroup_get_ve_root1(tg->css.cgroup);
	return cg ? css_tg(&cg->self) : NULL;
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
	u64 *cpustat = cpuacct_cpustat(cpuacct_css, i)->cpustat;
	u64 now = cpu_clock(i);
	u64 delta, idle, iowait, steal;

	/* root_task_group has not sched entities */
	if (tg == &root_task_group)
		return;

	iowait = se->statistics.iowait_sum;
	idle = se->statistics.sum_sleep_runtime;
	steal = se->statistics.wait_sum;

	if (idle > iowait)
		idle -= iowait;
	else
		idle = 0;

	if (se->statistics.sleep_start) {
		delta = now - se->statistics.sleep_start;
		if ((s64)delta > 0)
			idle += delta;
	} else if (se->statistics.block_start) {
		delta = now - se->statistics.block_start;
		if ((s64)delta > 0)
			iowait += delta;
	} else if (se->statistics.wait_start) {
		delta = now - se->statistics.wait_start;
		if ((s64)delta > 0)
			steal += delta;
	}

	cpustat[CPUTIME_IDLE]	= max(cpustat[CPUTIME_IDLE], idle);
	cpustat[CPUTIME_IOWAIT]	= max(cpustat[CPUTIME_IOWAIT], iowait);
	cpustat[CPUTIME_STEAL]	= steal;
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
	s64 boot_sec;
	u64 user, nice, system, idle, iowait, steal;
	struct timespec64 boottime;
	struct task_group *tg = css_tg(cpu_css);
	bool virt = !ve_is_super(get_exec_env()) && tg != &root_task_group;
	int nr_vcpus = tg_nr_cpus(tg);
	struct kernel_cpustat *kcpustat;
	unsigned long tg_nr_running = 0;
	unsigned long tg_nr_iowait = 0;
	unsigned long long tg_nr_switches = 0;

	getboottime64(&boottime);

	/*
	 * In VE0 we always show host's boottime and in VEX we show real CT
	 * start time, even across CT migrations, as we rely on userspace to
	 * set real_start_timespec for us on resume.
	 */
	boot_sec = boottime.tv_sec +
		   get_exec_env()->real_start_time / NSEC_PER_SEC;

	for_each_possible_cpu(i) {
		cpu_cgroup_update_stat(cpu_css, cpuacct_css, i);

		/* root task group has autogrouping, so this doesn't hold */
#ifdef CONFIG_FAIR_GROUP_SCHED
		tg_nr_running += tg->cfs_rq[i]->h_nr_running;
		tg_nr_iowait  += tg->cfs_rq[i]->nr_iowait;
		tg_nr_switches += tg->cfs_rq[i]->nr_switches;
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
		   (unsigned long long)boot_sec,
		   total_forks,
		   tg_nr_running,
		   tg_nr_iowait);

	return 0;
}
