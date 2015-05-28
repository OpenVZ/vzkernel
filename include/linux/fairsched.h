/*
 * Fair Scheduler
 *
 * Copyright (C) 2000-2008  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __LINUX_FAIRSCHED_H__
#define __LINUX_FAIRSCHED_H__

#include <linux/cgroup.h>
#include <linux/seq_file.h>

#include <uapi/linux/fairsched.h>

#ifdef __KERNEL__

#ifdef CONFIG_VZ_FAIRSCHED

#define FSCHWEIGHT_MAX		((1 << 16) - 1)
#define FSCHRATE_SHIFT		10
#define FSCH_TIMESLICE		16

/******************************************************************************
 * cfs group shares = FSCHWEIGHT_BASE / fairsched weight
 *
 * vzctl cpuunits default 1000
 * cfs shares default value is 1024 (see init_task_group_load in sched.c)
 * cpuunits = 1000 --> weight = 500000 / cpuunits = 500 --> shares = 1024
 *				^--- from vzctl
 * weight in 1..65535  -->  shares in 7..512000
 * shares should be >1 (see comment in sched_group_set_shares function)
 *****************************************************************************/

#define FSCHWEIGHT_BASE		512000UL

asmlinkage long sys_fairsched_mknod(unsigned int parent, unsigned int weight,
				   unsigned int newid);
asmlinkage long sys_fairsched_rmnod(unsigned int id);
asmlinkage long sys_fairsched_mvpr(pid_t pid, unsigned int id);
asmlinkage long sys_fairsched_vcpus(unsigned int id, unsigned int vcpus);
asmlinkage long sys_fairsched_chwt(unsigned int id, unsigned int weight);
asmlinkage long sys_fairsched_rate(unsigned int id, int op, unsigned int rate);
asmlinkage long sys_fairsched_cpumask(unsigned int id, unsigned int len,
				      unsigned long __user *user_mask_ptr);
asmlinkage long sys_fairsched_nodemask(unsigned int id, unsigned int len,
				       unsigned long __user *user_mask_ptr);

int fairsched_new_node(int id, unsigned int vcpus);
int fairsched_move_task(int id, struct task_struct *tsk);
void fairsched_drop_node(int id, int leave);

int fairsched_get_cpu_stat(const char *name, struct kernel_cpustat *kstat);

int cpu_cgroup_get_avenrun(struct cgroup *cgrp, unsigned long *avenrun);
int fairsched_get_cpu_avenrun(const char *name, unsigned long *avenrun);

struct cftype;
int cpu_cgroup_proc_stat(struct cgroup *cgrp, struct cftype *cft,
				struct seq_file *p);
int fairsched_show_stat(const char *name, struct seq_file *p);

#else /* CONFIG_VZ_FAIRSCHED */

static inline int fairsched_new_node(int id, unsigned int vcpus) { return 0; }
static inline int fairsched_move_task(int id, struct task_struct *tsk) { return 0; }
static inline void fairsched_drop_node(int id, int leave) { }
static inline int fairsched_show_stat(const char *name, struct seq_file *p) { return -ENOSYS; }
static inline int fairsched_get_cpu_avenrun(const char *name, unsigned long *avenrun) { return -ENOSYS; }
static inline int fairsched_get_cpu_stat(const char *name, struct kernel_cpustat *kstat) { return -ENOSYS; }

#endif /* CONFIG_VZ_FAIRSCHED */

struct kernel_cpustat;
void cpu_cgroup_get_stat(struct cgroup *cgrp, struct kernel_cpustat *kstat);

#endif /* __KERNEL__ */

#endif /* __LINUX_FAIRSCHED_H__ */
