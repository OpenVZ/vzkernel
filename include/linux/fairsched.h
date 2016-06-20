/*
 *  include/linux/fairsched.h
 *
 *  Fair Scheduler
 *
 *  Copyright (c) 2000-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *
 */

#ifndef __LINUX_FAIRSCHED_H__
#define __LINUX_FAIRSCHED_H__

#include <linux/cgroup.h>
#include <linux/seq_file.h>

#include <uapi/linux/fairsched.h>

#ifdef __KERNEL__

struct kernel_cpustat;

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

#endif /* CONFIG_VZ_FAIRSCHED */

#endif /* __KERNEL__ */

#endif /* __LINUX_FAIRSCHED_H__ */
