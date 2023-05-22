/*
 *  include/linux/ve.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef _LINUX_VE_H
#define _LINUX_VE_H

#include <linux/types.h>
#include <linux/capability.h>
#include <linux/sysctl.h>
#include <linux/net.h>
#include <linux/vzstat.h>
#include <linux/kobject.h>
#include <linux/pid.h>
#include <linux/path.h>
#include <linux/socket.h>
#include <linux/kthread.h>
#include <linux/ve_proto.h>
#include <net/inet_frag.h>
#include <linux/cgroup.h>

struct tty_driver;
struct file_system_type;
struct veip_struct;
struct nsproxy;

struct ve_struct {
	struct cgroup_subsys_state	css;

	const char		*ve_name;

	struct list_head	ve_list;

	envid_t			veid;

	unsigned int		class_id;
	struct rw_semaphore	op_sem;
	int			is_running;
	atomic_t		suspend;
	/* see vzcalluser.h for VE_FEATURE_XXX definitions */
	__u64			features;

	struct task_struct	*ve_kthread_task;
	struct kthread_worker	ve_kthread_worker;

	struct super_block	*devpts_sb;

#define	MAX_NR_VTTY		12
	struct tty_struct	*vtty[MAX_NR_VTTY];

	struct list_head	devices;

#if defined(CONFIG_VE_NETDEV) || defined (CONFIG_VE_NETDEV_MODULE)
	struct veip_struct	*veip;
	struct net_device	*_venet_dev;
#endif

/* per VE CPU stats*/
	struct timespec		start_timespec;		/* monotonic time */
	struct timespec		real_start_timespec;	/* boot based time */
	u64			start_jiffies;	/* Deprecated */

	struct kstat_lat_pcpu_struct	sched_lat_ve;

#ifdef CONFIG_INET
	struct venet_stat       *stat;
#ifdef CONFIG_VE_IPTABLES
/* core/netfilter.c virtualization */
	__u64			ipt_mask;
	__u64			_iptables_modules;
#endif /* CONFIG_VE_IPTABLES */
#endif

	unsigned long		down_at;
	struct list_head	cleanup_list;
	unsigned long		meminfo_val;
	int _randomize_va_space;

	int			odirect_enable;

	struct nsproxy		*ve_ns;
	struct cred		*init_cred;
	struct net		*ve_netns;
	struct mutex		sync_mutex;

	struct list_head	devmnt_list;
	struct mutex		devmnt_mutex;
};

struct ve_devmnt {
	struct list_head	link;

	dev_t                   dev;
	char			*allowed_options;
	char			*hidden_options; /* balloon_ino, etc. */
};

#define VE_MEMINFO_DEFAULT      1       /* default behaviour */
#define VE_MEMINFO_SYSTEM       0       /* disable meminfo virtualization */

extern int nr_ve;
extern struct proc_dir_entry *proc_vz_dir;
extern struct proc_dir_entry *glob_proc_vz_dir;

#ifdef CONFIG_VE

void do_update_load_avg_ve(void);

extern struct ve_struct *get_ve(struct ve_struct *ve);
extern void put_ve(struct ve_struct *ve);

static inline struct ve_struct *cgroup_ve(struct cgroup *cgroup)
{
	return container_of(cgroup_subsys_state(cgroup, ve_subsys_id),
			struct ve_struct, css);
}

extern unsigned long long ve_relative_clock(struct timespec * ts);

#ifdef CONFIG_VTTYS
extern int vtty_open_master(int veid, int idx);
extern struct tty_driver *vtty_driver;
#else
static inline int vtty_open_master(int veid, int idx) { return -ENODEV; }
#endif

void ve_stop_ns(struct pid_namespace *ns);
void ve_exit_ns(struct pid_namespace *ns);

#else	/* CONFIG_VE */
#define ve_utsname	system_utsname
#define get_ve(ve)	(NULL)
#define put_ve(ve)	do { } while (0)

static inline void ve_stop_ns(struct pid_namespace *ns) { }
static inline void ve_exit_ns(struct pid_namespace *ns) { }

#endif	/* CONFIG_VE */

#endif /* _LINUX_VE_H */
