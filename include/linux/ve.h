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
#include <linux/binfmts.h>

struct tty_driver;
struct file_system_type;
struct veip_struct;
struct nsproxy;
struct user_namespace;
extern struct user_namespace init_user_ns;

struct ve_struct {
	struct cgroup_subsys_state	css;

	const char		*ve_name;

	struct list_head	ve_list;

	envid_t			veid;

	unsigned int		class_id;
	struct rw_semaphore	op_sem;
	int			is_running;
	int			is_pseudosuper;
	atomic_t		suspend;
	/* see vzcalluser.h for VE_FEATURE_XXX definitions */
	__u64			features;

	struct task_struct	*ve_kthread_task;
	struct kthread_worker	ve_kthread_worker;

	struct super_block	*dev_sb;
	struct super_block	*devpts_sb;

#if IS_ENABLED(CONFIG_BINFMT_MISC)
	struct binfmt_misc	*binfmt_misc;
#endif

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

	void			*log_state;
#define VE_LOG_BUF_LEN		4096

	unsigned long		down_at;
	struct list_head	cleanup_list;
	unsigned long		meminfo_val;
	int _randomize_va_space;

	int			odirect_enable;
	int			fsync_enable;

	u64			_uevent_seqnum;
	struct nsproxy __rcu	*ve_ns;
	struct task_struct	*init_task;
	struct cred		*init_cred;
	struct net		*ve_netns;

	struct list_head	devmnt_list;
	struct mutex		devmnt_mutex;

#ifdef CONFIG_AIO
	spinlock_t		aio_nr_lock;
	unsigned long		aio_nr;
	unsigned long		aio_max_nr;
#endif
	atomic_t		netif_avail_nr;
	int			netif_max_nr;
	atomic_t		mnt_nr;	/* number of present VE mounts */
#ifdef CONFIG_COREDUMP
	char 			core_pattern[CORENAME_MAX_SIZE];
#endif
};

struct ve_devmnt {
	struct list_head	link;

	dev_t                   dev;
	char			*allowed_options;
	char			*hidden_options; /* balloon_ino, etc. */
};

#define NETIF_MAX_NR_DEFAULT	256	/* number of net-interfaces per-VE */

#define VE_MEMINFO_DEFAULT      1       /* default behaviour */
#define VE_MEMINFO_SYSTEM       0       /* disable meminfo virtualization */

extern int nr_ve;
extern struct proc_dir_entry *proc_vz_dir;
extern struct cgroup_subsys ve_subsys;

extern unsigned int sysctl_ve_mount_nr;

#ifdef CONFIG_VE
#define ve_uevent_seqnum       (get_exec_env()->_uevent_seqnum)

extern int vz_security_family_check(struct net *net, int family);
extern int vz_security_protocol_check(struct net *net, int protocol);

void do_update_load_avg_ve(void);

extern struct ve_struct *get_ve(struct ve_struct *ve);
extern void put_ve(struct ve_struct *ve);

struct cgroup_subsys_state *ve_get_init_css(struct ve_struct *ve, int subsys_id);

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

extern bool current_user_ns_initial(void);
struct user_namespace *ve_init_user_ns(void);

extern struct cgroup *cgroup_get_ve_root(struct cgroup *cgrp);

#else	/* CONFIG_VE */

#define ve_uevent_seqnum uevent_seqnum

static inline int vz_security_family_check(struct net *net, int family) { return 0; }
static inline int vz_security_protocol_check(struct net *net, int protocol) { return 0; }

#define ve_utsname	system_utsname
#define get_ve(ve)	(NULL)
#define put_ve(ve)	do { } while (0)

static inline void ve_stop_ns(struct pid_namespace *ns) { }
static inline void ve_exit_ns(struct pid_namespace *ns) { }

static inline bool current_user_ns_initial(void)
{
	return current_user_ns() == init_cred.user_ns;
}

static inline struct user_namespace *ve_init_user_ns(void)
{
	return &init_user_ns;
}

static inline struct cgroup *cgroup_get_ve_root(struct cgroup *cgrp)
{
	return NULL;
}
#endif	/* CONFIG_VE */

struct seq_file;
struct kernel_cpustat;

#if defined(CONFIG_VE) && defined(CONFIG_CGROUP_SCHED)
int ve_show_cpu_stat(struct ve_struct *ve, struct seq_file *p);
int ve_show_loadavg(struct ve_struct *ve, struct seq_file *p);
int ve_get_cpu_avenrun(struct ve_struct *ve, unsigned long *avenrun);
int ve_get_cpu_stat(struct ve_struct *ve, struct kernel_cpustat *kstat);
#else
static inline int ve_show_cpu_stat(struct ve_struct *ve, struct seq_file *p) { return -ENOSYS; }
static inline int ve_show_loadavg(struct ve_struct *ve, struct seq_file *p) { return -ENOSYS; }
static inline int ve_get_cpu_avenrun(struct ve_struct *ve, unsigned long *avenrun) { return -ENOSYS; }
static inline int ve_get_cpu_stat(struct ve_struct *ve, struct kernel_cpustat *kstat) { return -ENOSYS; }
#endif

#endif /* _LINUX_VE_H */
