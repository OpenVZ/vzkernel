/*
 *  include/linux/ve.h
 *
 *  Copyright (c) 2005-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
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
#include <linux/kmapset.h>

struct tty_driver;
struct file_system_type;
struct veip_struct;
struct nsproxy;
struct user_namespace;
struct cn_private;
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

	struct task_struct	*ve_umh_task;
	struct kthread_worker	ve_umh_worker;

	struct super_block	*dev_sb;
	struct super_block	*devpts_sb;

#if IS_ENABLED(CONFIG_BINFMT_MISC)
	struct binfmt_misc	*binfmt_misc;
#endif

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
	atomic_t		netns_avail_nr;
	int			netns_max_nr;
	atomic_t		netif_avail_nr;
	int			netif_max_nr;
	atomic_t		arp_neigh_nr;
	atomic_t		nd_neigh_nr;
	atomic_t		mnt_nr;	/* number of present VE mounts */
#ifdef CONFIG_COREDUMP
	char 			core_pattern[CORENAME_MAX_SIZE];
#endif
#ifdef CONFIG_CONNECTOR
	struct cn_private	*cn;
#endif
	struct kmapset_key	sysfs_perms_key;

	struct workqueue_struct	*wq;
};

struct ve_devmnt {
	struct list_head	link;

	dev_t                   dev;
	char			*allowed_options;
	char			*hidden_options; /* balloon_ino, etc. */
};

#define NETNS_MAX_NR_DEFAULT	256	/* number of net-namespaces per-VE */
#define NETIF_MAX_NR_DEFAULT	256	/* number of net-interfaces per-VE */

#define VE_MEMINFO_DEFAULT      1       /* default behaviour */
#define VE_MEMINFO_SYSTEM       0       /* disable meminfo virtualization */

#define capable_setveid() \
	(ve_is_super(get_exec_env()) && capable(CAP_SYS_ADMIN))

extern int nr_ve;
extern struct proc_dir_entry *proc_vz_dir;
extern struct cgroup_subsys ve_subsys;

extern unsigned int sysctl_ve_mount_nr;

#ifdef CONFIG_VE
#define ve_uevent_seqnum       (get_exec_env()->_uevent_seqnum)

extern int vz_security_family_check(struct net *net, int family, int type);
extern int vz_security_protocol_check(struct net *net, int protocol);

extern struct task_struct *kthread_create_on_node_ve(struct ve_struct *ve,
					int (*threadfn)(void *data),
					void *data, int node,
					const char namefmt[], ...);

#define kthread_create_ve(ve, threadfn, data, namefmt, arg...) \
	kthread_create_on_node_ve(ve, threadfn, data, -1, namefmt, ##arg)

#define kthread_run_ve(ve, threadfn, data, namefmt, ...)		   \
({									   \
	struct task_struct *__k						   \
		= kthread_create_ve(ve, threadfn, data, namefmt, ## __VA_ARGS__); \
	if (!IS_ERR(__k))						   \
		wake_up_process(__k);					   \
	__k;								   \
})

struct subprocess_info;
extern int call_usermodehelper_fns_ve(struct ve_struct *ve,
	char *path, char **argv, char **envp, int wait,
	int (*init)(struct subprocess_info *info, struct cred *new),
	void (*cleanup)(struct subprocess_info *), void *data);

static inline int
call_usermodehelper_ve(struct ve_struct *ve, char *path, char **argv,
		       char **envp, int wait)
{
	return call_usermodehelper_fns_ve(ve, path, argv, envp, wait,
				       NULL, NULL, NULL);
}
void do_update_load_avg_ve(void);

extern struct ve_struct *get_ve(struct ve_struct *ve);
extern void put_ve(struct ve_struct *ve);

struct cgroup_subsys_state *ve_get_init_css(struct ve_struct *ve, int subsys_id);

static inline struct ve_struct *cgroup_ve(struct cgroup *cgroup)
{
	return container_of(cgroup_subsys_state(cgroup, ve_subsys_id),
			struct ve_struct, css);
}

static inline void ve_try_set_task_start_time(struct ve_struct *ve,
	struct task_struct *t)
{
	struct timespec host_uptime;

	/*
	 * mitigate memory access reordering risks by doing double check,
	 * 'is_running' could be read as 1 before we see
	 * 'real_start_timespec' updated here. If it's still 0,
	 * we know 'is_running' is being modified right NOW in
	 * parallel so it's safe to say that start time is also 0
	 */
	if (!ve->is_running || !timespec_to_ns(&ve->real_start_timespec)) {
		t->real_start_time_ct.tv_sec = 0;
		t->real_start_time_ct.tv_nsec = 0;
	} else {
		do_posix_clock_monotonic_gettime(&host_uptime);
		monotonic_to_bootbased(&host_uptime);
		t->real_start_time_ct = timespec_sub(host_uptime,
			ve->real_start_timespec);
	}
}

extern unsigned long long ve_relative_clock(struct timespec * ts);
extern void monotonic_abs_to_ve(clockid_t which_clock, struct timespec *tp);
extern void monotonic_ve_to_abs(clockid_t which_clock, struct timespec *tp);

void ve_stop_ns(struct pid_namespace *ns);
void ve_exit_ns(struct pid_namespace *ns);

static inline struct ve_struct *css_to_ve(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct ve_struct, css) : NULL;
}

extern bool current_user_ns_initial(void);
struct user_namespace *ve_init_user_ns(void);

int ve_net_hide_sysctl(struct net *net);

#ifdef CONFIG_TTY
extern struct tty_driver *vtty_driver(dev_t dev, int *index);
extern struct tty_driver *vtty_console_driver(int *index);
extern int vtty_open_master(envid_t veid, int idx);
extern void vtty_release(struct tty_struct *tty, struct tty_struct *o_tty,
			 int *tty_closing, int *o_tty_closing);
extern bool vtty_is_master(struct tty_struct *tty);
#endif /* CONFIG_TTY */

extern struct cgroup *cgroup_get_ve_root(struct cgroup *cgrp);

#else	/* CONFIG_VE */

#define ve_uevent_seqnum uevent_seqnum

static inline int vz_security_family_check(struct net *net, int family, int type) { return 0; }
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

#define kthread_create_on_node_ve(ve, threadfn, data, node, namefmt...)	\
	kthread_create_on_node_ve(threadfn, data, node, namefmt...)

static inline void monotonic_abs_to_ve(clockid_t which_clock,
				struct timespec *tp) { }
static inline void monotonic_ve_to_abs(clockid_t which_clock,
				struct timepsec *tp) { }

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
