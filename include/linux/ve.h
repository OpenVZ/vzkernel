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
#include <linux/kmapset.h>

struct tty_driver;
struct file_system_type;
struct veip_struct;
struct ve_monitor;
struct nsproxy;
struct user_namespace;
extern struct user_namespace init_user_ns;

struct ve_struct {
	struct cgroup_subsys_state	css;

	const char		*ve_name;

	struct list_head	ve_list;

	envid_t			veid;
	bool			legacy;	/* created using the legacy API
					   (vzctl ioctl - see do_env_create) */

	unsigned int		class_id;
	struct rw_semaphore	op_sem;
	int			is_running;
	int			is_locked;
	int			is_pseudosuper;
	atomic_t		suspend;
	/* see vzcalluser.h for VE_FEATURE_XXX definitions */
	__u64			features;

	struct task_struct	*ve_kthread_task;
	struct kthread_worker	ve_kthread_worker;

	struct task_struct	*ve_umh_task;
	struct kthread_worker	ve_umh_worker;

/* VE's root */
	struct path		root_path;

	struct super_block	*dev_sb;
	struct super_block	*devpts_sb;

#if IS_ENABLED(CONFIG_BINFMT_MISC)
	struct binfmt_misc	*binfmt_misc;
#endif

#ifdef CONFIG_LEGACY_PTYS
	struct tty_driver	*pty_driver, *pty_slave_driver;
#endif

#ifdef CONFIG_TTY
	struct device		*consdev;
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
	u32			jiffies_fixup;

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
	unsigned char		disable_net;
	struct ve_monitor	*monitor;
	struct proc_dir_entry	*monitor_proc;
	unsigned long		meminfo_val;
	int _randomize_va_space;

	int			odirect_enable;
	int			fsync_enable;

	u64			_uevent_seqnum;
	struct nsproxy __rcu	*ve_ns;
	struct cred		*init_cred;
	struct net		*ve_netns;
	struct mutex		sync_mutex;

	struct list_head	devmnt_list;
	struct mutex		devmnt_mutex;

	struct kmapset_key	ve_sysfs_perms;

#ifdef CONFIG_AIO
	spinlock_t		aio_nr_lock;
	unsigned long		aio_nr;
	unsigned long		aio_max_nr;
#endif
	/* Number of mounts. May become unbalanced if VE0 mounts something
	 * and the VE unmounts it. This is acceptable.
	 */
	int			mnt_nr;
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
extern struct cgroup_subsys ve_subsys;

extern unsigned int sysctl_ve_mount_nr;

#ifdef CONFIG_VE_IPTABLES
extern __u64 ve_setup_iptables_mask(__u64 init_mask);
#endif

#ifdef CONFIG_VE
#define ve_uevent_seqnum       (get_exec_env()->_uevent_seqnum)

extern int vz_compat;

extern struct kobj_ns_type_operations ve_ns_type_operations;
extern struct kobject * kobject_create_and_add_ve(const char *name,
						struct kobject *parent);

extern const void *ve_namespace(struct device *dev);

extern struct kmapset_set ve_sysfs_perms;

extern int vz_security_family_check(struct net *net, int family);
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

static inline struct ve_struct *cgroup_ve(struct cgroup *cgroup)
{
	return container_of(cgroup_subsys_state(cgroup, ve_subsys_id),
			struct ve_struct, css);
}

extern unsigned long long ve_relative_clock(struct timespec * ts);
extern void monotonic_abs_to_ve(clockid_t which_clock, struct timespec *tp);
extern void monotonic_ve_to_abs(clockid_t which_clock, struct timespec *tp);

void ve_stop_ns(struct pid_namespace *ns);
void ve_exit_ns(struct pid_namespace *ns);
int ve_start_container(struct ve_struct *ve);

extern bool current_user_ns_initial(void);
struct user_namespace *ve_init_user_ns(void);

#ifdef CONFIG_TTY
#define MAX_NR_VTTY_CONSOLES	(12)
extern struct tty_driver *vtty_driver(dev_t dev, int *index);
extern struct tty_driver *vtty_console_driver(int *index);
extern int vtty_open_master(envid_t veid, int idx);
extern void vtty_release(struct tty_struct *tty, struct tty_struct *o_tty,
			 int *tty_closing, int *o_tty_closing);
#endif /* CONFIG_TTY */

static inline int ve_mount_allowed(void)
{
	struct ve_struct *ve = get_exec_env();

	return ve_is_super(ve) || ve->mnt_nr < sysctl_ve_mount_nr;
}

static inline void ve_mount_nr_inc(void)
{
	get_exec_env()->mnt_nr++;
}

static inline void ve_mount_nr_dec(void)
{
	get_exec_env()->mnt_nr--;
}

#else	/* CONFIG_VE */

#define ve_uevent_seqnum uevent_seqnum

#define vz_compat	(0)

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

#define kthread_create_on_node_ve(ve, threadfn, data, node, namefmt...)	\
	kthread_create_on_node_ve(threadfn, data, node, namefmt...)

#define kobject_create_and_add_ve		kobject_create_and_add

static const void *ve_namespace(struct device *dev) { return NULL; }

static inline void monotonic_abs_to_ve(clockid_t which_clock,
				struct timespec *tp) { }
static inline void monotonic_ve_to_abs(clockid_t which_clock,
				struct timepsec *tp) { }

static inline int ve_mount_allowed(void) { return 1; }
static inline void ve_mount_nr_inc(void) { }
static inline void ve_mount_nr_dec(void) { }
#endif	/* CONFIG_VE */

#endif /* _LINUX_VE_H */
