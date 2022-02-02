/*
 *  include/linux/ve.h
 *
 *  Copyright (c) 2005-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef _LINUX_VE_H
#define _LINUX_VE_H

#include <linux/types.h>
#include <linux/ve_proto.h>
#include <linux/vzstat.h>
#include <linux/cgroup.h>
#include <linux/kmapset.h>
#include <linux/kthread.h>
#include <linux/binfmts.h>
#include <linux/tty_driver.h>
#include <asm/vdso.h>
#include <linux/time_namespace.h>
#include <linux/binfmts.h>

struct nsproxy;
struct user_namespace;
struct cn_private;
struct vfsmount;

struct ve_struct {
	struct cgroup_subsys_state	css;

	const char		*ve_name;

	struct list_head	ve_list;

	envid_t			veid;
	int			is_running;
	u8			is_pseudosuper:1;

	struct rw_semaphore	op_sem;

	/* per VE CPU stats*/
	u64			start_jiffies;		/* Deprecated */

	struct nsproxy __rcu	*ve_ns;
	struct cred		*init_cred;

	/* see vzcalluser.h for VE_FEATURE_XXX definitions */
	__u64			features;

	void			*log_state;
#define VE_LOG_BUF_LEN		4096

	struct kstat_lat_pcpu_struct    sched_lat_ve;
	int			odirect_enable;

	int			fsync_enable;

#if IS_ENABLED(CONFIG_BINFMT_MISC)
	struct binfmt_misc	*binfmt_misc;
#endif

	struct kmapset_key	sysfs_perms_key;

	atomic_t		netns_avail_nr;
	int			netns_max_nr;

	atomic_t		netif_avail_nr;
	int			netif_max_nr;

	u64			_uevent_seqnum;

	int			_randomize_va_space;

	atomic_t		arp_neigh_nr;
	atomic_t		nd_neigh_nr;
	unsigned long		meminfo_val;

	atomic_t		mnt_nr; /* number of present VE mounts */

#ifdef CONFIG_COREDUMP
	char			core_pattern[CORENAME_MAX_SIZE];
#endif
#ifdef CONFIG_CONNECTOR
	struct cn_private	*cn;
#endif

	struct kthread_worker	*kthreadd_worker;
	struct task_struct	*kthreadd_task;

	struct kthread_worker	umh_worker;
	struct task_struct	*umh_task;

	struct vdso_image	*vdso_64;
	struct vdso_image	*vdso_32;

	struct list_head	devmnt_list;
	struct mutex		devmnt_mutex;

#ifdef CONFIG_AIO
	spinlock_t		aio_nr_lock;
	unsigned long		aio_nr;
	unsigned long		aio_max_nr;
#endif
	/*
	 * cgroups, that want to notify about becoming
	 * empty, are linked to this release_list.
	 */
	struct list_head	release_list;
	spinlock_t		release_list_lock;

	/* Should take rcu_read_lock and check ve->is_running before queue */
	struct workqueue_struct	*wq;
	struct work_struct	release_agent_work;

	/*
	 * List of data, private for each root cgroup in
	 * ve's css_set.
	 */
	struct list_head	ra_data_list;
	spinlock_t		ra_data_lock;

	struct vfsmount		*devtmpfs_mnt;
};

struct ve_devmnt {
	struct list_head	link;

	dev_t                   dev;
	char			*allowed_options;
	char			*hidden_options; /* balloon_ino, etc. */
};

#define VE_MEMINFO_DEFAULT	1	/* default behaviour */
#define VE_MEMINFO_SYSTEM	0	/* disable meminfo virtualization */

extern int nr_ve;

#define NETNS_MAX_NR_DEFAULT	256	/* number of net-namespaces per-VE */
#define NETIF_MAX_NR_DEFAULT	256	/* number of net-interfaces per-VE */

extern unsigned int sysctl_ve_mount_nr;

#ifdef CONFIG_VE
void ve_add_to_release_list(struct cgroup *cgrp);
void ve_rm_from_release_list(struct cgroup *cgrp);

const char *ve_ra_data_get_path_locked(struct ve_struct *ve,
				       struct cgroup_root *cgroot);
int ve_ra_data_set(struct ve_struct *ve, struct cgroup_root *cgroot,
		   const char *release_agent);
void cgroot_ve_cleanup_ra_data(struct cgroup_root *cgroot);

extern struct ve_struct *get_ve(struct ve_struct *ve);
extern void put_ve(struct ve_struct *ve);

void ve_stop_ns(struct pid_namespace *ns);
void ve_exit_ns(struct pid_namespace *ns);
bool ve_check_trusted_exec(struct file *file, struct filename *name);
bool ve_check_trusted_mmap(struct file *file);

static inline struct ve_struct *css_to_ve(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct ve_struct, css) : NULL;
}

extern struct cgroup_subsys_state *ve_get_init_css(struct ve_struct *ve, int subsys_id);

static inline struct time_namespace *ve_get_time_ns(struct ve_struct *ve)
{
	struct nsproxy *ve_ns;
	struct time_namespace *time_ns;

	rcu_read_lock();
	ve_ns = rcu_dereference(ve->ve_ns);
	time_ns = ve_ns ? get_time_ns(ve_ns->time_ns) : NULL;
	rcu_read_unlock();

	return time_ns;
}

extern u64 ve_get_monotonic(struct ve_struct *ve);
extern u64 ve_get_uptime(struct ve_struct *ve);

static inline void ve_set_task_start_time(struct ve_struct *ve,
					  struct task_struct *t)
{
	t->start_boottime_ct = ve_get_uptime(ve);
}

#define ve_feature_set(ve, f)			\
	!!((ve)->features & VE_FEATURE_##f)

extern bool current_user_ns_initial(void);
struct user_namespace *ve_init_user_ns(void);

#ifdef CONFIG_TTY
extern struct tty_driver *vtty_driver(dev_t dev, int *index);
extern struct tty_driver *vtty_console_driver(int *index);
extern int vtty_open_master(envid_t veid, int idx);
extern void vtty_release(struct tty_struct *tty, struct tty_struct *o_tty,
			int *tty_closing, int *o_tty_closing);
extern bool vtty_is_master(struct tty_struct *tty);
extern void vtty_alloc_tty_struct(const struct tty_driver *driver,
				  struct tty_struct *o_tty);
#endif /* CONFIG_TTY */

extern struct cgroup *cgroup_ve_root1(struct cgroup *cgrp);
extern struct cgroup_subsys_state *css_ve_root1(
		struct cgroup_subsys_state *css);

#define ve_uevent_seqnum       (get_exec_env()->_uevent_seqnum)

extern int vz_security_family_check(struct net *net, int family, int type);
extern int vz_security_protocol_check(struct net *net, int protocol);

int ve_net_hide_sysctl(struct net *net);

extern struct net *ve_get_net_ns(struct ve_struct* ve);
extern bool is_ve_init_net(const struct net *net);

#else	/* CONFIG_VE */
#include <linux/init_task.h>
#define get_ve(ve)	((void)(ve), NULL)
#define put_ve(ve)	do { (void)(ve); } while (0)

static inline void ve_stop_ns(struct pid_namespace *ns) { }
static inline void ve_exit_ns(struct pid_namespace *ns) { }

#define ve_feature_set(ve, f)		{ true; }

static inline bool current_user_ns_initial(void)
{
	return current_user_ns() == init_cred.user_ns;
}

static inline struct user_namespace *ve_init_user_ns(void)
{
	return &init_user_ns;
}

static inline bool is_ve_init_net(const struct net *net)
{
	return net_eq(net, &init_net);
}

static inline struct cgroup *cgroup_ve_root1(struct cgroup *cgrp)
{
	return NULL;
}
static inline struct cgroup_subsys_state *css_ve_root1(
		struct cgroup_subsys_state *css)
{
	return NULL;
}

#define ve_uevent_seqnum uevent_seqnum

static inline int vz_security_family_check(struct net *net, int family, int type) { return 0; }
static inline int vz_security_protocol_check(struct net *net, int protocol) { return 0; }

#endif	/* CONFIG_VE */

struct seq_file;

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
