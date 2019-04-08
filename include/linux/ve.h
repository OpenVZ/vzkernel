/*
 *  include/linux/ve.h
 *
 *  Copyright (c) 2000-2017 Virtuozzo International GmbH.  All rights reserved.
 *
 */

#ifndef _LINUX_VE_H
#define _LINUX_VE_H

#include <linux/types.h>
#include <linux/ve_proto.h>
#include <linux/cgroup.h>
#include <linux/vzstat.h>
#include <linux/kmapset.h>
#include <linux/kthread.h>
#include <linux/binfmts.h>

struct nsproxy;
struct veip_struct;
struct user_namespace;
struct super_block;
struct tty_driver;
struct tty_struct;
struct cn_private;

struct ve_struct {
	struct cgroup_subsys_state	css;

	const char		*ve_name;

	struct list_head	ve_list;

	envid_t			veid;
	int			is_running;
	u8			is_pseudosuper:1;

	struct rw_semaphore	op_sem;

	/* per VE CPU stats*/
	u64			start_time;		/* monotonic time */
	u64			real_start_time;	/* boot based time */
	u64			start_jiffies;		/* Deprecated */

	struct nsproxy __rcu	*ve_ns;
	/* Please, use ve_net_lock() and ve_net_unlock() instead of ve_netns */
#define ve_netns		[:|||||||:]
	struct cred		*init_cred;

#if defined(CONFIG_VE_NETDEV) || defined (CONFIG_VE_NETDEV_MODULE)
	struct veip_struct	*veip;
	struct net_device	*venet_dev;
#endif

/* per VE CPU stats*/
	struct timespec		start_timespec;		/* monotonic time */
	struct timespec		real_start_timespec;	/* boot based time */

	/* see vzcalluser.h for VE_FEATURE_XXX definitions */
	__u64			features;

	void			*log_state;
#define VE_LOG_BUF_LEN		4096

	int			_randomize_va_space;

#ifdef CONFIG_VE_IPTABLES
	__u64			ipt_mask;
#endif

	u64			_uevent_seqnum;

	struct kstat_lat_pcpu_struct	sched_lat_ve;

	struct super_block	*dev_sb;

	struct kmapset_key	sysfs_perms_key;

	atomic_t		netns_avail_nr;
	int			netns_max_nr;

	struct kthread_worker	*kthreadd_worker;
	struct task_struct	*kthreadd_task;

	struct kthread_worker	umh_worker;
	struct task_struct	*umh_task;

	unsigned long		meminfo_val;
#ifdef CONFIG_COREDUMP
	char			core_pattern[CORENAME_MAX_SIZE];
#endif
#ifdef CONFIG_CONNECTOR
	struct cn_private	*cn;
#endif
};

#define VE_MEMINFO_DEFAULT	1	/* default behaviour */
#define VE_MEMINFO_SYSTEM	0	/* disable meminfo virtualization */

extern int nr_ve;

#define NETNS_MAX_NR_DEFAULT	256	/* number of net-namespaces per-VE */

#define capable_setveid() \
	(ve_is_super(get_exec_env()) && capable(CAP_SYS_ADMIN))

#ifdef CONFIG_VE
extern struct ve_struct *get_ve(struct ve_struct *ve);
extern void put_ve(struct ve_struct *ve);

void ve_stop_ns(struct pid_namespace *ns);
void ve_exit_ns(struct pid_namespace *ns);

#ifdef CONFIG_TTY
#define MAX_NR_VTTY_CONSOLES	(12)
extern struct tty_driver *vtty_driver(dev_t dev, int *index);
extern struct tty_driver *vtty_console_driver(int *index);
extern int vtty_open_master(envid_t veid, int idx);
extern void vtty_release_init(struct tty_struct *tty, struct tty_struct *o_tty);
extern void vtty_release_fini(struct tty_struct *tty, struct tty_struct *o_tty);
extern bool vtty_is_master(struct tty_struct *tty);
#endif /* CONFIG_TTY */

static inline struct ve_struct *css_to_ve(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct ve_struct, css) : NULL;
}

extern struct cgroup_subsys_state *ve_get_init_css(struct ve_struct *ve, int subsys_id);

#define ve_feature_set(ve, f)			\
	!!((ve)->features & VE_FEATURE_##f)

extern bool current_user_ns_initial(void);
struct user_namespace *ve_init_user_ns(void);

#define ve_uevent_seqnum       (get_exec_env()->_uevent_seqnum)

extern int vz_security_family_check(struct net *net, int family);
extern int vz_security_protocol_check(struct net *net, int protocol);

int ve_net_hide_sysctl(struct net *net);

#else	/* CONFIG_VE */
#define get_ve(ve)	(NULL)
#define put_ve(ve)	do { } while (0)

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

#define ve_uevent_seqnum uevent_seqnum

static inline int vz_security_family_check(struct net *net, int family) { return 0; }
static inline int vz_security_protocol_check(struct net *net, int protocol) { return 0; }

#endif	/* CONFIG_VE */

#endif /* _LINUX_VE_H */
