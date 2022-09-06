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
#include <linux/cgroup.h>
#include <linux/kmapset.h>
#include <linux/kthread.h>
#include <linux/vzstat.h>
#include <asm/vdso.h>

struct nsproxy;
struct user_namespace;

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
	u64			start_boottime;		/* boot based time */
	u64			start_jiffies;		/* Deprecated */

	struct nsproxy __rcu	*ve_ns;
	struct cred		*init_cred;

	/* see vzcalluser.h for VE_FEATURE_XXX definitions */
	__u64			features;

	void			*log_state;
#define VE_LOG_BUF_LEN		4096

	struct kstat_lat_pcpu_struct    sched_lat_ve;
	int			odirect_enable;

#if IS_ENABLED(CONFIG_BINFMT_MISC)
	struct binfmt_misc	*binfmt_misc;
#endif

	struct kmapset_key	sysfs_perms_key;

	atomic_t		netns_avail_nr;
	int			netns_max_nr;

	u64			_uevent_seqnum;

	int			_randomize_va_space;

	unsigned long		meminfo_val;

	atomic_t		mnt_nr; /* number of present VE mounts */

	struct kthread_worker	*kthreadd_worker;
	struct task_struct	*kthreadd_task;

	struct kthread_worker	umh_worker;
	struct task_struct	*umh_task;

	struct vdso_image	*vdso_64;
	struct vdso_image	*vdso_32;

	struct list_head	devmnt_list;
	struct mutex		devmnt_mutex;
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

extern unsigned int sysctl_ve_mount_nr;

#ifdef CONFIG_VE
extern struct ve_struct *get_ve(struct ve_struct *ve);
extern void put_ve(struct ve_struct *ve);

void ve_stop_ns(struct pid_namespace *ns);
void ve_exit_ns(struct pid_namespace *ns);

static inline struct ve_struct *css_to_ve(struct cgroup_subsys_state *css)
{
	return css ? container_of(css, struct ve_struct, css) : NULL;
}

extern struct cgroup_subsys_state *ve_get_init_css(struct ve_struct *ve, int subsys_id);

#define ve_feature_set(ve, f)			\
	!!((ve)->features & VE_FEATURE_##f)

extern bool current_user_ns_initial(void);
struct user_namespace *ve_init_user_ns(void);

extern struct cgroup *cgroup_get_ve_root1(struct cgroup *cgrp);

#define ve_uevent_seqnum       (get_exec_env()->_uevent_seqnum)

extern int vz_security_family_check(struct net *net, int family, int type);
extern int vz_security_protocol_check(struct net *net, int protocol);

int ve_net_hide_sysctl(struct net *net);

#else	/* CONFIG_VE */
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

static inline struct cgroup *cgroup_get_ve_root1(struct cgroup *cgrp)
{
	return NULL;
}
#define ve_uevent_seqnum uevent_seqnum

static inline int vz_security_family_check(struct net *net, int family, int type) { return 0; }
static inline int vz_security_protocol_check(struct net *net, int protocol) { return 0; }

#endif	/* CONFIG_VE */

struct seq_file;

#if defined(CONFIG_VE) && defined(CONFIG_CGROUP_SCHED)
int ve_show_loadavg(struct ve_struct *ve, struct seq_file *p);
#else
static inline int ve_show_loadavg(struct ve_struct *ve, struct seq_file *p) { return -ENOSYS; }
#endif

#endif /* _LINUX_VE_H */
