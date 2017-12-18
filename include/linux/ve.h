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

struct nsproxy;
struct veip_struct;

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

	/* see vzcalluser.h for VE_FEATURE_XXX definitions */
	__u64			features;
};

extern int nr_ve;

#define capable_setveid() \
	(ve_is_super(get_exec_env()) && capable(CAP_SYS_ADMIN))

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

extern struct cgroup *cgroup_get_ve_root1(struct cgroup *cgrp);

#else	/* CONFIG_VE */
#define get_ve(ve)	(NULL)
#define put_ve(ve)	do { } while (0)

static inline void ve_stop_ns(struct pid_namespace *ns) { }
static inline void ve_exit_ns(struct pid_namespace *ns) { }

#define ve_feature_set(ve, f)		{ true; }

static inline struct cgroup *cgroup_get_ve_root1(struct cgroup *cgrp)
{
	return NULL;
}
#endif	/* CONFIG_VE */

#endif /* _LINUX_VE_H */
