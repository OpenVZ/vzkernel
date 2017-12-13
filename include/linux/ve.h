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

struct ve_struct {
	struct cgroup_subsys_state	css;

	const char		*ve_name;

	struct list_head	ve_list;

	envid_t			veid;
	int			is_running;

	struct rw_semaphore	op_sem;

	/* per VE CPU stats*/
	u64			start_time;		/* monotonic time */
	u64			start_boottime;		/* boot based time */
	u64			start_jiffies;		/* Deprecated */

	struct nsproxy __rcu	*ve_ns;
	struct cred		*init_cred;
};

extern int nr_ve;

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

#else	/* CONFIG_VE */
#define get_ve(ve)	((void)(ve), NULL)
#define put_ve(ve)	do { (void)(ve); } while (0)

static inline void ve_stop_ns(struct pid_namespace *ns) { }
static inline void ve_exit_ns(struct pid_namespace *ns) { }
#endif	/* CONFIG_VE */

#endif /* _LINUX_VE_H */
