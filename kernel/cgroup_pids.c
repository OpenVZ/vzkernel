/*
 * Process number limiting controller for cgroups.
 *
 * Used to allow a cgroup hierarchy to stop any new processes from fork()ing
 * after a certain limit is reached.
 *
 * Since it is trivial to hit the task limit without hitting any kmemcg limits
 * in place, PIDs are a fundamental resource. As such, PID exhaustion must be
 * preventable in the scope of a cgroup hierarchy by allowing resource limiting
 * of the number of tasks in a cgroup.
 *
 * In order to use the `pids` controller, set the maximum number of tasks in
 * pids.max (this is not available in the root cgroup for obvious reasons). The
 * number of processes currently in the cgroup is given by pids.current.
 * Organisational operations are not blocked by cgroup policies, so it is
 * possible to have pids.current > pids.max. However, it is not possible to
 * violate a cgroup policy through fork(). fork() will return -EAGAIN if forking
 * would cause a cgroup policy to be violated.
 *
 * To set a cgroup to have no limit, set pids.max to "max". This is the default
 * for all new cgroups (N.B. that PID limits are hierarchical, so the most
 * stringent limit in the hierarchy is followed).
 *
 * pids.current tracks all child cgroup hierarchies, so parent/pids.current is
 * a superset of parent/child/pids.current.
 *
 * Copyright (C) 2015 Aleksa Sarai <cyphar@cyphar.com>
 *
 * This file is subject to the terms and conditions of version 2 of the GNU
 * General Public License.  See the file COPYING in the main directory of the
 * Linux distribution for more details.
 */

#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/atomic.h>
#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/seq_file.h>

#define PIDS_MAX (PID_MAX_LIMIT + 1ULL)
#define PIDS_MAX_STR "max"

struct pids_cgroup {
	struct cgroup_subsys_state	css;

	/*
	 * Use 64-bit types so that we can safely represent "max" as
	 * %PIDS_MAX = (%PID_MAX_LIMIT + 1).
	 */
	atomic64_t			counter;
	int64_t				limit;
#ifdef CONFIG_BEANCOUNTERS
	/* beancounter-related stats */
	atomic_long_t pids_failcnt;
#endif /* CONFIG_BEANCOUNTERS */
};

#ifdef CONFIG_BEANCOUNTERS
static inline
struct pids_cgroup *pids_cgroup_from_css(struct cgroup_subsys_state *s)
{
	return container_of(s, struct pids_cgroup, css);
}

struct pids_cgroup *pids_cgroup_from_cont(struct cgroup *cont)
{
	return pids_cgroup_from_css(
			cgroup_subsys_state(cont, pids_subsys_id));
}

#include <bc/beancounter.h>
void pids_cgroup_sync_beancounter(struct pids_cgroup *pids,
				  struct user_beancounter *ub)
{
	unsigned long lim;
	volatile struct ubparm *p;

	p = &ub->ub_parms[UB_NUMPROC];
	p->held = p->maxheld = (unsigned long)atomic64_read(&pids->counter);
	p->failcnt = atomic_long_read(&pids->pids_failcnt);

	lim = pids->limit;
	lim = lim >= PIDS_MAX ? UB_MAXVALUE :
		min_t(unsigned long, lim, UB_MAXVALUE);
	p->barrier = p->limit = lim;
}
#endif /* CONFIG_BEANCOUNTERS */

static struct pids_cgroup *css_pids(struct cgroup_subsys_state *css)
{
	return container_of(css, struct pids_cgroup, css);
}

static inline struct pids_cgroup *cgroup_pids(struct cgroup *cgroup)
{
	return css_pids(cgroup_subsys_state(cgroup, pids_subsys_id));
}

static struct pids_cgroup *parent_pids(struct pids_cgroup *pids)
{
	struct cgroup *pcg = pids->css.cgroup->parent;
	return pcg ? cgroup_pids(pcg) : NULL;
}

static struct cgroup_subsys_state *pids_css_alloc(struct cgroup *cgroup)
{
	struct pids_cgroup *pids;

	pids = kzalloc(sizeof(struct pids_cgroup), GFP_KERNEL);
	if (!pids)
		return ERR_PTR(-ENOMEM);

	pids->limit = PIDS_MAX;
	atomic64_set(&pids->counter, 0);
	return &pids->css;
}

static void pids_css_free(struct cgroup *cgroup)
{
	kfree(cgroup_pids(cgroup));
}

/**
 * pids_cancel - uncharge the local pid count
 * @pids: the pid cgroup state
 * @num: the number of pids to cancel
 *
 * This function will WARN if the pid count goes under 0, because such a case is
 * a bug in the pids controller proper.
 */
static void pids_cancel(struct pids_cgroup *pids, int num)
{
	/*
	 * A negative count (or overflow for that matter) is invalid,
	 * and indicates a bug in the `pids` controller proper.
	 */
	WARN_ON_ONCE(atomic64_add_negative(-num, &pids->counter));
}

/**
 * pids_uncharge - hierarchically uncharge the pid count
 * @pids: the pid cgroup state
 * @num: the number of pids to uncharge
 */
static void pids_uncharge(struct pids_cgroup *pids, int num)
{
	struct pids_cgroup *p;

	for (p = pids; p; p = parent_pids(p))
		pids_cancel(p, num);
}

/**
 * pids_charge - hierarchically charge the pid count
 * @pids: the pid cgroup state
 * @num: the number of pids to charge
 *
 * This function does *not* follow the pid limit set. It cannot fail and the new
 * pid count may exceed the limit. This is only used for reverting failed
 * attaches, where there is no other way out than violating the limit.
 */
static void pids_charge(struct pids_cgroup *pids, int num)
{
	struct pids_cgroup *p;

	for (p = pids; p; p = parent_pids(p))
		atomic64_add(num, &p->counter);
}

/**
 * pids_try_charge - hierarchically try to charge the pid count
 * @pids: the pid cgroup state
 * @num: the number of pids to charge
 *
 * This function follows the set limit. It will fail if the charge would cause
 * the new value to exceed the hierarchical limit. Returns 0 if the charge
 * succeded, otherwise -EAGAIN.
 */
static int pids_try_charge(struct pids_cgroup *pids, int num)
{
	struct pids_cgroup *p, *q;

	for (p = pids; p; p = parent_pids(p)) {
		int64_t new = atomic64_add_return(num, &p->counter);

		/*
		 * Since new is capped to the maximum number of pid_t, if
		 * p->limit is %PIDS_MAX then we know that this test will never
		 * fail.
		 */
		if (new > p->limit)
			goto revert;
	}

	return 0;

revert:
	for (q = pids; q != p; q = parent_pids(q))
		pids_cancel(q, num);
	pids_cancel(p, num);
#ifdef CONFIG_BEANCOUNTERS
	atomic_long_inc(&pids->pids_failcnt);
#endif /* CONFIG_BEANCOUNTERS */

	return -EAGAIN;
}

static int pids_can_attach(struct cgroup *cgrp,
			   struct cgroup_taskset *tset)
{
	struct pids_cgroup *pids = cgroup_pids(cgrp);
	struct task_struct *task;

	cgroup_taskset_for_each(task, cgrp, tset) {
		struct cgroup_subsys_state *old_css;
		struct pids_cgroup *old_pids;

		/*
		 * No need to pin @old_css between here and cancel_attach()
		 * because cgroup core protects it from being freed before
		 * the migration completes or fails.
		 */
		old_css = task_subsys_state(task, pids_subsys_id);
		old_pids = css_pids(old_css);

		pids_charge(pids, 1);
		pids_uncharge(old_pids, 1);
	}

	return 0;
}

static void pids_cancel_attach(struct cgroup *cgrp,
			       struct cgroup_taskset *tset)
{
	struct pids_cgroup *pids = cgroup_pids(cgrp);
	struct task_struct *task;

	cgroup_taskset_for_each(task, cgrp, tset) {
		struct cgroup_subsys_state *old_css;
		struct pids_cgroup *old_pids;

		old_css = task_subsys_state(task, pids_subsys_id);
		old_pids = css_pids(old_css);

		pids_charge(old_pids, 1);
		pids_uncharge(pids, 1);
	}
}

static int pids_can_fork(struct task_struct *task, void **priv_p)
{
	struct cgroup_subsys_state *css;
	struct pids_cgroup *pids;
	int err;

	/*
	 * Use the "current" task_css for the pids subsystem as the tentative
	 * css. It is possible we will charge the wrong hierarchy, in which
	 * case we will forcefully revert/reapply the charge on the right
	 * hierarchy after it is committed to the task proper.
	 */
	css = task_get_css(current, pids_subsys_id);
	pids = css_pids(css);

	err = pids_try_charge(pids, 1);
	if (err)
		goto err_css_put;

	*priv_p = css;
	return 0;

err_css_put:
	css_put(css);
	return err;
}

static void pids_cancel_fork(struct task_struct *task, void *priv)
{
	struct cgroup_subsys_state *css = priv;
	struct pids_cgroup *pids = css_pids(css);

	pids_uncharge(pids, 1);
	css_put(css);
}

static void pids_fork(struct task_struct *task, void *priv)
{
	struct cgroup_subsys_state *css;
	struct cgroup_subsys_state *old_css = priv;
	struct pids_cgroup *pids;
	struct pids_cgroup *old_pids = css_pids(old_css);

	css = task_get_css(task, pids_subsys_id);
	pids = css_pids(css);

	/*
	 * If the association has changed, we have to revert and reapply the
	 * charge/uncharge on the wrong hierarchy to the current one. Since
	 * the association can only change due to an organisation event, its
	 * okay for us to ignore the limit in this case.
	 */
	if (pids != old_pids) {
		pids_uncharge(old_pids, 1);
		pids_charge(pids, 1);
	}

	css_put(css);
	css_put(old_css);
}

void cgroup_pids_release(struct task_struct *task)
{
	struct list_head *cg_list = &task->cg_list;
	struct cgroup_subsys_state *css;

	if (WARN_ON(!list_empty(cg_list)))
		return;
	if (WARN_ON(cg_list->prev == cg_list))
		return;

	css = (void *)cg_list->prev;
	pids_uncharge(css_pids(css), 1);
	css_put(css);
}

static void pids_exit(struct cgroup *cgroup,
		      struct cgroup *old_cgroup,
		      struct task_struct *task)
{
	struct list_head *cg_list = &task->cg_list;
	struct cgroup_subsys_state *css;

	if (WARN_ON(cg_list->prev != cg_list))
		return;
	/*
	 * This preserves list_empty(cg_list) == T and nobody else can use
	 * ->cg_list after cgroup_exit(). Abuse cg_list->prev to pass this
	 * css to cgroup_pids_release().
	 */
	css = cgroup_subsys_state(old_cgroup, pids_subsys_id);
	cg_list->prev = (void *)css;
	css_get(css);
}

static int pids_max_write(struct cgroup *cgroup, struct cftype *cft,
			  const char *buf)
{
	struct pids_cgroup *pids = cgroup_pids(cgroup);
	int64_t limit;
	int err;

	buf = strstrip((char *)buf);
	if (!strcmp(buf, PIDS_MAX_STR)) {
		limit = PIDS_MAX;
		goto set_limit;
	}

	err = kstrtoll(buf, 0, &limit);
	if (err)
		return err;

	if (limit < 0 || limit >= PIDS_MAX)
		return -EINVAL;

set_limit:
	/*
	 * Limit updates don't need to be mutex'd, since it isn't
	 * critical that any racing fork()s follow the new limit.
	 */
	pids->limit = limit;
	return 0;
}

static int pids_max_show(struct cgroup *cgroup, struct cftype *cft,
                         struct seq_file *sf)
{
	struct pids_cgroup *pids = cgroup_pids(cgroup);
	int64_t limit = pids->limit;

	if (limit >= PIDS_MAX)
		seq_printf(sf, "%s\n", PIDS_MAX_STR);
	else
		seq_printf(sf, "%lld\n", limit);

	return 0;
}

static s64 pids_current_read(struct cgroup *cgroup,
			     struct cftype *cft)
{
	struct pids_cgroup *pids = cgroup_pids(cgroup);

	return atomic64_read(&pids->counter);
}

static struct cftype pids_files[] = {
	{
		.name = "max",
		.write_string = pids_max_write,
		.read_seq_string = pids_max_show,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "current",
		.read_s64 = pids_current_read,
	},
	{ }	/* terminate */
};

struct cgroup_subsys pids_subsys = {
	.name		= "pids",
	.subsys_id	= pids_subsys_id,
	.css_alloc	= pids_css_alloc,
	.css_free	= pids_css_free,
	.can_attach 	= pids_can_attach,
	.cancel_attach 	= pids_cancel_attach,
	.can_fork	= pids_can_fork,
	.cancel_fork	= pids_cancel_fork,
	.fork		= pids_fork,
	.exit		= pids_exit,
	.base_cftypes	= pids_files,
};
