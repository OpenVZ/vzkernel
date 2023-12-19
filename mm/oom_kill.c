/*
 *  linux/mm/oom_kill.c
 * 
 *  Copyright (C)  1998,2000  Rik van Riel
 *	Thanks go out to Claus Fischer for some serious inspiration and
 *	for goading me into coding this file...
 *  Copyright (C)  2010  Google, Inc.
 *	Rewritten by David Rientjes
 *
 *  The routines in this file are used to kill a process when
 *  we're seriously out of memory. This gets called from __alloc_pages()
 *  in mm/page_alloc.c when we really run out of memory.
 *
 *  Since we won't call these routines often (on a well-configured
 *  machine) this file will double as a 'coding guide' and a signpost
 *  for newbie kernel hackers. It features several pointers to major
 *  kernel subsystems and hints as to where to find out what things do.
 */

#include <linux/oom.h>
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/timex.h>
#include <linux/jiffies.h>
#include <linux/cpuset.h>
#include <linux/export.h>
#include <linux/notifier.h>
#include <linux/memcontrol.h>
#include <linux/mempolicy.h>
#include <linux/security.h>
#include <linux/ptrace.h>
#include <linux/freezer.h>
#include <linux/ftrace.h>
#include <linux/ratelimit.h>

#define CREATE_TRACE_POINTS
#include <trace/events/oom.h>

int sysctl_panic_on_oom;
int sysctl_oom_kill_allocating_task;
int sysctl_oom_dump_tasks;
int sysctl_oom_relaxation = HZ;

static DEFINE_SPINLOCK(oom_context_lock);

#define OOM_TIMEOUT	(5 * HZ)

#define OOM_BASE_RAGE	-10
#define OOM_MAX_RAGE	20

#ifndef CONFIG_MEMCG
struct oom_context oom_ctx = {
	.rage		= OOM_BASE_RAGE,
	.waitq		= __WAIT_QUEUE_HEAD_INITIALIZER(oom_ctx.waitq),
};
#endif

void init_oom_context(struct oom_context *ctx)
{
	ctx->owner = NULL;
	ctx->victim = NULL;
	ctx->marked = false;
	ctx->oom_start = 0;
	ctx->oom_end = 0;
	ctx->rage = OOM_BASE_RAGE;
	init_waitqueue_head(&ctx->waitq);
}

static void __release_oom_context(struct oom_context *ctx)
{
	ctx->owner = NULL;
	ctx->victim = NULL;
	ctx->marked = false;
	ctx->oom_end = jiffies;
	wake_up_all(&ctx->waitq);
}

void release_oom_context(struct oom_context *ctx)
{
	spin_lock(&oom_context_lock);
	__release_oom_context(ctx);
	spin_unlock(&oom_context_lock);
}

#ifdef CONFIG_NUMA
/**
 * has_intersects_mems_allowed() - check task eligiblity for kill
 * @start: task struct of which task to consider
 * @mask: nodemask passed to page allocator for mempolicy ooms
 *
 * Task eligibility is determined by whether or not a candidate task, @tsk,
 * shares the same mempolicy nodes as current if it is bound by such a policy
 * and whether or not it has the same set of allowed cpuset nodes.
 */
static bool has_intersects_mems_allowed(struct task_struct *start,
					const nodemask_t *mask)
{
	struct task_struct *tsk;
	bool ret = false;

	rcu_read_lock();
	for_each_thread(start, tsk) {
		if (mask) {
			/*
			 * If this is a mempolicy constrained oom, tsk's
			 * cpuset is irrelevant.  Only return true if its
			 * mempolicy intersects current, otherwise it may be
			 * needlessly killed.
			 */
			ret = mempolicy_nodemask_intersects(tsk, mask);
		} else {
			/*
			 * This is not a mempolicy constrained oom, so only
			 * check the mems of tsk's cpuset.
			 */
			ret = cpuset_mems_allowed_intersects(current, tsk);
		}
		if (ret)
			break;
	}
	rcu_read_unlock();

	return ret;
}
#else
static bool has_intersects_mems_allowed(struct task_struct *tsk,
					const nodemask_t *mask)
{
	return true;
}
#endif /* CONFIG_NUMA */

/*
 * The process p may have detached its own ->mm while exiting or through
 * use_mm(), but one or more of its subthreads may still have a valid
 * pointer.  Return p, or any of its subthreads with a valid ->mm, with
 * task_lock() held.
 */
struct task_struct *find_lock_task_mm(struct task_struct *p)
{
	struct task_struct *t;

	rcu_read_lock();

	for_each_thread(p, t) {
		task_lock(t);
		if (likely(t->mm))
			goto found;
		task_unlock(t);
	}
	t = NULL;
found:
	rcu_read_unlock();

	return t;
}

/* return true if the task is not adequate as candidate victim task. */
static bool oom_unkillable_task(struct task_struct *p,
		const struct mem_cgroup *memcg, const nodemask_t *nodemask)
{
	if (is_global_init(p))
		return true;
	if (p->flags & PF_KTHREAD)
		return true;

	/* When mem_cgroup_out_of_memory() and p is not member of the group */
	if (memcg && !task_in_mem_cgroup(p, memcg))
		return true;

	/* p may not have freeable memory in nodemask */
	if (!has_intersects_mems_allowed(p, nodemask))
		return true;

	return false;
}

static unsigned long mm_overdraft(struct mm_struct *mm)
{
	struct mem_cgroup *memcg;
	struct oom_context *ctx;
	unsigned long overdraft;

	memcg = try_get_mem_cgroup_from_mm(mm);
	ctx = mem_cgroup_oom_context(memcg);
	overdraft = ctx->overdraft;
	mem_cgroup_put(memcg);

	return overdraft;
}

/**
 * oom_badness - heuristic function to determine which candidate task to kill
 * @p: task struct of which task we should calculate
 * @totalpages: total present RAM allowed for page allocation
 *
 * The heuristic for determining which task to kill is made to be as simple and
 * predictable as possible.  The goal is to return the highest value for the
 * task consuming the most memory to avoid subsequent oom failures.
 */
unsigned long oom_badness(struct task_struct *p, struct mem_cgroup *memcg,
			  const nodemask_t *nodemask, unsigned long totalpages,
			  unsigned long *overdraft)
{
	long points;
	long adj;

	if (overdraft)
		*overdraft = 0;

	if (oom_unkillable_task(p, memcg, nodemask))
		return 0;

	p = find_lock_task_mm(p);
	if (!p)
		return 0;

	if (overdraft)
		*overdraft = mm_overdraft(p->mm);

	adj = get_task_oom_score_adj(p);
	if (adj == OOM_SCORE_ADJ_MIN) {
		task_unlock(p);
		return 0;
	}

	/*
	 * The baseline for the badness score is the proportion of RAM that each
	 * task's rss, pagetable and swap space use.
	 */
	points = get_mm_rss(p->mm) + atomic_long_read(&p->mm->nr_ptes) +
		 get_mm_counter(p->mm, MM_SWAPENTS);
	task_unlock(p);

	/*
	 * Root processes get 3% bonus, just like the __vm_enough_memory()
	 * implementation used by LSMs.
	 */
	if (has_capability_noaudit(p, CAP_SYS_ADMIN))
		points -= (points * 3) / 100;

	/* Normalize to oom_score_adj units */
	adj *= totalpages / 1000;
	points += adj;

	/*
	 * Never return 0 for an eligible task regardless of the root bonus and
	 * oom_score_adj (oom_score_adj can't be OOM_SCORE_ADJ_MIN here).
	 */
	return points > 0 ? points : 1;
}

/*
 * Determine the type of allocation constraint.
 */
#ifdef CONFIG_NUMA
static enum oom_constraint constrained_alloc(struct zonelist *zonelist,
				gfp_t gfp_mask, nodemask_t *nodemask,
				unsigned long *totalpages)
{
	struct zone *zone;
	struct zoneref *z;
	enum zone_type high_zoneidx = gfp_zone(gfp_mask);
	bool cpuset_limited = false;
	int nid;

	/* Default to all available memory */
	*totalpages = totalram_pages + total_swap_pages;

	if (!zonelist)
		return CONSTRAINT_NONE;
	/*
	 * Reach here only when __GFP_NOFAIL is used. So, we should avoid
	 * to kill current.We have to random task kill in this case.
	 * Hopefully, CONSTRAINT_THISNODE...but no way to handle it, now.
	 */
	if (gfp_mask & __GFP_THISNODE)
		return CONSTRAINT_NONE;

	/*
	 * This is not a __GFP_THISNODE allocation, so a truncated nodemask in
	 * the page allocator means a mempolicy is in effect.  Cpuset policy
	 * is enforced in get_page_from_freelist().
	 */
	if (nodemask && !nodes_subset(node_states[N_MEMORY], *nodemask)) {
		*totalpages = total_swap_pages;
		for_each_node_mask(nid, *nodemask)
			*totalpages += node_spanned_pages(nid);
		return CONSTRAINT_MEMORY_POLICY;
	}

	/* Check this allocation failure is caused by cpuset's wall function */
	for_each_zone_zonelist_nodemask(zone, z, zonelist,
			high_zoneidx, nodemask)
		if (!cpuset_zone_allowed_softwall(zone, gfp_mask))
			cpuset_limited = true;

	if (cpuset_limited) {
		*totalpages = total_swap_pages;
		for_each_node_mask(nid, cpuset_current_mems_allowed)
			*totalpages += node_spanned_pages(nid);
		return CONSTRAINT_CPUSET;
	}
	return CONSTRAINT_NONE;
}
#else
static enum oom_constraint constrained_alloc(struct zonelist *zonelist,
				gfp_t gfp_mask, nodemask_t *nodemask,
				unsigned long *totalpages)
{
	*totalpages = totalram_pages + total_swap_pages;
	return CONSTRAINT_NONE;
}
#endif

enum oom_scan_t oom_scan_process_thread(struct task_struct *task,
		unsigned long totalpages, const nodemask_t *nodemask,
		bool force_kill)
{
	if (oom_unkillable_task(task, NULL, nodemask))
		return OOM_SCAN_CONTINUE;

	/*
	 * This task already has access to memory reserves and is being killed.
	 * Try to select another one.
	 *
	 * This can only happen if oom_trylock timeout-ed, which most probably
	 * means that the victim had dead-locked.
	 */
	if (test_tsk_thread_flag(task, TIF_MEMDIE)) {
		if (!force_kill)
			return OOM_SCAN_CONTINUE;
	}
	if (!task->mm)
		return OOM_SCAN_CONTINUE;

	/*
	 * If task is allocating a lot of memory and has been marked to be
	 * killed first if it triggers an oom, then select it.
	 */
	if (oom_task_origin(task))
		return OOM_SCAN_SELECT;

	return OOM_SCAN_OK;
}

/*
 * Simple selection loop. We chose the process with the highest
 * number of 'points'.
 *
 * (not docbooked, we don't want this one cluttering up the manual)
 */
static struct task_struct *select_bad_process(unsigned long *ppoints,
		unsigned long *poverdraft,
		unsigned long totalpages, const nodemask_t *nodemask,
		bool force_kill)
{
	struct task_struct *g, *p;
	struct task_struct *chosen = NULL;
	unsigned long chosen_points = 0;
	unsigned long max_overdraft = 0;

	rcu_read_lock();
	for_each_process_thread(g, p) {
		unsigned int points;
		unsigned long overdraft;

		switch (oom_scan_process_thread(p, totalpages, nodemask,
						force_kill)) {
		case OOM_SCAN_SELECT:
			chosen = p;
			chosen_points = ULONG_MAX;
			max_overdraft = ULONG_MAX;
			/* fall through */
		case OOM_SCAN_CONTINUE:
			continue;
		case OOM_SCAN_OK:
			break;
		};
		points = oom_badness(p, NULL, nodemask, totalpages,
				     &overdraft);
		if (oom_worse(points, overdraft, &chosen_points,
			      &max_overdraft))
			chosen = p;
	}
	if (chosen)
		get_task_struct(chosen);
	rcu_read_unlock();

	*ppoints = chosen_points;
	*poverdraft = max_overdraft;
	return chosen;
}

/**
 * dump_tasks - dump current memory state of all system tasks
 * @memcg: current's memory controller, if constrained
 * @nodemask: nodemask passed to page allocator for mempolicy ooms
 *
 * Dumps the current memory state of all eligible tasks.  Tasks not in the same
 * memcg, not in the same cpuset, or bound to a disjoint set of mempolicy nodes
 * are not shown.
 * State information includes task's pid, uid, tgid, vm size, rss, nr_ptes,
 * swapents, oom_score_adj value, and name.
 */
static void dump_tasks(const struct mem_cgroup *memcg, const nodemask_t *nodemask)
{
	struct task_struct *p;
	struct task_struct *task;

	pr_info("[ pid ]   uid  tgid total_vm      rss nr_ptes swapents oom_score_adj name\n");
	rcu_read_lock();
	for_each_process(p) {
		if (oom_unkillable_task(p, memcg, nodemask))
			continue;

		task = find_lock_task_mm(p);
		if (!task) {
			/*
			 * This is a kthread or all of p's threads have already
			 * detached their mm's.  There's no need to report
			 * them; they can't be oom killed anyway.
			 */
			continue;
		}

		pr_info("[%5d] %5d %5d %8lu %8lu %7ld %8lu         %5hd %s\n",
			task->pid, from_kuid(&init_user_ns, task_uid(task)),
			task->tgid, task->mm->total_vm, get_mm_rss(task->mm),
			atomic_long_read(&task->mm->nr_ptes),
			get_mm_counter(task->mm, MM_SWAPENTS),
			task->signal->oom_score_adj, task->comm);
		task_unlock(task);
	}
	rcu_read_unlock();
}

static void dump_header(struct task_struct *p, gfp_t gfp_mask, int order,
			struct mem_cgroup *memcg, const nodemask_t *nodemask)
{
	task_lock(current);
	pr_warning("%s invoked oom-killer: gfp_mask=0x%x, order=%d, "
		"oom_score_adj=%hd\n",
		current->comm, gfp_mask, order,
		current->signal->oom_score_adj);
	cpuset_print_task_mems_allowed(current);
	task_unlock(current);
	dump_stack();
	if (memcg)
		mem_cgroup_print_oom_info(memcg, p);
	else
		show_mem(SHOW_MEM_FILTER_NODES);
	if (sysctl_oom_dump_tasks)
		dump_tasks(memcg, nodemask);
}

/*
 * Number of OOM killer invocations (including memcg OOM killer).
 * Primarily used by PM freezer to check for potential races with
 * OOM killed frozen task.
 */
static atomic_t oom_kills = ATOMIC_INIT(0);

int oom_kills_count(void)
{
	return atomic_read(&oom_kills);
}

void note_oom_kill(void)
{
	atomic_inc(&oom_kills);
}

/**
 * mark_oom_victim - mark the given task as OOM victim
 * @tsk: task to mark
 */
void mark_oom_victim(struct task_struct *tsk)
{
	struct mem_cgroup *memcg;
	struct oom_context *ctx;

	set_tsk_thread_flag(tsk, TIF_MEMDIE);

	/*
	 * Make sure that the task is woken up from uninterruptible sleep
	 * if it is frozen because OOM killer wouldn't be able to free
	 * any memory and livelock. freezing_slow_path will tell the freezer
	 * that TIF_MEMDIE tasks should be ignored.
	 */
	__thaw_task(tsk);

	/*
	 * Record the pointer to the victim in the oom context of the
	 * owner memcg so that others can wait for it to exit. It will
	 * be cleared in exit_oom_victim.
	 */
	memcg = try_get_mem_cgroup_from_mm(tsk->mm);
	ctx = mem_cgroup_oom_context(memcg);
	spin_lock(&oom_context_lock);
	if (!ctx->victim) {
		ctx->victim = tsk;
		ctx->marked = true;
	}
	spin_unlock(&oom_context_lock);
	mem_cgroup_put(memcg);
}

/**
 * exit_oom_victim - note the exit of an OOM victim
 */
void exit_oom_victim(void)
{
	struct mem_cgroup *iter;
	struct oom_context *ctx;

	clear_thread_flag(TIF_MEMDIE);

	/*
	 * Wake up every process waiting for this oom victim to exit.
	 */
	spin_lock(&oom_context_lock);
	iter = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		ctx = mem_cgroup_oom_context(iter);
		if (ctx->victim != current)
			continue;
		if (!ctx->owner)
			__release_oom_context(ctx);
		else
			/* To be released by owner (see oom_unlock) */
			ctx->victim = NULL;
	} while ((iter = mem_cgroup_iter(NULL, iter, NULL)));
	spin_unlock(&oom_context_lock);
}

static void __wait_oom_context(struct oom_context *ctx)
{
	unsigned long now = jiffies;
	unsigned long timeout;
	DEFINE_WAIT(wait);

	if (ctx->victim == current ||
	    time_after_eq(now, ctx->oom_start + OOM_TIMEOUT)) {
		spin_unlock(&oom_context_lock);
		return;
	}

	prepare_to_wait(&ctx->waitq, &wait, TASK_KILLABLE);
	timeout = ctx->oom_start + OOM_TIMEOUT - now;
	spin_unlock(&oom_context_lock);
	schedule_timeout(timeout);
	finish_wait(&ctx->waitq, &wait);
}

bool oom_trylock(struct mem_cgroup *memcg)
{
	unsigned long now = jiffies;
	struct mem_cgroup *iter, *parent;
	struct oom_context *ctx;

	spin_lock(&oom_context_lock);

	/*
	 * Check if oom context of memcg or any of its descendants is
	 * active, i.e. if there is a process selecting a victim or a
	 * victim dying. If there is, wait for it to finish, otherwise
	 * proceed to oom.
	 */
	iter = mem_cgroup_iter(memcg, NULL, NULL);
	do {
		ctx = mem_cgroup_oom_context(iter);
		if ((ctx->owner || ctx->victim) &&
		    time_before(now, ctx->oom_start + OOM_TIMEOUT)) {
			__wait_oom_context(ctx);
			mem_cgroup_iter_break(memcg, iter);
			return false;
		} else if (ctx->owner || ctx->victim) {
			/*
			 * Timeout. Release the context and dump stack
			 * trace of the stuck process.
			 *
			 * To avoid dumping stack trace of the same task
			 * more than once, we mark the context that
			 * contained the victim when it was killed (see
			 * mark_oom_victim).
			 */
			struct task_struct *p = ctx->victim;

			if (p && ctx->marked) {
				task_lock(p);
				pr_err("OOM kill timeout: %d (%s)\n",
				       task_pid_nr(p), p->comm);
				task_unlock(p);
				show_stack(p, NULL);
			}

			__release_oom_context(ctx);
		}
	} while ((iter = mem_cgroup_iter(memcg, iter, NULL)));

	/*
	 * Acquire oom context of memcg and all its descendants.
	 */
	iter = mem_cgroup_iter(memcg, NULL, NULL);
	do {
		ctx = mem_cgroup_oom_context(iter);
		BUG_ON(ctx->owner);
		BUG_ON(ctx->victim);
		ctx->owner = current;
		ctx->oom_start = now;
		/*
		 * Update overdraft of each cgroup under us. This
		 * information will be used in oom_badness.
		 */
		ctx->overdraft = mem_cgroup_overdraft(iter);
		parent = parent_mem_cgroup(iter);
		if (parent && iter != memcg)
			ctx->overdraft = max(ctx->overdraft,
				mem_cgroup_oom_context(parent)->overdraft);
	} while ((iter = mem_cgroup_iter(memcg, iter, NULL)));

	spin_unlock(&oom_context_lock);

	return true;
}

void oom_unlock(struct mem_cgroup *memcg)
{
	struct task_struct *victim = NULL;
	struct mem_cgroup *iter, *victim_memcg = NULL;
	struct oom_context *ctx;

	spin_lock(&oom_context_lock);

	/*
	 * Find oom victim if any.
	 */
	iter = mem_cgroup_iter(memcg, NULL, NULL);
	do {
		ctx = mem_cgroup_oom_context(iter);
		if (ctx->owner != current) {
			/* Lost ownership on timeout */
			mem_cgroup_iter_break(memcg, iter);
			break;
		}
		if (ctx->victim) {
			victim = ctx->victim;
			/*
			 * Remember the victim memcg so that we can wait
			 * on it for the victim to exit below.
			 */
			victim_memcg = iter;
			mem_cgroup_get(iter);

			mem_cgroup_iter_break(memcg, iter);
			break;
		}
	} while ((iter = mem_cgroup_iter(memcg, iter, NULL)));

	/*
	 * Propagate victim up to the context that initiated oom.
	 */
	for (iter = victim_memcg; iter; iter = parent_mem_cgroup(iter)) {
		ctx = mem_cgroup_oom_context(iter);
		BUG_ON(ctx->owner != current);
		if (!ctx->victim)
			ctx->victim = victim;
		if (iter == memcg)
			break;
	}

	/*
	 * Release oom context of memcg and all its descendants.
	 */
	iter = mem_cgroup_iter(memcg, NULL, NULL);
	do {
		ctx = mem_cgroup_oom_context(iter);
		if (ctx->owner != current)
			/* Lost ownership on timeout */
			continue;
		if (!ctx->victim)
			/*
			 * Victim already exited or nobody was killed in
			 * this cgroup? It's our responsibility to wake
			 * up blocked processes then.
			 */
			__release_oom_context(ctx);
		else
			/* To be released by victim (see exit_oom_victim) */
			ctx->owner = NULL;
	} while ((iter = mem_cgroup_iter(memcg, iter, NULL)));

	if (!victim) {
		spin_unlock(&oom_context_lock);
		return;
	}

	/*
	 * Wait for the victim to exit.
	 */
	ctx = mem_cgroup_oom_context(victim_memcg);
	__wait_oom_context(ctx);
	mem_cgroup_put(victim_memcg);
}

/*
 * task->mm can be NULL if the task is the exited group leader.  So to
 * determine whether the task is using a particular mm, we examine all the
 * task's threads: if one of those is using this mm then this task was also
 * using it.
 */
static bool process_shares_mm(struct task_struct *p, struct mm_struct *mm)
{
	struct task_struct *t;

	for_each_thread(p, t) {
		struct mm_struct *t_mm = READ_ONCE(t->mm);
		if (t_mm)
			return t_mm == mm;
	}
	return false;
}

/*
 * Kill more processes if oom happens too often in this context.
 */
static void oom_berserker(unsigned long points, unsigned long overdraft,
			  unsigned long totalpages, struct mem_cgroup *memcg,
			  nodemask_t *nodemask)
{
	static DEFINE_RATELIMIT_STATE(berserker_rs,
				      DEFAULT_RATELIMIT_INTERVAL,
				      DEFAULT_RATELIMIT_BURST);
	struct oom_context *ctx;
	struct task_struct *p;
	int rage;
	int killed = 0;

	spin_lock(&oom_context_lock);
	ctx = mem_cgroup_oom_context(memcg);
	if (ctx->owner != current) {
		/* Lost ownership on timeout */
		spin_unlock(&oom_context_lock);
		return;
	}
	/*
	 * Increase rage if oom happened recently in this context, reset
	 * rage otherwise.
	 *
	 * previous oom                            this oom (unfinished)
	 * ++++++++++++----------------------------++++++++
	 *            ^                            ^
	 *         oom_end  <<oom_relaxation>>  oom_start
	 */
	if (time_after(ctx->oom_start, ctx->oom_end + sysctl_oom_relaxation))
		ctx->rage = OOM_BASE_RAGE;
	else if (ctx->rage < OOM_MAX_RAGE)
		ctx->rage++;
	rage = ctx->rage;
	spin_unlock(&oom_context_lock);

	if (rage < 0)
		return;

	/*
	 * So, we are in rage. Kill (1 << rage) youngest tasks that are
	 * as bad as the victim.
	 */
	qread_lock(&tasklist_lock);
	list_for_each_entry_reverse(p, &init_task.tasks, tasks) {
		unsigned long tsk_points;
		unsigned long tsk_overdraft;

		if (!p->mm || test_tsk_thread_flag(p, TIF_MEMDIE) ||
		    fatal_signal_pending(p) || p->flags & PF_EXITING ||
		    oom_unkillable_task(p, memcg, nodemask))
			continue;

		tsk_points = oom_badness(p, memcg, nodemask, totalpages,
					 &tsk_overdraft);
		if (tsk_overdraft < overdraft)
			continue;

		/*
		 * oom_badness never returns a negative value, even if
		 * oom_score_adj would make badness so, instead it
		 * returns 1. So we do not kill task with badness 1 if
		 * the victim has badness > 1 so as not to risk killing
		 * protected tasks.
		 */
		if (tsk_points <= 1 && points > 1)
			continue;

		/*
		 * Consider tasks as equally bad if they have equal
		 * normalized scores.
		 */
		if (tsk_points * 1000 / totalpages <
		    points * 1000 / totalpages)
			continue;

		if (__ratelimit(&berserker_rs)) {
			task_lock(p);
			pr_err("Rage kill process %d (%s)\n",
			       task_pid_nr(p), p->comm);
			task_unlock(p);
		}

		do_send_sig_info(SIGKILL, SEND_SIG_FORCED, p, true);
		mem_cgroup_note_oom_kill(memcg, p);

		if (++killed >= 1 << rage)
			break;
	}
	qread_unlock(&tasklist_lock);

	pr_err("OOM killer in rage %d: %d tasks killed\n", rage, killed);
}

#define K(x) ((x) << (PAGE_SHIFT-10))
/*
 * Must be called while holding a reference to p, which will be released upon
 * returning.
 */
void oom_kill_process(struct task_struct *p, gfp_t gfp_mask, int order,
		      unsigned long points, unsigned long overdraft,
		      unsigned long totalpages,
		      struct mem_cgroup *memcg, nodemask_t *nodemask,
		      const char *message)
{
	struct task_struct *victim = p;
	struct task_struct *child;
	struct task_struct *t;
	struct mm_struct *mm;
	unsigned int victim_points = 0;
	static DEFINE_RATELIMIT_STATE(oom_rs, DEFAULT_RATELIMIT_INTERVAL,
					      DEFAULT_RATELIMIT_BURST);

	/*
	 * If the task is already exiting, don't alarm the sysadmin or kill
	 * its children or threads, just set TIF_MEMDIE so it can die quickly
	 */
	task_lock(p);
	if (task_will_free_mem(p)) {
		mark_oom_victim(p);
		task_unlock(p);
		put_task_struct(p);
		return;
	}
	task_unlock(p);

	if (__ratelimit(&oom_rs))
		dump_header(p, gfp_mask, order, memcg, nodemask);

	task_lock(p);
	pr_err("%s: Kill process %d (%s) score %lu or sacrifice child\n",
		message, task_pid_nr(p), p->comm, points * 1000 / totalpages);
	task_unlock(p);

	/*
	 * If any of p's children has a different mm and is eligible for kill,
	 * the one with the highest oom_badness() score is sacrificed for its
	 * parent.  This attempts to lose the minimal amount of work done while
	 * still freeing memory.
	 */
	qread_lock(&tasklist_lock);

	/*
	 * The task 'p' might have already exited before reaching here. The
	 * put_task_struct() will free task_struct 'p' while the loop still try
	 * to access the field of 'p', so, get an extra reference.
	 */
	get_task_struct(p);
	for_each_thread(p, t) {
		list_for_each_entry(child, &t->children, sibling) {
			unsigned int child_points;

			if (process_shares_mm(child, p->mm))
				continue;
			if (!child->mm ||
			    test_tsk_thread_flag(child, TIF_MEMDIE))
				continue;
			/*
			 * oom_badness() returns 0 if the thread is unkillable
			 */
			child_points = oom_badness(child, memcg, nodemask,
						   totalpages, NULL);
			if (child_points > victim_points) {
				put_task_struct(victim);
				victim = child;
				victim_points = child_points;
				get_task_struct(victim);
			}
		}
	}
	put_task_struct(p);
	qread_unlock(&tasklist_lock);

	p = find_lock_task_mm(victim);
	if (!p) {
		put_task_struct(victim);
		return;
	} else if (victim != p) {
		get_task_struct(p);
		put_task_struct(victim);
		victim = p;
	}

	/* Get a reference to safely compare mm after task_unlock(victim) */
	mm = victim->mm;
	atomic_inc(&mm->mm_count);
	/*
	 * We should send SIGKILL before setting TIF_MEMDIE in order to prevent
	 * the OOM victim from depleting the memory reserves from the user
	 * space under its control.
	 */
	do_send_sig_info(SIGKILL, SEND_SIG_FORCED, victim, true);
	mark_oom_victim(victim);
	rcu_read_lock();
	pr_err("Killed process %d (%s) in VE \"%s\", UID %d, total-vm:%lukB, anon-rss:%lukB, file-rss:%lukB, shmem-rss:%lukB\n",
		task_pid_nr(victim), victim->comm, task_ve_name(victim),
		task_uid(victim).val, K(victim->mm->total_vm),
		K(get_mm_counter(victim->mm, MM_ANONPAGES)),
		K(get_mm_counter(victim->mm, MM_FILEPAGES)),
		K(get_mm_counter(victim->mm, MM_SHMEMPAGES)));
	rcu_read_unlock();
	task_unlock(victim);
	mem_cgroup_note_oom_kill(memcg, victim);

	/*
	 * Kill all user processes sharing victim->mm in other thread groups, if
	 * any.  They don't get access to memory reserves, though, to avoid
	 * depletion of all memory.  This prevents mm->mmap_sem livelock when an
	 * oom killed thread cannot exit because it requires the semaphore and
	 * its contended by another thread trying to allocate memory itself.
	 * That thread will now get access to memory reserves since it has a
	 * pending fatal signal.
	 */
	rcu_read_lock();
	for_each_process(p) {
		if (!process_shares_mm(p, mm))
			continue;
		if (same_thread_group(p, victim))
			continue;
		if (unlikely(p->flags & PF_KTHREAD))
			continue;
		if (is_global_init(p))
			continue;
		if (p->signal->oom_score_adj == OOM_SCORE_ADJ_MIN)
			continue;

		do_send_sig_info(SIGKILL, SEND_SIG_FORCED, p, true);
		mem_cgroup_note_oom_kill(memcg, p);
	}
	rcu_read_unlock();

	mmdrop(mm);
	put_task_struct(victim);

	oom_berserker(points, overdraft, totalpages, memcg, nodemask);
}
#undef K

/*
 * Determines whether the kernel must panic because of the panic_on_oom sysctl.
 */
void check_panic_on_oom(enum oom_constraint constraint, gfp_t gfp_mask,
			int order, const nodemask_t *nodemask)
{
	if (likely(!sysctl_panic_on_oom))
		return;
	if (sysctl_panic_on_oom != 2) {
		/*
		 * panic_on_oom == 1 only affects CONSTRAINT_NONE, the kernel
		 * does not panic for cpuset, mempolicy, or memcg allocation
		 * failures.
		 */
		if (constraint != CONSTRAINT_NONE)
			return;
	}
	dump_header(NULL, gfp_mask, order, NULL, nodemask);
	panic("Out of memory: %s panic_on_oom is enabled\n",
		sysctl_panic_on_oom == 2 ? "compulsory" : "system-wide");
}

static BLOCKING_NOTIFIER_HEAD(oom_notify_list);

int register_oom_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&oom_notify_list, nb);
}
EXPORT_SYMBOL_GPL(register_oom_notifier);

int unregister_oom_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&oom_notify_list, nb);
}
EXPORT_SYMBOL_GPL(unregister_oom_notifier);

/**
 * out_of_memory - kill the "best" process when we run out of memory
 * @zonelist: zonelist pointer
 * @gfp_mask: memory allocation flags
 * @order: amount of memory being requested as a power of 2
 * @nodemask: nodemask passed to page allocator
 * @force_kill: true if a task must be killed, even if others are exiting
 *
 * If we run out of memory, we have the choice between either
 * killing a random task (bad), letting the system crash (worse)
 * OR try to be smart about which process to kill. Note that we
 * don't have to be perfect here, we just have to be good.
 */
void out_of_memory(struct zonelist *zonelist, gfp_t gfp_mask,
		int order, nodemask_t *nodemask, bool force_kill)
{
	const nodemask_t *mpol_mask;
	struct task_struct *p;
	unsigned long totalpages;
	unsigned long freed = 0;
	unsigned long uninitialized_var(points);
	unsigned long uninitialized_var(overdraft);
	enum oom_constraint constraint = CONSTRAINT_NONE;

	blocking_notifier_call_chain(&oom_notify_list, 0, &freed);
	if (freed > 0)
		/* Got some memory back in the last second. */
		return;

	/*
	 * If current has a pending SIGKILL or is exiting, then automatically
	 * select it.  The goal is to allow it to allocate so that it may
	 * quickly exit and free its memory.
	 *
	 * But don't select if current has already released its mm and cleared
	 * TIF_MEMDIE flag at exit_mm(), otherwise an OOM livelock may occur.
	 */
	if (current->mm &&
	    (fatal_signal_pending(current) || task_will_free_mem(current))) {
		mark_oom_victim(current);
		return;
	}

	/*
	 * Check if there were limitations on the allocation (only relevant for
	 * NUMA) that may require different handling.
	 */
	constraint = constrained_alloc(zonelist, gfp_mask, nodemask,
						&totalpages);
	mpol_mask = (constraint == CONSTRAINT_MEMORY_POLICY) ? nodemask : NULL;
	check_panic_on_oom(constraint, gfp_mask, order, mpol_mask);

	if (sysctl_oom_kill_allocating_task && current->mm &&
	    !oom_unkillable_task(current, NULL, nodemask) &&
	    current->signal->oom_score_adj != OOM_SCORE_ADJ_MIN) {
		get_task_struct(current);
		oom_kill_process(current, gfp_mask, order, 0, 0, totalpages,
				 NULL, nodemask,
				 "Out of memory (oom_kill_allocating_task)");
		return;
	}

	p = select_bad_process(&points, &overdraft, totalpages, mpol_mask,
			       force_kill);
	/* Found nothing?!?! Either we hang forever, or we panic. */
	if (!p) {
		dump_header(NULL, gfp_mask, order, NULL, mpol_mask);
		panic("Out of memory and no killable processes...\n");
	} else
		oom_kill_process(p, gfp_mask, order, points, overdraft,
				 totalpages, NULL,
				 nodemask, "Out of memory");
}

/*
 * The pagefault handler calls here because it is out of memory, so kill a
 * memory-hogging task.  If any populated zone has ZONE_OOM_LOCKED set, a
 * parallel oom killing is already in progress so do nothing.
 */
void pagefault_out_of_memory(void)
{
	if (mem_cgroup_oom_synchronize(true))
		return;

	if (oom_trylock(NULL)) {
		out_of_memory(NULL, 0, 0, NULL, false);
		oom_unlock(NULL);
	}
}
