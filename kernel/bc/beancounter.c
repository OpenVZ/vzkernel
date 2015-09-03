/*
 *  linux/kernel/bc/beancounter.c
 *
 *  Copyright (C) 1998  Alan Cox
 *                1998-2000  Andrey V. Savochkin <saw@saw.sw.com.sg>
 *  Copyright (C) 2000-2005 SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 * TODO:
 *   - more intelligent limit check in mremap(): currently the new size is
 *     charged and _then_ old size is uncharged
 *     (almost done: !move_vma case is completely done,
 *      move_vma in its current implementation requires too many conditions to
 *      do things right, because it may be not only expansion, but shrinking
 *      also, plus do_munmap will require an additional parameter...)
 *   - problem: bad pmd page handling
 *   - consider /proc redesign
 *   - TCP/UDP ports
 *   + consider whether __charge_beancounter_locked should be inline
 *
 * Changes:
 *   1999/08/17  Marcelo Tosatti <marcelo@conectiva.com.br>
 *	- Set "barrier" and "limit" parts of limits atomically.
 *   1999/10/06  Marcelo Tosatti <marcelo@conectiva.com.br>
 *	- setublimit system call.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/sched.h>
#include <linux/random.h>
#include <linux/cgroup.h>
#include <linux/pid_namespace.h>
#include <linux/ve.h>
#include <linux/cgroup.h>
#include <linux/task_work.h>

#include <bc/beancounter.h>
#include <bc/io_acct.h>
#include <bc/vmpages.h>
#include <bc/proc.h>

struct user_beancounter ub0 = {
};
EXPORT_SYMBOL(ub0);

const char *ub_rnames[] = {
	"kmemsize",	/* 0 */
	"lockedpages",
	"privvmpages",
	"shmpages",
	"dummy",
	"numproc",	/* 5 */
	"physpages",
	"vmguarpages",
	"oomguarpages",
	"numtcpsock",
	"numflock",	/* 10 */
	"numpty",
	"numsiginfo",
	"tcpsndbuf",
	"tcprcvbuf",
	"othersockbuf",	/* 15 */
	"dgramrcvbuf",
	"numothersock",
	"dcachesize",
	"numfile",
	"dummy",	/* 20 */
	"dummy",
	"dummy",
	"numiptent",
	"swappages",
};

/* default maximum perpcu resources precharge */
int ub_resource_precharge[UB_RESOURCES] = {
	[UB_PRIVVMPAGES]= 256,
	[UB_NUMPROC]	= 4,
	[UB_NUMSIGINFO]	= 4,
	[UB_NUMFILE]	= 8,
};

/* natural limits for percpu precharge bounds */
static int resource_precharge_min = 0;
static int resource_precharge_max = INT_MAX / NR_CPUS;

static struct vfsmount *ub_cgroup_mnt;
static struct vfsmount *ub_bound_cgroup_mnt[NR_UB_BOUND_CGROUPS];

#define mem_cgroup_mnt		(ub_bound_cgroup_mnt[UB_MEM_CGROUP])
#define blkio_cgroup_mnt	(ub_bound_cgroup_mnt[UB_BLKIO_CGROUP])

static void __ub_set_css(struct user_beancounter *ub, int idx,
			 struct cgroup_subsys_state *css)
{
	struct cgroup_subsys_state *old_css;
	unsigned long flags;

	if (css)
		css_get(css);

	spin_lock_irqsave(&ub->ub_lock, flags);
	old_css = ub->ub_bound_css[idx];
	ACCESS_ONCE(ub->ub_bound_css[idx]) = css;
	spin_unlock_irqrestore(&ub->ub_lock, flags);

	if (old_css)
		css_put(old_css);
}

struct cgroup_subsys_state *__ub_get_css(struct user_beancounter *ub, int idx)
{
	struct cgroup_subsys_state *css, *root_css;
	unsigned long flags;

	rcu_read_lock();
retry:
	css = ACCESS_ONCE(ub->ub_bound_css[idx]);
	if (likely(css && css_tryget(css))) {
		rcu_read_unlock();
		return css;
	}

	root_css = ub0.ub_bound_css[idx];

	/* cgroup was removed, fall back to the root */
	spin_lock_irqsave(&ub->ub_lock, flags);
	if (unlikely(ub->ub_bound_css[idx] != css)) {
		/* someone did it for us, retry */
		spin_unlock_irqrestore(&ub->ub_lock, flags);
		goto retry;
	}
	ACCESS_ONCE(ub->ub_bound_css[idx]) = root_css;
	spin_unlock_irqrestore(&ub->ub_lock, flags);

	rcu_read_unlock();

	if (css)
		css_put(css);

	css_get(root_css);
	return root_css;
}

static void ub_set_mem_css(struct user_beancounter *ub,
				  struct cgroup_subsys_state *css)
{
	__ub_set_css(ub, UB_MEM_CGROUP, css);
}

static void ub_set_blkio_css(struct user_beancounter *ub,
			     struct cgroup_subsys_state *css)
{
	__ub_set_css(ub, UB_BLKIO_CGROUP, css);
}

/*
 * Used to attach a task to a beancounter in the legacy API.
 */
int ub_attach_task(struct user_beancounter *ub, struct task_struct *tsk)
{
	int ret = 0;
	struct user_beancounter *old_ub = tsk->task_bc.exec_ub;
	struct cgroup_subsys_state *css;

	if (ub == old_ub)
		goto out;
	css = ub_get_mem_css(ub);
	ret = cgroup_kernel_attach(css->cgroup, tsk);
	css_put(css);
	if (ret)
		goto out;
	css = ub_get_blkio_css(ub);
	ret = cgroup_kernel_attach(css->cgroup, tsk);
	css_put(css);
	if (ret)
		goto fail_blkio;
	ret = cgroup_kernel_attach(ub->css.cgroup, tsk);
	if (ret)
		goto fail_ub;
out:
	return ret;
fail_ub:
	css = ub_get_blkio_css(old_ub);
	cgroup_kernel_attach(css->cgroup, tsk);
	css_put(css);
fail_blkio:
	css = ub_get_mem_css(old_ub);
	cgroup_kernel_attach(css->cgroup, tsk);
	css_put(css);
	goto out;
}

extern void mem_cgroup_sync_beancounter(struct mem_cgroup *memcg,
					struct user_beancounter *ub);
extern int mem_cgroup_apply_beancounter(struct mem_cgroup *memcg,
					struct user_beancounter *ub);
extern void mem_cgroup_get_nr_pages(struct mem_cgroup *memcg, int nid,
				    unsigned long *pages);
extern unsigned long mem_cgroup_total_pages(struct mem_cgroup *memcg,
					    bool swap);

/*
 * Update memcg limits according to beancounter configuration.
 */
int ub_update_memcg(struct user_beancounter *ub)
{
	struct cgroup_subsys_state *css;
	int ret;

	css = ub_get_mem_css(ub);
	ret = mem_cgroup_apply_beancounter(mem_cgroup_from_cont(css->cgroup),
					   ub);
	css_put(css);
	return ret;
}

/*
 * Synchronize memcg stats with beancounter.
 */
void ub_sync_memcg(struct user_beancounter *ub)
{
	struct cgroup_subsys_state *css;

	css = ub_get_mem_css(ub);
	mem_cgroup_sync_beancounter(mem_cgroup_from_cont(css->cgroup), ub);
	css_put(css);
}

void ub_page_stat(struct user_beancounter *ub, const nodemask_t *nodemask,
		  unsigned long *pages)
{
	int nid;
	struct cgroup_subsys_state *css;

	memset(pages, 0, sizeof(unsigned long) * NR_LRU_LISTS);

	css = ub_get_mem_css(ub);
	for_each_node_mask(nid, *nodemask)
		mem_cgroup_get_nr_pages(mem_cgroup_from_cont(css->cgroup),
					nid, pages);
	css_put(css);
}

unsigned long ub_total_pages(struct user_beancounter *ub, bool swap)
{
	struct cgroup_subsys_state *css;
	unsigned long ret;

	css = ub_get_mem_css(ub);
	ret = mem_cgroup_total_pages(mem_cgroup_from_cont(css->cgroup), swap);
	css_put(css);
	return ret;
}

void init_beancounter_precharge(struct user_beancounter *ub, int resource)
{
	/* limit maximum precharge with one half of current resource excess */
	ub->ub_parms[resource].max_precharge = min_t(long,
			ub_resource_precharge[resource],
			ub_resource_excess(ub, resource, UB_SOFT) /
			(2 * num_possible_cpus()));
}

static void init_beancounter_precharges(struct user_beancounter *ub)
{
	int resource;

	for ( resource = 0 ; resource < UB_RESOURCES ; resource++ )
		init_beancounter_precharge(ub, resource);
}

static void __init init_beancounter_precharges_early(struct user_beancounter *ub)
{
	int resource;

	for ( resource = 0 ; resource < UB_RESOURCES ; resource++ ) {

		/* DEBUG: sanity checks for initial prechage bounds */
		BUG_ON(ub_resource_precharge[resource] < resource_precharge_min);
		BUG_ON(ub_resource_precharge[resource] > resource_precharge_max);

		ub->ub_parms[resource].max_precharge =
			ub_resource_precharge[resource];
	}
}

void ub_precharge_snapshot(struct user_beancounter *ub, int *precharge)
{
	int cpu, resource;

	memset(precharge, 0, sizeof(int) * UB_RESOURCES);
	for_each_possible_cpu(cpu) {
		struct ub_percpu_struct *pcpu = ub_percpu(ub, cpu);
		for ( resource = 0 ; resource < UB_RESOURCES ; resource++ )
			precharge[resource] += pcpu->precharge[resource];
	}
}

static void uncharge_beancounter_precharge(struct user_beancounter *ub)
{
	int resource, precharge[UB_RESOURCES];

	ub_precharge_snapshot(ub, precharge);
	for ( resource = 0 ; resource < UB_RESOURCES ; resource++ )
		ub->ub_parms[resource].held -= precharge[resource];
}

static void init_beancounter_struct(struct user_beancounter *ub);
static void init_beancounter_nolimits(struct user_beancounter *ub);

static DEFINE_SPINLOCK(ub_list_lock);
LIST_HEAD(ub_list_head); /* protected by ub_list_lock */
EXPORT_SYMBOL(ub_list_head);
int ub_count;

/*
 *	Per user resource beancounting. Resources are tied to their luid.
 *	The resource structure itself is tagged both to the process and
 *	the charging resources (a socket doesn't want to have to search for
 *	things at irq time for example). Reference counters keep things in
 *	hand.
 *
 *	The case where a user creates resource, kills all his processes and
 *	then starts new ones is correctly handled this way. The refcounters
 *	will mean the old entry is still around with resource tied to it.
 */

static struct user_beancounter *alloc_ub(const char *name)
{
	struct user_beancounter *new_ub;

	new_ub = kzalloc(sizeof(*new_ub), GFP_KERNEL);
	if (new_ub == NULL)
		return NULL;

	init_beancounter_nolimits(new_ub);
	init_beancounter_struct(new_ub);

	init_beancounter_precharges(new_ub);

	new_ub->ub_name = kstrdup(name, GFP_KERNEL);
	if (!new_ub->ub_name)
		goto fail_name;

	new_ub->ub_percpu = alloc_percpu(struct ub_percpu_struct);
	if (new_ub->ub_percpu == NULL)
		goto fail_free;

	return new_ub;

fail_free:
	kfree(new_ub->ub_name);
fail_name:
	kfree(new_ub);
	return NULL;
}

static inline void free_ub(struct user_beancounter *ub)
{
	free_percpu(ub->ub_percpu);
	kfree(ub->ub_store);
	kfree(ub->private_data2);
	kfree(ub->ub_name);
	kfree(ub);
}

/*
 * Used to lookup or create a beancounter in the legacy API.
 */
struct user_beancounter *get_beancounter_by_name(const char *name, int create)
{
	struct user_beancounter *ub;
	struct cgroup *cg, *ub_cg;
	int err = 0;

	if (!strcmp(name, get_ub0()->ub_name))
		return get_beancounter(get_ub0());

	ub_cg = cgroup_kernel_open(cgroup_get_root(ub_cgroup_mnt), 0, name);
	if (IS_ERR(ub_cg))
		return NULL;
	if (ub_cg) {
		ub = cgroup_ub(ub_cg);
		goto out;
	}
	if (!create)
		return NULL;

	/* The beancounter does not exist and we were asked to create it */

	ub_cg = cgroup_kernel_open(cgroup_get_root(ub_cgroup_mnt),
				   CGRP_CREAT, name);
	if (IS_ERR(ub_cg))
		return ERR_CAST(ub_cg);

	ub = cgroup_ub(ub_cg);

	cg = cgroup_kernel_open(cgroup_get_root(mem_cgroup_mnt),
				CGRP_CREAT, name);
	err = PTR_ERR(cg);
	if (IS_ERR(cg))
		goto out;

	ub_set_mem_css(ub, cgroup_subsys_state(cg, mem_cgroup_subsys_id));
	cgroup_kernel_close(cg);

	cg = cgroup_kernel_open(cgroup_get_root(blkio_cgroup_mnt),
				CGRP_CREAT, name);
	err = PTR_ERR(cg);
	if (IS_ERR(cg))
		goto out;

	ub_set_blkio_css(ub, cgroup_subsys_state(cg, blkio_subsys_id));
	cgroup_kernel_close(cg);

	err = ub_update_memcg(cgroup_ub(ub_cg));
	if (err)
		pr_warn("Failed to init UB %s limits: %d\n", name, err);

out:
	if (!err)
		get_beancounter(ub);
	else
		ub = NULL;

	/* Don't care about cgroup removal on error, because currently we never
	 * cleanup beancounter cgroups in the legacy mode */
	cgroup_kernel_close(ub_cg);
	return ub;
}

struct user_beancounter *get_beancounter_byuid(uid_t uid, int create)
{
	char name[32];

	snprintf(name, sizeof(name), "%u", uid);
	return get_beancounter_by_name(name, create);
}
EXPORT_SYMBOL(get_beancounter_byuid);

uid_t ub_legacy_id(struct user_beancounter *ub)
{
	uid_t id;

	if (kstrtouint(ub->ub_name, 10, &id) != 0)
		id = -1;
	return id;
}

static int verify_res(struct user_beancounter *ub, const char *name,
		unsigned long held)
{
	if (likely(held == 0))
		return 1;

	printk(KERN_WARNING "Ub %s helds %ld in %s on put\n",
			ub->ub_name, held, name);
	return 0;
}

static inline int bc_verify_held(struct user_beancounter *ub)
{
	int i, clean;

	ub_stat_mod(ub, dirty_pages, __ub_percpu_sum(ub, dirty_pages));
	ub_stat_mod(ub, writeback_pages, __ub_percpu_sum(ub, writeback_pages));
	uncharge_beancounter_precharge(ub);

	/* accounted by memcg */
	ub->ub_parms[UB_KMEMSIZE].held = 0;
	ub->ub_parms[UB_DCACHESIZE].held = 0;
	ub->ub_parms[UB_PHYSPAGES].held = 0;
	ub->ub_parms[UB_SWAPPAGES].held = 0;
	ub->ub_parms[UB_OOMGUARPAGES].held = 0;
	ub->ub_parms[UB_NUMTCPSOCK].held = 0;
	ub->ub_parms[UB_TCPSNDBUF].held = 0;
	ub->ub_parms[UB_TCPRCVBUF].held = 0;
	ub->ub_parms[UB_OTHERSOCKBUF].held = 0;
	ub->ub_parms[UB_DGRAMRCVBUF].held = 0;
	ub->ub_parms[UB_NUMOTHERSOCK].held = 0;

	clean = 1;
	for (i = 0; i < UB_RESOURCES; i++)
		clean &= verify_res(ub, ub_rnames[i], ub->ub_parms[i].held);

	clean &= verify_res(ub, "dirty_pages",
			__ub_stat_get(ub, dirty_pages));
	clean &= verify_res(ub, "writeback_pages",
			__ub_stat_get(ub, writeback_pages));

	return clean;
}

static struct cgroup_subsys_state *ub_cgroup_css_alloc(struct cgroup *cg)
{
	struct user_beancounter *ub;

	if (!cg->parent)
		return &ub0.css;

	/* forbid nested containers */
	if (cgroup_ub(cg->parent) != &ub0)
		return ERR_PTR(-EPERM);

	ub = alloc_ub(cg->dentry->d_name.name);
	if (!ub)
		return ERR_PTR(-ENOMEM);

	return &ub->css;
}

static int ub_cgroup_css_online(struct cgroup *cg)
{
	struct user_beancounter *ub = cgroup_ub(cg);

	if (!cg->parent)
		return 0;

	init_beancounter_nolimits(ub);
	spin_lock(&ub_list_lock);
	list_add_rcu(&ub->ub_list, &ub_list_head);
	ub_count++;
	spin_unlock(&ub_list_lock);
	return 0;
}

static void ub_cgroup_css_offline(struct cgroup *cg)
{
	struct user_beancounter *ub = cgroup_ub(cg);

	spin_lock(&ub_list_lock);
	ub_count--;
	list_del_rcu(&ub->ub_list);
	spin_unlock(&ub_list_lock);
}

static void ub_cgroup_css_free(struct cgroup *cg)
{
	struct user_beancounter *ub = cgroup_ub(cg);
	int i;

	for (i = 0; i < NR_UB_BOUND_CGROUPS; i++)
		__ub_set_css(ub, i, NULL);

	if (!bc_verify_held(ub)) {
		printk(KERN_ERR "UB: leaked beancounter %s (%p)\n",
				ub->ub_name, ub);
		add_taint(TAINT_CRAP, LOCKDEP_STILL_OK);
		return;
	}
	free_ub(ub);
}

static void __ub_cgroup_attach(struct task_struct *tsk)
{
	struct user_beancounter *ub;

	rcu_read_lock();
	do {
		ub = cgroup_ub(task_cgroup(current, ub_subsys_id));
		if (tsk->task_bc.exec_ub == ub)
			goto out;
	} while (!get_beancounter_rcu(ub));
	put_beancounter(tsk->task_bc.exec_ub);
	tsk->task_bc.exec_ub = ub;
out:
	rcu_read_unlock();
}

static void ub_cgroup_attach_work_fn(struct callback_head *ch)
{
	__ub_cgroup_attach(current);
}

static void ub_cgroup_attach(struct cgroup *cg, struct cgroup_taskset *tset)
{
	struct task_struct *p;

	/*
	 * task_bc->exec_ub can only be modified by the owner task so we use
	 * task work to get things done
	 */
	cgroup_taskset_for_each(p, cg, tset) {
		/*
		 * kthreads cannot be kicked to run a task work so we just
		 * don't change ub for them
		 */
		if (p->flags & PF_KTHREAD)
			return;

		init_task_work(&p->task_bc.cgroup_attach_work,
			       ub_cgroup_attach_work_fn);
		task_work_cancel(p, ub_cgroup_attach_work_fn);
		task_work_add(p, &p->task_bc.cgroup_attach_work, true);
	}
}

static void ub_cgroup_fork(struct task_struct *tsk)
{
	/*
	 * If a forking task is moved between cgroups, the child will have
	 * exec_ub set to the source cgroup while being attached to the
	 * destination cgroup, because the parent's exec_ub will only change
	 * when it returns to userspace (see ub_cgroup_attach). To avoid this
	 * discrepancy, here we synchronize the child's exec_ub with its
	 * cgroup. It is safe, because the task is not allowed to run yet and
	 * therefore cannot get/set its exec_ub.
	 */
	__ub_cgroup_attach(tsk);
}

static ssize_t ub_cgroup_read(struct cgroup *cg, struct cftype *cft,
			      struct file *file, char __user *buf,
			      size_t nbytes, loff_t *ppos)
{
	struct user_beancounter *ub = cgroup_ub(cg);
	struct cgroup_subsys_state *bound_css;
	char *path;
	int len;
	ssize_t ret;

	bound_css = __ub_get_css(ub, cft->private);

	ret = -ENOMEM;
	path = kmalloc(PATH_MAX + 1, GFP_KERNEL);
	if (!path)
		goto out;
	ret = cgroup_path(bound_css->cgroup, path, PATH_MAX);
	if (!ret) {
		len = strlen(path);
		path[len++] = '\n';
		path[len] = '\0';
		ret = simple_read_from_buffer(buf, nbytes, ppos, path, len);
	}
	kfree(path);
out:
	css_put(bound_css);
	return ret;
}

static int ub_cgroup_write(struct cgroup *cg, struct cftype *cft,
			   const char *buf)
{
	struct user_beancounter *ub = cgroup_ub(cg);
	struct cgroup *bound_cg;

	bound_cg = cgroup_kernel_lookup(ub_bound_cgroup_mnt[cft->private],
					buf);
	if (IS_ERR(bound_cg))
		return PTR_ERR(bound_cg);

	switch (cft->private) {
	case UB_MEM_CGROUP:
		ub_set_mem_css(ub, cgroup_subsys_state(bound_cg,
					mem_cgroup_subsys_id));
		break;
	case UB_BLKIO_CGROUP:
		ub_set_blkio_css(ub, cgroup_subsys_state(bound_cg,
					blkio_subsys_id));
		break;
	}

	cgroup_kernel_close(bound_cg);
	return 0;
}

static struct cftype ub_cgroup_files[] = {
	{
		.name = "memory",
		.flags = CFTYPE_NOT_ON_ROOT,
		.private = UB_MEM_CGROUP,
		.write_string = ub_cgroup_write,
		.read = ub_cgroup_read,
	},
	{
		.name = "blkio",
		.flags = CFTYPE_NOT_ON_ROOT,
		.private = UB_BLKIO_CGROUP,
		.write_string = ub_cgroup_write,
		.read = ub_cgroup_read,
	},
	{ },	/* terminate */
};

enum {
	UB_CGROUP_ATTR_HELD,
	UB_CGROUP_ATTR_MAXHELD,
	UB_CGROUP_ATTR_BARRIER,
	UB_CGROUP_ATTR_LIMIT,
	UB_CGROUP_ATTR_FAILCNT,
	UB_CGROUP_NR_ATTRS,
};

#define UB_CGROUP_PRIVATE(res, attr)	(((res) << 16) | (attr))
#define UB_CGROUP_RES(val)		(((val) >> 16) & 0xffff)
#define UB_CGROUP_ATTR(val)		((val) & 0xffff)

static ssize_t ub_cgroup_resource_read(struct cgroup *cg, struct cftype *cft,
				       struct file *file, char __user *buf,
				       size_t nbytes, loff_t *ppos)
{
	struct user_beancounter *ub = cgroup_ub(cg);
	struct ubparm *ubparm;
	unsigned long val;
	int res, attr;
	int len;
	char str[32];

	res = UB_CGROUP_RES(cft->private);
	attr = UB_CGROUP_ATTR(cft->private);

	ubparm = &ub->ub_parms[res];

	switch (attr) {
	case UB_CGROUP_ATTR_HELD:
		val = ubparm->held;
		break;
	case UB_CGROUP_ATTR_MAXHELD:
		val = ubparm->maxheld;
		break;
	case UB_CGROUP_ATTR_BARRIER:
		val = ubparm->barrier;
		break;
	case UB_CGROUP_ATTR_LIMIT:
		val = ubparm->limit;
		break;
	case UB_CGROUP_ATTR_FAILCNT:
		val = ubparm->failcnt;
		break;
	default:
		BUG();
	}

	len = scnprintf(str, sizeof(str), "%lu\n", val);
	return simple_read_from_buffer(buf, nbytes, ppos, str, len);
}

static int ub_cgroup_resource_write(struct cgroup *cg, struct cftype *cft,
				    u64 val)
{
	struct user_beancounter *ub = cgroup_ub(cg);
	struct ubparm *ubparm;
	int res, attr;

	if (val > UB_MAXVALUE)
		return -EINVAL;

	res = UB_CGROUP_RES(cft->private);
	attr = UB_CGROUP_ATTR(cft->private);

	ubparm = &ub->ub_parms[res];

	spin_lock_irq(&ub->ub_lock);
	switch (attr) {
	case UB_CGROUP_ATTR_BARRIER:
		ubparm->barrier = val;
		break;
	case UB_CGROUP_ATTR_LIMIT:
		ubparm->limit = val;
		break;
	default:
		BUG();
	}
	init_beancounter_precharge(ub, res);
	spin_unlock_irq(&ub->ub_lock);
	return 0;
}

static __init int ub_cgroup_init(void)
{
	static struct cftype cgroup_files[UB_RESOURCES * UB_CGROUP_NR_ATTRS + 1];
	struct cftype *cft;
	int i, j;

	for (i = 0, j = 0; i < UB_RESOURCES; i++) {
		if (!strcmp(ub_rnames[i], "dummy"))
			continue;

		/* accounted by memcg */
		switch (i) {
		case UB_KMEMSIZE:
		case UB_DCACHESIZE:
		case UB_PHYSPAGES:
		case UB_SWAPPAGES:
		case UB_OOMGUARPAGES:
		case UB_NUMTCPSOCK:
		case UB_TCPSNDBUF:
		case UB_TCPRCVBUF:
		case UB_OTHERSOCKBUF:
		case UB_DGRAMRCVBUF:
		case UB_NUMOTHERSOCK:
			continue;
		}

		cft = &cgroup_files[j * UB_CGROUP_NR_ATTRS];
		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.held", ub_rnames[i]);
		cft->flags = CFTYPE_NOT_ON_ROOT;
		cft->private = UB_CGROUP_PRIVATE(i, UB_CGROUP_ATTR_HELD);
		cft->read = ub_cgroup_resource_read;

		cft = &cgroup_files[j * UB_CGROUP_NR_ATTRS + 1];
		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.maxheld", ub_rnames[i]);
		cft->flags = CFTYPE_NOT_ON_ROOT;
		cft->private = UB_CGROUP_PRIVATE(i, UB_CGROUP_ATTR_MAXHELD);
		cft->read = ub_cgroup_resource_read;

		cft = &cgroup_files[j * UB_CGROUP_NR_ATTRS + 2];
		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.barrier", ub_rnames[i]);
		cft->flags = CFTYPE_NOT_ON_ROOT;
		cft->private = UB_CGROUP_PRIVATE(i, UB_CGROUP_ATTR_BARRIER);
		cft->read = ub_cgroup_resource_read;
		cft->write_u64 = ub_cgroup_resource_write;

		cft = &cgroup_files[j * UB_CGROUP_NR_ATTRS + 3];
		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.limit", ub_rnames[i]);
		cft->flags = CFTYPE_NOT_ON_ROOT;
		cft->private = UB_CGROUP_PRIVATE(i, UB_CGROUP_ATTR_LIMIT);
		cft->read = ub_cgroup_resource_read;
		cft->write_u64 = ub_cgroup_resource_write;

		cft = &cgroup_files[j * UB_CGROUP_NR_ATTRS + 4];
		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.failcnt", ub_rnames[i]);
		cft->flags = CFTYPE_NOT_ON_ROOT;
		cft->private = UB_CGROUP_PRIVATE(i, UB_CGROUP_ATTR_FAILCNT);
		cft->read = ub_cgroup_resource_read;

		j++;
	}

	WARN_ON(cgroup_add_cftypes(&ub_subsys, cgroup_files));

	return 0;
}
module_init(ub_cgroup_init);

struct cgroup_subsys ub_subsys = {
	.name = "beancounter",
	.subsys_id = ub_subsys_id,
	.css_alloc = ub_cgroup_css_alloc,
	.css_online = ub_cgroup_css_online,
	.css_offline = ub_cgroup_css_offline,
	.css_free = ub_cgroup_css_free,
	.attach = ub_cgroup_attach,
	.fork = ub_cgroup_fork,
	.base_cftypes = ub_cgroup_files,
	.use_id = true,
};
EXPORT_SYMBOL(ub_subsys);

/*
 *	Generic resource charging stuff
 */

int __charge_beancounter_locked(struct user_beancounter *ub,
		int resource, unsigned long val, enum ub_severity strict)
{
	/*
	 * ub_value <= UB_MAXVALUE, value <= UB_MAXVALUE, and only one addition
	 * at the moment is possible so an overflow is impossible.  
	 */
	ub->ub_parms[resource].held += val;

	switch (strict & ~UB_SEV_FLAGS) {
		case UB_HARD:
			if (ub->ub_parms[resource].held >
					ub->ub_parms[resource].barrier)
				break;
		case UB_SOFT:
			if (ub->ub_parms[resource].held >
					ub->ub_parms[resource].limit)
				break;
		case UB_FORCE:
			ub_adjust_maxheld(ub, resource);
			return 0;
		default:
			BUG();
	}

	if (!(strict & UB_TEST)) {
		if (strict == UB_SOFT && __ratelimit(&ub->ub_ratelimit))
			printk(KERN_INFO "Fatal resource shortage: %s, UB %s.\n",
			       ub_rnames[resource], ub->ub_name);
		ub->ub_parms[resource].failcnt++;
	}
	ub->ub_parms[resource].held -= val;
	return -ENOMEM;
}

int charge_beancounter(struct user_beancounter *ub,
		int resource, unsigned long val, enum ub_severity strict)
{
	int retval;
	unsigned long flags;

	retval = -EINVAL;
	if (val > UB_MAXVALUE)
		goto out;

	if (ub) {
		spin_lock_irqsave(&ub->ub_lock, flags);
		retval = __charge_beancounter_locked(ub, resource, val, strict);
		spin_unlock_irqrestore(&ub->ub_lock, flags);
	}
out:
	return retval;
}

EXPORT_SYMBOL(charge_beancounter);

void uncharge_warn(struct user_beancounter *ub, const char *resource,
		unsigned long val, unsigned long held)
{
	printk(KERN_ERR "Uncharging too much %lu h %lu, res %s ub %s\n",
			val, held, resource, ub->ub_name);
}

void __uncharge_beancounter_locked(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	if (ub->ub_parms[resource].held < val) {
		uncharge_warn(ub, ub_rnames[resource],
				val, ub->ub_parms[resource].held);
		val = ub->ub_parms[resource].held;
	}
	ub->ub_parms[resource].held -= val;
}

void uncharge_beancounter(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	unsigned long flags;

	if (ub) {
		spin_lock_irqsave(&ub->ub_lock, flags);
		__uncharge_beancounter_locked(ub, resource, val);
		spin_unlock_irqrestore(&ub->ub_lock, flags);
	}
}

EXPORT_SYMBOL(uncharge_beancounter);

/* called with disabled interrupts */
static int __precharge_beancounter_percpu(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	struct ub_percpu_struct *ub_pcpu = ub_percpu(ub, smp_processor_id());
	int charge, retval;

	BUG_ON(ub->ub_parms[resource].max_precharge < 0);

	if (likely(ub_pcpu->precharge[resource] >= val))
		return 0;

	spin_lock(&ub->ub_lock);
	charge = max((int)val, ub->ub_parms[resource].max_precharge >> 1) -
		ub_pcpu->precharge[resource];
	retval = __charge_beancounter_locked(ub, resource,
			charge, UB_SOFT | UB_TEST);
	if (!retval)
		ub_pcpu->precharge[resource] += charge;
	spin_unlock(&ub->ub_lock);

	return retval;
}

/* called with disabled interrupts */
int __charge_beancounter_percpu(struct user_beancounter *ub,
		struct ub_percpu_struct *ub_pcpu,
		int resource, unsigned long val, enum ub_severity strict)
{
	int retval, precharge;

	spin_lock(&ub->ub_lock);
	precharge = max(0, (ub->ub_parms[resource].max_precharge >> 1) -
			ub_pcpu->precharge[resource]);
	retval = __charge_beancounter_locked(ub, resource,
			val + precharge, UB_SOFT | UB_TEST);
	if (!retval)
		ub_pcpu->precharge[resource] += precharge;
	else {
		init_beancounter_precharge(ub, resource);
		retval = __charge_beancounter_locked(ub, resource,
				val, strict);
	}
	spin_unlock(&ub->ub_lock);

	return retval;
}
EXPORT_SYMBOL(__charge_beancounter_percpu);

/* called with disabled interrupts */
void __uncharge_beancounter_percpu(struct user_beancounter *ub,
		struct ub_percpu_struct *ub_pcpu,
		int resource, unsigned long val)
{
	int uncharge;

	spin_lock(&ub->ub_lock);
	if (ub->ub_parms[resource].max_precharge !=
			ub_resource_precharge[resource])
		init_beancounter_precharge(ub, resource);
	uncharge = max(0, ub_pcpu->precharge[resource] -
			(ub->ub_parms[resource].max_precharge >> 1));
	ub_pcpu->precharge[resource] -= uncharge;
	smp_wmb();
	__uncharge_beancounter_locked(ub, resource, val + uncharge);
	spin_unlock(&ub->ub_lock);
}
EXPORT_SYMBOL(__uncharge_beancounter_percpu);

unsigned long __get_beancounter_usage_percpu(struct user_beancounter *ub,
		int resource)
{
	long held, precharge;

	held = ub->ub_parms[resource].held;
	smp_rmb();
	precharge = __ub_percpu_sum(ub, precharge[resource]);

	return max(0l, held - precharge);
}

int precharge_beancounter(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	unsigned long flags;
	int retval;

	retval = -EINVAL;
	if (val > UB_MAXVALUE)
		goto out;

	local_irq_save(flags);
	if (ub)
		retval = __precharge_beancounter_percpu(ub, resource, val);
	local_irq_restore(flags);
out:
	return retval;
}
EXPORT_SYMBOL(precharge_beancounter);

/*
 *	Initialization
 *
 *	struct user_beancounter contains
 *	 - limits and other configuration settings,
 *	   with a copy stored for accounting purposes,
 *	 - structural fields: lists, spinlocks and so on.
 *
 *	Before these parts are initialized, the structure should be memset
 *	to 0 or copied from a known clean structure.  That takes care of a lot
 *	of fields not initialized explicitly.
 */

static void init_beancounter_struct(struct user_beancounter *ub)
{
	ub->ub_magic = UB_MAGIC;
	spin_lock_init(&ub->ub_lock);
}

static void init_beancounter_nolimits(struct user_beancounter *ub)
{
	int k;

	for (k = 0; k < UB_RESOURCES; k++) {
		ub->ub_parms[k].limit = UB_MAXVALUE;
		ub->ub_parms[k].barrier = UB_MAXVALUE;
	}

	/*
	 * Unlimited vmguarpages gives immunity against systemwide overcommit
	 * policy. It makes sense in some cases but by default we must obey it.
	 */
	ub->ub_parms[UB_VMGUARPAGES].barrier = 0;

	/*
	 * Unlimited oomguarpages makes container or host mostly immune to
	 * to the OOM-killer while other containers exists. Withal we cannot
	 * set it to zero, otherwise single unconfigured container will be
	 * first target for OOM-killer. 75% of ram looks like sane default.
	 */
	ub->ub_parms[UB_OOMGUARPAGES].barrier = totalram_pages * 3 / 4;

	/* Ratelimit for messages in the kernel log */
	ub->ub_ratelimit.burst = 4;
	ub->ub_ratelimit.interval = 300*HZ;
}

static DEFINE_PER_CPU(struct ub_percpu_struct, ub0_percpu);

void __init ub_init_early(void)
{
	struct user_beancounter *ub;

	ub = get_ub0();
	ub->ub_name = "0";
	init_beancounter_nolimits(ub);
	init_beancounter_struct(ub);
	init_beancounter_precharges_early(ub);
	ub->ub_percpu = &ub0_percpu;

	memset(&current->task_bc, 0, sizeof(struct task_beancounter));
	(void)set_exec_ub(ub);
	current->task_bc.task_ub = get_beancounter(ub);
	__charge_beancounter_locked(ub, UB_NUMPROC, 1, UB_FORCE);
	init_mm.mm_ub = get_beancounter(ub);

	list_add(&ub->ub_list, &ub_list_head);
	ub_count++;
}

static int proc_resource_precharge(ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos)
{
	static DEFINE_MUTEX(lock);
	struct user_beancounter *ub;
	int err;

	mutex_lock(&lock);

	err = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	if (err || !write)
		goto out;

	rcu_read_lock();
	for_each_beancounter(ub) {
		spin_lock_irq(&ub->ub_lock);
		init_beancounter_precharges(ub);
		spin_unlock_irq(&ub->ub_lock);
	}
	rcu_read_unlock();

out:
	mutex_unlock(&lock);
	return err;
}

static ctl_table ub_sysctl_table[] = {
	{
		.procname	= "resource_precharge",
		.data		= &ub_resource_precharge,
		.extra1		= &resource_precharge_min,
		.extra2		= &resource_precharge_max,
		.maxlen		= sizeof(ub_resource_precharge),
		.mode		= 0644,
		.proc_handler	= &proc_resource_precharge,
	},
#ifdef CONFIG_BC_IO_ACCOUNTING
	{
		.procname	= "dirty_ratio",
		.data		= &ub_dirty_radio,
		.maxlen		= sizeof ub_dirty_radio,
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "dirty_background_ratio",
		.data		= &ub_dirty_background_ratio,
		.maxlen		= sizeof ub_dirty_background_ratio,
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
#endif /* CONFIG_BC_IO_ACCOUNTING */
	{ }
};

static ctl_table ub_sysctl_root[] = {
       {
	       .procname	= "ubc",
	       .mode		= 0555,
	       .child		= ub_sysctl_table,
       },
       { }
};

void __init ub_init_late(void)
{
	register_sysctl_table(ub_sysctl_root);
}

int __init ub_init_cgroup(void)
{
	struct cgroup_sb_opts blkio_opts = {
		.name		= vz_compat ? "beancounter" : NULL,
		.subsys_mask    = (1ul << blkio_subsys_id),
	};
	struct cgroup_sb_opts mem_opts = {
		.subsys_mask    = (1ul << mem_cgroup_subsys_id),
	};
	struct cgroup_sb_opts ub_opts = {
		.subsys_mask	= (1ul << ub_subsys_id),
	};

	blkio_cgroup_mnt = cgroup_kernel_mount(&blkio_opts);
	if (IS_ERR(blkio_cgroup_mnt))
		panic("Failed to mount blkio cgroup: %ld\n",
		      PTR_ERR(blkio_cgroup_mnt));

	mem_cgroup_mnt = cgroup_kernel_mount(&mem_opts);
	if (IS_ERR(mem_cgroup_mnt))
		panic("Failed to mount memory cgroup: %ld\n",
		      PTR_ERR(mem_cgroup_mnt));

	ub_cgroup_mnt = cgroup_kernel_mount(&ub_opts);
	if (IS_ERR(ub_cgroup_mnt))
		panic("Failed to mount beancounter cgroup: %ld\n",
		      PTR_ERR(ub_cgroup_mnt));

	ub_set_mem_css(&ub0, cgroup_subsys_state(
		cgroup_get_root(mem_cgroup_mnt), mem_cgroup_subsys_id));
	ub_set_blkio_css(&ub0, cgroup_subsys_state(
		cgroup_get_root(blkio_cgroup_mnt), blkio_subsys_id));

	return 0;
}
late_initcall(ub_init_cgroup);
