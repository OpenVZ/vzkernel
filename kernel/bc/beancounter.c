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
#include <bc/dcache.h>
#include <bc/proc.h>

static struct kmem_cache *ub_cachep;
static struct user_beancounter default_beancounter;
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

unsigned int ub_dcache_threshold __read_mostly = 4 * 1024; /* ~7Mb per container */

static int ubc_ioprio = 1;

/* default maximum perpcu resources precharge */
int ub_resource_precharge[UB_RESOURCES] = {
	[UB_KMEMSIZE]	= 32 * PAGE_SIZE,
       [UB_PRIVVMPAGES]= 256,
	[UB_NUMPROC]	= 4,
	[UB_PHYSPAGES]	= 512,	/* up to 2Mb, 1 huge page */
	[UB_NUMSIGINFO]	= 4,
	[UB_DCACHESIZE] = 4 * PAGE_SIZE,
	[UB_NUMFILE]	= 8,
	[UB_SWAPPAGES]	= 256,
};

/* natural limits for percpu precharge bounds */
static int resource_precharge_min = 0;
static int resource_precharge_max = INT_MAX / NR_CPUS;
static struct cgroup *mem_cgroup_root, *blkio_cgroup_root, *ub_cgroup_root;

extern int mem_cgroup_apply_beancounter(struct cgroup *cg,
					struct user_beancounter *ub);

static int ub_mem_cgroup_attach_task(struct user_beancounter *ub,
				     struct task_struct *tsk)
{
	struct cgroup *cg;
	int ret;

	cg = cgroup_kernel_open(mem_cgroup_root, CGRP_CREAT, ub->ub_name);
	if (IS_ERR(cg))
		return PTR_ERR(cg);

	if (ub != get_ub0())
		ret = mem_cgroup_apply_beancounter(cg, ub);
	else
		ret = 0;
	if (!ret)
		ret = cgroup_kernel_attach(cg, tsk);

	cgroup_kernel_close(cg);
	return ret;
}

static int ub_blkio_cgroup_attach_task(struct user_beancounter *ub,
				       struct task_struct *tsk)
{
	struct cgroup *cg;
	int ret;

	if (!ubc_ioprio)
		return 0;

	cg = cgroup_kernel_open(blkio_cgroup_root, CGRP_CREAT, ub->ub_name);
	if (IS_ERR(cg))
		return PTR_ERR(cg);

	ret = cgroup_kernel_attach(cg, tsk);

	cgroup_kernel_close(cg);
	return ret;
}
 
static int ub_cgroup_attach_task(struct user_beancounter *ub,
				 struct task_struct *tsk)
{
	struct cgroup *cg;
	int ret;

	if (ub != get_ub0()) {
		cg = cgroup_kernel_open(ub_cgroup_root, CGRP_CREAT, ub->ub_name);
		if (IS_ERR(cg))
			return PTR_ERR(cg);
	} else
		cg = ub_cgroup_root;

	ret = cgroup_kernel_attach(cg, tsk);

	if (ub != get_ub0())
		cgroup_kernel_close(cg);
	return ret;
}

int ub_attach_task(struct user_beancounter *ub, struct task_struct *tsk)
{
	int ret;
	struct user_beancounter *old_ub = tsk->task_bc.exec_ub;

	ret = ub_mem_cgroup_attach_task(ub, tsk);
	if (ret)
		goto out;
	ret = ub_blkio_cgroup_attach_task(ub, tsk);
	if (ret)
		goto fail_blkio;
	ret = ub_cgroup_attach_task(ub, tsk);
	if (ret)
		goto fail_ub;
out:
	return ret;
fail_ub:
	if (ub != old_ub)
		ub_blkio_cgroup_attach_task(old_ub, tsk);
fail_blkio:
	if (ub != old_ub)
		ub_mem_cgroup_attach_task(old_ub, tsk);
	goto out;
}

int ub_update_mem_cgroup_limits(struct user_beancounter *ub)
{
	struct cgroup *cg;
	int ret;

	if (ub == get_ub0())
		return -EPERM;

	cg = cgroup_kernel_open(mem_cgroup_root, 0, ub->ub_name);
	if (IS_ERR_OR_NULL(cg))
		return PTR_ERR(cg) ?: -ENOENT;
	ret = mem_cgroup_apply_beancounter(cg, ub);
	cgroup_kernel_close(cg);
	return ret;
}

extern void mem_cgroup_fill_ub_parms(struct cgroup *cg,
		struct ubparm *p, struct ubparm *s, struct ubparm *k);

void ub_get_mem_cgroup_parms(struct user_beancounter *ub,
			     struct ubparm *physpages,
			     struct ubparm *swappages,
			     struct ubparm *kmemsize)
{
	struct cgroup *cg;
	struct ubparm parms[3];

	memset(parms, 0, sizeof(parms));

	cg = cgroup_kernel_open(mem_cgroup_root, 0, ub->ub_name);
	if (!IS_ERR_OR_NULL(cg)) {
		mem_cgroup_fill_ub_parms(cg, &parms[0], &parms[1], &parms[2]);
		cgroup_kernel_close(cg);
	}

	if (physpages)
		*physpages = parms[0];
	if (swappages)
		*swappages = parms[1];
	if (kmemsize)
		*kmemsize = parms[2];
}

extern void mem_cgroup_get_nr_pages(struct cgroup *cg, int nid,
				    unsigned long *pages);

void ub_page_stat(struct user_beancounter *ub, const nodemask_t *nodemask,
		  unsigned long *pages)
{
	int nid;
	struct cgroup *cg;

	memset(pages, 0, sizeof(unsigned long) * NR_LRU_LISTS);

	cg = cgroup_kernel_open(mem_cgroup_root, 0, ub->ub_name);
	if (IS_ERR_OR_NULL(cg))
		return;

	for_each_node_mask(nid, *nodemask)
		mem_cgroup_get_nr_pages(cg, nid, pages);

	cgroup_kernel_close(cg);
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
	precharge[UB_PHYSPAGES] += precharge[UB_KMEMSIZE] >> PAGE_SHIFT;
	precharge[UB_OOMGUARPAGES] = precharge[UB_SWAPPAGES];
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
static void init_beancounter_syslimits(struct user_beancounter *ub);

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
	ub_debug(UBD_ALLOC, "Creating ub %p\n", new_ub);

	new_ub = (struct user_beancounter *)kmem_cache_alloc(ub_cachep, 
			GFP_KERNEL);
	if (new_ub == NULL)
		return NULL;

	memcpy(new_ub, &default_beancounter, sizeof(*new_ub));
	init_beancounter_struct(new_ub);

	init_beancounter_precharges(new_ub);

	new_ub->ub_name = kstrdup(name, GFP_KERNEL);
	if (!new_ub->ub_name)
		goto fail_name;

	if (percpu_counter_init(&new_ub->ub_orphan_count, 0))
		goto fail_pcpu;

	new_ub->ub_percpu = alloc_percpu(struct ub_percpu_struct);
	if (new_ub->ub_percpu == NULL)
		goto fail_free;

	return new_ub;

fail_free:
	percpu_counter_destroy(&new_ub->ub_orphan_count);
fail_pcpu:
	kfree(new_ub->ub_name);
fail_name:
	kmem_cache_free(ub_cachep, new_ub);
	return NULL;
}

static inline void free_ub(struct user_beancounter *ub)
{
	percpu_counter_destroy(&ub->ub_orphan_count);
	free_percpu(ub->ub_percpu);
	kfree(ub->ub_store);
	kfree(ub->private_data2);
	kfree(ub->ub_name);
	kmem_cache_free(ub_cachep, ub);
}

struct user_beancounter *get_beancounter_by_name(const char *name, int create)
{
	struct cgroup *cg;
	struct user_beancounter *ub;

	if (!strcmp(name, get_ub0()->ub_name))
		return get_beancounter(get_ub0());

	if (create) {
		/*
		 * We're might be asked to allocate new beancounter
		 * from syscall. In this case we:
		 *  - try to open existing UB
		 *  - if not existed allocate new one and apply old
		 *    veird limits in a sake of compatibility.
		 */
		cg = cgroup_kernel_open(ub_cgroup_root, 0, name);
		if (IS_ERR(cg))
			return NULL;
		if (!cg) {
			cg = cgroup_kernel_open(ub_cgroup_root, CGRP_CREAT, name);
			if (IS_ERR_OR_NULL(cg))
				return NULL;
			pr_warn_once("Allocating UB with syslimits is deprecated!\n");
			init_beancounter_syslimits(cgroup_ub(cg));
		}
	} else {
		cg = cgroup_kernel_open(ub_cgroup_root, 0, name);
		if (IS_ERR_OR_NULL(cg))
			return NULL;
	}

	ub = get_beancounter(cgroup_ub(cg));
	cgroup_kernel_close(cg);
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
	ub_update_resources_locked(ub);

	clean = 1;
	for (i = 0; i < UB_RESOURCES; i++)
		clean &= verify_res(ub, ub_rnames[i], ub->ub_parms[i].held);

	clean &= verify_res(ub, "dirty_pages",
			__ub_stat_get(ub, dirty_pages));
	clean &= verify_res(ub, "writeback_pages",
			__ub_stat_get(ub, writeback_pages));
	clean &= verify_res(ub, "tmpfs_respages", ub->ub_tmpfs_respages);

	clean &= verify_res(ub, "pincount", __ub_percpu_sum(ub, pincount));

	clean &= verify_res(ub, "dcache", !list_empty(&ub->ub_dentry_lru));

	ub_debug_trace(!clean, 5, 60*HZ);

	return clean;
}

static void bc_free_rcu(struct rcu_head *rcu)
{
	struct user_beancounter *ub;

	ub = container_of(rcu, struct user_beancounter, rcu);
	free_ub(ub);
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

	init_beancounter_nolimits(ub);
	spin_lock(&ub_list_lock);
	list_add_rcu(&ub->ub_list, &ub_list_head);
	ub_count++;
	spin_unlock(&ub_list_lock);

	return &ub->css;
}

static void ub_cgroup_css_free(struct cgroup *cg)
{
	struct user_beancounter *ub = cgroup_ub(cg);

	spin_lock(&ub_list_lock);
	ub_count--;
	list_del_rcu(&ub->ub_list);
	spin_unlock(&ub_list_lock);

	if (!bc_verify_held(ub)) {
		printk(KERN_ERR "UB: leaked beancounter %s (%p)\n",
				ub->ub_name, ub);
		add_taint(TAINT_CRAP, LOCKDEP_STILL_OK);
		return;
	}

	call_rcu(&ub->rcu, bc_free_rcu);
}

static void ub_cgroup_attach_work_fn(struct callback_head *ch)
{
	struct task_struct *tsk = current;
	struct user_beancounter *ub;

	rcu_read_lock();
	do {
		ub = cgroup_ub(task_cgroup(current, ub_subsys_id));
	} while (!get_beancounter_rcu(ub));
	put_beancounter(tsk->task_bc.exec_ub);
	tsk->task_bc.exec_ub = ub;
	rcu_read_unlock();
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

static ssize_t ub_cgroup_read(struct cgroup *cg, struct cftype *cft,
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

static int ub_cgroup_write_u64(struct cgroup *cg, struct cftype *cft, u64 val)
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

		if (i == UB_PHYSPAGES ||
		    i == UB_SWAPPAGES ||
		    i == UB_KMEMSIZE)
			continue;

		cft = &cgroup_files[j * UB_CGROUP_NR_ATTRS];
		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.held", ub_rnames[i]);
		cft->flags = CFTYPE_NOT_ON_ROOT;
		cft->private = UB_CGROUP_PRIVATE(i, UB_CGROUP_ATTR_HELD);
		cft->read = ub_cgroup_read;

		cft = &cgroup_files[j * UB_CGROUP_NR_ATTRS + 1];
		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.maxheld", ub_rnames[i]);
		cft->flags = CFTYPE_NOT_ON_ROOT;
		cft->private = UB_CGROUP_PRIVATE(i, UB_CGROUP_ATTR_MAXHELD);
		cft->read = ub_cgroup_read;

		cft = &cgroup_files[j * UB_CGROUP_NR_ATTRS + 2];
		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.barrier", ub_rnames[i]);
		cft->flags = CFTYPE_NOT_ON_ROOT;
		cft->private = UB_CGROUP_PRIVATE(i, UB_CGROUP_ATTR_BARRIER);
		cft->read = ub_cgroup_read;
		cft->write_u64 = ub_cgroup_write_u64;

		cft = &cgroup_files[j * UB_CGROUP_NR_ATTRS + 3];
		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.limit", ub_rnames[i]);
		cft->flags = CFTYPE_NOT_ON_ROOT;
		cft->private = UB_CGROUP_PRIVATE(i, UB_CGROUP_ATTR_LIMIT);
		cft->read = ub_cgroup_read;
		cft->write_u64 = ub_cgroup_write_u64;

		cft = &cgroup_files[j * UB_CGROUP_NR_ATTRS + 4];
		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.failcnt", ub_rnames[i]);
		cft->flags = CFTYPE_NOT_ON_ROOT;
		cft->private = UB_CGROUP_PRIVATE(i, UB_CGROUP_ATTR_FAILCNT);
		cft->read = ub_cgroup_read;

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
	.css_free = ub_cgroup_css_free,
	.attach = ub_cgroup_attach,
	.use_id = true,
};
EXPORT_SYMBOL(ub_subsys);

/*
 *	Generic resource charging stuff
 */

int __charge_beancounter_locked(struct user_beancounter *ub,
		int resource, unsigned long val, enum ub_severity strict)
{
	ub_debug_resource(resource, "Charging %lu for %d of %p with %lu\n",
			val, resource, ub, ub->ub_parms[resource].held);
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
	ub_debug_trace(1, 10, 10*HZ);
}

void __uncharge_beancounter_locked(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	ub_debug_resource(resource, "Uncharging %lu for %d of %p with %lu\n",
			val, resource, ub, ub->ub_parms[resource].held);
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

	switch (resource) {
	case UB_PHYSPAGES:
		/* kmemsize precharge already charged into physpages  */
		precharge += __ub_percpu_sum(ub, precharge[UB_KMEMSIZE]) >> PAGE_SHIFT;
		break;
	case UB_OOMGUARPAGES:
		/* oomguarpages contains swappages and its precharge too */
		precharge = __ub_percpu_sum(ub, precharge[UB_SWAPPAGES]);
		break;
	}

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

void ub_reclaim_rate_limit(struct user_beancounter *ub, int wait, unsigned count)
{
	ktime_t wall;
	u64 step;

	if (!ub->rl_step)
		return;

	spin_lock(&ub->rl_lock);
	step = (u64)ub->rl_step * count;
	wall = ktime_add_ns(ktime_get(), step);
	if (wall.tv64 < ub->rl_wall.tv64)
		wall = ktime_add_ns(ub->rl_wall, step);
	ub->rl_wall = wall;
	spin_unlock(&ub->rl_lock);

	if (wait && get_exec_ub() == ub && !test_thread_flag(TIF_MEMDIE)) {
		set_current_state(TASK_KILLABLE);
		schedule_hrtimeout(&wall, HRTIMER_MODE_ABS);
	}
}

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
	INIT_LIST_HEAD(&ub->ub_tcp_sk_list);
	INIT_LIST_HEAD(&ub->ub_other_sk_list);
	INIT_LIST_HEAD(&ub->ub_dentry_lru);
	INIT_LIST_HEAD(&ub->ub_dentry_top);
	init_oom_control(&ub->oom_ctrl);
	spin_lock_init(&ub->rl_lock);
	ub->rl_wall.tv64 = LLONG_MIN;
}

static void init_beancounter_nolimits(struct user_beancounter *ub)
{
	int k;

	for (k = 0; k < UB_RESOURCES; k++) {
		ub->ub_parms[k].limit = UB_MAXVALUE;
		/* FIXME: whether this is right for physpages and guarantees? */
		ub->ub_parms[k].barrier = UB_MAXVALUE;
	}

	ub->ub_parms[UB_VMGUARPAGES].limit = 0;
	ub->ub_parms[UB_VMGUARPAGES].barrier = 0;

	/* FIXME: set unlimited rate? */
	ub->ub_ratelimit.burst = 4;
	ub->ub_ratelimit.interval = 300*HZ;

	if (ub != get_ub0())
		ub->rl_step = NSEC_PER_SEC / 25600; /* 100 Mb/s */
}

static void init_beancounter_syslimits(struct user_beancounter *ub)
{
	unsigned long mp;
	extern int max_threads;
	int k;

	mp = num_physpages;
	ub->ub_parms[UB_KMEMSIZE].limit = 
		mp > (192*1024*1024 >> PAGE_SHIFT) ?
				32*1024*1024 : (mp << PAGE_SHIFT) / 6;
	ub->ub_parms[UB_LOCKEDPAGES].limit = 8;
	ub->ub_parms[UB_PRIVVMPAGES].limit = UB_MAXVALUE;
	ub->ub_parms[UB_SHMPAGES].limit = 64;
	ub->ub_parms[UB_NUMPROC].limit = max_threads / 2;
	ub->ub_parms[UB_NUMTCPSOCK].limit = 1024;
	ub->ub_parms[UB_TCPSNDBUF].limit = 1024*4*1024; /* 4k per socket */
	ub->ub_parms[UB_TCPRCVBUF].limit = 1024*6*1024; /* 6k per socket */
	ub->ub_parms[UB_NUMOTHERSOCK].limit = 256;
	ub->ub_parms[UB_DGRAMRCVBUF].limit = 256*4*1024; /* 4k per socket */
	ub->ub_parms[UB_OTHERSOCKBUF].limit = 256*8*1024; /* 8k per socket */
	ub->ub_parms[UB_NUMFLOCK].limit = 1024;
	ub->ub_parms[UB_NUMPTY].limit = 16;
	ub->ub_parms[UB_NUMSIGINFO].limit = 1024;
	ub->ub_parms[UB_DCACHESIZE].limit = 1024*1024;
	ub->ub_parms[UB_NUMFILE].limit = 1024;
	ub->ub_parms[UB_PHYSPAGES].limit = UB_MAXVALUE;
	ub->ub_parms[UB_SWAPPAGES].limit = UB_MAXVALUE;

	for (k = 0; k < UB_RESOURCES; k++)
		ub->ub_parms[k].barrier = ub->ub_parms[k].limit;

	ub->ub_ratelimit.burst = 4;
	ub->ub_ratelimit.interval = 300*HZ;

	ub->rl_step = NSEC_PER_SEC / 25600; /* 100 Mb/s */
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
	{
		.procname	= "dcache_threshold",
		.data		= &ub_dcache_threshold,
		.maxlen		= sizeof(ub_dcache_threshold),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{
		.procname	= "ioprio",
		.data		= &ubc_ioprio,
		.maxlen		= sizeof(ubc_ioprio),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
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
	ub_cachep = kmem_cache_create("user_beancounters",
			sizeof(struct user_beancounter),
			0, SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);

	memset(&default_beancounter, 0, sizeof(default_beancounter));
#ifdef CONFIG_BC_UNLIMITED
	init_beancounter_nolimits(&default_beancounter);
#else
	init_beancounter_syslimits(&default_beancounter);
#endif
	init_beancounter_struct(&default_beancounter);

	init_oom_control(&global_oom_ctrl);
}

int __init ub_init_cgroup(void)
{
	int err;
	struct vfsmount *blkio_mnt, *mem_mnt, *ub_mnt;
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

	blkio_mnt = cgroup_kernel_mount(&blkio_opts);
	if (IS_ERR(blkio_mnt))
		return PTR_ERR(blkio_mnt);
	blkio_cgroup_root = cgroup_get_root(blkio_mnt);

	mem_mnt = cgroup_kernel_mount(&mem_opts);
	if (IS_ERR(mem_mnt)) {
		kern_unmount(blkio_mnt);
		return PTR_ERR(mem_mnt);
	}
	mem_cgroup_root = cgroup_get_root(mem_mnt);

	ub_mnt = cgroup_kernel_mount(&ub_opts);
	if (IS_ERR(ub_mnt)) {
		kern_unmount(blkio_mnt);
		kern_unmount(mem_mnt);
		return PTR_ERR(ub_mnt);
	}
	ub_cgroup_root = cgroup_get_root(ub_mnt);

	err = ub_attach_task(&ub0, init_pid_ns.child_reaper);
	if (err)
		return err;

	/* pin ub0's cgroups to prevent insidious systemd from deleting them */
	cgroup_kernel_open(mem_cgroup_root, 0, ub0.ub_name);
	cgroup_kernel_open(blkio_cgroup_root, 0, ub0.ub_name);

	return 0;
}
late_initcall(ub_init_cgroup);

static int __init parse_ubc_ioprio(char *arg)
{
	ubc_ioprio = simple_strtoul(arg, NULL, 0);
	return 0;
}
__setup("ubc.ioprio=", parse_ubc_ioprio);
