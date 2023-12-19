/* memcontrol.h - Memory Controller
 *
 * Copyright IBM Corporation, 2007
 * Author Balbir Singh <balbir@linux.vnet.ibm.com>
 *
 * Copyright 2007 OpenVZ SWsoft Inc
 * Author: Pavel Emelianov <xemul@openvz.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _LINUX_MEMCONTROL_H
#define _LINUX_MEMCONTROL_H
#include <linux/cgroup.h>
#include <linux/vm_event_item.h>
#include <linux/hardirq.h>
#include <linux/jump_label.h>
#include <linux/page-flags.h>

struct mem_cgroup;
struct page_cgroup;
struct page;
struct mm_struct;
struct kmem_cache;
struct oom_context;

extern struct oom_context global_oom_ctx;

/* Stats that can be updated by kernel. */
enum mem_cgroup_page_stat_item {
	MEMCG_NR_FILE_MAPPED, /* # of pages charged as file rss */
};

struct mem_cgroup_reclaim_cookie {
	struct zone *zone;
	int priority;
	unsigned int generation;
};

/*
 * Bitmap of shrinker::id corresponding to memcg-aware shrinkers,
 * which have elements charged to this memcg.
 */
struct memcg_shrinker_map {
	struct rcu_head rcu;
	unsigned long map[0];
};

/*
 * Reclaim flags for mem_cgroup_hierarchical_reclaim
 */
#define MEM_CGROUP_RECLAIM_NOSWAP_BIT	0x0
#define MEM_CGROUP_RECLAIM_NOSWAP	(1 << MEM_CGROUP_RECLAIM_NOSWAP_BIT)
#define MEM_CGROUP_RECLAIM_SHRINK_BIT	0x1
#define MEM_CGROUP_RECLAIM_SHRINK	(1 << MEM_CGROUP_RECLAIM_SHRINK_BIT)
#define MEM_CGROUP_RECLAIM_KMEM_BIT	0x2
#define MEM_CGROUP_RECLAIM_KMEM		(1 << MEM_CGROUP_RECLAIM_KMEM_BIT)

#ifdef CONFIG_MEMCG

#define MEM_CGROUP_ID_SHIFT	16
#define MEM_CGROUP_ID_MAX	USHRT_MAX

int mem_cgroup_try_charge(struct page *page, struct mm_struct *mm,
			  gfp_t gfp_mask, struct mem_cgroup **memcgp);
int mem_cgroup_try_charge_cache(struct page *page, struct mm_struct *mm,
			  gfp_t gfp_mask, struct mem_cgroup **memcgp);
void mem_cgroup_commit_charge(struct page *page, struct mem_cgroup *memcg,
			      bool lrucare);
void mem_cgroup_cancel_charge(struct page *page, struct mem_cgroup *memcg);
void mem_cgroup_cancel_cache_charge(struct page *page, struct mem_cgroup *memcg);
void mem_cgroup_uncharge(struct page *page);
void mem_cgroup_uncharge_list(struct list_head *page_list);

void mem_cgroup_migrate(struct page *oldpage, struct page *newpage,
			bool lrucare);

struct lruvec *mem_cgroup_zone_lruvec(struct zone *, struct mem_cgroup *);
struct lruvec *mem_cgroup_page_lruvec(struct page *, struct zone *);

bool __mem_cgroup_same_or_subtree(const struct mem_cgroup *root_memcg,
				  struct mem_cgroup *memcg);
int task_in_mem_cgroup(struct task_struct *task, const struct mem_cgroup *memcg);

extern struct mem_cgroup *try_get_mem_cgroup_from_page(struct page *page);
extern struct mem_cgroup *mem_cgroup_from_task(struct task_struct *p);
extern struct mem_cgroup *get_mem_cgroup_from_mm(struct mm_struct *mm);

extern struct mem_cgroup *parent_mem_cgroup(struct mem_cgroup *memcg);
extern struct mem_cgroup *mem_cgroup_from_cont(struct cgroup *cont);

unsigned short mem_cgroup_id(struct mem_cgroup *memcg);
struct mem_cgroup *mem_cgroup_from_id(unsigned short id);

static inline
bool mm_match_cgroup(const struct mm_struct *mm, const struct mem_cgroup *memcg)
{
	struct mem_cgroup *task_memcg;
	bool match;

	rcu_read_lock();
	task_memcg = mem_cgroup_from_task(rcu_dereference(mm->owner));
	match = __mem_cgroup_same_or_subtree(memcg, task_memcg);
	rcu_read_unlock();
	return match;
}

extern struct cgroup_subsys_state *mem_cgroup_css(struct mem_cgroup *memcg);

unsigned long page_cgroup_ino(struct page *page);

struct mem_cgroup *mem_cgroup_iter(struct mem_cgroup *,
				   struct mem_cgroup *,
				   struct mem_cgroup_reclaim_cookie *);
void mem_cgroup_iter_break(struct mem_cgroup *, struct mem_cgroup *);

/*
 * For memory reclaim.
 */
bool mem_cgroup_dcache_is_low(struct mem_cgroup *memcg, int vfs_cache_min_ratio);
bool mem_cgroup_low(struct mem_cgroup *root, struct mem_cgroup *memcg);
bool mem_cgroup_cleancache_disabled(struct page *page);
int mem_cgroup_select_victim_node(struct mem_cgroup *memcg);
unsigned long mem_cgroup_get_lru_size(struct lruvec *lruvec, enum lru_list);
void mem_cgroup_update_lru_size(struct lruvec *, enum lru_list, int);
extern struct oom_context *mem_cgroup_oom_context(struct mem_cgroup *memcg);
extern unsigned long mem_cgroup_overdraft(struct mem_cgroup *memcg);
extern void mem_cgroup_note_oom_kill(struct mem_cgroup *memcg,
				     struct task_struct *task);
extern void mem_cgroup_print_oom_info(struct mem_cgroup *memcg,
					struct task_struct *p);

unsigned long mem_cgroup_node_nr_lru_pages(struct mem_cgroup *memcg,
					   int nid, unsigned int lru_mask);

static inline void mem_cgroup_oom_enable(void)
{
	WARN_ON(current->memcg_oom.may_oom);
	current->memcg_oom.may_oom = 1;
}

static inline void mem_cgroup_oom_disable(void)
{
	WARN_ON(!current->memcg_oom.may_oom);
	current->memcg_oom.may_oom = 0;
}

static inline bool task_in_memcg_oom(struct task_struct *p)
{
	return p->memcg_oom.memcg;
}

bool mem_cgroup_oom_synchronize(bool wait);

#ifdef CONFIG_MEMCG_SWAP
extern int do_swap_account;
#endif

static inline bool mem_cgroup_disabled(void)
{
	if (mem_cgroup_subsys.disabled)
		return true;
	return false;
}

static inline void mem_cgroup_get(struct mem_cgroup *memcg)
{
	css_get(mem_cgroup_css(memcg));
}

static inline void mem_cgroup_put(struct mem_cgroup *memcg)
{
	css_put(mem_cgroup_css(memcg));
}

void __mem_cgroup_begin_update_page_stat(struct page *page, bool *locked,
					 unsigned long *flags);

extern atomic_t memcg_moving;

static inline void mem_cgroup_begin_update_page_stat(struct page *page,
					bool *locked, unsigned long *flags)
{
	if (mem_cgroup_disabled())
		return;

	rcu_read_lock();
	*locked = false;
	if (atomic_read(&memcg_moving))
		__mem_cgroup_begin_update_page_stat(page, locked, flags);
}

void __mem_cgroup_end_update_page_stat(struct page *page,
				unsigned long *flags);
static inline void mem_cgroup_end_update_page_stat(struct page *page,
					bool *locked, unsigned long *flags)
{
	if (mem_cgroup_disabled())
		return;
	if (*locked)
		__mem_cgroup_end_update_page_stat(page, flags);
	rcu_read_unlock();
}

void mem_cgroup_update_page_stat(struct page *page,
				 enum mem_cgroup_page_stat_item idx,
				 int val);

static inline void mem_cgroup_inc_page_stat(struct page *page,
					    enum mem_cgroup_page_stat_item idx)
{
	mem_cgroup_update_page_stat(page, idx, 1);
}

static inline void mem_cgroup_dec_page_stat(struct page *page,
					    enum mem_cgroup_page_stat_item idx)
{
	mem_cgroup_update_page_stat(page, idx, -1);
}

void mem_cgroup_fill_vmstat(struct mem_cgroup *memcg, unsigned long *stats);

unsigned long memcg_ws_activates(struct mem_cgroup *memcg);
void memcg_inc_ws_activate(struct mem_cgroup *memcg);

unsigned long mem_cgroup_soft_limit_reclaim(struct zone *zone, int order,
						gfp_t gfp_mask,
						unsigned long *total_scanned);

void __mem_cgroup_count_vm_event(struct mm_struct *mm, enum vm_event_item idx);
static inline void mem_cgroup_count_vm_event(struct mm_struct *mm,
					     enum vm_event_item idx)
{
	if (mem_cgroup_disabled())
		return;
	__mem_cgroup_count_vm_event(mm, idx);
}
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
void mem_cgroup_split_huge_fixup(struct page *head);
#endif

#ifdef CONFIG_DEBUG_VM
bool mem_cgroup_bad_page_check(struct page *page);
void mem_cgroup_print_bad_page(struct page *page);
#endif
#else /* CONFIG_MEMCG */

#define MEM_CGROUP_ID_SHIFT	0
#define MEM_CGROUP_ID_MAX	0

struct mem_cgroup;

static inline bool mem_cgroup_disabled(void)
{
	return true;
}

static inline unsigned short mem_cgroup_id(struct mem_cgroup *memcg)
{
	return 0;
}

static inline struct mem_cgroup *mem_cgroup_from_id(unsigned short id)
{
	WARN_ON_ONCE(id);
	/* XXX: This should always return root_mem_cgroup */
	return NULL;
}

static inline int mem_cgroup_try_charge(struct page *page, struct mm_struct *mm,
					gfp_t gfp_mask,
					struct mem_cgroup **memcgp)
{
	*memcgp = NULL;
	return 0;
}

static inline int mem_cgroup_try_charge_cache(struct page *page, struct mm_struct *mm,
					gfp_t gfp_mask,
					struct mem_cgroup **memcgp)
{
	*memcgp = NULL;
	return 0;
}

static inline void mem_cgroup_commit_charge(struct page *page,
					    struct mem_cgroup *memcg,
					    bool lrucare)
{
}

static inline void mem_cgroup_cancel_charge(struct page *page,
					    struct mem_cgroup *memcg)
{
}

static inline void mem_cgroup_cancel_cache_charge(struct page *page,
					    struct mem_cgroup *memcg)
{
}

static inline void mem_cgroup_uncharge(struct page *page)
{
}

static inline void mem_cgroup_uncharge_list(struct list_head *page_list)
{
}

static inline void mem_cgroup_migrate(struct page *oldpage,
				      struct page *newpage,
				      bool lrucare)
{
}

static inline struct lruvec *mem_cgroup_zone_lruvec(struct zone *zone,
						    struct mem_cgroup *memcg)
{
	return &zone->lruvec;
}

static inline struct lruvec *mem_cgroup_page_lruvec(struct page *page,
						    struct zone *zone)
{
	return &zone->lruvec;
}

static inline struct mem_cgroup *try_get_mem_cgroup_from_page(struct page *page)
{
	return NULL;
}

static inline bool mm_match_cgroup(struct mm_struct *mm,
		struct mem_cgroup *memcg)
{
	return true;
}

static inline struct mem_cgroup *get_mem_cgroup_from_mm(struct mm_struct *mm)
{
       return NULL;
}

static inline int task_in_mem_cgroup(struct task_struct *task,
				     const struct mem_cgroup *memcg)
{
	return 1;
}

static inline struct cgroup_subsys_state
		*mem_cgroup_css(struct mem_cgroup *memcg)
{
	return NULL;
}

static inline struct mem_cgroup *
mem_cgroup_iter(struct mem_cgroup *root,
		struct mem_cgroup *prev,
		struct mem_cgroup_reclaim_cookie *reclaim)
{
	return NULL;
}

static inline void mem_cgroup_iter_break(struct mem_cgroup *root,
					 struct mem_cgroup *prev)
{
}

static inline struct mem_cgroup *mem_cgroup_from_id(unsigned short id)
{
	WARN_ON_ONCE(id);
	/* XXX: This should always return root_mem_cgroup */
	return NULL;
}

static inline void mem_cgroup_get(struct mem_cgroup *memcg)
{
}

static inline void mem_cgroup_put(struct mem_cgroup *memcg)
{
}

static inline bool mem_cgroup_dcache_is_low(struct mem_cgroup *memcg,
	int vfs_cache_min_ratio)
{
	return false;
}

static inline bool mem_cgroup_low(struct mem_cgroup *root,
				  struct mem_cgroup *memcg)
{
	return false;
}

static inline bool mem_cgroup_cleancache_disabled(struct page *page)
{
	return false;
}

static inline unsigned long
mem_cgroup_get_lru_size(struct lruvec *lruvec, enum lru_list lru)
{
	return 0;
}

static inline void
mem_cgroup_update_lru_size(struct lruvec *lruvec, enum lru_list lru,
			      int increment)
{
}

static inline struct oom_context *
mem_cgroup_oom_context(struct mem_cgroup *memcg)
{
	return &global_oom_ctx;
}

static inline unsigned long mem_cgroup_overdraft(struct mem_cgroup *memcg)
{
	return 0;
}

static inline unsigned long
mem_cgroup_node_nr_lru_pages(struct mem_cgroup *memcg,
			     int nid, unsigned int lru_mask)
{
	return 0;
}

static inline void
mem_cgroup_note_oom_kill(struct mem_cgroup *memcg, struct task_struct *task)
{
}

static inline void
mem_cgroup_print_oom_info(struct mem_cgroup *memcg, struct task_struct *p)
{
}

static inline void mem_cgroup_begin_update_page_stat(struct page *page,
					bool *locked, unsigned long *flags)
{
}

static inline void mem_cgroup_end_update_page_stat(struct page *page,
					bool *locked, unsigned long *flags)
{
}

static inline void mem_cgroup_oom_enable(void)
{
}

static inline void mem_cgroup_oom_disable(void)
{
}

static inline bool task_in_memcg_oom(struct task_struct *p)
{
	return false;
}

static inline bool mem_cgroup_oom_synchronize(bool wait)
{
	return false;
}

static inline void mem_cgroup_inc_page_stat(struct page *page,
					    enum mem_cgroup_page_stat_item idx)
{
}

static inline void mem_cgroup_dec_page_stat(struct page *page,
					    enum mem_cgroup_page_stat_item idx)
{
}

static inline void mem_cgroup_fill_vmstat(struct mem_cgroup *memcg,
					unsigned long *stats)
{
}

static inline unsigned long memcg_ws_activates(struct mem_cgroup *memcg)
{
	return 0;
}

static inline void memcg_inc_ws_activate(struct mem_cgroup *memcg) { }

static inline
unsigned long mem_cgroup_soft_limit_reclaim(struct zone *zone, int order,
					    gfp_t gfp_mask,
					    unsigned long *total_scanned)
{
	return 0;
}

static inline void mem_cgroup_split_huge_fixup(struct page *head)
{
}

static inline
void mem_cgroup_count_vm_event(struct mm_struct *mm, enum vm_event_item idx)
{
}
#endif /* CONFIG_MEMCG */

#if !defined(CONFIG_MEMCG) || !defined(CONFIG_DEBUG_VM)
static inline bool
mem_cgroup_bad_page_check(struct page *page)
{
	return false;
}

static inline void
mem_cgroup_print_bad_page(struct page *page)
{
}
#endif

enum {
	UNDER_LIMIT,
	SOFT_LIMIT,
	OVER_LIMIT,
};

struct sock;
#if defined(CONFIG_INET) && defined(CONFIG_MEMCG_KMEM)
void sock_update_memcg(struct sock *sk);
void sock_release_memcg(struct sock *sk);
#else
static inline void sock_update_memcg(struct sock *sk)
{
}
static inline void sock_release_memcg(struct sock *sk)
{
}
#endif /* CONFIG_INET && CONFIG_MEMCG_KMEM */

extern struct mem_cgroup *root_mem_cgroup;

#ifdef CONFIG_MEMCG_KMEM
extern struct static_key memcg_kmem_enabled_key;

extern int memcg_nr_cache_ids;
extern void memcg_get_cache_ids(void);
extern void memcg_put_cache_ids(void);

static inline bool mem_cgroup_is_root(struct mem_cgroup *memcg)
{
	return (memcg == root_mem_cgroup);
}

static inline void memcg_stop_kmem_account(void)
{
	current->memcg_kmem_skip_account++;
}

static inline void memcg_resume_kmem_account(void)
{
	current->memcg_kmem_skip_account--;
}

/*
 * Helper macro to loop through all memcg-specific caches. Callers must still
 * check if the cache is valid (it is either valid or NULL).
 * the slab_mutex must be held when looping through those caches
 */
#define for_each_memcg_cache_index(_idx)	\
	for ((_idx) = 0; (_idx) < memcg_nr_cache_ids; (_idx)++)

static inline bool memcg_kmem_enabled(void)
{
	return static_key_false(&memcg_kmem_enabled_key);
}

bool memcg_kmem_is_active(struct mem_cgroup *memcg);

/*
 * In general, we'll do everything in our power to not incur in any overhead
 * for non-memcg users for the kmem functions. Not even a function call, if we
 * can avoid it.
 *
 * Therefore, we'll inline all those functions so that in the best case, we'll
 * see that kmemcg is off for everybody and proceed quickly.  If it is on,
 * we'll still do most of the flag checking inline. We check a lot of
 * conditions, but because they are pretty simple, they are expected to be
 * fast.
 */
bool __memcg_kmem_newpage_charge(struct page *page, gfp_t gfp, int order);
void __memcg_kmem_uncharge_pages(struct page *page, int order);

int memcg_cache_id(struct mem_cgroup *memcg);

struct kmem_cache *
__memcg_kmem_get_cache(struct kmem_cache *cachep, gfp_t gfp);
void __memcg_kmem_put_cache(struct kmem_cache *cachep);

struct mem_cgroup *__mem_cgroup_from_kmem(void *ptr);

int memcg_charge_kmem(struct mem_cgroup *memcg, gfp_t gfp, unsigned long nr_pages);
void memcg_charge_kmem_nofail(struct mem_cgroup *memcg, unsigned long nr_pages);
void memcg_uncharge_kmem(struct mem_cgroup *memcg, unsigned long nr_pages);

void mem_cgroup_destroy_cache(struct kmem_cache *cachep);

/**
 * memcg_kmem_newpage_charge: verify if a new kmem allocation is allowed.
 * @page: page to charge.
 * @gfp: the gfp allocation flags.
 * @order: allocation order.
 *
 * returns true if the memcg where the current task belongs can hold this
 * allocation.
 *
 * We return true automatically if this allocation is not to be accounted to
 * any memcg.
 */
static inline bool
memcg_kmem_newpage_charge(struct page *page, gfp_t gfp, int order)
{
	if (!memcg_kmem_enabled())
		return true;
	if (!(gfp & __GFP_ACCOUNT))
		return true;

	/*
	 * __GFP_NOFAIL allocations will move on even if charging is not
	 * possible. Therefore we don't even try, and have this allocation
	 * unaccounted. We could in theory charge it forcibly, but we hope
	 * those allocations are rare, and won't be worth the trouble.
	 */
	if (gfp & __GFP_NOFAIL)
		return true;
	if (in_interrupt() || (!current->mm) || (current->flags & PF_KTHREAD))
		return true;

	/* If the test is dying, just let it go. */
	if (unlikely(fatal_signal_pending(current)))
		return true;

	return __memcg_kmem_newpage_charge(page, gfp, order);
}

/**
 * memcg_kmem_uncharge_pages: uncharge pages from memcg
 * @page: pointer to struct page being freed
 * @order: allocation order.
 *
 * there is no need to specify memcg here, since it is embedded in page_cgroup
 */
static inline void
memcg_kmem_uncharge_pages(struct page *page, int order)
{
	if (memcg_kmem_enabled() && PageKmemcg(page))
		__memcg_kmem_uncharge_pages(page, order);
}

/**
 * memcg_kmem_get_cache: selects the correct per-memcg cache for allocation
 * @cachep: the original global kmem cache
 * @gfp: allocation flags.
 *
 * All memory allocated from a per-memcg cache is charged to the owner memcg.
 */
static __always_inline struct kmem_cache *
memcg_kmem_get_cache(struct kmem_cache *cachep, gfp_t gfp)
{
	if (!memcg_kmem_enabled())
		return cachep;
	if (gfp & __GFP_NOFAIL)
		return cachep;
	if (in_interrupt() || (!current->mm) || (current->flags & PF_KTHREAD))
		return cachep;
	if (unlikely(fatal_signal_pending(current)))
		return cachep;

	return __memcg_kmem_get_cache(cachep, gfp);
}

static __always_inline void memcg_kmem_put_cache(struct kmem_cache *cachep)
{
	if (memcg_kmem_enabled())
		__memcg_kmem_put_cache(cachep);
}

static __always_inline struct mem_cgroup *mem_cgroup_from_kmem(void *ptr)
{
	if (!memcg_kmem_enabled())
		return NULL;
	return __mem_cgroup_from_kmem(ptr);
}
extern int memcg_expand_shrinker_maps(int new_id);
extern void memcg_set_shrinker_bit(struct mem_cgroup *memcg,
				   int nid, int shrinker_id);

extern struct memcg_shrinker_map *memcg_nid_shrinker_map(struct mem_cgroup *memcg, int nid);
#else
#define for_each_memcg_cache_index(_idx)	\
	for (; NULL; )

static inline bool mem_cgroup_is_root(struct mem_cgroup *memcg)
{
	return true;
}

static inline bool memcg_kmem_enabled(void)
{
	return false;
}

static inline bool memcg_kmem_is_active(struct mem_cgroup *memcg)
{
	return false;
}

static inline bool
memcg_kmem_newpage_charge(struct page *page, gfp_t gfp, int order)
{
	return true;
}

static inline void memcg_kmem_uncharge_pages(struct page *page, int order)
{
}

static inline int memcg_cache_id(struct mem_cgroup *memcg)
{
	return -1;
}

static inline void memcg_get_cache_ids(void)
{
}

static inline void memcg_put_cache_ids(void)
{
}

static inline void memcg_stop_kmem_account(void)
{
}

static inline void memcg_resume_kmem_account(void)
{
}

static inline struct kmem_cache *
memcg_kmem_get_cache(struct kmem_cache *cachep, gfp_t gfp)
{
	return cachep;
}

static inline void memcg_kmem_put_cache(struct kmem_cache *cachep)
{
}

static inline struct mem_cgroup *mem_cgroup_from_kmem(void *ptr)
{
	return NULL;
}
static inline void memcg_set_shrinker_bit(struct mem_cgroup *memcg,
					  int nid, int shrinker_id) { }
#endif /* CONFIG_MEMCG_KMEM */
#endif /* _LINUX_MEMCONTROL_H */

