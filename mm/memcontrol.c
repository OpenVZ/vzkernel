/* memcontrol.c - Memory Controller
 *
 * Copyright IBM Corporation, 2007
 * Author Balbir Singh <balbir@linux.vnet.ibm.com>
 *
 * Copyright 2007 OpenVZ SWsoft Inc
 * Author: Pavel Emelianov <xemul@openvz.org>
 *
 * Memory thresholds
 * Copyright (C) 2009 Nokia Corporation
 * Author: Kirill A. Shutemov
 *
 * Kernel Memory Controller
 * Copyright (C) 2012 Parallels Inc. and Google Inc.
 * Authors: Glauber Costa and Suleiman Souhlal
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

#include <linux/page_counter.h>
#include <linux/memcontrol.h>
#include <linux/cgroup.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/smp.h>
#include <linux/page-flags.h>
#include <linux/backing-dev.h>
#include <linux/bit_spinlock.h>
#include <linux/rcupdate.h>
#include <linux/limits.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/spinlock.h>
#include <linux/eventfd.h>
#include <linux/sort.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/vmpressure.h>
#include <linux/mm_inline.h>
#include <linux/page_cgroup.h>
#include <linux/cpu.h>
#include <linux/oom.h>
#include <linux/virtinfo.h>
#include <linux/migrate.h>
#include "internal.h"
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp_memcontrol.h>
#include "slab.h"

#include <asm/uaccess.h>

#include <trace/events/vmscan.h>

struct cgroup_subsys mem_cgroup_subsys __read_mostly;
EXPORT_SYMBOL(mem_cgroup_subsys);

#define MEM_CGROUP_RECLAIM_RETRIES	5
static struct mem_cgroup *root_mem_cgroup __read_mostly;

/* Kernel memory accounting disabled? */
static bool cgroup_memory_nokmem;

#ifdef CONFIG_MEMCG_SWAP
/* Turned on only when memory cgroup is enabled && really_do_swap_account = 1 */
int do_swap_account __read_mostly;

/* for remember boot option*/
#ifdef CONFIG_MEMCG_SWAP_ENABLED
static int really_do_swap_account __initdata = 1;
#else
static int really_do_swap_account __initdata = 0;
#endif

#else
#define do_swap_account		0
#endif


/*
 * Statistics for memory cgroup.
 */
enum mem_cgroup_stat_index {
	/*
	 * For MEM_CONTAINER_TYPE_ALL, usage = pagecache + rss.
	 */
	MEM_CGROUP_STAT_CACHE,		/* # of pages charged as cache */
	MEM_CGROUP_STAT_RSS,		/* # of pages charged as anon rss */
	MEM_CGROUP_STAT_RSS_HUGE,	/* # of pages charged as anon huge */
	MEM_CGROUP_STAT_FILE_MAPPED,	/* # of pages charged as file rss */
	MEM_CGROUP_STAT_SHMEM,		/* # of charged shmem pages */
	MEM_CGROUP_STAT_SWAP,		/* # of pages, swapped out */
	MEM_CGROUP_STAT_NSTATS,
};

static const char * const mem_cgroup_stat_names[] = {
	"cache",
	"rss",
	"rss_huge",
	"mapped_file",
	"shmem",
	"swap",
};

enum mem_cgroup_events_index {
	MEM_CGROUP_EVENTS_PGPGIN,	/* # of pages paged in */
	MEM_CGROUP_EVENTS_PGPGOUT,	/* # of pages paged out */
	MEM_CGROUP_EVENTS_PSWPIN,	/* # of pages swapped in */
	MEM_CGROUP_EVENTS_PSWPOUT,	/* # of pages swapped out */
	MEM_CGROUP_EVENTS_PGFAULT,	/* # of page-faults */
	MEM_CGROUP_EVENTS_PGMAJFAULT,	/* # of major page-faults */
	MEM_CGROUP_EVENTS_NSTATS,
};

static const char * const mem_cgroup_events_names[] = {
	"pgpgin",
	"pgpgout",
	"pswpin",
	"pswpout",
	"pgfault",
	"pgmajfault",
};

static const char * const mem_cgroup_lru_names[] = {
	"inactive_anon",
	"active_anon",
	"inactive_file",
	"active_file",
	"unevictable",
};

/*
 * Per memcg event counter is incremented at every pagein/pageout. With THP,
 * it will be incremated by the number of pages. This counter is used for
 * for trigger some periodic events. This is straightforward and better
 * than using jiffies etc. to handle periodic memcg event.
 */
enum mem_cgroup_events_target {
	MEM_CGROUP_TARGET_THRESH,
	MEM_CGROUP_TARGET_SOFTLIMIT,
	MEM_CGROUP_TARGET_NUMAINFO,
	MEM_CGROUP_NTARGETS,
};
#define THRESHOLDS_EVENTS_TARGET 128
#define SOFTLIMIT_EVENTS_TARGET 1024
#define NUMAINFO_EVENTS_TARGET	1024

#define MEM_CGROUP_ID_MAX	USHRT_MAX

static void mem_cgroup_id_put(struct mem_cgroup *memcg);
static unsigned short mem_cgroup_id(struct mem_cgroup *memcg);

struct mem_cgroup_stat_cpu {
	long count[MEM_CGROUP_STAT_NSTATS];
	unsigned long events[MEM_CGROUP_EVENTS_NSTATS];
	unsigned long nr_page_events;
	unsigned long targets[MEM_CGROUP_NTARGETS];
};

struct mem_cgroup_reclaim_iter {
	/*
	 * last scanned hierarchy member. Valid only if last_dead_count
	 * matches memcg->dead_count of the hierarchy root group.
	 */
	struct mem_cgroup *last_visited;
	unsigned long last_dead_count;

	/* scan generation, increased every round-trip */
	unsigned int generation;
};

/*
 * per-zone information in memory controller.
 */
struct mem_cgroup_per_zone {
	struct lruvec		lruvec;
	unsigned long		lru_size[NR_LRU_LISTS];

	struct mem_cgroup_reclaim_iter reclaim_iter[DEF_PRIORITY + 1];

	struct rb_node		tree_node;	/* RB tree node */
	unsigned long		usage_in_excess;/* Set to the value by which */
						/* the soft limit is exceeded*/
	bool			on_tree;
	struct mem_cgroup	*memcg;		/* Back pointer, we cannot */
						/* use container_of	   */
};

struct mem_cgroup_per_node {
	struct mem_cgroup_per_zone zoneinfo[MAX_NR_ZONES];
};

struct mem_cgroup_lru_info {
	struct mem_cgroup_per_node *nodeinfo[0];
};

/*
 * Cgroups above their limits are maintained in a RB-Tree, independent of
 * their hierarchy representation
 */

struct mem_cgroup_tree_per_zone {
	struct rb_root rb_root;
	spinlock_t lock;
};

struct mem_cgroup_tree_per_node {
	struct mem_cgroup_tree_per_zone rb_tree_per_zone[MAX_NR_ZONES];
};

struct mem_cgroup_tree {
	struct mem_cgroup_tree_per_node *rb_tree_per_node[MAX_NUMNODES];
};

static struct mem_cgroup_tree soft_limit_tree __read_mostly;

struct mem_cgroup_threshold {
	struct eventfd_ctx *eventfd;
	unsigned long threshold;
};

/* For threshold */
struct mem_cgroup_threshold_ary {
	/* An array index points to threshold just below or equal to usage. */
	int current_threshold;
	/* Size of entries[] */
	unsigned int size;
	/* Array of thresholds */
	struct mem_cgroup_threshold entries[0];
};

struct mem_cgroup_thresholds {
	/* Primary thresholds array */
	struct mem_cgroup_threshold_ary *primary;
	/*
	 * Spare threshold array.
	 * This is needed to make mem_cgroup_unregister_event() "never fail".
	 * It must be able to store at least primary->size - 1 entries.
	 */
	struct mem_cgroup_threshold_ary *spare;
};

/* for OOM */
struct mem_cgroup_eventfd_list {
	struct list_head list;
	struct eventfd_ctx *eventfd;
};

static void mem_cgroup_threshold(struct mem_cgroup *memcg);
static void mem_cgroup_oom_notify(struct mem_cgroup *memcg);

/*
 * The memory controller data structure. The memory controller controls both
 * page cache and RSS per cgroup. We would eventually like to provide
 * statistics based on the statistics developed by Rik Van Riel for clock-pro,
 * to help the administrator determine what knobs to tune.
 *
 * TODO: Add a water mark for the memory controller. Reclaim will begin when
 * we hit the water mark. May be even add a low water mark, such that
 * no reclaim occurs from a cgroup at it's low water mark, this is
 * a feature that will be implemented much later in the future.
 */
struct mem_cgroup {
	struct cgroup_subsys_state css;

	/* Private memcg ID. Used to ID objects that outlive the cgroup */
	unsigned short id;

	/*
	 * the counter to account for memory usage
	 */
	struct page_counter memory;

	unsigned long soft_limit;

	/* Normal memory consumption range */
	unsigned long long low;
	unsigned long long high;

	/* vmpressure notifications */
	struct vmpressure vmpressure;

	/*
	 * the counter to account for kernel memory usage.
	 */
	struct page_counter kmem;

	/* beancounter-related stats */
	unsigned long long swap_max;
	atomic_long_t mem_failcnt;
	atomic_long_t swap_failcnt;
	atomic_long_t oom_kill_cnt;

	unsigned long long oom_guarantee;

	/*
	 * Should the accounting and control be hierarchical, per subtree?
	 */
	bool use_hierarchy;
	bool is_offline;
	unsigned long kmem_account_flags; /* See KMEM_ACCOUNTED_*, below */

	bool		oom_lock;
	atomic_t	under_oom;
	atomic_t	oom_wakeups;

	int	swappiness;
	/* OOM-Killer disable */
	int		oom_kill_disable;

	/* set when res.limit == memsw.limit */
	bool		memsw_is_minimum;

#ifdef CONFIG_CLEANCACHE
	/*
	 * cleancache_disabled_toggle: toggled by writing to
	 * memory.disable_cleancache
	 *
	 * cleancache_disabled: set iff cleancache_disabled_toggle is
	 * set in this cgroup or any of its ascendants; controls whether
	 * cleancache callback is called when a page is evicted from
	 * this cgroup
	 */
	bool cleancache_disabled_toggle;
	bool cleancache_disabled;
#endif

	/* protect arrays of thresholds */
	struct mutex thresholds_lock;

	/* thresholds for memory usage. RCU-protected */
	struct mem_cgroup_thresholds thresholds;

	/* thresholds for mem+swap usage. RCU-protected */
	struct mem_cgroup_thresholds memsw_thresholds;

	/* For oom notifier event fd */
	struct list_head oom_notify;

	/*
	 * Should we move charges of a task when a task is moved into this
	 * mem_cgroup ? And what type of charges should we move ?
	 */
	unsigned long 	move_charge_at_immigrate;
	/*
	 * set > 0 if pages under this cgroup are moving to other cgroup.
	 */
	atomic_t	moving_account;
	/* taken only while moving_account > 0 */
	spinlock_t	move_lock;
	/*
	 * percpu counter.
	 */
	struct mem_cgroup_stat_cpu __percpu *stat;
	spinlock_t pcp_counter_lock;

	atomic_t	dead_count;
#if defined(CONFIG_MEMCG_KMEM) && defined(CONFIG_INET)
	struct tcp_memcontrol tcp_mem;
#endif
#if defined(CONFIG_MEMCG_KMEM)
        /* Index in the kmem_cache->memcg_params.memcg_caches array */
	int kmemcg_id;
	/* List of memcgs sharing the same kmemcg_id */
	struct list_head kmemcg_sharers;
#endif

	int last_scanned_node;
#if MAX_NUMNODES > 1
	nodemask_t	scan_nodes;
	atomic_t	numainfo_events;
	atomic_t	numainfo_updating;
#endif

	/*
	 * Per cgroup active and inactive list, similar to the
	 * per zone LRU lists.
	 *
	 * WARNING: This has to be the last element of the struct. Don't
	 * add new fields after this point.
	 */
	struct mem_cgroup_lru_info info;
};

/* internal only representation about the status of kmem accounting. */
enum {
	KMEM_ACCOUNTED_ACTIVE, /* accounted by this cgroup itself */
	KMEM_ACCOUNTED_ACTIVATED, /* static key enabled */
	KMEM_ACCOUNTED_DEAD, /* dead memcg with pending kmem charges */
};

#ifdef CONFIG_MEMCG_KMEM
bool memcg_kmem_is_active(struct mem_cgroup *memcg)
{
	return test_bit(KMEM_ACCOUNTED_ACTIVE, &memcg->kmem_account_flags);
}

static void memcg_kmem_mark_dead(struct mem_cgroup *memcg)
{
	/*
	 * Our caller must use css_get() first, because memcg_uncharge_kmem()
	 * will call css_put() if it sees the memcg is dead.
	 */
	smp_wmb();
	set_bit(KMEM_ACCOUNTED_DEAD, &memcg->kmem_account_flags);
}

static bool memcg_kmem_test_and_clear_dead(struct mem_cgroup *memcg)
{
	return test_and_clear_bit(KMEM_ACCOUNTED_DEAD,
				  &memcg->kmem_account_flags);
}
#endif

/* Stuffs for move charges at task migration. */
/*
 * Types of charges to be moved. "move_charge_at_immitgrate" and
 * "immigrate_flags" are treated as a left-shifted bitmap of these types.
 */
enum move_type {
	MOVE_CHARGE_TYPE_ANON,	/* private anonymous page and swap of it */
	MOVE_CHARGE_TYPE_FILE,	/* file page(including tmpfs) and swap of it */
	NR_MOVE_TYPE,
};

/* "mc" and its members are protected by cgroup_mutex */
static struct move_charge_struct {
	spinlock_t	  lock; /* for from, to */
	struct mem_cgroup *from;
	struct mem_cgroup *to;
	unsigned long immigrate_flags;
	unsigned long precharge;
	unsigned long moved_charge;
	unsigned long moved_swap;
	struct task_struct *moving_task;	/* a task moving charges */
	wait_queue_head_t waitq;		/* a waitq for other context */
} mc = {
	.lock = __SPIN_LOCK_UNLOCKED(mc.lock),
	.waitq = __WAIT_QUEUE_HEAD_INITIALIZER(mc.waitq),
};

static bool move_anon(void)
{
	return test_bit(MOVE_CHARGE_TYPE_ANON, &mc.immigrate_flags);
}

static bool move_file(void)
{
	return test_bit(MOVE_CHARGE_TYPE_FILE, &mc.immigrate_flags);
}

/*
 * Maximum loops in mem_cgroup_hierarchical_reclaim(), used for soft
 * limit reclaim to prevent infinite loops, if they ever occur.
 */
#define	MEM_CGROUP_MAX_RECLAIM_LOOPS		100
#define	MEM_CGROUP_MAX_SOFT_LIMIT_RECLAIM_LOOPS	2

enum charge_type {
	MEM_CGROUP_CHARGE_TYPE_CACHE = 0,
	MEM_CGROUP_CHARGE_TYPE_ANON,
	MEM_CGROUP_CHARGE_TYPE_SWAPOUT,	/* for accounting swapcache */
	MEM_CGROUP_CHARGE_TYPE_DROP,	/* a page was unused swap cache */
	NR_CHARGE_TYPE,
};

/* for encoding cft->private value on file */
enum res_type {
	_MEM,
	_MEMSWAP,
	_OOM_TYPE,
	_KMEM,
};

#define MEMFILE_PRIVATE(x, val)	((x) << 16 | (val))
#define MEMFILE_TYPE(val)	((val) >> 16 & 0xffff)
#define MEMFILE_ATTR(val)	((val) & 0xffff)
/* Used for OOM nofiier */
#define OOM_CONTROL		(0)

/*
 * Reclaim flags for mem_cgroup_hierarchical_reclaim
 */
#define MEM_CGROUP_RECLAIM_NOSWAP_BIT	0x0
#define MEM_CGROUP_RECLAIM_NOSWAP	(1 << MEM_CGROUP_RECLAIM_NOSWAP_BIT)
#define MEM_CGROUP_RECLAIM_SHRINK_BIT	0x1
#define MEM_CGROUP_RECLAIM_SHRINK	(1 << MEM_CGROUP_RECLAIM_SHRINK_BIT)

/*
 * The memcg_create_mutex will be held whenever a new cgroup is created.
 * As a consequence, any change that needs to protect against new child cgroups
 * appearing has to hold it as well.
 */
static DEFINE_MUTEX(memcg_create_mutex);

static inline
struct mem_cgroup *mem_cgroup_from_css(struct cgroup_subsys_state *s)
{
	return container_of(s, struct mem_cgroup, css);
}

/* Some nice accessors for the vmpressure. */
struct vmpressure *memcg_to_vmpressure(struct mem_cgroup *memcg)
{
	if (!memcg)
		memcg = root_mem_cgroup;
	return &memcg->vmpressure;
}

struct cgroup_subsys_state *vmpressure_to_css(struct vmpressure *vmpr)
{
	return &container_of(vmpr, struct mem_cgroup, vmpressure)->css;
}

struct vmpressure *css_to_vmpressure(struct cgroup_subsys_state *css)
{
	return &mem_cgroup_from_css(css)->vmpressure;
}

static inline bool mem_cgroup_is_root(struct mem_cgroup *memcg)
{
	return (memcg == root_mem_cgroup);
}

/* Writing them here to avoid exposing memcg's inner layout */
#if defined(CONFIG_INET) && defined(CONFIG_MEMCG_KMEM)

void sock_update_memcg(struct sock *sk)
{
	if (mem_cgroup_sockets_enabled) {
		struct mem_cgroup *memcg;
		struct cg_proto *cg_proto;

		BUG_ON(!sk->sk_prot->proto_cgroup);

		/* Socket cloning can throw us here with sk_cgrp already
		 * filled. It won't however, necessarily happen from
		 * process context. So the test for root memcg given
		 * the current task's memcg won't help us in this case.
		 *
		 * Respecting the original socket's memcg is a better
		 * decision in this case.
		 */
		if (sk->sk_cgrp) {
			BUG_ON(mem_cgroup_is_root(sk->sk_cgrp->memcg));
			css_get(&sk->sk_cgrp->memcg->css);
			return;
		}

		rcu_read_lock();
		memcg = mem_cgroup_from_task(current);
		cg_proto = sk->sk_prot->proto_cgroup(memcg);
		if (!mem_cgroup_is_root(memcg) &&
		    memcg_proto_active(cg_proto) && css_tryget(&memcg->css)) {
			sk->sk_cgrp = cg_proto;
		}
		rcu_read_unlock();
	}
}
EXPORT_SYMBOL(sock_update_memcg);

void sock_release_memcg(struct sock *sk)
{
	if (mem_cgroup_sockets_enabled && sk->sk_cgrp) {
		struct mem_cgroup *memcg;
		WARN_ON(!sk->sk_cgrp->memcg);
		memcg = sk->sk_cgrp->memcg;
		css_put(&sk->sk_cgrp->memcg->css);
	}
}

struct cg_proto *tcp_proto_cgroup(struct mem_cgroup *memcg)
{
	if (!memcg || mem_cgroup_is_root(memcg))
		return NULL;

	return &memcg->tcp_mem.cg_proto;
}
EXPORT_SYMBOL(tcp_proto_cgroup);

static void disarm_sock_keys(struct mem_cgroup *memcg)
{
	if (!memcg_proto_activated(&memcg->tcp_mem.cg_proto))
		return;
	static_key_slow_dec(&memcg_socket_limit_enabled);
}
#else
static void disarm_sock_keys(struct mem_cgroup *memcg)
{
}
#endif

#ifdef CONFIG_MEMCG_KMEM
/*
 * This will be the memcg's index in each cache's ->memcg_params.memcg_caches.
 * There are two main reasons for not using the css_id for this:
 *  1) this works better in sparse environments, where we have a lot of memcgs,
 *     but only a few kmem-limited. Or also, if we have, for instance, 200
 *     memcgs, and none but the 200th is kmem-limited, we'd have to have a
 *     200 entry array for that.
 *
 *  2) In order not to violate the cgroup API, we would like to do all memory
 *     allocation in ->create(). At that point, we haven't yet allocated the
 *     css_id. Having a separate index prevents us from messing with the cgroup
 *     core for this
 *
 * The current size of the caches array is stored in memcg_nr_cache_ids. It
 * will double each time we have to increase it.
 */
static DEFINE_IDA(memcg_cache_ida);
int memcg_nr_cache_ids;

/* Protects memcg_nr_cache_ids */
static DECLARE_RWSEM(memcg_cache_ids_sem);

void memcg_get_cache_ids(void)
{
	down_read(&memcg_cache_ids_sem);
}

void memcg_put_cache_ids(void)
{
	up_read(&memcg_cache_ids_sem);
}

/*
 * MIN_SIZE is different than 1, because we would like to avoid going through
 * the alloc/free process all the time. In a small machine, 4 kmem-limited
 * cgroups is a reasonable guess. In the future, it could be a parameter or
 * tunable, but that is strictly not necessary.
 *
 * MAX_SIZE should be as large as the number of css_ids. Ideally, we could get
 * this constant directly from cgroup, but it is understandable that this is
 * better kept as an internal representation in cgroup.c. In any case, the
 * css_id space is not getting any smaller, and we don't have to necessarily
 * increase ours as well if it increases.
 */
#define MEMCG_CACHES_MIN_SIZE 4
#define MEMCG_CACHES_MAX_SIZE 65535

/*
 * A lot of the calls to the cache allocation functions are expected to be
 * inlined by the compiler. Since the calls to memcg_kmem_get_cache are
 * conditional to this static branch, we'll have to allow modules that does
 * kmem_cache_alloc and the such to see this symbol as well
 */
struct static_key memcg_kmem_enabled_key;
EXPORT_SYMBOL(memcg_kmem_enabled_key);

static void disarm_kmem_keys(struct mem_cgroup *memcg)
{
	if (test_bit(KMEM_ACCOUNTED_ACTIVATED, &memcg->kmem_account_flags))
		static_key_slow_dec(&memcg_kmem_enabled_key);
	/*
	 * This check can't live in kmem destruction function,
	 * since the charges will outlive the cgroup
	 */
	WARN_ON(page_counter_read(&memcg->kmem));
}
#else
static void disarm_kmem_keys(struct mem_cgroup *memcg)
{
}
#endif /* CONFIG_MEMCG_KMEM */

static void disarm_static_keys(struct mem_cgroup *memcg)
{
	disarm_sock_keys(memcg);
	disarm_kmem_keys(memcg);
}

static void drain_all_stock_async(struct mem_cgroup *memcg);

static struct mem_cgroup_per_zone *
mem_cgroup_zoneinfo(struct mem_cgroup *memcg, int nid, int zid)
{
	VM_BUG_ON((unsigned)nid >= nr_node_ids);
	return &memcg->info.nodeinfo[nid]->zoneinfo[zid];
}

struct cgroup_subsys_state *mem_cgroup_css(struct mem_cgroup *memcg)
{
	return &memcg->css;
}

/**
 * page_cgroup_ino - return inode number of the memcg a page is charged to
 * @page: the page
 *
 * Look up the memory cgroup @page is charged to and return its inode number or
 * 0 if @page is not charged to any cgroup. It is safe to call this function
 * without holding a reference to @page.
 *
 * Note, this function is inherently racy, because there is nothing to prevent
 * the cgroup inode from getting torn down and potentially reallocated a moment
 * after page_cgroup_ino() returns, so it only should be used by callers that
 * do not care (such as procfs interfaces).
 */
ino_t page_cgroup_ino(struct page *page)
{
	struct page_cgroup *pc;
	unsigned long ino = 0;

	pc = lookup_page_cgroup(page);
	if (!PageCgroupUsed(pc))
		return 0;
	lock_page_cgroup(pc);
	if (likely(PageCgroupUsed(pc)))
		ino = pc->mem_cgroup->css.cgroup->dentry->d_inode->i_ino;
	unlock_page_cgroup(pc);
	return ino;
}

static struct mem_cgroup_per_zone *
page_cgroup_zoneinfo(struct mem_cgroup *memcg, struct page *page)
{
	int nid = page_to_nid(page);
	int zid = page_zonenum(page);

	return mem_cgroup_zoneinfo(memcg, nid, zid);
}

static struct mem_cgroup_tree_per_zone *
soft_limit_tree_node_zone(int nid, int zid)
{
	return &soft_limit_tree.rb_tree_per_node[nid]->rb_tree_per_zone[zid];
}

static struct mem_cgroup_tree_per_zone *
soft_limit_tree_from_page(struct page *page)
{
	int nid = page_to_nid(page);
	int zid = page_zonenum(page);

	return &soft_limit_tree.rb_tree_per_node[nid]->rb_tree_per_zone[zid];
}

static void
__mem_cgroup_insert_exceeded(struct mem_cgroup *memcg,
				struct mem_cgroup_per_zone *mz,
				struct mem_cgroup_tree_per_zone *mctz,
				unsigned long new_usage_in_excess)
{
	struct rb_node **p = &mctz->rb_root.rb_node;
	struct rb_node *parent = NULL;
	struct mem_cgroup_per_zone *mz_node;

	if (mz->on_tree)
		return;

	mz->usage_in_excess = new_usage_in_excess;
	if (!mz->usage_in_excess)
		return;
	while (*p) {
		parent = *p;
		mz_node = rb_entry(parent, struct mem_cgroup_per_zone,
					tree_node);
		if (mz->usage_in_excess < mz_node->usage_in_excess)
			p = &(*p)->rb_left;
		/*
		 * We can't avoid mem cgroups that are over their soft
		 * limit by the same amount
		 */
		else if (mz->usage_in_excess >= mz_node->usage_in_excess)
			p = &(*p)->rb_right;
	}
	rb_link_node(&mz->tree_node, parent, p);
	rb_insert_color(&mz->tree_node, &mctz->rb_root);
	mz->on_tree = true;
}

static void
__mem_cgroup_remove_exceeded(struct mem_cgroup *memcg,
				struct mem_cgroup_per_zone *mz,
				struct mem_cgroup_tree_per_zone *mctz)
{
	if (!mz->on_tree)
		return;
	rb_erase(&mz->tree_node, &mctz->rb_root);
	mz->on_tree = false;
}

static void
mem_cgroup_remove_exceeded(struct mem_cgroup *memcg,
				struct mem_cgroup_per_zone *mz,
				struct mem_cgroup_tree_per_zone *mctz)
{
	spin_lock(&mctz->lock);
	__mem_cgroup_remove_exceeded(memcg, mz, mctz);
	spin_unlock(&mctz->lock);
}

static unsigned long soft_limit_excess(struct mem_cgroup *memcg)
{
	unsigned long nr_pages = page_counter_read(&memcg->memory);
	unsigned long soft_limit = ACCESS_ONCE(memcg->soft_limit);
	unsigned long excess = 0;

	if (nr_pages > soft_limit)
		excess = nr_pages - soft_limit;

	return excess;
}

static void mem_cgroup_update_tree(struct mem_cgroup *memcg, struct page *page)
{
	unsigned long excess;
	struct mem_cgroup_per_zone *mz;
	struct mem_cgroup_tree_per_zone *mctz;
	int nid = page_to_nid(page);
	int zid = page_zonenum(page);
	mctz = soft_limit_tree_from_page(page);

	/*
	 * Necessary to update all ancestors when hierarchy is used.
	 * because their event counter is not touched.
	 */
	for (; memcg; memcg = parent_mem_cgroup(memcg)) {
		mz = mem_cgroup_zoneinfo(memcg, nid, zid);
		excess = soft_limit_excess(memcg);
		/*
		 * We have to update the tree if mz is on RB-tree or
		 * mem is over its softlimit.
		 */
		if (excess || mz->on_tree) {
			spin_lock(&mctz->lock);
			/* if on-tree, remove it */
			if (mz->on_tree)
				__mem_cgroup_remove_exceeded(memcg, mz, mctz);
			/*
			 * Insert again. mz->usage_in_excess will be updated.
			 * If excess is 0, no tree ops.
			 */
			__mem_cgroup_insert_exceeded(memcg, mz, mctz, excess);
			spin_unlock(&mctz->lock);
		}
	}
}

static void mem_cgroup_remove_from_trees(struct mem_cgroup *memcg)
{
	int node, zone;
	struct mem_cgroup_per_zone *mz;
	struct mem_cgroup_tree_per_zone *mctz;

	for_each_node(node) {
		for (zone = 0; zone < MAX_NR_ZONES; zone++) {
			mz = mem_cgroup_zoneinfo(memcg, node, zone);
			mctz = soft_limit_tree_node_zone(node, zone);
			mem_cgroup_remove_exceeded(memcg, mz, mctz);
		}
	}
}

static struct mem_cgroup_per_zone *
__mem_cgroup_largest_soft_limit_node(struct mem_cgroup_tree_per_zone *mctz)
{
	struct rb_node *rightmost = NULL;
	struct mem_cgroup_per_zone *mz;

retry:
	mz = NULL;
	rightmost = rb_last(&mctz->rb_root);
	if (!rightmost)
		goto done;		/* Nothing to reclaim from */

	mz = rb_entry(rightmost, struct mem_cgroup_per_zone, tree_node);
	/*
	 * Remove the node now but someone else can add it back,
	 * we will to add it back at the end of reclaim to its correct
	 * position in the tree.
	 */
	__mem_cgroup_remove_exceeded(mz->memcg, mz, mctz);
	if (!soft_limit_excess(mz->memcg) ||
		!css_tryget(&mz->memcg->css))
		goto retry;
done:
	return mz;
}

static struct mem_cgroup_per_zone *
mem_cgroup_largest_soft_limit_node(struct mem_cgroup_tree_per_zone *mctz)
{
	struct mem_cgroup_per_zone *mz;

	spin_lock(&mctz->lock);
	mz = __mem_cgroup_largest_soft_limit_node(mctz);
	spin_unlock(&mctz->lock);
	return mz;
}

/*
 * Implementation Note: reading percpu statistics for memcg.
 *
 * Both of vmstat[] and percpu_counter has threshold and do periodic
 * synchronization to implement "quick" read. There are trade-off between
 * reading cost and precision of value. Then, we may have a chance to implement
 * a periodic synchronizion of counter in memcg's counter.
 *
 * But this _read() function is used for user interface now. The user accounts
 * memory usage by memory cgroup and he _always_ requires exact value because
 * he accounts memory. Even if we provide quick-and-fuzzy read, we always
 * have to visit all online cpus and make sum. So, for now, unnecessary
 * synchronization is not implemented. (just implemented for cpu hotplug)
 *
 * If there are kernel internal actions which can make use of some not-exact
 * value, and reading all cpu value can be performance bottleneck in some
 * common workload, threashold and synchonization as vmstat[] should be
 * implemented.
 */
static long mem_cgroup_read_stat(struct mem_cgroup *memcg,
				 enum mem_cgroup_stat_index idx)
{
	long val = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		val += per_cpu(memcg->stat->count[idx], cpu);
	return val;
}

static void mem_cgroup_swap_statistics(struct mem_cgroup *memcg,
					 bool charge)
{
	int val = (charge) ? 1 : -1;
	this_cpu_add(memcg->stat->count[MEM_CGROUP_STAT_SWAP], val);
}

static void mem_cgroup_update_swap_max(struct mem_cgroup *memcg)
{
	long long swap;

	for (; memcg; memcg = parent_mem_cgroup(memcg)) {
		swap = res_counter_read_u64(&memcg->memsw, RES_USAGE) -
			res_counter_read_u64(&memcg->res, RES_USAGE);

		/* This is racy, but we don't have to be absolutely precise */
		if (swap > (long long)memcg->swap_max)
			memcg->swap_max = swap;
	}
}

static void mem_cgroup_inc_failcnt(struct mem_cgroup *memcg,
				   gfp_t gfp_mask, unsigned int nr_pages)
{
	if (gfp_mask & __GFP_NOWARN)
		return;

	atomic_long_inc(&memcg->mem_failcnt);
	if (do_swap_account &&
	    res_counter_margin(&memcg->memsw) < nr_pages * PAGE_SIZE)
		atomic_long_inc(&memcg->swap_failcnt);
}

static unsigned long mem_cgroup_read_events(struct mem_cgroup *memcg,
					    enum mem_cgroup_events_index idx)
{
	unsigned long val = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		val += per_cpu(memcg->stat->events[idx], cpu);
	return val;
}

/*
 * A more cacheline efficient way to accumulate all the percpu statistics
 * counts and events in the percpu stat->count and stat->events arrays into
 * the given stats and events arrays.
 */
static void mem_cgroup_sum_all_stat_events(struct mem_cgroup *memcg,
					   unsigned long *stats,
					   unsigned long *events)
{
	int i;
	int cpu;

	for_each_possible_cpu(cpu) {
		unsigned long *pcpu_stats = per_cpu(memcg->stat->count, cpu);
		unsigned long *pcpu_events = per_cpu(memcg->stat->events, cpu);

		for (i = 0; i < MEM_CGROUP_STAT_NSTATS; i++)
			stats[i] += pcpu_stats[i];

		for (i = 0; i < MEM_CGROUP_EVENTS_NSTATS; i++)
			events[i] = pcpu_events[i];
	}
	return;
}

static void mem_cgroup_charge_statistics(struct mem_cgroup *memcg,
					 struct page *page,
					 bool anon, int nr_pages)
{
	preempt_disable();

	/*
	 * Here, RSS means 'mapped anon' and anon's SwapCache. Shmem/tmpfs is
	 * counted as CACHE even if it's on ANON LRU.
	 */
	if (anon)
		__this_cpu_add(memcg->stat->count[MEM_CGROUP_STAT_RSS],
				nr_pages);
	else {
		__this_cpu_add(memcg->stat->count[MEM_CGROUP_STAT_CACHE],
				nr_pages);
		if (PageSwapBacked(page))
			__this_cpu_add(memcg->stat->count[MEM_CGROUP_STAT_SHMEM],
				       nr_pages);
	}

	if (PageTransHuge(page))
		__this_cpu_add(memcg->stat->count[MEM_CGROUP_STAT_RSS_HUGE],
				nr_pages);

	/* pagein of a big page is an event. So, ignore page size */
	if (nr_pages > 0)
		__this_cpu_inc(memcg->stat->events[MEM_CGROUP_EVENTS_PGPGIN]);
	else {
		__this_cpu_inc(memcg->stat->events[MEM_CGROUP_EVENTS_PGPGOUT]);
		nr_pages = -nr_pages; /* for event */
	}

	__this_cpu_add(memcg->stat->nr_page_events, nr_pages);

	preempt_enable();
}

unsigned long
mem_cgroup_get_lru_size(struct lruvec *lruvec, enum lru_list lru)
{
	struct mem_cgroup_per_zone *mz;

	mz = container_of(lruvec, struct mem_cgroup_per_zone, lruvec);
	return mz->lru_size[lru];
}

static unsigned long
mem_cgroup_zone_nr_lru_pages(struct mem_cgroup *memcg, int nid, int zid,
			unsigned int lru_mask)
{
	struct mem_cgroup_per_zone *mz;
	enum lru_list lru;
	unsigned long ret = 0;

	mz = mem_cgroup_zoneinfo(memcg, nid, zid);

	for_each_lru(lru) {
		if (BIT(lru) & lru_mask)
			ret += mz->lru_size[lru];
	}
	return ret;
}

static unsigned long
mem_cgroup_node_nr_lru_pages(struct mem_cgroup *memcg,
			int nid, unsigned int lru_mask)
{
	u64 total = 0;
	int zid;

	for (zid = 0; zid < MAX_NR_ZONES; zid++)
		total += mem_cgroup_zone_nr_lru_pages(memcg,
						nid, zid, lru_mask);

	return total;
}

static unsigned long mem_cgroup_nr_lru_pages(struct mem_cgroup *memcg,
			unsigned int lru_mask)
{
	int nid;
	u64 total = 0;

	for_each_node_state(nid, N_MEMORY)
		total += mem_cgroup_node_nr_lru_pages(memcg, nid, lru_mask);
	return total;
}

static bool mem_cgroup_event_ratelimit(struct mem_cgroup *memcg,
				       enum mem_cgroup_events_target target)
{
	unsigned long val, next;

	val = __this_cpu_read(memcg->stat->nr_page_events);
	next = __this_cpu_read(memcg->stat->targets[target]);
	/* from time_after() in jiffies.h */
	if ((long)next - (long)val < 0) {
		switch (target) {
		case MEM_CGROUP_TARGET_THRESH:
			next = val + THRESHOLDS_EVENTS_TARGET;
			break;
		case MEM_CGROUP_TARGET_SOFTLIMIT:
			next = val + SOFTLIMIT_EVENTS_TARGET;
			break;
		case MEM_CGROUP_TARGET_NUMAINFO:
			next = val + NUMAINFO_EVENTS_TARGET;
			break;
		default:
			break;
		}
		__this_cpu_write(memcg->stat->targets[target], next);
		return true;
	}
	return false;
}

/*
 * Check events in order.
 *
 */
static void memcg_check_events(struct mem_cgroup *memcg, struct page *page)
{
	preempt_disable();
	/* threshold event is triggered in finer grain than soft limit */
	if (unlikely(mem_cgroup_event_ratelimit(memcg,
						MEM_CGROUP_TARGET_THRESH))) {
		bool do_softlimit;
		bool do_numainfo __maybe_unused;

		do_softlimit = mem_cgroup_event_ratelimit(memcg,
						MEM_CGROUP_TARGET_SOFTLIMIT);
#if MAX_NUMNODES > 1
		do_numainfo = mem_cgroup_event_ratelimit(memcg,
						MEM_CGROUP_TARGET_NUMAINFO);
#endif
		preempt_enable();

		mem_cgroup_threshold(memcg);
		if (unlikely(do_softlimit))
			mem_cgroup_update_tree(memcg, page);
#if MAX_NUMNODES > 1
		if (unlikely(do_numainfo))
			atomic_inc(&memcg->numainfo_events);
#endif
	} else
		preempt_enable();
}

struct mem_cgroup *mem_cgroup_from_cont(struct cgroup *cont)
{
	return mem_cgroup_from_css(
		cgroup_subsys_state(cont, mem_cgroup_subsys_id));
}

struct mem_cgroup *mem_cgroup_from_task(struct task_struct *p)
{
	/*
	 * mm_update_next_owner() may clear mm->owner to NULL
	 * if it races with swapoff, page migration, etc.
	 * So this can be called with p == NULL.
	 */
	if (unlikely(!p))
		return NULL;

	return mem_cgroup_from_css(task_subsys_state(p, mem_cgroup_subsys_id));
}

struct mem_cgroup *try_get_mem_cgroup_from_mm(struct mm_struct *mm)
{
	struct mem_cgroup *memcg = NULL;

	if (!mm)
		return NULL;
	/*
	 * Because we have no locks, mm->owner's may be being moved to other
	 * cgroup. We use css_tryget() here even if this looks
	 * pessimistic (rather than adding locks here).
	 */
	rcu_read_lock();
	do {
		memcg = mem_cgroup_from_task(rcu_dereference(mm->owner));
		if (unlikely(!memcg))
			break;
	} while (!css_tryget(&memcg->css));
	rcu_read_unlock();
	return memcg;
}

/*
 * Returns a next (in a pre-order walk) alive memcg (with elevated css
 * ref. count) or NULL if the whole root's subtree has been visited.
 *
 * helper function to be used by mem_cgroup_iter
 */
static struct mem_cgroup *__mem_cgroup_iter_next(struct mem_cgroup *root,
		struct mem_cgroup *last_visited)
{
	struct cgroup *prev_cgroup, *next_cgroup;

	/*
	 * Root is not visited by cgroup iterators so it needs an
	 * explicit visit.
	 */
	if (!last_visited)
		return root;

	prev_cgroup = (last_visited == root) ? NULL
		: last_visited->css.cgroup;
skip_node:
	next_cgroup = cgroup_next_descendant_pre(
			prev_cgroup, root->css.cgroup);

	/*
	 * Even if we found a group we have to make sure it is
	 * alive. css && !memcg means that the groups should be
	 * skipped and we should continue the tree walk.
	 * last_visited css is safe to use because it is
	 * protected by css_get and the tree walk is rcu safe.
	 */
	if (next_cgroup) {
		struct mem_cgroup *mem = mem_cgroup_from_cont(
				next_cgroup);
		if (css_tryget(&mem->css))
			return mem;
		else {
			prev_cgroup = next_cgroup;
			goto skip_node;
		}
	}

	return NULL;
}

static void mem_cgroup_iter_invalidate(struct mem_cgroup *root)
{
	/*
	 * When a group in the hierarchy below root is destroyed, the
	 * hierarchy iterator can no longer be trusted since it might
	 * have pointed to the destroyed group.  Invalidate it.
	 */
	atomic_inc(&root->dead_count);
}

static struct mem_cgroup *
mem_cgroup_iter_load(struct mem_cgroup_reclaim_iter *iter,
		     struct mem_cgroup *root,
		     int *sequence)
{
	struct mem_cgroup *position = NULL;
	/*
	 * A cgroup destruction happens in two stages: offlining and
	 * release.  They are separated by a RCU grace period.
	 *
	 * If the iterator is valid, we may still race with an
	 * offlining.  The RCU lock ensures the object won't be
	 * released, tryget will fail if we lost the race.
	 */
	*sequence = atomic_read(&root->dead_count);
	if (iter->last_dead_count == *sequence) {
		smp_rmb();
		position = iter->last_visited;

		/*
		 * We cannot take a reference to root because we might race
		 * with root removal and returning NULL would end up in
		 * an endless loop on the iterator user level when root
		 * would be returned all the time.
		*/
		if (position && position != root &&
				!css_tryget(&position->css))

			position = NULL;
	}
	return position;
}

static void mem_cgroup_iter_update(struct mem_cgroup_reclaim_iter *iter,
				   struct mem_cgroup *last_visited,
				   struct mem_cgroup *new_position,
				   struct mem_cgroup *root,
				   int sequence)
{
	/* root reference counting symmetric to mem_cgroup_iter_load */
	if (last_visited && last_visited != root)
		css_put(&last_visited->css);
	/*
	 * We store the sequence count from the time @last_visited was
	 * loaded successfully instead of rereading it here so that we
	 * don't lose destruction events in between.  We could have
	 * raced with the destruction of @new_position after all.
	 */
	iter->last_visited = new_position;
	smp_wmb();
	iter->last_dead_count = sequence;
}

/**
 * mem_cgroup_iter - iterate over memory cgroup hierarchy
 * @root: hierarchy root
 * @prev: previously returned memcg, NULL on first invocation
 * @reclaim: cookie for shared reclaim walks, NULL for full walks
 *
 * Returns references to children of the hierarchy below @root, or
 * @root itself, or %NULL after a full round-trip.
 *
 * Caller must pass the return value in @prev on subsequent
 * invocations for reference counting, or use mem_cgroup_iter_break()
 * to cancel a hierarchy walk before the round-trip is complete.
 *
 * Reclaimers can specify a zone and a priority level in @reclaim to
 * divide up the memcgs in the hierarchy among all concurrent
 * reclaimers operating on the same zone and priority.
 */
struct mem_cgroup *mem_cgroup_iter(struct mem_cgroup *root,
				   struct mem_cgroup *prev,
				   struct mem_cgroup_reclaim_cookie *reclaim)
{
	struct mem_cgroup *memcg = NULL;
	struct mem_cgroup *last_visited = NULL;

	if (mem_cgroup_disabled())
		return NULL;

	if (!root)
		root = root_mem_cgroup;

	if (prev && !reclaim)
		last_visited = prev;

	if (!root->use_hierarchy && root != root_mem_cgroup) {
		if (prev)
			goto out_css_put;
		return root;
	}

	rcu_read_lock();
	while (!memcg) {
		struct mem_cgroup_reclaim_iter *uninitialized_var(iter);
		int uninitialized_var(seq);

		if (reclaim) {
			int nid = zone_to_nid(reclaim->zone);
			int zid = zone_idx(reclaim->zone);
			struct mem_cgroup_per_zone *mz;

			mz = mem_cgroup_zoneinfo(root, nid, zid);
			iter = &mz->reclaim_iter[reclaim->priority];
			if (prev && reclaim->generation != iter->generation) {
				iter->last_visited = NULL;
				goto out_unlock;
			}

			last_visited = mem_cgroup_iter_load(iter, root, &seq);
		}

		memcg = __mem_cgroup_iter_next(root, last_visited);

		if (reclaim) {
			mem_cgroup_iter_update(iter, last_visited, memcg, root,
					seq);

			if (!memcg)
				iter->generation++;
			else if (!prev && memcg)
				reclaim->generation = iter->generation;
		}

		if (prev && !memcg)
			goto out_unlock;
	}
out_unlock:
	rcu_read_unlock();
out_css_put:
	if (prev && prev != root)
		css_put(&prev->css);

	return memcg;
}

/**
 * mem_cgroup_iter_break - abort a hierarchy walk prematurely
 * @root: hierarchy root
 * @prev: last visited hierarchy member as returned by mem_cgroup_iter()
 */
void mem_cgroup_iter_break(struct mem_cgroup *root,
			   struct mem_cgroup *prev)
{
	if (!root)
		root = root_mem_cgroup;
	if (prev && prev != root)
		css_put(&prev->css);
}

/*
 * Iteration constructs for visiting all cgroups (under a tree).  If
 * loops are exited prematurely (break), mem_cgroup_iter_break() must
 * be used for reference counting.
 */
#define for_each_mem_cgroup_tree(iter, root)		\
	for (iter = mem_cgroup_iter(root, NULL, NULL);	\
	     iter != NULL;				\
	     iter = mem_cgroup_iter(root, iter, NULL))

#define for_each_mem_cgroup(iter)			\
	for (iter = mem_cgroup_iter(NULL, NULL, NULL);	\
	     iter != NULL;				\
	     iter = mem_cgroup_iter(NULL, iter, NULL))

void mem_cgroup_get_nr_pages(struct mem_cgroup *memcg, int nid,
			     unsigned long *pages)
{
	struct mem_cgroup *iter;
	int i;

	for_each_mem_cgroup_tree(iter, memcg) {
		for (i = 0; i < NR_LRU_LISTS; i++)
			pages[i] += mem_cgroup_node_nr_lru_pages(iter, nid,
								 BIT(i));
	}
}

void __mem_cgroup_count_vm_event(struct mm_struct *mm, enum vm_event_item idx)
{
	struct mem_cgroup *memcg;

	rcu_read_lock();
	memcg = mem_cgroup_from_task(rcu_dereference(mm->owner));
	if (unlikely(!memcg))
		goto out;

	switch (idx) {
	case PGFAULT:
		this_cpu_inc(memcg->stat->events[MEM_CGROUP_EVENTS_PGFAULT]);
		break;
	case PGMAJFAULT:
		this_cpu_inc(memcg->stat->events[MEM_CGROUP_EVENTS_PGMAJFAULT]);
		break;
	default:
		BUG();
	}
out:
	rcu_read_unlock();
}
EXPORT_SYMBOL(__mem_cgroup_count_vm_event);

/**
 * mem_cgroup_zone_lruvec - get the lru list vector for a zone and memcg
 * @zone: zone of the wanted lruvec
 * @memcg: memcg of the wanted lruvec
 *
 * Returns the lru list vector holding pages for the given @zone and
 * @mem.  This can be the global zone lruvec, if the memory controller
 * is disabled.
 */
struct lruvec *mem_cgroup_zone_lruvec(struct zone *zone,
				      struct mem_cgroup *memcg)
{
	struct mem_cgroup_per_zone *mz;
	struct lruvec *lruvec;

	if (mem_cgroup_disabled()) {
		lruvec = &zone->lruvec;
		goto out;
	}

	mz = mem_cgroup_zoneinfo(memcg, zone_to_nid(zone), zone_idx(zone));
	lruvec = &mz->lruvec;
out:
	/*
	 * Since a node can be onlined after the mem_cgroup was created,
	 * we have to be prepared to initialize lruvec->zone here;
	 * and if offlined then reonlined, we need to reinitialize it.
	 */
	if (unlikely(lruvec->zone != zone))
		lruvec->zone = zone;
	return lruvec;
}

/*
 * Following LRU functions are allowed to be used without PCG_LOCK.
 * Operations are called by routine of global LRU independently from memcg.
 * What we have to take care of here is validness of pc->mem_cgroup.
 *
 * Changes to pc->mem_cgroup happens when
 * 1. charge
 * 2. moving account
 * In typical case, "charge" is done before add-to-lru. Exception is SwapCache.
 * It is added to LRU before charge.
 * If PCG_USED bit is not set, page_cgroup is not added to this private LRU.
 * When moving account, the page is not on LRU. It's isolated.
 */

/**
 * mem_cgroup_page_lruvec - return lruvec for adding an lru page
 * @page: the page
 * @zone: zone of the page
 */
struct lruvec *mem_cgroup_page_lruvec(struct page *page, struct zone *zone)
{
	struct mem_cgroup_per_zone *mz;
	struct mem_cgroup *memcg;
	struct page_cgroup *pc;
	struct lruvec *lruvec;

	if (mem_cgroup_disabled()) {
		lruvec = &zone->lruvec;
		goto out;
	}

	pc = lookup_page_cgroup(page);
	memcg = pc->mem_cgroup;

	/*
	 * Surreptitiously switch any uncharged offlist page to root:
	 * an uncharged page off lru does nothing to secure
	 * its former mem_cgroup from sudden removal.
	 *
	 * Our caller holds lru_lock, and PageCgroupUsed is updated
	 * under page_cgroup lock: between them, they make all uses
	 * of pc->mem_cgroup safe.
	 */
	if (!PageLRU(page) && !PageCgroupUsed(pc) && memcg != root_mem_cgroup)
		pc->mem_cgroup = memcg = root_mem_cgroup;

	mz = page_cgroup_zoneinfo(memcg, page);
	lruvec = &mz->lruvec;
out:
	/*
	 * Since a node can be onlined after the mem_cgroup was created,
	 * we have to be prepared to initialize lruvec->zone here;
	 * and if offlined then reonlined, we need to reinitialize it.
	 */
	if (unlikely(lruvec->zone != zone))
		lruvec->zone = zone;
	return lruvec;
}

/**
 * mem_cgroup_update_lru_size - account for adding or removing an lru page
 * @lruvec: mem_cgroup per zone lru vector
 * @lru: index of lru list the page is sitting on
 * @nr_pages: positive when adding or negative when removing
 *
 * This function must be called when a page is added to or removed from an
 * lru list.
 */
void mem_cgroup_update_lru_size(struct lruvec *lruvec, enum lru_list lru,
				int nr_pages)
{
	struct mem_cgroup_per_zone *mz;
	unsigned long *lru_size;

	if (mem_cgroup_disabled())
		return;

	mz = container_of(lruvec, struct mem_cgroup_per_zone, lruvec);
	lru_size = mz->lru_size + lru;
	*lru_size += nr_pages;
	VM_BUG_ON((long)(*lru_size) < 0);
}

/*
 * Checks whether given mem is same or in the root_mem_cgroup's
 * hierarchy subtree
 */
bool __mem_cgroup_same_or_subtree(const struct mem_cgroup *root_memcg,
				  struct mem_cgroup *memcg)
{
	if (root_memcg == memcg)
		return true;
	if (!root_memcg->use_hierarchy || !memcg)
		return false;
	return cgroup_is_descendant(memcg->css.cgroup, root_memcg->css.cgroup);
}

static bool mem_cgroup_same_or_subtree(const struct mem_cgroup *root_memcg,
				       struct mem_cgroup *memcg)
{
	bool ret;

	rcu_read_lock();
	ret = __mem_cgroup_same_or_subtree(root_memcg, memcg);
	rcu_read_unlock();
	return ret;
}

int task_in_mem_cgroup(struct task_struct *task, const struct mem_cgroup *memcg)
{
	int ret;
	struct mem_cgroup *curr = NULL;
	struct task_struct *p;

	p = find_lock_task_mm(task);
	if (p) {
		curr = try_get_mem_cgroup_from_mm(p->mm);
		task_unlock(p);
	} else {
		/*
		 * All threads may have already detached their mm's, but the oom
		 * killer still needs to detect if they have already been oom
		 * killed to prevent needlessly killing additional tasks.
		 */
		task_lock(task);
		curr = mem_cgroup_from_task(task);
		if (curr)
			css_get(&curr->css);
		task_unlock(task);
	}
	if (!curr)
		return 0;
	/*
	 * We should check use_hierarchy of "memcg" not "curr". Because checking
	 * use_hierarchy of "curr" here make this function true if hierarchy is
	 * enabled in "curr" and "curr" is a child of "memcg" in *cgroup*
	 * hierarchy(even if use_hierarchy is disabled in "memcg").
	 */
	ret = mem_cgroup_same_or_subtree(memcg, curr);
	css_put(&curr->css);
	return ret;
}

int mem_cgroup_inactive_anon_is_low(struct lruvec *lruvec)
{
	unsigned long inactive_ratio;
	unsigned long inactive;
	unsigned long active;
	unsigned long gb;

	inactive = mem_cgroup_get_lru_size(lruvec, LRU_INACTIVE_ANON);
	active = mem_cgroup_get_lru_size(lruvec, LRU_ACTIVE_ANON);

	gb = (inactive + active) >> (30 - PAGE_SHIFT);
	if (gb)
		inactive_ratio = int_sqrt(10 * gb);
	else
		inactive_ratio = 1;

	return inactive * inactive_ratio < active;
}

bool mem_cgroup_dcache_is_low(struct mem_cgroup *memcg, int vfs_cache_min_ratio)
{
	unsigned long anon, file, dcache;

	anon = mem_cgroup_read_stat(memcg, MEM_CGROUP_STAT_RSS);
	file = mem_cgroup_read_stat(memcg, MEM_CGROUP_STAT_CACHE);
	dcache = mem_cgroup_read_stat(memcg, MEM_CGROUP_STAT_SLAB_RECLAIMABLE);

	return dcache / vfs_cache_min_ratio <
			(anon + file + dcache) / 100;
}

/**
 * mem_cgroup_low - check if memory consumption is below the normal range
 * @root: the highest ancestor to consider
 * @memcg: the memory cgroup to check
 *
 * Returns %true if memory consumption of @memcg, and that of all
 * configurable ancestors up to @root, is below the normal range.
 */
bool mem_cgroup_low(struct mem_cgroup *root, struct mem_cgroup *memcg)
{
	if (mem_cgroup_disabled())
		return false;

	/*
	 * The toplevel group doesn't have a configurable range, so
	 * it's never low when looked at directly, and it is not
	 * considered an ancestor when assessing the hierarchy.
	 */

	if (memcg == root_mem_cgroup)
		return false;

	if (res_counter_read_u64(&memcg->res, RES_USAGE) >= memcg->low)
		return false;

	/*
	 * XXX: It's OK to set memory.low for a cgroup to infinity. This might
	 * be useful if no tasks are supposed to run inside the cgroup itself,
	 * but only in its sub-cgroups (e.g. /machine.slice). In this case
	 * protection against memory pressure originating on upper levels will
	 * be guarded solely by memory.low configuration in sub-cgroups.
	 *
	 * However, in the current implementation, in contrast to mainstream,
	 * charges can appear in a cgroup even if there's no tasks in it - they
	 * can be reparented from a dead sub-cgroup. If the cgroup has
	 * memory.low set to inf, such reparented charges will not get
	 * reclaimed normally on memory pressure, resulting in performance
	 * degradation in other cgroups. To avoid that, let's ignore memory.low
	 * for cgroups w/o tasks.
	 */
	if (cgroup_task_count(memcg->css.cgroup) == 0)
		return false;

	while (memcg != root) {
		memcg = parent_mem_cgroup(memcg);
		if (!memcg)
			break;

		if (memcg == root_mem_cgroup)
			break;

		if (res_counter_read_u64(&memcg->res, RES_USAGE) >= memcg->low)
			return false;
	}
	return true;
}

static bool __mem_cgroup_below_oom_guarantee(struct mem_cgroup *root,
					     struct mem_cgroup *memcg)
{
	if (mem_cgroup_disabled())
		return false;

	if (memcg == root_mem_cgroup)
		return false;

	if (res_counter_read_u64(&memcg->memsw, RES_USAGE) >=
					memcg->oom_guarantee)
		return false;

	while (memcg != root) {
		memcg = parent_mem_cgroup(memcg);
		if (!memcg)
			break;

		if (memcg == root_mem_cgroup)
			break;

		if (res_counter_read_u64(&memcg->memsw, RES_USAGE) >=
						memcg->oom_guarantee)
			return false;
	}
	return true;
}

bool mem_cgroup_below_oom_guarantee(struct task_struct *p)
{
	struct mem_cgroup *memcg = NULL;
	bool ret = false;

	p = find_lock_task_mm(p);
	if (p) {
		memcg = try_get_mem_cgroup_from_mm(p->mm);
		task_unlock(p);
	}
	if (memcg) {
		ret = __mem_cgroup_below_oom_guarantee(root_mem_cgroup, memcg);
		css_put(&memcg->css);
	}
	return ret;
}

#ifdef CONFIG_CLEANCACHE
bool mem_cgroup_cleancache_disabled(struct page *page)
{
	struct page_cgroup *pc;
	bool ret = false;

	if (mem_cgroup_disabled())
		return false;

	pc = lookup_page_cgroup(page);
	if (!PageCgroupUsed(pc))
		return false;

	lock_page_cgroup(pc);
	if (likely(PageCgroupUsed(pc)))
		ret = pc->mem_cgroup->cleancache_disabled;
	unlock_page_cgroup(pc);
	return ret;
}
#endif

void mem_cgroup_note_oom_kill(struct mem_cgroup *root_memcg,
			      struct task_struct *task)
{
	struct mem_cgroup *memcg, *memcg_to_put;
	struct task_struct *p;

	if (!root_memcg)
		root_memcg = root_mem_cgroup;

	p = find_lock_task_mm(task);
	if (p) {
		memcg = try_get_mem_cgroup_from_mm(p->mm);
		task_unlock(p);
	} else {
		rcu_read_lock();
		memcg = mem_cgroup_from_task(task);
		css_get(&memcg->css);
		rcu_read_unlock();
	}
	memcg_to_put = memcg;
	if (!memcg || !mem_cgroup_same_or_subtree(root_memcg, memcg))
		memcg = root_memcg;

	for (; memcg; memcg = parent_mem_cgroup(memcg)) {
		atomic_long_inc(&memcg->oom_kill_cnt);
		if (memcg == root_memcg)
			break;
	}

	if (memcg_to_put)
		css_put(&memcg_to_put->css);
}

unsigned long mem_cgroup_total_pages(struct mem_cgroup *memcg, bool swap)
{
	unsigned long long limit;

	limit = swap ? res_counter_read_u64(&memcg->memsw, RES_LIMIT) :
			res_counter_read_u64(&memcg->res, RES_LIMIT);
	if (limit >= RESOURCE_MAX)
		return ULONG_MAX;
	return min_t(unsigned long long, ULONG_MAX, limit >> PAGE_SHIFT);
}

#define mem_cgroup_from_counter(counter, member)	\
	container_of(counter, struct mem_cgroup, member)

/**
 * mem_cgroup_margin - calculate chargeable space of a memory cgroup
 * @memcg: the memory cgroup
 *
 * Returns the maximum amount of memory @mem can be charged with, in
 * pages.
 */
static unsigned long mem_cgroup_margin(struct mem_cgroup *memcg)
{
	unsigned long margin = 0;
	unsigned long count;
	unsigned long limit;

	count = page_counter_read(&memcg->memory);
	limit = ACCESS_ONCE(memcg->memory.limit);
	if (count < limit)
		margin = limit - count;

	if (do_swap_account) {
		count = page_counter_read(&memcg->memsw);
		limit = ACCESS_ONCE(memcg->memsw.limit);
		if (count <= limit)
			margin = min(margin, limit - count);
	}

	return margin;
}

int mem_cgroup_swappiness(struct mem_cgroup *memcg)
{
	struct cgroup *cgrp = memcg->css.cgroup;

	/* root ? */
	if (cgrp->parent == NULL)
		return vm_swappiness;

	return memcg->swappiness;
}

/*
 * memcg->moving_account is used for checking possibility that some thread is
 * calling move_account(). When a thread on CPU-A starts moving pages under
 * a memcg, other threads should check memcg->moving_account under
 * rcu_read_lock(), like this:
 *
 *         CPU-A                                    CPU-B
 *                                              rcu_read_lock()
 *         memcg->moving_account+1              if (memcg->mocing_account)
 *                                                   take heavy locks.
 *         synchronize_rcu()                    update something.
 *                                              rcu_read_unlock()
 *         start move here.
 */

/* for quick checking without looking up memcg */
atomic_t memcg_moving __read_mostly;

static void mem_cgroup_start_move(struct mem_cgroup *memcg)
{
	atomic_inc(&memcg_moving);
	atomic_inc(&memcg->moving_account);
	synchronize_rcu();
}

static void mem_cgroup_end_move(struct mem_cgroup *memcg)
{
	/*
	 * Now, mem_cgroup_clear_mc() may call this function with NULL.
	 * We check NULL in callee rather than caller.
	 */
	if (memcg) {
		atomic_dec(&memcg_moving);
		atomic_dec(&memcg->moving_account);
	}
}

/*
 * 2 routines for checking "mem" is under move_account() or not.
 *
 * mem_cgroup_stolen() -  checking whether a cgroup is mc.from or not. This
 *			  is used for avoiding races in accounting.  If true,
 *			  pc->mem_cgroup may be overwritten.
 *
 * mem_cgroup_under_move() - checking a cgroup is mc.from or mc.to or
 *			  under hierarchy of moving cgroups. This is for
 *			  waiting at hith-memory prressure caused by "move".
 */

static bool mem_cgroup_stolen(struct mem_cgroup *memcg)
{
	VM_BUG_ON(!rcu_read_lock_held());
	return atomic_read(&memcg->moving_account) > 0;
}

static bool mem_cgroup_under_move(struct mem_cgroup *memcg)
{
	struct mem_cgroup *from;
	struct mem_cgroup *to;
	bool ret = false;
	/*
	 * Unlike task_move routines, we access mc.to, mc.from not under
	 * mutual exclusion by cgroup_mutex. Here, we take spinlock instead.
	 */
	spin_lock(&mc.lock);
	from = mc.from;
	to = mc.to;
	if (!from)
		goto unlock;

	ret = mem_cgroup_same_or_subtree(memcg, from)
		|| mem_cgroup_same_or_subtree(memcg, to);
unlock:
	spin_unlock(&mc.lock);
	return ret;
}

static bool mem_cgroup_wait_acct_move(struct mem_cgroup *memcg)
{
	if (mc.moving_task && current != mc.moving_task) {
		if (mem_cgroup_under_move(memcg)) {
			DEFINE_WAIT(wait);
			prepare_to_wait(&mc.waitq, &wait, TASK_INTERRUPTIBLE);
			/* moving charge context might have finished. */
			if (mc.moving_task)
				schedule();
			finish_wait(&mc.waitq, &wait);
			return true;
		}
	}
	return false;
}

/*
 * Take this lock when
 * - a code tries to modify page's memcg while it's USED.
 * - a code tries to modify page state accounting in a memcg.
 * see mem_cgroup_stolen(), too.
 */
static void move_lock_mem_cgroup(struct mem_cgroup *memcg,
				  unsigned long *flags)
{
	spin_lock_irqsave(&memcg->move_lock, *flags);
}

static void move_unlock_mem_cgroup(struct mem_cgroup *memcg,
				unsigned long *flags)
{
	spin_unlock_irqrestore(&memcg->move_lock, *flags);
}

#define K(x) ((x) << (PAGE_SHIFT-10))
/**
 * mem_cgroup_print_oom_info: Print OOM information relevant to memory controller.
 * @memcg: The memory cgroup that went over limit
 * @p: Task that is going to be killed
 *
 * NOTE: @memcg and @p's mem_cgroup can be different when hierarchy is
 * enabled
 */
void mem_cgroup_print_oom_info(struct mem_cgroup *memcg, struct task_struct *p)
{
	/*
	 * protects memcg_name and makes sure that parallel ooms do not
	 * interleave
	 */
	static DEFINE_MUTEX(oom_info_lock);
	struct cgroup *task_cgrp;
	struct cgroup *mem_cgrp;
	static char memcg_name[PATH_MAX];
	int ret;
	struct mem_cgroup *iter;
	unsigned int i;

	if (!p)
		return;

	mutex_lock(&oom_info_lock);
	rcu_read_lock();

	mem_cgrp = memcg->css.cgroup;
	task_cgrp = task_cgroup(p, mem_cgroup_subsys_id);

	ret = cgroup_path(task_cgrp, memcg_name, PATH_MAX);
	if (ret < 0) {
		/*
		 * Unfortunately, we are unable to convert to a useful name
		 * But we'll still print out the usage information
		 */
		rcu_read_unlock();
		goto done;
	}
	rcu_read_unlock();

	pr_info("Task in %s killed", memcg_name);

	rcu_read_lock();
	ret = cgroup_path(mem_cgrp, memcg_name, PATH_MAX);
	if (ret < 0) {
		rcu_read_unlock();
		goto done;
	}
	rcu_read_unlock();

	/*
	 * Continues from above, so we don't need an KERN_ level
	 */
	pr_cont(" as a result of limit of %s\n", memcg_name);
done:

	pr_info("memory: usage %llukB, limit %llukB, failcnt %lu\n",
		K((u64)page_counter_read(&memcg->memory)),
		K((u64)memcg->memory.limit), memcg->memory.failcnt);
	pr_info("memory+swap: usage %llukB, limit %llukB, failcnt %lu\n",
		K((u64)page_counter_read(&memcg->memsw)),
		K((u64)memcg->memsw.limit), memcg->memsw.failcnt);
	pr_info("kmem: usage %llukB, limit %llukB, failcnt %lu\n",
		K((u64)page_counter_read(&memcg->kmem)),
		K((u64)memcg->kmem.limit), memcg->kmem.failcnt);

	for_each_mem_cgroup_tree(iter, memcg) {
		pr_info("Memory cgroup stats");

		rcu_read_lock();
		ret = cgroup_path(iter->css.cgroup, memcg_name, PATH_MAX);
		if (!ret)
			pr_cont(" for %s", memcg_name);
		rcu_read_unlock();
		pr_cont(":");

		for (i = 0; i < MEM_CGROUP_STAT_NSTATS; i++) {
			if (i == MEM_CGROUP_STAT_SWAP && !do_swap_account)
				continue;
			pr_cont(" %s:%ldKB", mem_cgroup_stat_names[i],
				K(mem_cgroup_read_stat(iter, i)));
		}

		for (i = 0; i < NR_LRU_LISTS; i++)
			pr_cont(" %s:%luKB", mem_cgroup_lru_names[i],
				K(mem_cgroup_nr_lru_pages(iter, BIT(i))));

		pr_cont("\n");
	}
	mutex_unlock(&oom_info_lock);
}

/*
 * This function returns the number of memcg under hierarchy tree. Returns
 * 1(self count) if no children.
 */
static int mem_cgroup_count_children(struct mem_cgroup *memcg)
{
	int num = 0;
	struct mem_cgroup *iter;

	for_each_mem_cgroup_tree(iter, memcg)
		num++;
	return num;
}

/*
 * Return the memory (and swap, if configured) limit for a memcg.
 */
static unsigned long mem_cgroup_get_limit(struct mem_cgroup *memcg)
{
	unsigned long limit;

	limit = memcg->memory.limit;
	if (mem_cgroup_swappiness(memcg)) {
		unsigned long memsw_limit;

		memsw_limit = memcg->memsw.limit;
		limit = min(limit + total_swap_pages, memsw_limit);
	}
	return limit;
}

static void mem_cgroup_out_of_memory(struct mem_cgroup *memcg, gfp_t gfp_mask,
				     int order)
{
	struct mem_cgroup *iter;
	unsigned long chosen_points = 0;
	unsigned long totalpages;
	unsigned int points = 0;
	struct task_struct *chosen = NULL;
	bool ignore_memcg_guarantee = false;

	/*
	 * If current has a pending SIGKILL or is exiting, then automatically
	 * select it.  The goal is to allow it to allocate so that it may
	 * quickly exit and free its memory.
	 */
	if (fatal_signal_pending(current) || task_will_free_mem(current)) {
		set_thread_flag(TIF_MEMDIE);
		return;
	}

	check_panic_on_oom(CONSTRAINT_MEMCG, gfp_mask, order, NULL);
	totalpages = mem_cgroup_get_limit(memcg) ? : 1;
retry:
	for_each_mem_cgroup_tree(iter, memcg) {
		struct cgroup *cgroup = iter->css.cgroup;
		struct cgroup_iter it;
		struct task_struct *task;

		if (!ignore_memcg_guarantee &&
		    __mem_cgroup_below_oom_guarantee(memcg, iter))
			continue;

		cgroup_iter_start(cgroup, &it);
		while ((task = cgroup_iter_next(cgroup, &it))) {
			switch (oom_scan_process_thread(task, totalpages, NULL,
							false, true)) {
			case OOM_SCAN_SELECT:
				if (chosen)
					put_task_struct(chosen);
				chosen = task;
				chosen_points = ULONG_MAX;
				get_task_struct(chosen);
				/* fall through */
			case OOM_SCAN_CONTINUE:
				continue;
			case OOM_SCAN_ABORT:
				cgroup_iter_end(cgroup, &it);
				mem_cgroup_iter_break(memcg, iter);
				if (chosen)
					put_task_struct(chosen);
				return;
			case OOM_SCAN_OK:
				break;
			};
			points = oom_badness(task, memcg, NULL, totalpages);
			if (points > chosen_points) {
				if (chosen)
					put_task_struct(chosen);
				chosen = task;
				chosen_points = points;
				get_task_struct(chosen);
			}
		}
		cgroup_iter_end(cgroup, &it);
	}

	if (!chosen) {
		if (!ignore_memcg_guarantee) {
			ignore_memcg_guarantee = true;
			goto retry;
		}
		return;
	}
	points = chosen_points * 1000 / totalpages;
	oom_kill_process(chosen, gfp_mask, order, points, totalpages, memcg,
			 NULL, "Memory cgroup out of memory");
}

static unsigned long mem_cgroup_reclaim(struct mem_cgroup *memcg,
					gfp_t gfp_mask,
					unsigned long flags)
{
	unsigned long total = 0;
	bool noswap = false;
	int loop;

	if (flags & MEM_CGROUP_RECLAIM_NOSWAP)
		noswap = true;
	if (!(flags & MEM_CGROUP_RECLAIM_SHRINK) && memcg->memsw_is_minimum)
		noswap = true;

	for (loop = 0; loop < MEM_CGROUP_MAX_RECLAIM_LOOPS; loop++) {
		if (loop)
			drain_all_stock_async(memcg);
		total += try_to_free_mem_cgroup_pages(memcg, SWAP_CLUSTER_MAX,
						      gfp_mask, noswap);
		if (fatal_signal_pending(current))
			return 1;
		/*
		 * Allow limit shrinkers, which are triggered directly
		 * by userspace, to catch signals and stop reclaim
		 * after minimal progress, regardless of the margin.
		 */
		if (total && (flags & MEM_CGROUP_RECLAIM_SHRINK))
			break;
		if (mem_cgroup_margin(memcg))
			break;
		/*
		 * If nothing was reclaimed after two attempts, there
		 * may be no reclaimable pages in this hierarchy.
		 */
		if (loop && !total)
			break;
	}
	return total;
}

/**
 * test_mem_cgroup_node_reclaimable
 * @memcg: the target memcg
 * @nid: the node ID to be checked.
 * @noswap : specify true here if the user wants flle only information.
 *
 * This function returns whether the specified memcg contains any
 * reclaimable pages on a node. Returns true if there are any reclaimable
 * pages in the node.
 */
static bool test_mem_cgroup_node_reclaimable(struct mem_cgroup *memcg,
		int nid, bool noswap)
{
	if (mem_cgroup_node_nr_lru_pages(memcg, nid, LRU_ALL_FILE))
		return true;
	if (noswap || !total_swap_pages)
		return false;
	if (mem_cgroup_node_nr_lru_pages(memcg, nid, LRU_ALL_ANON))
		return true;
	return false;

}
#if MAX_NUMNODES > 1

/*
 * Always updating the nodemask is not very good - even if we have an empty
 * list or the wrong list here, we can start from some node and traverse all
 * nodes based on the zonelist. So update the list loosely once per 10 secs.
 *
 */
static void mem_cgroup_may_update_nodemask(struct mem_cgroup *memcg)
{
	int nid;
	/*
	 * numainfo_events > 0 means there was at least NUMAINFO_EVENTS_TARGET
	 * pagein/pageout changes since the last update.
	 */
	if (!atomic_read(&memcg->numainfo_events))
		return;
	if (atomic_inc_return(&memcg->numainfo_updating) > 1)
		return;

	/* make a nodemask where this memcg uses memory from */
	memcg->scan_nodes = node_states[N_MEMORY];

	for_each_node_mask(nid, node_states[N_MEMORY]) {

		if (!test_mem_cgroup_node_reclaimable(memcg, nid, false))
			node_clear(nid, memcg->scan_nodes);
	}

	atomic_set(&memcg->numainfo_events, 0);
	atomic_set(&memcg->numainfo_updating, 0);
}

/*
 * Selecting a node where we start reclaim from. Because what we need is just
 * reducing usage counter, start from anywhere is O,K. Considering
 * memory reclaim from current node, there are pros. and cons.
 *
 * Freeing memory from current node means freeing memory from a node which
 * we'll use or we've used. So, it may make LRU bad. And if several threads
 * hit limits, it will see a contention on a node. But freeing from remote
 * node means more costs for memory reclaim because of memory latency.
 *
 * Now, we use round-robin. Better algorithm is welcomed.
 */
int mem_cgroup_select_victim_node(struct mem_cgroup *memcg)
{
	int node;

	mem_cgroup_may_update_nodemask(memcg);
	node = memcg->last_scanned_node;

	node = next_node(node, memcg->scan_nodes);
	if (node == MAX_NUMNODES)
		node = first_node(memcg->scan_nodes);
	/*
	 * We call this when we hit limit, not when pages are added to LRU.
	 * No LRU may hold pages because all pages are UNEVICTABLE or
	 * memcg is too small and all pages are not on LRU. In that case,
	 * we use curret node.
	 */
	if (unlikely(node == MAX_NUMNODES))
		node = numa_node_id();

	memcg->last_scanned_node = node;
	return node;
}

/*
 * Check all nodes whether it contains reclaimable pages or not.
 * For quick scan, we make use of scan_nodes. This will allow us to skip
 * unused nodes. But scan_nodes is lazily updated and may not cotain
 * enough new information. We need to do double check.
 */
static bool mem_cgroup_reclaimable(struct mem_cgroup *memcg, bool noswap)
{
	int nid;

	/*
	 * quick check...making use of scan_node.
	 * We can skip unused nodes.
	 */
	if (!nodes_empty(memcg->scan_nodes)) {
		for (nid = first_node(memcg->scan_nodes);
		     nid < MAX_NUMNODES;
		     nid = next_node(nid, memcg->scan_nodes)) {

			if (test_mem_cgroup_node_reclaimable(memcg, nid, noswap))
				return true;
		}
	}
	/*
	 * Check rest of nodes.
	 */
	for_each_node_state(nid, N_MEMORY) {
		if (node_isset(nid, memcg->scan_nodes))
			continue;
		if (test_mem_cgroup_node_reclaimable(memcg, nid, noswap))
			return true;
	}
	return false;
}

#else
int mem_cgroup_select_victim_node(struct mem_cgroup *memcg)
{
	return 0;
}

static bool mem_cgroup_reclaimable(struct mem_cgroup *memcg, bool noswap)
{
	return test_mem_cgroup_node_reclaimable(memcg, 0, noswap);
}
#endif

static int mem_cgroup_soft_reclaim(struct mem_cgroup *root_memcg,
				   struct zone *zone,
				   gfp_t gfp_mask,
				   unsigned long *total_scanned)
{
	struct mem_cgroup *victim = NULL;
	int total = 0;
	int loop = 0;
	unsigned long excess;
	unsigned long nr_scanned;
	struct mem_cgroup_reclaim_cookie reclaim = {
		.zone = zone,
		.priority = 0,
	};

	excess = soft_limit_excess(root_memcg);

	while (1) {
		victim = mem_cgroup_iter(root_memcg, victim, &reclaim);
		if (!victim) {
			loop++;
			if (loop >= 2) {
				/*
				 * If we have not been able to reclaim
				 * anything, it might because there are
				 * no reclaimable pages under this hierarchy
				 */
				if (!total)
					break;
				/*
				 * We want to do more targeted reclaim.
				 * excess >> 2 is not to excessive so as to
				 * reclaim too much, nor too less that we keep
				 * coming back to reclaim from this cgroup
				 */
				if (total >= (excess >> 2) ||
					(loop > MEM_CGROUP_MAX_RECLAIM_LOOPS))
					break;
			}
			continue;
		}
		if (!mem_cgroup_reclaimable(victim, false))
			continue;
		total += mem_cgroup_shrink_node_zone(victim, gfp_mask, false,
						     zone, &nr_scanned);
		*total_scanned += nr_scanned;
		if (!soft_limit_excess(root_memcg))
			break;
	}
	mem_cgroup_iter_break(root_memcg, victim);
	return total;
}

static DEFINE_SPINLOCK(memcg_oom_lock);

/*
 * Check OOM-Killer is already running under our hierarchy.
 * If someone is running, return false.
 */
static bool mem_cgroup_oom_trylock(struct mem_cgroup *memcg)
{
	struct mem_cgroup *iter, *failed = NULL;

	spin_lock(&memcg_oom_lock);

	for_each_mem_cgroup_tree(iter, memcg) {
		if (iter->oom_lock) {
			/*
			 * this subtree of our hierarchy is already locked
			 * so we cannot give a lock.
			 */
			failed = iter;
			mem_cgroup_iter_break(memcg, iter);
			break;
		} else
			iter->oom_lock = true;
	}

	if (failed) {
		/*
		 * OK, we failed to lock the whole subtree so we have
		 * to clean up what we set up to the failing subtree
		 */
		for_each_mem_cgroup_tree(iter, memcg) {
			if (iter == failed) {
				mem_cgroup_iter_break(memcg, iter);
				break;
			}
			iter->oom_lock = false;
		}
	}

	spin_unlock(&memcg_oom_lock);

	return !failed;
}

static void mem_cgroup_oom_unlock(struct mem_cgroup *memcg)
{
	struct mem_cgroup *iter;

	spin_lock(&memcg_oom_lock);
	for_each_mem_cgroup_tree(iter, memcg)
		iter->oom_lock = false;
	spin_unlock(&memcg_oom_lock);
}

static void mem_cgroup_mark_under_oom(struct mem_cgroup *memcg)
{
	struct mem_cgroup *iter;

	for_each_mem_cgroup_tree(iter, memcg)
		atomic_inc(&iter->under_oom);
}

static void mem_cgroup_unmark_under_oom(struct mem_cgroup *memcg)
{
	struct mem_cgroup *iter;

	/*
	 * When a new child is created while the hierarchy is under oom,
	 * mem_cgroup_oom_lock() may not be called. We have to use
	 * atomic_add_unless() here.
	 */
	for_each_mem_cgroup_tree(iter, memcg)
		atomic_add_unless(&iter->under_oom, -1, 0);
}

static DECLARE_WAIT_QUEUE_HEAD(memcg_oom_waitq);

struct oom_wait_info {
	struct mem_cgroup *memcg;
	wait_queue_t	wait;
};

static int memcg_oom_wake_function(wait_queue_t *wait,
	unsigned mode, int sync, void *arg)
{
	struct mem_cgroup *wake_memcg = (struct mem_cgroup *)arg;
	struct mem_cgroup *oom_wait_memcg;
	struct oom_wait_info *oom_wait_info;

	oom_wait_info = container_of(wait, struct oom_wait_info, wait);
	oom_wait_memcg = oom_wait_info->memcg;

	/*
	 * Both of oom_wait_info->memcg and wake_memcg are stable under us.
	 * Then we can use css_is_ancestor without taking care of RCU.
	 */
	if (!mem_cgroup_same_or_subtree(oom_wait_memcg, wake_memcg)
		&& !mem_cgroup_same_or_subtree(wake_memcg, oom_wait_memcg))
		return 0;
	return autoremove_wake_function(wait, mode, sync, arg);
}

static void memcg_wakeup_oom(struct mem_cgroup *memcg)
{
	atomic_inc(&memcg->oom_wakeups);
	/* for filtering, pass "memcg" as argument. */
	__wake_up(&memcg_oom_waitq, TASK_NORMAL, 0, memcg);
}

static void memcg_oom_recover(struct mem_cgroup *memcg)
{
	if (memcg && atomic_read(&memcg->under_oom))
		memcg_wakeup_oom(memcg);
}

static void mem_cgroup_oom(struct mem_cgroup *memcg, gfp_t mask, int order)
{
	if (!current->memcg_oom.may_oom)
		return;
	/*
	 * We are in the middle of the charge context here, so we
	 * don't want to block when potentially sitting on a callstack
	 * that holds all kinds of filesystem and mm locks.
	 *
	 * Also, the caller may handle a failed allocation gracefully
	 * (like optional page cache readahead) and so an OOM killer
	 * invocation might not even be necessary.
	 *
	 * That's why we don't do anything here except remember the
	 * OOM context and then deal with it at the end of the page
	 * fault when the stack is unwound, the locks are released,
	 * and when we know whether the fault was overall successful.
	 */
	css_get(&memcg->css);
	current->memcg_oom.memcg = memcg;
	current->memcg_oom.gfp_mask = mask;
	current->memcg_oom.order = order;
}

/**
 * mem_cgroup_oom_synchronize - complete memcg OOM handling
 * @handle: actually kill/wait or just clean up the OOM state
 *
 * This has to be called at the end of a page fault if the memcg OOM
 * handler was enabled.
 *
 * Memcg supports userspace OOM handling where failed allocations must
 * sleep on a waitqueue until the userspace task resolves the
 * situation.  Sleeping directly in the charge context with all kinds
 * of locks held is not a good idea, instead we remember an OOM state
 * in the task and mem_cgroup_oom_synchronize() has to be called at
 * the end of the page fault to complete the OOM handling.
 *
 * Returns %true if an ongoing memcg OOM situation was detected and
 * completed, %false otherwise.
 */
bool mem_cgroup_oom_synchronize(bool handle)
{
	struct mem_cgroup *memcg = current->memcg_oom.memcg;
	struct oom_wait_info owait;
	bool locked;

	/* OOM is global, do not handle */
	if (!memcg)
		return false;

	if (!handle)
		goto cleanup;

	owait.memcg = memcg;
	owait.wait.flags = 0;
	owait.wait.func = memcg_oom_wake_function;
	owait.wait.private = current;
	INIT_LIST_HEAD(&owait.wait.task_list);

	prepare_to_wait(&memcg_oom_waitq, &owait.wait, TASK_KILLABLE);
	mem_cgroup_mark_under_oom(memcg);

	locked = mem_cgroup_oom_trylock(memcg);

	if (locked)
		mem_cgroup_oom_notify(memcg);

	if (locked && !memcg->oom_kill_disable) {
		mem_cgroup_unmark_under_oom(memcg);
		finish_wait(&memcg_oom_waitq, &owait.wait);
		mem_cgroup_out_of_memory(memcg, current->memcg_oom.gfp_mask,
					 current->memcg_oom.order);
	} else {
		schedule();
		mem_cgroup_unmark_under_oom(memcg);
		finish_wait(&memcg_oom_waitq, &owait.wait);
	}

	if (locked) {
		mem_cgroup_oom_unlock(memcg);
		/*
		 * There is no guarantee that an OOM-lock contender
		 * sees the wakeups triggered by the OOM kill
		 * uncharges.  Wake any sleepers explicitely.
		 */
		memcg_oom_recover(memcg);
	}
cleanup:
	current->memcg_oom.memcg = NULL;
	css_put(&memcg->css);
	return true;
}

/*
 * Currently used to update mapped file statistics, but the routine can be
 * generalized to update other statistics as well.
 *
 * Notes: Race condition
 *
 * We usually use page_cgroup_lock() for accessing page_cgroup member but
 * it tends to be costly. But considering some conditions, we doesn't need
 * to do so _always_.
 *
 * Considering "charge", lock_page_cgroup() is not required because all
 * file-stat operations happen after a page is attached to radix-tree. There
 * are no race with "charge".
 *
 * Considering "uncharge", we know that memcg doesn't clear pc->mem_cgroup
 * at "uncharge" intentionally. So, we always see valid pc->mem_cgroup even
 * if there are race with "uncharge". Statistics itself is properly handled
 * by flags.
 *
 * Considering "move", this is an only case we see a race. To make the race
 * small, we check mm->moving_account and detect there are possibility of race
 * If there is, we take a lock.
 */

void __mem_cgroup_begin_update_page_stat(struct page *page,
				bool *locked, unsigned long *flags)
{
	struct mem_cgroup *memcg;
	struct page_cgroup *pc;

	pc = lookup_page_cgroup(page);
again:
	memcg = pc->mem_cgroup;
	if (unlikely(!memcg || !PageCgroupUsed(pc)))
		return;
	/*
	 * If this memory cgroup is not under account moving, we don't
	 * need to take move_lock_mem_cgroup(). Because we already hold
	 * rcu_read_lock(), any calls to move_account will be delayed until
	 * rcu_read_unlock() if mem_cgroup_stolen() == true.
	 */
	if (!mem_cgroup_stolen(memcg))
		return;

	move_lock_mem_cgroup(memcg, flags);
	if (memcg != pc->mem_cgroup || !PageCgroupUsed(pc)) {
		move_unlock_mem_cgroup(memcg, flags);
		goto again;
	}
	*locked = true;
}

void __mem_cgroup_end_update_page_stat(struct page *page, unsigned long *flags)
{
	struct page_cgroup *pc = lookup_page_cgroup(page);

	/*
	 * It's guaranteed that pc->mem_cgroup never changes while
	 * lock is held because a routine modifies pc->mem_cgroup
	 * should take move_lock_mem_cgroup().
	 */
	move_unlock_mem_cgroup(pc->mem_cgroup, flags);
}

void mem_cgroup_update_page_stat(struct page *page,
				 enum mem_cgroup_page_stat_item idx, int val)
{
	struct mem_cgroup *memcg;
	struct page_cgroup *pc = lookup_page_cgroup(page);
	unsigned long uninitialized_var(flags);

	if (mem_cgroup_disabled())
		return;

	memcg = pc->mem_cgroup;
	if (unlikely(!memcg || !PageCgroupUsed(pc)))
		return;

	switch (idx) {
	case MEMCG_NR_FILE_MAPPED:
		idx = MEM_CGROUP_STAT_FILE_MAPPED;
		break;
	default:
		BUG();
	}

	this_cpu_add(memcg->stat->count[idx], val);
}

/*
 * size of first charge trial. "32" comes from vmscan.c's magic value.
 * TODO: maybe necessary to use big numbers in big irons.
 */
#define CHARGE_BATCH	32U
struct memcg_stock_pcp {
	struct mem_cgroup *cached; /* this never be root cgroup */
	unsigned int nr_pages;
	struct work_struct work;
	unsigned long flags;
#define FLUSHING_CACHED_CHARGE	0
};
static DEFINE_PER_CPU(struct memcg_stock_pcp, memcg_stock);
static DEFINE_MUTEX(percpu_charge_mutex);

/**
 * consume_stock: Try to consume stocked charge on this cpu.
 * @memcg: memcg to consume from.
 * @nr_pages: how many pages to charge.
 *
 * The charges will only happen if @memcg matches the current cpu's memcg
 * stock, and at least @nr_pages are available in that stock.  Failure to
 * service an allocation will refill the stock.
 *
 * returns true if successful, false otherwise.
 */
static bool consume_stock(struct mem_cgroup *memcg, unsigned int nr_pages)
{
	struct memcg_stock_pcp *stock;
	bool ret = false;

	if (nr_pages > CHARGE_BATCH)
		return ret;

	stock = &get_cpu_var(memcg_stock);
	if (memcg == stock->cached && stock->nr_pages >= nr_pages) {
		stock->nr_pages -= nr_pages;
		ret = true;
	}
	put_cpu_var(memcg_stock);
	return ret;
}

/*
 * Returns stocks cached in percpu and reset cached information.
 */
static void drain_stock(struct memcg_stock_pcp *stock)
{
	struct mem_cgroup *old = stock->cached;

	if (stock->nr_pages) {
		page_counter_uncharge(&old->memory, stock->nr_pages);
		if (do_swap_account)
			page_counter_uncharge(&old->memsw, stock->nr_pages);
		stock->nr_pages = 0;
	}
	stock->cached = NULL;
}

/*
 * This must be called under preempt disabled or must be called by
 * a thread which is pinned to local cpu.
 */
static void drain_local_stock(struct work_struct *dummy)
{
	struct memcg_stock_pcp *stock = this_cpu_ptr(&memcg_stock);
	drain_stock(stock);
	clear_bit(FLUSHING_CACHED_CHARGE, &stock->flags);
}

static void __init memcg_stock_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct memcg_stock_pcp *stock =
					&per_cpu(memcg_stock, cpu);
		INIT_WORK(&stock->work, drain_local_stock);
	}
}

/*
 * Cache charges(val) to local per_cpu area.
 * This will be consumed by consume_stock() function, later.
 */
static void refill_stock(struct mem_cgroup *memcg, unsigned int nr_pages)
{
	struct memcg_stock_pcp *stock = &get_cpu_var(memcg_stock);

	if (stock->cached != memcg) { /* reset if necessary */
		drain_stock(stock);
		stock->cached = memcg;
	}
	stock->nr_pages += nr_pages;
	put_cpu_var(memcg_stock);
}

/*
 * Drains all per-CPU charge caches for given root_memcg resp. subtree
 * of the hierarchy under it. sync flag says whether we should block
 * until the work is done.
 */
static void drain_all_stock(struct mem_cgroup *root_memcg, bool sync)
{
	int cpu, curcpu;

	/* Notify other cpus that system-wide "drain" is running */
	get_online_cpus();
	curcpu = get_cpu();
	for_each_online_cpu(cpu) {
		struct memcg_stock_pcp *stock = &per_cpu(memcg_stock, cpu);
		struct mem_cgroup *memcg;
		bool flush = false;

		rcu_read_lock();
		memcg = stock->cached;
		if (memcg && stock->nr_pages &&
		    __mem_cgroup_same_or_subtree(root_memcg, memcg))
			flush = true;
		rcu_read_unlock();

		if (flush &&
		    !test_and_set_bit(FLUSHING_CACHED_CHARGE, &stock->flags)) {
			if (cpu == curcpu)
				drain_local_stock(&stock->work);
			else
				schedule_work_on(cpu, &stock->work);
		}
	}
	put_cpu();

	if (!sync)
		goto out;

	for_each_online_cpu(cpu) {
		struct memcg_stock_pcp *stock = &per_cpu(memcg_stock, cpu);
		if (test_bit(FLUSHING_CACHED_CHARGE, &stock->flags))
			flush_work(&stock->work);
	}
out:
 	put_online_cpus();
}

/*
 * Tries to drain stocked charges in other cpus. This function is asynchronous
 * and just put a work per cpu for draining localy on each cpu. Caller can
 * expects some charges will be back later but cannot wait for it.
 */
static void drain_all_stock_async(struct mem_cgroup *root_memcg)
{
	/*
	 * If someone calls draining, avoid adding more kworker runs.
	 */
	if (!mutex_trylock(&percpu_charge_mutex))
		return;
	drain_all_stock(root_memcg, false);
	mutex_unlock(&percpu_charge_mutex);
}

/* This is a synchronous drain interface. */
static void drain_all_stock_sync(struct mem_cgroup *root_memcg)
{
	/* called when force_empty is called */
	mutex_lock(&percpu_charge_mutex);
	drain_all_stock(root_memcg, true);
	mutex_unlock(&percpu_charge_mutex);
}

static int memcg_cpu_hotplug_callback(struct notifier_block *nb,
					unsigned long action,
					void *hcpu)
{
	int cpu = (unsigned long)hcpu;
	struct memcg_stock_pcp *stock;

	if (action == CPU_ONLINE)
		return NOTIFY_OK;

	if (action != CPU_DEAD && action != CPU_DEAD_FROZEN)
		return NOTIFY_OK;

	stock = &per_cpu(memcg_stock, cpu);
	drain_stock(stock);
	return NOTIFY_OK;
}


/* See __mem_cgroup_try_charge() for details */
enum {
	CHARGE_OK,		/* success */
	CHARGE_RETRY,		/* need to retry but retry is not bad */
	CHARGE_NOMEM,		/* we can't do more. return -ENOMEM */
	CHARGE_WOULDBLOCK,	/* GFP_WAIT wasn't set and no enough res. */
};

static int mem_cgroup_do_charge(struct mem_cgroup *memcg, gfp_t gfp_mask,
				unsigned int nr_pages, unsigned int min_pages,
				bool invoke_oom)
{
	struct mem_cgroup *mem_over_limit;
	struct page_counter *counter;
	unsigned long flags = 0;
	int ret = -ENOMEM;

	if (likely(page_counter_try_charge(&memcg->memory, nr_pages,
					   &counter))) {
		if (!do_swap_account)
			return CHARGE_OK;
		if (likely(page_counter_try_charge(&memcg->memsw, nr_pages,
						   &counter)))
			return CHARGE_OK;

		page_counter_uncharge(&memcg->memory, nr_pages);
		mem_over_limit = mem_cgroup_from_counter(counter, memsw);
		flags |= MEM_CGROUP_RECLAIM_NOSWAP;
	} else if (gfp_mask & __GFP_NOFAIL) {
		/*
		 * RHEL7: This __GFP_NOFAIL case is loosely based on the "force"
		 * case, taken from the 4th hunk to try_charge() in upstream
		 * commit 10d53c748bc9 ("memcg: ratify and consolidate
		 * over-charge handling").
		 *
		 * We need to allow memory usage go over the limit, by force
		 * charging allocations that carry the __GFP_NOFAIL flag.
		 */
		page_counter_charge(&memcg->memory, nr_pages);

		return CHARGE_OK;
	} else
		mem_over_limit = mem_cgroup_from_counter(counter, memory);
	/*
	 * Never reclaim on behalf of optional batching, retry with a
	 * single page instead.
	 */
	if (nr_pages > min_pages)
		return CHARGE_RETRY;

	if (!(gfp_mask & __GFP_WAIT)) {
		mem_cgroup_inc_failcnt(mem_over_limit, gfp_mask, nr_pages);
		return CHARGE_WOULDBLOCK;
	}

	if (gfp_mask & __GFP_NORETRY) {
		mem_cgroup_inc_failcnt(mem_over_limit, gfp_mask, nr_pages);
		return CHARGE_NOMEM;
	}

	ret = mem_cgroup_reclaim(mem_over_limit, gfp_mask, flags);
	if (mem_cgroup_margin(mem_over_limit) >= nr_pages)
		return CHARGE_RETRY;
	/*
	 * Even though the limit is exceeded at this point, reclaim
	 * may have been able to free some pages.  Retry the charge
	 * before killing the task.
	 *
	 * Only for regular pages, though: huge pages are rather
	 * unlikely to succeed so close to the limit, and we fall back
	 * to regular pages anyway in case of failure.
	 */
	if (nr_pages <= (1 << PAGE_ALLOC_COSTLY_ORDER) && ret)
		return CHARGE_RETRY;

	/*
	 * At task move, charge accounts can be doubly counted. So, it's
	 * better to wait until the end of task_move if something is going on.
	 */
	if (mem_cgroup_wait_acct_move(mem_over_limit))
		return CHARGE_RETRY;

	if (invoke_oom) {
		mem_cgroup_inc_failcnt(mem_over_limit, gfp_mask, nr_pages);
		mem_cgroup_oom(mem_over_limit, gfp_mask,
			       get_order(nr_pages * PAGE_SIZE));
	}

	return CHARGE_NOMEM;
}

/*
 * __mem_cgroup_try_charge() does
 * 1. detect memcg to be charged against from passed *mm and *ptr,
 * 2. update page_counter
 * 3. call memory reclaim if necessary.
 *
 * In some special case, if the task is fatal, fatal_signal_pending() or
 * has TIF_MEMDIE, this function returns -EINTR while writing root_mem_cgroup
 * to *ptr. There are two reasons for this. 1: fatal threads should quit as soon
 * as possible without any hazards. 2: all pages should have a valid
 * pc->mem_cgroup. If mm is NULL and the caller doesn't pass a valid memcg
 * pointer, that is treated as a charge to root_mem_cgroup.
 *
 * So __mem_cgroup_try_charge() will return
 *  0       ...  on success, filling *ptr with a valid memcg pointer.
 *  -ENOMEM ...  charge failure because of resource limits.
 *  -EINTR  ...  if thread is fatal. *ptr is filled with root_mem_cgroup.
 *
 * Unlike the exported interface, an "oom" parameter is added. if oom==true,
 * the oom-killer can be invoked.
 */
static int __mem_cgroup_try_charge(struct mm_struct *mm,
				   gfp_t gfp_mask,
				   unsigned int nr_pages,
				   struct mem_cgroup **ptr,
				   bool oom)
{
	unsigned int batch = max(CHARGE_BATCH, nr_pages);
	int nr_oom_retries = MEM_CGROUP_RECLAIM_RETRIES;
	struct mem_cgroup *memcg = NULL, *iter;
	int ret;

	/*
	 * Unlike gloval-vm's OOM-kill, we're not in memory shortage
	 * in system level. So, allow to go ahead dying process in addition to
	 * MEMDIE process.
	 */
	if (unlikely(test_thread_flag(TIF_MEMDIE)
		     || fatal_signal_pending(current)))
		goto bypass;

	/*
	 * Prevent unbounded recursion when reclaim operations need to
	 * allocate memory. This might exceed the limits temporarily,
	 * but we prefer facilitating memory reclaim and getting back
	 * under the limit over triggering OOM kills in these cases.
	 */
	if (unlikely(current->flags & PF_MEMALLOC))
		goto bypass;

	if (unlikely(task_in_memcg_oom(current)))
		goto nomem;

	if (gfp_mask & __GFP_NOFAIL)
		oom = false;

	/*
	 * We always charge the cgroup the mm_struct belongs to.
	 * The mm_struct's mem_cgroup changes on task migration if the
	 * thread group leader migrates. It's possible that mm is not
	 * set, if so charge the root memcg (happens for pagecache usage).
	 */
	if (!*ptr && !mm)
		*ptr = root_mem_cgroup;
again:
	if (*ptr) { /* css should be a valid one */
		memcg = *ptr;
		if (mem_cgroup_is_root(memcg))
			goto done;
		if (consume_stock(memcg, nr_pages))
			goto done;
		css_get(&memcg->css);
	} else {
		struct task_struct *p;

		rcu_read_lock();
		p = rcu_dereference(mm->owner);
		/*
		 * Because we don't have task_lock(), "p" can exit.
		 * In that case, "memcg" can point to root or p can be NULL with
		 * race with swapoff. Then, we have small risk of mis-accouning.
		 * But such kind of mis-account by race always happens because
		 * we don't have cgroup_mutex(). It's overkill and we allo that
		 * small race, here.
		 * (*) swapoff at el will charge against mm-struct not against
		 * task-struct. So, mm->owner can be NULL.
		 */
		memcg = mem_cgroup_from_task(p);
		if (!memcg)
			memcg = root_mem_cgroup;
		if (mem_cgroup_is_root(memcg)) {
			rcu_read_unlock();
			goto done;
		}
		if (consume_stock(memcg, nr_pages)) {
			/*
			 * It seems dagerous to access memcg without css_get().
			 * But considering how consume_stok works, it's not
			 * necessary. If consume_stock success, some charges
			 * from this memcg are cached on this cpu. So, we
			 * don't need to call css_get()/css_tryget() before
			 * calling consume_stock().
			 */
			rcu_read_unlock();
			goto done;
		}
		/* after here, we may be blocked. we need to get refcnt */
		if (!css_tryget(&memcg->css)) {
			rcu_read_unlock();
			goto again;
		}
		rcu_read_unlock();
	}

	do {
		bool invoke_oom = oom && !nr_oom_retries;

		/* If killed, bypass charge */
		if (fatal_signal_pending(current)) {
			css_put(&memcg->css);
			goto bypass;
		}

		ret = mem_cgroup_do_charge(memcg, gfp_mask, batch,
					   nr_pages, invoke_oom);
		switch (ret) {
		case CHARGE_OK:
			break;
		case CHARGE_RETRY: /* not in OOM situation but retry */
			batch = nr_pages;
			css_put(&memcg->css);
			memcg = NULL;
			goto again;
		case CHARGE_WOULDBLOCK: /* !__GFP_WAIT */
			css_put(&memcg->css);
			goto nomem;
		case CHARGE_NOMEM: /* OOM routine works */
			if (!oom || invoke_oom) {
				css_put(&memcg->css);
				goto nomem;
			}
			nr_oom_retries--;
			break;
		}
	} while (ret != CHARGE_OK);

	/*
	 * Cancel charge in case this cgroup was destroyed while we were here,
	 * otherwise we can get a pending user memory charge to an offline
	 * cgroup, which might result in use-after-free after the cgroup gets
	 * released (see also mem_cgroup_css_offline()).
	 *
	 * Note, no need to issue an explicit barrier here, because a
	 * successful charge implies full memory barrier.
	 */
	if (unlikely(memcg->is_offline)) {
		res_counter_uncharge(&memcg->res, batch * PAGE_SIZE);
		if (do_swap_account)
			res_counter_uncharge(&memcg->memsw, batch * PAGE_SIZE);
		css_put(&memcg->css);
		goto bypass;
	}

	if (batch > nr_pages)
		refill_stock(memcg, batch - nr_pages);

	/*
	 * If the hierarchy is above the normal consumption range,
	 * make the charging task trim their excess contribution.
	 */
	iter = memcg;
	do {
		if (!(gfp_mask & __GFP_WAIT))
			break;
		if (res_counter_read_u64(&iter->res, RES_USAGE) <= iter->high)
			continue;
		try_to_free_mem_cgroup_pages(iter, nr_pages, gfp_mask, false);
	} while ((iter = parent_mem_cgroup(iter)));

	css_put(&memcg->css);
done:
	*ptr = memcg;
	return 0;
nomem:
	if (!(gfp_mask & __GFP_NOFAIL)) {
		*ptr = NULL;
		return -ENOMEM;
	}
bypass:
	*ptr = root_mem_cgroup;
	return -EINTR;
}

/*
 * Somemtimes we have to undo a charge we got by try_charge().
 * This function is for that and do uncharge, put css's refcnt.
 * gotten by try_charge().
 */
static void __mem_cgroup_cancel_charge(struct mem_cgroup *memcg,
				       unsigned int nr_pages)
{
	if (!mem_cgroup_is_root(memcg)) {
		page_counter_uncharge(&memcg->memory, nr_pages);
		if (do_swap_account)
			page_counter_uncharge(&memcg->memsw, nr_pages);
	}
}

struct mem_cgroup *mem_cgroup_from_id(unsigned short id);
/*
 * A helper function to get mem_cgroup from ID. must be called under
 * rcu_read_lock().  The caller is responsible for calling css_tryget if
 * the mem_cgroup is used for charging. (dropping refcnt from swap can be
 * called against removed memcg.)
 */
static struct mem_cgroup *mem_cgroup_lookup(unsigned short id)
{
	/* ID 0 is unused ID */
	if (!id)
		return NULL;
	return mem_cgroup_from_id(id);
}

struct mem_cgroup *try_get_mem_cgroup_from_page(struct page *page)
{
	struct mem_cgroup *memcg = NULL;
	struct page_cgroup *pc;
	unsigned short id;
	swp_entry_t ent;

	VM_BUG_ON_PAGE(!PageLocked(page), page);

	pc = lookup_page_cgroup(page);
	lock_page_cgroup(pc);
	if (PageCgroupUsed(pc)) {
		memcg = pc->mem_cgroup;
		if (memcg && !css_tryget(&memcg->css))
			memcg = NULL;
	} else if (PageSwapCache(page)) {
		ent.val = page_private(page);
		id = lookup_swap_cgroup_id(ent);
		rcu_read_lock();
		memcg = mem_cgroup_lookup(id);
		if (memcg && !css_tryget(&memcg->css))
			memcg = NULL;
		rcu_read_unlock();
	}
	unlock_page_cgroup(pc);
	return memcg;
}

static void __mem_cgroup_commit_charge(struct mem_cgroup *memcg,
				       struct page *page,
				       unsigned int nr_pages,
				       enum charge_type ctype,
				       bool lrucare)
{
	struct page_cgroup *pc = lookup_page_cgroup(page);
	struct zone *uninitialized_var(zone);
	struct lruvec *lruvec;
	bool was_on_lru = false;
	bool anon;

	lock_page_cgroup(pc);
	VM_BUG_ON_PAGE(PageCgroupUsed(pc), page);
	/*
	 * we don't need page_cgroup_lock about tail pages, becase they are not
	 * accessed by any other context at this point.
	 */

	/*
	 * In some cases, SwapCache and FUSE(splice_buf->radixtree), the page
	 * may already be on some other mem_cgroup's LRU.  Take care of it.
	 */
	if (lrucare) {
		zone = page_zone(page);
		spin_lock_irq(&zone->lru_lock);
		if (PageLRU(page)) {
			lruvec = mem_cgroup_zone_lruvec(zone, pc->mem_cgroup);
			ClearPageLRU(page);
			del_page_from_lru_list(page, lruvec, page_lru(page));
			was_on_lru = true;
		}
	}

	pc->mem_cgroup = memcg;
	/*
	 * We access a page_cgroup asynchronously without lock_page_cgroup().
	 * Especially when a page_cgroup is taken from a page, pc->mem_cgroup
	 * is accessed after testing USED bit. To make pc->mem_cgroup visible
	 * before USED bit, we need memory barrier here.
	 * See mem_cgroup_add_lru_list(), etc.
 	 */
	smp_wmb();
	SetPageCgroupUsed(pc);

	if (lrucare) {
		if (was_on_lru) {
			lruvec = mem_cgroup_zone_lruvec(zone, pc->mem_cgroup);
			VM_BUG_ON_PAGE(PageLRU(page), page);
			SetPageLRU(page);
			add_page_to_lru_list(page, lruvec, page_lru(page));
		}
		spin_unlock_irq(&zone->lru_lock);
	}

	if (ctype == MEM_CGROUP_CHARGE_TYPE_ANON)
		anon = true;
	else
		anon = false;

	mem_cgroup_charge_statistics(memcg, page, anon, nr_pages);
	unlock_page_cgroup(pc);

	/*
	 * "charge_statistics" updated event counter. Then, check it.
	 * Insert ancestor (and ancestor's ancestors), to softlimit RB-tree.
	 * if they exceeds softlimit.
	 */
	memcg_check_events(memcg, page);
}

#ifdef CONFIG_MEMCG_KMEM
#ifdef CONFIG_SLABINFO
static int mem_cgroup_slabinfo_read(struct cgroup *cont, struct cftype *cft,
					struct seq_file *m)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	loff_t pos = 0;
	void *p;

	for (p = slab_start(m, &pos); p; p = slab_next(m, p, &pos))
		memcg_slab_show(memcg, m, p);
	slab_stop(m, p);

	return 0;
}
#endif

int memcg_charge_kmem(struct mem_cgroup *memcg, gfp_t gfp,
			     unsigned long nr_pages)
{
	struct page_counter *counter;
	struct mem_cgroup *_memcg;
	int ret = 0;
	bool may_oom;

	/*
	 * Conditions under which we can wait for the oom_killer. Those are
	 * the same conditions tested by the core page allocator
	 */
	may_oom = (gfp & __GFP_FS) && !(gfp & __GFP_NORETRY);

	_memcg = memcg;
	ret = __mem_cgroup_try_charge(NULL, gfp | __GFP_NOFAIL,
				      nr_pages, &_memcg, may_oom);

	if (ret == -EINTR)  {
		/*
		 * __mem_cgroup_try_charge() chosed to bypass to root due to
		 * OOM kill or fatal signal.  Since our only options are to
		 * either fail the allocation or charge it to this cgroup, do
		 * it as a temporary condition. But we can't fail. From a
		 * kmem/slab perspective, the cache has already been selected,
		 * by mem_cgroup_kmem_get_cache(), so it is too late to change
		 * our minds.
		 *
		 * This condition will only trigger if the task entered
		 * memcg_charge_kmem in a sane state, but was OOM-killed during
		 * __mem_cgroup_try_charge() above. Tasks that were already
		 * dying when the allocation triggers should have been already
		 * directed to the root cgroup in memcontrol.h
		 */
		page_counter_charge(&memcg->memory, nr_pages);
		if (do_swap_account)
			page_counter_charge(&memcg->memsw, nr_pages);
		ret = 0;
	}

	if (ret)
		return ret;

	/*
	 * When a cgroup is destroyed, all user memory pages get recharged to
	 * the parent cgroup. Recharging is done by mem_cgroup_reparent_charges
	 * which keeps looping until res <= kmem. This is supposed to guarantee
	 * that by the time cgroup gets released, no pages is charged to it.
	 *
	 * If kmem were charged before res or uncharged after, kmem might
	 * become greater than res for a short period of time even if there
	 * were still user memory pages charged to the cgroup. In this case
	 * mem_cgroup_reparent_charges would give up prematurely, and the
	 * cgroup could be released though there were still pages charged to
	 * it. Uncharge of such a page would trigger kernel panic.
	 *
	 * To prevent this from happening, kmem must be charged after res and
	 * uncharged before res.
	 */
	if (!page_counter_try_charge(&memcg->kmem, nr_pages, &counter)) {
		ret = -ENOMEM;
		page_counter_uncharge(&memcg->memory, nr_pages);
		if (do_swap_account)
			page_counter_uncharge(&memcg->memsw, nr_pages);
	}

	return ret;
}

void memcg_uncharge_kmem(struct mem_cgroup *memcg,
				unsigned long nr_pages)
{
	u64 kmem;

	kmem = page_counter_uncharge(&memcg->kmem, nr_pages);

	page_counter_uncharge(&memcg->memory, nr_pages);
	if (do_swap_account)
		page_counter_uncharge(&memcg->memsw, nr_pages);

	/* Not down to 0 */
	if (kmem)
		return;

	/*
	 * Releases a reference taken in memcg_deactivate_kmem in case
	 * this last uncharge is racing with the offlining code or it is
	 * outliving the memcg existence.
	 *
	 * The memory barrier imposed by test&clear is paired with the
	 * explicit one in memcg_kmem_mark_dead().
	 */
	if (memcg_kmem_test_and_clear_dead(memcg))
		css_put(&memcg->css);
}

/*
 * helper for acessing a memcg's index. It will be used as an index in the
 * child cache array in kmem_cache, and also to derive its name. This function
 * will return -1 when this is not a kmem-limited memcg.
 */
int memcg_cache_id(struct mem_cgroup *memcg)
{
	return memcg ? memcg->kmemcg_id : -1;
}

/*
 * This ends up being protected by the set_limit mutex, during normal
 * operation, because that is its main call site.
 *
 * But when we create a new cache, we can call this as well if its parent
 * is kmem-limited. That will have to hold set_limit_mutex as well.
 */
static int memcg_update_cache_sizes(struct mem_cgroup *memcg)
{
	int num, ret;

	num = ida_simple_get(&kmem_limited_groups,
				0, MEMCG_CACHES_MAX_SIZE, GFP_KERNEL);
	if (num < 0)
		return num;

	mutex_lock(&memcg_slab_mutex);
	ret = memcg_update_all_caches(num+1);
	mutex_unlock(&memcg_slab_mutex);
	if (ret) {
		ida_simple_remove(&kmem_limited_groups, num);
		return ret;
	}

	memcg->kmemcg_id = num;
	INIT_LIST_HEAD(&memcg->memcg_slab_caches);
	return 0;
}

static int memcg_alloc_cache_id(void)
{
	int id, size;
	int err;

	id = ida_simple_get(&memcg_cache_ida,
			    0, MEMCG_CACHES_MAX_SIZE, GFP_KERNEL);
	if (id < 0)
		return id;

	if (id < memcg_nr_cache_ids)
		return id;

	/*
	 * There's no space for the new id in memcg_caches arrays,
	 * so we have to grow them.
	 */
	down_write(&memcg_cache_ids_sem);

	size = 2 * (id + 1);
	if (size < MEMCG_CACHES_MIN_SIZE)
		size = MEMCG_CACHES_MIN_SIZE;
	else if (size > MEMCG_CACHES_MAX_SIZE)
		size = MEMCG_CACHES_MAX_SIZE;

	err = memcg_update_all_caches(size);
	if (!err)
		err = memcg_update_all_list_lrus(size);
	if (!err)
		memcg_nr_cache_ids = size;

	up_write(&memcg_cache_ids_sem);

	if (err) {
		ida_simple_remove(&memcg_cache_ida, id);
		return err;
	}
	return id;
}

static void memcg_free_cache_id(int id)
{
	ida_simple_remove(&memcg_cache_ida, id);
}

/*
 * During the creation a new cache, we need to disable our accounting mechanism
 * altogether. This is true even if we are not creating, but rather just
 * enqueing new caches to be created.
 *
 * This is because that process will trigger allocations; some visible, like
 * explicit kmallocs to auxiliary data structures, name strings and internal
 * cache structures; some well concealed, like INIT_WORK() that can allocate
 * objects during debug.
 *
 * If any allocation happens during memcg_kmem_get_cache, we will recurse back
 * to it. This may not be a bounded recursion: since the first cache creation
 * failed to complete (waiting on the allocation), we'll just try to create the
 * cache again, failing at the same point.
 *
 * memcg_kmem_get_cache is prepared to abort after seeing a positive count of
 * memcg_kmem_skip_account. So we enclose anything that might allocate memory
 * inside the following two functions.
 */
static inline void memcg_stop_kmem_account(void)
{
	VM_BUG_ON(!current->mm);
	current->memcg_kmem_skip_account++;
}

static inline void memcg_resume_kmem_account(void)
{
	VM_BUG_ON(!current->mm);
	current->memcg_kmem_skip_account--;
}

static DEFINE_MUTEX(memcg_limit_mutex);

struct memcg_kmem_cache_create_work {
	struct mem_cgroup *memcg;
	struct kmem_cache *cachep;
	struct work_struct work;
};

static void memcg_kmem_cache_create_func(struct work_struct *w)
{
	struct memcg_kmem_cache_create_work *cw =
		container_of(w, struct memcg_kmem_cache_create_work, work);
	struct mem_cgroup *memcg = cw->memcg;
	struct kmem_cache *cachep = cw->cachep;

	memcg_create_kmem_cache(memcg, cachep);

	css_put(&memcg->css);
	kfree(cw);
}

/*
 * Enqueue the creation of a per-memcg kmem_cache.
 */
static void __memcg_schedule_kmem_cache_create(struct mem_cgroup *memcg,
					       struct kmem_cache *cachep)
{
	struct memcg_kmem_cache_create_work *cw;

	cw = kmalloc(sizeof(*cw), GFP_NOWAIT);
	if (!cw)
		return;

	css_get(&memcg->css);

	cw->memcg = memcg;
	cw->cachep = cachep;
	INIT_WORK(&cw->work, memcg_kmem_cache_create_func);

	schedule_work(&cw->work);
}

static void memcg_schedule_kmem_cache_create(struct mem_cgroup *memcg,
					     struct kmem_cache *cachep)
{
	/*
	 * We need to stop accounting when we kmalloc, because if the
	 * corresponding kmalloc cache is not yet created, the first allocation
	 * in __memcg_schedule_kmem_cache_create will recurse.
	 *
	 * However, it is better to enclose the whole function. Depending on
	 * the debugging options enabled, INIT_WORK(), for instance, can
	 * trigger an allocation. This too, will make us recurse. Because at
	 * this point we can't allow ourselves back into memcg_kmem_get_cache,
	 * the safest choice is to do it like this, wrapping the whole function.
	 */
	memcg_stop_kmem_account();
	__memcg_schedule_kmem_cache_create(memcg, cachep);
	memcg_resume_kmem_account();
}

/*
 * Return the kmem_cache we're supposed to use for a slab allocation.
 * We try to use the current memcg's version of the cache.
 *
 * If the cache does not exist yet, if we are the first user of it,
 * we either create it immediately, if possible, or create it asynchronously
 * in a workqueue.
 * In the latter case, we will let the current allocation go through with
 * the original cache.
 *
 * Can't be called in interrupt context or from kernel threads.
 * This function needs to be called with rcu_read_lock() held.
 */
struct kmem_cache *__memcg_kmem_get_cache(struct kmem_cache *cachep,
					  gfp_t gfp)
{
	struct mem_cgroup *memcg;
	struct kmem_cache *memcg_cachep;

	VM_BUG_ON(!is_root_cache(cachep));

	if (cachep->flags & SLAB_ACCOUNT)
		gfp |= __GFP_ACCOUNT;

	if (!(gfp & __GFP_ACCOUNT))
		return cachep;

	if (!current->mm || current->memcg_kmem_skip_account)
		return cachep;

	memcg = try_get_mem_cgroup_from_mm(current->mm);
	if (unlikely(!memcg))
		return cachep;

	if (!memcg_kmem_is_active(memcg))
		goto out;

	memcg_cachep = cache_from_memcg_idx(cachep, memcg_cache_id(memcg));
	if (likely(memcg_cachep))
		return memcg_cachep;

	/*
	 * If we are in a safe context (can wait, and not in interrupt
	 * context), we could be be predictable and return right away.
	 * This would guarantee that the allocation being performed
	 * already belongs in the new cache.
	 *
	 * However, there are some clashes that can arrive from locking.
	 * For instance, because we acquire the slab_mutex while doing
	 * memcg_create_kmem_cache, this means no further allocation
	 * could happen with the slab_mutex held. So it's better to
	 * defer everything.
	 */
	memcg_schedule_kmem_cache_create(memcg, cachep);
out:
	css_put(&memcg->css);
	return cachep;
}
EXPORT_SYMBOL(__memcg_kmem_get_cache);

void __memcg_kmem_put_cache(struct kmem_cache *cachep)
{
	if (!is_root_cache(cachep))
		css_put(&cachep->memcg_params.memcg->css);
}

/*
 * We need to verify if the allocation against current->mm->owner's memcg is
 * possible for the given order. But the page is not allocated yet, so we'll
 * need a further commit step to do the final arrangements.
 *
 * It is possible for the task to switch cgroups in this mean time, so at
 * commit time, we can't rely on task conversion any longer.  We'll then use
 * the handle argument to return to the caller which cgroup we should commit
 * against. We could also return the memcg directly and avoid the pointer
 * passing, but a boolean return value gives better semantics considering
 * the compiled-out case as well.
 *
 * Returning true means the allocation is possible.
 */
bool
__memcg_kmem_newpage_charge(struct page *page, gfp_t gfp, int order)
{
	struct page_cgroup *pc;
	struct mem_cgroup *memcg;
	int ret;

	/*
	 * Disabling accounting is only relevant for some specific memcg
	 * internal allocations. Therefore we would initially not have such
	 * check here, since direct calls to the page allocator that are marked
	 * with GFP_KMEMCG only happen outside memcg core. We are mostly
	 * concerned with cache allocations, and by having this test at
	 * memcg_kmem_get_cache, we are already able to relay the allocation to
	 * the root cache and bypass the memcg cache altogether.
	 *
	 * There is one exception, though: the SLUB allocator does not create
	 * large order caches, but rather service large kmallocs directly from
	 * the page allocator. Therefore, the following sequence when backed by
	 * the SLUB allocator:
	 *
	 * 	memcg_stop_kmem_account();
	 * 	kmalloc(<large_number>)
	 * 	memcg_resume_kmem_account();
	 *
	 * would effectively ignore the fact that we should skip accounting,
	 * since it will drive us directly to this function without passing
	 * through the cache selector memcg_kmem_get_cache. Such large
	 * allocations are extremely rare but can happen, for instance, for the
	 * cache arrays. We bring this test here.
	 */
	if (!current->mm || current->memcg_kmem_skip_account)
		return true;

	memcg = try_get_mem_cgroup_from_mm(current->mm);

	/*
	 * very rare case described in mem_cgroup_from_task. Unfortunately there
	 * isn't much we can do without complicating this too much, and it would
	 * be gfp-dependent anyway. Just let it go
	 */
	if (unlikely(!memcg))
		return true;

	if (!memcg_kmem_is_active(memcg)) {
		css_put(&memcg->css);
		return true;
	}

	ret = memcg_charge_kmem(memcg, gfp, 1 << order);
	css_put(&memcg->css);

	if (ret)
		return false;

	pc = lookup_page_cgroup(page);
	lock_page_cgroup(pc);
	pc->mem_cgroup = memcg;
	SetPageCgroupUsed(pc);
	unlock_page_cgroup(pc);

	__SetPageKmemcg(page);

	return true;
}

void __memcg_kmem_uncharge_pages(struct page *page, int order)
{
	struct mem_cgroup *memcg = NULL;
	struct page_cgroup *pc;


	pc = lookup_page_cgroup(page);
	/*
	 * Fast unlocked return. Theoretically might have changed, have to
	 * check again after locking.
	 */
	if (!PageCgroupUsed(pc))
		return;

	lock_page_cgroup(pc);
	if (PageCgroupUsed(pc)) {
		memcg = pc->mem_cgroup;
		ClearPageCgroupUsed(pc);
	}
	unlock_page_cgroup(pc);

	/*
	 * We trust that only if there is a memcg associated with the page, it
	 * is a valid allocation
	 */
	if (!memcg)
		return;

	VM_BUG_ON_PAGE(mem_cgroup_is_root(memcg), page);
	memcg_uncharge_kmem(memcg, 1 << order);

	__ClearPageKmemcg(page);
}

struct mem_cgroup *__mem_cgroup_from_kmem(void *ptr)
{
	struct mem_cgroup *memcg = NULL;
	struct page_cgroup *pc;
	struct kmem_cache *cachep;
	struct page *page;

	page = virt_to_head_page(ptr);
	if (PageSlab(page)) {
		cachep = page->slab_cache;
		if (!is_root_cache(cachep))
			memcg = cachep->memcg_params.memcg;
	} else {
		pc = lookup_page_cgroup(page);
		if (PageCgroupUsed(pc))
			memcg = pc->mem_cgroup;
	}

	return memcg;
}
#endif /* CONFIG_MEMCG_KMEM */

#ifdef CONFIG_TRANSPARENT_HUGEPAGE

#define PCGF_NOCOPY_AT_SPLIT (1 << PCG_LOCK | 1 << PCG_MIGRATION)
/*
 * Because tail pages are not marked as "used", set it. We're under
 * zone->lru_lock, 'splitting on pmd' and compound_lock.
 * charge/uncharge will be never happen and move_account() is done under
 * compound_lock(), so we don't have to take care of races.
 */
void mem_cgroup_split_huge_fixup(struct page *head)
{
	struct page_cgroup *head_pc = lookup_page_cgroup(head);
	struct page_cgroup *pc;
	struct mem_cgroup *memcg;
	int i;

	if (mem_cgroup_disabled())
		return;

	memcg = head_pc->mem_cgroup;
	for (i = 1; i < HPAGE_PMD_NR; i++) {
		pc = head_pc + i;
		pc->mem_cgroup = memcg;
		smp_wmb();/* see __commit_charge() */
		pc->flags = head_pc->flags & ~PCGF_NOCOPY_AT_SPLIT;
	}
	__this_cpu_sub(memcg->stat->count[MEM_CGROUP_STAT_RSS_HUGE],
		       HPAGE_PMD_NR);
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

/**
 * mem_cgroup_move_account - move account of the page
 * @page: the page
 * @nr_pages: number of regular pages (>1 for huge pages)
 * @pc:	page_cgroup of the page.
 * @from: mem_cgroup which the page is moved from.
 * @to:	mem_cgroup which the page is moved to. @from != @to.
 *
 * The caller must confirm following.
 * - page is not on LRU (isolate_page() is useful.)
 * - compound_lock is held when nr_pages > 1
 *
 * This function doesn't do "charge" to new cgroup and doesn't do "uncharge"
 * from old cgroup.
 */
static int mem_cgroup_move_account(struct page *page,
				   unsigned int nr_pages,
				   struct page_cgroup *pc,
				   struct mem_cgroup *from,
				   struct mem_cgroup *to)
{
	unsigned long flags;
	int ret;
	bool anon = PageAnon(page);

	VM_BUG_ON(from == to);
	VM_BUG_ON_PAGE(PageLRU(page), page);
	/*
	 * The page is isolated from LRU. So, collapse function
	 * will not handle this page. But page splitting can happen.
	 * Do this check under compound_page_lock(). The caller should
	 * hold it.
	 */
	ret = -EBUSY;
	if (nr_pages > 1 && !PageTransHuge(page))
		goto out;

	lock_page_cgroup(pc);

	ret = -EINVAL;
	if (!PageCgroupUsed(pc) || pc->mem_cgroup != from)
		goto unlock;

	move_lock_mem_cgroup(from, &flags);

	if (!anon && page_mapped(page)) {
		/* Update mapped_file data for mem_cgroup */
		preempt_disable();
		__this_cpu_dec(from->stat->count[MEM_CGROUP_STAT_FILE_MAPPED]);
		__this_cpu_inc(to->stat->count[MEM_CGROUP_STAT_FILE_MAPPED]);
		preempt_enable();
	}
	mem_cgroup_charge_statistics(from, page, anon, -nr_pages);

	/* caller should have done css_get */
	pc->mem_cgroup = to;
	mem_cgroup_charge_statistics(to, page, anon, nr_pages);
	move_unlock_mem_cgroup(from, &flags);
	ret = 0;
unlock:
	unlock_page_cgroup(pc);
	/*
	 * check events
	 */
	memcg_check_events(to, page);
	memcg_check_events(from, page);
out:
	return ret;
}

/**
 * mem_cgroup_move_parent - moves page to the parent group
 * @page: the page to move
 * @pc: page_cgroup of the page
 * @child: page's cgroup
 *
 * move charges to its parent or the root cgroup if the group has no
 * parent (aka use_hierarchy==0).
 * Although this might fail (get_page_unless_zero, isolate_lru_page or
 * mem_cgroup_move_account fails) the failure is always temporary and
 * it signals a race with a page removal/uncharge or migration. In the
 * first case the page is on the way out and it will vanish from the LRU
 * on the next attempt and the call should be retried later.
 * Isolation from the LRU fails only if page has been isolated from
 * the LRU since we looked at it and that usually means either global
 * reclaim or migration going on. The page will either get back to the
 * LRU or vanish.
 * Finaly mem_cgroup_move_account fails only if the page got uncharged
 * (!PageCgroupUsed) or moved to a different group. The page will
 * disappear in the next attempt.
 */
static int mem_cgroup_move_parent(struct page *page,
				  struct page_cgroup *pc,
				  struct mem_cgroup *child)
{
	struct mem_cgroup *parent;
	unsigned int nr_pages;
	unsigned long uninitialized_var(flags);
	int ret;

	VM_BUG_ON(mem_cgroup_is_root(child));

	ret = -EBUSY;
	if (!get_page_unless_zero(page))
		goto out;
	if (isolate_lru_page(page))
		goto put;

	nr_pages = hpage_nr_pages(page);

	parent = parent_mem_cgroup(child);
	/*
	 * If no parent, move charges to root cgroup.
	 */
	if (!parent)
		parent = root_mem_cgroup;

	if (nr_pages > 1) {
		VM_BUG_ON_PAGE(!PageTransHuge(page), page);
		flags = compound_lock_irqsave(page);
	}

	ret = mem_cgroup_move_account(page, nr_pages,
				pc, child, parent);
	if (!ret) {
		/* Take charge off the local counters */
		page_counter_cancel(&child->memory, nr_pages);
		if (do_swap_account)
			page_counter_cancel(&child->memsw, nr_pages);
	}

	if (nr_pages > 1)
		compound_unlock_irqrestore(page, flags);
	putback_lru_page(page);
put:
	put_page(page);
out:
	return ret;
}

/*
 * Charge the memory controller for page usage.
 * Return
 * 0 if the charge was successful
 * < 0 if the cgroup is over its limit
 */
static int mem_cgroup_charge_common(struct page *page, struct mm_struct *mm,
				gfp_t gfp_mask, enum charge_type ctype)
{
	struct mem_cgroup *memcg = NULL;
	unsigned int nr_pages = 1;
	bool oom = true;
	int ret;

	if (PageTransHuge(page)) {
		nr_pages <<= compound_order(page);
		VM_BUG_ON_PAGE(!PageTransHuge(page), page);
		/*
		 * Never OOM-kill a process for a huge page.  The
		 * fault handler will fall back to regular pages.
		 */
		oom = false;
	}

	ret = __mem_cgroup_try_charge(mm, gfp_mask, nr_pages, &memcg, oom);
	if (ret == -ENOMEM)
		return ret;
	__mem_cgroup_commit_charge(memcg, page, nr_pages, ctype, false);
	return 0;
}

int mem_cgroup_newpage_charge(struct page *page,
			      struct mm_struct *mm, gfp_t gfp_mask)
{
	if (mem_cgroup_disabled())
		return 0;
	VM_BUG_ON_PAGE(page_mapped(page), page);
	VM_BUG_ON_PAGE(page->mapping && !PageAnon(page), page);
	VM_BUG_ON(!mm);
	return mem_cgroup_charge_common(page, mm, gfp_mask,
					MEM_CGROUP_CHARGE_TYPE_ANON);
}

/*
 * While swap-in, try_charge -> commit or cancel, the page is locked.
 * And when try_charge() successfully returns, one refcnt to memcg without
 * struct page_cgroup is acquired. This refcnt will be consumed by
 * "commit()" or removed by "cancel()"
 */
static int __mem_cgroup_try_charge_swapin(struct mm_struct *mm,
					  struct page *page,
					  gfp_t mask,
					  struct mem_cgroup **memcgp)
{
	struct mem_cgroup *memcg;
	struct page_cgroup *pc;
	int ret;

	pc = lookup_page_cgroup(page);
	/*
	 * Every swap fault against a single page tries to charge the
	 * page, bail as early as possible.  shmem_unuse() encounters
	 * already charged pages, too.  The USED bit is protected by
	 * the page lock, which serializes swap cache removal, which
	 * in turn serializes uncharging.
	 */
	if (PageCgroupUsed(pc))
		return 0;
	if (!do_swap_account)
		goto charge_cur_mm;
	memcg = try_get_mem_cgroup_from_page(page);
	if (!memcg)
		goto charge_cur_mm;
	*memcgp = memcg;
	ret = __mem_cgroup_try_charge(NULL, mask, 1, memcgp, true);
	css_put(&memcg->css);
	if (ret == -EINTR)
		ret = 0;
	return ret;
charge_cur_mm:
	ret = __mem_cgroup_try_charge(mm, mask, 1, memcgp, true);
	if (ret == -EINTR)
		ret = 0;
	return ret;
}

int mem_cgroup_try_charge_swapin(struct mm_struct *mm, struct page *page,
				 gfp_t gfp_mask, struct mem_cgroup **memcgp)
{
	*memcgp = NULL;
	if (mem_cgroup_disabled())
		return 0;
	/*
	 * A racing thread's fault, or swapoff, may have already
	 * updated the pte, and even removed page from swap cache: in
	 * those cases unuse_pte()'s pte_same() test will fail; but
	 * there's also a KSM case which does need to charge the page.
	 */
	if (!PageSwapCache(page)) {
		int ret;

		ret = __mem_cgroup_try_charge(mm, gfp_mask, 1, memcgp, true);
		if (ret == -EINTR)
			ret = 0;
		return ret;
	}
	return __mem_cgroup_try_charge_swapin(mm, page, gfp_mask, memcgp);
}

void mem_cgroup_cancel_charge_swapin(struct mem_cgroup *memcg)
{
	if (mem_cgroup_disabled())
		return;
	if (!memcg)
		return;
	__mem_cgroup_cancel_charge(memcg, 1);
}

static void
__mem_cgroup_commit_charge_swapin(struct page *page, struct mem_cgroup *memcg,
					enum charge_type ctype)
{
	if (mem_cgroup_disabled())
		return;
	if (!memcg)
		return;

	__mem_cgroup_commit_charge(memcg, page, 1, ctype, true);
	/*
	 * Now swap is on-memory. This means this page may be
	 * counted both as mem and swap....double count.
	 * Fix it by uncharging from memsw. Basically, this SwapCache is stable
	 * under lock_page(). But in do_swap_page()::memory.c, reuse_swap_page()
	 * may call delete_from_swap_cache() before reach here.
	 */
	if (do_swap_account && PageSwapCache(page)) {
		swp_entry_t ent = {.val = page_private(page)};
		mem_cgroup_uncharge_swap(ent);
	}

	this_cpu_inc(memcg->stat->events[MEM_CGROUP_EVENTS_PSWPIN]);
}

void mem_cgroup_commit_charge_swapin(struct page *page,
				     struct mem_cgroup *memcg)
{
	__mem_cgroup_commit_charge_swapin(page, memcg,
					  MEM_CGROUP_CHARGE_TYPE_ANON);
}

int mem_cgroup_cache_charge(struct page *page, struct mm_struct *mm,
				gfp_t gfp_mask)
{
	struct mem_cgroup *memcg = NULL;
	enum charge_type type = MEM_CGROUP_CHARGE_TYPE_CACHE;
	int ret;

	if (mem_cgroup_disabled())
		return 0;
	if (PageCompound(page))
		return 0;

	if (!PageSwapCache(page))
		ret = mem_cgroup_charge_common(page, mm, gfp_mask, type);
	else { /* page is swapcache/shmem */
		ret = __mem_cgroup_try_charge_swapin(mm, page,
						     gfp_mask, &memcg);
		if (!ret)
			__mem_cgroup_commit_charge_swapin(page, memcg, type);
	}
	return ret;
}

static void mem_cgroup_do_uncharge(struct mem_cgroup *memcg,
				   unsigned int nr_pages,
				   const enum charge_type ctype)
{
	struct memcg_batch_info *batch = NULL;
	bool uncharge_memsw = true;

	/* If swapout, usage of swap doesn't decrease */
	if (!do_swap_account || ctype == MEM_CGROUP_CHARGE_TYPE_SWAPOUT)
		uncharge_memsw = false;

	batch = &current->memcg_batch;
	/*
	 * In usual, we do css_get() when we remember memcg pointer.
	 * But in this case, we keep res->usage until end of a series of
	 * uncharges. Then, it's ok to ignore memcg's refcnt.
	 */
	if (!batch->memcg)
		batch->memcg = memcg;
	/*
	 * do_batch > 0 when unmapping pages or inode invalidate/truncate.
	 * In those cases, all pages freed continuously can be expected to be in
	 * the same cgroup and we have chance to coalesce uncharges.
	 * But we do uncharge one by one if this is killed by OOM(TIF_MEMDIE)
	 * because we want to do uncharge as soon as possible.
	 */

	if (!batch->do_batch || test_thread_flag(TIF_MEMDIE))
		goto direct_uncharge;

	if (nr_pages > 1)
		goto direct_uncharge;

	/*
	 * In typical case, batch->memcg == mem. This means we can
	 * merge a series of uncharges to an uncharge of page_counter.
	 * If not, we uncharge page_counter ony by one.
	 */
	if (batch->memcg != memcg)
		goto direct_uncharge;
	/* remember freed charge and uncharge it later */
	batch->nr_pages++;
	if (uncharge_memsw)
		batch->memsw_nr_pages++;
	return;
direct_uncharge:
	page_counter_uncharge(&memcg->memory, nr_pages);
	if (uncharge_memsw)
		page_counter_uncharge(&memcg->memsw, nr_pages);
	if (unlikely(batch->memcg != memcg))
		memcg_oom_recover(memcg);
}

/*
 * uncharge if !page_mapped(page)
 */
static struct mem_cgroup *
__mem_cgroup_uncharge_common(struct page *page, enum charge_type ctype,
			     bool end_migration)
{
	struct mem_cgroup *memcg = NULL;
	unsigned int nr_pages = 1;
	struct page_cgroup *pc;
	bool anon;

	if (mem_cgroup_disabled())
		return NULL;

	if (PageTransHuge(page)) {
		nr_pages <<= compound_order(page);
		VM_BUG_ON_PAGE(!PageTransHuge(page), page);
	}
	/*
	 * Check if our page_cgroup is valid
	 */
	pc = lookup_page_cgroup(page);
	if (unlikely(!PageCgroupUsed(pc)))
		return NULL;

	lock_page_cgroup(pc);

	memcg = pc->mem_cgroup;

	if (!PageCgroupUsed(pc))
		goto unlock_out;

	anon = PageAnon(page);

	switch (ctype) {
	case MEM_CGROUP_CHARGE_TYPE_ANON:
		/*
		 * Generally PageAnon tells if it's the anon statistics to be
		 * updated; but sometimes e.g. mem_cgroup_uncharge_page() is
		 * used before page reached the stage of being marked PageAnon.
		 */
		anon = true;
		/* fallthrough */
	case MEM_CGROUP_CHARGE_TYPE_DROP:
		/* See mem_cgroup_prepare_migration() */
		if (page_mapped(page))
			goto unlock_out;
		/*
		 * Pages under migration may not be uncharged.  But
		 * end_migration() /must/ be the one uncharging the
		 * unused post-migration page and so it has to call
		 * here with the migration bit still set.  See the
		 * page_counter handling below.
		 */
		if (!end_migration && PageCgroupMigration(pc))
			goto unlock_out;
		break;
	case MEM_CGROUP_CHARGE_TYPE_SWAPOUT:
		if (!PageAnon(page)) {	/* Shared memory */
			if (page->mapping && !page_is_file_cache(page))
				goto unlock_out;
		} else if (page_mapped(page)) /* Anon */
				goto unlock_out;
		break;
	default:
		break;
	}

	mem_cgroup_charge_statistics(memcg, page, anon, -nr_pages);

	ClearPageCgroupUsed(pc);
	/*
	 * pc->mem_cgroup is not cleared here. It will be accessed when it's
	 * freed from LRU. This is safe because uncharged page is expected not
	 * to be reused (freed soon). Exception is SwapCache, it's handled by
	 * special functions.
	 */

	unlock_page_cgroup(pc);
	/*
	 * even after unlock, we have memcg->memory.usage here and this memcg
	 * will never be freed, so it's safe to call css_get().
	 */
	memcg_check_events(memcg, page);
	if (do_swap_account && ctype == MEM_CGROUP_CHARGE_TYPE_SWAPOUT) {
		mem_cgroup_swap_statistics(memcg, true);
		mem_cgroup_update_swap_max(memcg);
		css_get(&memcg->css);
	}
	/*
	 * Migration does not charge the page_counter for the
	 * replacement page, so leave it alone when phasing out the
	 * page that is unused after the migration.
	 */
	if (!end_migration && !mem_cgroup_is_root(memcg))
		mem_cgroup_do_uncharge(memcg, nr_pages, ctype);

	return memcg;

unlock_out:
	unlock_page_cgroup(pc);
	return NULL;
}

void mem_cgroup_uncharge_page(struct page *page)
{
	/* early check. */
	if (page_mapped(page))
		return;
	VM_BUG_ON_PAGE(page->mapping && !PageAnon(page), page);
	/*
	 * If the page is in swap cache, uncharge should be deferred
	 * to the swap path, which also properly accounts swap usage
	 * and handles memcg lifetime.
	 *
	 * Note that this check is not stable and reclaim may add the
	 * page to swap cache at any time after this.  However, if the
	 * page is not in swap cache by the time page->mapcount hits
	 * 0, there won't be any page table references to the swap
	 * slot, and reclaim will free it and not actually write the
	 * page to disk.
	 */
	if (PageSwapCache(page))
		return;
	__mem_cgroup_uncharge_common(page, MEM_CGROUP_CHARGE_TYPE_ANON, false);
}

void mem_cgroup_uncharge_cache_page(struct page *page)
{
	VM_BUG_ON_PAGE(page_mapped(page), page);
	VM_BUG_ON_PAGE(page->mapping, page);
	__mem_cgroup_uncharge_common(page, MEM_CGROUP_CHARGE_TYPE_CACHE, false);
}

/*
 * Batch_start/batch_end is called in unmap_page_range/invlidate/trucate.
 * In that cases, pages are freed continuously and we can expect pages
 * are in the same memcg. All these calls itself limits the number of
 * pages freed at once, then uncharge_start/end() is called properly.
 * This may be called prural(2) times in a context,
 */

void mem_cgroup_uncharge_start(void)
{
	current->memcg_batch.do_batch++;
	/* We can do nest. */
	if (current->memcg_batch.do_batch == 1) {
		current->memcg_batch.memcg = NULL;
		current->memcg_batch.nr_pages = 0;
		current->memcg_batch.memsw_nr_pages = 0;
	}
}

void mem_cgroup_uncharge_end(void)
{
	struct memcg_batch_info *batch = &current->memcg_batch;

	if (!batch->do_batch)
		return;

	batch->do_batch--;
	if (batch->do_batch) /* If stacked, do nothing. */
		return;

	if (!batch->memcg)
		return;
	/*
	 * This "batch->memcg" is valid without any css_get/put etc...
	 * bacause we hide charges behind us.
	 */
	if (batch->nr_pages)
		page_counter_uncharge(&batch->memcg->memory, batch->nr_pages);
	if (batch->memsw_nr_pages)
		page_counter_uncharge(&batch->memcg->memsw, batch->memsw_nr_pages);
	memcg_oom_recover(batch->memcg);
	/* forget this pointer (for sanity check) */
	batch->memcg = NULL;
}

#ifdef CONFIG_SWAP
/*
 * called after __delete_from_swap_cache() and drop "page" account.
 * memcg information is recorded to swap_cgroup of "ent"
 */
void
mem_cgroup_uncharge_swapcache(struct page *page, swp_entry_t ent, bool swapout)
{
	struct mem_cgroup *memcg;
	int ctype = MEM_CGROUP_CHARGE_TYPE_SWAPOUT;

	if (!swapout) /* this was a swap cache but the swap is unused ! */
		ctype = MEM_CGROUP_CHARGE_TYPE_DROP;

	memcg = __mem_cgroup_uncharge_common(page, ctype, false);

	/*
	 * record memcg information,  if swapout && memcg != NULL,
	 * css_get() was called in uncharge().
	 */
	if (do_swap_account && swapout && memcg)
		swap_cgroup_record(ent, mem_cgroup_id(memcg));

	if (swapout && memcg)
		this_cpu_inc(memcg->stat->events[MEM_CGROUP_EVENTS_PSWPOUT]);
}
#endif

#ifdef CONFIG_MEMCG_SWAP
/*
 * called from swap_entry_free(). remove record in swap_cgroup and
 * uncharge "memsw" account.
 */
void mem_cgroup_uncharge_swap(swp_entry_t ent)
{
	struct mem_cgroup *memcg;
	unsigned short id;

	if (!do_swap_account)
		return;

	id = swap_cgroup_record(ent, 0);
	rcu_read_lock();
	memcg = mem_cgroup_lookup(id);
	if (memcg) {
		/*
		 * We uncharge this because swap is freed.
		 * This memcg can be obsolete one. We avoid calling css_tryget
		 */
		if (!mem_cgroup_is_root(memcg))
			page_counter_uncharge(&memcg->memsw, 1);
		mem_cgroup_swap_statistics(memcg, false);
		css_put(&memcg->css);
	}
	rcu_read_unlock();
}

/**
 * mem_cgroup_move_swap_account - move swap charge and swap_cgroup's record.
 * @entry: swap entry to be moved
 * @from:  mem_cgroup which the entry is moved from
 * @to:  mem_cgroup which the entry is moved to
 *
 * It succeeds only when the swap_cgroup's record for this entry is the same
 * as the mem_cgroup's id of @from.
 *
 * Returns 0 on success, -EINVAL on failure.
 *
 * The caller must have charged to @to, IOW, called page_counter_charge() about
 * both res and memsw, and called css_get().
 */
static int mem_cgroup_move_swap_account(swp_entry_t entry,
				struct mem_cgroup *from, struct mem_cgroup *to)
{
	unsigned short old_id, new_id;

	old_id = mem_cgroup_id(from);
	new_id = mem_cgroup_id(to);

	if (swap_cgroup_cmpxchg(entry, old_id, new_id) == old_id) {
		mem_cgroup_swap_statistics(from, false);
		mem_cgroup_swap_statistics(to, true);
		/*
		 * This function is only called from task migration context now.
		 * It postpones page_counter and refcount handling till the end
		 * of task migration(mem_cgroup_clear_mc()) for performance
		 * improvement. But we cannot postpone css_get(to)  because if
		 * the process that has been moved to @to does swap-in, the
		 * refcount of @to might be decreased to 0.
		 *
		 * We are in attach() phase, so the cgroup is guaranteed to be
		 * alive, so we can just call css_get().
		 */
		css_get(&to->css);
		return 0;
	}
	return -EINVAL;
}
#else
static inline int mem_cgroup_move_swap_account(swp_entry_t entry,
				struct mem_cgroup *from, struct mem_cgroup *to)
{
	return -EINVAL;
}
#endif

/*
 * Before starting migration, account PAGE_SIZE to mem_cgroup that the old
 * page belongs to.
 */
void mem_cgroup_prepare_migration(struct page *page, struct page *newpage,
				  struct mem_cgroup **memcgp)
{
	struct mem_cgroup *memcg = NULL;
	unsigned int nr_pages = 1;
	struct page_cgroup *pc;
	enum charge_type ctype;

	*memcgp = NULL;

	if (mem_cgroup_disabled())
		return;

	if (PageTransHuge(page))
		nr_pages <<= compound_order(page);

	pc = lookup_page_cgroup(page);
	lock_page_cgroup(pc);
	if (PageCgroupUsed(pc)) {
		memcg = pc->mem_cgroup;
		css_get(&memcg->css);
		/*
		 * At migrating an anonymous page, its mapcount goes down
		 * to 0 and uncharge() will be called. But, even if it's fully
		 * unmapped, migration may fail and this page has to be
		 * charged again. We set MIGRATION flag here and delay uncharge
		 * until end_migration() is called
		 *
		 * Corner Case Thinking
		 * A)
		 * When the old page was mapped as Anon and it's unmap-and-freed
		 * while migration was ongoing.
		 * If unmap finds the old page, uncharge() of it will be delayed
		 * until end_migration(). If unmap finds a new page, it's
		 * uncharged when it make mapcount to be 1->0. If unmap code
		 * finds swap_migration_entry, the new page will not be mapped
		 * and end_migration() will find it(mapcount==0).
		 *
		 * B)
		 * When the old page was mapped but migraion fails, the kernel
		 * remaps it. A charge for it is kept by MIGRATION flag even
		 * if mapcount goes down to 0. We can do remap successfully
		 * without charging it again.
		 *
		 * C)
		 * The "old" page is under lock_page() until the end of
		 * migration, so, the old page itself will not be swapped-out.
		 * If the new page is swapped out before end_migraton, our
		 * hook to usual swap-out path will catch the event.
		 */
		if (PageAnon(page))
			SetPageCgroupMigration(pc);
	}
	unlock_page_cgroup(pc);
	/*
	 * If the page is not charged at this point,
	 * we return here.
	 */
	if (!memcg)
		return;

	*memcgp = memcg;
	/*
	 * We charge new page before it's used/mapped. So, even if unlock_page()
	 * is called before end_migration, we can catch all events on this new
	 * page. In the case new page is migrated but not remapped, new page's
	 * mapcount will be finally 0 and we call uncharge in end_migration().
	 */
	if (PageAnon(page))
		ctype = MEM_CGROUP_CHARGE_TYPE_ANON;
	else
		ctype = MEM_CGROUP_CHARGE_TYPE_CACHE;
	/*
	 * The page is committed to the memcg, but it's not actually
	 * charged to the page_counter since we plan on replacing the
	 * old one and only one page is going to be left afterwards.
	 */
	__mem_cgroup_commit_charge(memcg, newpage, nr_pages, ctype, false);
}

/* remove redundant charge if migration failed*/
void mem_cgroup_end_migration(struct mem_cgroup *memcg,
	struct page *oldpage, struct page *newpage, bool migration_ok)
{
	struct page *used, *unused;
	struct page_cgroup *pc;
	bool anon;

	if (!memcg)
		return;

	if (!migration_ok) {
		used = oldpage;
		unused = newpage;
	} else {
		used = newpage;
		unused = oldpage;
	}
	anon = PageAnon(used);
	__mem_cgroup_uncharge_common(unused,
				     anon ? MEM_CGROUP_CHARGE_TYPE_ANON
				     : MEM_CGROUP_CHARGE_TYPE_CACHE,
				     true);
	css_put(&memcg->css);
	/*
	 * We disallowed uncharge of pages under migration because mapcount
	 * of the page goes down to zero, temporarly.
	 * Clear the flag and check the page should be charged.
	 */
	pc = lookup_page_cgroup(oldpage);
	lock_page_cgroup(pc);
	ClearPageCgroupMigration(pc);
	unlock_page_cgroup(pc);

	/*
	 * If a page is a file cache, radix-tree replacement is very atomic
	 * and we can skip this check. When it was an Anon page, its mapcount
	 * goes down to 0. But because we added MIGRATION flage, it's not
	 * uncharged yet. There are several case but page->mapcount check
	 * and USED bit check in mem_cgroup_uncharge_page() will do enough
	 * check. (see prepare_charge() also)
	 */
	if (anon)
		mem_cgroup_uncharge_page(used);
}

/*
 * At replace page cache, newpage is not under any memcg but it's on
 * LRU. So, this function doesn't touch page_counter but handles LRU
 * in correct way. Both pages are locked so we cannot race with uncharge.
 */
void mem_cgroup_replace_page_cache(struct page *oldpage,
				  struct page *newpage)
{
	struct mem_cgroup *memcg = NULL;
	struct page_cgroup *pc;
	enum charge_type type = MEM_CGROUP_CHARGE_TYPE_CACHE;

	if (mem_cgroup_disabled())
		return;

	pc = lookup_page_cgroup(oldpage);
	/* fix accounting on old pages */
	lock_page_cgroup(pc);
	if (PageCgroupUsed(pc)) {
		memcg = pc->mem_cgroup;
		mem_cgroup_charge_statistics(memcg, oldpage, false, -1);
		ClearPageCgroupUsed(pc);
	}
	unlock_page_cgroup(pc);

	/*
	 * When called from shmem_replace_page(), in some cases the
	 * oldpage has already been charged, and in some cases not.
	 */
	if (!memcg)
		return;
	/*
	 * Even if newpage->mapping was NULL before starting replacement,
	 * the newpage may be on LRU(or pagevec for LRU) already. We lock
	 * LRU while we overwrite pc->mem_cgroup.
	 */
	__mem_cgroup_commit_charge(memcg, newpage, 1, type, true);
}

#ifdef CONFIG_DEBUG_VM
static struct page_cgroup *lookup_page_cgroup_used(struct page *page)
{
	struct page_cgroup *pc;

	pc = lookup_page_cgroup(page);
	/*
	 * Can be NULL while feeding pages into the page allocator for
	 * the first time, i.e. during boot or memory hotplug;
	 * or when mem_cgroup_disabled().
	 */
	if (likely(pc) && PageCgroupUsed(pc))
		return pc;
	return NULL;
}

bool mem_cgroup_bad_page_check(struct page *page)
{
	if (mem_cgroup_disabled())
		return false;

	return lookup_page_cgroup_used(page) != NULL;
}

void mem_cgroup_print_bad_page(struct page *page)
{
	struct page_cgroup *pc;

	pc = lookup_page_cgroup_used(page);
	if (pc) {
		pr_alert("pc:%p pc->flags:%lx pc->mem_cgroup:%p\n",
			 pc, pc->flags, pc->mem_cgroup);
	}
}
#endif

static int mem_cgroup_resize_limit(struct mem_cgroup *memcg,
				   unsigned long limit)
{
	unsigned long curusage;
	unsigned long oldusage;
	unsigned long memswlimit;
	bool enlarge = false;
	int retry_count;
	int ret;

	/*
	 * For keeping hierarchical_reclaim simple, how long we should retry
	 * is depends on callers. We set our retry-count to be function
	 * of # of children which we should visit in this loop.
	 */
	retry_count = MEM_CGROUP_RECLAIM_RETRIES *
		      mem_cgroup_count_children(memcg);

	oldusage = page_counter_read(&memcg->memory);

	do {
		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}
		mutex_lock(&memcg_limit_mutex);
		memswlimit = memcg->memsw.limit;
		if (limit > memswlimit) {
			mutex_unlock(&memcg_limit_mutex);
			ret = -EINVAL;
			break;
		}

		if (limit > memcg->memory.limit)
			enlarge = true;

		ret = page_counter_limit(&memcg->memory, limit);
		if (!ret) {
			if (memswlimit == limit)
				memcg->memsw_is_minimum = true;
			else
				memcg->memsw_is_minimum = false;
		}
		mutex_unlock(&memcg_limit_mutex);

		if (!ret)
			break;

		mem_cgroup_reclaim(memcg, GFP_KERNEL,
				   MEM_CGROUP_RECLAIM_SHRINK);
		curusage = page_counter_read(&memcg->memory);
		/* Usage is reduced ? */
  		if (curusage >= oldusage)
			retry_count--;
		else
			oldusage = curusage;
	} while (retry_count);

	if (!ret && enlarge)
		memcg_oom_recover(memcg);

	return ret;
}

static int mem_cgroup_resize_memsw_limit(struct mem_cgroup *memcg,
					 unsigned long limit)
{
	unsigned long curusage;
	unsigned long oldusage;
	unsigned long memlimit, memswlimit;
	bool enlarge = false;
	int retry_count;
	int ret;

	/* see mem_cgroup_resize_res_limit */
	retry_count = MEM_CGROUP_RECLAIM_RETRIES *
		      mem_cgroup_count_children(memcg);

	oldusage = page_counter_read(&memcg->memsw);

	do {
		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}
		mutex_lock(&memcg_limit_mutex);
		memlimit = memcg->memory.limit;
		if (limit < memlimit) {
			mutex_unlock(&memcg_limit_mutex);
			ret = -EINVAL;
			break;
		}
		memswlimit = memcg->memsw.limit;
		if (limit > memswlimit)
			enlarge = true;
		ret = page_counter_limit(&memcg->memsw, limit);
		if (!ret) {
			if (memlimit == limit)
				memcg->memsw_is_minimum = true;
			else
				memcg->memsw_is_minimum = false;
		}
		mutex_unlock(&memcg_limit_mutex);

		if (!ret)
			break;

		mem_cgroup_reclaim(memcg, GFP_KERNEL,
				   MEM_CGROUP_RECLAIM_NOSWAP |
				   MEM_CGROUP_RECLAIM_SHRINK);
		curusage = page_counter_read(&memcg->memsw);
		/* Usage is reduced ? */
		if (curusage >= oldusage)
			retry_count--;
		else
			oldusage = curusage;
	} while (retry_count);

	if (!ret && enlarge)
		memcg_oom_recover(memcg);
	return ret;
}

unsigned long mem_cgroup_soft_limit_reclaim(struct zone *zone, int order,
					    gfp_t gfp_mask,
					    unsigned long *total_scanned)
{
	unsigned long nr_reclaimed = 0;
	struct mem_cgroup_per_zone *mz, *next_mz = NULL;
	unsigned long reclaimed;
	int loop = 0;
	struct mem_cgroup_tree_per_zone *mctz;
	unsigned long excess;
	unsigned long nr_scanned;

	if (order > 0)
		return 0;

	mctz = soft_limit_tree_node_zone(zone_to_nid(zone), zone_idx(zone));
	/*
	 * This loop can run a while, specially if mem_cgroup's continuously
	 * keep exceeding their soft limit and putting the system under
	 * pressure
	 */
	do {
		if (next_mz)
			mz = next_mz;
		else
			mz = mem_cgroup_largest_soft_limit_node(mctz);
		if (!mz)
			break;

		nr_scanned = 0;
		reclaimed = mem_cgroup_soft_reclaim(mz->memcg, zone,
						    gfp_mask, &nr_scanned);
		nr_reclaimed += reclaimed;
		*total_scanned += nr_scanned;
		spin_lock(&mctz->lock);

		/*
		 * If we failed to reclaim anything from this memory cgroup
		 * it is time to move on to the next cgroup
		 */
		next_mz = NULL;
		if (!reclaimed) {
			do {
				/*
				 * Loop until we find yet another one.
				 *
				 * By the time we get the soft_limit lock
				 * again, someone might have aded the
				 * group back on the RB tree. Iterate to
				 * make sure we get a different mem.
				 * mem_cgroup_largest_soft_limit_node returns
				 * NULL if no other cgroup is present on
				 * the tree
				 */
				next_mz =
				__mem_cgroup_largest_soft_limit_node(mctz);
				if (next_mz == mz)
					css_put(&next_mz->memcg->css);
				else /* next_mz == NULL or other memcg */
					break;
			} while (1);
		}
		__mem_cgroup_remove_exceeded(mz->memcg, mz, mctz);
		excess = soft_limit_excess(mz->memcg);
		/*
		 * One school of thought says that we should not add
		 * back the node to the tree if reclaim returns 0.
		 * But our reclaim could return 0, simply because due
		 * to priority we are exposing a smaller subset of
		 * memory to reclaim from. Consider this as a longer
		 * term TODO.
		 */
		/* If excess == 0, no tree ops */
		__mem_cgroup_insert_exceeded(mz->memcg, mz, mctz, excess);
		spin_unlock(&mctz->lock);
		css_put(&mz->memcg->css);
		loop++;
		/*
		 * Could not reclaim anything and there are no more
		 * mem cgroups to try or we seem to be looping without
		 * reclaiming anything.
		 */
		if (!nr_reclaimed &&
			(next_mz == NULL ||
			loop > MEM_CGROUP_MAX_SOFT_LIMIT_RECLAIM_LOOPS))
			break;
	} while (!nr_reclaimed);
	if (next_mz)
		css_put(&next_mz->memcg->css);
	return nr_reclaimed;
}

/**
 * mem_cgroup_force_empty_list - clears LRU of a group
 * @memcg: group to clear
 * @node: NUMA node
 * @zid: zone id
 * @lru: lru to to clear
 *
 * Traverse a specified page_cgroup list and try to drop them all.  This doesn't
 * reclaim the pages page themselves - pages are moved to the parent (or root)
 * group.
 */
static void mem_cgroup_force_empty_list(struct mem_cgroup *memcg,
				int node, int zid, enum lru_list lru)
{
	struct lruvec *lruvec;
	unsigned long flags;
	struct list_head *list;
	struct page *busy;
	struct zone *zone;

	zone = &NODE_DATA(node)->node_zones[zid];
	lruvec = mem_cgroup_zone_lruvec(zone, memcg);
	list = &lruvec->lists[lru];

	busy = NULL;
	do {
		struct page_cgroup *pc;
		struct page *page;

		cond_resched();
		spin_lock_irqsave(&zone->lru_lock, flags);
		if (list_empty(list)) {
			spin_unlock_irqrestore(&zone->lru_lock, flags);
			break;
		}
		page = list_entry(list->prev, struct page, lru);
		if (busy == page) {
			list_move(&page->lru, list);
			busy = NULL;
			spin_unlock_irqrestore(&zone->lru_lock, flags);
			continue;
		}
		spin_unlock_irqrestore(&zone->lru_lock, flags);

		pc = lookup_page_cgroup(page);

		if (mem_cgroup_move_parent(page, pc, memcg)) {
			/* found lock contention or "pc" is obsolete. */
			busy = page;
		} else
			busy = NULL;
	} while (!list_empty(list));
}

/*
 * make mem_cgroup's charge to be 0 if there is no task by moving
 * all the charges and pages to the parent.
 * This enables deleting this mem_cgroup.
 *
 * Caller is responsible for holding css reference on the memcg.
 */
static void mem_cgroup_reparent_charges(struct mem_cgroup *memcg)
{
	int node, zid;

	do {
		/* This is for making all *used* pages to be on LRU. */
		lru_add_drain_all();
		drain_all_stock_sync(memcg);
		mem_cgroup_start_move(memcg);
		for_each_node_state(node, N_MEMORY) {
			for (zid = 0; zid < MAX_NR_ZONES; zid++) {
				enum lru_list lru;
				for_each_lru(lru) {
					mem_cgroup_force_empty_list(memcg,
							node, zid, lru);
				}
			}
		}
		mem_cgroup_end_move(memcg);
		memcg_oom_recover(memcg);
		cond_resched();

		/*
		 * Kernel memory may not necessarily be trackable to a specific
		 * process. So they are not migrated, and therefore we can't
		 * expect their value to drop to 0 here.
		 * Having res filled up with kmem only is enough.
		 *
		 * This is a safety check because mem_cgroup_force_empty_list
		 * could have raced with mem_cgroup_replace_page_cache callers
		 * so the lru seemed empty but the page could have been added
		 * right after the check. RES_USAGE should be safe as we always
		 * charge before adding to the LRU.
		 */
	} while (page_counter_read(&memcg->memory) -
		 page_counter_read(&memcg->kmem) > 0);
}

/*
 * This mainly exists for tests during the setting of set of use_hierarchy.
 * Since this is the very setting we are changing, the current hierarchy value
 * is meaningless
 */
static inline bool __memcg_has_children(struct mem_cgroup *memcg)
{
	struct cgroup *pos;

	/* bounce at first found */
	cgroup_for_each_child(pos, memcg->css.cgroup)
		return true;
	return false;
}

/*
 * Must be called with memcg_create_mutex held, unless the cgroup is guaranteed
 * to be already dead (as in mem_cgroup_force_empty, for instance).  This is
 * from mem_cgroup_count_children(), in the sense that we don't really care how
 * many children we have; we only need to know if we have any.  It also counts
 * any memcg without hierarchy as infertile.
 */
static inline bool memcg_has_children(struct mem_cgroup *memcg)
{
	return memcg->use_hierarchy && __memcg_has_children(memcg);
}

/*
 * Reclaims as many pages from the given memcg as possible and moves
 * the rest to the parent.
 *
 * Caller is responsible for holding css reference for memcg.
 */
static int mem_cgroup_force_empty(struct mem_cgroup *memcg)
{
	int nr_retries = MEM_CGROUP_RECLAIM_RETRIES;
	struct cgroup *cgrp = memcg->css.cgroup;

	/* returns EBUSY if there is a task or if we come here twice. */
	if (cgroup_task_count(cgrp) || !list_empty(&cgrp->children))
		return -EBUSY;

	/* we call try-to-free pages for make this cgroup empty */
	lru_add_drain_all();
	/* try to free all pages in this cgroup */
	while (nr_retries && page_counter_read(&memcg->memory)) {
		int progress;

		if (signal_pending(current))
			return -EINTR;

		progress = try_to_free_mem_cgroup_pages(memcg, SWAP_CLUSTER_MAX,
							GFP_KERNEL, false);
		if (!progress) {
			nr_retries--;
			/* maybe some writeback is necessary */
			congestion_wait(BLK_RW_ASYNC, HZ/10);
		}

	}
	lru_add_drain();
	mem_cgroup_reparent_charges(memcg);

	return 0;
}

static int mem_cgroup_force_empty_write(struct cgroup *cont, unsigned int event)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	int ret;

	if (mem_cgroup_is_root(memcg))
		return -EINVAL;
	css_get(&memcg->css);
	ret = mem_cgroup_force_empty(memcg);
	css_put(&memcg->css);

	return ret;
}


static u64 mem_cgroup_hierarchy_read(struct cgroup *cont, struct cftype *cft)
{
	return mem_cgroup_from_cont(cont)->use_hierarchy;
}

static int mem_cgroup_hierarchy_write(struct cgroup *cont, struct cftype *cft,
					u64 val)
{
	int retval = 0;
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	struct cgroup *parent = cont->parent;
	struct mem_cgroup *parent_memcg = NULL;

	if (parent)
		parent_memcg = mem_cgroup_from_cont(parent);

	mutex_lock(&memcg_create_mutex);

	if (memcg->use_hierarchy == val)
		goto out;

	/*
	 * If parent's use_hierarchy is set, we can't make any modifications
	 * in the child subtrees. If it is unset, then the change can
	 * occur, provided the current cgroup has no children.
	 *
	 * For the root cgroup, parent_mem is NULL, we allow value to be
	 * set if there are no children.
	 */
	if ((!parent_memcg || !parent_memcg->use_hierarchy) &&
				(val == 1 || val == 0)) {
		if (!__memcg_has_children(memcg))
			memcg->use_hierarchy = val;
		else
			retval = -EBUSY;
	} else
		retval = -EINVAL;

out:
	mutex_unlock(&memcg_create_mutex);

	return retval;
}


static unsigned long tree_stat(struct mem_cgroup *memcg,
			       enum mem_cgroup_stat_index idx)
{
	struct mem_cgroup *iter;
	long val = 0;

	/* Per-cpu values can be negative, use a signed accumulator */
	for_each_mem_cgroup_tree(iter, memcg)
		val += mem_cgroup_read_stat(iter, idx);

	if (val < 0) /* race ? */
		val = 0;
	return val;
}

void mem_cgroup_fill_meminfo(struct mem_cgroup *memcg, struct meminfo *mi)
{
	int nid;
	unsigned long slab;

	memset(&mi->pages, 0, sizeof(mi->pages));
	for_each_online_node(nid)
		mem_cgroup_get_nr_pages(memcg, nid, mi->pages);

	slab = res_counter_read_u64(&memcg->kmem, RES_USAGE) >> PAGE_SHIFT;
	mi->slab_reclaimable = res_counter_read_u64(&memcg->dcache, RES_USAGE)
								>> PAGE_SHIFT;
	mi->slab_unreclaimable = max_t(long, slab - mi->slab_reclaimable, 0);

	mi->cached = mem_cgroup_recursive_stat(memcg, MEM_CGROUP_STAT_CACHE);
	mi->shmem = mem_cgroup_recursive_stat(memcg, MEM_CGROUP_STAT_SHMEM);
}

int mem_cgroup_enough_memory(struct mem_cgroup *memcg, long pages)
{
	long free;

	/* unused memory */
	free = (res_counter_read_u64(&memcg->memsw, RES_LIMIT) -
		res_counter_read_u64(&memcg->memsw, RES_USAGE)) >> PAGE_SHIFT;

	/* reclaimable slabs */
	free += res_counter_read_u64(&memcg->dcache, RES_USAGE) >> PAGE_SHIFT;

	/* assume file cache is reclaimable */
	free += mem_cgroup_recursive_stat(memcg, MEM_CGROUP_STAT_CACHE);

	/* but do not count shmem pages as they can't be purged,
	 * only swapped out */
	free -= mem_cgroup_recursive_stat(memcg, MEM_CGROUP_STAT_SHMEM);

	return free < pages ? -ENOMEM : 0;
}

static inline unsigned long mem_cgroup_usage(struct mem_cgroup *memcg, bool swap)
{
	unsigned long val;

	if (mem_cgroup_is_root(memcg)) {
		val = tree_stat(memcg, MEM_CGROUP_STAT_CACHE);
		val += tree_stat(memcg, MEM_CGROUP_STAT_RSS);
		if (swap)
			val += tree_stat(memcg, MEM_CGROUP_STAT_SWAP);
	} else {
		if (!swap)
			val = page_counter_read(&memcg->memory);
		else
			val = page_counter_read(&memcg->memsw);
	}
	return val;
}

struct accumulated_stats {
	unsigned long stat[MEM_CGROUP_STAT_NSTATS];
	unsigned long events[MEM_CGROUP_EVENTS_NSTATS];
	unsigned long lru_pages[NR_LRU_LISTS];
};

static void accumulate_memcg_tree(struct mem_cgroup *memcg,
				  struct accumulated_stats *acc)
{
	struct mem_cgroup *mi;
	int i;

	for_each_mem_cgroup_tree(mi, memcg) {
		mem_cgroup_sum_all_stat_events(mi, acc->stat, acc->events);

		for (i = 0; i < NR_LRU_LISTS; i++)
			acc->lru_pages[i] += mem_cgroup_nr_lru_pages(mi, BIT(i));

		cond_resched();
	}
}

enum {
	RES_USAGE,
	RES_LIMIT,
	RES_MAX_USAGE,
	RES_FAILCNT,
	RES_SOFT_LIMIT,
};

static ssize_t mem_cgroup_read(struct cgroup *cont, struct cftype *cft,
			       struct file *file, char __user *buf,
			       size_t nbytes, loff_t *ppos)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	char str[64];
	u64 val;
	int len;
	struct page_counter *counter;

	switch (MEMFILE_TYPE(cft->private)) {
	case _MEM:
		counter = &memcg->memory;
		break;
	case _MEMSWAP:
		counter = &memcg->memsw;
		break;
	case _KMEM:
		counter = &memcg->kmem;
		break;
	default:
		BUG();
	}

	switch (MEMFILE_ATTR(cft->private)) {
	case RES_USAGE:
		if (counter == &memcg->memory)
			val = (u64)mem_cgroup_usage(memcg, false) * PAGE_SIZE;
		else if (counter == &memcg->memsw)
			val = (u64)mem_cgroup_usage(memcg, true) * PAGE_SIZE;
		else
			val = (u64)page_counter_read(counter) * PAGE_SIZE;
		break;
	case RES_LIMIT:
		val = (u64)counter->limit * PAGE_SIZE;
		break;
	case RES_MAX_USAGE:
		val = (u64)counter->watermark * PAGE_SIZE;
		break;
	case RES_FAILCNT:
		val = (u64)counter->failcnt;
		break;
	case RES_SOFT_LIMIT:
		val = (u64)memcg->soft_limit * PAGE_SIZE;
		break;
	default:
		BUG();
	}

	len = scnprintf(str, sizeof(str), "%llu\n", (unsigned long long)val);
	return simple_read_from_buffer(buf, nbytes, ppos, str, len);
}

static int memcg_update_kmem_limit(struct cgroup *cont, unsigned long limit)
{
	int ret = -EINVAL;
#ifdef CONFIG_MEMCG_KMEM
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);

	/*
	 * When cgroup_memory_nokmem is set, kmem limit update is silently
	 * ignored to not break existing applications that write to
	 * kmem.limit_in_bytes.
	 */
	if (cgroup_memory_nokmem)
		return 0;

	/*
	 * For simplicity, we won't allow this to be disabled.  It also can't
	 * be changed if the cgroup has children already, or if tasks had
	 * already joined.
	 *
	 * If tasks join before we set the limit, a person looking at
	 * kmem.usage_in_bytes will have no way to determine when it took
	 * place, which makes the value quite meaningless.
	 *
	 * After it first became limited, changes in the value of the limit are
	 * of course permitted.
	 */
	mutex_lock(&memcg_create_mutex);
	mutex_lock(&memcg_limit_mutex);
	if (!memcg->kmem_account_flags && limit != PAGE_COUNTER_MAX) {
		if (cgroup_task_count(cont) || memcg_has_children(memcg)) {
			ret = -EBUSY;
			goto out;
		}
		ret = page_counter_limit(&memcg->kmem, limit);
		VM_BUG_ON(ret);

		ret = memcg_update_cache_sizes(memcg);
		if (ret) {
			page_counter_limit(&memcg->kmem, PAGE_COUNTER_MAX);
			goto out;
		}
		static_key_slow_inc(&memcg_kmem_enabled_key);
		/*
		 * setting the active bit after the inc will guarantee no one
		 * starts accounting before all call sites are patched
		 */
		set_bit(KMEM_ACCOUNTED_ACTIVE, &memcg->kmem_account_flags);
		set_bit(KMEM_ACCOUNTED_ACTIVATED, &memcg->kmem_account_flags);
	} else
		ret = page_counter_limit(&memcg->kmem, limit);
out:
	mutex_unlock(&memcg_limit_mutex);
	mutex_unlock(&memcg_create_mutex);
#endif
	return ret;
}

#ifdef CONFIG_MEMCG_KMEM
static int memcg_propagate_kmem(struct mem_cgroup *memcg)
{
	int ret = 0;
	struct mem_cgroup *parent = parent_mem_cgroup(memcg);

	if (!parent || cgroup_memory_nokmem)
		goto out;

	memcg->kmem_account_flags = parent->kmem_account_flags;
	/*
	 * When that happen, we need to disable the static branch only on those
	 * memcgs that enabled it. To achieve this, we would be forced to
	 * complicate the code by keeping track of which memcgs were the ones
	 * that actually enabled limits, and which ones got it from its
	 * parents.
	 *
	 * It is a lot simpler just to do static_key_slow_inc() on every child
	 * that is accounted.
	 */
	if (!memcg_kmem_is_active(memcg))
		goto out;

	/*
	 * __mem_cgroup_free() will issue static_key_slow_dec() because this
	 * memcg is active already. If the later initialization fails then the
	 * cgroup core triggers the cleanup so we do not have to do it here.
	 */
	static_key_slow_inc(&memcg_kmem_enabled_key);

	mutex_lock(&memcg_limit_mutex);
	memcg_stop_kmem_account();
	ret = memcg_update_cache_sizes(memcg);
	memcg_resume_kmem_account();
	mutex_unlock(&memcg_limit_mutex);
out:
	return ret;
}
#endif /* CONFIG_MEMCG_KMEM */

/*
 * The user of this function is...
 * RES_LIMIT.
 */
static int mem_cgroup_write(struct cgroup *cont, struct cftype *cft,
			    const char *buffer)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	unsigned long nr_pages;
	int ret;

	ret = page_counter_memparse(buffer, &nr_pages);
	if (ret)
		return ret;

	switch (MEMFILE_ATTR(cft->private)) {
	case RES_LIMIT:
		if (mem_cgroup_is_root(memcg)) { /* Can't set limit on root */
			ret = -EINVAL;
			break;
		}
		switch (MEMFILE_TYPE(cft->private)) {
		case _MEM:
			ret = mem_cgroup_resize_limit(memcg, nr_pages);
			break;
		case _MEMSWAP:
			ret = mem_cgroup_resize_memsw_limit(memcg, nr_pages);
			break;
		case _KMEM:
			ret = memcg_update_kmem_limit(cont, nr_pages);
			break;
		}
		break;
	case RES_SOFT_LIMIT:
		memcg->soft_limit = nr_pages;
		ret = 0;
		break;
	}
	return ret;
}

static ssize_t mem_cgroup_low_read(struct cgroup *cont, struct cftype *cft,
				   struct file *file, char __user *buf,
				   size_t nbytes, loff_t *ppos)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	char str[64];
	int len;

	len = scnprintf(str, sizeof(str), "%llu\n", memcg->low);
	return simple_read_from_buffer(buf, nbytes, ppos, str, len);
}

static int mem_cgroup_low_write(struct cgroup *cont, struct cftype *cft,
				const char *buffer)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	unsigned long long val;
	int ret;

	ret = res_counter_memparse_write_strategy(buffer, &val);
	if (ret)
		return ret;

	memcg->low = val;
	return 0;
}

static ssize_t mem_cgroup_high_read(struct cgroup *cont, struct cftype *cft,
				    struct file *file, char __user *buf,
				    size_t nbytes, loff_t *ppos)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	char str[64];
	int len;

	len = scnprintf(str, sizeof(str), "%llu\n", memcg->high);
	return simple_read_from_buffer(buf, nbytes, ppos, str, len);
}

static int mem_cgroup_high_write(struct cgroup *cont, struct cftype *cft,
				 const char *buffer)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	unsigned long long val, usage;
	int ret;

	ret = res_counter_memparse_write_strategy(buffer, &val);
	if (ret)
		return ret;

	memcg->high = val;

	usage = res_counter_read_u64(&memcg->res, RES_USAGE);
	if (usage > val)
		try_to_free_mem_cgroup_pages(memcg,
					     (usage - val) >> PAGE_SHIFT,
					     GFP_KERNEL, false);
	return 0;
}

static ssize_t mem_cgroup_oom_guarantee_read(struct cgroup *cont,
		struct cftype *cft, struct file *file, char __user *buf,
		size_t nbytes, loff_t *ppos)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	char str[64];
	int len;

	len = scnprintf(str, sizeof(str), "%llu\n", memcg->oom_guarantee);
	return simple_read_from_buffer(buf, nbytes, ppos, str, len);
}

static int mem_cgroup_oom_guarantee_write(struct cgroup *cont,
		struct cftype *cft, const char *buffer)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	unsigned long long val;
	int ret;

	ret = res_counter_memparse_write_strategy(buffer, &val);
	if (ret)
		return ret;

	memcg->oom_guarantee = val;
	return 0;
}

#ifdef CONFIG_CLEANCACHE
static u64 mem_cgroup_disable_cleancache_read(struct cgroup *cgrp,
					      struct cftype *cft)
{
	return mem_cgroup_from_cont(cgrp)->cleancache_disabled_toggle;
}

static int mem_cgroup_disable_cleancache_write(struct cgroup *cgrp,
					       struct cftype *cft, u64 val)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cgrp);
	struct mem_cgroup *iter, *parent;

	mutex_lock(&memcg_create_mutex);
	memcg->cleancache_disabled_toggle = !!val;
	for_each_mem_cgroup_tree(iter, memcg) {
		parent = parent_mem_cgroup(iter);
		iter->cleancache_disabled = iter->cleancache_disabled_toggle;
		if (parent)
			iter->cleancache_disabled |= parent->cleancache_disabled;
	}
	mutex_unlock(&memcg_create_mutex);
	return 0;
}
#endif

static int mem_cgroup_reset(struct cgroup *cont, unsigned int event)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	struct page_counter *counter;

	switch (MEMFILE_TYPE(event)) {
	case _MEM:
		counter = &memcg->memory;
		break;
	case _MEMSWAP:
		counter = &memcg->memsw;
		break;
	case _KMEM:
		counter = &memcg->kmem;
		break;
	default:
		BUG();
	}

	switch (MEMFILE_ATTR(event)) {
	case RES_MAX_USAGE:
		page_counter_reset_watermark(counter);
		break;
	case RES_FAILCNT:
		counter->failcnt = 0;
		break;
	default:
		BUG();
	}

	return 0;
}

static u64 mem_cgroup_move_charge_read(struct cgroup *cgrp,
					struct cftype *cft)
{
	return mem_cgroup_from_cont(cgrp)->move_charge_at_immigrate;
}

#ifdef CONFIG_MMU
static int mem_cgroup_move_charge_write(struct cgroup *cgrp,
					struct cftype *cft, u64 val)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cgrp);

	if (val >= (1 << NR_MOVE_TYPE))
		return -EINVAL;

	/*
	 * No kind of locking is needed in here, because ->can_attach() will
	 * check this value once in the beginning of the process, and then carry
	 * on with stale data. This means that changes to this value will only
	 * affect task migrations starting after the change.
	 */
	memcg->move_charge_at_immigrate = val;
	return 0;
}
#else
static int mem_cgroup_move_charge_write(struct cgroup *cgrp,
					struct cftype *cft, u64 val)
{
	return -ENOSYS;
}
#endif

#ifdef CONFIG_BEANCOUNTERS

#include <bc/beancounter.h>

void mem_cgroup_sync_beancounter(struct mem_cgroup *memcg,
				 struct user_beancounter *ub)
{
	struct mem_cgroup *mi;
	unsigned long long lim, held, maxheld;
	volatile struct ubparm *k, *d, *p, *s, *o;

	k = &ub->ub_parms[UB_KMEMSIZE];
	d = &ub->ub_parms[UB_DCACHESIZE];
	p = &ub->ub_parms[UB_PHYSPAGES];
	s = &ub->ub_parms[UB_SWAPPAGES];
	o = &ub->ub_parms[UB_OOMGUARPAGES];

	p->held	= res_counter_read_u64(&memcg->res, RES_USAGE) >> PAGE_SHIFT;
	p->maxheld = res_counter_read_u64(&memcg->res, RES_MAX_USAGE) >> PAGE_SHIFT;
	p->failcnt = atomic_long_read(&memcg->mem_failcnt);
	lim = res_counter_read_u64(&memcg->res, RES_LIMIT);
	lim = lim >= RESOURCE_MAX ? UB_MAXVALUE :
		min_t(unsigned long long, lim >> PAGE_SHIFT, UB_MAXVALUE);
	p->barrier = p->limit = lim;

	k->held = res_counter_read_u64(&memcg->kmem, RES_USAGE);
	k->maxheld = res_counter_read_u64(&memcg->kmem, RES_MAX_USAGE);
	k->failcnt = res_counter_read_u64(&memcg->kmem, RES_FAILCNT);
	lim = res_counter_read_u64(&memcg->kmem, RES_LIMIT);
	lim = lim >= RESOURCE_MAX ? UB_MAXVALUE :
		min_t(unsigned long long, lim, UB_MAXVALUE);
	k->barrier = k->limit = lim;

	d->held = res_counter_read_u64(&memcg->dcache, RES_USAGE);
	d->maxheld = res_counter_read_u64(&memcg->dcache, RES_MAX_USAGE);
	d->failcnt = 0;
	d->barrier = d->limit = UB_MAXVALUE;

	held = (res_counter_read_u64(&memcg->memsw, RES_USAGE) -
		res_counter_read_u64(&memcg->res, RES_USAGE)) >> PAGE_SHIFT;
	maxheld = memcg->swap_max >> PAGE_SHIFT;
	s->failcnt = atomic_long_read(&memcg->swap_failcnt);
	lim = res_counter_read_u64(&memcg->memsw, RES_LIMIT);
	lim = lim >= RESOURCE_MAX ? UB_MAXVALUE :
		min_t(unsigned long long, lim >> PAGE_SHIFT, UB_MAXVALUE);
	if (lim != UB_MAXVALUE)
		lim -= p->limit;
	s->barrier = s->limit = lim;

	/* Due to global reclaim, memory.memsw.usage can be greater than
	 * (memory.memsw.limit - memory.limit). */
	s->held = min(held, lim);
	s->maxheld = min(maxheld, lim);

	o->held = res_counter_read_u64(&memcg->memsw, RES_USAGE) >> PAGE_SHIFT;
	o->maxheld = res_counter_read_u64(&memcg->memsw, RES_MAX_USAGE) >> PAGE_SHIFT;
	o->failcnt = atomic_long_read(&memcg->oom_kill_cnt);
	lim = memcg->oom_guarantee;
	lim = lim >= RESOURCE_MAX ? UB_MAXVALUE :
		min_t(unsigned long long, lim >> PAGE_SHIFT, UB_MAXVALUE);
	o->barrier = o->limit = lim;

	ub->swapin = 0;
	ub->swapout = 0;
	for_each_mem_cgroup_tree(mi, memcg) {
		ub->swapin += mem_cgroup_read_events(mi, MEM_CGROUP_EVENTS_PSWPIN);
		ub->swapout += mem_cgroup_read_events(mi, MEM_CGROUP_EVENTS_PSWPOUT);
	}
}

int mem_cgroup_apply_beancounter(struct mem_cgroup *memcg,
				 struct user_beancounter *ub)
{
	unsigned long long mem, memsw, mem_old, memsw_old, oomguar;
	int ret = 0;

	if (mem_cgroup_is_root(memcg))
		return -EPERM;

	mem = ub->ub_parms[UB_PHYSPAGES].limit;
	if (mem < RESOURCE_MAX >> PAGE_SHIFT)
		mem <<= PAGE_SHIFT;
	else
		mem = RESOURCE_MAX;

	memsw = ub->ub_parms[UB_SWAPPAGES].limit;
	if (memsw < RESOURCE_MAX >> PAGE_SHIFT)
		memsw <<= PAGE_SHIFT;
	else
		memsw = RESOURCE_MAX;
	if (memsw < RESOURCE_MAX - mem)
		memsw += mem;
	else
		memsw = RESOURCE_MAX;

	oomguar = ub->ub_parms[UB_OOMGUARPAGES].barrier;
	if (oomguar < RESOURCE_MAX >> PAGE_SHIFT)
		oomguar <<= PAGE_SHIFT;
	else
		oomguar = RESOURCE_MAX;

	if (ub->ub_parms[UB_KMEMSIZE].limit != UB_MAXVALUE)
		pr_warn_once("ub: kmemsize limit is deprecated\n");
	if (ub->ub_parms[UB_DCACHESIZE].limit != UB_MAXVALUE)
		pr_warn_once("ub: dcachesize limit is deprecated\n");

	/* activate kmem accounting */
	ret = memcg_update_kmem_limit(cg, RESOURCE_MAX);
	if (ret)
		goto out;

	/* try change mem+swap before changing mem limit */
	if (res_counter_read_u64(&memcg->memsw, RES_LIMIT) != memsw)
		(void)mem_cgroup_resize_memsw_limit(memcg, memsw);

	if (res_counter_read_u64(&memcg->res, RES_LIMIT) != mem) {
		ret = mem_cgroup_resize_limit(memcg, mem);
		if (ret)
			goto out;
	}

	mem_old = res_counter_read_u64(&memcg->res, RES_LIMIT);
	memsw_old = res_counter_read_u64(&memcg->memsw, RES_LIMIT);

	if (mem != mem_old) {
		/* first, reset memsw limit since it cannot be < mem limit */
		if (memsw_old < RESOURCE_MAX) {
			memsw_old = RESOURCE_MAX;
			ret = mem_cgroup_resize_memsw_limit(memcg, memsw_old);
			if (ret)
				goto out;
		}
		ret = mem_cgroup_resize_limit(memcg, mem);
		if (ret)
			goto out;
	}

	if (memsw != memsw_old) {
		ret = mem_cgroup_resize_memsw_limit(memcg, memsw);
		if (ret)
			goto out;
	}

	memcg->oom_guarantee = oomguar;
out:
	return ret;
}

#endif /* CONFIG_BEANCOUNTERS */

#ifdef CONFIG_NUMA
static int memcg_numa_stat_show(struct cgroup *cont, struct cftype *cft,
				      struct seq_file *m)
{
	int nid;
	unsigned long total_nr, file_nr, anon_nr, unevictable_nr;
	unsigned long node_nr;
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);

	total_nr = mem_cgroup_nr_lru_pages(memcg, LRU_ALL);
	seq_printf(m, "total=%lu", total_nr);
	for_each_node_state(nid, N_MEMORY) {
		node_nr = mem_cgroup_node_nr_lru_pages(memcg, nid, LRU_ALL);
		seq_printf(m, " N%d=%lu", nid, node_nr);
	}
	seq_putc(m, '\n');

	file_nr = mem_cgroup_nr_lru_pages(memcg, LRU_ALL_FILE);
	seq_printf(m, "file=%lu", file_nr);
	for_each_node_state(nid, N_MEMORY) {
		node_nr = mem_cgroup_node_nr_lru_pages(memcg, nid,
				LRU_ALL_FILE);
		seq_printf(m, " N%d=%lu", nid, node_nr);
	}
	seq_putc(m, '\n');

	anon_nr = mem_cgroup_nr_lru_pages(memcg, LRU_ALL_ANON);
	seq_printf(m, "anon=%lu", anon_nr);
	for_each_node_state(nid, N_MEMORY) {
		node_nr = mem_cgroup_node_nr_lru_pages(memcg, nid,
				LRU_ALL_ANON);
		seq_printf(m, " N%d=%lu", nid, node_nr);
	}
	seq_putc(m, '\n');

	unevictable_nr = mem_cgroup_nr_lru_pages(memcg, BIT(LRU_UNEVICTABLE));
	seq_printf(m, "unevictable=%lu", unevictable_nr);
	for_each_node_state(nid, N_MEMORY) {
		node_nr = mem_cgroup_node_nr_lru_pages(memcg, nid,
				BIT(LRU_UNEVICTABLE));
		seq_printf(m, " N%d=%lu", nid, node_nr);
	}
	seq_putc(m, '\n');
	return 0;
}

/*
 * memcg_numa_migrate_new_page() private argument. @target_nodes specifies the
 * set of nodes to allocate pages from. @current_node is the current preferable
 * node, it gets rotated after each allocation.
 */
struct memcg_numa_migrate_struct {
	nodemask_t *target_nodes;
	int current_node;
};

/*
 * Used as an argument for migrate_pages(). Allocated pages are spread evenly
 * among destination nodes.
 */
static struct page *memcg_numa_migrate_new_page(struct page *page,
				unsigned long private, int **result)
{
	struct memcg_numa_migrate_struct *ms = (void *)private;
	gfp_t gfp_mask = GFP_HIGHUSER_MOVABLE | __GFP_NORETRY | __GFP_NOWARN;

	ms->current_node = next_node(ms->current_node, *ms->target_nodes);
	if (ms->current_node >= MAX_NUMNODES) {
		ms->current_node = first_node(*ms->target_nodes);
		VM_BUG_ON(ms->current_node >= MAX_NUMNODES);
	}

	return __alloc_pages_nodemask(gfp_mask, 0,
			node_zonelist(ms->current_node, gfp_mask),
			ms->target_nodes);
}

/*
 * Isolate at most @nr_to_scan pages from @lruvec for further migration and
 * store them in @dst. Returns the number of pages scanned. Return value of 0
 * means that @lruved is empty.
 */
static long memcg_numa_isolate_pages(struct lruvec *lruvec, enum lru_list lru,
				     long nr_to_scan, struct list_head *dst)
{
	struct list_head *src = &lruvec->lists[lru];
	struct zone *zone = lruvec_zone(lruvec);
	struct page *page, *tmp;
	long scanned = 0, taken = 0;

	spin_lock_irq(&zone->lru_lock);
	while (!list_empty(src) && scanned < nr_to_scan && taken < nr_to_scan) {
		int nr_pages;
		page = list_last_entry(src, struct page, lru);

		scanned++;

		switch (__isolate_lru_page(page, ISOLATE_ASYNC_MIGRATE)) {
		case 0:
			nr_pages = hpage_nr_pages(page);
			mem_cgroup_update_lru_size(lruvec, lru, -nr_pages);
			list_move(&page->lru, dst);
			taken += nr_pages;
			break;

		case -EBUSY:
			list_move(&page->lru, src);
			continue;

		default:
			BUG();
		}
	}
	__mod_zone_page_state(zone, NR_LRU_BASE + lru, -taken);
	__mod_zone_page_state(zone, NR_ISOLATED_ANON + is_file_lru(lru), taken);
	spin_unlock_irq(&zone->lru_lock);

	list_for_each_entry_safe(page, tmp, dst, lru) {
		if (PageTransHuge(page) && split_huge_page_to_list(page, dst)) {
			list_del(&page->lru);
			mod_zone_page_state(zone, NR_ISOLATED_ANON,
					-HPAGE_PMD_NR);
			putback_lru_page(page);
		}
	}

	return scanned;
}

static long __memcg_numa_migrate_pages(struct lruvec *lruvec, enum lru_list lru,
				       nodemask_t *target_nodes, long nr_to_scan)
{
	struct memcg_numa_migrate_struct ms = {
		.target_nodes = target_nodes,
		.current_node = -1,
	};
	LIST_HEAD(pages);
	long total_scanned = 0;

	/*
	 * If no limit on the maximal number of migrated pages is specified,
	 * assume the caller wants to migrate them all.
	 */
	if (nr_to_scan < 0)
		nr_to_scan = mem_cgroup_get_lru_size(lruvec, lru);

	while (total_scanned < nr_to_scan) {
		int ret;
		long scanned;

		scanned = memcg_numa_isolate_pages(lruvec, lru,
						   SWAP_CLUSTER_MAX, &pages);
		if (!scanned)
			break;

		ret = migrate_pages(&pages, memcg_numa_migrate_new_page,
				    (unsigned long)&ms, MIGRATE_ASYNC,
				    MR_SYSCALL);
		putback_lru_pages(&pages);
		if (ret < 0)
			return ret;

		if (signal_pending(current))
			return -EINTR;

		total_scanned += scanned;
	}

	return total_scanned;
}

/*
 * Migrate at most @nr_to_scan pages accounted to @memcg to @target_nodes.
 * Pages are spreaded evenly among destination nodes. If @nr_to_scan is <= 0,
 * then the function will attempt to migrate all pages accounted to @memcg.
 */
static int memcg_numa_migrate_pages(struct mem_cgroup *memcg,
				    nodemask_t *target_nodes, long nr_to_scan)
{
	struct mem_cgroup *mi;
	long total_scanned = 0, scanned;

again:
	scanned = 0;
	for_each_mem_cgroup_tree(mi, memcg) {
		struct zone *zone;

		for_each_populated_zone(zone) {
			struct lruvec *lruvec;
			enum lru_list lru;

			if (node_isset(zone_to_nid(zone), *target_nodes))
				continue;

			lruvec = mem_cgroup_zone_lruvec(zone, mi);
			/*
			 * For the sake of simplicity, do not attempt to migrate
			 * unevictable pages. It should be fine as long as there
			 * aren't too many of them, which is usually true.
			 */
			for_each_evictable_lru(lru) {
				long ret = __memcg_numa_migrate_pages(lruvec,
						lru, target_nodes,
						nr_to_scan > 0 ?
						SWAP_CLUSTER_MAX : -1);
				if (ret < 0) {
					mem_cgroup_iter_break(memcg, mi);
					return ret;
				}
				scanned += ret;
			}
		}
	}

	total_scanned += scanned;

	/*
	 * Retry only if we made progress in the previous iteration.
	 */
	if (nr_to_scan > 0 && scanned > 0 && total_scanned < nr_to_scan)
		goto again;

	return 0;
}

/*
 * The format of memory.numa_migrate is
 *
 *   NODELIST[ MAX_SCAN]
 *
 * where NODELIST is a comma-separated list of ranges N1-N2 specifying the set
 * of nodes to migrate pages of this cgroup to, and the optional MAX_SCAN
 * imposes a limit on the number of pages that can be migrated in one go.
 *
 * The call may be interrupted by a signal, in which case -EINTR is returned.
 */
static int memcg_numa_migrate_write(struct cgroup *cont,
		struct cftype *cft, const char *buf)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	NODEMASK_ALLOC(nodemask_t, target_nodes, GFP_KERNEL);
	const char *nodes_str = buf, *nr_str;
	long nr_to_scan = -1;
	int ret = -ENOMEM;

	if (!target_nodes)
		goto out;

	nr_str = strchr(buf, ' ');
	if (nr_str) {
		nodes_str = kstrndup(buf, nr_str - buf, GFP_KERNEL);
		if (!nodes_str)
			goto out;
		nr_str += 1;
	}

	ret = nodelist_parse(nodes_str, *target_nodes);
	if (ret)
		goto out;

	ret = -EINVAL;
	if (!nodes_subset(*target_nodes, node_states[N_MEMORY]))
		goto out;

	if (nr_str && (kstrtol(nr_str, 10, &nr_to_scan) || nr_to_scan <= 0))
		goto out;

	ret = memcg_numa_migrate_pages(memcg, target_nodes, nr_to_scan);
out:
	if (nodes_str != buf)
		kfree(nodes_str);
	NODEMASK_FREE(target_nodes);
	return ret;
}

#endif /* CONFIG_NUMA */

static inline void mem_cgroup_lru_names_not_uptodate(void)
{
	BUILD_BUG_ON(ARRAY_SIZE(mem_cgroup_lru_names) != NR_LRU_LISTS);
}

static int memcg_stat_show(struct cgroup *cont, struct cftype *cft,
				 struct seq_file *m)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	unsigned long memory, memsw;
	struct mem_cgroup *mi;
	unsigned int i;
	struct accumulated_stats acc;

	for (i = 0; i < MEM_CGROUP_STAT_NSTATS; i++) {
		if (i == MEM_CGROUP_STAT_SWAP && !do_swap_account)
			continue;
		seq_printf(m, "%s %ld\n", mem_cgroup_stat_names[i],
			   mem_cgroup_read_stat(memcg, i) * PAGE_SIZE);
	}

	for (i = 0; i < MEM_CGROUP_EVENTS_NSTATS; i++)
		seq_printf(m, "%s %lu\n", mem_cgroup_events_names[i],
			   mem_cgroup_read_events(memcg, i));

	for (i = 0; i < NR_LRU_LISTS; i++)
		seq_printf(m, "%s %lu\n", mem_cgroup_lru_names[i],
			   mem_cgroup_nr_lru_pages(memcg, BIT(i)) * PAGE_SIZE);

	/* Hierarchical information */
	memory = memsw = PAGE_COUNTER_MAX;
	for (mi = memcg; mi; mi = parent_mem_cgroup(mi)) {
		memory = min(memory, mi->memory.limit);
		memsw = min(memsw, mi->memsw.limit);
	}
	seq_printf(m, "hierarchical_memory_limit %llu\n",
		   (u64)memory * PAGE_SIZE);
	if (do_swap_account)
		seq_printf(m, "hierarchical_memsw_limit %llu\n",
			   (u64)memsw * PAGE_SIZE);

	memset(&acc, 0, sizeof(acc));
	accumulate_memcg_tree(memcg, &acc);

	for (i = 0; i < MEM_CGROUP_STAT_NSTATS; i++) {
		if (i == MEM_CGROUP_STAT_SWAP && !do_swap_account)
			continue;
		seq_printf(m, "total_%s %lld\n", mem_cgroup_stat_names[i],
			   (u64)acc.stat[i] * PAGE_SIZE);
	}

	for (i = 0; i < MEM_CGROUP_EVENTS_NSTATS; i++)
		seq_printf(m, "total_%s %llu\n", mem_cgroup_events_names[i],
			   (u64)acc.events[i]);

	for (i = 0; i < NR_LRU_LISTS; i++)
		seq_printf(m, "total_%s %llu\n", mem_cgroup_lru_names[i],
			   (u64)acc.lru_pages[i] * PAGE_SIZE);

#ifdef CONFIG_DEBUG_VM
	{
		int nid, zid;
		struct mem_cgroup_per_zone *mz;
		struct zone_reclaim_stat *rstat;
		unsigned long recent_rotated[2] = {0, 0};
		unsigned long recent_scanned[2] = {0, 0};

		for_each_online_node(nid)
			for (zid = 0; zid < MAX_NR_ZONES; zid++) {
				mz = mem_cgroup_zoneinfo(memcg, nid, zid);
				rstat = &mz->lruvec.reclaim_stat;

				recent_rotated[0] += rstat->recent_rotated[0];
				recent_rotated[1] += rstat->recent_rotated[1];
				recent_scanned[0] += rstat->recent_scanned[0];
				recent_scanned[1] += rstat->recent_scanned[1];
			}
		seq_printf(m, "recent_rotated_anon %lu\n", recent_rotated[0]);
		seq_printf(m, "recent_rotated_file %lu\n", recent_rotated[1]);
		seq_printf(m, "recent_scanned_anon %lu\n", recent_scanned[0]);
		seq_printf(m, "recent_scanned_file %lu\n", recent_scanned[1]);
	}
#endif

	return 0;
}

static u64 mem_cgroup_swappiness_read(struct cgroup *cgrp, struct cftype *cft)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cgrp);

	return mem_cgroup_swappiness(memcg);
}

static int mem_cgroup_swappiness_write(struct cgroup *cgrp, struct cftype *cft,
				       u64 val)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cgrp);

	if (val > 100)
		return -EINVAL;

	if (cgrp->parent)
		memcg->swappiness = val;
	else
		vm_swappiness = val;

	return 0;
}

static void __mem_cgroup_threshold(struct mem_cgroup *memcg, bool swap)
{
	struct mem_cgroup_threshold_ary *t;
	unsigned long usage;
	int i;

	rcu_read_lock();
	if (!swap)
		t = rcu_dereference(memcg->thresholds.primary);
	else
		t = rcu_dereference(memcg->memsw_thresholds.primary);

	if (!t)
		goto unlock;

	usage = mem_cgroup_usage(memcg, swap);

	/*
	 * current_threshold points to threshold just below or equal to usage.
	 * If it's not true, a threshold was crossed after last
	 * call of __mem_cgroup_threshold().
	 */
	i = t->current_threshold;

	/*
	 * Iterate backward over array of thresholds starting from
	 * current_threshold and check if a threshold is crossed.
	 * If none of thresholds below usage is crossed, we read
	 * only one element of the array here.
	 */
	for (; i >= 0 && unlikely(t->entries[i].threshold > usage); i--)
		eventfd_signal(t->entries[i].eventfd, 1);

	/* i = current_threshold + 1 */
	i++;

	/*
	 * Iterate forward over array of thresholds starting from
	 * current_threshold+1 and check if a threshold is crossed.
	 * If none of thresholds above usage is crossed, we read
	 * only one element of the array here.
	 */
	for (; i < t->size && unlikely(t->entries[i].threshold <= usage); i++)
		eventfd_signal(t->entries[i].eventfd, 1);

	/* Update current_threshold */
	t->current_threshold = i - 1;
unlock:
	rcu_read_unlock();
}

static void mem_cgroup_threshold(struct mem_cgroup *memcg)
{
	while (memcg) {
		__mem_cgroup_threshold(memcg, false);
		if (do_swap_account)
			__mem_cgroup_threshold(memcg, true);

		memcg = parent_mem_cgroup(memcg);
	}
}

static int compare_thresholds(const void *a, const void *b)
{
	const struct mem_cgroup_threshold *_a = a;
	const struct mem_cgroup_threshold *_b = b;

	if (_a->threshold > _b->threshold)
		return 1;

	if (_a->threshold < _b->threshold)
		return -1;

	return 0;
}

static int mem_cgroup_oom_notify_cb(struct mem_cgroup *memcg)
{
	struct mem_cgroup_eventfd_list *ev;

	spin_lock(&memcg_oom_lock);

	list_for_each_entry(ev, &memcg->oom_notify, list)
		eventfd_signal(ev->eventfd, 1);

	spin_unlock(&memcg_oom_lock);
	return 0;
}

static void mem_cgroup_oom_notify(struct mem_cgroup *memcg)
{
	struct mem_cgroup *iter;

	for_each_mem_cgroup_tree(iter, memcg)
		mem_cgroup_oom_notify_cb(iter);
}

static int mem_cgroup_usage_register_event(struct cgroup *cgrp,
	struct cftype *cft, struct eventfd_ctx *eventfd, const char *args)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cgrp);
	struct mem_cgroup_thresholds *thresholds;
	struct mem_cgroup_threshold_ary *new;
	enum res_type type = MEMFILE_TYPE(cft->private);
	unsigned long threshold;
	unsigned long usage;
	int i, size, ret;

	ret = page_counter_memparse(args, &threshold);
	if (ret)
		return ret;

	mutex_lock(&memcg->thresholds_lock);

	if (type == _MEM)
		thresholds = &memcg->thresholds;
	else if (type == _MEMSWAP)
		thresholds = &memcg->memsw_thresholds;
	else
		BUG();

	usage = mem_cgroup_usage(memcg, type == _MEMSWAP);

	/* Check if a threshold crossed before adding a new one */
	if (thresholds->primary)
		__mem_cgroup_threshold(memcg, type == _MEMSWAP);

	size = thresholds->primary ? thresholds->primary->size + 1 : 1;

	/* Allocate memory for new array of thresholds */
	new = kmalloc(sizeof(*new) + size * sizeof(struct mem_cgroup_threshold),
			GFP_KERNEL);
	if (!new) {
		ret = -ENOMEM;
		goto unlock;
	}
	new->size = size;

	/* Copy thresholds (if any) to new array */
	if (thresholds->primary) {
		memcpy(new->entries, thresholds->primary->entries, (size - 1) *
				sizeof(struct mem_cgroup_threshold));
	}

	/* Add new threshold */
	new->entries[size - 1].eventfd = eventfd;
	new->entries[size - 1].threshold = threshold;

	/* Sort thresholds. Registering of new threshold isn't time-critical */
	sort(new->entries, size, sizeof(struct mem_cgroup_threshold),
			compare_thresholds, NULL);

	/* Find current threshold */
	new->current_threshold = -1;
	for (i = 0; i < size; i++) {
		if (new->entries[i].threshold <= usage) {
			/*
			 * new->current_threshold will not be used until
			 * rcu_assign_pointer(), so it's safe to increment
			 * it here.
			 */
			++new->current_threshold;
		} else
			break;
	}

	/* Free old spare buffer and save old primary buffer as spare */
	kfree(thresholds->spare);
	thresholds->spare = thresholds->primary;

	rcu_assign_pointer(thresholds->primary, new);

	/* To be sure that nobody uses thresholds */
	synchronize_rcu();

unlock:
	mutex_unlock(&memcg->thresholds_lock);

	return ret;
}

static void mem_cgroup_usage_unregister_event(struct cgroup *cgrp,
	struct cftype *cft, struct eventfd_ctx *eventfd)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cgrp);
	struct mem_cgroup_thresholds *thresholds;
	struct mem_cgroup_threshold_ary *new;
	enum res_type type = MEMFILE_TYPE(cft->private);
	unsigned long usage;
	int i, j, size, entries;

	mutex_lock(&memcg->thresholds_lock);
	if (type == _MEM)
		thresholds = &memcg->thresholds;
	else if (type == _MEMSWAP)
		thresholds = &memcg->memsw_thresholds;
	else
		BUG();

	if (!thresholds->primary)
		goto unlock;

	usage = mem_cgroup_usage(memcg, type == _MEMSWAP);

	/* Check if a threshold crossed before removing */
	__mem_cgroup_threshold(memcg, type == _MEMSWAP);

	/* Calculate new number of threshold */
	size = entries = 0;
	for (i = 0; i < thresholds->primary->size; i++) {
		if (thresholds->primary->entries[i].eventfd != eventfd)
			size++;
		else
			entries++;
	}

	new = thresholds->spare;

	/* If no items related to eventfd have been cleared, nothing to do */
	if (!entries)
		goto unlock;

	/* Set thresholds array to NULL if we don't have thresholds */
	if (!size) {
		kfree(new);
		new = NULL;
		goto swap_buffers;
	}

	new->size = size;

	/* Copy thresholds and find current threshold */
	new->current_threshold = -1;
	for (i = 0, j = 0; i < thresholds->primary->size; i++) {
		if (thresholds->primary->entries[i].eventfd == eventfd)
			continue;

		new->entries[j] = thresholds->primary->entries[i];
		if (new->entries[j].threshold <= usage) {
			/*
			 * new->current_threshold will not be used
			 * until rcu_assign_pointer(), so it's safe to increment
			 * it here.
			 */
			++new->current_threshold;
		}
		j++;
	}

swap_buffers:
	/* Swap primary and spare array */
	thresholds->spare = thresholds->primary;

	rcu_assign_pointer(thresholds->primary, new);

	/* To be sure that nobody uses thresholds */
	synchronize_rcu();

	/* If all events are unregistered, free the spare array */
	if (!new) {
		kfree(thresholds->spare);
		thresholds->spare = NULL;
	}
unlock:
	mutex_unlock(&memcg->thresholds_lock);
}

static int mem_cgroup_oom_register_event(struct cgroup *cgrp,
	struct cftype *cft, struct eventfd_ctx *eventfd, const char *args)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cgrp);
	struct mem_cgroup_eventfd_list *event;
	enum res_type type = MEMFILE_TYPE(cft->private);

	BUG_ON(type != _OOM_TYPE);
	event = kmalloc(sizeof(*event),	GFP_KERNEL);
	if (!event)
		return -ENOMEM;

	spin_lock(&memcg_oom_lock);

	event->eventfd = eventfd;
	list_add(&event->list, &memcg->oom_notify);

	/* already in OOM ? */
	if (atomic_read(&memcg->under_oom))
		eventfd_signal(eventfd, 1);
	spin_unlock(&memcg_oom_lock);

	return 0;
}

static void mem_cgroup_oom_unregister_event(struct cgroup *cgrp,
	struct cftype *cft, struct eventfd_ctx *eventfd)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cgrp);
	struct mem_cgroup_eventfd_list *ev, *tmp;
	enum res_type type = MEMFILE_TYPE(cft->private);

	BUG_ON(type != _OOM_TYPE);

	spin_lock(&memcg_oom_lock);

	list_for_each_entry_safe(ev, tmp, &memcg->oom_notify, list) {
		if (ev->eventfd == eventfd) {
			list_del(&ev->list);
			kfree(ev);
		}
	}

	spin_unlock(&memcg_oom_lock);
}

static int mem_cgroup_oom_control_read(struct cgroup *cgrp,
	struct cftype *cft,  struct cgroup_map_cb *cb)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cgrp);

	cb->fill(cb, "oom_kill_disable", memcg->oom_kill_disable);

	if (atomic_read(&memcg->under_oom))
		cb->fill(cb, "under_oom", 1);
	else
		cb->fill(cb, "under_oom", 0);
	return 0;
}

static int mem_cgroup_oom_control_write(struct cgroup *cgrp,
	struct cftype *cft, u64 val)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cgrp);

	/* cannot set to root cgroup and only 0 and 1 are allowed */
	if (!cgrp->parent || !((val == 0) || (val == 1)))
		return -EINVAL;

	if (!ve_is_super(get_exec_env()) && val != 0)
		return -EACCES;

	memcg->oom_kill_disable = val;
	if (!val)
		memcg_oom_recover(memcg);

	return 0;
}

#ifdef CONFIG_MEMCG_KMEM
static int memcg_init_kmem(struct mem_cgroup *memcg, struct cgroup_subsys *ss)
{
	int ret;

	ret = memcg_propagate_kmem(memcg);
	if (ret)
		return ret;

	return mem_cgroup_sockets_init(memcg, ss);
}

static void memcg_destroy_kmem(struct mem_cgroup *memcg)
{
	if (test_bit(KMEM_ACCOUNTED_ACTIVATED, &memcg->kmem_account_flags)) {
		list_del(&memcg->kmemcg_sharers);
		memcg_destroy_kmem_caches(memcg);
	}
	mem_cgroup_sockets_destroy(memcg);
}

static void memcg_deactivate_kmem(struct mem_cgroup *memcg)
{
	struct mem_cgroup *parent, *sharer;
	int kmemcg_id;

	if (!memcg_kmem_is_active(memcg))
		return;

	/*
	 * Clear the 'active' flag before clearing memcg_caches arrays entries.
	 * Since we take the slab_mutex in memcg_deactivate_kmem_caches(), it
	 * guarantees no cache will be created for this cgroup after we are
	 * done (see memcg_create_kmem_cache()).
	 */
	clear_bit(KMEM_ACCOUNTED_ACTIVE, &memcg->kmem_account_flags);

	memcg_deactivate_kmem_caches(memcg);

	kmemcg_id = memcg->kmemcg_id;
	BUG_ON(kmemcg_id < 0);

	parent = parent_mem_cgroup(memcg);
	if (!parent)
		parent = root_mem_cgroup;

	/*
	 * Change kmemcg_id of this cgroup and all its descendants to the
	 * parent's id, and then move all entries from this cgroup's list_lrus
	 * to ones of the parent. After we have finished, all list_lrus
	 * corresponding to this cgroup are guaranteed to remain empty. The
	 * ordering is imposed by list_lru_node->lock taken by
	 * memcg_drain_all_list_lrus().
	 */
	list_for_each_entry(sharer, &memcg->kmemcg_sharers, kmemcg_sharers) {
		BUG_ON(sharer->kmemcg_id != kmemcg_id);
		sharer->kmemcg_id = parent->kmemcg_id;
	}
	memcg->kmemcg_id = parent->kmemcg_id;
	list_splice(&memcg->kmemcg_sharers, &parent->kmemcg_sharers);
	list_add(&memcg->kmemcg_sharers, &parent->kmemcg_sharers);

	memcg_drain_all_list_lrus(kmemcg_id, parent->kmemcg_id);

	memcg_free_cache_id(kmemcg_id);

	/*
	 * kmem charges can outlive the cgroup. In the case of slab
	 * pages, for instance, a page contain objects from various
	 * processes. As we prevent from taking a reference for every
	 * such allocation we have to be careful when doing uncharge
	 * (see memcg_uncharge_kmem) and here during offlining.
	 *
	 * The idea is that that only the _last_ uncharge which sees
	 * the dead memcg will drop the last reference. An additional
	 * reference is taken here before the group is marked dead
	 * which is then paired with css_put during uncharge resp. here.
	 *
	 * Although this might sound strange as this path is called from
	 * css_offline() when the referencemight have dropped down to 0
	 * and shouldn't be incremented anymore (css_tryget would fail)
	 * we do not have other options because of the kmem allocations
	 * lifetime.
	 */
	css_get(&memcg->css);

	memcg_kmem_mark_dead(memcg);

	if (page_counter_read(&memcg->kmem))
		return;

	/*
	 * Charges already down to 0, undo mem_cgroup_get() done in the charge
	 * path here, being careful not to race with memcg_uncharge_kmem: it is
	 * possible that the charges went down to 0 between mark_dead and the
	 * page_counter read, so in that case, we don't need the put
	 */
	if (memcg_kmem_test_and_clear_dead(memcg))
		css_put(&memcg->css);
}
#else
static int memcg_init_kmem(struct mem_cgroup *memcg, struct cgroup_subsys *ss)
{
	return 0;
}

static void memcg_destroy_kmem(struct mem_cgroup *memcg)
{
}

static void memcg_deactivate_kmem(struct mem_cgroup *memcg)
{
}
#endif

static struct cftype mem_cgroup_files[] = {
	{
		.name = "usage_in_bytes",
		.private = MEMFILE_PRIVATE(_MEM, RES_USAGE),
		.read = mem_cgroup_read,
		.register_event = mem_cgroup_usage_register_event,
		.unregister_event = mem_cgroup_usage_unregister_event,
	},
	{
		.name = "max_usage_in_bytes",
		.private = MEMFILE_PRIVATE(_MEM, RES_MAX_USAGE),
		.trigger = mem_cgroup_reset,
		.read = mem_cgroup_read,
	},
	{
		.name = "limit_in_bytes",
		.private = MEMFILE_PRIVATE(_MEM, RES_LIMIT),
		.write_string = mem_cgroup_write,
		.read = mem_cgroup_read,
	},
	{
		.name = "soft_limit_in_bytes",
		.private = MEMFILE_PRIVATE(_MEM, RES_SOFT_LIMIT),
		.write_string = mem_cgroup_write,
		.read = mem_cgroup_read,
	},
	{
		.name = "low",
		.flags = CFTYPE_NOT_ON_ROOT,
		.write_string = mem_cgroup_low_write,
		.read = mem_cgroup_low_read,
	},
	{
		.name = "high",
		.flags = CFTYPE_NOT_ON_ROOT,
		.write_string = mem_cgroup_high_write,
		.read = mem_cgroup_high_read,
	},
	{
		.name = "failcnt",
		.private = MEMFILE_PRIVATE(_MEM, RES_FAILCNT),
		.trigger = mem_cgroup_reset,
		.read = mem_cgroup_read,
	},
	{
		.name = "stat",
		.read_seq_string = memcg_stat_show,
	},
	{
		.name = "force_empty",
		.trigger = mem_cgroup_force_empty_write,
	},
	{
		.name = "use_hierarchy",
		.flags = CFTYPE_INSANE | CFTYPE_VE_WRITABLE,
		.write_u64 = mem_cgroup_hierarchy_write,
		.read_u64 = mem_cgroup_hierarchy_read,
	},
	{
		.name = "swappiness",
		.read_u64 = mem_cgroup_swappiness_read,
		.write_u64 = mem_cgroup_swappiness_write,
	},
	{
		.name = "move_charge_at_immigrate",
		.read_u64 = mem_cgroup_move_charge_read,
		.write_u64 = mem_cgroup_move_charge_write,
	},
	{
		.name = "oom_control",
		.read_map = mem_cgroup_oom_control_read,
		.write_u64 = mem_cgroup_oom_control_write,
		.register_event = mem_cgroup_oom_register_event,
		.unregister_event = mem_cgroup_oom_unregister_event,
		.private = MEMFILE_PRIVATE(_OOM_TYPE, OOM_CONTROL),
	},
	{
		.name = "oom_guarantee",
		.flags = CFTYPE_NOT_ON_ROOT,
		.write_string = mem_cgroup_oom_guarantee_write,
		.read = mem_cgroup_oom_guarantee_read,
	},
	{
		.name = "pressure_level",
		.register_event = vmpressure_register_event,
		.unregister_event = vmpressure_unregister_event,
	},
#ifdef CONFIG_NUMA
	{
		.name = "numa_stat",
		.read_seq_string = memcg_numa_stat_show,
	},
	{
		.name = "numa_migrate",
		.flags = CFTYPE_NOT_ON_ROOT,
		.write_string = memcg_numa_migrate_write,
	},
#endif
#ifdef CONFIG_CLEANCACHE
	{
		.name = "disable_cleancache",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_u64 = mem_cgroup_disable_cleancache_read,
		.write_u64 = mem_cgroup_disable_cleancache_write,
	},
#endif
#ifdef CONFIG_MEMCG_KMEM
	{
		.name = "kmem.limit_in_bytes",
		.private = MEMFILE_PRIVATE(_KMEM, RES_LIMIT),
		.write_string = mem_cgroup_write,
		.read = mem_cgroup_read,
	},
	{
		.name = "kmem.usage_in_bytes",
		.private = MEMFILE_PRIVATE(_KMEM, RES_USAGE),
		.read = mem_cgroup_read,
	},
	{
		.name = "kmem.failcnt",
		.private = MEMFILE_PRIVATE(_KMEM, RES_FAILCNT),
		.trigger = mem_cgroup_reset,
		.read = mem_cgroup_read,
	},
	{
		.name = "kmem.max_usage_in_bytes",
		.private = MEMFILE_PRIVATE(_KMEM, RES_MAX_USAGE),
		.trigger = mem_cgroup_reset,
		.read = mem_cgroup_read,
	},
#ifdef CONFIG_SLABINFO
	{
		.name = "kmem.slabinfo",
		.read_seq_string = mem_cgroup_slabinfo_read,
	},
#endif
#endif
	{ },	/* terminate */
};

#ifdef CONFIG_MEMCG_SWAP
static struct cftype memsw_cgroup_files[] = {
	{
		.name = "memsw.usage_in_bytes",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_USAGE),
		.read = mem_cgroup_read,
		.register_event = mem_cgroup_usage_register_event,
		.unregister_event = mem_cgroup_usage_unregister_event,
	},
	{
		.name = "memsw.max_usage_in_bytes",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_MAX_USAGE),
		.trigger = mem_cgroup_reset,
		.read = mem_cgroup_read,
	},
	{
		.name = "memsw.limit_in_bytes",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_LIMIT),
		.write_string = mem_cgroup_write,
		.read = mem_cgroup_read,
	},
	{
		.name = "memsw.failcnt",
		.private = MEMFILE_PRIVATE(_MEMSWAP, RES_FAILCNT),
		.trigger = mem_cgroup_reset,
		.read = mem_cgroup_read,
	},
	{ },	/* terminate */
};
#endif

/*
 * Private memory cgroup IDR
 *
 * Swap-out records and page cache shadow entries need to store memcg
 * references in constrained space, so we maintain an ID space that is
 * limited to 16 bit (MEM_CGROUP_ID_MAX), limiting the total number of
 * memory-controlled cgroups to 64k.
 *
 * However, there usually are many references to the oflline CSS after
 * the cgroup has been destroyed, such as page cache or reclaimable
 * slab objects, that don't need to hang on to the ID. We want to keep
 * those dead CSS from occupying IDs, or we might quickly exhaust the
 * relatively small ID space and prevent the creation of new cgroups
 * even when there are much fewer than 64k cgroups - possibly none.
 *
 * Maintain a private 16-bit ID space for memcg, and allow the ID to
 * be freed and recycled when it's no longer needed, which is usually
 * when the CSS is offlined.
 *
 * The only exception to that are records of swapped out tmpfs/shmem
 * pages that need to be attributed to live ancestors on swapin. But
 * those references are manageable from userspace.
 */

static DEFINE_IDR(mem_cgroup_idr);

static unsigned short mem_cgroup_id(struct mem_cgroup *memcg)
{
	return memcg->id;
}

static void mem_cgroup_id_put(struct mem_cgroup *memcg)
{
	idr_remove(&mem_cgroup_idr, memcg->id);
	memcg->id = 0;
	synchronize_rcu();
}

/**
 * mem_cgroup_from_id - look up a memcg from a memcg id
 * @id: the memcg id to look up
 *
 * Caller must hold rcu_read_lock().
 */
struct mem_cgroup *mem_cgroup_from_id(unsigned short id)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return idr_find(&mem_cgroup_idr, id);
}

static int alloc_mem_cgroup_per_zone_info(struct mem_cgroup *memcg, int node)
{
	struct mem_cgroup_per_node *pn;
	struct mem_cgroup_per_zone *mz;
	int zone, tmp = node;
	/*
	 * This routine is called against possible nodes.
	 * But it's BUG to call kmalloc() against offline node.
	 *
	 * TODO: this routine can waste much memory for nodes which will
	 *       never be onlined. It's better to use memory hotplug callback
	 *       function.
	 */
	if (!node_state(node, N_NORMAL_MEMORY))
		tmp = -1;
	pn = kzalloc_node(sizeof(*pn), GFP_KERNEL, tmp);
	if (!pn)
		return 1;

	for (zone = 0; zone < MAX_NR_ZONES; zone++) {
		mz = &pn->zoneinfo[zone];
		lruvec_init(&mz->lruvec);
		mz->usage_in_excess = 0;
		mz->on_tree = false;
		mz->memcg = memcg;
	}
	memcg->info.nodeinfo[node] = pn;
	return 0;
}

static void free_mem_cgroup_per_zone_info(struct mem_cgroup *memcg, int node)
{
	kfree(memcg->info.nodeinfo[node]);
}

static struct mem_cgroup *mem_cgroup_alloc(void)
{
	struct mem_cgroup *memcg;
	size_t size;
	int id;

	size = sizeof(struct mem_cgroup);
	size += nr_node_ids * sizeof(struct mem_cgroup_per_node *);

	memcg = kzalloc(size, GFP_KERNEL);
	if (!memcg)
		return NULL;

	id = idr_alloc(&mem_cgroup_idr, NULL,
		       1, MEM_CGROUP_ID_MAX,
		       GFP_KERNEL);
	if (id < 0)
		goto fail;

	memcg->id = id;

	memcg->stat = alloc_percpu(struct mem_cgroup_stat_cpu);
	if (!memcg->stat)
		goto out_free;
	spin_lock_init(&memcg->pcp_counter_lock);
	idr_replace(&mem_cgroup_idr, memcg, memcg->id);
	synchronize_rcu();
	return memcg;

out_free:
	if (memcg->id > 0) {
		idr_remove(&mem_cgroup_idr, memcg->id);
		synchronize_rcu();
	}
fail:
	kfree(memcg);
	return NULL;
}

/*
 * At destroying mem_cgroup, references from swap_cgroup can remain.
 * (scanning all at force_empty is too costly...)
 *
 * Instead of clearing all references at force_empty, we remember
 * the number of reference from swap_cgroup and free mem_cgroup when
 * it goes down to 0.
 *
 * Removal of cgroup itself succeeds regardless of refs from swap.
 */

static void __mem_cgroup_free(struct mem_cgroup *memcg)
{
	int node;

	mem_cgroup_remove_from_trees(memcg);

	mem_cgroup_id_put(memcg);

	for_each_node(node)
		free_mem_cgroup_per_zone_info(memcg, node);

	free_percpu(memcg->stat);

	/*
	 * We need to make sure that (at least for now), the jump label
	 * destruction code runs outside of the cgroup lock. This is because
	 * get_online_cpus(), which is called from the static_branch update,
	 * can't be called inside the cgroup_lock. cpusets are the ones
	 * enforcing this dependency, so if they ever change, we might as well.
	 *
	 * schedule_work() will guarantee this happens. Be careful if you need
	 * to move this code around, and make sure it is outside
	 * the cgroup_lock.
	 */
	disarm_static_keys(memcg);
	kfree(memcg);
}

/*
 * Returns the parent mem_cgroup in memcgroup hierarchy with hierarchy enabled.
 */
struct mem_cgroup *parent_mem_cgroup(struct mem_cgroup *memcg)
{
	if (!memcg->memory.parent)
		return NULL;
	return mem_cgroup_from_counter(memcg->memory.parent, memory);
}
EXPORT_SYMBOL(parent_mem_cgroup);

static void __init mem_cgroup_soft_limit_tree_init(void)
{
	struct mem_cgroup_tree_per_node *rtpn;
	struct mem_cgroup_tree_per_zone *rtpz;
	int tmp, node, zone;

	for_each_node(node) {
		tmp = node;
		if (!node_state(node, N_NORMAL_MEMORY))
			tmp = -1;
		rtpn = kzalloc_node(sizeof(*rtpn), GFP_KERNEL, tmp);
		BUG_ON(!rtpn);

		soft_limit_tree.rb_tree_per_node[node] = rtpn;

		for (zone = 0; zone < MAX_NR_ZONES; zone++) {
			rtpz = &rtpn->rb_tree_per_zone[zone];
			rtpz->rb_root = RB_ROOT;
			spin_lock_init(&rtpz->lock);
		}
	}
}

static struct cgroup_subsys_state * __ref
mem_cgroup_css_alloc(struct cgroup *cont)
{
	struct mem_cgroup *memcg;
	long error = -ENOMEM;
	int node;

	memcg = mem_cgroup_alloc();
	if (!memcg)
		return ERR_PTR(error);

	for_each_node(node)
		if (alloc_mem_cgroup_per_zone_info(memcg, node))
			goto free_out;

	/* root ? */
	if (cont->parent == NULL) {
		root_mem_cgroup = memcg;
		page_counter_init(&memcg->memory, NULL);
		memcg->soft_limit = PAGE_COUNTER_MAX;
		memcg->high = RESOURCE_MAX;
		page_counter_init(&memcg->memsw, NULL);
		page_counter_init(&memcg->kmem, NULL);
	}

	memcg->last_scanned_node = MAX_NUMNODES;
	INIT_LIST_HEAD(&memcg->oom_notify);
	memcg->move_charge_at_immigrate = 0;
	mutex_init(&memcg->thresholds_lock);
	spin_lock_init(&memcg->move_lock);
	vmpressure_init(&memcg->vmpressure);
#ifdef CONFIG_MEMCG_KMEM
	memcg->kmemcg_id = -1;
	INIT_LIST_HEAD(&memcg->kmemcg_sharers);
#endif

	return &memcg->css;

free_out:
	__mem_cgroup_free(memcg);
	return ERR_PTR(error);
}

static int
mem_cgroup_css_online(struct cgroup *cont)
{
	struct mem_cgroup *memcg, *parent;
	int error = 0;

	if (!cont->parent)
		return 0;

	mutex_lock(&memcg_create_mutex);
	memcg = mem_cgroup_from_cont(cont);
	parent = mem_cgroup_from_cont(cont->parent);

	memcg->use_hierarchy = parent->use_hierarchy;
	memcg->oom_kill_disable = parent->oom_kill_disable;
	memcg->swappiness = mem_cgroup_swappiness(parent);
#ifdef CONFIG_CLEANCACHE
	memcg->cleancache_disabled = parent->cleancache_disabled;
#endif

	if (parent->use_hierarchy) {
		page_counter_init(&memcg->memory, &parent->memory);
		memcg->soft_limit = PAGE_COUNTER_MAX;
		memcg->high = RESOURCE_MAX;
		page_counter_init(&memcg->memsw, &parent->memsw);
		page_counter_init(&memcg->kmem, &parent->kmem);

		/*
		 * No need to take a reference to the parent because cgroup
		 * core guarantees its existence.
		 */
	} else {
		page_counter_init(&memcg->memory, NULL);
		memcg->soft_limit = PAGE_COUNTER_MAX;
		memcg->high = RESOURCE_MAX;
		page_counter_init(&memcg->memsw, NULL);
		page_counter_init(&memcg->kmem, NULL);
		/*
		 * Deeper hierachy with use_hierarchy == false doesn't make
		 * much sense so let cgroup subsystem know about this
		 * unfortunate state in our controller.
		 */
		if (parent != root_mem_cgroup)
			mem_cgroup_subsys.broken_hierarchy = true;
	}

	error = memcg_init_kmem(memcg, &mem_cgroup_subsys);
	mutex_unlock(&memcg_create_mutex);
	return error;
}

/*
 * Announce all parents that a group from their hierarchy is gone.
 */
static void mem_cgroup_invalidate_reclaim_iterators(struct mem_cgroup *memcg)
{
	struct mem_cgroup *parent = memcg;

	while ((parent = parent_mem_cgroup(parent)))
		mem_cgroup_iter_invalidate(parent);

	/*
	 * if the root memcg is not hierarchical we have to check it
	 * explicitely.
	 */
	if (!root_mem_cgroup->use_hierarchy)
		mem_cgroup_iter_invalidate(root_mem_cgroup);
}

static void mem_cgroup_css_offline(struct cgroup *cont)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	struct cgroup *iter;

	/*
	 * Mark memory cgroup as offline before going to reparent charges.
	 * This guarantees that __mem_cgroup_try_charge() either charges before
	 * reparenting starts or doesn't charge at all, hence we won't have
	 * pending user memory charges after reparenting is done.
	 */
	memcg->is_offline = true;
	smp_mb();

	memcg_deactivate_kmem(memcg);

	mem_cgroup_invalidate_reclaim_iterators(memcg);

	/*
	 * This requires that offlining is serialized.  Right now that is
	 * guaranteed because css_killed_work_fn() holds the cgroup_mutex.
	 */
	rcu_read_lock();
	cgroup_for_each_descendant_post(iter, cont) {
		rcu_read_unlock();
		mem_cgroup_reparent_charges(mem_cgroup_from_cont(iter));
		rcu_read_lock();
	}
	rcu_read_unlock();
	mem_cgroup_reparent_charges(memcg);

	vmpressure_cleanup(&memcg->vmpressure);
}

static void mem_cgroup_css_free(struct cgroup *cont)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);

	memcg_destroy_kmem(memcg);
	__mem_cgroup_free(memcg);
}

#ifdef CONFIG_MMU
/* Handlers for move charge at task migration. */
#define PRECHARGE_COUNT_AT_ONCE	256
static int mem_cgroup_do_precharge(unsigned long count)
{
	int ret = 0;
	int batch_count = PRECHARGE_COUNT_AT_ONCE;
	struct mem_cgroup *memcg = mc.to;

	if (mem_cgroup_is_root(memcg)) {
		mc.precharge += count;
		/* we don't need css_get for root */
		return ret;
	}
	/* try to charge at once */
	if (count > 1) {
		struct page_counter *dummy;
		/*
		 * "memcg" cannot be under rmdir() because we've already checked
		 * by cgroup_lock_live_cgroup() that it is not removed and we
		 * are still under the same cgroup_mutex. So we can postpone
		 * css_get().
		 */
		if (!page_counter_try_charge(&memcg->memory, count, &dummy))
			goto one_by_one;
		if (do_swap_account &&
		    !page_counter_try_charge(&memcg->memsw, count, &dummy)) {
			page_counter_uncharge(&memcg->memory, count);
			goto one_by_one;
		}
		mc.precharge += count;
		return ret;
	}
one_by_one:
	/* fall back to one by one charge */
	while (count--) {
		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}
		if (!batch_count--) {
			batch_count = PRECHARGE_COUNT_AT_ONCE;
			cond_resched();
		}
		ret = __mem_cgroup_try_charge(NULL,
					GFP_KERNEL, 1, &memcg, false);
		if (ret)
			/* mem_cgroup_clear_mc() will do uncharge later */
			return ret;
		mc.precharge++;
	}
	return ret;
}

/**
 * get_mctgt_type - get target type of moving charge
 * @vma: the vma the pte to be checked belongs
 * @addr: the address corresponding to the pte to be checked
 * @ptent: the pte to be checked
 * @target: the pointer the target page or swap ent will be stored(can be NULL)
 *
 * Returns
 *   0(MC_TARGET_NONE): if the pte is not a target for move charge.
 *   1(MC_TARGET_PAGE): if the page corresponding to this pte is a target for
 *     move charge. if @target is not NULL, the page is stored in target->page
 *     with extra refcnt got(Callers should handle it).
 *   2(MC_TARGET_SWAP): if the swap entry corresponding to this pte is a
 *     target for charge migration. if @target is not NULL, the entry is stored
 *     in target->ent.
 *
 * Called with pte lock held.
 */
union mc_target {
	struct page	*page;
	swp_entry_t	ent;
};

enum mc_target_type {
	MC_TARGET_NONE = 0,
	MC_TARGET_PAGE,
	MC_TARGET_SWAP,
};

static struct page *mc_handle_present_pte(struct vm_area_struct *vma,
						unsigned long addr, pte_t ptent)
{
	struct page *page = vm_normal_page(vma, addr, ptent);

	if (!page || !page_mapped(page))
		return NULL;
	if (PageAnon(page)) {
		/* we don't move shared anon */
		if (!move_anon())
			return NULL;
	} else if (!move_file())
		/* we ignore mapcount for file pages */
		return NULL;
	if (!get_page_unless_zero(page))
		return NULL;

	return page;
}

#ifdef CONFIG_SWAP
static struct page *mc_handle_swap_pte(struct vm_area_struct *vma,
			unsigned long addr, pte_t ptent, swp_entry_t *entry)
{
	struct page *page = NULL;
	swp_entry_t ent = pte_to_swp_entry(ptent);

	if (!move_anon() || non_swap_entry(ent))
		return NULL;
	/*
	 * Because lookup_swap_cache() updates some statistics counter,
	 * we call find_get_page() with swapper_space directly.
	 */
	page = find_get_page(swap_address_space(ent), ent.val);
	if (do_swap_account)
		entry->val = ent.val;

	return page;
}
#else
static struct page *mc_handle_swap_pte(struct vm_area_struct *vma,
			unsigned long addr, pte_t ptent, swp_entry_t *entry)
{
	return NULL;
}
#endif

static struct page *mc_handle_file_pte(struct vm_area_struct *vma,
			unsigned long addr, pte_t ptent, swp_entry_t *entry)
{
	struct page *page = NULL;
	struct address_space *mapping;
	pgoff_t pgoff;

	if (!vma->vm_file) /* anonymous vma */
		return NULL;
	if (!move_file())
		return NULL;

	mapping = vma->vm_file->f_mapping;
	pgoff = linear_page_index(vma, addr);

	/* page is moved even if it's not RSS of this task(page-faulted). */
#ifdef CONFIG_SWAP
	/* shmem/tmpfs may report page out on swap: account for that too. */
	if (shmem_mapping(mapping)) {
		page = __find_get_page(mapping, pgoff);
		if (radix_tree_exceptional_entry(page)) {
			swp_entry_t swp = radix_to_swp_entry(page);
			if (do_swap_account)
				*entry = swp;
			page = find_get_page(swap_address_space(swp), swp.val);
		}
	} else
		page = find_get_page(mapping, pgoff);
#else
	page = find_get_page(mapping, pgoff);
#endif
	return page;
}

static enum mc_target_type get_mctgt_type(struct vm_area_struct *vma,
		unsigned long addr, pte_t ptent, union mc_target *target)
{
	struct page *page = NULL;
	struct page_cgroup *pc;
	enum mc_target_type ret = MC_TARGET_NONE;
	swp_entry_t ent = { .val = 0 };

	if (pte_present(ptent))
		page = mc_handle_present_pte(vma, addr, ptent);
	else if (is_swap_pte(ptent))
		page = mc_handle_swap_pte(vma, addr, ptent, &ent);
	else if (pte_none(ptent))
		page = mc_handle_file_pte(vma, addr, ptent, &ent);

	if (!page && !ent.val)
		return ret;
	if (page) {
		pc = lookup_page_cgroup(page);
		/*
		 * Do only loose check w/o page_cgroup lock.
		 * mem_cgroup_move_account() checks the pc is valid or not under
		 * the lock.
		 */
		if (PageCgroupUsed(pc) && pc->mem_cgroup == mc.from) {
			ret = MC_TARGET_PAGE;
			if (target)
				target->page = page;
		}
		if (!ret || !target)
			put_page(page);
	}
	/* There is a swap entry and a page doesn't exist or isn't charged */
	if (ent.val && !ret &&
			mem_cgroup_id(mc.from) == lookup_swap_cgroup_id(ent)) {
		ret = MC_TARGET_SWAP;
		if (target)
			target->ent = ent;
	}
	return ret;
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/*
 * We don't consider swapping or file mapped pages because THP does not
 * support them for now.
 * Caller should make sure that pmd_trans_huge(pmd) is true.
 */
static enum mc_target_type get_mctgt_type_thp(struct vm_area_struct *vma,
		unsigned long addr, pmd_t pmd, union mc_target *target)
{
	struct page *page = NULL;
	struct page_cgroup *pc;
	enum mc_target_type ret = MC_TARGET_NONE;

	page = pmd_page(pmd);
	VM_BUG_ON_PAGE(!page || !PageHead(page), page);
	if (!move_anon())
		return ret;
	pc = lookup_page_cgroup(page);
	if (PageCgroupUsed(pc) && pc->mem_cgroup == mc.from) {
		ret = MC_TARGET_PAGE;
		if (target) {
			get_page(page);
			target->page = page;
		}
	}
	return ret;
}
#else
static inline enum mc_target_type get_mctgt_type_thp(struct vm_area_struct *vma,
		unsigned long addr, pmd_t pmd, union mc_target *target)
{
	return MC_TARGET_NONE;
}
#endif

static int mem_cgroup_count_precharge_pte_range(pmd_t *pmd,
					unsigned long addr, unsigned long end,
					struct mm_walk *walk)
{
	struct vm_area_struct *vma = walk->private;
	pte_t *pte;
	spinlock_t *ptl;

	if (pmd_trans_huge_lock(pmd, vma, &ptl) == 1) {
		if (get_mctgt_type_thp(vma, addr, *pmd, NULL) == MC_TARGET_PAGE)
			mc.precharge += HPAGE_PMD_NR;
		spin_unlock(ptl);
		return 0;
	}

	if (pmd_trans_unstable(pmd))
		return 0;
	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	for (; addr != end; pte++, addr += PAGE_SIZE)
		if (get_mctgt_type(vma, addr, *pte, NULL))
			mc.precharge++;	/* increment precharge temporarily */
	pte_unmap_unlock(pte - 1, ptl);
	cond_resched();

	return 0;
}

static unsigned long mem_cgroup_count_precharge(struct mm_struct *mm)
{
	unsigned long precharge;
	struct vm_area_struct *vma;

	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		struct mm_walk mem_cgroup_count_precharge_walk = {
			.pmd_entry = mem_cgroup_count_precharge_pte_range,
			.mm = mm,
			.private = vma,
		};
		if (is_vm_hugetlb_page(vma))
			continue;
		walk_page_range(vma->vm_start, vma->vm_end,
					&mem_cgroup_count_precharge_walk);
	}
	up_read(&mm->mmap_sem);

	precharge = mc.precharge;
	mc.precharge = 0;

	return precharge;
}

static int mem_cgroup_precharge_mc(struct mm_struct *mm)
{
	unsigned long precharge = mem_cgroup_count_precharge(mm);

	VM_BUG_ON(mc.moving_task);
	mc.moving_task = current;
	return mem_cgroup_do_precharge(precharge);
}

/* cancels all extra charges on mc.from and mc.to, and wakes up all waiters. */
static void __mem_cgroup_clear_mc(void)
{
	struct mem_cgroup *from = mc.from;
	struct mem_cgroup *to = mc.to;
	int i;

	/* we must uncharge all the leftover precharges from mc.to */
	if (mc.precharge) {
		__mem_cgroup_cancel_charge(mc.to, mc.precharge);
		mc.precharge = 0;
	}
	/*
	 * we didn't uncharge from mc.from at mem_cgroup_move_account(), so
	 * we must uncharge here.
	 */
	if (mc.moved_charge) {
		__mem_cgroup_cancel_charge(mc.from, mc.moved_charge);
		mc.moved_charge = 0;
	}
	/* we must fixup refcnts and charges */
	if (mc.moved_swap) {
		/* uncharge swap account from the old cgroup */
		if (!mem_cgroup_is_root(mc.from))
			page_counter_uncharge(&mc.from->memsw, mc.moved_swap);

		for (i = 0; i < mc.moved_swap; i++)
			css_put(&mc.from->css);

		if (!mem_cgroup_is_root(mc.to)) {
			/*
			 * we charged both to->memory and to->memsw, so we
			 * should uncharge to->memory.
			 */
			page_counter_uncharge(&mc.to->memory, mc.moved_swap);
		}
		/* we've already done css_get(mc.to) */
		mc.moved_swap = 0;
	}
	if (do_swap_account) {
		mem_cgroup_update_swap_max(from);
		mem_cgroup_update_swap_max(to);
	}
	memcg_oom_recover(from);
	memcg_oom_recover(to);
	wake_up_all(&mc.waitq);
}

static void mem_cgroup_clear_mc(void)
{
	struct mem_cgroup *from = mc.from;

	/*
	 * we must clear moving_task before waking up waiters at the end of
	 * task migration.
	 */
	mc.moving_task = NULL;
	__mem_cgroup_clear_mc();
	spin_lock(&mc.lock);
	mc.from = NULL;
	mc.to = NULL;
	spin_unlock(&mc.lock);
	mem_cgroup_end_move(from);
}

static int mem_cgroup_can_attach(struct cgroup *cgroup,
				 struct cgroup_taskset *tset)
{
	struct task_struct *p = cgroup_taskset_first(tset);
	int ret = 0;
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cgroup);
	unsigned long move_charge_at_immigrate;

	/*
	 * We are now commited to this value whatever it is. Changes in this
	 * tunable will only affect upcoming migrations, not the current one.
	 * So we need to save it, and keep it going.
	 */
	move_charge_at_immigrate  = memcg->move_charge_at_immigrate;
	if (move_charge_at_immigrate) {
		struct mm_struct *mm;
		struct mem_cgroup *from = mem_cgroup_from_task(p);

		VM_BUG_ON(from == memcg);

		mm = get_task_mm(p);
		if (!mm)
			return 0;
		/* We move charges only when we move a owner of the mm */
		if (mm->owner == p) {
			VM_BUG_ON(mc.from);
			VM_BUG_ON(mc.to);
			VM_BUG_ON(mc.precharge);
			VM_BUG_ON(mc.moved_charge);
			VM_BUG_ON(mc.moved_swap);
			mem_cgroup_start_move(from);
			spin_lock(&mc.lock);
			mc.from = from;
			mc.to = memcg;
			mc.immigrate_flags = move_charge_at_immigrate;
			spin_unlock(&mc.lock);
			/* We set mc.moving_task later */

			ret = mem_cgroup_precharge_mc(mm);
			if (ret)
				mem_cgroup_clear_mc();
		}
		mmput(mm);
	}
	return ret;
}

static void mem_cgroup_cancel_attach(struct cgroup *cgroup,
				     struct cgroup_taskset *tset)
{
	mem_cgroup_clear_mc();
}

static int mem_cgroup_move_charge_pte_range(pmd_t *pmd,
				unsigned long addr, unsigned long end,
				struct mm_walk *walk)
{
	int ret = 0;
	struct vm_area_struct *vma = walk->private;
	pte_t *pte;
	spinlock_t *ptl;
	enum mc_target_type target_type;
	union mc_target target;
	struct page *page;
	struct page_cgroup *pc;

	/*
	 * We don't take compound_lock() here but no race with splitting thp
	 * happens because:
	 *  - if pmd_trans_huge_lock() returns 1, the relevant thp is not
	 *    under splitting, which means there's no concurrent thp split,
	 *  - if another thread runs into split_huge_page() just after we
	 *    entered this if-block, the thread must wait for page table lock
	 *    to be unlocked in __split_huge_page_splitting(), where the main
	 *    part of thp split is not executed yet.
	 */
	if (pmd_trans_huge_lock(pmd, vma, &ptl) == 1) {
		if (mc.precharge < HPAGE_PMD_NR) {
			spin_unlock(ptl);
			return 0;
		}
		target_type = get_mctgt_type_thp(vma, addr, *pmd, &target);
		if (target_type == MC_TARGET_PAGE) {
			page = target.page;
			if (!isolate_lru_page(page)) {
				pc = lookup_page_cgroup(page);
				if (!mem_cgroup_move_account(page, HPAGE_PMD_NR,
							pc, mc.from, mc.to)) {
					mc.precharge -= HPAGE_PMD_NR;
					mc.moved_charge += HPAGE_PMD_NR;
				}
				putback_lru_page(page);
			}
			put_page(page);
		}
		spin_unlock(ptl);
		return 0;
	}

	if (pmd_trans_unstable(pmd))
		return 0;
retry:
	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	for (; addr != end; addr += PAGE_SIZE) {
		pte_t ptent = *(pte++);
		swp_entry_t ent;

		if (!mc.precharge)
			break;

		switch (get_mctgt_type(vma, addr, ptent, &target)) {
		case MC_TARGET_PAGE:
			page = target.page;
			if (isolate_lru_page(page))
				goto put;
			pc = lookup_page_cgroup(page);
			if (!mem_cgroup_move_account(page, 1, pc,
						     mc.from, mc.to)) {
				mc.precharge--;
				/* we uncharge from mc.from later. */
				mc.moved_charge++;
			}
			putback_lru_page(page);
put:			/* get_mctgt_type() gets the page */
			put_page(page);
			break;
		case MC_TARGET_SWAP:
			ent = target.ent;
			if (!mem_cgroup_move_swap_account(ent, mc.from, mc.to)) {
				mc.precharge--;
				/* we fixup refcnts and charges later. */
				mc.moved_swap++;
			}
			break;
		default:
			break;
		}
	}
	pte_unmap_unlock(pte - 1, ptl);
	cond_resched();

	if (addr != end) {
		/*
		 * We have consumed all precharges we got in can_attach().
		 * We try charge one by one, but don't do any additional
		 * charges to mc.to if we have failed in charge once in attach()
		 * phase.
		 */
		ret = mem_cgroup_do_precharge(1);
		if (!ret)
			goto retry;
	}

	return ret;
}

static void mem_cgroup_move_charge(struct mm_struct *mm)
{
	struct vm_area_struct *vma;

	lru_add_drain_all();
retry:
	if (unlikely(!down_read_trylock(&mm->mmap_sem))) {
		/*
		 * Someone who are holding the mmap_sem might be waiting in
		 * waitq. So we cancel all extra charges, wake up all waiters,
		 * and retry. Because we cancel precharges, we might not be able
		 * to move enough charges, but moving charge is a best-effort
		 * feature anyway, so it wouldn't be a big problem.
		 */
		__mem_cgroup_clear_mc();
		cond_resched();
		goto retry;
	}
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		int ret;
		struct mm_walk mem_cgroup_move_charge_walk = {
			.pmd_entry = mem_cgroup_move_charge_pte_range,
			.mm = mm,
			.private = vma,
		};
		if (is_vm_hugetlb_page(vma))
			continue;
		ret = walk_page_range(vma->vm_start, vma->vm_end,
						&mem_cgroup_move_charge_walk);
		if (ret)
			/*
			 * means we have consumed all precharges and failed in
			 * doing additional charge. Just abandon here.
			 */
			break;
	}
	up_read(&mm->mmap_sem);
}

static void mem_cgroup_move_task(struct cgroup *cont,
				 struct cgroup_taskset *tset)
{
	struct task_struct *p = cgroup_taskset_first(tset);
	struct mm_struct *mm = get_task_mm(p);

	if (mm) {
		if (mc.to)
			mem_cgroup_move_charge(mm);
		mmput(mm);
	}
	if (mc.to)
		mem_cgroup_clear_mc();
}
#else	/* !CONFIG_MMU */
static int mem_cgroup_can_attach(struct cgroup *cgroup,
				 struct cgroup_taskset *tset)
{
	return 0;
}
static void mem_cgroup_cancel_attach(struct cgroup *cgroup,
				     struct cgroup_taskset *tset)
{
}
static void mem_cgroup_move_task(struct cgroup *cont,
				 struct cgroup_taskset *tset)
{
}
#endif

/*
 * Cgroup retains root cgroups across [un]mount cycles making it necessary
 * to verify sane_behavior flag on each mount attempt.
 */
static void mem_cgroup_bind(struct cgroup *root)
{
	/*
	 * use_hierarchy is forced with sane_behavior.  cgroup core
	 * guarantees that @root doesn't have any children, so turning it
	 * on for the root memcg is enough.
	 */
	if (cgroup_sane_behavior(root))
		mem_cgroup_from_cont(root)->use_hierarchy = true;
}

struct cgroup_subsys mem_cgroup_subsys = {
	.name = "memory",
	.subsys_id = mem_cgroup_subsys_id,
	.css_alloc = mem_cgroup_css_alloc,
	.css_online = mem_cgroup_css_online,
	.css_offline = mem_cgroup_css_offline,
	.css_free = mem_cgroup_css_free,
	.can_attach = mem_cgroup_can_attach,
	.cancel_attach = mem_cgroup_cancel_attach,
	.attach = mem_cgroup_move_task,
	.bind = mem_cgroup_bind,
	.base_cftypes = mem_cgroup_files,
	.early_init = 0,
};

#ifdef CONFIG_MEMCG_SWAP
static int __init enable_swap_account(char *s)
{
	/* consider enabled if no parameter or 1 is given */
	if (!strcmp(s, "1"))
		really_do_swap_account = 1;
	else if (!strcmp(s, "0"))
		really_do_swap_account = 0;
	return 1;
}
__setup("swapaccount=", enable_swap_account);

static void __init memsw_file_init(void)
{
	WARN_ON(cgroup_add_cftypes(&mem_cgroup_subsys, memsw_cgroup_files));
}

static void __init enable_swap_cgroup(void)
{
	if (!mem_cgroup_disabled() && really_do_swap_account) {
		do_swap_account = 1;
		memsw_file_init();
	}
}

#else
static void __init enable_swap_cgroup(void)
{
}
#endif

static int __init cgroup_memory(char *s)
{
	char *token;

	while ((token = strsep(&s, ",")) != NULL) {
		if (!*token)
			continue;
		if (!strcmp(token, "nokmem"))
			cgroup_memory_nokmem = true;
	}
	return 0;
}
__setup("cgroup.memory=", cgroup_memory);

/*
 * subsys_initcall() for memory controller.
 *
 * Some parts like hotcpu_notifier() have to be initialized from this context
 * because of lock dependencies (cgroup_lock -> cpu hotplug) but basically
 * everything that doesn't depend on a specific mem_cgroup structure should
 * be initialized from here.
 */
static int __init mem_cgroup_init(void)
{
	hotcpu_notifier(memcg_cpu_hotplug_callback, 0);
	enable_swap_cgroup();
	mem_cgroup_soft_limit_tree_init();
	memcg_stock_init();
	return 0;
}
subsys_initcall(mem_cgroup_init);
