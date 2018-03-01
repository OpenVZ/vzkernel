/*
 *  mm/tcache.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/rwsem.h>
#include <linux/pagemap.h>
#include <linux/rbtree.h>
#include <linux/radix-tree.h>
#include <linux/idr.h>
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/jhash.h>
#include <linux/completion.h>
#include <linux/shrinker.h>
#include <linux/vmstat.h>
#include <linux/swap.h>
#include <linux/cleancache.h>

/* cleancache_put_page is called from atomic context */
#define TCACHE_GFP_MASK			(__GFP_NORETRY | __GFP_NOWARN)

struct tcache_node_tree {
	struct rb_root			root;
	spinlock_t			lock;
};

/*
 * Per NUMA node data of a tcache_pool. Protected by tcache_nodeinfo->lock.
 */
struct tcache_pool_nodeinfo {
	struct tcache_pool		*pool;

	/* node in tcache_nodeinfo->reclaim_tree */
	struct rb_node			reclaim_node;

	/* LRU list of pages, linked through page->lru */
	struct list_head		lru;

	/* number of pages on the LRU list */
	unsigned long			nr_pages;

	/* recent number of successful gets and puts from the pool;
	 * used in calculating reclaim prio */
	unsigned long			recent_gets;
	unsigned long			recent_puts;

	/* reuse_ratio is basically recent_gets / recent_puts;
	 * it shows the efficiency of the pool */
	unsigned long			reuse_ratio;

	/* timestamp of the eldest page on the LRU list */
	unsigned long			timestamp;

	/* increased on every LRU add/del, reset once it gets big enough;
	 * used for rate limiting rebalancing of reclaim_tree */
	unsigned long			events;
	spinlock_t			lock;
} ____cacheline_aligned_in_smp;

/*
 * Tcache pools correspond to super blocks. A pool is created on FS mount
 * (cleancache_init_fs) and destroyed on unmount (cleancache_invalidate_fs).
 */
struct tcache_pool {
	/*
	 * Reference counter. Pool destruction (triggered by unmount) will
	 * actually start only after it reaches zero.
	 *
	 * Initialized to 1 on creation, decremented on destruction. May be
	 * held temporarily by active users.
	 */
	struct kref			kref;

	/*
	 * Binary search trees of tcache_node structs that belong to this pool.
	 * Linked by tcache_node->tree_node.
	 */
	struct tcache_node_tree		*node_tree;

	/* track total number of nodes in each pool for debugging */
	atomic_long_t			nr_nodes;

	/* used to synchronize destruction */
	struct completion		completion;
	struct rcu_head			rcu;

	/* Per NUMA node data. This must be the last element of the struct. */
	struct tcache_pool_nodeinfo	nodeinfo[0];
};

static atomic_long_t nr_tcache_nodes;

/*
 * Tcache nodes correspond to inodes. A node is created automatically when a
 * new page is added to the cache (cleancache_put_page) and destroyed either
 * when the corresponding inode is invalidated (cleancache_invalidate_inode) or
 * when the last page is removed from it (by the shrinker, cleancache_get_page,
 * or cleancache_invalidate_page).
 */
struct tcache_node {
	/*
	 * Reference counter. Node is freed when it reaches zero.
	 *
	 * Incremented when the first page is attached to the node (node
	 * becomes non-empty) and decremented when the last page is detached
	 * (node becomes empty). May also be held temporarily by active users.
	 *
	 * Note that a node with a non-zero reference count is not guaranteed
	 * to be present on the tcache_pool->node_tree - it could have been
	 * removed by cleancache_invalidate_inode. However, if a node is found
	 * on the tree with the tree_lock held, it must have a positive
	 * reference count.
	 */
	struct kref			kref;

	struct tcache_pool		*pool;
	struct cleancache_filekey	key;
	struct rb_node			tree_node;

	/*
	 * Radix tree of pages attached to this node. Protected by tree_lock.
	 */
	struct radix_tree_root		page_tree;
	spinlock_t			tree_lock;

	unsigned long			nr_pages;
	bool				invalidated;
};

/*
 * To reduce contention on tcache_node_tree->lock, we maintain several trees
 * per each pool and distribute nodes among them in accordance with their hash.
 */
static int num_node_trees __read_mostly = 1;

/*
 * tcache_pool_idr provides id -> tcache_pool map. Lookups are lock free (RCU).
 * Updated are protected by the tcache_pool_lock.
 */
static DEFINE_IDR(tcache_pool_idr);
static DEFINE_SPINLOCK(tcache_pool_lock);

struct tcache_nodeinfo {
	spinlock_t lock;

	/* tree of pools, sorted by reclaim prio */
	struct rb_root reclaim_tree;
	struct rb_node __rcu *rb_first;

	/* total number of pages on all LRU lists corresponding to this node */
	atomic_long_t nr_pages;
} ____cacheline_aligned_in_smp;

/*
 * Global per NUMA node data.
 */
static struct tcache_nodeinfo *tcache_nodeinfo;

/*
 * Locking rules:
 *
 *  tcache_node->tree_lock
 *       tcache_node_tree->lock
 *       tcache_nodeinfo->lock
 */

/* Enable/disable tcache backend (set at boot time) */
static bool tcache_enabled __read_mostly = true;
module_param_named(enabled, tcache_enabled, bool, 0444);

/* Enable/disable populating the cache */
static bool tcache_active __read_mostly = true;
module_param_named(active, tcache_active, bool, 0644);

/*
 * How long a tcache page is considered active, i.e. likely to be reused.
 * A pool that contains only active pages will be given a boost over other
 * pools while selecting a reclaim target.
 */
static unsigned long tcache_active_interval __read_mostly = 60 * HZ;

/* Total number of pages cached */
static DEFINE_PER_CPU(long, nr_tcache_pages);

static inline u32 key_hash(const struct cleancache_filekey *key)
{
	return jhash2(key->u.key, CLEANCACHE_KEY_MAX, 0);
}

static inline struct tcache_node_tree *
node_tree_from_key(struct tcache_pool *pool,
		   const struct cleancache_filekey *key)
{
	return &pool->node_tree[key_hash(key) & (num_node_trees - 1)];
}

static struct rb_node *update_ni_rb_first(struct tcache_nodeinfo *ni)
{
	struct rb_node *first = rb_first(&ni->reclaim_tree);
	rcu_assign_pointer(ni->rb_first, first);
	return first;
}

static void __tcache_insert_reclaim_node(struct tcache_nodeinfo *ni,
					 struct tcache_pool_nodeinfo *pni);

static inline bool tcache_check_events(struct tcache_pool_nodeinfo *pni)
{
	/*
	 * We don't want to rebalance reclaim_tree on each get/put, because it
	 * would be way too costly. Instead we count get/put events per each
	 * pool and update a pool's reclaim prio only once the counter gets big
	 * enough. This should yield satisfactory reclaim fairness while still
	 * keeping the cost of get/put low.
	 */
	pni->events++;
	if (likely(pni->events < 1024))
		return false;

	pni->events = 0;

	/*
	 * The pool is empty, so there's no point in adding it to the
	 * reclaim_tree. Neither do we need to remove it from the tree -
	 * it will be done by the shrinker once it tries to scan it.
	 */
	if (unlikely(list_empty(&pni->lru)))
		return false;

	/*
	 * This can only happen if the node was removed from the tree on pool
	 * destruction (see tcache_remove_from_reclaim_trees()). Nothing to do
	 * then.
	 */
	if (unlikely(RB_EMPTY_NODE(&pni->reclaim_node)))
		return false;

	return true;
}

/*
 * Add a page to the LRU list. This effectively makes the page visible to the
 * shrinker, so it must only be called after the page was properly initialized
 * and added to the corresponding page tree.
 */
static void tcache_lru_add(struct tcache_pool *pool, struct page *page)
{
	int nid = page_to_nid(page);
	struct tcache_nodeinfo *ni = &tcache_nodeinfo[nid];
	struct tcache_pool_nodeinfo *pni = &pool->nodeinfo[nid];

	atomic_long_inc(&ni->nr_pages);

	spin_lock(&pni->lock);
	pni->nr_pages++;
	list_add_tail(&page->lru, &pni->lru);

	pni->recent_puts++;
	if (unlikely(pni->recent_puts > pni->nr_pages / 2)) {
		pni->recent_gets /= 2;
		pni->recent_puts /= 2;
	}

	if (tcache_check_events(pni) || RB_EMPTY_NODE(&pni->reclaim_node)) {
		spin_lock(&ni->lock);
		if (!RB_EMPTY_NODE(&pni->reclaim_node))
			rb_erase(&pni->reclaim_node, &ni->reclaim_tree);
		__tcache_insert_reclaim_node(ni, pni);
		update_ni_rb_first(ni);
		spin_unlock(&ni->lock);
	}
	spin_unlock(&pni->lock);
}

static void __tcache_lru_del(struct tcache_pool_nodeinfo *pni,
			     struct page *page)
{
	pni->nr_pages--;
	list_del_init(&page->lru);
}

/*
 * Remove a page from the LRU list. This function is safe to call on the same
 * page from concurrent threads - the page will be removed only once.
 */
static void tcache_lru_del(struct tcache_pool *pool, struct page *page,
			   bool reused)
{
	int nid = page_to_nid(page);
	struct tcache_nodeinfo *ni = &tcache_nodeinfo[nid];
	struct tcache_pool_nodeinfo *pni = &pool->nodeinfo[nid];
	bool deleted = false;

	spin_lock(&pni->lock);

	/* Raced with reclaimer? */
	if (unlikely(list_empty(&page->lru)))
		goto out;

	__tcache_lru_del(pni, page);
	deleted = true;

	if (reused)
		pni->recent_gets++;

	if (tcache_check_events(pni)) {
		spin_lock(&ni->lock);
		if (!RB_EMPTY_NODE(&pni->reclaim_node))
			rb_erase(&pni->reclaim_node, &ni->reclaim_tree);
		__tcache_insert_reclaim_node(ni, pni);
		update_ni_rb_first(ni);
		spin_unlock(&ni->lock);
	}
out:
	spin_unlock(&pni->lock);
	if (deleted)
		atomic_long_dec(&ni->nr_pages);
}

static int tcache_create_pool(void)
{
	size_t size;
	struct tcache_pool *pool;
	struct tcache_pool_nodeinfo *pni;
	int id;
	int i;

	size = sizeof(struct tcache_pool);
	size += nr_node_ids * sizeof(struct tcache_pool_nodeinfo);

	pool = kzalloc(size, GFP_KERNEL);
	if (!pool)
		goto fail;

	pool->node_tree = kcalloc(num_node_trees, sizeof(*pool->node_tree),
				  GFP_KERNEL);
	if (!pool->node_tree)
		goto free_pool;

	kref_init(&pool->kref);
	init_completion(&pool->completion);

	for (i = 0; i < num_node_trees; i++) {
		pool->node_tree[i].root = RB_ROOT;
		spin_lock_init(&pool->node_tree[i].lock);
	}

	for (i = 0; i < nr_node_ids; i++) {
		pni = &pool->nodeinfo[i];
		pni->pool = pool;
		RB_CLEAR_NODE(&pni->reclaim_node);
		INIT_LIST_HEAD(&pni->lru);
		spin_lock_init(&pni->lock);
	}

	idr_preload(GFP_KERNEL);
	spin_lock(&tcache_pool_lock);

	id = idr_alloc(&tcache_pool_idr, pool, 0, 0, GFP_NOWAIT);

	spin_unlock(&tcache_pool_lock);
	idr_preload_end();

	if (id < 0)
		goto free_trees;
	return id;

free_trees:
	kfree(pool->node_tree);
free_pool:
	kfree(pool);
fail:
	return -1;
}

/*
 * Take a reference to a pool unless it is being destroyed. Returns true on
 * success, false on failure. The caller must guarantee that the pool can be
 * safely dereferenced.
 */
static bool tcache_grab_pool(struct tcache_pool *pool)
{
	return kref_get_unless_zero(&pool->kref);
}

static void tcache_hold_pool(struct tcache_pool *pool)
{
	kref_get(&pool->kref);
}

/*
 * Return the pool corresponding to an id (or NULL if there is no such). The
 * reference counter of the returned pool is incremented.
 */
static struct tcache_pool *tcache_get_pool(int id)
{
	struct tcache_pool *pool;

	if (id < 0)
		return NULL;

	rcu_read_lock();
	pool = idr_find(&tcache_pool_idr, id);
	if (pool && !tcache_grab_pool(pool))
		pool = NULL;
	rcu_read_unlock();

	return pool;
}

static void tcache_pool_release_fn(struct kref *kref)
{
	struct tcache_pool *pool = container_of(kref, struct tcache_pool, kref);

	/*
	 * Notify tcache_destroy_pool that it is now safe to proceed to
	 * destruction.
	 */
	complete(&pool->completion);
}

/*
 * Release reference to a pool taken by tcache_grab_pool or tcache_get_pool.
 */
static inline void tcache_put_pool(struct tcache_pool *pool)
{
	kref_put(&pool->kref, tcache_pool_release_fn);
}

static void tcache_remove_from_reclaim_trees(struct tcache_pool *pool);
static void tcache_invalidate_node_tree(struct tcache_node_tree *tree);

static void tcache_destroy_pool(int id)
{
	int i;
	struct tcache_pool *pool;
	unsigned long nr_nodes;

	spin_lock(&tcache_pool_lock);
	pool = idr_find(&tcache_pool_idr, id);
	if (pool)
		idr_remove(&tcache_pool_idr, id);
	spin_unlock(&tcache_pool_lock);

	if (!pool)
		return;

	tcache_put_pool(pool);

	/*
	 * Wait until all references to this pool are released.
	 *
	 * We removed the pool from id -> pool map, so now new references can
	 * only be taken by the shrinker. The latter takes a reference to this
	 * pool only in order to remove a page from it. Since no new pages can
	 * be added to the pool, we are guaranteed to make progress.
	 */
	wait_for_completion(&pool->completion);

	tcache_remove_from_reclaim_trees(pool);

	for (i = 0; i < num_node_trees; i++)
		tcache_invalidate_node_tree(&pool->node_tree[i]);

	nr_nodes = atomic_long_read(&pool->nr_nodes);
	if (WARN(nr_nodes != 0, "pool->nr_nodes %ld", nr_nodes))
		return;

	kfree(pool->node_tree);
	kfree_rcu(pool, rcu);
}

static struct tcache_node *tcache_alloc_node(void)
{
	struct tcache_node *node;

	node = kzalloc(sizeof(*node), TCACHE_GFP_MASK);
	if (!node)
		return NULL;

	kref_init(&node->kref);
	INIT_RADIX_TREE(&node->page_tree, TCACHE_GFP_MASK);
	spin_lock_init(&node->tree_lock);

	return node;
}

static struct tcache_node *__tcache_lookup_node(struct rb_root *rb_root,
		const struct cleancache_filekey *key,
		struct rb_node ***rb_link, struct rb_node **rb_parent)
{
	struct rb_node **__rb_link = &rb_root->rb_node;
	struct rb_node *__rb_parent = NULL;
	struct tcache_node *node;
	int ret;

	*rb_link = NULL;
	*rb_parent = NULL;

	while (*__rb_link) {
		__rb_parent = *__rb_link;
		node = rb_entry(__rb_parent, struct tcache_node, tree_node);

		ret = memcmp(&node->key, key, sizeof(*key));
		if (ret > 0)
			__rb_link = &__rb_parent->rb_left;
		else if (ret < 0)
			__rb_link = &__rb_parent->rb_right;
		else
			return node;
	}

	*rb_parent = __rb_parent;
	*rb_link = __rb_link;

	return NULL;
}

static void __tcache_insert_node(struct rb_root *rb_root,
		struct tcache_node *node,
		struct rb_node **rb_link, struct rb_node *rb_parent)
{
	rb_link_node(&node->tree_node, rb_parent, rb_link);
	rb_insert_color(&node->tree_node, rb_root);
}

static void __tcache_delete_node(struct rb_root *rb_root,
				 struct tcache_node *node)
{
	/*
	 * A node is deleted from the tree automatically by the node release
	 * function as soon as the last reference to it has been dropped (all
	 * pages and users have gone), but it can also be deleted explicitly by
	 * tcache_invalidate_node, in which case the release function will
	 * receive a node which is already not on the tree.
	 */
	if (!RB_EMPTY_NODE(&node->tree_node)) {
		rb_erase(&node->tree_node, rb_root);
		RB_CLEAR_NODE(&node->tree_node);
	}
}

/*
 * Take a reference to a node. The caller must guarantee that the node has a
 * positive reference count. In particular, the function is safe to call if the
 * node is known to be on the tree.
 */
static inline void tcache_hold_node(struct tcache_node *node)
{
	kref_get(&node->kref);
}

/*
 * Find and get a reference to the node corresponding to a key in a pool. If
 * the requested node does not exist and may_create is true, try to create a
 * new one.
 */
static noinline_for_stack struct tcache_node *
tcache_get_node(struct tcache_pool *pool, const struct cleancache_filekey *key,
		bool may_create)
{
	struct tcache_node_tree *tree;
	struct tcache_node *new_node = NULL, *node;
	struct rb_node **rb_link, *rb_parent;
	unsigned long flags;

	tree = node_tree_from_key(pool, key);
retry:
	spin_lock_irqsave(&tree->lock, flags);
	node = __tcache_lookup_node(&tree->root, key, &rb_link, &rb_parent);
	if (node)
		tcache_hold_node(node);
	else if (new_node) {
		node = new_node;
		node->pool = pool;
		node->key = *key;
		atomic_long_inc(&pool->nr_nodes);
		atomic_long_inc(&nr_tcache_nodes);
		__tcache_insert_node(&tree->root, node, rb_link, rb_parent);
	}
	spin_unlock_irqrestore(&tree->lock, flags);

	if (node) {
		if (node != new_node)
			kfree(new_node);
		if (WARN_ON(node->pool != pool))
			node = NULL;
		return node;
	}

	if (may_create) {
		new_node = tcache_alloc_node();
		if (new_node)
			goto retry;
	}
	return NULL;
}

static void tcache_node_release_fn(struct kref *kref)
{
	struct tcache_node *node = container_of(kref, struct tcache_node, kref);
	struct tcache_node_tree *tree;

	tree = node_tree_from_key(node->pool, &node->key);

	__tcache_delete_node(&tree->root, node);
	spin_unlock(&tree->lock);

	atomic_long_dec(&nr_tcache_nodes);
	atomic_long_dec(&node->pool->nr_nodes);
	kfree(node);
}

/*
 * Release a reference to a node taken by tcache_hold_node or tcache_get_node.
 */
static inline void tcache_put_node(struct tcache_node *node)
{
	struct tcache_node_tree *tree;

	tree = node_tree_from_key(node->pool, &node->key);
	kref_put_spinlock_irqsave(&node->kref, tcache_node_release_fn,
				  &tree->lock);
}

static struct tcache_node *tcache_get_node_and_pool(int pool_id,
		const struct cleancache_filekey *key, bool may_create)
{
	struct tcache_pool *pool;
	struct tcache_node *node;

	pool = tcache_get_pool(pool_id);
	if (!pool)
		return NULL;
	node = tcache_get_node(pool, key, may_create);
	if (!node)
		tcache_put_pool(pool);
	return node;
}

static void tcache_put_node_and_pool(struct tcache_node *node)
{
	struct tcache_pool *pool = node->pool;

	tcache_put_node(node);
	tcache_put_pool(pool);
}

static void tcache_invalidate_node_pages(struct tcache_node *node);

/*
 * Remove a node from the tree and invalidate its pages.
 */
static void tcache_invalidate_node(struct tcache_pool *pool,
				   const struct cleancache_filekey *key)
{
	struct tcache_node_tree *tree;
	struct tcache_node *node;
	struct rb_node **rb_link, *rb_parent;

	tree = node_tree_from_key(pool, key);

	spin_lock_irq(&tree->lock);
	node = __tcache_lookup_node(&tree->root, key, &rb_link, &rb_parent);
	if (node) {
		tcache_hold_node(node);
		node->invalidated = true;
		__tcache_delete_node(&tree->root, node);
	}
	spin_unlock_irq(&tree->lock);

	if (node) {
		tcache_invalidate_node_pages(node);
		tcache_put_node(node);
	}
}

static noinline_for_stack void
tcache_invalidate_node_tree(struct tcache_node_tree *tree)
{
	struct tcache_node *node;

	/*
	 * There is no need to take tree->lock, because this function is only
	 * called when the pool is about to be destroyed.
	 */
	while (!RB_EMPTY_ROOT(&tree->root)) {
		node = rb_entry(rb_first(&tree->root),
				struct tcache_node, tree_node);

		/* Remaining nodes must be held solely by their pages */
		WARN_ON(atomic_read(&node->kref.refcount) != 1);
		WARN_ON(node->nr_pages == 0);
		WARN_ON(node->invalidated);
		node->invalidated = true;

		tcache_hold_node(node);
		tcache_invalidate_node_pages(node);
		tcache_put_node(node);
	}
}

static inline struct tcache_node *tcache_page_node(struct page *page)
{
	return (struct tcache_node *)page->mapping;
}

static inline unsigned long tcache_page_timestamp(struct page *page)
{
	return page->private;
}

static inline void tcache_init_page(struct page *page,
				    struct tcache_node *node, pgoff_t index)
{
	page->mapping = (struct address_space *)node;
	page->private = jiffies;
	page->index = index;
}

static inline void tcache_put_page(struct page *page)
{
	page->mapping = NULL;
	free_hot_cold_page(page, false);
}

static int tcache_page_tree_insert(struct tcache_node *node, pgoff_t index,
				    struct page *page)
{
	int err = 0;

	/*
	 * If the node was invalidated after we looked it up, abort in order to
	 * avoid clashes with tcache_invalidate_node_pages.
	 */
	if (unlikely(node->invalidated)) {
		err = -EAGAIN;
		goto out;
	}

	err = radix_tree_insert(&node->page_tree, index, page);
	if (!err) {
		if (!node->nr_pages++)
			tcache_hold_node(node);
		__this_cpu_inc(nr_tcache_pages);
		__inc_zone_page_state(page, NR_FILE_PAGES);
	}
out:
	return err;
}

static struct page *__tcache_page_tree_delete(struct tcache_node *node,
					      pgoff_t index, struct page *page)
{
	if (!page_ref_freeze(page, 2)) {
		put_page(page);
		return NULL;
	}

	page = radix_tree_delete_item(&node->page_tree, index, page);
	if (page) {
		if (!--node->nr_pages)
			tcache_put_node(node);
		__this_cpu_dec(nr_tcache_pages);
		__dec_zone_page_state(page, NR_FILE_PAGES);
	}
	return page;
}

static struct page *tcache_page_tree_delete(struct tcache_node *node,
					    pgoff_t index, struct page *page)
{
	spin_lock(&node->tree_lock);
	page = __tcache_page_tree_delete(node, index, page);
	spin_unlock(&node->tree_lock);
	return page;
}

/*
 * Attempt to attach a page to a node at a given offset. If there is already a
 * page at the given offset, it will be replaced. Returns 0 on success. The
 * caller must put the page no matter if the function succeeds or fails.
 */
static noinline_for_stack int
tcache_attach_page(struct tcache_node *node, pgoff_t index, struct page *page)
{
	unsigned long flags;
	int err = 0;

	tcache_init_page(page, node, index);
	/*
	 * Disabling of irqs implies rcu_read_lock_sched().
	 * See tcache_invalidate_node_pages() for details.
	 */
	spin_lock_irqsave(&node->tree_lock, flags);
	err = tcache_page_tree_insert(node, index, page);
	spin_unlock(&node->tree_lock);
	if (!err)
		tcache_lru_add(node->pool, page);
	local_irq_restore(flags); /* Implies rcu_read_lock_sched() */
	return err;
}

/*
 * Detach and return the page at a given offset of a node. The caller must put
 * the page when it is done with it.
 */
static struct page *tcache_detach_page(struct tcache_node *node, pgoff_t index,
				       bool reused)
{
	void **pagep;
	unsigned long flags;
	struct page *page;

	rcu_read_lock();
repeat:
	page = NULL;
	pagep = radix_tree_lookup_slot(&node->page_tree, index);
	if (pagep) {
		page = radix_tree_deref_slot(pagep);
		if (unlikely(!page))
			goto out;
		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page))
				goto repeat;
			WARN_ON(1);
		}
		if (!page_cache_get_speculative(page))
			goto repeat;
		/*
		 * Has the page moved?
		 * This is part of the lockless pagecache protocol. See
		 * include/linux/pagemap.h for details.
		 */
		if (unlikely(page != *pagep)) {
			put_page(page);
			goto repeat;
		}
	}
out:
	rcu_read_unlock();

	if (page) {
		local_irq_save(flags);
		page = tcache_page_tree_delete(node, index, page);
		if (page)
			tcache_lru_del(node->pool, page, reused);
		local_irq_restore(flags);
		/*
		 * Shrinker could isolated the page in parallel
		 * with us. This case page_ref_freeze(page, 2)
		 * in __tcache_page_tree_delete() fails, and
		 * we have to repeat the cycle.
		 */
		if (!page)
			goto repeat;
	}

	return page;
}

static unsigned tcache_lookup(struct page **pages, struct tcache_node *node,
			pgoff_t start, unsigned int nr_pages, pgoff_t *indices)
{
	struct radix_tree_iter iter;
	unsigned int ret = 0;
	void **slot;

	if (!nr_pages)
		return 0;

	rcu_read_lock();
restart:
	radix_tree_for_each_slot(slot, &node->page_tree, &iter, start) {
		struct page *page;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;

		if (radix_tree_exception(page) && radix_tree_deref_retry(page))
			goto restart;

		if (!page_cache_get_speculative(page))
			goto repeat;

		/* Has the page moved? */
		if (unlikely(page != *slot)) {
			page_cache_release(page);
			goto repeat;
		}

		indices[ret] = iter.index;
		pages[ret] = page;
		if (++ret == nr_pages)
			break;
	}
	rcu_read_unlock();
	return ret;
}

#define TCACHE_PAGEVEC_SIZE 16
static noinline_for_stack void
tcache_invalidate_node_pages(struct tcache_node *node)
{
	bool repeat = false, synchronize_sched_once = true;
	pgoff_t indices[TCACHE_PAGEVEC_SIZE];
	struct page *pages[TCACHE_PAGEVEC_SIZE];
	pgoff_t index;
	unsigned nr_pages;
	int i;

	/*
	 * First forbid new page insertions - see tcache_page_tree_replace.
	 */
again:
	index = 0;
	while ((nr_pages = tcache_lookup(pages, node, index,
						TCACHE_PAGEVEC_SIZE, indices))) {
		for (i = 0; i < nr_pages; i++) {
			struct page *page = pages[i];

			index = indices[i];

			spin_lock_irq(&node->tree_lock);
			page = __tcache_page_tree_delete(node, page->index, page);
			spin_unlock(&node->tree_lock);

			if (page) {
				tcache_lru_del(node->pool, page, false);
				local_irq_enable();
				tcache_put_page(page);
			} else {
				/* Race with page_ref_freeze() */
				local_irq_enable();
				repeat = true;
			}
		}
		cond_resched();
		index++;
	}

	if (synchronize_sched_once) {
		synchronize_sched_once = false;
		if (!repeat) {
			/* Race with tcache_attach_page() */
			spin_lock_irq(&node->tree_lock);
			repeat = (node->nr_pages != 0);
			spin_unlock_irq(&node->tree_lock);
		}
		if (repeat) {
			synchronize_sched();
			goto again;
		}
	}

	WARN_ON(node->nr_pages != 0);
}

static noinline_for_stack void
tcache_remove_from_reclaim_trees(struct tcache_pool *pool)
{
	int i;
	struct tcache_nodeinfo *ni;
	struct tcache_pool_nodeinfo *pni;

	for (i = 0; i < nr_node_ids; i++) {
		ni = &tcache_nodeinfo[i];
		pni = &pool->nodeinfo[i];

		spin_lock_irq(&ni->lock);
		if (!RB_EMPTY_NODE(&pni->reclaim_node)) {
			rb_erase(&pni->reclaim_node, &ni->reclaim_tree);
			update_ni_rb_first(ni);
			/*
			 * Clear the node for tcache_check_events() not to
			 * reinsert the pool back into the tree.
			 */
			RB_CLEAR_NODE(&pni->reclaim_node);
		}
		spin_unlock_irq(&ni->lock);
	}
}

static inline bool tcache_reclaim_node_before(struct tcache_pool_nodeinfo *a,
					      struct tcache_pool_nodeinfo *b,
					      unsigned long now)
{
	bool a_active = now - a->timestamp < tcache_active_interval;
	bool b_active = now - b->timestamp < tcache_active_interval;

	/*
	 * Always favor active pools over inactive. If the two pools are both
	 * active or both inactive, the order in the reclaim_tree is determined
	 * by the reuse ratio.
	 */
	if (a_active && !b_active)
		return false;
	if (!a_active && b_active)
		return true;
	return a->reuse_ratio < b->reuse_ratio;
}

static noinline_for_stack void
__tcache_insert_reclaim_node(struct tcache_nodeinfo *ni,
			     struct tcache_pool_nodeinfo *pni)
{
	struct rb_node **link = &ni->reclaim_tree.rb_node;
	struct rb_node *parent = NULL;
	struct tcache_pool_nodeinfo *pni2;
	unsigned long now = jiffies;

	BUG_ON(list_empty(&pni->lru));

	pni->reuse_ratio = pni->recent_gets * 100 / (pni->recent_puts + 1);
	pni->timestamp = tcache_page_timestamp(list_first_entry(&pni->lru,
							struct page, lru));

	while (*link) {
		parent = *link;
		pni2 = rb_entry(parent, struct tcache_pool_nodeinfo,
				reclaim_node);
		if (tcache_reclaim_node_before(pni, pni2, now))
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}

	rb_link_node(&pni->reclaim_node, parent, link);
	rb_insert_color(&pni->reclaim_node, &ni->reclaim_tree);
}

static noinline_for_stack int
__tcache_lru_isolate(struct tcache_pool_nodeinfo *pni,
		     struct page **pages, int nr_to_scan)
{
	struct tcache_node *node;
	struct page *page;
	int nr_isolated = 0;

	while (nr_to_scan-- > 0 && !list_empty(&pni->lru)) {
		page = list_first_entry(&pni->lru, struct page, lru);

		if (unlikely(!page_cache_get_speculative(page)))
			continue;

		__tcache_lru_del(pni, page);

		/*
		 * A node can be destroyed only if all its pages have been
		 * removed both from the tree and the LRU list. Since we are
		 * holding the LRU lock here and hence preventing the page
		 * from being removed from the LRU list, it is therefore safe
		 * to access the node which the page is attached to.
		 */
		node = tcache_page_node(page);
		tcache_hold_node(node);
		tcache_hold_pool(node->pool);

		pages[nr_isolated++] = page;
	}
	return nr_isolated;
}

static noinline_for_stack int
tcache_lru_isolate(int nid, struct page **pages, int nr_to_isolate)
{
	struct tcache_nodeinfo *ni = &tcache_nodeinfo[nid];
	struct tcache_pool_nodeinfo *pni;
	int nr_isolated = 0;
	struct rb_node *rbn;

	rcu_read_lock();
again:
	rbn = rcu_dereference(ni->rb_first);
	if (!rbn) {
		rcu_read_unlock();
		goto out;
	}

	pni = rb_entry(rbn, struct tcache_pool_nodeinfo, reclaim_node);
	if (!tcache_grab_pool(pni->pool)) {
		spin_lock_irq(&ni->lock);
		if (!RB_EMPTY_NODE(rbn) && list_empty(&pni->lru)) {
			rb_erase(rbn, &ni->reclaim_tree);
			RB_CLEAR_NODE(rbn);
			update_ni_rb_first(ni);
		}
		spin_unlock_irq(&ni->lock);
		goto again;
	}
	rcu_read_unlock();

	spin_lock_irq(&pni->lock);
	nr_isolated = __tcache_lru_isolate(pni, pages, nr_to_isolate);

	if (!nr_isolated)
		goto unlock;

	if (!RB_EMPTY_NODE(rbn) || !list_empty(&pni->lru)) {
		spin_lock(&ni->lock);
		if (!RB_EMPTY_NODE(rbn))
			rb_erase(rbn, &ni->reclaim_tree);
		if (!list_empty(&pni->lru))
			__tcache_insert_reclaim_node(ni, pni);
		else
			RB_CLEAR_NODE(rbn);
		update_ni_rb_first(ni);
		spin_unlock(&ni->lock);
	}
unlock:
	spin_unlock_irq(&pni->lock);
	tcache_put_pool(pni->pool);
out:
	if (nr_isolated)
		atomic_long_sub(nr_isolated, &ni->nr_pages);
	return nr_isolated;
}

static bool __tcache_reclaim_page(struct page *page)
{
	struct tcache_node *node;

	node = tcache_page_node(page);
	page = tcache_page_tree_delete(node, page->index, page);
	tcache_put_node_and_pool(node);
	return (page != NULL);
}

static int tcache_reclaim_pages(struct page **pages, int nr)
{
	int i;
	int nr_reclaimed = 0;

	local_irq_disable();
	for (i = 0; i < nr; i++) {
		if (__tcache_reclaim_page(pages[i])) {
			nr_reclaimed++;
			tcache_put_page(pages[i]);
		}
		pages[i] = NULL;
	}
	local_irq_enable();
	return nr_reclaimed;
}

static noinline_for_stack struct page *
tcache_try_to_reclaim_page(struct tcache_pool *pool, int nid)
{
	struct tcache_nodeinfo *ni = &tcache_nodeinfo[nid];
	struct tcache_pool_nodeinfo *pni = &pool->nodeinfo[nid];
	struct page *page = NULL;
	unsigned long flags;
	int ret;

	local_irq_save(flags);

	spin_lock(&pni->lock);
	ret = __tcache_lru_isolate(pni, &page, 1);
	spin_unlock(&pni->lock);

	if (!ret)
		goto out;

	atomic_long_dec(&ni->nr_pages);

	if (!__tcache_reclaim_page(page))
		page = NULL;
	else
		page_ref_unfreeze(page, 1);
out:
	local_irq_restore(flags);
	return page;
}

static struct page *tcache_alloc_page(struct tcache_pool *pool)
{
	struct page *page;

	page = alloc_page(TCACHE_GFP_MASK | __GFP_HIGHMEM);
	if (!page)
		page = tcache_try_to_reclaim_page(pool, numa_node_id());

	return page;
}

static unsigned long tcache_shrink_count(struct shrinker *shrink,
					 struct shrink_control *sc)
{
	atomic_long_t *nr_pages = &tcache_nodeinfo[sc->nid].nr_pages;
	long ret;

	ret = atomic_long_read(nr_pages);
	WARN_ON(ret < 0);
	return ret >= 0 ? ret : 0;
}

#define TCACHE_SCAN_BATCH 128UL
static DEFINE_PER_CPU(struct page * [TCACHE_SCAN_BATCH], tcache_page_vec);

static unsigned long tcache_shrink_scan(struct shrinker *shrink,
					struct shrink_control *sc)
{
	long nr_isolated, nr_reclaimed;
	struct page **pages;

	pages = get_cpu_var(tcache_page_vec); /* Implies rcu_read_lock_sched() */

	if (WARN_ON(sc->nr_to_scan > TCACHE_SCAN_BATCH))
		sc->nr_to_scan = TCACHE_SCAN_BATCH;

	nr_isolated = tcache_lru_isolate(sc->nid, pages, sc->nr_to_scan);
	if (!nr_isolated) {
		nr_reclaimed = SHRINK_STOP;
		goto out;
	}
	nr_reclaimed = tcache_reclaim_pages(pages, nr_isolated);
	if (current->reclaim_state)
		current->reclaim_state->reclaimed_slab += nr_reclaimed;
out:
	put_cpu_var(tcache_page_vec); /* Implies rcu_read_unlock_sched() */
	return nr_reclaimed;
}

struct shrinker tcache_shrinker = {
	.count_objects		= tcache_shrink_count,
	.scan_objects		= tcache_shrink_scan,
	.seeks			= 8,
	.batch			= TCACHE_SCAN_BATCH,
	.flags			= SHRINKER_NUMA_AWARE,
};

static int tcache_cleancache_init_fs(size_t pagesize)
{
	return tcache_create_pool();
}

static int tcache_cleancache_init_shared_fs(char *uuid, size_t pagesize)
{
	return -1;
}

static int tcache_cleancache_put_page(int pool_id,
				       struct cleancache_filekey key,
				       pgoff_t index, struct page *page)
{
	int ret = 0;
	struct tcache_node *node;
	struct page *cache_page = NULL;

	/* It makes no sense to populate tcache when we are short on memory */
	if (!READ_ONCE(tcache_active) || !(current->flags & PF_MEMCG_RECLAIM))
		return 0;

	node = tcache_get_node_and_pool(pool_id, &key, true);
	if (node) {
		cache_page = tcache_alloc_page(node->pool);
		if (cache_page) {
			copy_highpage(cache_page, page);
			ret = tcache_attach_page(node, index, cache_page);
			if (ret) {
				if (ret == -EEXIST) {
					struct page *page;

					page = tcache_detach_page(node, index, false);
					if (page)
						tcache_put_page(page);
				}
				if (put_page_testzero(cache_page))
					tcache_put_page(cache_page);
				ret = 0;
			} else
				ret = 1;
		}
		tcache_put_node_and_pool(node);
	}

	return ret;
}

static int tcache_cleancache_get_page(int pool_id,
				      struct cleancache_filekey key,
				      pgoff_t index, struct page *page)
{
	struct tcache_node *node;
	struct page *cache_page = NULL;

	if (!atomic_long_read(&nr_tcache_nodes))
		return -1;

	node = tcache_get_node_and_pool(pool_id, &key, false);
	if (node) {
		cache_page = tcache_detach_page(node, index, true);
		if (unlikely(cache_page && node->invalidated)) {
			tcache_put_page(cache_page);
			cache_page = NULL;
		}
		tcache_put_node_and_pool(node);
	}

	if (cache_page) {
		copy_highpage(page, cache_page);
		tcache_put_page(cache_page);
		return 0;
	}
	return -1;
}

static void tcache_cleancache_invalidate_page(int pool_id,
		struct cleancache_filekey key, pgoff_t index)
{
	struct tcache_node *node;
	struct page *page;

	if (!atomic_long_read(&nr_tcache_nodes))
		return;

	node = tcache_get_node_and_pool(pool_id, &key, false);
	if (node) {
		page = tcache_detach_page(node, index, false);
		if (page)
			tcache_put_page(page);
		tcache_put_node_and_pool(node);
	}
}

static void tcache_cleancache_invalidate_inode(int pool_id,
					       struct cleancache_filekey key)
{
	struct tcache_pool *pool;

	if (!atomic_long_read(&nr_tcache_nodes))
		return;

	pool = tcache_get_pool(pool_id);
	if (pool) {
		tcache_invalidate_node(pool, &key);
		tcache_put_pool(pool);
	}
}

static void tcache_cleancache_invalidate_fs(int pool_id)
{
	tcache_destroy_pool(pool_id);
}

static struct cleancache_ops tcache_cleancache_ops = {
	.init_fs		= tcache_cleancache_init_fs,
	.init_shared_fs		= tcache_cleancache_init_shared_fs,
	.put_page		= tcache_cleancache_put_page,
	.get_page		= tcache_cleancache_get_page,
	.invalidate_page	= tcache_cleancache_invalidate_page,
	.invalidate_inode	= tcache_cleancache_invalidate_inode,
	.invalidate_fs		= tcache_cleancache_invalidate_fs,
};

unsigned long get_nr_tcache_pages(void)
{
	int cpu;
	long val = 0;

	for_each_possible_cpu(cpu)
		val += per_cpu(nr_tcache_pages, cpu);
	if (val < 0)
		val = 0;
	return val;
}

static int param_get_nr_pages(char *buffer, const struct kernel_param *kp)
{
	return sprintf(buffer, "%lu", get_nr_tcache_pages());
}

static struct kernel_param_ops param_ops_nr_pages = {
	.get = param_get_nr_pages,
};
module_param_cb(nr_pages, &param_ops_nr_pages, NULL, 0444);

static int param_set_active_interval(const char *val,
				     const struct kernel_param *kp)
{
	int ret;
	unsigned int msecs;

	ret = kstrtouint(val, 10, &msecs);
	if (ret)
		return ret;

	tcache_active_interval = msecs_to_jiffies(msecs);
	return 0;
}

static int param_get_active_interval(char *buffer,
				     const struct kernel_param *kp)
{
	unsigned int msecs;

	msecs = jiffies_to_msecs(tcache_active_interval);
	return sprintf(buffer, "%u", msecs);
}

static struct kernel_param_ops param_ops_active_interval = {
	.set = param_set_active_interval,
	.get = param_get_active_interval,
};
module_param_cb(active_interval_msecs, &param_ops_active_interval, NULL, 0644);

static int __init tcache_nodeinfo_init(void)
{
	int i;
	struct tcache_nodeinfo *ni;

	tcache_nodeinfo = kcalloc(nr_node_ids, sizeof(*tcache_nodeinfo),
				  GFP_KERNEL);
	if (!tcache_nodeinfo)
		return -ENOMEM;

	for (i = 0; i < nr_node_ids; i++) {
		ni = &tcache_nodeinfo[i];
		spin_lock_init(&ni->lock);
		atomic_long_set(&ni->nr_pages, 0);
		ni->reclaim_tree = RB_ROOT;
		update_ni_rb_first(ni);
	}
	return 0;
}

static int __init tcache_init(void)
{
	int err;

	if (!tcache_enabled)
		return 0;

	err = tcache_nodeinfo_init();
	if (err)
		goto out_fail;

	err = register_shrinker(&tcache_shrinker);
	if (err)
		goto out_free_lru;

#ifdef CONFIG_SMP
	num_node_trees = roundup_pow_of_two(2 * num_possible_cpus());
#endif

	err = cleancache_register_ops(&tcache_cleancache_ops);
	if (err)
		goto out_unregister_shrinker;

	pr_info("tcache loaded\n");
	return 0;

out_unregister_shrinker:
	unregister_shrinker(&tcache_shrinker);
out_free_lru:
	kfree(tcache_nodeinfo);
out_fail:
	return err;
}
module_init(tcache_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Transcendent file cache");
