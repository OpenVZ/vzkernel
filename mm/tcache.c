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
#include <linux/rbtree.h>
#include <linux/radix-tree.h>
#include <linux/idr.h>
#include <linux/atomic.h>
#include <linux/kref.h>
#include <linux/jhash.h>
#include <linux/completion.h>
#include <linux/shrinker.h>
#include <linux/vmstat.h>
#include <linux/cleancache.h>

/* cleancache_put_page is called from atomic context */
#define TCACHE_GFP_MASK			(__GFP_NORETRY | __GFP_NOWARN)

struct tcache_node_tree {
	struct rb_root			root;
	spinlock_t			lock;
};

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
};

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

struct tcache_lru {
	spinlock_t lock;
	struct list_head list;
	unsigned long nr_items;
} ____cacheline_aligned_in_smp;

/*
 * Per NUMA node LRU lists of pages. Linked through page->lru. Used to reclaim
 * memory from the cache on global reclaim - see tcache_shrinker.
 */
static struct tcache_lru *tcache_lru_node;

/*
 * Locking rules:
 *
 * - tcache_node_tree->lock nests inside tcache_node->tree_lock
 * - tcache_lru->lock is independent
 */

/* Enable/disable tcache backend (set at boot time) */
static bool tcache_enabled __read_mostly = true;
module_param_named(enabled, tcache_enabled, bool, 0444);

/* Enable/disable populating the cache */
static bool tcache_active __read_mostly;
module_param_named(active, tcache_active, bool, 0644);

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

/*
 * Add a page to the LRU list. This effectively makes the page visible to the
 * shrinker, so it must only be called after the page was properly initialized
 * and added to the corresponding page tree.
 */
static void tcache_lru_add(struct page *page)
{
	struct tcache_lru *lru = &tcache_lru_node[page_to_nid(page)];

	spin_lock(&lru->lock);
	list_add_tail(&page->lru, &lru->list);
	lru->nr_items++;
	spin_unlock(&lru->lock);
}

/*
 * Remove a page from the LRU list. This function is safe to call on the same
 * page from concurrent threads - the page will be removed only once.
 */
static void tcache_lru_del(struct page *page)
{
	struct tcache_lru *lru = &tcache_lru_node[page_to_nid(page)];

	spin_lock(&lru->lock);
	if (!list_empty(&page->lru)) {
		list_del_init(&page->lru);
		lru->nr_items--;
	}
	spin_unlock(&lru->lock);
}

static int tcache_create_pool(void)
{
	struct tcache_pool *pool;
	int id;
	int i;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
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

static void tcache_invalidate_node_tree(struct tcache_node_tree *tree);

static void tcache_destroy_pool(int id)
{
	int i;
	struct tcache_pool *pool;

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

	for (i = 0; i < num_node_trees; i++)
		tcache_invalidate_node_tree(&pool->node_tree[i]);

	BUG_ON(atomic_long_read(&pool->nr_nodes) != 0);

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
		__tcache_insert_node(&tree->root, node, rb_link, rb_parent);
	}
	spin_unlock_irqrestore(&tree->lock, flags);

	if (node) {
		BUG_ON(node->pool != pool);
		if (node != new_node)
			kfree(new_node);
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
		BUG_ON(atomic_read(&node->kref.refcount) != 1);
		BUG_ON(node->nr_pages == 0);
		BUG_ON(node->invalidated);

		tcache_hold_node(node);
		tcache_invalidate_node_pages(node);
		tcache_put_node(node);
	}
}


static inline struct tcache_node *tcache_page_node(struct page *page)
{
	return (struct tcache_node *)page->private;
}

static inline void tcache_init_page(struct page *page,
				    struct tcache_node *node, pgoff_t index)
{
	page->private = (unsigned long)node;
	page->index = index;
}

static int tcache_page_tree_replace(struct tcache_node *node, pgoff_t index,
				    struct page *page, struct page **old_page)
{
	void **pslot;
	int err = 0;

	*old_page = NULL;

	spin_lock(&node->tree_lock);
	/*
	 * If the node was invalidated after we looked it up, abort in order to
	 * avoid clashes with tcache_invalidate_node_pages.
	 */
	if (unlikely(node->invalidated)) {
		err = -EAGAIN;
		goto out;
	}

	pslot = radix_tree_lookup_slot(&node->page_tree, index);
	if (pslot) {
		*old_page = radix_tree_deref_slot_protected(pslot,
							    &node->tree_lock);
		radix_tree_replace_slot(pslot, page);
		__dec_zone_page_state(*old_page, NR_FILE_PAGES);
		__inc_zone_page_state(page, NR_FILE_PAGES);
	} else {
		err = radix_tree_insert(&node->page_tree, index, page);
		BUG_ON(err == -EEXIST);
		if (!err) {
			if (!node->nr_pages++)
				tcache_hold_node(node);
			__this_cpu_inc(nr_tcache_pages);
			__inc_zone_page_state(page, NR_FILE_PAGES);
		}
	}
out:
	spin_unlock(&node->tree_lock);
	return err;
}

static struct page *__tcache_page_tree_delete(struct tcache_node *node,
					      pgoff_t index, struct page *page)
{
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
	struct page *old_page;
	unsigned long flags;
	int err = 0;

	tcache_init_page(page, node, index);

	local_irq_save(flags);
	err = tcache_page_tree_replace(node, index, page, &old_page);
	if (err)
		goto out;

	if (old_page) {
		tcache_lru_del(old_page);
		put_page(old_page);
	}
	get_page(page);
	tcache_lru_add(page);
out:
	local_irq_restore(flags);
	return err;
}

/*
 * Detach and return the page at a given offset of a node. The caller must put
 * the page when it is done with it.
 */
static struct page *tcache_detach_page(struct tcache_node *node, pgoff_t index)
{
	unsigned long flags;
	struct page *page;

	local_irq_save(flags);
	page = tcache_page_tree_delete(node, index, NULL);
	if (page)
		tcache_lru_del(page);
	local_irq_restore(flags);

	return page;
}

static noinline_for_stack void
tcache_invalidate_node_pages(struct tcache_node *node)
{
	struct radix_tree_iter iter;
	struct page *page;
	void **slot;

	spin_lock_irq(&node->tree_lock);

	/*
	 * First forbid new page insertions - see tcache_page_tree_replace.
	 */
	node->invalidated = true;

	/*
	 * Now truncate all pages. Be careful, because pages can still be
	 * deleted from this node by the shrinker or by concurrent lookups.
	 */
	radix_tree_for_each_slot(slot, &node->page_tree, &iter, 0) {
		page = radix_tree_deref_slot_protected(slot, &node->tree_lock);
		BUG_ON(!__tcache_page_tree_delete(node, page->index, page));
		spin_unlock(&node->tree_lock);

		tcache_lru_del(page);
		put_page(page);

		local_irq_enable();
		cond_resched();
		local_irq_disable();

		spin_lock(&node->tree_lock);
	}

	BUG_ON(node->nr_pages != 0);

	spin_unlock_irq(&node->tree_lock);
}

static struct page *tcache_lru_isolate(struct tcache_lru *lru,
				       struct tcache_node **pnode)
{
	struct page *page = NULL;
	struct tcache_node *node;

	*pnode = NULL;

	spin_lock(&lru->lock);
	if (list_empty(&lru->list))
		goto out;

	page = list_first_entry(&lru->list, struct page, lru);

	list_del_init(&page->lru);
	lru->nr_items--;

	node = tcache_page_node(page);

	/*
	 * A node can be destroyed only if all its pages have been removed both
	 * from the tree and the LRU list, and a pool can be freed only after
	 * all its nodes have been destroyed. Since we are holding the LRU lock
	 * here and hence preventing the page from being removed from the LRU
	 * list, it is therefore safe to access the node and the pool which the
	 * page is attached to.
	 */
	if (!tcache_grab_pool(node->pool)) {
		/*
		 * Do not bother adding the page back to the LRU list if the
		 * pool is under destruction - it will be freed anyway soon.
		 */
		page = NULL;
		goto out;
	}

	tcache_hold_node(node);
	get_page(page);

	*pnode = node;
out:
	spin_unlock(&lru->lock);
	return page;
}

static noinline_for_stack struct page *
__tcache_try_to_reclaim_page(struct tcache_lru *lru)
{
	struct page *page = NULL;
	struct tcache_node *node;
	unsigned long flags;

	local_irq_save(flags);
	page = tcache_lru_isolate(lru, &node);
	if (page) {
		if (tcache_page_tree_delete(node, page->index, page)) {
			/*
			 * We deleted the page from the tree - drop the
			 * corresponding reference. Note, we still hold the
			 * page reference taken in tcache_lru_isolate.
			 */
			put_page(page);
		} else {
			/*
			 * The page was deleted by a concurrent thread - drop
			 * the reference taken in tcache_lru_isolate and abort.
			 */
			put_page(page);
			page = NULL;
		}
		tcache_put_node_and_pool(node);
	}
	local_irq_restore(flags);
	return page;
}

static struct page *tcache_try_to_reclaim_page(void)
{
	struct tcache_lru *lru = &tcache_lru_node[numa_node_id()];

	return __tcache_try_to_reclaim_page(lru);
}

static struct page *tcache_alloc_page(void)
{
	struct page *page;

	page = alloc_page(TCACHE_GFP_MASK | __GFP_HIGHMEM);
	if (!page)
		page = tcache_try_to_reclaim_page();

	return page;
}

static unsigned long tcache_shrink_count(struct shrinker *shrink,
					 struct shrink_control *sc)
{
	return tcache_lru_node[sc->nid].nr_items;
}

static unsigned long tcache_shrink_scan(struct shrinker *shrink,
					struct shrink_control *sc)
{
	struct tcache_lru *lru = &tcache_lru_node[sc->nid];
	struct page *page;
	unsigned long nr_reclaimed = 0;

	while (lru->nr_items > 0 && sc->nr_to_scan > 0) {
		page = __tcache_try_to_reclaim_page(lru);
		if (page) {
			put_page(page);
			nr_reclaimed++;
		}
		sc->nr_to_scan--;
	}
	return nr_reclaimed;
}

struct shrinker tcache_shrinker = {
	.count_objects		= tcache_shrink_count,
	.scan_objects		= tcache_shrink_scan,
	.seeks			= DEFAULT_SEEKS,
	.flags			= SHRINKER_NUMA_AWARE,
};

static int tcache_cleancache_init_fs(size_t pagesize)
{
	BUG_ON(pagesize != PAGE_SIZE);
	return tcache_create_pool();
}

static int tcache_cleancache_init_shared_fs(char *uuid, size_t pagesize)
{
	return -1;
}

static void tcache_cleancache_put_page(int pool_id,
				       struct cleancache_filekey key,
				       pgoff_t index, struct page *page)
{
	struct tcache_node *node;
	struct page *cache_page = NULL;

	node = tcache_get_node_and_pool(pool_id, &key, true);
	if (node) {
		if (tcache_active && !(current->flags & PF_MEMALLOC))
			cache_page = tcache_alloc_page();
		if (cache_page) {
			copy_highpage(cache_page, page);
			/* cleancache does not care about failures */
			(void)tcache_attach_page(node, index, cache_page);
		} else
			cache_page = tcache_detach_page(node, index);
		tcache_put_node_and_pool(node);
	}

	if (cache_page)
		put_page(cache_page);
}

static int tcache_cleancache_get_page(int pool_id,
				      struct cleancache_filekey key,
				      pgoff_t index, struct page *page)
{
	struct tcache_node *node;
	struct page *cache_page = NULL;

	node = tcache_get_node_and_pool(pool_id, &key, false);
	if (node) {
		cache_page = tcache_detach_page(node, index);
		if (unlikely(cache_page && node->invalidated)) {
			put_page(cache_page);
			cache_page = NULL;
		}
		tcache_put_node_and_pool(node);
	}

	if (cache_page) {
		copy_highpage(page, cache_page);
		put_page(cache_page);
		return 0;
	}
	return -1;
}

static void tcache_cleancache_invalidate_page(int pool_id,
		struct cleancache_filekey key, pgoff_t index)
{
	struct tcache_node *node;
	struct page *page;

	node = tcache_get_node_and_pool(pool_id, &key, false);
	if (node) {
		page = tcache_detach_page(node, index);
		if (page)
			put_page(page);
		tcache_put_node_and_pool(node);
	}
}

static void tcache_cleancache_invalidate_inode(int pool_id,
					       struct cleancache_filekey key)
{
	struct tcache_pool *pool;

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

static int param_get_nr_pages(char *buffer, const struct kernel_param *kp)
{
	int cpu;
	long val = 0;

	for_each_possible_cpu(cpu)
		val += per_cpu(nr_tcache_pages, cpu);
	if (val < 0)
		val = 0;
	return sprintf(buffer, "%lu", val);
}

static struct kernel_param_ops param_ops_nr_pages = {
	.get = param_get_nr_pages,
};
module_param_cb(nr_pages, &param_ops_nr_pages, NULL, 0444);

static int __init tcache_lru_init(void)
{
	int i;

	tcache_lru_node = kcalloc(nr_node_ids, sizeof(*tcache_lru_node),
				  GFP_KERNEL);
	if (!tcache_lru_node)
		return -ENOMEM;

	for (i = 0; i < nr_node_ids; i++) {
		spin_lock_init(&tcache_lru_node[i].lock);
		INIT_LIST_HEAD(&tcache_lru_node[i].list);
	}
	return 0;
}

static int __init tcache_init(void)
{
	int err;

	if (!tcache_enabled)
		return 0;

	err = tcache_lru_init();
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
	kfree(tcache_lru_node);
out_fail:
	return err;
}
module_init(tcache_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Transcendent file cache");
