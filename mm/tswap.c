#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/radix-tree.h>
#include <linux/list.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/shrinker.h>
#include <linux/frontswap.h>

static RADIX_TREE(tswap_page_tree, GFP_ATOMIC | __GFP_NOWARN);
static DEFINE_SPINLOCK(tswap_lock);

struct tswap_lru {
	spinlock_t lock;
	struct list_head list;
	unsigned long nr_items;
} ____cacheline_aligned_in_smp;

static struct tswap_lru *tswap_lru_node;

/* Enable/disable tswap backend (set at boot time) */
static bool tswap_enabled __read_mostly = true;
module_param_named(enabled, tswap_enabled, bool, 0444);

/* Enable/disable populating the cache */
static bool tswap_active __read_mostly;
module_param_named(active, tswap_active, bool, 0644);

/* Total number of pages cached */
static unsigned long tswap_nr_pages;
module_param_named(nr_pages, tswap_nr_pages, ulong, 0444);

static void tswap_lru_add(struct page *page)
{
	struct tswap_lru *lru = &tswap_lru_node[page_to_nid(page)];

	spin_lock(&lru->lock);
	list_add_tail(&page->lru, &lru->list);
	lru->nr_items++;
	spin_unlock(&lru->lock);
}

static void tswap_lru_del(struct page *page)
{
	struct tswap_lru *lru = &tswap_lru_node[page_to_nid(page)];

	spin_lock(&lru->lock);
	if (!list_empty(&page->lru)) {
		list_del_init(&page->lru);
		lru->nr_items--;
	}
	spin_unlock(&lru->lock);
}

static unsigned long tswap_shrink_count(struct shrinker *shrink,
					struct shrink_control *sc)
{
	return tswap_lru_node[sc->nid].nr_items;
}

static int tswap_writeback_page(struct page *page)
{
	struct address_space *swapper_space;
	struct page *found_page;
	swp_entry_t entry;
	int err;
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_NONE,
	};

	entry.val = page_private(page);
	swapper_space = swap_address_space(entry);
retry:
	err = -EEXIST;
	found_page = find_get_page(swapper_space, entry.val);
	if (found_page) {
		/*
		 * There is already a swap cache page at the given offset.
		 * Hence, if the current page has not been loaded yet, it will
		 * be in a moment (see read_swap_cache_async), so there is no
		 * need to put it back to the lru list.
		 */
		put_page(found_page);
		goto out;
	}

	err = swapcache_prepare(entry);
	if (err == -EEXIST) {
		cond_resched();
		goto retry;
	}
	if (err)
		/* the swap entry has been freed, and therefore the page must
		 * have been invalidated */
		goto out;

	/*
	 * From now on, no frontswap callbacks can be called on the swap entry,
	 * because we hold its swap cache reference.
	 */

	spin_lock(&tswap_lock);
	if (radix_tree_lookup(&tswap_page_tree, entry.val) != page)
		err = -ENOENT;
	spin_unlock(&tswap_lock);

	if (err)
		/* the page could have been removed from tswap before we
		 * prepared swap cache */
		goto out_free_swapcache;

	__set_page_locked(page);
	SetPageSwapBacked(page);
	err = __add_to_swap_cache(page, entry);
	if (err) {
		ClearPageSwapBacked(page);
		__clear_page_locked(page);
		/* __add_to_swap_cache clears page->private on failure */
		set_page_private(page, entry.val);
		/* putting the page back to the lru list before freeing swap
		 * cache blocks others reclaiming threads from interfering */
		tswap_lru_add(page);
		/* __add_to_swap_cache does not return -EEXIST, so we can
		 * safely clear SWAP_HAS_CACHE flag */
		goto out_free_swapcache;
	}

	/* the page is now in the swap cache, remove it from tswap */
	spin_lock(&tswap_lock);
	BUG_ON(!radix_tree_delete_item(&tswap_page_tree, entry.val, page));
	tswap_nr_pages--;
	spin_unlock(&tswap_lock);

	put_page(page);

	lru_cache_add_anon(page);
	SetPageUptodate(page);

	/* move it to the tail of the inactive list after end_writeback */
	SetPageReclaim(page);

	/* start writeback */
	__swap_writepage(page, &wbc, end_swap_bio_write);

	goto out;

out_free_swapcache:
	swapcache_free(entry, NULL);
out:
	return err;
}

static unsigned long tswap_shrink_scan(struct shrinker *shrink,
				       struct shrink_control *sc)
{
	struct tswap_lru *lru = &tswap_lru_node[sc->nid];
	unsigned long nr_reclaimed = 0;

	spin_lock(&lru->lock);
	while (lru->nr_items > 0 && sc->nr_to_scan > 0) {
		struct page *page;
		
		page = list_first_entry(&lru->list, struct page, lru);
		get_page(page);

		list_del_init(&page->lru);
		lru->nr_items--;
		spin_unlock(&lru->lock);

		if (tswap_writeback_page(page) == 0)
			nr_reclaimed++;
		sc->nr_to_scan--;

		put_page(page);

		cond_resched();
		spin_lock(&lru->lock);
	}
	spin_unlock(&lru->lock);

	return nr_reclaimed;
}

static struct shrinker tswap_shrinker = {
	.count_objects = tswap_shrink_count,
	.scan_objects = tswap_shrink_scan,
	.seeks = DEFAULT_SEEKS,
	.flags = SHRINKER_NUMA_AWARE,
};

static void tswap_frontswap_init(unsigned type)
{
	/*
	 * We maintain the single page tree for all swap types, so nothing to
	 * do here.
	 */
}

static int tswap_frontswap_store(unsigned type, pgoff_t offset,
				 struct page *page)
{
	swp_entry_t entry = swp_entry(type, offset);
	struct page *cache_page;

	if (!tswap_active)
		return -1;

	cache_page = alloc_page(__GFP_HIGHMEM | __GFP_NORETRY | __GFP_NOWARN);
	if (!cache_page)
		return -1;

	copy_highpage(cache_page, page);
	set_page_private(cache_page, entry.val);

	spin_lock(&tswap_lock);
	BUG_ON(radix_tree_insert(&tswap_page_tree, entry.val, cache_page));
	tswap_nr_pages++;
	spin_unlock(&tswap_lock);

	tswap_lru_add(cache_page);

	return 0;
}

static int tswap_frontswap_load(unsigned type, pgoff_t offset,
				struct page *page)
{
	swp_entry_t entry = swp_entry(type, offset);
	struct page *cache_page;

	spin_lock(&tswap_lock);
	cache_page = radix_tree_delete(&tswap_page_tree, entry.val);
	if (cache_page)
		tswap_nr_pages--;
	spin_unlock(&tswap_lock);

	if (!cache_page)
		return -1;

	BUG_ON(page_private(cache_page) != entry.val);
	tswap_lru_del(cache_page);

	if (page)
		copy_highpage(page, cache_page);
	put_page(cache_page);

	return 0;
}

static void tswap_frontswap_invalidate_page(unsigned type, pgoff_t offset)
{
	(void)tswap_frontswap_load(type, offset, NULL);
}

static void tswap_frontswap_invalidate_area(unsigned type)
{
	/*
	 * This function is called on swapoff after all swap entries of the
	 * given type has been freed and therefore all frontswap pages has been
	 * invalidated, so nothing to do here.
	 */
}

static struct frontswap_ops tswap_frontswap_ops = {
	.init = tswap_frontswap_init,
	.store = tswap_frontswap_store,
	.load = tswap_frontswap_load,
	.invalidate_page = tswap_frontswap_invalidate_page,
	.invalidate_area = tswap_frontswap_invalidate_area,
};

static int __init tswap_lru_init(void)
{
	int i;

	tswap_lru_node = kcalloc(nr_node_ids, sizeof(*tswap_lru_node),
				 GFP_KERNEL);
	if (!tswap_lru_node)
		return -ENOMEM;

	for (i = 0; i < nr_node_ids; i++) {
		spin_lock_init(&tswap_lru_node[i].lock);
		INIT_LIST_HEAD(&tswap_lru_node[i].list);
	}
	return 0;
}

static int __init tswap_init(void)
{
	int err;
	struct frontswap_ops *old_ops;

	if (!tswap_enabled)
		return 0;

	err = tswap_lru_init();
	if (err)
		goto out_fail;

	err = register_shrinker(&tswap_shrinker);
	if (err)
		goto out_free_lru;

	old_ops = frontswap_register_ops(&tswap_frontswap_ops);
	pr_info("tswap loaded\n");
	if (old_ops)
		pr_warn("tswap: frontswap_ops %p overridden\n", old_ops);

	return 0;

out_free_lru:
	kfree(tswap_lru_node);
out_fail:
	return err;
}
module_init(tswap_init);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Transcendent swap cache");
