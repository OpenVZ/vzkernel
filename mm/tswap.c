/*
 *  mm/tswap.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *
 */

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
#include <linux/swap_slots.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/shrinker.h>
#include <linux/frontswap.h>

#define TSWAP_GFP_MASK		(GFP_NOIO | __GFP_NORETRY | __GFP_NOWARN)

static RADIX_TREE(tswap_page_tree, GFP_ATOMIC | __GFP_NOWARN);
static DEFINE_SPINLOCK(tswap_lock);

struct tswap_lru {
	struct list_head list;
	unsigned long nr_items;
} ____cacheline_aligned_in_smp;

static struct tswap_lru *tswap_lru_node;

/* Enable/disable tswap backend (set at boot time) */
static bool tswap_enabled __read_mostly = true;
module_param_named(enabled, tswap_enabled, bool, 0444);

/* Enable/disable populating the cache */
static bool tswap_active __read_mostly = true;
module_param_named(active, tswap_active, bool, 0644);

/* Total number of pages cached */
static unsigned long tswap_nr_pages;
module_param_named(nr_pages, tswap_nr_pages, ulong, 0444);

/* Enable/disable zero pages */
static bool tswap_check_zero __read_mostly = true;
module_param_named(check_zero, tswap_check_zero, bool, 0644);

unsigned long get_nr_tswap_pages(void)
{
	return tswap_nr_pages;
}

static void tswap_lru_add(struct page *page)
{
	struct tswap_lru *lru = &tswap_lru_node[page_to_nid(page)];

	if (page != ZERO_PAGE(0)) {
		list_add_tail(&page->lru, &lru->list);
		lru->nr_items++;
	}
}

static void tswap_lru_del(struct page *page)
{
	struct tswap_lru *lru = &tswap_lru_node[page_to_nid(page)];

	if (page != ZERO_PAGE(0)) {
		list_del(&page->lru);
		lru->nr_items--;
	}
}

static struct page *tswap_lookup_page(swp_entry_t entry)
{
	struct page *page;

	spin_lock(&tswap_lock);
	page = radix_tree_lookup(&tswap_page_tree, entry.val);
	spin_unlock(&tswap_lock);
	BUG_ON(page && page != ZERO_PAGE(0) && page_private(page) != entry.val);
	return page;
}

static int tswap_insert_page(swp_entry_t entry, struct page *page)
{
	int err;

	err = radix_tree_preload(TSWAP_GFP_MASK);
	if (err)
		return err;

	if (page != ZERO_PAGE(0))
		set_page_private(page, entry.val);
	spin_lock(&tswap_lock);
	err = radix_tree_insert(&tswap_page_tree, entry.val, page);
	if (!err) {
		tswap_lru_add(page);
		tswap_nr_pages++;
	}
	spin_unlock(&tswap_lock);

	radix_tree_preload_end();
	return err;
}

static struct page *tswap_delete_page(swp_entry_t entry, struct page *expected)
{
	struct page *page;

	spin_lock(&tswap_lock);
	page = radix_tree_delete_item(&tswap_page_tree, entry.val, expected);
	if (page) {
		tswap_lru_del(page);
		tswap_nr_pages--;
	}
	spin_unlock(&tswap_lock);
	if (page) {
		BUG_ON(expected && page != expected);
		BUG_ON(page_private(page) != entry.val && page != ZERO_PAGE(0));
	}
	return page;
}

static unsigned long tswap_shrink_count(struct shrinker *shrink,
					struct shrink_control *sc)
{
	return tswap_lru_node[sc->nid].nr_items;
}

static int tswap_evict_page(struct page *page)
{
	struct address_space *swapper_space;
	struct page *found_page;
	swp_entry_t entry;
	int err;

	BUG_ON(!PageLocked(page));

	entry.val = page_private(page);
	swapper_space = swap_address_space(entry);
retry:
	err = -EEXIST;
	found_page = find_get_page(swapper_space, entry.val);
	if (found_page) {
		/*
		 * There is already a swap cache page at the given offset. If
		 * the page is uptodate, we can safely free the frontswap page,
		 * marking the swapcache page dirty. Otherwise, the frontswap
		 * page is about to be loaded and cannot be released.
		 */
		err = -EBUSY;
		if (!trylock_page(found_page)) {
			put_page(found_page);
			goto out;
		}
		/* recheck that the page is still in the swap cache */
		if (!PageSwapCache(found_page) ||
		    page_private(found_page) != entry.val) {
			unlock_page(found_page);
			put_page(found_page);
			goto retry;
		}
		if (PageUptodate(found_page)) {
			/*
			 * Since we are holding the swap cache page lock, no
			 * frontswap callbacks are allowed now. However, the
			 * frontswap page could have been invalidated before we
			 * took the lock, in which case we have nothing to do.
			 */
			err = -ENOENT;
			if (tswap_delete_page(entry, page)) {
				SetPageDirty(found_page);
				put_page(page);
				err = 0;
			}
		}
		unlock_page(found_page);
		put_page(found_page);
		goto out;
	}

	if (!__swp_swapcount(entry) && swap_slot_cache_enabled) {
		err = -ENOENT;
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

	err = -ENOENT;
	if (tswap_lookup_page(entry) != page)
		/* the page could have been removed from tswap before we
		 * prepared swap cache */
		goto out_free_swapcache;

	SetPageSwapBacked(page);
	err = __add_to_swap_cache(page, entry);
	if (err) {
		ClearPageSwapBacked(page);
		/* __add_to_swap_cache clears page->private on failure */
		set_page_private(page, entry.val);
		/* __add_to_swap_cache does not return -EEXIST, so we can
		 * safely clear SWAP_HAS_CACHE flag */
		goto out_free_swapcache;
	}

	/* the page is now in the swap cache, remove it from tswap */
	BUG_ON(!tswap_delete_page(entry, page));
	put_page(page);

	lru_cache_add_anon(page);
	SetPageUptodate(page);
	SetPageDirty(page);
	return 0;

out_free_swapcache:
	swapcache_free(entry);
out:
	return err;
}

static unsigned long tswap_shrink_scan(struct shrinker *shrink,
				       struct shrink_control *sc)
{
	struct tswap_lru *lru = &tswap_lru_node[sc->nid];
	unsigned long nr_reclaimed = 0;

	spin_lock(&tswap_lock);
	while (sc->nr_to_scan-- > 0) {
		struct page *page;

		if (!lru->nr_items)
			break;

		page = list_first_entry(&lru->list, struct page, lru);
		/* lock the page to avoid interference with
		 * other reclaiming threads */
		if (!trylock_page(page)) {
			list_move_tail(&page->lru, &lru->list);
			cond_resched_lock(&tswap_lock);
			continue;
		}
		get_page(page);
		spin_unlock(&tswap_lock);

		if (tswap_evict_page(page) == 0)
			nr_reclaimed++;

		unlock_page(page);
		put_page(page);

		cond_resched();
		spin_lock(&tswap_lock);
	}
	spin_unlock(&tswap_lock);

	return nr_reclaimed;
}

static struct shrinker tswap_shrinker = {
	.count_objects = tswap_shrink_count,
	.scan_objects = tswap_shrink_scan,
	.seeks = 4,
	.flags = SHRINKER_NUMA_AWARE,
};

static void tswap_frontswap_init(unsigned type)
{
	/*
	 * We maintain the single page tree for all swap types, so nothing to
	 * do here.
	 */
}

static bool is_zero_filled_page(struct page *page)
{
	bool zero_filled = true;
	unsigned long *v;
	int i;

	if (!tswap_check_zero)
		return false;

	v = kmap_atomic(page);
	for (i = 0; i < PAGE_SIZE / sizeof(*v); i++) {
		if (v[i] != 0) {
			zero_filled = false;
			break;
		}
	}
	kunmap_atomic(v);
	return zero_filled;
}

static int tswap_frontswap_store(unsigned type, pgoff_t offset,
				 struct page *page)
{
	swp_entry_t entry = swp_entry(type, offset);
	int zero_filled = -1, err = 0;
	struct page *cache_page;

	if (!tswap_active)
		return -1;

	cache_page = tswap_lookup_page(entry);
	if (cache_page) {
		zero_filled = is_zero_filled_page(page);
		/* If type of page has not changed, just reuse it */
		if (zero_filled == (cache_page == ZERO_PAGE(0)))
			goto copy;
		tswap_delete_page(entry, NULL);
		put_page(cache_page);
	}

	if (!(current->flags & PF_MEMCG_RECLAIM))
		return -1;

	if (zero_filled == -1)
		zero_filled = is_zero_filled_page(page);

	if (!zero_filled) {
		cache_page = alloc_page(TSWAP_GFP_MASK | __GFP_HIGHMEM);
		if (!cache_page)
			return -1;
	} else {
		cache_page = ZERO_PAGE(0);
		get_page(cache_page);
	}

	err = tswap_insert_page(entry, cache_page);
	if (err) {
		/*
		 * Frontswap stores proceed under the page lock, so this can
		 * only fail with ENOMEM.
		 */
		BUG_ON(err == -EEXIST);
		put_page(cache_page);
		return -1;
	}
copy:
	if (cache_page != ZERO_PAGE(0))
		copy_highpage(cache_page, page);
	return 0;
}

static int tswap_frontswap_load(unsigned type, pgoff_t offset,
				struct page *page)
{
	struct page *cache_page;

	cache_page = tswap_delete_page(swp_entry(type, offset), NULL);
	if (!cache_page)
		return -1;

	copy_highpage(page, cache_page);
	put_page(cache_page);
	return 0;
}

static void tswap_frontswap_invalidate_page(unsigned type, pgoff_t offset)
{
	struct page *cache_page;

	cache_page = tswap_delete_page(swp_entry(type, offset), NULL);
	if (cache_page)
		put_page(cache_page);
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

	for (i = 0; i < nr_node_ids; i++)
		INIT_LIST_HEAD(&tswap_lru_node[i].list);
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

	frontswap_tmem_exclusive_gets(true);

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
