/*
 * Memory Migration functionality - linux/mm/migration.c
 *
 * Copyright (C) 2006 Silicon Graphics, Inc., Christoph Lameter
 *
 * Page migration was first developed in the context of the memory hotplug
 * project. The main authors of the migration code are:
 *
 * IWAMOTO Toshihiro <iwamoto@valinux.co.jp>
 * Hirokazu Takahashi <taka@valinux.co.jp>
 * Dave Hansen <haveblue@us.ibm.com>
 * Christoph Lameter
 */

#include <linux/migrate.h>
#include <linux/export.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/buffer_head.h>
#include <linux/mm_inline.h>
#include <linux/nsproxy.h>
#include <linux/pagevec.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/writeback.h>
#include <linux/mempolicy.h>
#include <linux/vmalloc.h>
#include <linux/security.h>
#include <linux/memcontrol.h>
#include <linux/syscalls.h>
#include <linux/hugetlb.h>
#include <linux/hugetlb_cgroup.h>
#include <linux/gfp.h>
#include <linux/balloon_compaction.h>
#include <linux/mmu_notifier.h>
#include <linux/memremap.h>
#include <linux/userfaultfd_k.h>
#include <linux/ptrace.h>
#include <linux/page_idle.h>

#include <asm/tlbflush.h>

#define CREATE_TRACE_POINTS
#include <trace/events/migrate.h>

#include "internal.h"

extern atomic_long_t num_poisoned_pages __read_mostly;

/*
 * migrate_prep() needs to be called before we start compiling a list of pages
 * to be migrated using isolate_lru_page(). If scheduling work on other CPUs is
 * undesirable, use migrate_prep_local()
 */
int migrate_prep(void)
{
	/*
	 * Clear the LRU lists so pages can be isolated.
	 * Note that pages may be moved off the LRU after we have
	 * drained them. Those pages will fail to migrate like other
	 * pages that may be busy.
	 */
	lru_add_drain_all();

	return 0;
}

/* Do the necessary work of migrate_prep but not if it involves other CPUs */
int migrate_prep_local(void)
{
	lru_add_drain();

	return 0;
}

/*
 * Add isolated pages on the list back to the LRU under page lock
 * to avoid leaking evictable pages back onto unevictable list.
 */
void putback_lru_pages(struct list_head *l)
{
	struct page *page;
	struct page *page2;

	list_for_each_entry_safe(page, page2, l, lru) {
		list_del(&page->lru);
		dec_zone_page_state(page, NR_ISOLATED_ANON +
				page_is_file_cache(page));
			putback_lru_page(page);
	}
}

/*
 * Put previously isolated pages back onto the appropriate lists
 * from where they were once taken off for compaction/migration.
 *
 * This function shall be used instead of putback_lru_pages(),
 * whenever the isolated pageset has been built by isolate_migratepages_range()
 */
void putback_movable_pages(struct list_head *l)
{
	struct page *page;
	struct page *page2;

	list_for_each_entry_safe(page, page2, l, lru) {
		if (unlikely(PageHuge(page))) {
			putback_active_hugepage(page);
			continue;
		}
		list_del(&page->lru);
		dec_zone_page_state(page, NR_ISOLATED_ANON +
				page_is_file_cache(page));
		if (unlikely(isolated_balloon_page(page)))
			balloon_page_putback(page);
		else
			putback_lru_page(page);
	}
}

/*
 * Restore a potential migration pte to a working pte entry
 */
static int remove_migration_pte(struct page *new, struct vm_area_struct *vma,
				 unsigned long addr, void *old)
{
	struct mm_struct *mm = vma->vm_mm;
	swp_entry_t entry;
 	pmd_t *pmd;
	pte_t *ptep, pte;
 	spinlock_t *ptl;

	if (unlikely(PageHuge(new))) {
		ptep = huge_pte_offset(mm, addr);
		if (!ptep)
			goto out;
		ptl = huge_pte_lockptr(hstate_vma(vma), mm, ptep);
	} else {
		pmd = mm_find_pmd(mm, addr);
		if (!pmd)
			goto out;

		ptep = pte_offset_map(pmd, addr);

		/*
		 * Peek to check is_swap_pte() before taking ptlock?  No, we
		 * can race mremap's move_ptes(), which skips anon_vma lock.
		 */

		ptl = pte_lockptr(mm, pmd);
	}

 	spin_lock(ptl);
	pte = *ptep;
	if (!is_swap_pte(pte))
		goto unlock;

	entry = pte_to_swp_entry(pte);

	if (!is_migration_entry(entry) ||
	    migration_entry_to_page(entry) != old)
		goto unlock;

	get_page(new);
	pte = pte_mkold(mk_pte(new, READ_ONCE(vma->vm_page_prot)));
	if (pte_swp_soft_dirty(*ptep))
		pte = pte_mksoft_dirty(pte);
	if (is_write_migration_entry(entry))
		pte = pte_mkwrite(pte);
#ifdef CONFIG_HUGETLB_PAGE
	if (PageHuge(new)) {
		pte = pte_mkhuge(pte);
		pte = arch_make_huge_pte(pte, vma, new, 0);
	}
#endif

	if (unlikely(is_zone_device_page(new)) && is_hmm_page(new)) {
		entry = make_hmm_entry(new, pte_write(pte));
		pte = swp_entry_to_pte(entry);
	} else
		flush_dcache_page(new);
	set_pte_at(mm, addr, ptep, pte);

	if (PageHuge(new)) {
		if (PageAnon(new))
			hugepage_add_anon_rmap(new, vma, addr);
		else
			page_dup_rmap(new);
	} else if (PageAnon(new))
		page_add_anon_rmap(new, vma, addr);
	else
		page_add_file_rmap(new);

	if (vma->vm_flags & VM_LOCKED)
		mlock_vma_page(new);

	/* No need to invalidate - it was non-present before */
	update_mmu_cache(vma, addr, ptep);
unlock:
	pte_unmap_unlock(ptep, ptl);
out:
	return SWAP_AGAIN;
}

/*
 * Get rid of all migration entries and replace them by
 * references to the indicated page.
 */
static void remove_migration_ptes(struct page *old, struct page *new)
{
	struct rmap_walk_control rwc = {
		.rmap_one = remove_migration_pte,
		.arg = old,
	};

	rmap_walk(new, &rwc);
}

/*
 * Something used the pte of a page under migration. We need to
 * get to the page and wait until migration is finished.
 * When we return from this function the fault will be retried.
 */
void __migration_entry_wait(struct mm_struct *mm, pte_t *ptep,
				spinlock_t *ptl)
{
	pte_t pte;
	swp_entry_t entry;
	struct page *page;

	spin_lock(ptl);
	pte = *ptep;
	if (!is_swap_pte(pte))
		goto out;

	entry = pte_to_swp_entry(pte);
	if (!is_migration_entry(entry))
		goto out;

	page = migration_entry_to_page(entry);

	/*
	 * Once radix-tree replacement of page migration started, page_count
	 * *must* be zero. And, we don't want to call wait_on_page_locked()
	 * against a page without get_page().
	 * So, we use get_page_unless_zero(), here. Even failed, page fault
	 * will occur again.
	 */
	if (!get_page_unless_zero(page))
		goto out;
	if (is_zone_device_page(page))
		get_zone_device_page(page);
	pte_unmap_unlock(ptep, ptl);
	wait_on_page_locked(page);
	put_page(page);
	return;
out:
	pte_unmap_unlock(ptep, ptl);
}

void migration_entry_wait(struct mm_struct *mm, pmd_t *pmd,
				unsigned long address)
{
	spinlock_t *ptl = pte_lockptr(mm, pmd);
	pte_t *ptep = pte_offset_map(pmd, address);
	__migration_entry_wait(mm, ptep, ptl);
}

void migration_entry_wait_huge(struct vm_area_struct *vma,
		struct mm_struct *mm, pte_t *pte)
{
	spinlock_t *ptl = huge_pte_lockptr(hstate_vma(vma), mm, pte);
	__migration_entry_wait(mm, pte, ptl);
}

#ifdef CONFIG_BLOCK
/* Returns true if all buffers are successfully locked */
static bool buffer_migrate_lock_buffers(struct buffer_head *head,
							enum migrate_mode mode)
{
	struct buffer_head *bh = head;

	/* Simple case, sync compaction */
	if (mode != MIGRATE_ASYNC) {
		do {
			get_bh(bh);
			lock_buffer(bh);
			bh = bh->b_this_page;

		} while (bh != head);

		return true;
	}

	/* async case, we cannot block on lock_buffer so use trylock_buffer */
	do {
		get_bh(bh);
		if (!trylock_buffer(bh)) {
			/*
			 * We failed to lock the buffer and cannot stall in
			 * async migration. Release the taken locks
			 */
			struct buffer_head *failed_bh = bh;
			put_bh(failed_bh);
			bh = head;
			while (bh != failed_bh) {
				unlock_buffer(bh);
				put_bh(bh);
				bh = bh->b_this_page;
			}
			return false;
		}

		bh = bh->b_this_page;
	} while (bh != head);
	return true;
}
#else
static inline bool buffer_migrate_lock_buffers(struct buffer_head *head,
							enum migrate_mode mode)
{
	return true;
}
#endif /* CONFIG_BLOCK */

/*
 * Replace the page in the mapping.
 *
 * The number of remaining references must be:
 * 1 for anonymous pages without a mapping
 * 2 for pages with a mapping
 * 3 for pages with a mapping and PagePrivate/PagePrivate2 set.
 */
int migrate_page_move_mapping(struct address_space *mapping,
		struct page *newpage, struct page *page,
		struct buffer_head *head, enum migrate_mode mode,
		int extra_count)
{
	int expected_count = 1 + extra_count;
	void **pslot;

	/*
	 * ZONE_DEVICE pages have 1 refcount always held by their device
	 *
	 * Note that DAX memory will never reach that point as it does not have
	 * the MEMORY_DEVICE_ALLOW_MIGRATE flag set (see memory_hotplug.h).
	 */
	expected_count += is_zone_device_page(page);

	if (!mapping) {
		/* Anonymous page without mapping */
		if (page_count(page) != expected_count)
			return -EAGAIN;
		return MIGRATEPAGE_SUCCESS;
	}

	spin_lock_irq(&mapping->tree_lock);

	pslot = radix_tree_lookup_slot(&mapping->page_tree,
 					page_index(page));

	expected_count += 1 + page_has_private(page);
	if (page_count(page) != expected_count ||
		radix_tree_deref_slot_protected(pslot, &mapping->tree_lock) != page) {
		spin_unlock_irq(&mapping->tree_lock);
		return -EAGAIN;
	}

	if (!page_ref_freeze(page, expected_count)) {
		spin_unlock_irq(&mapping->tree_lock);
		return -EAGAIN;
	}

	/*
	 * In the async migration case of moving a page with buffers, lock the
	 * buffers using trylock before the mapping is moved. If the mapping
	 * was moved, we later failed to lock the buffers and could not move
	 * the mapping back due to an elevated page count, we would have to
	 * block waiting on other references to be dropped.
	 */
	if (mode == MIGRATE_ASYNC && head &&
			!buffer_migrate_lock_buffers(head, mode)) {
		page_ref_unfreeze(page, expected_count);
		spin_unlock_irq(&mapping->tree_lock);
		return -EAGAIN;
	}

	/*
	 * Now we know that no one else is looking at the page.
	 */
	get_page(newpage);	/* add cache reference */
	if (PageSwapCache(page)) {
		SetPageSwapCache(newpage);
		set_page_private(newpage, page_private(page));
	}

	radix_tree_replace_slot(pslot, newpage);

	/*
	 * Drop cache reference from old page by unfreezing
	 * to one less reference.
	 * We know this isn't the last reference.
	 */
	page_ref_unfreeze(page, expected_count - 1);

	/*
	 * If moved to a different zone then also account
	 * the page for that zone. Other VM counters will be
	 * taken care of when we establish references to the
	 * new page and drop references to the old page.
	 *
	 * Note that anonymous pages are accounted for
	 * via NR_FILE_PAGES and NR_ANON_PAGES if they
	 * are mapped to swap space.
	 */
	__dec_zone_page_state(page, NR_FILE_PAGES);
	__inc_zone_page_state(newpage, NR_FILE_PAGES);
	if (!PageSwapCache(page) && PageSwapBacked(page)) {
		__dec_zone_page_state(page, NR_SHMEM);
		__inc_zone_page_state(newpage, NR_SHMEM);
	}
	spin_unlock_irq(&mapping->tree_lock);

	return MIGRATEPAGE_SUCCESS;
}

/*
 * The expected number of remaining references is the same as that
 * of migrate_page_move_mapping().
 */
int migrate_huge_page_move_mapping(struct address_space *mapping,
				   struct page *newpage, struct page *page)
{
	int expected_count;
	void **pslot;

	if (!mapping) {
		if (page_count(page) != 1)
			return -EAGAIN;
		return MIGRATEPAGE_SUCCESS;
	}

	spin_lock_irq(&mapping->tree_lock);

	pslot = radix_tree_lookup_slot(&mapping->page_tree,
					page_index(page));

	expected_count = 2 + page_has_private(page);
	if (page_count(page) != expected_count ||
		radix_tree_deref_slot_protected(pslot, &mapping->tree_lock) != page) {
		spin_unlock_irq(&mapping->tree_lock);
		return -EAGAIN;
	}

	if (!page_ref_freeze(page, expected_count)) {
		spin_unlock_irq(&mapping->tree_lock);
		return -EAGAIN;
	}

	get_page(newpage);

	radix_tree_replace_slot(pslot, newpage);

	page_ref_unfreeze(page, expected_count - 1);

	spin_unlock_irq(&mapping->tree_lock);
	return MIGRATEPAGE_SUCCESS;
}

/*
 * Gigantic pages are so large that we do not guarantee that page++ pointer
 * arithmetic will work across the entire page.  We need something more
 * specialized.
 */
static void __copy_gigantic_page(struct page *dst, struct page *src,
				int nr_pages)
{
	int i;
	struct page *dst_base = dst;
	struct page *src_base = src;

	for (i = 0; i < nr_pages; ) {
		cond_resched();
		copy_highpage(dst, src);

		i++;
		dst = mem_map_next(dst, dst_base, i);
		src = mem_map_next(src, src_base, i);
	}
}

static void copy_huge_page(struct page *dst, struct page *src)
{
	int i;
	int nr_pages;

	if (PageHuge(src)) {
		/* hugetlbfs page */
		struct hstate *h = page_hstate(src);
		nr_pages = pages_per_huge_page(h);

		if (unlikely(nr_pages > MAX_ORDER_NR_PAGES)) {
			__copy_gigantic_page(dst, src, nr_pages);
			return;
		}
	} else {
		/* thp page */
		BUG_ON(!PageTransHuge(src));
		nr_pages = hpage_nr_pages(src);
	}

	for (i = 0; i < nr_pages; i++) {
		cond_resched();
		copy_highpage(dst + i, src + i);
	}
}

/*
 * Copy the page to its new location
 */
void migrate_page_states(struct page *newpage, struct page *page)
{
	int cpupid;

	if (PageError(page))
		SetPageError(newpage);
	if (PageReferenced(page))
		SetPageReferenced(newpage);
	if (PageUptodate(page))
		SetPageUptodate(newpage);
	if (TestClearPageActive(page)) {
		VM_BUG_ON_PAGE(PageUnevictable(page), page);
		SetPageActive(newpage);
	} else if (TestClearPageUnevictable(page))
		SetPageUnevictable(newpage);
	if (PageChecked(page))
		SetPageChecked(newpage);
	if (PageMappedToDisk(page))
		SetPageMappedToDisk(newpage);

	if (PageDirty(page)) {
		clear_page_dirty_for_io(page);
		/*
		 * Want to mark the page and the radix tree as dirty, and
		 * redo the accounting that clear_page_dirty_for_io undid,
		 * but we can't use set_page_dirty because that function
		 * is actually a signal that all of the page has become dirty.
		 * Whereas only part of our page may be dirty.
		 */
		if (PageSwapBacked(page))
			SetPageDirty(newpage);
		else
			__set_page_dirty_nobuffers(newpage);
 	}

	if (page_is_young(page))
		set_page_young(newpage);
	if (page_is_idle(page))
		set_page_idle(newpage);

	/*
	 * Copy NUMA information to the new page, to prevent over-eager
	 * future migrations of this same page.
	 */
	cpupid = page_cpupid_xchg_last(page, -1);
	page_cpupid_xchg_last(newpage, cpupid);

	ksm_migrate_page(newpage, page);
	/*
	 * Please do not reorder this without considering how mm/ksm.c's
	 * get_ksm_page() depends upon ksm_migrate_page() and PageSwapCache().
	 */
	if (PageSwapCache(page))
		ClearPageSwapCache(page);
	ClearPagePrivate(page);
	set_page_private(page, 0);

	/*
	 * If any waiters have accumulated on the new page then
	 * wake them up.
	 */
	if (PageWriteback(newpage))
		end_page_writeback(newpage);
}

void migrate_page_copy(struct page *newpage, struct page *page)
{
	if (PageHuge(page) || PageTransHuge(page))
		copy_huge_page(newpage, page);
	else
		copy_highpage(newpage, page);

	migrate_page_states(newpage, page);
}

/************************************************************
 *                    Migration functions
 ***********************************************************/

/* Always fail migration. Used for mappings that are not movable */
int fail_migrate_page(struct address_space *mapping,
			struct page *newpage, struct page *page)
{
	return -EIO;
}
EXPORT_SYMBOL(fail_migrate_page);

/*
 * Common logic to directly migrate a single page suitable for
 * pages that do not use PagePrivate/PagePrivate2.
 *
 * Pages are locked upon entry and exit.
 */
int migrate_page(struct address_space *mapping,
		struct page *newpage, struct page *page,
		enum migrate_mode mode)
{
	int rc;

	BUG_ON(PageWriteback(page));	/* Writeback must be complete */

	rc = migrate_page_move_mapping(mapping, newpage, page, NULL, mode, 0);

	if (rc != MIGRATEPAGE_SUCCESS)
		return rc;

	if ((int)mode != MIGRATE_SYNC_NO_COPY)
		migrate_page_copy(newpage, page);
	else
		migrate_page_states(newpage, page);
	return MIGRATEPAGE_SUCCESS;
}
EXPORT_SYMBOL(migrate_page);

#ifdef CONFIG_BLOCK
/*
 * Migration function for pages with buffers. This function can only be used
 * if the underlying filesystem guarantees that no other references to "page"
 * exist.
 */
int buffer_migrate_page(struct address_space *mapping,
		struct page *newpage, struct page *page, enum migrate_mode mode)
{
	struct buffer_head *bh, *head;
	int rc;

	if (!page_has_buffers(page))
		return migrate_page(mapping, newpage, page, mode);

	head = page_buffers(page);

	rc = migrate_page_move_mapping(mapping, newpage, page, head, mode, 0);

	if (rc != MIGRATEPAGE_SUCCESS)
		return rc;

	/*
	 * In the async case, migrate_page_move_mapping locked the buffers
	 * with an IRQ-safe spinlock held. In the sync case, the buffers
	 * need to be locked now
	 */
	if (mode != MIGRATE_ASYNC)
		BUG_ON(!buffer_migrate_lock_buffers(head, mode));

	ClearPagePrivate(page);
	set_page_private(newpage, page_private(page));
	set_page_private(page, 0);
	put_page(page);
	get_page(newpage);

	bh = head;
	do {
		set_bh_page(bh, newpage, bh_offset(bh));
		bh = bh->b_this_page;

	} while (bh != head);

	SetPagePrivate(newpage);

	if ((int)mode != MIGRATE_SYNC_NO_COPY)
		migrate_page_copy(newpage, page);
	else
		migrate_page_states(newpage, page);

	bh = head;
	do {
		unlock_buffer(bh);
 		put_bh(bh);
		bh = bh->b_this_page;

	} while (bh != head);

	return MIGRATEPAGE_SUCCESS;
}
EXPORT_SYMBOL(buffer_migrate_page);
#endif

/*
 * Writeback a page to clean the dirty state
 */
static int writeout(struct address_space *mapping, struct page *page)
{
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_NONE,
		.nr_to_write = 1,
		.range_start = 0,
		.range_end = LLONG_MAX,
		.for_reclaim = 1
	};
	int rc;

	if (!mapping->a_ops->writepage)
		/* No write method for the address space */
		return -EINVAL;

	if (!clear_page_dirty_for_io(page))
		/* Someone else already triggered a write */
		return -EAGAIN;

	/*
	 * A dirty page may imply that the underlying filesystem has
	 * the page on some queue. So the page must be clean for
	 * migration. Writeout may mean we loose the lock and the
	 * page state is no longer what we checked for earlier.
	 * At this point we know that the migration attempt cannot
	 * be successful.
	 */
	remove_migration_ptes(page, page);

	rc = mapping->a_ops->writepage(page, &wbc);

	if (rc != AOP_WRITEPAGE_ACTIVATE)
		/* unlocked. Relock */
		lock_page(page);

	return (rc < 0) ? -EIO : -EAGAIN;
}

/*
 * Default handling if a filesystem does not provide a migration function.
 */
static int fallback_migrate_page(struct address_space *mapping,
	struct page *newpage, struct page *page, enum migrate_mode mode)
{
	if (PageDirty(page)) {
		/* Only writeback pages in full synchronous migration */
		switch ((int)mode) {
		case MIGRATE_SYNC:
		case MIGRATE_SYNC_NO_COPY:
			break;
		default:
			return -EBUSY;
		}
		return writeout(mapping, page);
	}

	/*
	 * Buffers may be managed in a filesystem specific way.
	 * We must have no buffers or drop them.
	 */
	if (page_has_private(page) &&
	    !try_to_release_page(page, GFP_KERNEL))
		return -EAGAIN;

	return migrate_page(mapping, newpage, page, mode);
}

/*
 * Move a page to a newly allocated page
 * The page is locked and all ptes have been successfully removed.
 *
 * The new page will have replaced the old page if this function
 * is successful.
 *
 * Return value:
 *   < 0 - error code
 *  MIGRATEPAGE_SUCCESS - success
 */
static int move_to_new_page(struct page *newpage, struct page *page,
				int page_was_mapped, enum migrate_mode mode)
{
	struct address_space *mapping;
	int rc;

	/*
	 * Block others from accessing the page when we get around to
	 * establishing additional references. We are the only one
	 * holding a reference to the new page at this point.
	 */
	if (!trylock_page(newpage))
		BUG();

	/* Prepare mapping for the new page.*/
	newpage->index = page->index;
	newpage->mapping = page->mapping;
	if (PageSwapBacked(page))
		SetPageSwapBacked(newpage);

	mapping = page_mapping(page);
	if (!mapping)
		rc = migrate_page(mapping, newpage, page, mode);
	else if (mapping->a_ops->migratepage)
		/*
		 * Most pages have a mapping and most filesystems provide a
		 * migratepage callback. Anonymous pages are part of swap
		 * space which also has its own migratepage callback. This
		 * is the most common path for page migration.
		 */
		rc = mapping->a_ops->migratepage(mapping,
						newpage, page, mode);
	else
		rc = fallback_migrate_page(mapping, newpage, page, mode);

	if (rc != MIGRATEPAGE_SUCCESS) {
		newpage->mapping = NULL;
	} else {
		if (page_was_mapped)
			remove_migration_ptes(page, newpage);
		page->mapping = NULL;
	}

	unlock_page(newpage);

	return rc;
}

static int __unmap_and_move(struct page *page, struct page *newpage,
				int force, enum migrate_mode mode)
{
	int rc = -EAGAIN;
	int page_was_mapped = 0;
	struct mem_cgroup *mem;
	struct anon_vma *anon_vma = NULL;

	if (!trylock_page(page)) {
		if (!force || mode == MIGRATE_ASYNC)
			goto out;

		/*
		 * It's not safe for direct compaction to call lock_page.
		 * For example, during page readahead pages are added locked
		 * to the LRU. Later, when the IO completes the pages are
		 * marked uptodate and unlocked. However, the queueing
		 * could be merging multiple pages for one bio (e.g.
		 * mpage_readpages). If an allocation happens for the
		 * second or third page, the process can end up locking
		 * the same page twice and deadlocking. Rather than
		 * trying to be clever about what pages can be locked,
		 * avoid the use of lock_page for direct compaction
		 * altogether.
		 */
		if (current->flags & PF_MEMALLOC)
			goto out;

		lock_page(page);
	}

	/* charge against new page */
	mem_cgroup_prepare_migration(page, newpage, &mem);

	if (PageWriteback(page)) {
		/*
		 * Only in the case of a full synchronous migration is it
		 * necessary to wait for PageWriteback. In the async case,
		 * the retry loop is too short and in the sync-light case,
		 * the overhead of stalling is too much
		 */
		switch ((int)mode) {
		case MIGRATE_SYNC:
		case MIGRATE_SYNC_NO_COPY:
			break;
		default:
			rc = -EBUSY;
			goto uncharge;
		}
		if (!force)
			goto uncharge;
		wait_on_page_writeback(page);
	}
	/*
	 * By try_to_unmap(), page->mapcount goes down to 0 here. In this case,
	 * we cannot notice that anon_vma is freed while we migrates a page.
	 * This get_anon_vma() delays freeing anon_vma pointer until the end
	 * of migration. File cache pages are no problem because of page_lock()
	 * File Caches may use write_page() or lock_page() in migration, then,
	 * just care Anon page here.
	 */
	if (PageAnon(page) && !PageKsm(page)) {
		/*
		 * Only page_lock_anon_vma_read() understands the subtleties of
		 * getting a hold on an anon_vma from outside one of its mms.
		 */
		anon_vma = page_get_anon_vma(page);
		if (anon_vma) {
			/*
			 * Anon page
			 */
		} else if (PageSwapCache(page)) {
			/*
			 * We cannot be sure that the anon_vma of an unmapped
			 * swapcache page is safe to use because we don't
			 * know in advance if the VMA that this page belonged
			 * to still exists. If the VMA and others sharing the
			 * data have been freed, then the anon_vma could
			 * already be invalid.
			 *
			 * To avoid this possibility, swapcache pages get
			 * migrated but are not remapped when migration
			 * completes
			 */
		} else {
			goto uncharge;
		}
	}

	if (unlikely(isolated_balloon_page(page))) {
		/*
		 * A ballooned page does not need any special attention from
		 * physical to virtual reverse mapping procedures.
		 * Skip any attempt to unmap PTEs or to remap swap cache,
		 * in order to avoid burning cycles at rmap level, and perform
		 * the page migration right away (proteced by page lock).
		 */
		rc = balloon_page_migrate(newpage, page, mode);
		goto uncharge;
	}

	/*
	 * Corner case handling:
	 * 1. When a new swap-cache page is read into, it is added to the LRU
	 * and treated as swapcache but it has no rmap yet.
	 * Calling try_to_unmap() against a page->mapping==NULL page will
	 * trigger a BUG.  So handle it here.
	 * 2. An orphaned page (see truncate_complete_page) might have
	 * fs-private metadata. The page can be picked up due to memory
	 * offlining.  Everywhere else except page reclaim, the page is
	 * invisible to the vm, so the page can not be migrated.  So try to
	 * free the metadata, so the page can be freed.
	 */
	if (!page->mapping) {
		VM_BUG_ON_PAGE(PageAnon(page), page);
		if (page_has_private(page)) {
			try_to_free_buffers(page);
			goto uncharge;
		}
		goto skip_unmap;
	}

	/* Establish migration ptes or remove ptes */
	if (page_mapped(page)) {
		try_to_unmap(page,
			TTU_MIGRATION|TTU_IGNORE_MLOCK|TTU_IGNORE_ACCESS);
		page_was_mapped = 1;
	}

skip_unmap:
	if (!page_mapped(page))
		rc = move_to_new_page(newpage, page, page_was_mapped, mode);

	if (rc && page_was_mapped)
		remove_migration_ptes(page, page);

	/* Drop an anon_vma reference if we took one */
	if (anon_vma)
		put_anon_vma(anon_vma);

uncharge:
	mem_cgroup_end_migration(mem, page, newpage,
				 rc == MIGRATEPAGE_SUCCESS);
	unlock_page(page);
out:
	return rc;
}

/*
 * Obtain the lock on page, remove all ptes and migrate the page
 * to the newly allocated page in newpage.
 */
static int unmap_and_move(new_page_t get_new_page, unsigned long private,
			struct page *page, int force, enum migrate_mode mode,
			enum migrate_reason reason)
{
	int rc = 0;
	int *result = NULL;
	struct page *newpage = get_new_page(page, private, &result);
	bool is_lru = !isolated_balloon_page(page);

	if (!newpage)
		return -ENOMEM;

	if (page_count(page) == 1) {
		/* page was freed from under us. So we are done. */
		goto out;
	}

	if (unlikely(PageTransHuge(page)))
		if (unlikely(split_huge_page(page)))
			goto out;

	rc = __unmap_and_move(page, newpage, force, mode);

out:
	if (rc != -EAGAIN) {
		/*
		 * A page that has been migrated has all references
		 * removed and will be freed. A page that has not been
		 * migrated will have kepts its references and be
		 * restored.
		 */
		list_del(&page->lru);
		dec_zone_page_state(page, NR_ISOLATED_ANON +
				page_is_file_cache(page));
		if (reason != MR_MEMORY_FAILURE)
			putback_lru_page(page);
	}
	/*
	 * Move the new page to the LRU. If migration was not successful
	 * then this will free the page. Use the old state of the isolated
	 * source page to determine if we migrated a LRU page. newpage was
	 * already unlocked and possibly modified by its owner - don't rely
	 * on the page state.
	 */
	if (rc == MIGRATEPAGE_SUCCESS && unlikely(!is_lru)) {
		/* drop our reference, page already in the balloon */
		put_page(newpage);
	} else {
		putback_lru_page(newpage);
	}

	if (result) {
		if (rc)
			*result = rc;
		else
			*result = page_to_nid(newpage);
	}
	return rc;
}

/*
 * Counterpart of unmap_and_move_page() for hugepage migration.
 *
 * This function doesn't wait the completion of hugepage I/O
 * because there is no race between I/O and migration for hugepage.
 * Note that currently hugepage I/O occurs only in direct I/O
 * where no lock is held and PG_writeback is irrelevant,
 * and writeback status of all subpages are counted in the reference
 * count of the head page (i.e. if all subpages of a 2MB hugepage are
 * under direct I/O, the reference of the head page is 512 and a bit more.)
 * This means that when we try to migrate hugepage whose subpages are
 * doing direct I/O, some references remain after try_to_unmap() and
 * hugepage migration fails without data corruption.
 *
 * There is also no race when direct I/O is issued on the page under migration,
 * because then pte is replaced with migration swap entry and direct I/O code
 * will wait in the page fault for migration to complete.
 */
static int unmap_and_move_huge_page(new_page_t get_new_page,
				unsigned long private, struct page *hpage,
				int force, enum migrate_mode mode, int reason)
{
	int rc = 0;
	int *result = NULL;
	int page_was_mapped = 0;
	struct page *new_hpage;
	struct anon_vma *anon_vma = NULL;

	/*
	 * Movability of hugepages depends on architectures and hugepage size.
	 * This check is necessary because some callers of hugepage migration
	 * like soft offline and memory hotremove don't walk through page
	 * tables or check whether the hugepage is pmd-based or not before
	 * kicking migration.
	 */
	if (!hugepage_migration_supported(page_hstate(hpage))) {
		putback_active_hugepage(hpage);
		return -ENOSYS;
	}

	new_hpage = get_new_page(hpage, private, &result);
	if (!new_hpage)
		return -ENOMEM;

	rc = -EAGAIN;

	if (!trylock_page(hpage)) {
		if (!force)
			goto out;
		switch ((int)mode) {
		case MIGRATE_SYNC:
		case MIGRATE_SYNC_NO_COPY:
			break;
		default:
			goto out;
		}
		lock_page(hpage);
	}

	/*
	 * Check for pages which are in the process of being freed.  Without
	 * page_mapping() set, hugetlbfs specific move page routine will not
	 * be called and we could leak usage counts for subpools.
	 */
	if (page_private(hpage) && !page_mapping(hpage)) {
		rc = -EBUSY;
		goto out_unlock;
	}

	if (PageAnon(hpage))
		anon_vma = page_get_anon_vma(hpage);

	if (page_mapped(hpage)) {
		try_to_unmap(hpage,
			TTU_MIGRATION|TTU_IGNORE_MLOCK|TTU_IGNORE_ACCESS);
		page_was_mapped = 1;
	}

	if (!page_mapped(hpage))
		rc = move_to_new_page(new_hpage, hpage, page_was_mapped, mode);

	if (rc != MIGRATEPAGE_SUCCESS && page_was_mapped)
		remove_migration_ptes(hpage, hpage);

	if (anon_vma)
		put_anon_vma(anon_vma);

	if (!rc)
		hugetlb_cgroup_migrate(hpage, new_hpage);

out_unlock:
	unlock_page(hpage);
out:
	if (rc != -EAGAIN)
		putback_active_hugepage(hpage);

	if (reason == MR_MEMORY_FAILURE && !test_set_page_hwpoison(hpage))
		atomic_long_inc(&num_poisoned_pages);

	putback_active_hugepage(new_hpage);
	if (result) {
		if (rc)
			*result = rc;
		else
			*result = page_to_nid(new_hpage);
	}
	return rc;
}

/*
 * migrate_pages - migrate the pages specified in a list, to the free pages
 *		   supplied as the target for the page migration
 *
 * @from:		The list of pages to be migrated.
 * @get_new_page:	The function used to allocate free pages to be used
 *			as the target of the page migration.
 * @private:		Private data to be passed on to get_new_page()
 * @mode:		The migration mode that specifies the constraints for
 *			page migration, if any.
 * @reason:		The reason for page migration.
 *
 * The function returns after 10 attempts or if no pages are movable any more
 * because the list has become empty or no retryable pages exist any more.
 * The caller should call putback_lru_pages() to return pages to the LRU
 * or free list only if ret != 0.
 *
 * Returns the number of pages that were not migrated, or an error code.
 */
int migrate_pages(struct list_head *from, new_page_t get_new_page,
		unsigned long private, enum migrate_mode mode, int reason)
{
	int retry = 1;
	int nr_failed = 0;
	int nr_succeeded = 0;
	int pass = 0;
	struct page *page;
	struct page *page2;
	int swapwrite = current->flags & PF_SWAPWRITE;
	int rc;

	if (!swapwrite)
		current->flags |= PF_SWAPWRITE;

	for(pass = 0; pass < 10 && retry; pass++) {
		retry = 0;

		list_for_each_entry_safe(page, page2, from, lru) {
			cond_resched();

			if (PageHuge(page))
				rc = unmap_and_move_huge_page(get_new_page,
						private, page, pass > 2, mode,
						reason);
			else
				rc = unmap_and_move(get_new_page, private,
						page, pass > 2, mode, reason);

			switch(rc) {
			case -ENOMEM:
				goto out;
			case -EAGAIN:
				retry++;
				break;
			case MIGRATEPAGE_SUCCESS:
				nr_succeeded++;
				break;
			default:
				/* Permanent failure */
				nr_failed++;
				break;
			}
		}
	}
	rc = nr_failed + retry;
out:
	if (nr_succeeded)
		count_vm_events(PGMIGRATE_SUCCESS, nr_succeeded);
	if (nr_failed)
		count_vm_events(PGMIGRATE_FAIL, nr_failed);
	trace_mm_migrate_pages(nr_succeeded, nr_failed, mode, reason);

	if (!swapwrite)
		current->flags &= ~PF_SWAPWRITE;

	return rc;
}

#ifdef CONFIG_NUMA
/*
 * Move a list of individual pages
 */
struct page_to_node {
	unsigned long addr;
	struct page *page;
	int node;
	int status;
};

static struct page *new_page_node(struct page *p, unsigned long private,
		int **result)
{
	struct page_to_node *pm = (struct page_to_node *)private;

	while (pm->node != MAX_NUMNODES && pm->page != p)
		pm++;

	if (pm->node == MAX_NUMNODES)
		return NULL;

	*result = &pm->status;

	if (PageHuge(p))
		return alloc_huge_page_node(page_hstate(compound_head(p)),
					pm->node);
	else
		return alloc_pages_exact_node(pm->node,
				GFP_HIGHUSER_MOVABLE | __GFP_THISNODE, 0);
}

/*
 * Move a set of pages as indicated in the pm array. The addr
 * field must be set to the virtual address of the page to be moved
 * and the node number must contain a valid target node.
 * The pm array ends with node = MAX_NUMNODES.
 */
static int do_move_page_to_node_array(struct mm_struct *mm,
				      struct page_to_node *pm,
				      int migrate_all)
{
	int err;
	struct page_to_node *pp;
	LIST_HEAD(pagelist);

	down_read(&mm->mmap_sem);

	/*
	 * Build a list of pages to migrate
	 */
	for (pp = pm; pp->node != MAX_NUMNODES; pp++) {
		struct vm_area_struct *vma;
		struct page *page;

		err = -EFAULT;
		vma = find_vma(mm, pp->addr);
		if (!vma || pp->addr < vma->vm_start || !vma_migratable(vma))
			goto set_status;

		page = follow_page(vma, pp->addr, FOLL_GET|FOLL_SPLIT);

		err = PTR_ERR(page);
		if (IS_ERR(page))
			goto set_status;

		err = -ENOENT;
		if (!page)
			goto set_status;

		/* Use PageReserved to check for zero page */
		if (PageReserved(page))
			goto put_and_set;

		pp->page = page;
		err = page_to_nid(page);

		if (err == pp->node)
			/*
			 * Node already in the right place
			 */
			goto put_and_set;

		err = -EACCES;
		if (page_mapcount(page) > 1 &&
				!migrate_all)
			goto put_and_set;

		if (PageHuge(page)) {
			if (PageHead(page))
				isolate_huge_page(page, &pagelist);
			goto put_and_set;
		}

		err = isolate_lru_page(page);
		if (!err) {
			list_add_tail(&page->lru, &pagelist);
			inc_zone_page_state(page, NR_ISOLATED_ANON +
					    page_is_file_cache(page));
		}
put_and_set:
		/*
		 * Either remove the duplicate refcount from
		 * isolate_lru_page() or drop the page ref if it was
		 * not isolated.
		 */
		put_page(page);
set_status:
		pp->status = err;
	}

	err = 0;
	if (!list_empty(&pagelist)) {
		err = migrate_pages(&pagelist, new_page_node,
				(unsigned long)pm, MIGRATE_SYNC, MR_SYSCALL);
		if (err)
			putback_movable_pages(&pagelist);
	}

	up_read(&mm->mmap_sem);
	return err;
}

/*
 * Migrate an array of page address onto an array of nodes and fill
 * the corresponding array of status.
 */
static int do_pages_move(struct mm_struct *mm, nodemask_t task_nodes,
			 unsigned long nr_pages,
			 const void __user * __user *pages,
			 const int __user *nodes,
			 int __user *status, int flags)
{
	struct page_to_node *pm;
	unsigned long chunk_nr_pages;
	unsigned long chunk_start;
	int err;

	err = -ENOMEM;
	pm = (struct page_to_node *)__get_free_page(GFP_KERNEL);
	if (!pm)
		goto out;

	migrate_prep();

	/*
	 * Store a chunk of page_to_node array in a page,
	 * but keep the last one as a marker
	 */
	chunk_nr_pages = (PAGE_SIZE / sizeof(struct page_to_node)) - 1;

	for (chunk_start = 0;
	     chunk_start < nr_pages;
	     chunk_start += chunk_nr_pages) {
		int j;

		if (chunk_start + chunk_nr_pages > nr_pages)
			chunk_nr_pages = nr_pages - chunk_start;

		/* fill the chunk pm with addrs and nodes from user-space */
		for (j = 0; j < chunk_nr_pages; j++) {
			const void __user *p;
			int node;

			err = -EFAULT;
			if (get_user(p, pages + j + chunk_start))
				goto out_pm;
			pm[j].addr = (unsigned long) p;

			if (get_user(node, nodes + j + chunk_start))
				goto out_pm;

			err = -ENODEV;
			if (node < 0 || node >= MAX_NUMNODES)
				goto out_pm;

			if (!node_state(node, N_MEMORY))
				goto out_pm;

			err = -EACCES;
			if (!node_isset(node, task_nodes))
				goto out_pm;

			pm[j].node = node;
		}

		/* End marker for this chunk */
		pm[chunk_nr_pages].node = MAX_NUMNODES;

		/* Migrate this chunk */
		err = do_move_page_to_node_array(mm, pm,
						 flags & MPOL_MF_MOVE_ALL);
		if (err < 0)
			goto out_pm;

		/* Return status information */
		for (j = 0; j < chunk_nr_pages; j++)
			if (put_user(pm[j].status, status + j + chunk_start)) {
				err = -EFAULT;
				goto out_pm;
			}
	}
	err = 0;

out_pm:
	free_page((unsigned long)pm);
out:
	return err;
}

/*
 * Determine the nodes of an array of pages and store it in an array of status.
 */
static void do_pages_stat_array(struct mm_struct *mm, unsigned long nr_pages,
				const void __user **pages, int *status)
{
	unsigned long i;

	down_read(&mm->mmap_sem);

	for (i = 0; i < nr_pages; i++) {
		unsigned long addr = (unsigned long)(*pages);
		struct vm_area_struct *vma;
		struct page *page;
		int err = -EFAULT;

		vma = find_vma(mm, addr);
		if (!vma || addr < vma->vm_start)
			goto set_status;

		page = follow_page(vma, addr, 0);

		err = PTR_ERR(page);
		if (IS_ERR(page))
			goto set_status;

		err = -ENOENT;
		/* Use PageReserved to check for zero page */
		if (!page || PageReserved(page))
			goto set_status;

		err = page_to_nid(page);
set_status:
		*status = err;

		pages++;
		status++;
	}

	up_read(&mm->mmap_sem);
}

/*
 * Determine the nodes of a user array of pages and store it in
 * a user array of status.
 */
static int do_pages_stat(struct mm_struct *mm, unsigned long nr_pages,
			 const void __user * __user *pages,
			 int __user *status)
{
#define DO_PAGES_STAT_CHUNK_NR 16
	const void __user *chunk_pages[DO_PAGES_STAT_CHUNK_NR];
	int chunk_status[DO_PAGES_STAT_CHUNK_NR];

	while (nr_pages) {
		unsigned long chunk_nr;

		chunk_nr = nr_pages;
		if (chunk_nr > DO_PAGES_STAT_CHUNK_NR)
			chunk_nr = DO_PAGES_STAT_CHUNK_NR;

		if (copy_from_user(chunk_pages, pages, chunk_nr * sizeof(*chunk_pages)))
			break;

		do_pages_stat_array(mm, chunk_nr, chunk_pages, chunk_status);

		if (copy_to_user(status, chunk_status, chunk_nr * sizeof(*status)))
			break;

		pages += chunk_nr;
		status += chunk_nr;
		nr_pages -= chunk_nr;
	}
	return nr_pages ? -EFAULT : 0;
}

/*
 * Move a list of pages in the address space of the currently executing
 * process.
 */
SYSCALL_DEFINE6(move_pages, pid_t, pid, unsigned long, nr_pages,
		const void __user * __user *, pages,
		const int __user *, nodes,
		int __user *, status, int, flags)
{
	struct task_struct *task;
	struct mm_struct *mm;
	int err;
	nodemask_t task_nodes;

	/* Check flags */
	if (flags & ~(MPOL_MF_MOVE|MPOL_MF_MOVE_ALL))
		return -EINVAL;

	if ((flags & MPOL_MF_MOVE_ALL) && !capable(CAP_SYS_NICE))
		return -EPERM;

	/* Find the mm_struct */
	rcu_read_lock();
	task = pid ? find_task_by_vpid(pid) : current;
	if (!task) {
		rcu_read_unlock();
		return -ESRCH;
	}
	get_task_struct(task);

	/*
	 * Check if this process has the right to modify the specified
	 * process. Use the regular "ptrace_may_access()" checks.
	 */
	if (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS)) {
		rcu_read_unlock();
		err = -EPERM;
		goto out;
	}
	rcu_read_unlock();

 	err = security_task_movememory(task);
 	if (err)
		goto out;

	task_nodes = cpuset_mems_allowed(task);
	mm = get_task_mm(task);
	put_task_struct(task);

	if (!mm)
		return -EINVAL;

	if (nodes)
		err = do_pages_move(mm, task_nodes, nr_pages, pages,
				    nodes, status, flags);
	else
		err = do_pages_stat(mm, nr_pages, pages, status);

	mmput(mm);
	return err;

out:
	put_task_struct(task);
	return err;
}

/*
 * Call migration functions in the vma_ops that may prepare
 * memory in a vm for migration. migration functions may perform
 * the migration for vmas that do not have an underlying page struct.
 */
int migrate_vmas(struct mm_struct *mm, const nodemask_t *to,
	const nodemask_t *from, unsigned long flags)
{
 	struct vm_area_struct *vma;
 	int err = 0;

	for (vma = mm->mmap; vma && !err; vma = vma->vm_next) {
 		if (vma->vm_ops && vma->vm_ops->migrate) {
 			err = vma->vm_ops->migrate(vma, to, from, flags);
 			if (err)
 				break;
 		}
 	}
 	return err;
}

#ifdef CONFIG_NUMA_BALANCING
/*
 * Returns true if this is a safe migration target node for misplaced NUMA
 * pages. Currently it only checks the watermarks which crude
 */
static bool migrate_balanced_pgdat(struct pglist_data *pgdat,
				   unsigned long nr_migrate_pages)
{
	int z;
	for (z = pgdat->nr_zones - 1; z >= 0; z--) {
		struct zone *zone = pgdat->node_zones + z;

		if (!populated_zone(zone))
			continue;

		if (!zone_reclaimable(zone))
			continue;

		/* Avoid waking kswapd by allocating pages_to_migrate pages. */
		if (!zone_watermark_ok(zone, 0,
				       high_wmark_pages(zone) +
				       nr_migrate_pages,
				       0, 0))
			continue;
		return true;
	}
	return false;
}

static struct page *alloc_misplaced_dst_page(struct page *page,
					   unsigned long data,
					   int **result)
{
	int nid = (int) data;
	struct page *newpage;

	newpage = alloc_pages_exact_node(nid,
					 (GFP_HIGHUSER_MOVABLE |
					  __GFP_THISNODE | __GFP_NOMEMALLOC |
					  __GFP_NORETRY | __GFP_NOWARN) &
					 ~GFP_IOFS, 0);
	if (newpage)
		page_cpupid_xchg_last(newpage, page_cpupid_last(page));

	return newpage;
}

/*
 * page migration rate limiting control.
 * Do not migrate more than @pages_to_migrate in a @migrate_interval_millisecs
 * window of time. Default here says do not migrate more than 1280M per second.
 * If a node is rate-limited then PTE NUMA updates are also rate-limited. However
 * as it is faults that reset the window, pte updates will happen unconditionally
 * if there has not been a fault since @pteupdate_interval_millisecs after the
 * throttle window closed.
 */
static unsigned int migrate_interval_millisecs __read_mostly = 100;
static unsigned int pteupdate_interval_millisecs __read_mostly = 1000;
static unsigned int ratelimit_pages __read_mostly = 128 << (20 - PAGE_SHIFT);

/* Returns true if NUMA migration is currently rate limited */
bool migrate_ratelimited(int node)
{
	pg_data_t *pgdat = NODE_DATA(node);

	if (time_after(jiffies, pgdat->numabalancing_migrate_next_window +
				msecs_to_jiffies(pteupdate_interval_millisecs)))
		return false;

	if (pgdat->numabalancing_migrate_nr_pages < ratelimit_pages)
		return false;

	return true;
}

/* Returns true if the node is migrate rate-limited after the update */
static bool numamigrate_update_ratelimit(pg_data_t *pgdat,
					unsigned long nr_pages)
{
	/*
	 * Rate-limit the amount of data that is being migrated to a node.
	 * Optimal placement is no good if the memory bus is saturated and
	 * all the time is being spent migrating!
	 */
	if (time_after(jiffies, pgdat->numabalancing_migrate_next_window)) {
		spin_lock(&pgdat->numabalancing_migrate_lock);
		pgdat->numabalancing_migrate_nr_pages = 0;
		pgdat->numabalancing_migrate_next_window = jiffies +
			msecs_to_jiffies(migrate_interval_millisecs);
		spin_unlock(&pgdat->numabalancing_migrate_lock);
	}
	if (pgdat->numabalancing_migrate_nr_pages > ratelimit_pages) {
		trace_mm_numa_migrate_ratelimit(current, pgdat->node_id,
								nr_pages);
		return true;
	}

	/*
	 * This is an unlocked non-atomic update so errors are possible.
	 * The consequences are failing to migrate when we potentiall should
	 * have which is not severe enough to warrant locking. If it is ever
	 * a problem, it can be converted to a per-cpu counter.
	 */
	pgdat->numabalancing_migrate_nr_pages += nr_pages;
	return false;
}

static int numamigrate_isolate_page(pg_data_t *pgdat, struct page *page)
{
	int page_lru;

	VM_BUG_ON_PAGE(compound_order(page) && !PageTransHuge(page), page);

	/* Avoid migrating to a node that is nearly full */
	if (!migrate_balanced_pgdat(pgdat, 1UL << compound_order(page)))
		return 0;

	if (isolate_lru_page(page))
		return 0;

	/*
	 * migrate_misplaced_transhuge_page() skips page migration's usual
	 * check on page_count(), so we must do it here, now that the page
	 * has been isolated: a GUP pin, or any other pin, prevents migration.
	 * The expected page count is 3: 1 for page's mapcount and 1 for the
	 * caller's pin and 1 for the reference taken by isolate_lru_page().
	 */
	if (PageTransHuge(page) && page_count(page) != 3) {
		putback_lru_page(page);
		return 0;
	}

	page_lru = page_is_file_cache(page);
	mod_zone_page_state(page_zone(page), NR_ISOLATED_ANON + page_lru,
				hpage_nr_pages(page));

	/*
	 * Isolating the page has taken another reference, so the
	 * caller's reference can be safely dropped without the page
	 * disappearing underneath us during migration.
	 */
	put_page(page);
	return 1;
}

bool pmd_trans_migrating(pmd_t pmd)
{
	struct page *page = pmd_page(pmd);
	return PageLocked(page);
}

/*
 * Attempt to migrate a misplaced page to the specified destination
 * node. Caller is expected to have an elevated reference count on
 * the page that will be dropped by this function before returning.
 */
int migrate_misplaced_page(struct page *page, struct vm_area_struct *vma,
			   int node)
{
	pg_data_t *pgdat = NODE_DATA(node);
	int isolated;
	int nr_remaining;
	LIST_HEAD(migratepages);

	/*
	 * Don't migrate file pages that are mapped in multiple processes
	 * with execute permissions as they are probably shared libraries.
	 */
	if (page_mapcount(page) != 1 && page_is_file_cache(page) &&
	    (vma->vm_flags & VM_EXEC))
		goto out;

	/*
	 * Rate-limit the amount of data that is being migrated to a node.
	 * Optimal placement is no good if the memory bus is saturated and
	 * all the time is being spent migrating!
	 */
	if (numamigrate_update_ratelimit(pgdat, 1))
		goto out;

	isolated = numamigrate_isolate_page(pgdat, page);
	if (!isolated)
		goto out;

	list_add(&page->lru, &migratepages);
	nr_remaining = migrate_pages(&migratepages, alloc_misplaced_dst_page,
				     node, MIGRATE_ASYNC, MR_NUMA_MISPLACED);
	if (nr_remaining) {
		putback_lru_pages(&migratepages);
		isolated = 0;
	} else
		count_vm_numa_event(NUMA_PAGE_MIGRATE);
	BUG_ON(!list_empty(&migratepages));
	return isolated;

out:
	put_page(page);
	return 0;
}
#endif /* CONFIG_NUMA_BALANCING */

#if defined(CONFIG_NUMA_BALANCING) && defined(CONFIG_TRANSPARENT_HUGEPAGE)
/*
 * Migrates a THP to a given target node. page must be locked and is unlocked
 * before returning.
 */
int migrate_misplaced_transhuge_page(struct mm_struct *mm,
				struct vm_area_struct *vma,
				pmd_t *pmd, pmd_t entry,
				unsigned long address,
				struct page *page, int node)
{
	spinlock_t *ptl;
	pg_data_t *pgdat = NODE_DATA(node);
	int isolated = 0;
	struct page *new_page = NULL;
	struct mem_cgroup *memcg = NULL;
	int page_lru = page_is_file_cache(page);
	unsigned long start = address & HPAGE_PMD_MASK;

	/*
	 * Rate-limit the amount of data that is being migrated to a node.
	 * Optimal placement is no good if the memory bus is saturated and
	 * all the time is being spent migrating!
	 */
	if (numamigrate_update_ratelimit(pgdat, HPAGE_PMD_NR))
		goto out_dropref;

	new_page = alloc_pages_node(node,
		(GFP_TRANSHUGE | __GFP_THISNODE) & ~__GFP_WAIT,
		HPAGE_PMD_ORDER);
	if (!new_page)
		goto out_fail;

	isolated = numamigrate_isolate_page(pgdat, page);
	if (!isolated) {
		put_page(new_page);
		goto out_fail;
	}

	/* Prepare a page as a migration target */
	__set_page_locked(new_page);
	SetPageSwapBacked(new_page);

	/* anon mapping, we can simply copy page->mapping to the new page: */
	new_page->mapping = page->mapping;
	new_page->index = page->index;
	/* flush the cache before copying using the kernel virtual address */
	flush_cache_range(vma, start, start + HPAGE_PMD_SIZE);
	migrate_page_copy(new_page, page);
	WARN_ON(PageLRU(new_page));

	/* Recheck the target PMD */
	ptl = pmd_lock(mm, pmd);
	if (unlikely(!pmd_same(*pmd, entry) || !page_ref_freeze(page, 2))) {
		spin_unlock(ptl);

		/* Reverse changes made by migrate_page_copy() */
		if (TestClearPageActive(new_page))
			SetPageActive(page);
		if (TestClearPageUnevictable(new_page))
			SetPageUnevictable(page);

		unlock_page(new_page);
		put_page(new_page);		/* Free it */

		/* Retake the callers reference and putback on LRU */
		get_page(page);
		putback_lru_page(page);
		mod_zone_page_state(page_zone(page),
			 NR_ISOLATED_ANON + page_lru, -HPAGE_PMD_NR);

		goto out_unlock;
	}

	/*
	 * Traditional migration needs to prepare the memcg charge
	 * transaction early to prevent the old page from being
	 * uncharged when installing migration entries.  Here we can
	 * save the potential rollback and start the charge transfer
	 * only when migration is already known to end successfully.
	 */
	mem_cgroup_prepare_migration(page, new_page, &memcg);

	init_trans_huge_mmu_gather_count(new_page);

	entry = mk_pmd(new_page, vma->vm_page_prot);
	entry = pmd_mkhuge(entry);
	entry = maybe_pmd_mkwrite(pmd_mkdirty(entry), vma);

	/*
	 * Overwrite the old entry under pagetable lock and establish
	 * the new PTE. Any parallel GUP will either observe the old
	 * page blocking on the page lock, block on the page table
	 * lock or observe the new page. The SetPageUptodate on the
	 * new page and page_add_new_anon_rmap guarantee the copy is
	 * visible before the pagetable update.
	 */
	page_add_anon_rmap(new_page, vma, start);
	/*
	 * At this point the pmd is numa/protnone (i.e. non present) and the TLB
	 * has already been flushed globally.  So no TLB can be currently
	 * caching this non present pmd mapping.  There's no need to clear the
	 * pmd before doing set_pmd_at(), nor to flush the TLB after
	 * set_pmd_at().  Clearing the pmd here would introduce a race
	 * condition against MADV_DONTNEED, because MADV_DONTNEED only holds the
	 * mmap_sem for reading.  If the pmd is set to NULL at any given time,
	 * MADV_DONTNEED won't wait on the pmd lock and it'll skip clearing this
	 * pmd.
	 */
	set_pmd_at(mm, start, pmd, entry);
	update_mmu_cache_pmd(vma, address, &entry);

	page_ref_unfreeze(page, 2);
	mlock_migrate_page(new_page, page);
	page_remove_rmap(page);

	/*
	 * Finish the charge transaction under the page table lock to
	 * prevent split_huge_page() from dividing up the charge
	 * before it's fully transferred to the new page.
	 */
	mem_cgroup_end_migration(memcg, page, new_page, true);
	spin_unlock(ptl);

	/* Take an "isolate" reference and put new page on the LRU. */
	get_page(new_page);
	putback_lru_page(new_page);

	unlock_page(new_page);
	unlock_page(page);
	put_page(page);			/* Drop the rmap reference */
	put_page(page);			/* Drop the LRU isolation reference */

	count_vm_events(PGMIGRATE_SUCCESS, HPAGE_PMD_NR);
	count_vm_numa_events(NUMA_PAGE_MIGRATE, HPAGE_PMD_NR);

	mod_zone_page_state(page_zone(page),
			NR_ISOLATED_ANON + page_lru,
			-HPAGE_PMD_NR);
	return isolated;

out_fail:
	count_vm_events(PGMIGRATE_FAIL, HPAGE_PMD_NR);
out_dropref:
	ptl = pmd_lock(mm, pmd);
	if (pmd_same(*pmd, entry)) {
		entry = pmd_mknonnuma(entry);
		set_pmd_at(mm, start, pmd, entry);
		update_mmu_cache_pmd(vma, address, &entry);
	}
	spin_unlock(ptl);

out_unlock:
	unlock_page(page);
	put_page(page);
	return 0;
}
#endif /* CONFIG_NUMA_BALANCING */

#endif /* CONFIG_NUMA */


struct migrate_vma {
	struct vm_area_struct	*vma;
	unsigned long		*dst;
	unsigned long		*src;
	unsigned long		cpages;
	unsigned long		npages;
	unsigned long		start;
	unsigned long		end;
};

static int migrate_vma_collect_hole(unsigned long start,
				    unsigned long end,
				    struct mm_walk *walk)
{
	struct migrate_vma *migrate = walk->private;
	unsigned long addr;

	for (addr = start & PAGE_MASK; addr < end; addr += PAGE_SIZE) {
		migrate->src[migrate->npages] = MIGRATE_PFN_MIGRATE;
		migrate->dst[migrate->npages] = 0;
		migrate->npages++;
		migrate->cpages++;
	}

	return 0;
}

static int migrate_vma_collect_pmd(pmd_t *pmdp,
				   unsigned long start,
				   unsigned long end,
				   struct mm_walk *walk)
{
	struct migrate_vma *migrate = walk->private;
	unsigned long addr = start, unmapped = 0;
	struct mm_struct *mm = walk->mm;
	spinlock_t *ptl;
	pte_t *ptep;

	if (pmd_trans_huge(*pmdp))
		split_huge_page_pmd(migrate->vma, start, pmdp);
	if (pmd_none_or_trans_huge_or_clear_bad(pmdp))
		return migrate_vma_collect_hole(start, end, walk);

	ptep = pte_offset_map_lock(mm, pmdp, addr, &ptl);
	arch_enter_lazy_mmu_mode();

	for (; addr < end; addr += PAGE_SIZE, ptep++) {
		unsigned long mpfn, pfn;
		struct page *page;
		swp_entry_t entry;
		pte_t pte;

		pte = *ptep;
		pfn = pte_pfn(pte);

		if (pte_none(pte)) {
			mpfn = MIGRATE_PFN_MIGRATE;
			migrate->cpages++;
			pfn = 0;
			goto next;
		}

		if (!pte_present(pte)) {
			mpfn = pfn = 0;

			if (pte_file(pte))
				goto next;

			/*
			 * Only care about unaddressable device page special
			 * page table entry. Other special swap entries are not
			 * migratable, and we ignore regular swapped page.
			 */
			entry = pte_to_swp_entry(pte);
			if (!is_hmm_entry(entry))
				goto next;

			page = hmm_entry_to_page(entry);
			mpfn = migrate_pfn(page_to_pfn(page))|
				MIGRATE_PFN_DEVICE | MIGRATE_PFN_MIGRATE;
			if (is_write_hmm_entry(entry))
				mpfn |= MIGRATE_PFN_WRITE;
		} else {
			page = vm_normal_page(migrate->vma, addr, pte);
			mpfn = migrate_pfn(pfn) | MIGRATE_PFN_MIGRATE;
			mpfn |= pte_write(pte) ? MIGRATE_PFN_WRITE : 0;
		}

		/* FIXME support THP */
		if (!page || !page->mapping || PageTransCompound(page)) {
			mpfn = pfn = 0;
			goto next;
		}
		pfn = page_to_pfn(page);

		/*
		 * By getting a reference on the page we pin it and that blocks
		 * any kind of migration. Side effect is that it "freezes" the
		 * pte.
		 *
		 * We drop this reference after isolating the page from the lru
		 * for non device page (device page are not on the lru and thus
		 * can't be dropped from it).
		 */
		get_page(page);
		migrate->cpages++;

		/*
		 * Optimize for the common case where page is only mapped once
		 * in one process. If we can lock the page, then we can safely
		 * set up a special migration page table entry now.
		 */
		if (trylock_page(page)) {
			pte_t swp_pte;

			mpfn |= MIGRATE_PFN_LOCKED;
			ptep_get_and_clear(mm, addr, ptep);

			/* Setup special migration page table entry */
			entry = make_migration_entry(page, pte_write(pte));
			swp_pte = swp_entry_to_pte(entry);
			if (pte_soft_dirty(pte))
				swp_pte = pte_swp_mksoft_dirty(swp_pte);
			set_pte_at(mm, addr, ptep, swp_pte);

			/*
			 * This is like regular unmap: we remove the rmap and
			 * drop page refcount. Page won't be freed, as we took
			 * a reference just above.
			 */
			page_remove_rmap(page);
			put_page(page);
			if (pte_present(pte))
				unmapped++;
		}

next:
		migrate->dst[migrate->npages] = 0;
		migrate->src[migrate->npages++] = mpfn;
	}
	arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(ptep - 1, ptl);

	/* Only flush the TLB if we actually modified any entries */
	if (unmapped)
		flush_tlb_range(migrate->vma, start, end);

	return 0;
}

/*
 * migrate_vma_collect() - collect pages over a range of virtual addresses
 * @migrate: migrate struct containing all migration information
 *
 * This will walk the CPU page table. For each virtual address backed by a
 * valid page, it updates the src array and takes a reference on the page, in
 * order to pin the page until we lock it and unmap it.
 */
static void migrate_vma_collect(struct migrate_vma *migrate)
{
	struct mm_walk mm_walk;

	mm_walk.pgd_entry = NULL;
	mm_walk.pud_entry = NULL;
	mm_walk.pte_entry = NULL;
	mm_walk.private = migrate;
	mm_walk.hugetlb_entry = NULL;
	mm_walk.mm = migrate->vma->vm_mm;
	mm_walk.pte_hole = migrate_vma_collect_hole;
	mm_walk.pmd_entry = migrate_vma_collect_pmd;

	mmu_notifier_invalidate_range_start(mm_walk.mm,
					    migrate->start,
					    migrate->end);
	walk_page_range(migrate->start, migrate->end, &mm_walk);
	mmu_notifier_invalidate_range_end(mm_walk.mm,
					  migrate->start,
					  migrate->end);

	migrate->end = migrate->start + (migrate->npages << PAGE_SHIFT);
}

/*
 * migrate_vma_check_page() - check if page is pinned or not
 * @page: struct page to check
 *
 * Pinned pages cannot be migrated. This is the same test as in
 * migrate_page_move_mapping(), except that here we allow migration of a
 * ZONE_DEVICE page.
 */
static bool migrate_vma_check_page(struct page *page)
{
	/*
	 * One extra ref because caller holds an extra reference, either from
	 * isolate_lru_page() for a regular page, or migrate_vma_collect() for
	 * a device page.
	 */
	int extra = 1;

	/*
	 * FIXME support THP (transparent huge page), it is bit more complex to
	 * check them than regular pages, because they can be mapped with a pmd
	 * or with a pte (split pte mapping).
	 */
	if (PageCompound(page))
		return false;

	/*
	 * Private page can never be pin as they have no valid pte and
	 * GUP will fail for those. Yet if there is a pending migration
	 * a thread might try to wait on the pte migration entry and
	 * will bump the page reference count. Sadly there is no way to
	 * differentiate a regular pin from migration wait. Hence to
	 * avoid 2 racing thread trying to migrate back to CPU to enter
	 * infinite loop (one stoping migration because the other is
	 * waiting on pte migration entry). We always return true here.
	 *
	 * FIXME proper solution is to rework migration_entry_wait() so
	 * it does not need to take a reference on page.
	 */
	if (is_hmm_page(page))
		return true;

	if (is_zone_device_page(page))
		/* Other ZONE_DEVICE memory type are not supported */
		return false;

	if ((page_count(page) - extra) > page_mapcount(page))
		return false;

	return true;
}

/*
 * migrate_vma_prepare() - lock pages and isolate them from the lru
 * @migrate: migrate struct containing all migration information
 *
 * This locks pages that have been collected by migrate_vma_collect(). Once each
 * page is locked it is isolated from the lru (for non-device pages). Finally,
 * the ref taken by migrate_vma_collect() is dropped, as locked pages cannot be
 * migrated by concurrent kernel threads.
 */
static void migrate_vma_prepare(struct migrate_vma *migrate)
{
	const unsigned long npages = migrate->npages;
	const unsigned long start = migrate->start;
	unsigned long addr, i, restore = 0;
	bool allow_drain = true;

	lru_add_drain();

	for (i = 0; (i < npages) && migrate->cpages; i++) {
		struct page *page = migrate_pfn_to_page(migrate->src[i]);
		bool remap = true;

		if (!page)
			continue;

		if (!(migrate->src[i] & MIGRATE_PFN_LOCKED)) {
			/*
			 * Because we are migrating several pages there can be
			 * a deadlock between 2 concurrent migration where each
			 * are waiting on each other page lock.
			 *
			 * Make migrate_vma() a best effort thing and backoff
			 * for any page we can not lock right away.
			 */
			if (!trylock_page(page)) {
				migrate->src[i] = 0;
				migrate->cpages--;
				put_page(page);
				continue;
			}
			remap = false;
			migrate->src[i] |= MIGRATE_PFN_LOCKED;
		}

		/* ZONE_DEVICE pages are not on LRU */
		if (!is_zone_device_page(page)) {
			if (!PageLRU(page) && allow_drain) {
				/* Drain CPU's pagevec */
				lru_add_drain_all();
				allow_drain = false;
			}

			if (isolate_lru_page(page)) {
				if (remap) {
					migrate->src[i] &= ~MIGRATE_PFN_MIGRATE;
					migrate->cpages--;
					restore++;
				} else {
					migrate->src[i] = 0;
					unlock_page(page);
					migrate->cpages--;
					put_page(page);
				}
				continue;
			}

			/* Drop the reference we took in collect */
			put_page(page);
		}

		if (!migrate_vma_check_page(page)) {
			if (remap) {
				migrate->src[i] &= ~MIGRATE_PFN_MIGRATE;
				migrate->cpages--;
				restore++;

				if (!is_zone_device_page(page)) {
					get_page(page);
					putback_lru_page(page);
				}
			} else {
				migrate->src[i] = 0;
				unlock_page(page);
				migrate->cpages--;

				if (!is_zone_device_page(page))
					putback_lru_page(page);
				else
					put_page(page);
			}
		}
	}

	for (i = 0, addr = start; i < npages && restore; i++, addr += PAGE_SIZE) {
		struct page *page = migrate_pfn_to_page(migrate->src[i]);

		if (!page || (migrate->src[i] & MIGRATE_PFN_MIGRATE))
			continue;

		remove_migration_pte(page, migrate->vma, addr, page);

		migrate->src[i] = 0;
		unlock_page(page);
		put_page(page);
		restore--;
	}
}

/*
 * migrate_vma_unmap() - replace page mapping with special migration pte entry
 * @migrate: migrate struct containing all migration information
 *
 * Replace page mapping (CPU page table pte) with a special migration pte entry
 * and check again if it has been pinned. Pinned pages are restored because we
 * cannot migrate them.
 *
 * This is the last step before we call the device driver callback to allocate
 * destination memory and copy contents of original page over to new page.
 */
static void migrate_vma_unmap(struct migrate_vma *migrate)
{
	int flags = TTU_MIGRATION | TTU_IGNORE_MLOCK | TTU_IGNORE_ACCESS;
	const unsigned long npages = migrate->npages;
	const unsigned long start = migrate->start;
	unsigned long addr, i, restore = 0;

	for (i = 0; i < npages; i++) {
		struct page *page = migrate_pfn_to_page(migrate->src[i]);

		if (!page || !(migrate->src[i] & MIGRATE_PFN_MIGRATE))
			continue;

		if (page_mapped(page)) {
			try_to_unmap(page, flags);
			if (page_mapped(page))
				goto restore;
		}

		if (migrate_vma_check_page(page))
			continue;

restore:
		migrate->src[i] &= ~MIGRATE_PFN_MIGRATE;
		migrate->cpages--;
		restore++;
	}

	for (addr = start, i = 0; i < npages && restore; addr += PAGE_SIZE, i++) {
		struct page *page = migrate_pfn_to_page(migrate->src[i]);

		if (!page || (migrate->src[i] & MIGRATE_PFN_MIGRATE))
			continue;

		remove_migration_ptes(page, page);

		migrate->src[i] = 0;
		unlock_page(page);
		restore--;

		if (is_zone_device_page(page))
			put_page(page);
		else
			putback_lru_page(page);
	}
}

static void migrate_vma_insert_page(struct migrate_vma *migrate,
				    unsigned long addr,
				    struct page *page,
				    unsigned long *src,
				    unsigned long *dst)
{
	struct vm_area_struct *vma = migrate->vma;
	struct mm_struct *mm = vma->vm_mm;
	bool flush = false;
	spinlock_t *ptl;
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;
	pte_t entry;

	/* Only allow populating anonymous memory */
	if (!vma_is_anonymous(vma))
		goto abort;

	pgdp = pgd_offset(mm, addr);
	pudp = pud_alloc(mm, pgdp, addr);
	if (!pudp)
		goto abort;
	pmdp = pmd_alloc(mm, pudp, addr);
	if (!pmdp)
		goto abort;

	if (pmd_trans_unstable(pmdp))
		goto abort;

	/*
	 * Use __pte_alloc() instead of pte_alloc_map().  We can't run
	 * pte_offset_map() on pmds where a huge pmd might be created
	 * from a different thread.
	 *
	 * pte_alloc_map() is safe to use under down_write(mmap_sem) or when
	 * parallel threads are excluded by other means.
	 *
	 * Here we only have down_read(mmap_sem).
	 */
	if (__pte_alloc(mm, vma, pmdp, addr))
		goto abort;

	/* See the comment in pte_alloc_one_map() */
	if (unlikely(pmd_trans_unstable(pmdp)))
		goto abort;

	if (unlikely(anon_vma_prepare(vma)))
		goto abort;
	if (mem_cgroup_newpage_charge(page, vma->vm_mm, GFP_KERNEL))
		goto abort;

	/*
	 * The memory barrier inside __SetPageUptodate makes sure that
	 * preceding stores to the page contents become visible before
	 * the set_pte_at() write.
	 */
	__SetPageUptodate(page);

	if (is_zone_device_page(page) && is_hmm_page(page)) {
		swp_entry_t swp_entry;

		swp_entry = make_hmm_entry(page, vma->vm_flags & VM_WRITE);
		entry = swp_entry_to_pte(swp_entry);
	} else {
		entry = mk_pte(page, vma->vm_page_prot);
		if (vma->vm_flags & VM_WRITE)
			entry = pte_mkwrite(pte_mkdirty(entry));
	}

	ptep = pte_offset_map_lock(mm, pmdp, addr, &ptl);
	if (pte_present(*ptep)) {
		unsigned long pfn = pte_pfn(*ptep);

		if (!is_zero_pfn(pfn)) {
			pte_unmap_unlock(ptep, ptl);
			mem_cgroup_uncharge_page(page);
			goto abort;
		}
		flush = true;
	} else if (!pte_none(*ptep)) {
		pte_unmap_unlock(ptep, ptl);
		mem_cgroup_uncharge_page(page);
		goto abort;
	}

	/*
	 * Check for usefaultfd but do not deliver the fault. Instead,
	 * just back off.
	 */
	if (userfaultfd_missing(vma)) {
		pte_unmap_unlock(ptep, ptl);
		mem_cgroup_uncharge_page(page);
		goto abort;
	}

	page_add_new_anon_rmap(page, vma, addr);
	inc_mm_counter(mm, MM_ANONPAGES);
	get_page(page);

	if (flush) {
		flush_cache_page(vma, addr, pte_pfn(*ptep));
		ptep_clear_flush_notify(vma, addr, ptep);
		set_pte_at_notify(mm, addr, ptep, entry);
		update_mmu_cache(vma, addr, ptep);
	} else {
		/* No need to invalidate - it was non-present before */
		update_mmu_cache(vma, addr, ptep);
		set_pte_at(mm, addr, ptep, entry);
	}
	pte_unmap_unlock(ptep, ptl);
	*src = MIGRATE_PFN_MIGRATE;
	return;

abort:
	*src &= ~MIGRATE_PFN_MIGRATE;
}

/*
 * migrate_vma_pages() - migrate meta-data from src page to dst page
 * @migrate: migrate struct containing all migration information
 *
 * This migrates struct page meta-data from source struct page to destination
 * struct page. This effectively finishes the migration from source page to the
 * destination page.
 */
static void migrate_vma_pages(struct migrate_vma *migrate)
{
	const unsigned long npages = migrate->npages;
	const unsigned long start = migrate->start;
	struct vm_area_struct *vma = migrate->vma;
	struct mm_struct *mm = vma->vm_mm;
	unsigned long addr, i, mmu_start;
	bool notified = false;

	for (i = 0, addr = start; i < npages; addr += PAGE_SIZE, i++) {
		struct page *newpage = migrate_pfn_to_page(migrate->dst[i]);
		struct page *page = migrate_pfn_to_page(migrate->src[i]);
		struct address_space *mapping;
		struct mem_cgroup *memcg;
		int r;

		if (!newpage) {
			migrate->src[i] &= ~MIGRATE_PFN_MIGRATE;
			continue;
		}

		if (!page) {
			if (!(migrate->src[i] & MIGRATE_PFN_MIGRATE)) {
				continue;
			}
			if (!notified) {
				mmu_start = addr;
				notified = true;
				mmu_notifier_invalidate_range_start(mm,
								mmu_start,
								migrate->end);
			}
			migrate_vma_insert_page(migrate, addr, newpage,
						&migrate->src[i],
						&migrate->dst[i]);
			continue;
		}

		mapping = page_mapping(page);

		if (is_zone_device_page(newpage)) {
			if (is_hmm_page(newpage)) {
				/*
				 * For now only support private anonymous when
				 * migrating to un-addressable device memory.
				 */
				if (mapping) {
					migrate->src[i] &= ~MIGRATE_PFN_MIGRATE;
					continue;
				}
			} else {
				/*
				 * Other types of ZONE_DEVICE page are not
				 * supported.
				 */
				migrate->src[i] &= ~MIGRATE_PFN_MIGRATE;
				continue;
			}
		}

		newpage->index = page->index;
		newpage->mapping = page->mapping;
		if (PageSwapBacked(page))
			SetPageSwapBacked(newpage);

		mem_cgroup_prepare_migration(page, newpage, &memcg);
		r = migrate_page(mapping, newpage, page, MIGRATE_SYNC_NO_COPY);
		mem_cgroup_end_migration(memcg, page, newpage,
					 r == MIGRATEPAGE_SUCCESS);
		if (r != MIGRATEPAGE_SUCCESS)
			migrate->src[i] &= ~MIGRATE_PFN_MIGRATE;
	}

	if (notified)
		mmu_notifier_invalidate_range_end(mm, mmu_start,
						  migrate->end);
}

/*
 * migrate_vma_finalize() - restore CPU page table entry
 * @migrate: migrate struct containing all migration information
 *
 * This replaces the special migration pte entry with either a mapping to the
 * new page if migration was successful for that page, or to the original page
 * otherwise.
 *
 * This also unlocks the pages and puts them back on the lru, or drops the extra
 * refcount, for device pages.
 */
static void migrate_vma_finalize(struct migrate_vma *migrate)
{
	const unsigned long npages = migrate->npages;
	unsigned long i;

	for (i = 0; i < npages; i++) {
		struct page *newpage = migrate_pfn_to_page(migrate->dst[i]);
		struct page *page = migrate_pfn_to_page(migrate->src[i]);

		if (!page) {
			if (newpage) {
				unlock_page(newpage);
				put_page(newpage);
			}
			continue;
		}

		if (!(migrate->src[i] & MIGRATE_PFN_MIGRATE) || !newpage) {
			if (newpage) {
				unlock_page(newpage);
				put_page(newpage);
			}
			newpage = page;
		}

		remove_migration_ptes(page, newpage);
		unlock_page(page);
		migrate->cpages--;

		if (is_zone_device_page(page))
			put_page(page);
		else
			putback_lru_page(page);

		if (newpage != page) {
			unlock_page(newpage);
			if (is_zone_device_page(newpage))
				put_page(newpage);
			else
				putback_lru_page(newpage);
		}
	}
}

/*
 * migrate_vma() - migrate a range of memory inside vma
 *
 * @ops: migration callback for allocating destination memory and copying
 * @vma: virtual memory area containing the range to be migrated
 * @start: start address of the range to migrate (inclusive)
 * @end: end address of the range to migrate (exclusive)
 * @src: array of hmm_pfn_t containing source pfns
 * @dst: array of hmm_pfn_t containing destination pfns
 * @private: pointer passed back to each of the callback
 * Returns: 0 on success, error code otherwise
 *
 * This function tries to migrate a range of memory virtual address range, using
 * callbacks to allocate and copy memory from source to destination. First it
 * collects all the pages backing each virtual address in the range, saving this
 * inside the src array. Then it locks those pages and unmaps them. Once the pages
 * are locked and unmapped, it checks whether each page is pinned or not. Pages
 * that aren't pinned have the MIGRATE_PFN_MIGRATE flag set (by this function)
 * in the corresponding src array entry. It then restores any pages that are
 * pinned, by remapping and unlocking those pages.
 *
 * At this point it calls the alloc_and_copy() callback. For documentation on
 * what is expected from that callback, see struct migrate_vma_ops comments in
 * include/linux/migrate.h
 *
 * After the alloc_and_copy() callback, this function goes over each entry in
 * the src array that has the MIGRATE_PFN_VALID and MIGRATE_PFN_MIGRATE flag
 * set. If the corresponding entry in dst array has MIGRATE_PFN_VALID flag set,
 * then the function tries to migrate struct page information from the source
 * struct page to the destination struct page. If it fails to migrate the struct
 * page information, then it clears the MIGRATE_PFN_MIGRATE flag in the src
 * array.
 *
 * At this point all successfully migrated pages have an entry in the src
 * array with MIGRATE_PFN_VALID and MIGRATE_PFN_MIGRATE flag set and the dst
 * array entry with MIGRATE_PFN_VALID flag set.
 *
 * It then calls the finalize_and_map() callback. See comments for "struct
 * migrate_vma_ops", in include/linux/migrate.h for details about
 * finalize_and_map() behavior.
 *
 * After the finalize_and_map() callback, for successfully migrated pages, this
 * function updates the CPU page table to point to new pages, otherwise it
 * restores the CPU page table to point to the original source pages.
 *
 * Function returns 0 after the above steps, even if no pages were migrated
 * (The function only returns an error if any of the arguments are invalid.)
 *
 * Both src and dst array must be big enough for (end - start) >> PAGE_SHIFT
 * unsigned long entries.
 */
int migrate_vma(const struct migrate_vma_ops *ops,
		struct vm_area_struct *vma,
		unsigned long start,
		unsigned long end,
		unsigned long *src,
		unsigned long *dst,
		void *private)
{
	struct migrate_vma migrate;

	/* Sanity check the arguments */
	start &= PAGE_MASK;
	end &= PAGE_MASK;
	if (!vma || is_vm_hugetlb_page(vma) || (vma->vm_flags & VM_SPECIAL) ||
			vma_is_dax(vma))
		return -EINVAL;
	if (start < vma->vm_start || start >= vma->vm_end)
		return -EINVAL;
	if (end <= vma->vm_start || end > vma->vm_end)
		return -EINVAL;
	if (!ops || !src || !dst || start >= end)
		return -EINVAL;

	memset(src, 0, sizeof(*src) * ((end - start) >> PAGE_SHIFT));
	migrate.src = src;
	migrate.dst = dst;
	migrate.start = start;
	migrate.npages = 0;
	migrate.cpages = 0;
	migrate.end = end;
	migrate.vma = vma;

	/* Collect, and try to unmap source pages */
	migrate_vma_collect(&migrate);
	if (!migrate.cpages)
		return 0;

	/* Lock and isolate page */
	migrate_vma_prepare(&migrate);
	if (!migrate.cpages)
		return 0;

	/* Unmap pages */
	migrate_vma_unmap(&migrate);
	if (!migrate.cpages)
		return 0;

	/*
	 * At this point pages are locked and unmapped, and thus they have
	 * stable content and can safely be copied to destination memory that
	 * is allocated by the callback.
	 *
	 * Note that migration can fail in migrate_vma_struct_page() for each
	 * individual page.
	 */
	ops->alloc_and_copy(vma, src, dst, start, end, private);

	/* This does the real migration of struct page */
	migrate_vma_pages(&migrate);

	ops->finalize_and_map(vma, src, dst, start, end, private);

	/* Unlock and remap pages */
	migrate_vma_finalize(&migrate);

	return 0;
}
EXPORT_SYMBOL(migrate_vma);
