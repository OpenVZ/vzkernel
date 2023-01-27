/*
 *  linux/mm/swap.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 */

/*
 * This file contains the default values for the operation of the
 * Linux VM subsystem. Fine-tuning documentation can be found in
 * Documentation/sysctl/vm.txt.
 * Started 18.12.91
 * Swap aging added 23.2.95, Stephen Tweedie.
 * Buffermem limits added 12.3.98, Rik van Riel.
 */

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/mm_inline.h>
#include <linux/percpu_counter.h>
#include <linux/memremap.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/backing-dev.h>
#include <linux/memcontrol.h>
#include <linux/gfp.h>
#include <linux/uio.h>
#include <linux/page_idle.h>

#include "internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/pagemap.h>

/* How many pages do we try to swap or page in/out together? */
int page_cluster;

static DEFINE_PER_CPU(struct pagevec, lru_add_pvec);
static DEFINE_PER_CPU(struct pagevec, lru_rotate_pvecs);
static DEFINE_PER_CPU(struct pagevec, lru_deactivate_file_pvecs);
static DEFINE_PER_CPU(struct pagevec, lru_deactivate_pvecs);

/*
 * This path almost never happens for VM activity - pages are normally
 * freed via pagevecs.  But it gets used by networking.
 */
static void __page_cache_release(struct page *page)
{
	if (PageLRU(page)) {
		struct zone *zone = page_zone(page);
		struct lruvec *lruvec;
		unsigned long flags;

		spin_lock_irqsave(&zone->lru_lock, flags);
		lruvec = mem_cgroup_page_lruvec(page, zone);
		VM_BUG_ON_PAGE(!PageLRU(page), page);
		__ClearPageLRU(page);
		del_page_from_lru_list(page, lruvec, page_off_lru(page));
		spin_unlock_irqrestore(&zone->lru_lock, flags);
	}
}

static void __put_single_page(struct page *page)
{
	__page_cache_release(page);
	free_hot_cold_page(page, false);
}

static void __put_compound_page(struct page *page)
{
	compound_page_dtor *dtor;

	__page_cache_release(page);
	dtor = get_compound_page_dtor(page);
	(*dtor)(page);
}

/**
 * Two special cases here: we could avoid taking compound_lock_irqsave
 * and could skip the tail refcounting(in _mapcount).
 *
 * 1. Hugetlbfs page:
 *
 *    PageHeadHuge will remain true until the compound page
 *    is released and enters the buddy allocator, and it could
 *    not be split by __split_huge_page_refcount().
 *
 *    So if we see PageHeadHuge set, and we have the tail page pin,
 *    then we could safely put head page.
 *
 * 2. Slab THP page:
 *
 *    PG_slab is cleared before the slab frees the head page, and
 *    tail pin cannot be the last reference left on the head page,
 *    because the slab code is free to reuse the compound page
 *    after a kfree/kmem_cache_free without having to check if
 *    there's any tail pin left.  In turn all tail pinsmust be always
 *    released while the head is still pinned by the slab code
 *    and so we know PG_slab will be still set too.
 *
 *    So if we see PageSlab set, and we have the tail page pin,
 *    then we could safely put head page.
 */
static __always_inline
void put_unrefcounted_compound_page(struct page *page_head, struct page *page)
{
	/*
	 * If @page is a THP tail, we must read the tail page
	 * flags after the head page flags. The
	 * __split_huge_page_refcount side enforces write memory barriers
	 * between clearing PageTail and before the head page
	 * can be freed and reallocated.
	 */
	smp_rmb();
	if (likely(PageTail(page))) {
		/*
		 * __split_huge_page_refcount cannot race
		 * here, see the comment above this function.
		 */
		VM_BUG_ON_PAGE(!PageHead(page_head), page_head);
		VM_BUG_ON_PAGE(page_mapcount(page) != 0, page);
		if (put_page_testzero(page_head)) {
			/*
			 * If this is the tail of a slab THP page,
			 * the tail pin must not be the last reference
			 * held on the page, because the PG_slab cannot
			 * be cleared before all tail pins (which skips
			 * the _mapcount tail refcounting) have been
			 * released.
			 *
			 * If this is the tail of a hugetlbfs page,
			 * the tail pin may be the last reference on
			 * the page instead, because PageHeadHuge will
			 * not go away until the compound page enters
			 * the buddy allocator.
			 */
			VM_BUG_ON_PAGE(PageSlab(page_head), page_head);
			__put_compound_page(page_head);
		}
	} else
		/*
		 * __split_huge_page_refcount run before us,
		 * @page was a THP tail. The split @page_head
		 * has been freed and reallocated as slab or
		 * hugetlbfs page of smaller order (only
		 * possible if reallocated as slab on x86).
		 */
		if (put_page_testzero(page))
			__put_single_page(page);
}

static __always_inline
void put_refcounted_compound_page(struct page *page_head, struct page *page)
{
	if (likely(page != page_head && get_page_unless_zero(page_head))) {
		unsigned long flags;

		/*
		 * @page_head wasn't a dangling pointer but it may not
		 * be a head page anymore by the time we obtain the
		 * lock. That is ok as long as it can't be freed from
		 * under us.
		 */
		flags = compound_lock_irqsave(page_head);
		if (unlikely(!PageTail(page))) {
			/* __split_huge_page_refcount run before us */
			compound_unlock_irqrestore(page_head, flags);
			if (put_page_testzero(page_head)) {
				/*
				 * The @page_head may have been freed
				 * and reallocated as a compound page
				 * of smaller order and then freed
				 * again.  All we know is that it
				 * cannot have become: a THP page, a
				 * compound page of higher order, a
				 * tail page.  That is because we
				 * still hold the refcount of the
				 * split THP tail and page_head was
				 * the THP head before the split.
				 */
				if (PageHead(page_head))
					__put_compound_page(page_head);
				else
					__put_single_page(page_head);
			}
out_put_single:
			if (put_page_testzero(page))
				__put_single_page(page);
			return;
		}
		VM_BUG_ON_PAGE(page_head != page->first_page, page);
		/*
		 * We can release the refcount taken by
		 * get_page_unless_zero() now that
		 * __split_huge_page_refcount() is blocked on the
		 * compound_lock.
		 */
		if (put_page_testzero(page_head))
			VM_BUG_ON_PAGE(1, page_head);
		/* __split_huge_page_refcount will wait now */
		VM_BUG_ON_PAGE(page_mapcount(page) <= 0, page);
		atomic_dec(&page->_mapcount);
		VM_BUG_ON_PAGE(atomic_read(&page_head->_count) <= 0, page_head);
		VM_BUG_ON_PAGE(atomic_read(&page->_count) != 0, page);
		compound_unlock_irqrestore(page_head, flags);

		if (put_page_testzero(page_head)) {
			if (PageHead(page_head))
				__put_compound_page(page_head);
			else
				__put_single_page(page_head);
		}
	} else {
		/* @page_head is a dangling pointer */
		VM_BUG_ON_PAGE(PageTail(page), page);
		goto out_put_single;
	}
}

static void put_compound_page(struct page *page)
{
	struct page *page_head;

	/*
	 * We see the PageCompound set and PageTail not set, so @page maybe:
	 *  1. hugetlbfs head page, or
	 *  2. THP head page.
	 */
	if (likely(!PageTail(page))) {
		if (put_page_testzero(page)) {
			/*
			 * By the time all refcounts have been released
			 * split_huge_page cannot run anymore from under us.
			 */
			if (PageHead(page))
				__put_compound_page(page);
			else
				__put_single_page(page);
		}
		return;
	}

	/*
	 * We see the PageCompound set and PageTail set, so @page maybe:
	 *  1. a tail hugetlbfs page, or
	 *  2. a tail THP page, or
	 *  3. a split THP page.
	 *
	 *  Case 3 is possible, as we may race with
	 *  __split_huge_page_refcount tearing down a THP page.
	 */
	page_head = compound_head_by_tail(page);
	if (!__compound_tail_refcounted(page_head))
		put_unrefcounted_compound_page(page_head, page);
	else
		put_refcounted_compound_page(page_head, page);
}

void put_page(struct page *page)
{
	/*
	 * For devmap managed pages we need to catch refcount transition from
	 * 2 to 1, when refcount reach one it means the page is free and we
	 * need to inform the device driver through callback. See
	 * include/linux/memremap.h and HMM for details.
	 */
	if (put_devmap_managed_page(page))
		return;

	if (unlikely(PageCompound(page)))
		put_compound_page(page);
	else if (put_page_testzero(page))
		__put_single_page(page);
}
EXPORT_SYMBOL(put_page);

/*
 * This function is exported but must not be called by anything other
 * than get_page(). It implements the slow path of get_page().
 */
bool __get_page_tail(struct page *page)
{
	/*
	 * This takes care of get_page() if run on a tail page
	 * returned by one of the get_user_pages/follow_page variants.
	 * get_user_pages/follow_page itself doesn't need the compound
	 * lock because it runs __get_page_tail_foll() under the
	 * proper PT lock that already serializes against
	 * split_huge_page().
	 */
	unsigned long flags;
	bool got;
	struct page *page_head = compound_head(page);

	/* Ref to put_compound_page() comment. */
	if (!__compound_tail_refcounted(page_head)) {
		smp_rmb();
		if (likely(PageTail(page))) {
			/*
			 * This is a hugetlbfs page or a slab
			 * page. __split_huge_page_refcount
			 * cannot race here.
			 */
			VM_BUG_ON_PAGE(!PageHead(page_head), page_head);
			__get_page_tail_foll(page, true);
			return true;
		} else {
			/*
			 * __split_huge_page_refcount run
			 * before us, "page" was a THP
			 * tail. The split page_head has been
			 * freed and reallocated as slab or
			 * hugetlbfs page of smaller order
			 * (only possible if reallocated as
			 * slab on x86).
			 */
			return false;
		}
	}

	got = false;
	if (likely(page != page_head && get_page_unless_zero(page_head))) {
		/*
		 * page_head wasn't a dangling pointer but it
		 * may not be a head page anymore by the time
		 * we obtain the lock. That is ok as long as it
		 * can't be freed from under us.
		 */
		flags = compound_lock_irqsave(page_head);
		/* here __split_huge_page_refcount won't run anymore */
		if (likely(PageTail(page))) {
			__get_page_tail_foll(page, false);
			got = true;
		}
		compound_unlock_irqrestore(page_head, flags);
		if (unlikely(!got))
			put_page(page_head);
	}
	return got;
}
EXPORT_SYMBOL(__get_page_tail);

/**
 * put_pages_list() - release a list of pages
 * @pages: list of pages threaded on page->lru
 *
 * Release a list of pages which are strung together on page.lru.  Currently
 * used by read_cache_pages() and related error recovery code.
 */
void put_pages_list(struct list_head *pages)
{
	while (!list_empty(pages)) {
		struct page *victim;

		victim = list_entry(pages->prev, struct page, lru);
		list_del(&victim->lru);
		page_cache_release(victim);
	}
}
EXPORT_SYMBOL(put_pages_list);

/*
 * get_kernel_pages() - pin kernel pages in memory
 * @kiov:	An array of struct kvec structures
 * @nr_segs:	number of segments to pin
 * @write:	pinning for read/write, currently ignored
 * @pages:	array that receives pointers to the pages pinned.
 *		Should be at least nr_segs long.
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno. Each page returned must be released
 * with a put_page() call when it is finished with.
 */
int get_kernel_pages(const struct kvec *kiov, int nr_segs, int write,
		struct page **pages)
{
	int seg;

	for (seg = 0; seg < nr_segs; seg++) {
		if (WARN_ON(kiov[seg].iov_len != PAGE_SIZE))
			return seg;

		pages[seg] = kmap_to_page(kiov[seg].iov_base);
		page_cache_get(pages[seg]);
	}

	return seg;
}
EXPORT_SYMBOL_GPL(get_kernel_pages);

/*
 * get_kernel_page() - pin a kernel page in memory
 * @start:	starting kernel address
 * @write:	pinning for read/write, currently ignored
 * @pages:	array that receives pointer to the page pinned.
 *		Must be at least nr_segs long.
 *
 * Returns 1 if page is pinned. If the page was not pinned, returns
 * -errno. The page returned must be released with a put_page() call
 * when it is finished with.
 */
int get_kernel_page(unsigned long start, int write, struct page **pages)
{
	const struct kvec kiov = {
		.iov_base = (void *)start,
		.iov_len = PAGE_SIZE
	};

	return get_kernel_pages(&kiov, 1, write, pages);
}
EXPORT_SYMBOL_GPL(get_kernel_page);

static void pagevec_lru_move_fn(struct pagevec *pvec,
	void (*move_fn)(struct page *page, struct lruvec *lruvec, void *arg),
	void *arg)
{
	int i;
	struct zone *zone = NULL;
	struct lruvec *lruvec;
	unsigned long flags = 0;

	for (i = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];
		struct zone *pagezone = page_zone(page);

		if (pagezone != zone) {
			if (zone)
				spin_unlock_irqrestore(&zone->lru_lock, flags);
			zone = pagezone;
			spin_lock_irqsave(&zone->lru_lock, flags);
		}

		lruvec = mem_cgroup_page_lruvec(page, zone);
		(*move_fn)(page, lruvec, arg);
	}
	if (zone)
		spin_unlock_irqrestore(&zone->lru_lock, flags);
	release_pages(pvec->pages, pvec->nr, pvec->cold);
	pagevec_reinit(pvec);
}

static void pagevec_move_tail_fn(struct page *page, struct lruvec *lruvec,
				 void *arg)
{
	int *pgmoved = arg;

	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
		enum lru_list lru = page_lru_base_type(page);
		list_move_tail(&page->lru, &lruvec->lists[lru]);
		(*pgmoved)++;
	}
}

/*
 * pagevec_move_tail() must be called with IRQ disabled.
 * Otherwise this may cause nasty races.
 */
static void pagevec_move_tail(struct pagevec *pvec)
{
	int pgmoved = 0;

	pagevec_lru_move_fn(pvec, pagevec_move_tail_fn, &pgmoved);
	__count_vm_events(PGROTATED, pgmoved);
}

/*
 * Writeback is about to end against a page which has been marked for immediate
 * reclaim.  If it still appears to be reclaimable, move it to the tail of the
 * inactive list.
 */
void rotate_reclaimable_page(struct page *page)
{
	if (!PageLocked(page) && !PageDirty(page) && !PageActive(page) &&
	    !PageUnevictable(page) && PageLRU(page)) {
		struct pagevec *pvec;
		unsigned long flags;

		page_cache_get(page);
		local_irq_save(flags);
		pvec = this_cpu_ptr(&lru_rotate_pvecs);
		if (!pagevec_add(pvec, page) || PageCompound(page))
			pagevec_move_tail(pvec);
		local_irq_restore(flags);
	}
}

static void update_page_reclaim_stat(struct lruvec *lruvec,
				     int file, int rotated)
{
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;

	reclaim_stat->recent_scanned[file]++;
	if (rotated)
		reclaim_stat->recent_rotated[file]++;
}

static void __activate_page(struct page *page, struct lruvec *lruvec,
			    void *arg)
{
	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
		int file = page_is_file_cache(page);
		int lru = page_lru_base_type(page);

		del_page_from_lru_list(page, lruvec, lru);
		SetPageActive(page);
		lru += LRU_ACTIVE;
		add_page_to_lru_list(page, lruvec, lru);
		trace_mm_lru_activate(page, page_to_pfn(page));

		__count_vm_event(PGACTIVATE);
		update_page_reclaim_stat(lruvec, file, 1);
	}
}

#ifdef CONFIG_SMP
static DEFINE_PER_CPU(struct pagevec, activate_page_pvecs);

static void activate_page_drain(int cpu)
{
	struct pagevec *pvec = &per_cpu(activate_page_pvecs, cpu);

	if (pagevec_count(pvec))
		pagevec_lru_move_fn(pvec, __activate_page, NULL);
}

static bool need_activate_page_drain(int cpu)
{
	return pagevec_count(&per_cpu(activate_page_pvecs, cpu)) != 0;
}

void activate_page(struct page *page)
{
	if (PageLRU(page) && !PageActive(page) && !PageUnevictable(page)) {
		struct pagevec *pvec = &get_cpu_var(activate_page_pvecs);

		page_cache_get(page);
		if (!pagevec_add(pvec, page) || PageCompound(page))
			pagevec_lru_move_fn(pvec, __activate_page, NULL);
		put_cpu_var(activate_page_pvecs);
	}
}

#else
static inline void activate_page_drain(int cpu)
{
}

static bool need_activate_page_drain(int cpu)
{
	return false;
}

void activate_page(struct page *page)
{
	struct zone *zone = page_zone(page);

	spin_lock_irq(&zone->lru_lock);
	__activate_page(page, mem_cgroup_page_lruvec(page, zone), NULL);
	spin_unlock_irq(&zone->lru_lock);
}
#endif

static void __lru_cache_activate_page(struct page *page)
{
	struct pagevec *pvec = &get_cpu_var(lru_add_pvec);
	int i;

	/*
	 * Search backwards on the optimistic assumption that the page being
	 * activated has just been added to this pagevec. Note that only
	 * the local pagevec is examined as a !PageLRU page could be in the
	 * process of being released, reclaimed, migrated or on a remote
	 * pagevec that is currently being drained. Furthermore, marking
	 * a remote pagevec's page PageActive potentially hits a race where
	 * a page is marked PageActive just after it is added to the inactive
	 * list causing accounting errors and BUG_ON checks to trigger.
	 */
	for (i = pagevec_count(pvec) - 1; i >= 0; i--) {
		struct page *pagevec_page = pvec->pages[i];

		if (pagevec_page == page) {
			SetPageActive(page);
			break;
		}
	}

	put_cpu_var(lru_add_pvec);
}

/*
 * Mark a page as having seen activity.
 *
 * inactive,unreferenced	->	inactive,referenced
 * inactive,referenced		->	active,unreferenced
 * active,unreferenced		->	active,referenced
 */
void mark_page_accessed(struct page *page)
{
	if (!PageActive(page) && !PageUnevictable(page) &&
			PageReferenced(page)) {

		/*
		 * If the page is on the LRU, queue it for activation via
		 * activate_page_pvecs. Otherwise, assume the page is on a
		 * pagevec, mark it active and it'll be moved to the active
		 * LRU on the next drain.
		 */
		if (PageLRU(page))
			activate_page(page);
		else
			__lru_cache_activate_page(page);
		ClearPageReferenced(page);
		if (page_is_file_cache(page))
			workingset_activation(page);
	} else if (!PageReferenced(page)) {
		SetPageReferenced(page);
	}
	if (page_is_idle(page))
		clear_page_idle(page);
}
EXPORT_SYMBOL(mark_page_accessed);

/*
 * Queue the page for addition to the LRU via pagevec. The decision on whether
 * to add the page to the [in]active [file|anon] list is deferred until the
 * pagevec is drained. This gives a chance for the caller of __lru_cache_add()
 * have the page added to the active list using mark_page_accessed().
 */
void __lru_cache_add(struct page *page)
{
	struct pagevec *pvec = &get_cpu_var(lru_add_pvec);

	page_cache_get(page);
	if (!pagevec_add(pvec, page) || PageCompound(page))
		__pagevec_lru_add(pvec);
	put_cpu_var(lru_add_pvec);
}
EXPORT_SYMBOL(__lru_cache_add);

/**
 * lru_cache_add - add a page to a page list
 * @page: the page to be added to the LRU.
 */
void lru_cache_add(struct page *page)
{
	VM_BUG_ON_PAGE(PageActive(page) && PageUnevictable(page), page);
	VM_BUG_ON_PAGE(PageLRU(page), page);
	__lru_cache_add(page);
}

/**
 * add_page_to_unevictable_list - add a page to the unevictable list
 * @page:  the page to be added to the unevictable list
 *
 * Add page directly to its zone's unevictable list.  To avoid races with
 * tasks that might be making the page evictable, through eg. munlock,
 * munmap or exit, while it's not on the lru, we want to add the page
 * while it's locked or otherwise "invisible" to other tasks.  This is
 * difficult to do when using the pagevec cache, so bypass that.
 */
void add_page_to_unevictable_list(struct page *page)
{
	struct zone *zone = page_zone(page);
	struct lruvec *lruvec;

	spin_lock_irq(&zone->lru_lock);
	lruvec = mem_cgroup_page_lruvec(page, zone);
	ClearPageActive(page);
	SetPageUnevictable(page);
	SetPageLRU(page);
	add_page_to_lru_list(page, lruvec, LRU_UNEVICTABLE);
	spin_unlock_irq(&zone->lru_lock);
}

/*
 * If the page can not be invalidated, it is moved to the
 * inactive list to speed up its reclaim.  It is moved to the
 * head of the list, rather than the tail, to give the flusher
 * threads some time to write it out, as this is much more
 * effective than the single-page writeout from reclaim.
 *
 * If the page isn't page_mapped and dirty/writeback, the page
 * could reclaim asap using PG_reclaim.
 *
 * 1. active, mapped page -> none
 * 2. active, dirty/writeback page -> inactive, head, PG_reclaim
 * 3. inactive, mapped page -> none
 * 4. inactive, dirty/writeback page -> inactive, head, PG_reclaim
 * 5. inactive, clean -> inactive, tail
 * 6. Others -> none
 *
 * In 4, why it moves inactive's head, the VM expects the page would
 * be write it out by flusher threads as this is much more effective
 * than the single-page writeout from reclaim.
 */
static void lru_deactivate_file_fn(struct page *page, struct lruvec *lruvec,
			      void *arg)
{
	int lru, file;
	bool active;

	if (!PageLRU(page))
		return;

	if (PageUnevictable(page))
		return;

	/* Some processes are using the page */
	if (page_mapped(page))
		return;

	active = PageActive(page);
	file = page_is_file_cache(page);
	lru = page_lru_base_type(page);

	del_page_from_lru_list(page, lruvec, lru + active);
	ClearPageActive(page);
	ClearPageReferenced(page);
	add_page_to_lru_list(page, lruvec, lru);

	if (PageWriteback(page) || PageDirty(page)) {
		/*
		 * PG_reclaim could be raced with end_page_writeback
		 * It can make readahead confusing.  But race window
		 * is _really_ small and  it's non-critical problem.
		 */
		SetPageReclaim(page);
	} else {
		/*
		 * The page's writeback ends up during pagevec
		 * We moves tha page into tail of inactive.
		 */
		list_move_tail(&page->lru, &lruvec->lists[lru]);
		__count_vm_event(PGROTATED);
	}

	if (active)
		__count_vm_event(PGDEACTIVATE);
	update_page_reclaim_stat(lruvec, file, 0);
}


static void lru_deactivate_fn(struct page *page, struct lruvec *lruvec,
			    void *arg)
{
	if (PageLRU(page) && PageActive(page) && !PageUnevictable(page)) {
		int file = page_is_file_cache(page);
		int lru = page_lru_base_type(page);

		del_page_from_lru_list(page, lruvec, lru + LRU_ACTIVE);
		ClearPageActive(page);
		ClearPageReferenced(page);
		add_page_to_lru_list(page, lruvec, lru);

		__count_vm_event(PGDEACTIVATE);
		update_page_reclaim_stat(lruvec, file, 0);
	}
}

/*
 * Drain pages out of the cpu's pagevecs.
 * Either "cpu" is the current CPU, and preemption has already been
 * disabled; or "cpu" is being hot-unplugged, and is already dead.
 */
void lru_add_drain_cpu(int cpu)
{
	struct pagevec *pvec = &per_cpu(lru_add_pvec, cpu);

	if (pagevec_count(pvec))
		__pagevec_lru_add(pvec);

	pvec = &per_cpu(lru_rotate_pvecs, cpu);
	if (pagevec_count(pvec)) {
		unsigned long flags;

		/* No harm done if a racing interrupt already did this */
		local_irq_save(flags);
		pagevec_move_tail(pvec);
		local_irq_restore(flags);
	}

	pvec = &per_cpu(lru_deactivate_file_pvecs, cpu);
	if (pagevec_count(pvec))
		pagevec_lru_move_fn(pvec, lru_deactivate_file_fn, NULL);

	pvec = &per_cpu(lru_deactivate_pvecs, cpu);
	if (pagevec_count(pvec))
		pagevec_lru_move_fn(pvec, lru_deactivate_fn, NULL);

	activate_page_drain(cpu);
}

/**
 * deactivate_file_page - forcefully deactivate a file page
 * @page: page to deactivate
 *
 * This function hints the VM that @page is a good reclaim candidate,
 * for example if its invalidation fails due to the page being dirty
 * or under writeback.
 */
void deactivate_file_page(struct page *page)
{
	/*
	 * In a workload with many unevictable page such as mprotect,
	 * unevictable page deactivation for accelerating reclaim is pointless.
	 */
	if (PageUnevictable(page))
		return;

	if (likely(get_page_unless_zero(page))) {
		struct pagevec *pvec = &get_cpu_var(lru_deactivate_file_pvecs);

		if (!pagevec_add(pvec, page) || PageCompound(page))
			pagevec_lru_move_fn(pvec, lru_deactivate_file_fn, NULL);
		put_cpu_var(lru_deactivate_file_pvecs);
	}
}

/**
 * deactivate_page - deactivate a page
 * @page: page to deactivate
 *
 * deactivate_page() moves @page to the inactive list if @page was on the active
 * list and was not an unevictable page.  This is done to accelerate the reclaim
 * of @page.
 */
void deactivate_page(struct page *page)
{
	if (PageLRU(page) && PageActive(page) && !PageUnevictable(page)) {
		struct pagevec *pvec = &get_cpu_var(lru_deactivate_pvecs);

		page_cache_get(page);
		if (!pagevec_add(pvec, page) || PageCompound(page))
			pagevec_lru_move_fn(pvec, lru_deactivate_fn, NULL);
		put_cpu_var(lru_deactivate_pvecs);
	}
}

void lru_add_drain(void)
{
	lru_add_drain_cpu(get_cpu());
	put_cpu();
}

static void lru_add_drain_per_cpu(struct work_struct *dummy)
{
	lru_add_drain();
}

static DEFINE_PER_CPU(struct work_struct, lru_add_drain_work);

/*
 * lru_add_drain_wq is used to do lru_add_drain_all() from a WQ_MEM_RECLAIM
 * workqueue, aiding in getting memory freed.
 */
static struct workqueue_struct *lru_add_drain_wq;

static int __init lru_init(void)
{
	lru_add_drain_wq = alloc_workqueue("lru-add-drain", WQ_MEM_RECLAIM, 0);

	if (WARN(!lru_add_drain_wq,
		"Failed to create workqueue lru_add_drain_wq"))
		return -ENOMEM;

	return 0;
}
early_initcall(lru_init);

void lru_add_drain_all(void)
{
	static DEFINE_MUTEX(lock);
	static struct cpumask has_work;
	int cpu;

	mutex_lock(&lock);
	get_online_cpus();
	cpumask_clear(&has_work);

	for_each_online_cpu(cpu) {
		struct work_struct *work = &per_cpu(lru_add_drain_work, cpu);

		if (pagevec_count(&per_cpu(lru_add_pvec, cpu)) ||
		    pagevec_count(&per_cpu(lru_rotate_pvecs, cpu)) ||
		    pagevec_count(&per_cpu(lru_deactivate_file_pvecs, cpu)) ||
		    pagevec_count(&per_cpu(lru_deactivate_pvecs, cpu)) ||
		    need_activate_page_drain(cpu)) {
			INIT_WORK(work, lru_add_drain_per_cpu);
			queue_work_on(cpu, lru_add_drain_wq, work);
			cpumask_set_cpu(cpu, &has_work);
		}
	}

	for_each_cpu(cpu, &has_work)
		flush_work(&per_cpu(lru_add_drain_work, cpu));

	put_online_cpus();
	mutex_unlock(&lock);
}

static inline struct zone *zone_lru_lock(struct zone *zone,
					 struct page *page,
					 unsigned int *lock_batch,
					 unsigned long *_flags)
{
	struct zone *pagezone = page_zone(page);

	if (pagezone != zone) {
		unsigned long flags = *_flags;

		if (zone)
			spin_unlock_irqrestore(&zone->lru_lock, flags);
		*lock_batch = 0;
		zone = pagezone;
		spin_lock_irqsave(&zone->lru_lock, flags);

		*_flags = flags;
	}

	return zone;
}

static inline struct zone *zone_lru_unlock(struct zone *zone,
					   unsigned long flags)
{
	if (zone) {
		spin_unlock_irqrestore(&zone->lru_lock, flags);
		zone = NULL;
	}
	return zone;
}

/*
 * Batched page_cache_release().  Decrement the reference count on all the
 * passed pages.  If it fell to zero then remove the page from the LRU and
 * free it.
 *
 * Avoid taking zone->lru_lock if possible, but if it is taken, retain it
 * for the remainder of the operation.
 *
 * The locking in this function is against shrink_inactive_list(): we recheck
 * the page count inside the lock to see whether shrink_inactive_list()
 * grabbed the page via the LRU.  If it did, give up: shrink_inactive_list()
 * will free it.
 */
void release_pages(struct page **pages, int nr, bool cold)
{
	int i;
	LIST_HEAD(pages_to_free);
	LIST_HEAD(trans_huge_pages_to_free);
	struct zone *zone = NULL;
	struct lruvec *lruvec;
	unsigned long uninitialized_var(flags);
	unsigned int uninitialized_var(lock_batch);

	for (i = 0; i < nr; i++) {
		struct page *page = pages[i];
		const bool was_thp = is_trans_huge_page_release(page);
		bool check_mmu_gather = false;

		if (unlikely(!was_thp && PageCompound(page))) {
			zone = zone_lru_unlock(zone, flags);
			put_compound_page(page);
			continue;
		}

		/*
		 * Make sure the IRQ-safe lock-holding time does not get
		 * excessive with a continuous string of pages from the
		 * same zone. The lock is held only if zone != NULL.
		 */
		if (zone && ++lock_batch == SWAP_CLUSTER_MAX) {
			spin_unlock_irqrestore(&zone->lru_lock, flags);
			zone = NULL;
		}

		if (was_thp) {
			if (is_huge_zero_page_release(page)) {
				put_huge_zero_page();
				continue;
			}
			page = trans_huge_page_release_decode(page);
			zone = zone_lru_lock(zone, page, &lock_batch, &flags);
			/*
			 * Here, after taking the lru_lock,
			 * __split_huge_page_refcount() can't run
			 * anymore from under us and in turn
			 * PageTransHuge() retval is stable and can't
			 * change anymore.
			 *
			 * PageTransHuge() has an helpful
			 * VM_BUG_ON_PAGE() internally to enforce that
			 * the page cannot be a tail here.
			 */
			if (unlikely(!PageTransHuge(page))) {
				int idx;

				/*
				 * The THP page was splitted before we
				 * could free it, in turn its tails
				 * kept an elevated count because the
				 * mmu_gather_count was transferred to
				 * the tail page count during the
				 * split.
				 *
				 * This is a very unlikely slow path,
				 * performance is irrelevant here,
				 * just keep it to the simplest.
				 */
				zone = zone_lru_unlock(zone, flags);

				for (idx = 0; idx < HPAGE_PMD_NR;
				     idx++, page++) {
					VM_BUG_ON(PageTransCompound(page));
					put_page(page);
				}
				continue;
			} else {
				/*
				 * __split_huge_page_refcount() cannot
				 * run from under us, so we can
				 * release the refence we had on the
				 * mmu_gather_count as we don't care
				 * anymore if the page gets splitted
				 * or not. By now the TLB flush
				 * already happened for this mapping,
				 * so we don't need to prevent the
				 * tails to be freed anymore.
				 */
				dec_trans_huge_mmu_gather_count(page);
				check_mmu_gather = true;
			}
		}

		if (!put_page_testzero(page))
			continue;

		VM_BUG_ON_PAGE(check_mmu_gather &&
			       trans_huge_mmu_gather_count(page), page);

		if (PageLRU(page)) {
			if (!was_thp)
				zone = zone_lru_lock(zone, page, &lock_batch,
						     &flags);

			lruvec = mem_cgroup_page_lruvec(page, zone);
			VM_BUG_ON_PAGE(!PageLRU(page), page);
			__ClearPageLRU(page);
			del_page_from_lru_list(page, lruvec, page_off_lru(page));
		}

		if (!was_thp) {
			/*
			 * Clear Active bit in case of parallel
			 * mark_page_accessed.
			 */
			__ClearPageActive(page);

			list_add(&page->lru, &pages_to_free);
		} else
			list_add(&page->lru, &trans_huge_pages_to_free);
	}
	if (zone)
		spin_unlock_irqrestore(&zone->lru_lock, flags);

	if (!list_empty(&pages_to_free))
		free_hot_cold_page_list(&pages_to_free, cold);
#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	if (!list_empty(&trans_huge_pages_to_free))
		free_trans_huge_page_list(&trans_huge_pages_to_free);
#endif
}
EXPORT_SYMBOL(release_pages);

/*
 * The pages which we're about to release may be in the deferred lru-addition
 * queues.  That would prevent them from really being freed right now.  That's
 * OK from a correctness point of view but is inefficient - those pages may be
 * cache-warm and we want to give them back to the page allocator ASAP.
 *
 * So __pagevec_release() will drain those queues here.  __pagevec_lru_add()
 * and __pagevec_lru_add_active() call release_pages() directly to avoid
 * mutual recursion.
 */
void __pagevec_release(struct pagevec *pvec)
{
	lru_add_drain();
	release_pages(pvec->pages, pagevec_count(pvec), pvec->cold);
	pagevec_reinit(pvec);
}
EXPORT_SYMBOL(__pagevec_release);

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
/* used by __split_huge_page_refcount() */
void lru_add_page_tail(struct page *page, struct page *page_tail,
		       struct lruvec *lruvec, struct list_head *list)
{
	const int file = 0;

	VM_BUG_ON_PAGE(!PageHead(page), page);
	VM_BUG_ON_PAGE(PageCompound(page_tail), page);
	VM_BUG_ON_PAGE(PageLRU(page_tail), page);
	VM_BUG_ON(NR_CPUS != 1 &&
		  !spin_is_locked(&lruvec_zone(lruvec)->lru_lock));

	if (!list)
		SetPageLRU(page_tail);

	if (likely(PageLRU(page)))
		list_add_tail(&page_tail->lru, &page->lru);
	else if (list) {
		/* page reclaim is reclaiming a huge page */
		get_page(page_tail);
		list_add_tail(&page_tail->lru, list);
	} else {
		struct list_head *list_head;
		/*
		 * Head page has not yet been counted, as an hpage,
		 * so we must account for each subpage individually.
		 *
		 * Use the standard add function to put page_tail on the list,
		 * but then correct its position so they all end up in order.
		 */
		add_page_to_lru_list(page_tail, lruvec, page_lru(page_tail));
		list_head = page_tail->lru.prev;
		list_move_tail(&page_tail->lru, list_head);
	}

	if (!PageUnevictable(page))
		update_page_reclaim_stat(lruvec, file, PageActive(page_tail));
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

static void __pagevec_lru_add_fn(struct page *page, struct lruvec *lruvec,
				 void *arg)
{
	int file = page_is_file_cache(page);
	int active = PageActive(page);
	enum lru_list lru = page_lru(page);

	VM_BUG_ON_PAGE(PageLRU(page), page);

	SetPageLRU(page);
	add_page_to_lru_list(page, lruvec, lru);
	update_page_reclaim_stat(lruvec, file, active);
	trace_mm_lru_insertion(page, page_to_pfn(page), lru, trace_pagemap_flags(page));
}

/*
 * Add the passed pages to the LRU, then drop the caller's refcount
 * on them.  Reinitialises the caller's pagevec.
 */
void __pagevec_lru_add(struct pagevec *pvec)
{
	pagevec_lru_move_fn(pvec, __pagevec_lru_add_fn, NULL);
}
EXPORT_SYMBOL(__pagevec_lru_add);

/**
 * __pagevec_lookup - gang pagecache lookup
 * @pvec:	Where the resulting entries are placed
 * @mapping:	The address_space to search
 * @start:	The starting entry index
 * @nr_pages:	The maximum number of entries
 * @indices:	The cache indices corresponding to the entries in @pvec
 *
 * __pagevec_lookup() will search for and return a group of up to
 * @nr_pages pages and shadow entries in the mapping.  All entries are
 * placed in @pvec.  __pagevec_lookup() takes a reference against
 * actual pages in @pvec.
 *
 * The search returns a group of mapping-contiguous entries with
 * ascending indexes.  There may be holes in the indices due to
 * not-present entries.
 *
 * __pagevec_lookup() returns the number of entries which were found.
 */
unsigned __pagevec_lookup(struct pagevec *pvec, struct address_space *mapping,
			  pgoff_t start, unsigned nr_pages, pgoff_t *indices)
{
	pvec->nr = __find_get_pages(mapping, start, nr_pages,
				    pvec->pages, indices);
	return pagevec_count(pvec);
}

/**
 * pagevec_remove_exceptionals - pagevec exceptionals pruning
 * @pvec:	The pagevec to prune
 *
 * __pagevec_lookup() fills both pages and exceptional radix tree
 * entries into the pagevec.  This function prunes all exceptionals
 * from @pvec without leaving holes, so that it can be passed on to
 * page-only pagevec operations.
 */
void pagevec_remove_exceptionals(struct pagevec *pvec)
{
	int i, j;

	for (i = 0, j = 0; i < pagevec_count(pvec); i++) {
		struct page *page = pvec->pages[i];
		if (!radix_tree_exceptional_entry(page))
			pvec->pages[j++] = page;
	}
	pvec->nr = j;
}

/**
 * pagevec_lookup - gang pagecache lookup
 * @pvec:	Where the resulting pages are placed
 * @mapping:	The address_space to search
 * @start:	The starting page index
 * @nr_pages:	The maximum number of pages
 *
 * pagevec_lookup() will search for and return a group of up to @nr_pages pages
 * in the mapping.  The pages are placed in @pvec.  pagevec_lookup() takes a
 * reference against the pages in @pvec.
 *
 * The search returns a group of mapping-contiguous pages with ascending
 * indexes.  There may be holes in the indices due to not-present pages.
 *
 * pagevec_lookup() returns the number of pages which were found.
 */
unsigned pagevec_lookup(struct pagevec *pvec, struct address_space *mapping,
		pgoff_t start, unsigned nr_pages)
{
	pvec->nr = find_get_pages(mapping, start, nr_pages, pvec->pages);
	return pagevec_count(pvec);
}
EXPORT_SYMBOL(pagevec_lookup);

unsigned pagevec_lookup_tag(struct pagevec *pvec, struct address_space *mapping,
		pgoff_t *index, int tag, unsigned nr_pages)
{
	pvec->nr = find_get_pages_tag(mapping, index, tag,
					nr_pages, pvec->pages);
	return pagevec_count(pvec);
}
EXPORT_SYMBOL(pagevec_lookup_tag);

/*
 * Perform any setup for the swap system
 */
void __init swap_setup(void)
{
	unsigned long megs = totalram_pages >> (20 - PAGE_SHIFT);
#ifdef CONFIG_SWAP
	bdi_init(&swap_backing_dev_info);
#endif
	/* Use a smaller cluster for small-memory machines */
	if (megs < 16)
		page_cluster = 2;
	else
		page_cluster = 3;
	/*
	 * Right now other parts of the system means that we
	 * _really_ don't want to cluster much more
	 */
}
