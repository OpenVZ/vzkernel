/*
 *	linux/mm/filemap.c
 *
 * Copyright (C) 1994-1999  Linus Torvalds
 */

/*
 * This file handles the generic file mmap semantics used by
 * most "normal" filesystems (but you don't /have/ to use this:
 * the NFS filesystem used to do this differently, for example)
 */
#include <linux/export.h>
#include <linux/compiler.h>
#include <linux/dax.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/aio.h>
#include <linux/capability.h>
#include <linux/kernel_stat.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/hash.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/blkdev.h>
#include <linux/security.h>
#include <linux/cpuset.h>
#include <linux/hardirq.h> /* for BUG_ON(!in_atomic()) only */
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/cleancache.h>
#include "internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/filemap.h>

/*
 * FIXME: remove all knowledge of the buffer layer from the core VM
 */
#include <linux/buffer_head.h> /* for try_to_free_buffers */

#include <asm/mman.h>

#include <linux/virtinfo.h>
#include <bc/io_acct.h>

/*
 * Shared mappings implemented 30.11.1994. It's not fully working yet,
 * though.
 *
 * Shared mappings now work. 15.8.1995  Bruno.
 *
 * finished 'unifying' the page and buffer cache and SMP-threaded the
 * page-cache, 21.05.1999, Ingo Molnar <mingo@redhat.com>
 *
 * SMP-threaded pagemap-LRU 1999, Andrea Arcangeli <andrea@suse.de>
 */

/*
 * Lock ordering:
 *
 *  ->i_mmap_mutex		(truncate_pagecache)
 *    ->private_lock		(__free_pte->__set_page_dirty_buffers)
 *      ->swap_lock		(exclusive_swap_page, others)
 *        ->mapping->tree_lock
 *
 *  ->i_mutex
 *    ->i_mmap_mutex		(truncate->unmap_mapping_range)
 *
 *  ->mmap_sem
 *    ->i_mmap_mutex
 *      ->page_table_lock or pte_lock	(various, mainly in memory.c)
 *        ->mapping->tree_lock	(arch-dependent flush_dcache_mmap_lock)
 *
 *  ->mmap_sem
 *    ->lock_page		(access_process_vm)
 *
 *  ->i_mutex			(generic_file_buffered_write)
 *    ->mmap_sem		(fault_in_pages_readable->do_page_fault)
 *
 *  bdi->wb.list_lock
 *    sb_lock			(fs/fs-writeback.c)
 *    ->mapping->tree_lock	(__sync_single_inode)
 *
 *  ->i_mmap_mutex
 *    ->anon_vma.lock		(vma_adjust)
 *
 *  ->anon_vma.lock
 *    ->page_table_lock or pte_lock	(anon_vma_prepare and various)
 *
 *  ->page_table_lock or pte_lock
 *    ->swap_lock		(try_to_unmap_one)
 *    ->private_lock		(try_to_unmap_one)
 *    ->tree_lock		(try_to_unmap_one)
 *    ->zone.lru_lock		(follow_page->mark_page_accessed)
 *    ->zone.lru_lock		(check_pte_range->isolate_lru_page)
 *    ->private_lock		(page_remove_rmap->set_page_dirty)
 *    ->tree_lock		(page_remove_rmap->set_page_dirty)
 *    bdi.wb->list_lock		(page_remove_rmap->set_page_dirty)
 *    ->inode->i_lock		(page_remove_rmap->set_page_dirty)
 *    bdi.wb->list_lock		(zap_pte_range->set_page_dirty)
 *    ->inode->i_lock		(zap_pte_range->set_page_dirty)
 *    ->private_lock		(zap_pte_range->__set_page_dirty_buffers)
 *
 * ->i_mmap_mutex
 *   ->tasklist_lock            (memory_failure, collect_procs_ao)
 */

static int page_cache_tree_insert(struct address_space *mapping,
				  struct page *page, void **shadowp)
{
	struct radix_tree_node *node;
	void **slot;
	int error;

	error = __radix_tree_create(&mapping->page_tree, page->index, 0,
				    &node, &slot);
	if (error)
		return error;
	if (*slot) {
		void *p;

		p = radix_tree_deref_slot_protected(slot, &mapping->tree_lock);
		if (!radix_tree_exceptional_entry(p))
			return -EEXIST;

		mapping->nrexceptional--;
		if (shadowp)
			*shadowp = p;
		if (node)
			workingset_node_shadows_dec(node);
	}
	radix_tree_replace_slot(slot, page);
	mapping->nrpages++;
	if (node) {
		workingset_node_pages_inc(node);
		/*
		 * Don't track node that contains actual pages.
		 *
		 * Avoid acquiring the list_lru lock if already
		 * untracked.  The list_empty() test is safe as
		 * node->private_list is protected by
		 * mapping->tree_lock.
		 */
		if (!list_empty(&node->private_list))
			list_lru_del(&workingset_shadow_nodes,
				     &node->private_list);
	}
	return 0;
}

static void page_cache_tree_delete(struct address_space *mapping,
				   struct page *page, void *shadow)
{
	struct radix_tree_node *node;
	void **slot;

	VM_BUG_ON(!PageLocked(page));

	__radix_tree_lookup(&mapping->page_tree, page->index, &node, &slot);
	radix_tree_clear_tags(&mapping->page_tree, node, slot);

	if (!node) {
		/*
		 * We need a node to properly account shadow
		 * entries. Don't plant any without. XXX
		 */
		shadow = NULL;
	}

	radix_tree_replace_slot(slot, shadow);

	if (shadow) {
		mapping->nrexceptional++;
		/*
		 * Make sure the nrexceptional update is committed before
		 * the nrpages update so that final truncate racing
		 * with reclaim does not see both counters 0 at the
		 * same time and miss a shadow entry.
		 */
		smp_wmb();
	}
	mapping->nrpages--;

	if (!node)
		return;

	workingset_node_pages_dec(node);
	if (shadow)
		workingset_node_shadows_inc(node);
	else
		if (__radix_tree_delete_node(&mapping->page_tree, node))
			return;

	/*
	 * Track node that only contains shadow entries. DAX mappings contain
	 * no shadow entries and may contain other exceptional entries so skip
	 * those.
	 *
	 * Avoid acquiring the list_lru lock if already tracked.  The
	 * list_empty() test is safe as node->private_list is
	 * protected by mapping->tree_lock.
	 */
	if (!dax_mapping(mapping) && !workingset_node_pages(node) &&
	    list_empty(&node->private_list)) {
		node->private_data = mapping;
		list_lru_add(&workingset_shadow_nodes, &node->private_list);
	}
}

/*
 * Delete a page from the page cache and free it. Caller has to make
 * sure the page is locked and that nobody else uses it - or that usage
 * is safe.  The caller must hold the mapping's tree_lock.
 */
void __delete_from_page_cache(struct page *page, void *shadow)
{
	struct address_space *mapping = page->mapping;

	trace_mm_filemap_delete_from_page_cache(page);
	/*
	 * if we're uptodate, flush out into the cleancache, otherwise
	 * invalidate any existing cleancache entries.  We can't leave
	 * stale data around in the cleancache once our page is gone
	 */
	if (PageUptodate(page) && PageMappedToDisk(page))
		cleancache_put_page(page);
	else
		cleancache_invalidate_page(mapping, page);

	page_cache_tree_delete(mapping, page, shadow);
	if (mapping_cap_account_dirty(mapping) &&
			radix_tree_prev_tag_get(&mapping->page_tree,
				PAGECACHE_TAG_DIRTY))
		ub_io_account_cancel(mapping);

	if (mapping_cap_account_writeback(mapping) &&
			radix_tree_prev_tag_get(&mapping->page_tree,
				PAGECACHE_TAG_WRITEBACK))
		ub_io_writeback_dec(mapping);

	page->mapping = NULL;
	/* Leave page->index set: truncation lookup relies upon it */

	__dec_zone_page_state(page, NR_FILE_PAGES);
	if (PageSwapBacked(page))
		__dec_zone_page_state(page, NR_SHMEM);
	BUG_ON(page_mapped(page));

	/*
	 * Some filesystems seem to re-dirty the page even after
	 * the VM has canceled the dirty bit (eg ext3 journaling).
	 *
	 * Fix it up by doing a final dirty accounting check after
	 * having removed the page entirely.
	 */
	if (PageDirty(page) && mapping_cap_account_dirty(mapping)) {
		dec_zone_page_state(page, NR_FILE_DIRTY);
		dec_bdi_stat(mapping->backing_dev_info, BDI_RECLAIMABLE);
	}
}

/**
 * delete_from_page_cache - delete page from page cache
 * @page: the page which the kernel is trying to remove from page cache
 *
 * This must be called only on pages that have been verified to be in the page
 * cache and locked.  It will never put the page into the free list, the caller
 * has a reference on the page.
 */
void delete_from_page_cache(struct page *page)
{
	struct address_space *mapping = page->mapping;
	void (*freepage)(struct page *);

	BUG_ON(!PageLocked(page));

	freepage = mapping->a_ops->freepage;
	spin_lock_irq(&mapping->tree_lock);
	__delete_from_page_cache(page, NULL);
	spin_unlock_irq(&mapping->tree_lock);

	if (freepage)
		freepage(page);
	page_cache_release(page);
}
EXPORT_SYMBOL(delete_from_page_cache);

int filemap_check_errors(struct address_space *mapping)
{
	int ret = 0;
	/* Check for outstanding write errors */
	if (test_and_clear_bit(AS_ENOSPC, &mapping->flags))
		ret = -ENOSPC;
	if (test_and_clear_bit(AS_EIO, &mapping->flags))
		ret = -EIO;
	return ret;
}
EXPORT_SYMBOL(filemap_check_errors);

static int filemap_check_and_keep_errors(struct address_space *mapping)
{
	/* Check for outstanding write errors */
	if (test_bit(AS_EIO, &mapping->flags))
		return -EIO;
	if (test_bit(AS_ENOSPC, &mapping->flags))
		return -ENOSPC;
	return 0;
}

/**
 * __filemap_fdatawrite_range - start writeback on mapping dirty pages in range
 * @mapping:	address space structure to write
 * @start:	offset in bytes where the range starts
 * @end:	offset in bytes where the range ends (inclusive)
 * @sync_mode:	enable synchronous operation
 *
 * Start writeback against all of a mapping's dirty pages that lie
 * within the byte offsets <start, end> inclusive.
 *
 * If sync_mode is WB_SYNC_ALL then this is a "data integrity" operation, as
 * opposed to a regular memory cleansing writeback.  The difference between
 * these two operations is that if a dirty page/buffer is encountered, it must
 * be waited upon, and not just skipped over.
 */
int __filemap_fdatawrite_range(struct address_space *mapping, loff_t start,
				loff_t end, int sync_mode)
{
	int ret;
	struct writeback_control wbc = {
		.sync_mode = sync_mode,
		.nr_to_write = LONG_MAX,
		.range_start = start,
		.range_end = end,
	};

	if (!mapping_cap_writeback_dirty(mapping))
		return 0;

	ret = do_writepages(mapping, &wbc);
	return ret;
}

static inline int __filemap_fdatawrite(struct address_space *mapping,
	int sync_mode)
{
	return __filemap_fdatawrite_range(mapping, 0, LLONG_MAX, sync_mode);
}

int filemap_fdatawrite(struct address_space *mapping)
{
	return __filemap_fdatawrite(mapping, WB_SYNC_ALL);
}
EXPORT_SYMBOL(filemap_fdatawrite);

int filemap_fdatawrite_range(struct address_space *mapping, loff_t start,
				loff_t end)
{
	return __filemap_fdatawrite_range(mapping, start, end, WB_SYNC_ALL);
}
EXPORT_SYMBOL(filemap_fdatawrite_range);

/**
 * filemap_flush - mostly a non-blocking flush
 * @mapping:	target address_space
 *
 * This is a mostly non-blocking flush.  Not suitable for data-integrity
 * purposes - I/O may not be started against all dirty pages.
 */
int filemap_flush(struct address_space *mapping)
{
	return __filemap_fdatawrite(mapping, WB_SYNC_NONE);
}
EXPORT_SYMBOL(filemap_flush);

static void __filemap_fdatawait_range(struct address_space *mapping,
				     loff_t start_byte, loff_t end_byte)
{
	pgoff_t index = start_byte >> PAGE_CACHE_SHIFT;
	pgoff_t end = end_byte >> PAGE_CACHE_SHIFT;
	struct pagevec pvec;
	int nr_pages;

	if (end_byte < start_byte)
		return;

	pagevec_init(&pvec, 0);
	while ((index <= end) &&
			(nr_pages = pagevec_lookup_tag(&pvec, mapping, &index,
			PAGECACHE_TAG_WRITEBACK,
			min(end - index, (pgoff_t)PAGEVEC_SIZE-1) + 1)) != 0) {
		unsigned i;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];

			/* until radix tree lookup accepts end_index */
			if (page->index > end)
				continue;

			wait_on_page_writeback(page);
			ClearPageError(page);
		}
		pagevec_release(&pvec);
		cond_resched();
	}
}

/**
 * filemap_fdatawait_range - wait for writeback to complete
 * @mapping:		address space structure to wait for
 * @start_byte:		offset in bytes where the range starts
 * @end_byte:		offset in bytes where the range ends (inclusive)
 *
 * Walk the list of under-writeback pages of the given address space
 * in the given range and wait for all of them.  Check error status of
 * the address space and return it.
 *
 * Since the error status of the address space is cleared by this function,
 * callers are responsible for checking the return value and handling and/or
 * reporting the error.
 */
int filemap_fdatawait_range(struct address_space *mapping, loff_t start_byte,
			    loff_t end_byte)
{
	__filemap_fdatawait_range(mapping, start_byte, end_byte);
	return filemap_check_errors(mapping);
}
EXPORT_SYMBOL(filemap_fdatawait_range);

/**
 * filemap_fdatawait_keep_errors - wait for writeback without clearing errors
 * @mapping: address space structure to wait for
 *
 * Walk the list of under-writeback pages of the given address space
 * and wait for all of them.  Unlike filemap_fdatawait(), this function
 * does not clear error status of the address space.
 *
 * Use this function if callers don't handle errors themselves.  Expected
 * call sites are system-wide / filesystem-wide data flushers: e.g. sync(2),
 * fsfreeze(8)
 */
int filemap_fdatawait_keep_errors(struct address_space *mapping)
{
	loff_t i_size = i_size_read(mapping->host);

	if (i_size == 0)
		return 0;

	__filemap_fdatawait_range(mapping, 0, i_size - 1);
	return filemap_check_and_keep_errors(mapping);
}
EXPORT_SYMBOL(filemap_fdatawait_keep_errors);

/**
 * filemap_fdatawait - wait for all under-writeback pages to complete
 * @mapping: address space structure to wait for
 *
 * Walk the list of under-writeback pages of the given address space
 * and wait for all of them.  Check error status of the address space
 * and return it.
 *
 * Since the error status of the address space is cleared by this function,
 * callers are responsible for checking the return value and handling and/or
 * reporting the error.
 */
int filemap_fdatawait(struct address_space *mapping)
{
	loff_t i_size = i_size_read(mapping->host);

	if (i_size == 0)
		return 0;

	return filemap_fdatawait_range(mapping, 0, i_size - 1);
}
EXPORT_SYMBOL(filemap_fdatawait);

int filemap_write_and_wait(struct address_space *mapping)
{
	int err = 0;

	if ((!dax_mapping(mapping) && mapping->nrpages) ||
	    (dax_mapping(mapping) && mapping->nrexceptional)) {
		err = filemap_fdatawrite(mapping);
		/*
		 * Even if the above returned error, the pages may be
		 * written partially (e.g. -ENOSPC), so we wait for it.
		 * But the -EIO is special case, it may indicate the worst
		 * thing (e.g. bug) happened, so we avoid waiting for it.
		 */
		if (err != -EIO) {
			int err2 = filemap_fdatawait(mapping);
			if (!err)
				err = err2;
		} else {
			/* Clear any previously stored errors */
			filemap_check_errors(mapping);
		}
	} else {
		err = filemap_check_errors(mapping);
	}
	return err;
}
EXPORT_SYMBOL(filemap_write_and_wait);

/**
 * filemap_write_and_wait_range - write out & wait on a file range
 * @mapping:	the address_space for the pages
 * @lstart:	offset in bytes where the range starts
 * @lend:	offset in bytes where the range ends (inclusive)
 *
 * Write out and wait upon file offsets lstart->lend, inclusive.
 *
 * Note that `lend' is inclusive (describes the last byte to be written) so
 * that this function can be used to write to the very end-of-file (end = -1).
 */
int filemap_write_and_wait_range(struct address_space *mapping,
				 loff_t lstart, loff_t lend)
{
	int err = 0;

	if ((!dax_mapping(mapping) && mapping->nrpages) ||
	    (dax_mapping(mapping) && mapping->nrexceptional)) {
		err = __filemap_fdatawrite_range(mapping, lstart, lend,
						 WB_SYNC_ALL);
		/* See comment of filemap_write_and_wait() */
		if (err != -EIO) {
			int err2 = filemap_fdatawait_range(mapping,
						lstart, lend);
			if (!err)
				err = err2;
		} else {
			/* Clear any previously stored errors */
			filemap_check_errors(mapping);
		}
	} else {
		err = filemap_check_errors(mapping);
	}
	return err;
}
EXPORT_SYMBOL(filemap_write_and_wait_range);

void __filemap_set_wb_err(struct address_space *mapping, int err)
{
	errseq_t eseq = __errseq_set(&mapping->wb_err, err);

	trace_filemap_set_wb_err(mapping, eseq);
}
EXPORT_SYMBOL(__filemap_set_wb_err);

/**
 * file_check_and_advance_wb_err - report wb error (if any) that was previously
 * 				   and advance wb_err to current one
 * @file: struct file on which the error is being reported
 *
 * When userland calls fsync (or something like nfsd does the equivalent), we
 * want to report any writeback errors that occurred since the last fsync (or
 * since the file was opened if there haven't been any).
 *
 * Grab the wb_err from the mapping. If it matches what we have in the file,
 * then just quickly return 0. The file is all caught up.
 *
 * If it doesn't match, then take the mapping value, set the "seen" flag in
 * it and try to swap it into place. If it works, or another task beat us
 * to it with the new value, then update the f_wb_err and return the error
 * portion. The error at this point must be reported via proper channels
 * (a'la fsync, or NFS COMMIT operation, etc.).
 *
 * While we handle mapping->wb_err with atomic operations, the f_wb_err
 * value is protected by the f_lock since we must ensure that it reflects
 * the latest value swapped in for this file descriptor.
 */
int file_check_and_advance_wb_err(struct file *file)
{
	int err = 0;
	errseq_t old = READ_ONCE(file->f_wb_err);
	struct address_space *mapping = file->f_mapping;

	/* Locklessly handle the common case where nothing has changed */
	if (errseq_check(&mapping->wb_err, old)) {
		/* Something changed, must use slow path */
		spin_lock(&file->f_lock);
		old = file->f_wb_err;
		err = errseq_check_and_advance(&mapping->wb_err,
						&file->f_wb_err);
		trace_file_check_and_advance_wb_err(file, old);
		spin_unlock(&file->f_lock);
	}
	return err;
}
EXPORT_SYMBOL(file_check_and_advance_wb_err);

/**
 * file_write_and_wait_range - write out & wait on a file range
 * @file:	file pointing to address_space with pages
 * @lstart:	offset in bytes where the range starts
 * @lend:	offset in bytes where the range ends (inclusive)
 *
 * Write out and wait upon file offsets lstart->lend, inclusive.
 *
 * Note that @lend is inclusive (describes the last byte to be written) so
 * that this function can be used to write to the very end-of-file (end = -1).
 *
 * After writing out and waiting on the data, we check and advance the
 * f_wb_err cursor to the latest value, and return any errors detected there.
 */
int file_write_and_wait_range(struct file *file, loff_t lstart, loff_t lend)
{
	int err = 0, err2;
	struct address_space *mapping = file->f_mapping;

	if ((!dax_mapping(mapping) && mapping->nrpages) ||
	    (dax_mapping(mapping) && mapping->nrexceptional)) {
		err = __filemap_fdatawrite_range(mapping, lstart, lend,
						 WB_SYNC_ALL);
		/* See comment of filemap_write_and_wait() */
		if (err != -EIO)
			__filemap_fdatawait_range(mapping, lstart, lend);
	}
	err2 = file_check_and_advance_wb_err(file);
	if (!err)
		err = err2;
	return err;
}
EXPORT_SYMBOL(file_write_and_wait_range);

/**
 * replace_page_cache_page - replace a pagecache page with a new one
 * @old:	page to be replaced
 * @new:	page to replace with
 * @gfp_mask:	allocation mode
 *
 * This function replaces a page in the pagecache with a new one.  On
 * success it acquires the pagecache reference for the new page and
 * drops it for the old page.  Both the old and new pages must be
 * locked.  This function does not add the new page to the LRU, the
 * caller must do that.
 *
 * The remove + add is atomic.  The only way this function can fail is
 * memory allocation failure.
 */
int replace_page_cache_page(struct page *old, struct page *new, gfp_t gfp_mask)
{
	int error;

	VM_BUG_ON_PAGE(!PageLocked(old), old);
	VM_BUG_ON_PAGE(!PageLocked(new), new);
	VM_BUG_ON_PAGE(new->mapping, new);

	error = radix_tree_preload(gfp_mask & GFP_RECLAIM_MASK);
	if (!error) {
		struct address_space *mapping = old->mapping;
		void (*freepage)(struct page *);

		pgoff_t offset = old->index;
		freepage = mapping->a_ops->freepage;

		page_cache_get(new);
		new->mapping = mapping;
		new->index = offset;

		spin_lock_irq(&mapping->tree_lock);
		__delete_from_page_cache(old, NULL);
		error = page_cache_tree_insert(mapping, new, NULL);
		BUG_ON(error);

		__inc_zone_page_state(new, NR_FILE_PAGES);
		if (PageSwapBacked(new))
			__inc_zone_page_state(new, NR_SHMEM);
		spin_unlock_irq(&mapping->tree_lock);
		mem_cgroup_migrate(old, new, true);
		radix_tree_preload_end();
		if (freepage)
			freepage(old);
		page_cache_release(old);
	}

	return error;
}
EXPORT_SYMBOL_GPL(replace_page_cache_page);

static int __add_to_page_cache_locked(struct page *page,
				      struct address_space *mapping,
				      pgoff_t offset, gfp_t gfp_mask,
				      void **shadowp)
{
	int huge = PageHuge(page);
	struct mem_cgroup *memcg;
	gfp_t gfp_modifiers_mask;
	int error;

	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(PageSwapBacked(page));

	/*
	 * RHEL7 commit 16f6fdc2a3b6 ("[mm] fix deadlock when using dm-thin on
	 * loopback device") introduces the call to mapping_gfp_constraint()
	 * to mask off GFP_KERNEL allocations coming down this way and
	 * potentially leading to dm-thin deadlocks on loopback devices.
	 *
	 * The side effect of that fix, though, is that it also drops all the
	 * action modifiers flags from the given gfp_mask, which can lead to
	 * other subtle issues, like the failure to handle __GFP_NOFAIL or
	 * __GFP_ACCOUNT cases down in the cgroup charging path.
	 *
	 * We deal with that corner case here, by reintroducing any
	 * action modifier flag that was previously set before calling
	 * mem_cgroup_cache_charge().
	 */
	gfp_modifiers_mask = gfp_mask & GFP_ACTION_MODIFIERS_MASK;

	gfp_mask = mapping_gfp_constraint(mapping, gfp_mask);

	if (gfp_modifiers_mask)
		gfp_mask |= gfp_modifiers_mask;

	if (!huge) {
		error = mem_cgroup_try_charge_cache(page, current->mm, gfp_mask,
					&memcg);
		if (error)
			return error;
	}

	error = radix_tree_maybe_preload(gfp_mask & GFP_RECLAIM_MASK);
	if (error) {
		if (!huge)
			mem_cgroup_cancel_charge(page, memcg);
		return error;
	}

	page_cache_get(page);
	page->mapping = mapping;
	page->index = offset;

	spin_lock_irq(&mapping->tree_lock);
	error = page_cache_tree_insert(mapping, page, shadowp);
	radix_tree_preload_end();
	if (unlikely(error))
		goto err_insert;
	__inc_zone_page_state(page, NR_FILE_PAGES);
	spin_unlock_irq(&mapping->tree_lock);
	if (!huge)
		mem_cgroup_commit_charge(page, memcg, false);
	trace_mm_filemap_add_to_page_cache(page);
	return 0;
err_insert:
	page->mapping = NULL;
	/* Leave page->index set: truncation relies upon it */
	spin_unlock_irq(&mapping->tree_lock);
	if (!huge)
		mem_cgroup_cancel_cache_charge(page, memcg);
	page_cache_release(page);
	return error;
}

/**
 * add_to_page_cache_locked - add a locked page to the pagecache
 * @page:	page to add
 * @mapping:	the page's address_space
 * @offset:	page index
 * @gfp_mask:	page allocation mode
 *
 * This function is used to add a page to the pagecache. It must be locked.
 * This function does not add the page to the LRU.  The caller must do that.
 */
int add_to_page_cache_locked(struct page *page, struct address_space *mapping,
		pgoff_t offset, gfp_t gfp_mask)
{
	return __add_to_page_cache_locked(page, mapping, offset,
					  gfp_mask, NULL);
}
EXPORT_SYMBOL(add_to_page_cache_locked);

int add_to_page_cache_lru(struct page *page, struct address_space *mapping,
				pgoff_t offset, gfp_t gfp_mask)
{
	void *shadow = NULL;
	int ret;

	__set_page_locked(page);
	ret = __add_to_page_cache_locked(page, mapping, offset,
					 gfp_mask, &shadow);
	if (unlikely(ret))
		__clear_page_locked(page);
	else {
		/*
		 * The page might have been evicted from cache only
		 * recently, in which case it should be activated like
		 * any other repeatedly accessed page.
		 */
		if (shadow && workingset_refault(shadow)) {
			SetPageActive(page);
			workingset_activation(page);
		} else
			ClearPageActive(page);
		lru_cache_add(page);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(add_to_page_cache_lru);

#ifdef CONFIG_NUMA
struct page *__page_cache_alloc(gfp_t gfp)
{
	int n;
	struct page *page;

	if (cpuset_do_page_mem_spread()) {
		unsigned int cpuset_mems_cookie;
		do {
			cpuset_mems_cookie = read_mems_allowed_begin();
			n = cpuset_mem_spread_node();
			page = alloc_pages_exact_node(n, gfp, 0);
		} while (!page && read_mems_allowed_retry(cpuset_mems_cookie));

		return page;
	}
	return alloc_pages(gfp, 0);
}
EXPORT_SYMBOL(__page_cache_alloc);
#endif

/*
 * In order to wait for pages to become available there must be
 * waitqueues associated with pages. By using a hash table of
 * waitqueues where the bucket discipline is to maintain all
 * waiters on the same queue and wake all when any of the pages
 * become available, and for the woken contexts to check to be
 * sure the appropriate page became available, this saves space
 * at a cost of "thundering herd" phenomena during rare hash
 * collisions.
 */
wait_queue_head_t *page_waitqueue(struct page *page)
{
	const struct zone *zone = page_zone(page);

	return &zone->wait_table[hash_ptr(page, zone->wait_table_bits)];
}
EXPORT_SYMBOL(page_waitqueue);

void wait_on_page_bit(struct page *page, int bit_nr)
{
	DEFINE_WAIT_BIT(wait, &page->flags, bit_nr);

	if (test_bit(bit_nr, &page->flags))
		__wait_on_bit(page_waitqueue(page), &wait, bit_wait_io,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(wait_on_page_bit);

int wait_on_page_bit_killable(struct page *page, int bit_nr)
{
	DEFINE_WAIT_BIT(wait, &page->flags, bit_nr);

	if (!test_bit(bit_nr, &page->flags))
		return 0;

	return __wait_on_bit(page_waitqueue(page), &wait,
			     bit_wait_io, TASK_KILLABLE);
}

int wait_on_page_bit_killable_timeout(struct page *page,
				       int bit_nr, unsigned long timeout)
{
	DEFINE_WAIT_BIT(wait, &page->flags, bit_nr);

	wait.key.timeout = jiffies + timeout;
	if (!test_bit(bit_nr, &page->flags))
		return 0;
	return __wait_on_bit(page_waitqueue(page), &wait,
			     bit_wait_io_timeout, TASK_KILLABLE);
}
EXPORT_SYMBOL_GPL(wait_on_page_bit_killable_timeout);

/**
 * add_page_wait_queue - Add an arbitrary waiter to a page's wait queue
 * @page: Page defining the wait queue of interest
 * @waiter: Waiter to add to the queue
 *
 * Add an arbitrary @waiter to the wait queue for the nominated @page.
 */
void add_page_wait_queue(struct page *page, wait_queue_t *waiter)
{
	wait_queue_head_t *q = page_waitqueue(page);
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	__add_wait_queue(q, waiter);
	spin_unlock_irqrestore(&q->lock, flags);
}
EXPORT_SYMBOL_GPL(add_page_wait_queue);

/**
 * unlock_page - unlock a locked page
 * @page: the page
 *
 * Unlocks the page and wakes up sleepers in ___wait_on_page_locked().
 * Also wakes sleepers in wait_on_page_writeback() because the wakeup
 * mechananism between PageLocked pages and PageWriteback pages is shared.
 * But that's OK - sleepers in wait_on_page_writeback() just go back to sleep.
 *
 * The mb is necessary to enforce ordering between the clear_bit and the read
 * of the waitqueue (to avoid SMP races with a parallel wait_on_page_locked()).
 */
void unlock_page(struct page *page)
{
	VM_BUG_ON_PAGE(!PageLocked(page), page);
	clear_bit_unlock(PG_locked, &page->flags);
	smp_mb__after_clear_bit();
	wake_up_page(page, PG_locked);
}
EXPORT_SYMBOL(unlock_page);

/*
 * After completing I/O on a page, call this routine to update the page
 * flags appropriately
 */
void page_endio(struct page *page, int rw, int err)
{
	if (rw == READ) {
		if (!err) {
			SetPageUptodate(page);
		} else {
			ClearPageUptodate(page);
			SetPageError(page);
		}
		unlock_page(page);
	} else { /* rw == WRITE */
		if (err) {
			struct address_space *mapping;

			SetPageError(page);
			mapping = page_mapping(page);
			if (mapping)
				mapping_set_error(mapping, err);
		}
		end_page_writeback(page);
	}
}
EXPORT_SYMBOL_GPL(page_endio);

/**
 * end_page_writeback - end writeback against a page
 * @page: the page
 */
void end_page_writeback(struct page *page)
{
	if (TestClearPageReclaim(page))
		rotate_reclaimable_page(page);

	if (!test_clear_page_writeback(page))
		BUG();

	smp_mb__after_clear_bit();
	wake_up_page(page, PG_writeback);
}
EXPORT_SYMBOL(end_page_writeback);

/**
 * __lock_page - get a lock on the page, assuming we need to sleep to get it
 * @page: the page to lock
 */
void __lock_page(struct page *page)
{
	DEFINE_WAIT_BIT(wait, &page->flags, PG_locked);

	__wait_on_bit_lock(page_waitqueue(page), &wait, bit_wait_io,
							TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(__lock_page);

int __lock_page_killable(struct page *page)
{
	DEFINE_WAIT_BIT(wait, &page->flags, PG_locked);

	return __wait_on_bit_lock(page_waitqueue(page), &wait,
					bit_wait_io, TASK_KILLABLE);
}
EXPORT_SYMBOL_GPL(__lock_page_killable);

int __lock_page_or_retry(struct page *page, struct mm_struct *mm,
			 unsigned int flags)
{
	if (flags & FAULT_FLAG_ALLOW_RETRY) {
		/*
		 * CAUTION! In this case, mmap_sem is not released
		 * even though return 0.
		 */
		if (flags & FAULT_FLAG_RETRY_NOWAIT)
			return 0;

		up_read(&mm->mmap_sem);
		if (flags & FAULT_FLAG_KILLABLE)
			wait_on_page_locked_killable(page);
		else
			wait_on_page_locked(page);
		return 0;
	} else {
		if (flags & FAULT_FLAG_KILLABLE) {
			int ret;

			ret = __lock_page_killable(page);
			if (ret) {
				up_read(&mm->mmap_sem);
				return 0;
			}
		} else
			__lock_page(page);
		return 1;
	}
}

/**
 * page_cache_next_hole - find the next hole (not-present entry)
 * @mapping: mapping
 * @index: index
 * @max_scan: maximum range to search
 *
 * Search the set [index, min(index+max_scan-1, MAX_INDEX)] for the
 * lowest indexed hole.
 *
 * Returns: the index of the hole if found, otherwise returns an index
 * outside of the set specified (in which case 'return - index >=
 * max_scan' will be true). In rare cases of index wrap-around, 0 will
 * be returned.
 *
 * page_cache_next_hole may be called under rcu_read_lock. However,
 * like radix_tree_gang_lookup, this will not atomically search a
 * snapshot of the tree at a single point in time. For example, if a
 * hole is created at index 5, then subsequently a hole is created at
 * index 10, page_cache_next_hole covering both indexes may return 10
 * if called under rcu_read_lock.
 */
pgoff_t page_cache_next_hole(struct address_space *mapping,
			     pgoff_t index, unsigned long max_scan)
{
	unsigned long i;

	for (i = 0; i < max_scan; i++) {
		struct page *page;

		page = radix_tree_lookup(&mapping->page_tree, index);
		if (!page || radix_tree_exceptional_entry(page))
			break;
		index++;
		if (index == 0)
			break;
	}

	return index;
}
EXPORT_SYMBOL(page_cache_next_hole);

/**
 * page_cache_prev_hole - find the prev hole (not-present entry)
 * @mapping: mapping
 * @index: index
 * @max_scan: maximum range to search
 *
 * Search backwards in the range [max(index-max_scan+1, 0), index] for
 * the first hole.
 *
 * Returns: the index of the hole if found, otherwise returns an index
 * outside of the set specified (in which case 'index - return >=
 * max_scan' will be true). In rare cases of wrap-around, ULONG_MAX
 * will be returned.
 *
 * page_cache_prev_hole may be called under rcu_read_lock. However,
 * like radix_tree_gang_lookup, this will not atomically search a
 * snapshot of the tree at a single point in time. For example, if a
 * hole is created at index 10, then subsequently a hole is created at
 * index 5, page_cache_prev_hole covering both indexes may return 5 if
 * called under rcu_read_lock.
 */
pgoff_t page_cache_prev_hole(struct address_space *mapping,
			     pgoff_t index, unsigned long max_scan)
{
	unsigned long i;

	for (i = 0; i < max_scan; i++) {
		struct page *page;

		page = radix_tree_lookup(&mapping->page_tree, index);
		if (!page || radix_tree_exceptional_entry(page))
			break;
		index--;
		if (index == ULONG_MAX)
			break;
	}

	return index;
}
EXPORT_SYMBOL(page_cache_prev_hole);

/**
 * __find_get_page - find and get a page reference
 * @mapping: the address_space to search
 * @offset: the page index
 *
 * Looks up the page cache slot at @mapping & @offset.  If there is a
 * page cache page, it is returned with an increased refcount.
 *
 * If the slot holds a shadow entry of a previously evicted page, or a
 * swap entry from shmem/tmpfs, it is returned.
 *
 * Otherwise, %NULL is returned.
 */
struct page *__find_get_page(struct address_space *mapping, pgoff_t offset)
{
	void **pagep;
	struct page *page;

	rcu_read_lock();
repeat:
	page = NULL;
	pagep = radix_tree_lookup_slot(&mapping->page_tree, offset);
	if (pagep) {
		page = radix_tree_deref_slot(pagep);
		if (unlikely(!page))
			goto out;
		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page))
				goto repeat;
			/*
			 * A shadow entry of a recently evicted page,
			 * or a swap entry from shmem/tmpfs.  Return
			 * it without attempting to raise page count.
			 */
			goto out;
		}
		if (!page_cache_get_speculative(page))
			goto repeat;

		/*
		 * Has the page moved?
		 * This is part of the lockless pagecache protocol. See
		 * include/linux/pagemap.h for details.
		 */
		if (unlikely(page != *pagep)) {
			page_cache_release(page);
			goto repeat;
		}
	}
out:
	rcu_read_unlock();

	return page;
}
EXPORT_SYMBOL(__find_get_page);

/**
 * find_get_page - find and get a page reference
 * @mapping: the address_space to search
 * @offset: the page index
 *
 * Looks up the page cache slot at @mapping & @offset.  If there is a
 * page cache page, it is returned with an increased refcount.
 *
 * Otherwise, %NULL is returned.
 */
struct page *find_get_page(struct address_space *mapping, pgoff_t offset)
{
	struct page *page = __find_get_page(mapping, offset);

	if (radix_tree_exceptional_entry(page))
		page = NULL;
	return page;
}
EXPORT_SYMBOL(find_get_page);

/**
 * __find_lock_page - locate, pin and lock a pagecache page
 * @mapping: the address_space to search
 * @offset: the page index
 *
 * Looks up the page cache slot at @mapping & @offset.  If there is a
 * page cache page, it is returned locked and with an increased
 * refcount.
 *
 * If the slot holds a shadow entry of a previously evicted page, or a
 * swap entry from shmem/tmpfs, it is returned.
 *
 * Otherwise, %NULL is returned.
 *
 * __find_lock_page() may sleep.
 */
struct page *__find_lock_page(struct address_space *mapping, pgoff_t offset)
{
	struct page *page;
repeat:
	page = __find_get_page(mapping, offset);
	if (page && !radix_tree_exception(page)) {
		lock_page(page);
		/* Has the page been truncated? */
		if (unlikely(page->mapping != mapping)) {
			unlock_page(page);
			page_cache_release(page);
			goto repeat;
		}
		VM_BUG_ON_PAGE(page->index != offset, page);
	}
	return page;
}
EXPORT_SYMBOL(__find_lock_page);

/**
 * find_lock_page - locate, pin and lock a pagecache page
 * @mapping: the address_space to search
 * @offset: the page index
 *
 * Looks up the page cache slot at @mapping & @offset.  If there is a
 * page cache page, it is returned locked and with an increased
 * refcount.
 *
 * Otherwise, %NULL is returned.
 *
 * find_lock_page() may sleep.
 */
struct page *find_lock_page(struct address_space *mapping, pgoff_t offset)
{
	struct page *page = __find_lock_page(mapping, offset);

	if (radix_tree_exceptional_entry(page))
		page = NULL;
	return page;
}
EXPORT_SYMBOL(find_lock_page);

/**
 * find_or_create_page - locate or add a pagecache page
 * @mapping: the page's address_space
 * @index: the page's index into the mapping
 * @gfp_mask: page allocation mode
 *
 * Looks up the page cache slot at @mapping & @offset.  If there is a
 * page cache page, it is returned locked and with an increased
 * refcount.
 *
 * If the page is not present, a new page is allocated using @gfp_mask
 * and added to the page cache and the VM's LRU list.  The page is
 * returned locked and with an increased refcount.
 *
 * On memory exhaustion, %NULL is returned.
 *
 * find_or_create_page() may sleep, even if @gfp_flags specifies an
 * atomic allocation!
 */
struct page *find_or_create_page(struct address_space *mapping,
		pgoff_t index, gfp_t gfp_mask)
{
	struct page *page;
	int err;
repeat:
	page = find_lock_page(mapping, index);
	if (!page) {
		page = __page_cache_alloc(gfp_mask);
		if (!page)
			return NULL;
		/*
		 * We want a regular kernel memory (not highmem or DMA etc)
		 * allocation for the radix tree nodes, but we need to honour
		 * the context-specific requirements the caller has asked for.
		 * GFP_RECLAIM_MASK collects those requirements.
		 */
		err = add_to_page_cache_lru(page, mapping, index,
			(gfp_mask & GFP_RECLAIM_MASK));
		if (unlikely(err)) {
			page_cache_release(page);
			page = NULL;
			if (err == -EEXIST)
				goto repeat;
		}
	}
	return page;
}
EXPORT_SYMBOL(find_or_create_page);

/**
 * __find_get_pages - gang pagecache lookup
 * @mapping:	The address_space to search
 * @start:	The starting page index
 * @nr_pages:	The maximum number of pages
 * @pages:	Where the resulting entries are placed
 * @indices:	The cache indices corresponding to the entries in @pages
 *
 * __find_get_pages() will search for and return a group of up to
 * @nr_pages pages in the mapping.  The pages are placed at @pages.
 * __find_get_pages() takes a reference against the returned pages.
 *
 * The search returns a group of mapping-contiguous pages with ascending
 * indexes.  There may be holes in the indices due to not-present pages.
 *
 * Any shadow entries of evicted pages, or swap entries from
 * shmem/tmpfs, are included in the returned array.
 *
 * __find_get_pages() returns the number of pages and shadow entries
 * which were found.
 */
unsigned __find_get_pages(struct address_space *mapping,
			  pgoff_t start, unsigned int nr_pages,
			  struct page **pages, pgoff_t *indices)
{
	void **slot;
	unsigned int ret = 0;
	struct radix_tree_iter iter;

	if (!nr_pages)
		return 0;

	rcu_read_lock();
restart:
	radix_tree_for_each_slot(slot, &mapping->page_tree, &iter, start) {
		struct page *page;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;
		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page))
				goto restart;
			/*
			 * A shadow entry of a recently evicted page, a swap
			 * entry from shmem/tmpfs or a DAX entry.  Return it
			 * without attempting to raise page count.
			 */
			goto export;
		}
		if (!page_cache_get_speculative(page))
			goto repeat;

		/* Has the page moved? */
		if (unlikely(page != *slot)) {
			page_cache_release(page);
			goto repeat;
		}
export:
		indices[ret] = iter.index;
		pages[ret] = page;
		if (++ret == nr_pages)
			break;
	}
	rcu_read_unlock();
	return ret;
}

/**
 * find_get_pages - gang pagecache lookup
 * @mapping:	The address_space to search
 * @start:	The starting page index
 * @nr_pages:	The maximum number of pages
 * @pages:	Where the resulting pages are placed
 *
 * find_get_pages() will search for and return a group of up to
 * @nr_pages pages in the mapping.  The pages are placed at @pages.
 * find_get_pages() takes a reference against the returned pages.
 *
 * The search returns a group of mapping-contiguous pages with ascending
 * indexes.  There may be holes in the indices due to not-present pages.
 *
 * find_get_pages() returns the number of pages which were found.
 */
unsigned find_get_pages(struct address_space *mapping, pgoff_t start,
			    unsigned int nr_pages, struct page **pages)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned ret = 0;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
restart:
	radix_tree_for_each_slot(slot, &mapping->page_tree, &iter, start) {
		struct page *page;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;

		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				/*
				 * Transient condition which can only trigger
				 * when entry at index 0 moves out of or back
				 * to root: none yet gotten, safe to restart.
				 */
				WARN_ON(iter.index);
				goto restart;
			}
			/*
			 * A shadow entry of a recently evicted page,
			 * or a swap entry from shmem/tmpfs.  Skip
			 * over it.
			 */
			continue;
		}

		if (!page_cache_get_speculative(page))
			goto repeat;

		/* Has the page moved? */
		if (unlikely(page != *slot)) {
			page_cache_release(page);
			goto repeat;
		}

		pages[ret] = page;
		if (++ret == nr_pages)
			break;
	}

	rcu_read_unlock();
	return ret;
}

/**
 * find_get_pages_contig - gang contiguous pagecache lookup
 * @mapping:	The address_space to search
 * @index:	The starting page index
 * @nr_pages:	The maximum number of pages
 * @pages:	Where the resulting pages are placed
 *
 * find_get_pages_contig() works exactly like find_get_pages(), except
 * that the returned number of pages are guaranteed to be contiguous.
 *
 * find_get_pages_contig() returns the number of pages which were found.
 */
unsigned find_get_pages_contig(struct address_space *mapping, pgoff_t index,
			       unsigned int nr_pages, struct page **pages)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned int ret = 0;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
restart:
	radix_tree_for_each_contig(slot, &mapping->page_tree, &iter, index) {
		struct page *page;
repeat:
		page = radix_tree_deref_slot(slot);
		/* The hole, there no reason to continue */
		if (unlikely(!page))
			break;

		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				/*
				 * Transient condition which can only trigger
				 * when entry at index 0 moves out of or back
				 * to root: none yet gotten, safe to restart.
				 */
				goto restart;
			}
			/*
			 * A shadow entry of a recently evicted page,
			 * or a swap entry from shmem/tmpfs.  Stop
			 * looking for contiguous pages.
			 */
			break;
		}

		if (!page_cache_get_speculative(page))
			goto repeat;

		/* Has the page moved? */
		if (unlikely(page != *slot)) {
			page_cache_release(page);
			goto repeat;
		}

		/*
		 * must check mapping and index after taking the ref.
		 * otherwise we can get both false positives and false
		 * negatives, which is just confusing to the caller.
		 */
		if (page->mapping == NULL || page->index != iter.index) {
			page_cache_release(page);
			break;
		}

		pages[ret] = page;
		if (++ret == nr_pages)
			break;
	}
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(find_get_pages_contig);

/**
 * find_get_pages_tag - find and return pages that match @tag
 * @mapping:	the address_space to search
 * @index:	the starting page index
 * @tag:	the tag index
 * @nr_pages:	the maximum number of pages
 * @pages:	where the resulting pages are placed
 *
 * Like find_get_pages, except we only return pages which are tagged with
 * @tag.   We update @index to index the next page for the traversal.
 */
unsigned find_get_pages_tag(struct address_space *mapping, pgoff_t *index,
			int tag, unsigned int nr_pages, struct page **pages)
{
	struct radix_tree_iter iter;
	void **slot;
	unsigned ret = 0;

	if (unlikely(!nr_pages))
		return 0;

	rcu_read_lock();
restart:
	radix_tree_for_each_tagged(slot, &mapping->page_tree,
				   &iter, *index, tag) {
		struct page *page;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;

		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				/*
				 * Transient condition which can only trigger
				 * when entry at index 0 moves out of or back
				 * to root: none yet gotten, safe to restart.
				 */
				goto restart;
			}
			/*
			 * A shadow entry of a recently evicted page.
			 *
			 * Those entries should never be tagged, but
			 * this tree walk is lockless and the tags are
			 * looked up in bulk, one radix tree node at a
			 * time, so there is a sizable window for page
			 * reclaim to evict a page we saw tagged.
			 *
			 * Skip over it.
			 */
			continue;
		}

		if (!page_cache_get_speculative(page))
			goto repeat;

		/* Has the page moved? */
		if (unlikely(page != *slot)) {
			page_cache_release(page);
			goto repeat;
		}

		pages[ret] = page;
		if (++ret == nr_pages)
			break;
	}

	rcu_read_unlock();

	if (ret)
		*index = pages[ret - 1]->index + 1;

	return ret;
}
EXPORT_SYMBOL(find_get_pages_tag);

/**
 * grab_cache_page_nowait - returns locked page at given index in given cache
 * @mapping: target address_space
 * @index: the page index
 *
 * Same as grab_cache_page(), but do not wait if the page is unavailable.
 * This is intended for speculative data generators, where the data can
 * be regenerated if the page couldn't be grabbed.  This routine should
 * be safe to call while holding the lock for another page.
 *
 * Clear __GFP_FS when allocating the page to avoid recursion into the fs
 * and deadlock against the caller's locked page.
 */
struct page *
grab_cache_page_nowait(struct address_space *mapping, pgoff_t index)
{
	struct page *page = find_get_page(mapping, index);

	if (page) {
		if (trylock_page(page))
			return page;
		page_cache_release(page);
		return NULL;
	}
	page = __page_cache_alloc(mapping_gfp_mask(mapping) & ~__GFP_FS);
	if (page && add_to_page_cache_lru(page, mapping, index, GFP_NOFS)) {
		page_cache_release(page);
		page = NULL;
	}
	return page;
}
EXPORT_SYMBOL(grab_cache_page_nowait);

/**
 * find_get_entries_tag - find and return entries that match @tag
 * @mapping:	the address_space to search
 * @start:	the starting page cache index
 * @tag:	the tag index
 * @nr_entries:	the maximum number of entries
 * @entries:	where the resulting entries are placed
 * @indices:	the cache indices corresponding to the entries in @entries
 *
 * Like find_get_entries, except we only return entries which are tagged with
 * @tag.
 */
unsigned find_get_entries_tag(struct address_space *mapping, pgoff_t start,
			int tag, unsigned int nr_entries,
			struct page **entries, pgoff_t *indices)
{
	void **slot;
	unsigned int ret = 0;
	struct radix_tree_iter iter;

	if (!nr_entries)
		return 0;

	rcu_read_lock();
restart:
	radix_tree_for_each_tagged(slot, &mapping->page_tree,
				   &iter, start, tag) {
		struct page *page;
repeat:
		page = radix_tree_deref_slot(slot);
		if (unlikely(!page))
			continue;
		if (radix_tree_exception(page)) {
			if (radix_tree_deref_retry(page)) {
				/*
				 * Transient condition which can only trigger
				 * when entry at index 0 moves out of or back
				 * to root: none yet gotten, safe to restart.
				 */
				goto restart;
			}

			/*
			 * A shadow entry of a recently evicted page, a swap
			 * entry from shmem/tmpfs or a DAX entry.  Return it
			 * without attempting to raise page count.
			 */
			goto export;
		}
		if (!page_cache_get_speculative(page))
			goto repeat;

		/* Has the page moved? */
		if (unlikely(page != *slot)) {
			page_cache_release(page);
			goto repeat;
		}
export:
		indices[ret] = iter.index;
		entries[ret] = page;
		if (++ret == nr_entries)
			break;
	}
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(find_get_entries_tag);

/*
 * CD/DVDs are error prone. When a medium error occurs, the driver may fail
 * a _large_ part of the i/o request. Imagine the worst scenario:
 *
 *      ---R__________________________________________B__________
 *         ^ reading here                             ^ bad block(assume 4k)
 *
 * read(R) => miss => readahead(R...B) => media error => frustrating retries
 * => failing the whole request => read(R) => read(R+1) =>
 * readahead(R+1...B+1) => bang => read(R+2) => read(R+3) =>
 * readahead(R+3...B+2) => bang => read(R+3) => read(R+4) =>
 * readahead(R+4...B+3) => bang => read(R+4) => read(R+5) => ......
 *
 * It is going insane. Fix it by quickly scaling down the readahead size.
 */
static void shrink_readahead_size_eio(struct file *filp,
					struct file_ra_state *ra)
{
	ra->ra_pages /= 4;
}

/**
 * do_generic_file_read - generic file read routine
 * @filp:	the file to read
 * @ppos:	current file position
 * @desc:	read_descriptor
 * @actor:	read method
 *
 * This is a generic file read routine, and uses the
 * mapping->a_ops->readpage() function for the actual low-level stuff.
 *
 * This is really ugly. But the goto's actually try to clarify some
 * of the logic when it comes to error handling etc.
 */
static void do_generic_file_read(struct file *filp, loff_t *ppos,
		read_descriptor_t *desc, read_actor_t actor)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct file_ra_state *ra = &filp->f_ra;
	pgoff_t index;
	pgoff_t last_index;
	pgoff_t prev_index;
	unsigned long offset;      /* offset into pagecache page */
	unsigned int prev_offset;
	int error;

	index = *ppos >> PAGE_CACHE_SHIFT;
	prev_index = ra->prev_pos >> PAGE_CACHE_SHIFT;
	prev_offset = ra->prev_pos & (PAGE_CACHE_SIZE-1);
	last_index = (*ppos + desc->count + PAGE_CACHE_SIZE-1) >> PAGE_CACHE_SHIFT;
	offset = *ppos & ~PAGE_CACHE_MASK;

	for (;;) {
		struct page *page;
		pgoff_t end_index;
		loff_t isize;
		unsigned long nr, ret;

		cond_resched();
find_page:
		if (fatal_signal_pending(current)) {
			desc->error = -EINTR;
			goto out;
		}

		page = find_get_page(mapping, index);
		if (!page && mapping->i_peer_file) {
			page = pick_peer_page(mapping, index, ra,
					      last_index - index);
			if (page)
				goto page_ok;
		}
		if (!page) {
			page_cache_sync_readahead(mapping,
					ra, filp,
					index, last_index - index);
			page = find_get_page(mapping, index);
			if (unlikely(page == NULL))
				goto no_cached_page;
		}
		if (PageReadahead(page)) {
			page_cache_async_readahead(mapping,
					ra, filp, page,
					index, last_index - index);
		}
		if (!PageUptodate(page)) {
			if (inode->i_blkbits == PAGE_CACHE_SHIFT ||
					!mapping->a_ops->is_partially_uptodate)
				goto page_not_up_to_date;
			if (!trylock_page(page))
				goto page_not_up_to_date;
			/* Did it get truncated before we got the lock? */
			if (!page->mapping)
				goto page_not_up_to_date_locked;
			if (!mapping->a_ops->is_partially_uptodate(page,
								desc, offset))
				goto page_not_up_to_date_locked;
			unlock_page(page);
		}
page_ok:
		/*
		 * i_size must be checked after we know the page is Uptodate.
		 *
		 * Checking i_size after the check allows us to calculate
		 * the correct value for "nr", which means the zero-filled
		 * part of the page is not copied back to userspace (unless
		 * another truncate extends the file - this is desired though).
		 */

		isize = i_size_read(inode);
		end_index = (isize - 1) >> PAGE_CACHE_SHIFT;
		if (unlikely(!isize || index > end_index)) {
			page_cache_release(page);
			goto out;
		}

		/* nr is the maximum number of bytes to copy from this page */
		nr = PAGE_CACHE_SIZE;
		if (index == end_index) {
			nr = ((isize - 1) & ~PAGE_CACHE_MASK) + 1;
			if (nr <= offset) {
				page_cache_release(page);
				goto out;
			}
		}
		nr = nr - offset;

		/* If users can be writing to this page using arbitrary
		 * virtual addresses, take care about potential aliasing
		 * before reading the page on the kernel side.
		 */
		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		/*
		 * When a sequential read accesses a page several times,
		 * only mark it as accessed the first time.
		 */
		if (prev_index != index || offset != prev_offset)
			mark_page_accessed(page);
		prev_index = index;

		/*
		 * Ok, we have the page, and it's up-to-date, so
		 * now we can copy it to user space...
		 *
		 * The actor routine returns how many bytes were actually used..
		 * NOTE! This may not be the same as how much of a user buffer
		 * we filled up (we may be padding etc), so we can only update
		 * "pos" here (the actor routine has to update the user buffer
		 * pointers and the remaining count).
		 */
		ret = actor(desc, page, offset, nr);
		offset += ret;
		index += offset >> PAGE_CACHE_SHIFT;
		offset &= ~PAGE_CACHE_MASK;
		prev_offset = offset;

		page_cache_release(page);
		if (ret == nr && desc->count)
			continue;
		goto out;

page_not_up_to_date:
		virtinfo_notifier_call(VITYPE_IO, VIRTINFO_IO_PREPARE, NULL);

		/* Get exclusive access to the page ... */
		error = lock_page_killable(page);
		if (unlikely(error))
			goto readpage_error;

page_not_up_to_date_locked:
		/* Did it get truncated before we got the lock? */
		if (!page->mapping) {
			unlock_page(page);
			page_cache_release(page);
			continue;
		}

		/* Did somebody else fill it already? */
		if (PageUptodate(page)) {
			unlock_page(page);
			goto page_ok;
		}

readpage:
		/*
		 * A previous I/O error may have been due to temporary
		 * failures, eg. multipath errors.
		 * PG_error will be set again if readpage fails.
		 */
		ClearPageError(page);
		/* Start the actual read. The read will unlock the page. */
		error = mapping->a_ops->readpage(filp, page);

		if (unlikely(error)) {
			if (error == AOP_TRUNCATED_PAGE) {
				page_cache_release(page);
				goto find_page;
			}
			goto readpage_error;
		}

		if (!PageUptodate(page)) {
			error = lock_page_killable(page);
			if (unlikely(error))
				goto readpage_error;
			if (!PageUptodate(page)) {
				if (page->mapping == NULL) {
					/*
					 * invalidate_mapping_pages got it
					 */
					unlock_page(page);
					page_cache_release(page);
					goto find_page;
				}
				unlock_page(page);
				shrink_readahead_size_eio(filp, ra);
				error = -EIO;
				goto readpage_error;
			}
			unlock_page(page);
		}

		goto page_ok;

readpage_error:
		/* UHHUH! A synchronous read error occurred. Report it */
		desc->error = error;
		page_cache_release(page);
		goto out;

no_cached_page:
		virtinfo_notifier_call(VITYPE_IO, VIRTINFO_IO_PREPARE, NULL);

		/*
		 * Ok, it wasn't cached, so we need to create a new
		 * page..
		 */
		page = page_cache_alloc_cold(mapping);
		if (!page) {
			desc->error = -ENOMEM;
			goto out;
		}
		error = add_to_page_cache_lru(page, mapping,
						index, GFP_KERNEL);
		if (error) {
			page_cache_release(page);
			if (error == -EEXIST)
				goto find_page;
			desc->error = error;
			goto out;
		}
		goto readpage;
	}

out:
	ra->prev_pos = prev_index;
	ra->prev_pos <<= PAGE_CACHE_SHIFT;
	ra->prev_pos |= prev_offset;

	*ppos = ((loff_t)index << PAGE_CACHE_SHIFT) + offset;
	file_accessed(filp);
}

int file_read_actor(read_descriptor_t *desc, struct page *page,
			unsigned long offset, unsigned long size)
{
	char *kaddr;
	unsigned long left, count = desc->count;

	if (size > count)
		size = count;

	/*
	 * Faults on the destination of a read are common, so do it before
	 * taking the kmap.
	 */
	if (IS_ENABLED(CONFIG_HIGHMEM) && !fault_in_pages_writeable(desc->arg.buf, size)) {
		kaddr = kmap_atomic(page);
		left = __copy_to_user_inatomic(desc->arg.buf,
						kaddr + offset, size);
		kunmap_atomic(kaddr);
		if (left == 0)
			goto success;
	}

	/* Do it the slow way */
	kaddr = kmap(page);
	left = __copy_to_user(desc->arg.buf, kaddr + offset, size);
	kunmap(page);

	if (left) {
		size -= left;
		desc->error = -EFAULT;
	}
success:
	desc->count = count - size;
	desc->written += size;
	desc->arg.buf += size;
	return size;
}

/*
 * Performs necessary checks before doing a write
 * @iov:	io vector request
 * @nr_segs:	number of segments in the iovec
 * @count:	number of bytes to write
 * @access_flags: type of access: %VERIFY_READ or %VERIFY_WRITE
 *
 * Adjust number of segments and amount of bytes to write (nr_segs should be
 * properly initialized first). Returns appropriate error code that caller
 * should return or zero in case that write should be allowed.
 */
int generic_segment_checks(const struct iovec *iov,
			unsigned long *nr_segs, size_t *count, int access_flags)
{
	unsigned long   seg;
	size_t cnt = 0;
	for (seg = 0; seg < *nr_segs; seg++) {
		const struct iovec *iv = &iov[seg];

		/*
		 * If any segment has a negative length, or the cumulative
		 * length ever wraps negative then return -EINVAL.
		 */
		cnt += iv->iov_len;
		if (unlikely((ssize_t)(cnt|iv->iov_len) < 0))
			return -EINVAL;
		if (access_ok(access_flags, iv->iov_base, iv->iov_len))
			continue;
		if (seg == 0)
			return -EFAULT;
		*nr_segs = seg;
		cnt -= iv->iov_len;	/* This segment is no good */
		break;
	}
	*count = cnt;
	return 0;
}
EXPORT_SYMBOL(generic_segment_checks);

static ssize_t mapping_direct_IO(struct address_space *mapping, int rw,
			         struct kiocb *iocb, struct iov_iter *iter,
			         loff_t pos)
{
	if (iov_iter_has_iovec(iter))
		return mapping->a_ops->direct_IO(rw, iocb, iov_iter_iovec(iter),
						 pos, iter->nr_segs);
	else if (iov_iter_has_bvec(iter))
		return mapping->a_ops->direct_IO_bvec(rw, iocb,
						      iov_iter_bvec(iter), pos,
						      iter->nr_segs);
	else if (iov_iter_has_page(iter))
		return mapping->a_ops->direct_IO_page(rw, iocb,
						      iov_iter_page(iter), pos);
	else
		BUG();
}

static int file_read_iter_actor(read_descriptor_t *desc, struct page *page,
				unsigned long offset, unsigned long size)
{
	struct iov_iter *iter = desc->arg.data;
	unsigned long copied = 0;

	if (size > desc->count)
		size = desc->count;

	copied = iov_iter_copy_to_user(page, iter, offset, size);
	if (copied < size)
		desc->error = -EFAULT;

	iov_iter_advance(iter, copied);
	desc->count -= copied;
	desc->written += copied;

	return copied;
}


/**
 * generic_file_read_iter - generic filesystem read routine
 * @iocb:	kernel I/O control block
 * @iov_iter:	memory vector
 * @pos:	current file position
 */
ssize_t
generic_file_read_iter(struct kiocb *iocb, struct iov_iter *iter, loff_t pos)
{
	struct file *filp = iocb->ki_filp;
	read_descriptor_t desc;
	ssize_t retval = 0;
	size_t count = iov_iter_count(iter);
	loff_t *ppos = &iocb->ki_pos;

	if (io_is_direct(filp)) {
		loff_t size;
		struct address_space *mapping;
		struct inode *inode;

		mapping = filp->f_mapping;
		inode = mapping->host;
		if (!count)
			goto out; /* skip atime */
		size = i_size_read(inode);
		retval = filemap_write_and_wait_range(mapping, pos,
				pos + count - 1);
		if (!retval) {
			retval = mapping_direct_IO(mapping, READ,
						   iocb, iter, pos);
		}
		if (retval > 0) {
			*ppos = pos + retval;
			count -= retval;
		}

		/*
		 * Btrfs can have a short DIO read if we encounter
		 * compressed extents, so if there was an error, or if
		 * we've already read everything we wanted to, or if
		 * there was a short read because we hit EOF, go ahead
		 * and return.  Otherwise fallthrough to buffered io for
		 * the rest of the read.
		 */
		if (retval < 0 || !count || *ppos >= size) {
			file_accessed(filp);
			goto out;
		}

		/*
		 *  Buffered reads will not work for DAX files, so don't
		 *  bother trying.
		 */
		if (IS_DAX(inode)) {
			file_accessed(filp);
			goto out;
		}
	}

	iov_iter_advance(iter, retval);

	desc.written = 0;
	desc.arg.data = iter;
	desc.count = count;
	desc.error = 0;
	do_generic_file_read(filp, ppos, &desc, file_read_iter_actor);

	retval += desc.written;
	if (desc.error && !retval)
		retval = desc.error;
out:
	return retval;
}
EXPORT_SYMBOL(generic_file_read_iter);

/**
 * generic_file_aio_read - generic filesystem read routine
 * @iocb:	kernel I/O control block
 * @iov:	io vector request
 * @nr_segs:	number of segments in the iovec
 * @pos:	current file position
 *
 * This is the "read()" routine for all filesystems
 * that can use the page cache directly.
 */
ssize_t
generic_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	struct iov_iter iter;
	int ret;
	size_t count;

	count = 0;
	ret = generic_segment_checks(iov, &nr_segs, &count, VERIFY_WRITE);
	if (ret)
		return ret;

	iov_iter_init(&iter, iov, nr_segs, count, 0);

	return generic_file_read_iter(iocb, &iter, pos);
}
EXPORT_SYMBOL(generic_file_aio_read);

#ifdef CONFIG_MMU
/**
 * page_cache_read - adds requested page to the page cache if not already there
 * @file:	file to read
 * @offset:	page index
 *
 * This adds the requested page to the page cache if it isn't already there,
 * and schedules an I/O to read in its contents from disk.
 */
static int page_cache_read(struct file *file, pgoff_t offset, gfp_t gfp_mask)
{
	struct address_space *mapping = file->f_mapping;
	struct page *page; 
	int ret;

	virtinfo_notifier_call(VITYPE_IO, VIRTINFO_IO_PREPARE, NULL);

	do {
		page = __page_cache_alloc(gfp_mask|__GFP_COLD);
		if (!page)
			return -ENOMEM;

		ret = add_to_page_cache_lru(page, mapping, offset, gfp_mask);
		if (ret == 0)
			ret = mapping->a_ops->readpage(file, page);
		else if (ret == -EEXIST)
			ret = 0; /* losing race to add is OK */

		page_cache_release(page);

	} while (ret == AOP_TRUNCATED_PAGE);
		
	return ret;
}

#define MMAP_LOTSAMISS  (100)

/*
 * Synchronous readahead happens when we don't even find
 * a page in the page cache at all.
 */
static void do_sync_mmap_readahead(struct vm_area_struct *vma,
				   struct file_ra_state *ra,
				   struct file *file,
				   pgoff_t offset)
{
	struct address_space *mapping = file->f_mapping;

	/* If we don't want any read-ahead, don't bother */
	if (VM_RandomReadHint(vma))
		return;
	if (!ra->ra_pages)
		return;

	if (VM_SequentialReadHint(vma)) {
		page_cache_sync_readahead(mapping, ra, file, offset,
					  ra->ra_pages);
		return;
	}

	/* Avoid banging the cache line if not needed */
	if (ra->mmap_miss < MMAP_LOTSAMISS * 10)
		ra->mmap_miss++;

	/*
	 * Do we miss much more than hit in this file? If so,
	 * stop bothering with read-ahead. It will only hurt.
	 */
	if (ra->mmap_miss > MMAP_LOTSAMISS)
		return;

	/*
	 * mmap read-around
	 */
	ra->start = max_t(long, 0, offset - ra->ra_pages / 2);
	ra->size = ra->ra_pages;
	ra->async_size = ra->ra_pages / 4;
	ra_submit(ra, mapping, file);
}

/*
 * Asynchronous readahead happens when we find the page and PG_readahead,
 * so we want to possibly extend the readahead further..
 */
static void do_async_mmap_readahead(struct vm_area_struct *vma,
				    struct file_ra_state *ra,
				    struct file *file,
				    struct page *page,
				    pgoff_t offset)
{
	struct address_space *mapping = file->f_mapping;

	/* If we don't want any read-ahead, don't bother */
	if (VM_RandomReadHint(vma))
		return;
	if (ra->mmap_miss > 0)
		ra->mmap_miss--;
	if (PageReadahead(page))
		page_cache_async_readahead(mapping, ra, file,
					   page, offset, ra->ra_pages);
}

/**
 * filemap_fault - read in file data for page fault handling
 * @vma:	vma in which the fault was taken
 * @vmf:	struct vm_fault containing details of the fault
 *
 * filemap_fault() is invoked via the vma operations vector for a
 * mapped memory region to read in file data during a page fault.
 *
 * The goto's are kind of ugly, but this streamlines the normal case of having
 * it in the page cache, and handles the special cases reasonably without
 * having a lot of duplicated code.
 */
int filemap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int error;
	struct file *file = vma->vm_file;
	struct address_space *mapping = file->f_mapping;
	struct file_ra_state *ra = &file->f_ra;
	struct inode *inode = mapping->host;
	pgoff_t offset = vmf->pgoff;
	struct page *page;
	pgoff_t size;
	int ret = 0;

	size = (i_size_read(inode) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (offset >= size)
		return VM_FAULT_SIGBUS;

	/*
	 * Do we have something in the page cache already?
	 */
	page = find_get_page(mapping, offset);
	if (!page && mapping->i_peer_file) {
		page = pick_peer_page(mapping, offset, ra, ra->ra_pages);
		if (page) {
			vmf->page = page;
			return 0; /* unlocked page */
		}
	}
	if (likely(page) && !(vmf->flags & FAULT_FLAG_TRIED)) {
		/*
		 * We found the page, so try async readahead before
		 * waiting for the lock.
		 */
		do_async_mmap_readahead(vma, ra, file, page, offset);

		if (unlikely(!PageUptodate(page)))
			virtinfo_notifier_call(VITYPE_IO,
					VIRTINFO_IO_PREPARE, NULL);

	} else if (!page) {
		/* No page in the page cache at all */
		do_sync_mmap_readahead(vma, ra, file, offset);
		count_vm_event(PGMAJFAULT);
		mem_cgroup_count_vm_event(vma->vm_mm, PGMAJFAULT);
		ret = VM_FAULT_MAJOR;
retry_find:
		page = find_get_page(mapping, offset);
		if (!page)
			goto no_cached_page;
	}

	if (!lock_page_or_retry(page, vma->vm_mm, vmf->flags)) {
		page_cache_release(page);
		return ret | VM_FAULT_RETRY;
	}

	/* Did it get truncated? */
	if (unlikely(page->mapping != mapping)) {
		unlock_page(page);
		put_page(page);
		goto retry_find;
	}
	VM_BUG_ON_PAGE(page->index != offset, page);

	/*
	 * We have a locked page in the page cache, now we need to check
	 * that it's up-to-date. If not, it is going to be due to an error.
	 */
	if (unlikely(!PageUptodate(page)))
		goto page_not_uptodate;

	/*
	 * Found the page and have a reference on it.
	 * We must recheck i_size under page lock.
	 */
	size = (i_size_read(inode) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	if (unlikely(offset >= size)) {
		unlock_page(page);
		page_cache_release(page);
		return VM_FAULT_SIGBUS;
	}

	vmf->page = page;
	return ret | VM_FAULT_LOCKED;

no_cached_page:
	/*
	 * We're only likely to ever get here if MADV_RANDOM is in
	 * effect.
	 */
	error = page_cache_read(file, offset, vmf->gfp_mask);

	/*
	 * The page we want has now been added to the page cache.
	 * In the unlikely event that someone removed it in the
	 * meantime, we'll just come back here and read it again.
	 */
	if (error >= 0)
		goto retry_find;

	/*
	 * An error return from page_cache_read can result if the
	 * system is low on memory, or a problem occurs while trying
	 * to schedule I/O.
	 */
	if (error == -ENOMEM)
		return VM_FAULT_OOM;
	return VM_FAULT_SIGBUS;

page_not_uptodate:
	/*
	 * Umm, take care of errors if the page isn't up-to-date.
	 * Try to re-read it _once_. We do this synchronously,
	 * because there really aren't any performance issues here
	 * and we need to check for errors.
	 */
	ClearPageError(page);
	error = mapping->a_ops->readpage(file, page);
	if (!error) {
		wait_on_page_locked(page);
		if (!PageUptodate(page))
			error = -EIO;
	}
	page_cache_release(page);

	if (!error || error == AOP_TRUNCATED_PAGE)
		goto retry_find;

	/* Things didn't work out. Return zero to tell the mm layer so. */
	shrink_readahead_size_eio(file, ra);
	return VM_FAULT_SIGBUS;
}
EXPORT_SYMBOL(filemap_fault);

int filemap_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vma->vm_file);
	int ret = VM_FAULT_LOCKED;

	sb_start_pagefault(inode->i_sb);
	file_update_time(vma->vm_file);
	lock_page(page);
	if (page->mapping != inode->i_mapping) {
		unlock_page(page);
		ret = VM_FAULT_NOPAGE;
		goto out;
	}
	/*
	 * We mark the page dirty already here so that when freeze is in
	 * progress, we are guaranteed that writeback during freezing will
	 * see the dirty page and writeprotect it again.
	 */
	set_page_dirty(page);
	wait_for_stable_page(page);
out:
	sb_end_pagefault(inode->i_sb);
	return ret;
}
EXPORT_SYMBOL(filemap_page_mkwrite);

const struct vm_operations_struct generic_file_vm_ops = {
	.fault		= filemap_fault,
	.page_mkwrite	= filemap_page_mkwrite,
};

/* This is used for a general mmap of a disk file */

int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct address_space *mapping = file->f_mapping;

	if (!mapping->a_ops->readpage)
		return -ENOEXEC;
	file_accessed(file);
	vma->vm_ops = &generic_file_vm_ops;
	return 0;
}

/*
 * This is for filesystems which do not implement ->writepage.
 */
int generic_file_readonly_mmap(struct file *file, struct vm_area_struct *vma)
{
	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE))
		return -EINVAL;
	return generic_file_mmap(file, vma);
}
#else
int generic_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	return -ENOSYS;
}
int generic_file_readonly_mmap(struct file * file, struct vm_area_struct * vma)
{
	return -ENOSYS;
}
#endif /* CONFIG_MMU */

EXPORT_SYMBOL(generic_file_mmap);
EXPORT_SYMBOL(generic_file_readonly_mmap);

static struct page *__read_cache_page(struct address_space *mapping,
				pgoff_t index,
				int (*filler)(void *, struct page *),
				void *data,
				gfp_t gfp)
{
	struct page *page;
	int err;
repeat:
	page = find_get_page(mapping, index);
	if (!page) {
		page = __page_cache_alloc(gfp | __GFP_COLD);
		if (!page)
			return ERR_PTR(-ENOMEM);
		err = add_to_page_cache_lru(page, mapping, index, gfp);
		if (unlikely(err)) {
			page_cache_release(page);
			if (err == -EEXIST)
				goto repeat;
			/* Presumably ENOMEM for radix tree node */
			return ERR_PTR(err);
		}
		err = filler(data, page);
		if (err < 0) {
			page_cache_release(page);
			page = ERR_PTR(err);
		}
	}
	return page;
}

static struct page *do_read_cache_page(struct address_space *mapping,
				pgoff_t index,
				int (*filler)(void *, struct page *),
				void *data,
				gfp_t gfp)

{
	struct page *page;
	int err;

retry:
	page = __read_cache_page(mapping, index, filler, data, gfp);
	if (IS_ERR(page))
		return page;
	if (PageUptodate(page))
		goto out;

	lock_page(page);
	if (!page->mapping) {
		unlock_page(page);
		page_cache_release(page);
		goto retry;
	}
	if (PageUptodate(page)) {
		unlock_page(page);
		goto out;
	}
	err = filler(data, page);
	if (err < 0) {
		page_cache_release(page);
		return ERR_PTR(err);
	}
out:
	mark_page_accessed(page);
	return page;
}

/**
 * read_cache_page_async - read into page cache, fill it if needed
 * @mapping:	the page's address_space
 * @index:	the page index
 * @filler:	function to perform the read
 * @data:	first arg to filler(data, page) function, often left as NULL
 *
 * Same as read_cache_page, but don't wait for page to become unlocked
 * after submitting it to the filler.
 *
 * Read into the page cache. If a page already exists, and PageUptodate() is
 * not set, try to fill the page but don't wait for it to become unlocked.
 *
 * If the page does not get brought uptodate, return -EIO.
 */
struct page *read_cache_page_async(struct address_space *mapping,
				pgoff_t index,
				int (*filler)(void *, struct page *),
				void *data)
{
	return do_read_cache_page(mapping, index, filler, data, mapping_gfp_mask(mapping));
}
EXPORT_SYMBOL(read_cache_page_async);

static struct page *wait_on_page_read(struct page *page)
{
	if (!IS_ERR(page)) {
		wait_on_page_locked(page);
		if (!PageUptodate(page)) {
			page_cache_release(page);
			page = ERR_PTR(-EIO);
		}
	}
	return page;
}

/**
 * read_cache_page_gfp - read into page cache, using specified page allocation flags.
 * @mapping:	the page's address_space
 * @index:	the page index
 * @gfp:	the page allocator flags to use if allocating
 *
 * This is the same as "read_mapping_page(mapping, index, NULL)", but with
 * any new page allocations done using the specified allocation flags.
 *
 * If the page does not get brought uptodate, return -EIO.
 */
struct page *read_cache_page_gfp(struct address_space *mapping,
				pgoff_t index,
				gfp_t gfp)
{
	filler_t *filler = (filler_t *)mapping->a_ops->readpage;

	return wait_on_page_read(do_read_cache_page(mapping, index, filler, NULL, gfp));
}
EXPORT_SYMBOL(read_cache_page_gfp);

/**
 * read_cache_page - read into page cache, fill it if needed
 * @mapping:	the page's address_space
 * @index:	the page index
 * @filler:	function to perform the read
 * @data:	first arg to filler(data, page) function, often left as NULL
 *
 * Read into the page cache. If a page already exists, and PageUptodate() is
 * not set, try to fill the page then wait for it to become unlocked.
 *
 * If the page does not get brought uptodate, return -EIO.
 */
struct page *read_cache_page(struct address_space *mapping,
				pgoff_t index,
				int (*filler)(void *, struct page *),
				void *data)
{
	return wait_on_page_read(read_cache_page_async(mapping, index, filler, data));
}
EXPORT_SYMBOL(read_cache_page);

/*
 * Performs necessary checks before doing a write
 *
 * Can adjust writing position or amount of bytes to write.
 * Returns appropriate error code that caller should return or
 * zero in case that write should be allowed.
 */
inline int generic_write_checks(struct file *file, loff_t *pos, size_t *count, int isblk)
{
	struct inode *inode = file->f_mapping->host;
	unsigned long limit = rlimit(RLIMIT_FSIZE);

        if (unlikely(*pos < 0))
                return -EINVAL;

	if (!isblk) {
		/* FIXME: this is for backwards compatibility with 2.4 */
		if (file->f_flags & O_APPEND)
                        *pos = i_size_read(inode);

		if (limit != RLIM_INFINITY) {
			if (*pos >= limit) {
				send_sig(SIGXFSZ, current, 0);
				return -EFBIG;
			}
			if (*count > limit - (typeof(limit))*pos) {
				*count = limit - (typeof(limit))*pos;
			}
		}
	}

	/*
	 * LFS rule
	 */
	if (unlikely(*pos + *count > MAX_NON_LFS &&
				!(file->f_flags & O_LARGEFILE))) {
		if (*pos >= MAX_NON_LFS) {
			return -EFBIG;
		}
		if (*count > MAX_NON_LFS - (unsigned long)*pos) {
			*count = MAX_NON_LFS - (unsigned long)*pos;
		}
	}

	/*
	 * Are we about to exceed the fs block limit ?
	 *
	 * If we have written data it becomes a short write.  If we have
	 * exceeded without writing data we send a signal and return EFBIG.
	 * Linus frestrict idea will clean these up nicely..
	 */
	if (likely(!isblk)) {
		if (unlikely(*pos >= inode->i_sb->s_maxbytes)) {
			if (*count || *pos > inode->i_sb->s_maxbytes) {
				return -EFBIG;
			}
			/* zero-length writes at ->s_maxbytes are OK */
		}

		if (unlikely(*pos + *count > inode->i_sb->s_maxbytes))
			*count = inode->i_sb->s_maxbytes - *pos;
	} else {
#ifdef CONFIG_BLOCK
		loff_t isize;
		if (bdev_read_only(I_BDEV(inode)))
			return -EPERM;
		isize = i_size_read(inode);
		if (*pos >= isize) {
			if (*count || *pos > isize)
				return -ENOSPC;
		}

		if (*pos + *count > isize)
			*count = isize - *pos;
#else
		return -EPERM;
#endif
	}
	return 0;
}
EXPORT_SYMBOL(generic_write_checks);

int pagecache_write_begin(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata)
{
	const struct address_space_operations *aops = mapping->a_ops;

	return aops->write_begin(file, mapping, pos, len, flags,
							pagep, fsdata);
}
EXPORT_SYMBOL(pagecache_write_begin);

int pagecache_write_end(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata)
{
	const struct address_space_operations *aops = mapping->a_ops;

	mark_page_accessed(page);
	return aops->write_end(file, mapping, pos, len, copied, page, fsdata);
}
EXPORT_SYMBOL(pagecache_write_end);

ssize_t
generic_file_direct_write_iter(struct kiocb *iocb, struct iov_iter *iter,
		loff_t pos, loff_t *ppos, size_t count)
{
	struct file	*file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode	*inode = mapping->host;
	ssize_t		written;
	size_t		write_len;
	pgoff_t		end;

	if (count != iov_iter_count(iter)) {
		written = iov_iter_shorten(iter, count);
		if (written)
			goto out;
	}

	write_len = count;
	end = (pos + write_len - 1) >> PAGE_CACHE_SHIFT;

	written = filemap_write_and_wait_range(mapping, pos, pos + write_len - 1);
	if (written)
		goto out;

	/*
	 * After a write we want buffered reads to be sure to go to disk to get
	 * the new data.  We invalidate clean cached page from the region we're
	 * about to write.  We do this *before* the write so that we can return
	 * without clobbering -EIOCBQUEUED from ->direct_IO().
	 */
	written = invalidate_inode_pages2_range(mapping,
						pos >> PAGE_CACHE_SHIFT, end);
	/*
	 * If a page can not be invalidated, return 0 to fall back
	 * to buffered write.
	 */
	if (written) {
		if (written == -EBUSY)
			return 0;
		goto out;
	}

	written = mapping_direct_IO(mapping, WRITE, iocb, iter, pos);

	/*
	 * Finally, try again to invalidate clean pages which might have been
	 * cached by non-direct readahead, or faulted in by get_user_pages()
	 * if the source of the write was an mmap'ed region of the file
	 * we're writing.  Either one is a pretty crazy thing to do,
	 * so we don't support it 100%.  If this invalidation
	 * fails, tough, the write still worked...
	 */
	invalidate_inode_pages2_range(mapping,
				pos >> PAGE_CACHE_SHIFT, end);

	if (written > 0) {
		pos += written;
		if (pos > i_size_read(inode) && !S_ISBLK(inode->i_mode)) {
			i_size_write(inode, pos);
			mark_inode_dirty(inode);
		}
		*ppos = pos;
	}
out:
	return written;
}
EXPORT_SYMBOL(generic_file_direct_write_iter);

ssize_t
generic_file_direct_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long *nr_segs, loff_t pos, loff_t *ppos,
		size_t count, size_t ocount)
{
	struct iov_iter iter;
	ssize_t ret;

	iov_iter_init(&iter, iov, *nr_segs, ocount, 0);
	ret = generic_file_direct_write_iter(iocb, &iter, pos, ppos, count);
	/* generic_file_direct_write_iter() might have shortened the vec */
	if (*nr_segs != iter.nr_segs)
		*nr_segs = iter.nr_segs;
	return ret;
}
EXPORT_SYMBOL(generic_file_direct_write);

/*
 * Find or create a page at the given pagecache position. Return the locked
 * page. This function is specifically for buffered writes.
 */
struct page *grab_cache_page_write_begin(struct address_space *mapping,
					pgoff_t index, unsigned flags)
{
	int status;
	gfp_t gfp_mask;
	struct page *page;
	gfp_t gfp_notmask = 0;

	gfp_mask = mapping_gfp_mask(mapping);
	if (mapping_cap_account_dirty(mapping))
		gfp_mask |= __GFP_WRITE;
	if (flags & AOP_FLAG_NOFS)
		gfp_notmask = __GFP_FS;
repeat:
	page = find_lock_page(mapping, index);
	if (page)
		goto found;

	page = __page_cache_alloc(gfp_mask & ~gfp_notmask);
	if (!page)
		return NULL;
	status = add_to_page_cache_lru(page, mapping, index,
						gfp_mask & ~gfp_notmask);
	if (unlikely(status)) {
		page_cache_release(page);
		if (status == -EEXIST)
			goto repeat;
		return NULL;
	}
found:
	wait_for_stable_page(page);
	return page;
}
EXPORT_SYMBOL(grab_cache_page_write_begin);

static ssize_t generic_perform_write(struct file *file,
				struct iov_iter *i, loff_t pos)
{
	struct address_space *mapping = file->f_mapping;
	const struct address_space_operations *a_ops = mapping->a_ops;
	long status = 0;
	ssize_t written = 0;
	unsigned int flags = 0;

	/*
	 * Copies from kernel address space cannot fail (NFSD is a big user).
	 */
	if (segment_eq(get_fs(), KERNEL_DS))
		flags |= AOP_FLAG_UNINTERRUPTIBLE;

	do {
		struct page *page;
		unsigned long offset;	/* Offset into pagecache page */
		unsigned long bytes;	/* Bytes to write to page */
		size_t copied;		/* Bytes copied from user */
		void *fsdata;

		offset = (pos & (PAGE_CACHE_SIZE - 1));
		bytes = min_t(unsigned long, PAGE_CACHE_SIZE - offset,
						iov_iter_count(i));

again:
		/*
		 * Bring in the user page that we will copy from _first_.
		 * Otherwise there's a nasty deadlock on copying from the
		 * same page as we're writing to, without it being marked
		 * up-to-date.
		 *
		 * Not only is this an optimisation, but it is also required
		 * to check that the address is actually valid, when atomic
		 * usercopies are used, below.
		 */
		if (unlikely(iov_iter_fault_in_readable(i, bytes))) {
			status = -EFAULT;
			break;
		}

		status = a_ops->write_begin(file, mapping, pos, bytes, flags,
						&page, &fsdata);
		if (unlikely(status))
			break;

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		copied = iov_iter_copy_from_user_atomic(page, i, offset, bytes);
		flush_dcache_page(page);

		mark_page_accessed(page);
		status = a_ops->write_end(file, mapping, pos, bytes, copied,
						page, fsdata);
		if (unlikely(status < 0))
			break;
		copied = status;

		cond_resched();

		iov_iter_advance(i, copied);
		if (unlikely(copied == 0)) {
			/*
			 * If we were unable to copy any data at all, we must
			 * fall back to a single segment length write.
			 *
			 * If we didn't fallback here, we could livelock
			 * because not all segments in the iov can be copied at
			 * once without a pagefault.
			 */
			bytes = min_t(unsigned long, PAGE_CACHE_SIZE - offset,
						iov_iter_single_seg_count(i));
			goto again;
		}
		pos += copied;
		written += copied;

		balance_dirty_pages_ratelimited(mapping);
		if (fatal_signal_pending(current)) {
			status = -EINTR;
			break;
		}
	} while (iov_iter_count(i));

	return written ? written : status;
}

ssize_t
generic_file_buffered_write_iter(struct kiocb *iocb, struct iov_iter *iter,
		loff_t pos, loff_t *ppos, ssize_t written)
{
	struct file *file = iocb->ki_filp;
	ssize_t status;

	virtinfo_notifier_call(VITYPE_IO, VIRTINFO_IO_PREPARE, NULL);

	status = generic_perform_write(file, iter, pos);

	if (likely(status >= 0)) {
		written += status;
		*ppos = pos + status;
  	}
	
	return written ? written : status;
}
EXPORT_SYMBOL(generic_file_buffered_write_iter);

ssize_t
generic_file_buffered_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos, loff_t *ppos,
		size_t count, ssize_t written)
{
	struct iov_iter iter;
	iov_iter_init(&iter, iov, nr_segs, count, written);
	return generic_file_buffered_write_iter(iocb, &iter, pos, ppos,
						written);
}
EXPORT_SYMBOL(generic_file_buffered_write);

/**
 * __generic_file_aio_write - write data to a file
 * @iocb:	IO state structure (file, offset, etc.)
 * @iter:	iov_iter specifying memory to write
 * @ppos:	position where to write
 *
 * This function does all the work needed for actually writing data to a
 * file. It does all basic checks, removes SUID from the file, updates
 * modification times and calls proper subroutines depending on whether we
 * do direct IO or a standard buffered write.
 *
 * It expects i_mutex to be grabbed unless we work on a block device or similar
 * object which does not need locking at all.
 *
 * This function does *not* take care of syncing data in case of O_SYNC write.
 * A caller has to handle it. This is mainly due to the fact that we want to
 * avoid syncing under i_mutex.
 */
ssize_t __generic_file_write_iter(struct kiocb *iocb, struct iov_iter *iter,
				  loff_t *ppos)
{
	struct file *file = iocb->ki_filp;
	struct address_space * mapping = file->f_mapping;
	size_t count;		/* after file limit checks */
	struct inode 	*inode = mapping->host;
	loff_t		pos;
	ssize_t		written;
	ssize_t		err;

	count = iov_iter_count(iter);
	pos = *ppos;

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = mapping->backing_dev_info;
	written = 0;

	err = generic_write_checks(file, &pos, &count, S_ISBLK(inode->i_mode));
	if (err)
		goto out;

	if (count == 0)
		goto out;

	err = file_remove_privs(file);
	if (err)
		goto out;

	err = file_update_time(file);
	if (err)
		goto out;

	if (io_is_direct(file)) {
		loff_t endbyte;
		ssize_t written_buffered;

		written = generic_file_direct_write_iter(iocb, iter, pos,
							 ppos, count);
		/*
		 * If the write stopped short of completing, fall back to
		 * buffered writes.  Some filesystems do this for writes to
		 * holes, for example.  For DAX files, a buffered write will
		 * not succeed (even if it did, DAX does not handle dirty
		 * page-cache pages correctly).
		 */
		if (written < 0 || written == count || IS_DAX(inode))
			goto out;

		pos += written;
		count -= written;
		iov_iter_advance(iter, written);
		written_buffered = generic_file_buffered_write_iter(iocb, iter,
						pos, ppos, written);
		/*
		 * If generic_file_buffered_write() retuned a synchronous error
		 * then we want to return the number of bytes which were
		 * direct-written, or the error code if that was zero.  Note
		 * that this differs from normal direct-io semantics, which
		 * will return -EFOO even if some bytes were written.
		 */
		if (written_buffered < 0) {
			err = written_buffered;
			goto out;
		}

		/*
		 * We need to ensure that the page cache pages are written to
		 * disk and invalidated to preserve the expected O_DIRECT
		 * semantics.
		 */
		endbyte = pos + written_buffered - written - 1;
		err = filemap_write_and_wait_range(file->f_mapping, pos, endbyte);
		if (err == 0) {
			written = written_buffered;
			invalidate_mapping_pages(mapping,
						 pos >> PAGE_CACHE_SHIFT,
						 endbyte >> PAGE_CACHE_SHIFT);
		} else {
			/*
			 * We don't know how much we wrote, so just return
			 * the number of bytes which were direct-written
			 */
		}
	} else {
		iter->count = count;
		written = generic_file_buffered_write_iter(iocb, iter,
				pos, ppos, written);
	}
out:
	current->backing_dev_info = NULL;
	return written ? written : err;
}
EXPORT_SYMBOL(__generic_file_write_iter);

ssize_t generic_file_write_iter(struct kiocb *iocb, struct iov_iter *iter,
			        loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	mutex_lock(&inode->i_mutex);
	ret = __generic_file_write_iter(iocb, iter, &iocb->ki_pos);
	mutex_unlock(&inode->i_mutex);

	if (ret > 0 || ret == -EIOCBQUEUED) {
		ssize_t err;

		err = generic_write_sync(file, pos, ret);
		if (err < 0 && ret > 0)
			ret = err;
	}
	return ret;
}
EXPORT_SYMBOL(generic_file_write_iter);

ssize_t
__generic_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
			 unsigned long nr_segs, loff_t *ppos)
{
	struct iov_iter iter;
	size_t count;
	int ret;

	count = 0;
	ret = generic_segment_checks(iov, &nr_segs, &count, VERIFY_READ);
	if (ret)
		goto out;

	iov_iter_init(&iter, iov, nr_segs, count, 0);

	ret = __generic_file_write_iter(iocb, &iter, ppos);
out:
	return ret;
}
EXPORT_SYMBOL(__generic_file_aio_write);

/**
 * generic_file_aio_write - write data to a file
 * @iocb:	IO state structure
 * @iov:	vector with data to write
 * @nr_segs:	number of segments in the vector
 * @pos:	position in file where to write
 *
 * This is a wrapper around __generic_file_aio_write() to be used by most
 * filesystems. It takes care of syncing the file in case of O_SYNC file
 * and acquires i_mutex as needed.
 */
ssize_t generic_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	ssize_t ret;

	BUG_ON(iocb->ki_pos != pos);

	mutex_lock(&inode->i_mutex);
	ret = __generic_file_aio_write(iocb, iov, nr_segs, &iocb->ki_pos);
	mutex_unlock(&inode->i_mutex);

	if (ret > 0) {
		ssize_t err;

		err = generic_write_sync(file, pos, ret);
		if (err < 0 && ret > 0)
			ret = err;
	}
	return ret;
}
EXPORT_SYMBOL(generic_file_aio_write);

/**
 * try_to_release_page() - release old fs-specific metadata on a page
 *
 * @page: the page which the kernel is trying to free
 * @gfp_mask: memory allocation flags (and I/O mode)
 *
 * The address_space is to try to release any data against the page
 * (presumably at page->private).  If the release was successful, return `1'.
 * Otherwise return zero.
 *
 * This may also be called if PG_fscache is set on a page, indicating that the
 * page is known to the local caching routines.
 *
 * The @gfp_mask argument specifies whether I/O may be performed to release
 * this page (__GFP_IO), and whether the call may block (__GFP_WAIT & __GFP_FS).
 *
 */
int try_to_release_page(struct page *page, gfp_t gfp_mask)
{
	struct address_space * const mapping = page->mapping;

	BUG_ON(!PageLocked(page));
	if (PageWriteback(page))
		return 0;

	if (mapping && mapping->a_ops->releasepage)
		return mapping->a_ops->releasepage(page, gfp_mask);
	return try_to_free_buffers(page);
}

EXPORT_SYMBOL(try_to_release_page);
