/*
 * fs/dax.c - Direct Access filesystem code
 * Copyright (c) 2013-2014 Intel Corporation
 * Author: Matthew Wilcox <matthew.r.wilcox@intel.com>
 * Author: Ross Zwisler <ross.zwisler@linux.intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <linux/atomic.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/dax.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/highmem.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pagevec.h>
#include <linux/pmem.h>
#include <linux/sched.h>
#include <linux/uio.h>
#include <linux/socket.h>
#include <linux/vmstat.h>
#include <linux/pfn_t.h>
#include <linux/sizes.h>

/* We choose 4096 entries - same as per-zone page wait tables */
#define DAX_WAIT_TABLE_BITS 12
#define DAX_WAIT_TABLE_ENTRIES (1 << DAX_WAIT_TABLE_BITS)

static wait_queue_head_t wait_table[DAX_WAIT_TABLE_ENTRIES];

static int __init init_dax_wait_table(void)
{
	int i;

	for (i = 0; i < DAX_WAIT_TABLE_ENTRIES; i++)
		init_waitqueue_head(wait_table + i);
	return 0;
}
fs_initcall(init_dax_wait_table);

static long dax_map_atomic(struct block_device *bdev, struct blk_dax_ctl *dax)
{
	struct request_queue *q = bdev->bd_queue;
	long rc = -EIO;

	dax->addr = ERR_PTR(-EIO);
	if (blk_queue_enter(q, true) != 0)
		return rc;

	rc = bdev_direct_access(bdev, dax);
	if (rc < 0) {
		dax->addr = ERR_PTR(rc);
		blk_queue_exit(q);
		return rc;
	}
	return rc;
}

static void dax_unmap_atomic(struct block_device *bdev,
		const struct blk_dax_ctl *dax)
{
	if (IS_ERR(dax->addr))
		return;
	blk_queue_exit(bdev->bd_queue);
}

struct page *read_dax_sector(struct block_device *bdev, sector_t n)
{
	struct page *page = alloc_pages(GFP_KERNEL, 0);
	struct blk_dax_ctl dax = {
		.size = PAGE_SIZE,
		.sector = n & ~((((int) PAGE_SIZE) / 512) - 1),
	};
	long rc;

	if (!page)
		return ERR_PTR(-ENOMEM);

	rc = dax_map_atomic(bdev, &dax);
	if (rc < 0)
		return ERR_PTR(rc);
	memcpy_from_pmem(page_address(page), dax.addr, PAGE_SIZE);
	dax_unmap_atomic(bdev, &dax);
	return page;
}

static bool buffer_written(struct buffer_head *bh)
{
	return buffer_mapped(bh) && !buffer_unwritten(bh);
}

static int zero_toiovecend_partial(const struct iovec *iov, int offset, int len)
{
	int zero, orig_len = len;
	for (; len > 0; ++iov) {
		/* Skip over the finished iovecs */
		if (unlikely(offset >= iov->iov_len)) {
			offset -= iov->iov_len;
			continue;
		}
		zero = min_t(unsigned int, iov->iov_len - offset, len);
		if (clear_user(iov->iov_base + offset, zero))
			return orig_len - len;
		offset = 0;
		len -= zero;
	}

	return orig_len - len;
}


static sector_t to_sector(const struct buffer_head *bh,
		const struct inode *inode)
{
	sector_t sector = bh->b_blocknr << (inode->i_blkbits - 9);

	return sector;
}

static ssize_t dax_io(int rw, struct inode *inode, const struct iovec *iov,
			loff_t start, loff_t end, get_block_t get_block,
			struct buffer_head *bh)
{
	loff_t pos = start, max = start, bh_max = start;
	bool hole = false;
	struct block_device *bdev = NULL;
	int rc;
	long map_len = 0;
	struct blk_dax_ctl dax = {
		.addr = ERR_PTR(-EIO),
	};
	unsigned blkbits = inode->i_blkbits;
	sector_t file_blks = (i_size_read(inode) + (1 << blkbits) - 1)
								>> blkbits;

	rw &= RW_MASK;
	if (rw == READ)
		end = min(end, i_size_read(inode));

	while (pos < end) {
		size_t len;
		if (pos == max) {
			long page = pos >> PAGE_SHIFT;
			sector_t block = page << (PAGE_SHIFT - blkbits);
			unsigned first = pos - (block << blkbits);
			long size;

			if (pos == bh_max) {
				bh->b_size = PAGE_ALIGN(end - pos);
				bh->b_state = 0;
				rc = get_block(inode, block, bh, rw == WRITE);
				if (rc)
					break;
				bh_max = pos - first + bh->b_size;
				bdev = bh->b_bdev;
				/*
				 * We allow uninitialized buffers for writes
				 * beyond EOF as those cannot race with faults
				 */
				WARN_ON_ONCE(
					(buffer_new(bh) && block < file_blks) ||
					(rw == WRITE && buffer_unwritten(bh)));
			} else {
				unsigned done = bh->b_size -
						(bh_max - (pos - first));
				bh->b_blocknr += done >> blkbits;
				bh->b_size -= done;
			}

			hole = (rw == READ) && !buffer_written(bh);
			if (hole) {
				size = bh->b_size - first;
			} else {
				dax_unmap_atomic(bdev, &dax);
				dax.sector = to_sector(bh, inode);
				dax.size = bh->b_size;
				map_len = dax_map_atomic(bdev, &dax);
				if (map_len < 0) {
					rc = map_len;
					break;
				}
				dax.addr += first;
				size = map_len - first;
			}
			/*
			 * pos + size is one past the last offset for IO,
			 * so pos + size can overflow loff_t at extreme offsets.
			 * Cast to u64 to catch this and get the true minimum.
			 */
			max = min_t(u64, pos + size, end);
		}

		if (rw == WRITE)
			len = memcpy_fromiovecend_partial_nocache(
				(void __force *)dax.addr, iov, pos - start,
				max - pos);
		else if (!hole)
			len = memcpy_toiovecend_partial(iov,
				(void __force *)dax.addr, pos - start,
				max - pos);
		else
			len = zero_toiovecend_partial(iov, pos - start,
				max - pos);

		if (!len) {
			rc = -EFAULT;
			break;
		}

		pos += len;
		if (!IS_ERR(dax.addr))
			dax.addr += len;
	}

	dax_unmap_atomic(bdev, &dax);

	return (pos == start) ? rc : pos - start;
}

/**
 * dax_do_io - Perform I/O to a DAX file
 * @rw: READ to read or WRITE to write
 * @iocb: The control block for this I/O
 * @inode: The file which the I/O is directed at
 * @iter: The addresses to do I/O from or to
 * @pos: The file offset where the I/O starts
 * @get_block: The filesystem method used to translate file offsets to blocks
 * @end_io: A filesystem callback for I/O completion
 * @flags: See below
 *
 * This function uses the same locking scheme as do_blockdev_direct_IO:
 * If @flags has DIO_LOCKING set, we assume that the i_mutex is held by the
 * caller for writes.  For reads, we take and release the i_mutex ourselves.
 * If DIO_LOCKING is not set, the filesystem takes care of its own locking.
 * As with do_blockdev_direct_IO(), we increment i_dio_count while the I/O
 * is in progress.
 */
ssize_t dax_do_io(int rw, struct kiocb *iocb, struct inode *inode,
		  const struct iovec *iov, loff_t pos, unsigned long nr_segs,
		  get_block_t get_block, dio_iodone_t end_io, int flags)
{
	struct buffer_head bh;
	ssize_t retval = -EINVAL;
	loff_t end = pos + iov_length(iov, nr_segs);

	memset(&bh, 0, sizeof(bh));
	bh.b_bdev = inode->i_sb->s_bdev;

	if ((flags & DIO_LOCKING) && (rw == READ))
		mutex_lock(&inode->i_mutex);

	/* Protects against truncate */
	if (!(flags & DIO_SKIP_DIO_COUNT))
		inode_dio_begin(inode);

	retval = dax_io(rw, inode, iov, pos, end, get_block, &bh);

	if ((flags & DIO_LOCKING) && (rw == READ))
		mutex_unlock(&inode->i_mutex);

	if ((retval > 0) && end_io)
		end_io(iocb, pos, retval, bh.b_private, retval, false);

	if (!(flags & DIO_SKIP_DIO_COUNT))
		inode_dio_end(inode);
	return retval;
}
EXPORT_SYMBOL_GPL(dax_do_io);

/*
 * DAX radix tree locking
 */
struct exceptional_entry_key {
	struct address_space *mapping;
	pgoff_t entry_start;
};

struct wait_exceptional_entry_queue {
	wait_queue_t wait;
	struct exceptional_entry_key key;
};

static wait_queue_head_t *dax_entry_waitqueue(struct address_space *mapping,
		pgoff_t index, void *entry, struct exceptional_entry_key *key)
{
	unsigned long hash;

	/*
	 * If 'entry' is a PMD, align the 'index' that we use for the wait
	 * queue to the start of that PMD.  This ensures that all offsets in
	 * the range covered by the PMD map to the same bit lock.
	 */
	if (RADIX_DAX_TYPE(entry) == RADIX_DAX_PMD)
		index &= ~((1UL << (PMD_SHIFT - PAGE_SHIFT)) - 1);

	key->mapping = mapping;
	key->entry_start = index;

	hash = hash_long((unsigned long)mapping ^ index, DAX_WAIT_TABLE_BITS);
	return wait_table + hash;
}

static int wake_exceptional_entry_func(wait_queue_t *wait, unsigned int mode,
				       int sync, void *keyp)
{
	struct exceptional_entry_key *key = keyp;
	struct wait_exceptional_entry_queue *ewait =
		container_of(wait, struct wait_exceptional_entry_queue, wait);

	if (key->mapping != ewait->key.mapping ||
	    key->entry_start != ewait->key.entry_start)
		return 0;
	return autoremove_wake_function(wait, mode, sync, NULL);
}

/*
 * Check whether the given slot is locked. The function must be called with
 * mapping->tree_lock held
 */
static inline int slot_locked(struct address_space *mapping, void **slot)
{
	unsigned long entry = (unsigned long)
		radix_tree_deref_slot_protected(slot, &mapping->tree_lock);
	return entry & RADIX_DAX_ENTRY_LOCK;
}

/*
 * Mark the given slot is locked. The function must be called with
 * mapping->tree_lock held
 */
static inline void *lock_slot(struct address_space *mapping, void **slot)
{
	unsigned long entry = (unsigned long)
		radix_tree_deref_slot_protected(slot, &mapping->tree_lock);

	entry |= RADIX_DAX_ENTRY_LOCK;
	radix_tree_replace_slot(slot, (void *)entry);
	return (void *)entry;
}

/*
 * Mark the given slot is unlocked. The function must be called with
 * mapping->tree_lock held
 */
static inline void *unlock_slot(struct address_space *mapping, void **slot)
{
	unsigned long entry = (unsigned long)
		radix_tree_deref_slot_protected(slot, &mapping->tree_lock);

	entry &= ~(unsigned long)RADIX_DAX_ENTRY_LOCK;
	radix_tree_replace_slot(slot, (void *)entry);
	return (void *)entry;
}

/*
 * Lookup entry in radix tree, wait for it to become unlocked if it is
 * exceptional entry and return it. The caller must call
 * put_unlocked_mapping_entry() when he decided not to lock the entry or
 * put_locked_mapping_entry() when he locked the entry and now wants to
 * unlock it.
 *
 * The function must be called with mapping->tree_lock held.
 */
static void *get_unlocked_mapping_entry(struct address_space *mapping,
					pgoff_t index, void ***slotp)
{
	void *entry, **slot;
	struct wait_exceptional_entry_queue ewait;
	wait_queue_head_t *wq;

	init_wait(&ewait.wait);
	ewait.wait.func = wake_exceptional_entry_func;

	for (;;) {
		entry = __radix_tree_lookup(&mapping->page_tree, index, NULL,
					  &slot);
		if (!entry || !radix_tree_exceptional_entry(entry) ||
		    !slot_locked(mapping, slot)) {
			if (slotp)
				*slotp = slot;
			return entry;
		}

		wq = dax_entry_waitqueue(mapping, index, entry, &ewait.key);
		prepare_to_wait_exclusive(wq, &ewait.wait,
					  TASK_UNINTERRUPTIBLE);
		spin_unlock_irq(&mapping->tree_lock);
		schedule();
		finish_wait(wq, &ewait.wait);
		spin_lock_irq(&mapping->tree_lock);
	}
}

static void put_locked_mapping_entry(struct address_space *mapping,
				     pgoff_t index, void *entry)
{
	if (!radix_tree_exceptional_entry(entry)) {
		unlock_page(entry);
		page_cache_release(entry);
	} else {
		dax_unlock_mapping_entry(mapping, index);
	}
}

/*
 * Called when we are done with radix tree entry we looked up via
 * get_unlocked_mapping_entry() and which we didn't lock in the end.
 */
static void put_unlocked_mapping_entry(struct address_space *mapping,
				       pgoff_t index, void *entry)
{
	if (!radix_tree_exceptional_entry(entry))
		return;

	/* We have to wake up next waiter for the radix tree entry lock */
	dax_wake_mapping_entry_waiter(mapping, index, entry, false);
}

/*
 * Find radix tree entry at given index. If it points to a page, return with
 * the page locked. If it points to the exceptional entry, return with the
 * radix tree entry locked. If the radix tree doesn't contain given index,
 * create empty exceptional entry for the index and return with it locked.
 *
 * Note: Unlike filemap_fault() we don't honor FAULT_FLAG_RETRY flags. For
 * persistent memory the benefit is doubtful. We can add that later if we can
 * show it helps.
 */
static void *grab_mapping_entry(struct address_space *mapping, pgoff_t index)
{
	void *entry, **slot;

restart:
	spin_lock_irq(&mapping->tree_lock);
	entry = get_unlocked_mapping_entry(mapping, index, &slot);
	/* No entry for given index? Make sure radix tree is big enough. */
	if (!entry) {
		int err;

		spin_unlock_irq(&mapping->tree_lock);
		err = radix_tree_preload(
				mapping_gfp_mask(mapping) & ~__GFP_HIGHMEM);
		if (err)
			return ERR_PTR(err);
		entry = (void *)(RADIX_TREE_EXCEPTIONAL_ENTRY |
			       RADIX_DAX_ENTRY_LOCK);
		spin_lock_irq(&mapping->tree_lock);
		err = radix_tree_insert(&mapping->page_tree, index, entry);
		radix_tree_preload_end();
		if (err) {
			spin_unlock_irq(&mapping->tree_lock);
			/* Someone already created the entry? */
			if (err == -EEXIST)
				goto restart;
			return ERR_PTR(err);
		}
		/* Good, we have inserted empty locked entry into the tree. */
		mapping->nrexceptional++;
		spin_unlock_irq(&mapping->tree_lock);
		return entry;
	}
	/* Normal page in radix tree? */
	if (!radix_tree_exceptional_entry(entry)) {
		struct page *page = entry;

		get_page(page);
		spin_unlock_irq(&mapping->tree_lock);
		lock_page(page);
		/* Page got truncated? Retry... */
		if (unlikely(page->mapping != mapping)) {
			unlock_page(page);
			page_cache_release(page);
			goto restart;
		}
		return page;
	}
	entry = lock_slot(mapping, slot);
	spin_unlock_irq(&mapping->tree_lock);
	return entry;
}

/*
 * We do not necessarily hold the mapping->tree_lock when we call this
 * function so it is possible that 'entry' is no longer a valid item in the
 * radix tree.  This is okay, though, because all we really need to do is to
 * find the correct waitqueue where tasks might be sleeping waiting for that
 * old 'entry' and wake them.
 */
void dax_wake_mapping_entry_waiter(struct address_space *mapping,
		pgoff_t index, void *entry, bool wake_all)
{
	struct exceptional_entry_key key;
	wait_queue_head_t *wq;

	wq = dax_entry_waitqueue(mapping, index, entry, &key);

	/*
	 * Checking for locked entry and prepare_to_wait_exclusive() happens
	 * under mapping->tree_lock, ditto for entry handling in our callers.
	 * So at this point all tasks that could have seen our entry locked
	 * must be in the waitqueue and the following check will see them.
	 */
	if (waitqueue_active(wq))
		__wake_up(wq, TASK_NORMAL, wake_all ? 0 : 1, &key);
}

void dax_unlock_mapping_entry(struct address_space *mapping, pgoff_t index)
{
	void *entry, **slot;

	spin_lock_irq(&mapping->tree_lock);
	entry = __radix_tree_lookup(&mapping->page_tree, index, NULL, &slot);
	if (WARN_ON_ONCE(!entry || !radix_tree_exceptional_entry(entry) ||
			 !slot_locked(mapping, slot))) {
		spin_unlock_irq(&mapping->tree_lock);
		return;
	}
	unlock_slot(mapping, slot);
	spin_unlock_irq(&mapping->tree_lock);
	dax_wake_mapping_entry_waiter(mapping, index, entry, false);
}

/*
 * Delete exceptional DAX entry at @index from @mapping. Wait for radix tree
 * entry to get unlocked before deleting it.
 */
int dax_delete_mapping_entry(struct address_space *mapping, pgoff_t index)
{
	void *entry;

	spin_lock_irq(&mapping->tree_lock);
	entry = get_unlocked_mapping_entry(mapping, index, NULL);
	/*
	 * This gets called from truncate / punch_hole path. As such, the caller
	 * must hold locks protecting against concurrent modifications of the
	 * radix tree (usually fs-private i_mmap_sem for writing). Since the
	 * caller has seen exceptional entry for this index, we better find it
	 * at that index as well...
	 */
	if (WARN_ON_ONCE(!entry || !radix_tree_exceptional_entry(entry))) {
		spin_unlock_irq(&mapping->tree_lock);
		return 0;
	}
	radix_tree_delete(&mapping->page_tree, index);
	mapping->nrexceptional--;
	spin_unlock_irq(&mapping->tree_lock);
	dax_wake_mapping_entry_waiter(mapping, index, entry, true);

	return 1;
}

/*
 * The user has performed a load from a hole in the file.  Allocating
 * a new page in the file would cause excessive storage usage for
 * workloads with sparse files.  We allocate a page cache page instead.
 * We'll kick it out of the page cache if it's ever written to,
 * otherwise it will simply fall out of the page cache under memory
 * pressure without ever having been dirtied.
 */
static int dax_load_hole(struct address_space *mapping, void *entry,
			 struct vm_fault *vmf)
{
	struct page *page;

	/* Hole page already exists? Return it...  */
	if (!radix_tree_exceptional_entry(entry)) {
		vmf->page = entry;
		return VM_FAULT_LOCKED;
	}

	/* This will replace locked radix tree entry with a hole page */
	page = find_or_create_page(mapping, vmf->pgoff,
		mapping_gfp_mask(mapping) | __GFP_FS | __GFP_IO | __GFP_ZERO);
	if (!page) {
		put_locked_mapping_entry(mapping, vmf->pgoff, entry);
		return VM_FAULT_OOM;
	}
	vmf->page = page;
	return VM_FAULT_LOCKED;
}

static int copy_user_dax(struct block_device *bdev, sector_t sector, size_t size,
		struct page *to, unsigned long vaddr)
{
	struct blk_dax_ctl dax = {
		.sector = sector,
		.size = size,
	};
	void *vto;

	if (dax_map_atomic(bdev, &dax) < 0)
		return PTR_ERR(dax.addr);
	vto = kmap_atomic(to);
	copy_user_page(vto, (void __force *)dax.addr, vaddr, to);
	kunmap_atomic(vto);
	dax_unmap_atomic(bdev, &dax);
	return 0;
}

#define DAX_PMD_INDEX(page_index) (page_index & (PMD_MASK >> PAGE_CACHE_SHIFT))

static void *dax_insert_mapping_entry(struct address_space *mapping,
				      struct vm_fault *vmf,
				      void *entry, sector_t sector)
{
	struct radix_tree_root *page_tree = &mapping->page_tree;
	int error = 0;
	bool hole_fill = false;
	void *new_entry;
	pgoff_t index = vmf->pgoff;

	if (vmf->flags & FAULT_FLAG_WRITE)
		__mark_inode_dirty(mapping->host, I_DIRTY_PAGES);

	/* Replacing hole page with block mapping? */
	if (!radix_tree_exceptional_entry(entry)) {
		hole_fill = true;
		/*
		 * Unmap the page now before we remove it from page cache below.
		 * The page is locked so it cannot be faulted in again.
		 */
		unmap_mapping_range(mapping, vmf->pgoff << PAGE_SHIFT,
				    PAGE_SIZE, 0);
		error = radix_tree_preload(mapping_gfp_mask(mapping) & ~__GFP_HIGHMEM);
		if (error)
			return ERR_PTR(error);

	}

	spin_lock_irq(&mapping->tree_lock);
	new_entry = (void *)((unsigned long)RADIX_DAX_ENTRY(sector, false) |
		       RADIX_DAX_ENTRY_LOCK);
	if (hole_fill) {
		__delete_from_page_cache(entry, NULL);
		mem_cgroup_uncharge_page(entry);
		/* Drop pagecache reference */
		page_cache_release(entry);
		error = radix_tree_insert(page_tree, index, new_entry);
		if (error) {
			new_entry = ERR_PTR(error);
			goto unlock;
		}
		mapping->nrexceptional++;
	} else {
		void **slot;
		void *ret;

		ret = __radix_tree_lookup(page_tree, index, NULL, &slot);
		WARN_ON_ONCE(ret != entry);
		radix_tree_replace_slot(slot, new_entry);
	}
	if (vmf->flags & FAULT_FLAG_WRITE)
		radix_tree_tag_set(page_tree, index, PAGECACHE_TAG_DIRTY);
 unlock:
	spin_unlock_irq(&mapping->tree_lock);
	if (hole_fill) {
		radix_tree_preload_end();
		/*
		 * We don't need hole page anymore, it has been replaced with
		 * locked radix tree entry now.
		 */
		if (mapping->a_ops->freepage)
			mapping->a_ops->freepage(entry);
		unlock_page(entry);
		page_cache_release(entry);
	}
	return new_entry;

}

static int dax_writeback_one(struct block_device *bdev,
		struct address_space *mapping, pgoff_t index, void *entry)
{
	struct radix_tree_root *page_tree = &mapping->page_tree;
	int type = RADIX_DAX_TYPE(entry);
	struct radix_tree_node *node;
	struct blk_dax_ctl dax;
	void **slot;
	int ret = 0;

	spin_lock_irq(&mapping->tree_lock);
	/*
	 * Regular page slots are stabilized by the page lock even
	 * without the tree itself locked.  These unlocked entries
	 * need verification under the tree lock.
	 */
	if (!__radix_tree_lookup(page_tree, index, &node, &slot))
		goto unlock;
	if (*slot != entry)
		goto unlock;

	/* another fsync thread may have already written back this entry */
	if (!radix_tree_tag_get(page_tree, index, PAGECACHE_TAG_TOWRITE))
		goto unlock;

	if (WARN_ON_ONCE(type != RADIX_DAX_PTE && type != RADIX_DAX_PMD)) {
		ret = -EIO;
		goto unlock;
	}

	dax.sector = RADIX_DAX_SECTOR(entry);
	dax.size = (type == RADIX_DAX_PMD ? PMD_SIZE : PAGE_SIZE);
	spin_unlock_irq(&mapping->tree_lock);

	/*
	 * We cannot hold tree_lock while calling dax_map_atomic() because it
	 * eventually calls cond_resched().
	 */
	ret = dax_map_atomic(bdev, &dax);
	if (ret < 0)
		return ret;

	if (WARN_ON_ONCE(ret < dax.size)) {
		ret = -EIO;
		goto unmap;
	}

	wb_cache_pmem(dax.addr, dax.size);

	spin_lock_irq(&mapping->tree_lock);
	radix_tree_tag_clear(page_tree, index, PAGECACHE_TAG_TOWRITE);
	spin_unlock_irq(&mapping->tree_lock);
 unmap:
	dax_unmap_atomic(bdev, &dax);
	return ret;

 unlock:
	spin_unlock_irq(&mapping->tree_lock);
	return ret;
}

/*
 * Flush the mapping to the persistent domain within the byte range of [start,
 * end]. This is required by data integrity operations to ensure file data is
 * on persistent storage prior to completion of the operation.
 */
int dax_writeback_mapping_range(struct address_space *mapping,
		struct block_device *bdev, struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	pgoff_t start_index, end_index, pmd_index;
	pgoff_t indices[PAGEVEC_SIZE];
	struct pagevec pvec;
	bool done = false;
	int i, ret = 0;
	void *entry;

	if (WARN_ON_ONCE(inode->i_blkbits != PAGE_SHIFT))
		return -EIO;

	if (!mapping->nrexceptional || wbc->sync_mode != WB_SYNC_ALL)
		return 0;

	start_index = wbc->range_start >> PAGE_CACHE_SHIFT;
	end_index = wbc->range_end >> PAGE_CACHE_SHIFT;
	pmd_index = DAX_PMD_INDEX(start_index);

	rcu_read_lock();
	entry = radix_tree_lookup(&mapping->page_tree, pmd_index);
	rcu_read_unlock();

	/* see if the start of our range is covered by a PMD entry */
	if (entry && RADIX_DAX_TYPE(entry) == RADIX_DAX_PMD)
		start_index = pmd_index;

	tag_pages_for_writeback(mapping, start_index, end_index);

	pagevec_init(&pvec, 0);
	while (!done) {
		pvec.nr = find_get_entries_tag(mapping, start_index,
				PAGECACHE_TAG_TOWRITE, PAGEVEC_SIZE,
				pvec.pages, indices);

		if (pvec.nr == 0)
			break;

		for (i = 0; i < pvec.nr; i++) {
			if (indices[i] > end_index) {
				done = true;
				break;
			}

			ret = dax_writeback_one(bdev, mapping, indices[i],
					pvec.pages[i]);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}
EXPORT_SYMBOL_GPL(dax_writeback_mapping_range);

static int dax_insert_mapping(struct address_space *mapping,
		struct block_device *bdev, sector_t sector, size_t size,
		void **entryp, struct vm_area_struct *vma, struct vm_fault *vmf)
{
	unsigned long vaddr = (unsigned long)vmf->virtual_address;
	struct blk_dax_ctl dax = {
		.sector = sector,
		.size = size,
	};
	void *ret;
	void *entry = *entryp;

	if (dax_map_atomic(bdev, &dax) < 0)
		return PTR_ERR(dax.addr);
	dax_unmap_atomic(bdev, &dax);

	ret = dax_insert_mapping_entry(mapping, vmf, entry, dax.sector);
	if (IS_ERR(ret))
		return PTR_ERR(ret);
	*entryp = ret;

	return vm_insert_mixed(vma, vaddr, dax.pfn);
}

/**
 * dax_fault - handle a page fault on a DAX file
 * @vma: The virtual memory area where the fault occurred
 * @vmf: The description of the fault
 * @get_block: The filesystem method used to translate file offsets to blocks
 *
 * When a page fault occurs, filesystems may call this helper in their
 * fault handler for DAX files. dax_fault() assumes the caller has done all
 * the necessary locking for the page fault to proceed successfully.
 */
int dax_fault(struct vm_area_struct *vma, struct vm_fault *vmf,
			get_block_t get_block)
{
	struct file *file = vma->vm_file;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	void *entry;
	struct buffer_head bh;
	unsigned long vaddr = (unsigned long)vmf->virtual_address;
	unsigned blkbits = inode->i_blkbits;
	sector_t block;
	pgoff_t size;
	int error;
	int major = 0;

	/*
	 * Check whether offset isn't beyond end of file now. Caller is supposed
	 * to hold locks serializing us with truncate / punch hole so this is
	 * a reliable test.
	 */
	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (vmf->pgoff >= size)
		return VM_FAULT_SIGBUS;

	memset(&bh, 0, sizeof(bh));
	block = (sector_t)vmf->pgoff << (PAGE_SHIFT - blkbits);
	bh.b_bdev = inode->i_sb->s_bdev;
	bh.b_size = PAGE_SIZE;

	entry = grab_mapping_entry(mapping, vmf->pgoff);
	if (IS_ERR(entry)) {
		error = PTR_ERR(entry);
		goto out;
	}

	error = get_block(inode, block, &bh, 0);
	if (!error && (bh.b_size < PAGE_SIZE))
		error = -EIO;		/* fs corruption? */
	if (error)
		goto unlock_entry;

	if (vmf->cow_page) {
		struct page *new_page = vmf->cow_page;
		if (buffer_written(&bh))
			error = copy_user_dax(bh.b_bdev, to_sector(&bh, inode),
					bh.b_size, new_page, vaddr);
		else
			clear_user_highpage(new_page, vaddr);
		if (error)
			goto unlock_entry;
		if (!radix_tree_exceptional_entry(entry)) {
			vmf->page = entry;
			return VM_FAULT_LOCKED;
		}
		vmf->entry = entry;
		return VM_FAULT_DAX_LOCKED;
	}

	if (!buffer_mapped(&bh)) {
		if (vmf->flags & FAULT_FLAG_WRITE) {
			error = get_block(inode, block, &bh, 1);
			count_vm_event(PGMAJFAULT);
			mem_cgroup_count_vm_event(vma->vm_mm, PGMAJFAULT);
			major = VM_FAULT_MAJOR;
			if (!error && (bh.b_size < PAGE_SIZE))
				error = -EIO;
			if (error)
				goto unlock_entry;
		} else {
			return dax_load_hole(mapping, entry, vmf);
		}
	}

	/* Filesystem should not return unwritten buffers to us! */
	WARN_ON_ONCE(buffer_unwritten(&bh) || buffer_new(&bh));
	error = dax_insert_mapping(mapping, bh.b_bdev, to_sector(&bh, inode),
			bh.b_size, &entry, vma, vmf);
 unlock_entry:
	put_locked_mapping_entry(mapping, vmf->pgoff, entry);
 out:
	if (error == -ENOMEM)
		return VM_FAULT_OOM | major;
	/* -EBUSY is fine, somebody else faulted on the same PTE */
	if ((error < 0) && (error != -EBUSY))
		return VM_FAULT_SIGBUS | major;
	return VM_FAULT_NOPAGE | major;
}
EXPORT_SYMBOL_GPL(dax_fault);

/**
 * dax_pfn_mkwrite - handle first write to DAX page
 * @vma: The virtual memory area where the fault occurred
 * @vmf: The description of the fault
 */
int dax_pfn_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct file *file = vma->vm_file;
	struct address_space *mapping = file->f_mapping;
	void *entry;
	pgoff_t index = vmf->pgoff;

	spin_lock_irq(&mapping->tree_lock);
	entry = get_unlocked_mapping_entry(mapping, index, NULL);
	if (!entry || !radix_tree_exceptional_entry(entry))
		goto out;
	radix_tree_tag_set(&mapping->page_tree, index, PAGECACHE_TAG_DIRTY);
	put_unlocked_mapping_entry(mapping, index, entry);
out:
	spin_unlock_irq(&mapping->tree_lock);
	return VM_FAULT_NOPAGE;
}
EXPORT_SYMBOL_GPL(dax_pfn_mkwrite);

static bool dax_range_is_aligned(struct block_device *bdev,
				 unsigned int offset, unsigned int length)
{
	unsigned short sector_size = bdev_logical_block_size(bdev);

	if (!IS_ALIGNED(offset, sector_size))
		return false;
	if (!IS_ALIGNED(length, sector_size))
		return false;

	return true;
}

int __dax_zero_page_range(struct block_device *bdev, sector_t sector,
		unsigned int offset, unsigned int length)
{
	struct blk_dax_ctl dax = {
		.sector		= sector,
		.size		= PAGE_CACHE_SIZE,
	};

	if (dax_map_atomic(bdev, &dax) < 0)
		return PTR_ERR(dax.addr);
	clear_pmem(dax.addr + offset, length);
	dax_unmap_atomic(bdev, &dax);
	if (dax_range_is_aligned(bdev, offset, length)) {
		sector_t start_sector = dax.sector + (offset >> 9);

		return blkdev_issue_zeroout(bdev, start_sector,
				length >> 9, GFP_NOFS);
	} else {
		if (dax_map_atomic(bdev, &dax) < 0)
			return PTR_ERR(dax.addr);
		clear_pmem(dax.addr + offset, length);
		dax_unmap_atomic(bdev, &dax);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(__dax_zero_page_range);

/**
 * dax_zero_page_range - zero a range within a page of a DAX file
 * @inode: The file being truncated
 * @from: The file offset that is being truncated to
 * @length: The number of bytes to zero
 * @get_block: The filesystem method used to translate file offsets to blocks
 *
 * This function can be called by a filesystem when it is zeroing part of a
 * page in a DAX file.  This is intended for hole-punch operations.  If
 * you are truncating a file, the helper function dax_truncate_page() may be
 * more convenient.
 */
int dax_zero_page_range(struct inode *inode, loff_t from, unsigned length,
							get_block_t get_block)
{
	struct buffer_head bh;
	pgoff_t index = from >> PAGE_CACHE_SHIFT;
	unsigned offset = from & (PAGE_CACHE_SIZE-1);
	int err;

	/* Block boundary? Nothing to do */
	if (!length)
		return 0;
	if (WARN_ON_ONCE((offset + length) > PAGE_CACHE_SIZE))
		return -EINVAL;

	memset(&bh, 0, sizeof(bh));
	bh.b_bdev = inode->i_sb->s_bdev;
	bh.b_size = PAGE_CACHE_SIZE;
	err = get_block(inode, index, &bh, 0);
	if (err < 0 || !buffer_written(&bh))
		return err;

	return __dax_zero_page_range(bh.b_bdev, to_sector(&bh, inode),
			offset, length);
}
EXPORT_SYMBOL_GPL(dax_zero_page_range);

/**
 * dax_truncate_page - handle a partial page being truncated in a DAX file
 * @inode: The file being truncated
 * @from: The file offset that is being truncated to
 * @get_block: The filesystem method used to translate file offsets to blocks
 *
 * Similar to block_truncate_page(), this function can be called by a
 * filesystem when it is truncating a DAX file to handle the partial page.
 */
int dax_truncate_page(struct inode *inode, loff_t from, get_block_t get_block)
{
	unsigned length = PAGE_CACHE_ALIGN(from) - from;
	return dax_zero_page_range(inode, from, length, get_block);
}
EXPORT_SYMBOL_GPL(dax_truncate_page);
