/*
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (c) 2016 Christoph Hellwig.
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
#include <linux/module.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/uaccess.h>
#include <linux/aio.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/backing-dev.h>
#include <linux/buffer_head.h>
#include <linux/dax.h>
#include "internal.h"

/*
 * Execute a iomap write on a segment of the mapping that spans a
 * contiguous range of pages that have identical block mapping state.
 *
 * This avoids the need to map pages individually, do individual allocations
 * for each page and most importantly avoid the need for filesystem specific
 * locking per page. Instead, all the operations are amortised over the entire
 * range of pages. It is assumed that the filesystems will lock whatever
 * resources they require in the iomap_begin call, and release them in the
 * iomap_end call.
 */
loff_t
iomap_apply(struct inode *inode, loff_t pos, loff_t length, unsigned flags,
		const struct iomap_ops *ops, void *data, iomap_actor_t actor)
{
	struct iomap iomap = { 0 };
	loff_t written = 0, ret;

	/*
	 * Need to map a range from start position for length bytes. This can
	 * span multiple pages - it is only guaranteed to return a range of a
	 * single type of pages (e.g. all into a hole, all mapped or all
	 * unwritten). Failure at this point has nothing to undo.
	 *
	 * If allocation is required for this range, reserve the space now so
	 * that the allocation is guaranteed to succeed later on. Once we copy
	 * the data into the page cache pages, then we cannot fail otherwise we
	 * expose transient stale data. If the reserve fails, we can safely
	 * back out at this point as there is nothing to undo.
	 */
	ret = ops->iomap_begin(inode, pos, length, flags, &iomap);
	if (ret)
		return ret;
	if (WARN_ON(iomap.offset > pos))
		return -EIO;
	if (WARN_ON(iomap.length == 0))
		return -EIO;

	/*
	 * Cut down the length to the one actually provided by the filesystem,
	 * as it might not be able to give us the whole size that we requested.
	 */
	if (iomap.offset + iomap.length < pos + length)
		length = iomap.offset + iomap.length - pos;

	/*
	 * Now that we have guaranteed that the space allocation will succeed.
	 * we can do the copy-in page by page without having to worry about
	 * failures exposing transient data.
	 */
	written = actor(inode, pos, length, data, &iomap);

	/*
	 * Now the data has been copied, commit the range we've copied.  This
	 * should not fail unless the filesystem has had a fatal error.
	 */
	if (ops->iomap_end) {
		ret = ops->iomap_end(inode, pos, length,
				     written > 0 ? written : 0,
				     flags, &iomap);
	}

	return written ? written : ret;
}

static void
iomap_read_inline_data(struct inode *inode, struct page *page,
		struct iomap *iomap)
{
	size_t size = i_size_read(inode);
	void *addr;

	if (PageUptodate(page))
		return;

	BUG_ON(page->index);
	BUG_ON(size > PAGE_SIZE - offset_in_page(iomap->inline_data));

	addr = kmap_atomic(page);
	memcpy(addr, iomap->inline_data, size);
	memset(addr + size, 0, PAGE_SIZE - size);
	kunmap_atomic(addr);
	SetPageUptodate(page);
}

static void
iomap_write_failed(struct inode *inode, loff_t pos, unsigned len)
{
	loff_t i_size = i_size_read(inode);

	/*
	 * Only truncate newly allocated pages beyoned EOF, even if the
	 * write started inside the existing inode size.
	 */
	if (pos + len > i_size)
		truncate_pagecache_range(inode, max(pos, i_size), pos + len);
}

static int
iomap_write_begin(struct inode *inode, loff_t pos, unsigned len, unsigned flags,
		struct page **pagep, struct iomap *iomap)
{
	const struct iomap_page_ops *page_ops = iomap->page_ops;
	pgoff_t index = pos >> PAGE_SHIFT;
	struct page *page;
	int status = 0;

	BUG_ON(pos + len > iomap->offset + iomap->length);

	if (fatal_signal_pending(current))
		return -EINTR;

	if (page_ops && page_ops->page_prepare) {
		status = page_ops->page_prepare(inode, pos, len, iomap);
		if (status)
			return status;
	}

	page = grab_cache_page_write_begin(inode->i_mapping, index, flags);
	if (!page) {
		status = -ENOMEM;
		goto out_no_page;
	}

	if (iomap->type == IOMAP_INLINE)
		iomap_read_inline_data(inode, page, iomap);
	else
		status = __block_write_begin_int(page, pos, len, NULL, iomap);
	if (unlikely(status))
		goto out_unlock;

	*pagep = page;
	return 0;

out_unlock:
	unlock_page(page);
	put_page(page);
	iomap_write_failed(inode, pos, len);

out_no_page:
	if (page_ops && page_ops->page_done)
		page_ops->page_done(inode, pos, 0, NULL, iomap);
	return status;
}

static int
iomap_write_end_inline(struct inode *inode, struct page *page,
		struct iomap *iomap, loff_t pos, unsigned len, unsigned copied)
{
	void *addr;

	WARN_ON_ONCE(!PageUptodate(page));
	BUG_ON(pos + copied > PAGE_SIZE - offset_in_page(iomap->inline_data));

	addr = kmap_atomic(page);
	memcpy(iomap->inline_data + pos, addr + pos, copied);
	kunmap_atomic(addr);

	mark_inode_dirty(inode);
	return copied;
}

static int
iomap_write_end(struct inode *inode, loff_t pos, unsigned len,
		unsigned copied, struct page *page, struct iomap *iomap)
{
	const struct iomap_page_ops *page_ops = iomap->page_ops;
	loff_t old_size = inode->i_size;
	int ret;

	if (iomap->type == IOMAP_INLINE) {
		ret = iomap_write_end_inline(inode, page, iomap, pos, len,
				copied);
	} else {
		ret = block_write_end(NULL, inode->i_mapping, pos, len,
				copied, page, NULL);
	}

	/*
	 * Update the in-memory inode size after copying the data into the page
	 * cache.  It's up to the file system to write the updated size to disk,
	 * preferably after I/O completion so that no stale data is exposed.
	 */
	if (pos + ret > old_size) {
		i_size_write(inode, pos + ret);
		iomap->flags |= IOMAP_F_SIZE_CHANGED;
	}
	unlock_page(page);

	if (old_size < pos)
		pagecache_isize_extended(inode, old_size, pos);
	if (page_ops && page_ops->page_done)
		page_ops->page_done(inode, pos, ret, page, iomap);
	page_cache_release(page);

	if (ret < len)
		iomap_write_failed(inode, pos, len);
	return ret;
}

static loff_t
iomap_write_actor(struct inode *inode, loff_t pos, loff_t length, void *data,
		struct iomap *iomap)
{
	struct iov_iter *i = data;
	long status = 0;
	ssize_t written = 0;
	unsigned int flags = AOP_FLAG_NOFS;

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

		offset = (pos & (PAGE_SIZE - 1));
		bytes = min_t(unsigned long, PAGE_SIZE - offset,
						iov_iter_count(i));
again:
		if (bytes > length)
			bytes = length;

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

		status = iomap_write_begin(inode, pos, bytes, flags, &page,
				iomap);
		if (unlikely(status))
			break;

		if (mapping_writably_mapped(inode->i_mapping))
			flush_dcache_page(page);

		pagefault_disable();
		copied = iov_iter_copy_from_user_atomic(page, i, offset, bytes);
		pagefault_enable();

		flush_dcache_page(page);
		mark_page_accessed(page);

		status = iomap_write_end(inode, pos, bytes, copied, page,
				iomap);
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
			bytes = min_t(unsigned long, PAGE_SIZE - offset,
						iov_iter_single_seg_count(i));
			goto again;
		}
		pos += copied;
		written += copied;
		length -= copied;

		balance_dirty_pages_ratelimited(inode->i_mapping);
	} while (iov_iter_count(i) && length);

	return written ? written : status;
}

ssize_t
iomap_file_buffered_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos, loff_t *ppos,
		size_t count, const struct iomap_ops *ops)
{
	struct inode *inode = iocb->ki_filp->f_mapping->host;
	loff_t ret = 0;
	size_t written = 0;
	struct iov_iter iter;

	iov_iter_init(&iter, iov, nr_segs, count, 0);

	while (iov_iter_count(&iter)) {
		ret = iomap_apply(inode, pos, iov_iter_count(&iter),
				IOMAP_WRITE, ops, &iter, iomap_write_actor);
		if (ret <= 0)
			break;
		pos += ret;
		*ppos = pos;
		written += ret;
	}

	return written ? written : ret;
}
EXPORT_SYMBOL_GPL(iomap_file_buffered_write);

static struct page *
__iomap_read_page(struct inode *inode, loff_t offset)
{
	struct address_space *mapping = inode->i_mapping;
	struct page *page;

	page = read_mapping_page(mapping, offset >> PAGE_SHIFT, NULL);
	if (IS_ERR(page))
		return page;
	if (!PageUptodate(page)) {
		put_page(page);
		return ERR_PTR(-EIO);
	}
	return page;
}

static loff_t
iomap_dirty_actor(struct inode *inode, loff_t pos, loff_t length, void *data,
		struct iomap *iomap)
{
	long status = 0;
	ssize_t written = 0;

	do {
		struct page *page, *rpage;
		unsigned long offset;	/* Offset into pagecache page */
		unsigned long bytes;	/* Bytes to write to page */

		offset = (pos & (PAGE_SIZE - 1));
		bytes = min_t(loff_t, PAGE_SIZE - offset, length);

		rpage = __iomap_read_page(inode, pos);
		if (IS_ERR(rpage))
			return PTR_ERR(rpage);

		status = iomap_write_begin(inode, pos, bytes,
				AOP_FLAG_NOFS | AOP_FLAG_UNINTERRUPTIBLE,
				&page, iomap);
		put_page(rpage);
		if (unlikely(status))
			return status;

		WARN_ON_ONCE(!PageUptodate(page));

		status = iomap_write_end(inode, pos, bytes, bytes, page, iomap);
		if (unlikely(status <= 0)) {
			if (WARN_ON_ONCE(status == 0))
				return -EIO;
			return status;
		}

		cond_resched();

		pos += status;
		written += status;
		length -= status;

		balance_dirty_pages_ratelimited(inode->i_mapping);
	} while (length);

	return written;
}

int
iomap_file_dirty(struct inode *inode, loff_t pos, loff_t len,
		const struct iomap_ops *ops)
{
	loff_t ret;

	while (len) {
		ret = iomap_apply(inode, pos, len, IOMAP_WRITE, ops, NULL,
				iomap_dirty_actor);
		if (ret <= 0)
			return ret;
		pos += ret;
		len -= ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(iomap_file_dirty);

static int iomap_zero(struct inode *inode, loff_t pos, unsigned offset,
		unsigned bytes, struct iomap *iomap)
{
	struct page *page;
	int status;

	status = iomap_write_begin(inode, pos, bytes,
			AOP_FLAG_UNINTERRUPTIBLE | AOP_FLAG_NOFS, &page, iomap);
	if (status)
		return status;

	zero_user(page, offset, bytes);
	mark_page_accessed(page);

	return iomap_write_end(inode, pos, bytes, bytes, page, iomap);
}

static int iomap_dax_zero(loff_t pos, unsigned offset, unsigned bytes,
		struct iomap *iomap)
{
	sector_t sector = (iomap->addr +
			   (pos & PAGE_MASK) - iomap->offset) >> 9;

	return __dax_zero_page_range(iomap->bdev, iomap->dax_dev, sector,
			offset, bytes);
}

static loff_t
iomap_zero_range_actor(struct inode *inode, loff_t pos, loff_t count,
		void *data, struct iomap *iomap)
{
	bool *did_zero = data;
	loff_t written = 0;
	int status;

	/* already zeroed?  we're done. */
	if (iomap->type == IOMAP_HOLE || iomap->type == IOMAP_UNWRITTEN)
	    	return count;

	do {
		unsigned offset, bytes;

		offset = pos & (PAGE_SIZE - 1); /* Within page */
		bytes = min_t(loff_t, PAGE_SIZE - offset, count);

		if (IS_DAX(inode))
			status = iomap_dax_zero(pos, offset, bytes, iomap);
		else
			status = iomap_zero(inode, pos, offset, bytes, iomap);
		if (status < 0)
			return status;

		pos += bytes;
		count -= bytes;
		written += bytes;
		if (did_zero)
			*did_zero = true;
	} while (count > 0);

	return written;
}

int
iomap_zero_range(struct inode *inode, loff_t pos, loff_t len, bool *did_zero,
		const struct iomap_ops *ops)
{
	loff_t ret;

	while (len > 0) {
		ret = iomap_apply(inode, pos, len, IOMAP_ZERO,
				ops, did_zero, iomap_zero_range_actor);
		if (ret <= 0)
			return ret;

		pos += ret;
		len -= ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(iomap_zero_range);

int
iomap_truncate_page(struct inode *inode, loff_t pos, bool *did_zero,
		const struct iomap_ops *ops)
{
	unsigned blocksize = (1 << inode->i_blkbits);
	unsigned off = pos & (blocksize - 1);

	/* Block boundary? Nothing to do */
	if (!off)
		return 0;
	return iomap_zero_range(inode, pos, blocksize - off, did_zero, ops);
}
EXPORT_SYMBOL_GPL(iomap_truncate_page);

static loff_t
iomap_page_mkwrite_actor(struct inode *inode, loff_t pos, loff_t length,
		void *data, struct iomap *iomap)
{
	struct page *page = data;
	int ret;

	ret = __block_write_begin_int(page, pos, length, NULL, iomap);
	if (ret)
		return ret;

	block_commit_write(page, 0, length);
	return length;
}

int iomap_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf,
		const struct iomap_ops *ops)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vma->vm_file);
	unsigned long length;
	loff_t offset, size;
	ssize_t ret;

	lock_page(page);
	size = i_size_read(inode);
	if ((page->mapping != inode->i_mapping) ||
	    (page_offset(page) > size)) {
		/* We overload EFAULT to mean page got truncated */
		ret = -EFAULT;
		goto out_unlock;
	}

	/* page is wholly or partially inside EOF */
	if (((page->index + 1) << PAGE_SHIFT) > size)
		length = size & ~PAGE_MASK;
	else
		length = PAGE_SIZE;

	offset = page_offset(page);
	while (length > 0) {
		ret = iomap_apply(inode, offset, length,
				IOMAP_WRITE | IOMAP_FAULT, ops, page,
				iomap_page_mkwrite_actor);
		if (unlikely(ret <= 0))
			goto out_unlock;
		offset += ret;
		length -= ret;
	}

	set_page_dirty(page);
	wait_for_stable_page(page);
	return VM_FAULT_LOCKED;
out_unlock:
	unlock_page(page);
	return block_page_mkwrite_return(ret);
}
EXPORT_SYMBOL_GPL(iomap_page_mkwrite);

struct fiemap_ctx {
	struct fiemap_extent_info *fi;
	struct iomap prev;
};

static int iomap_to_fiemap(struct fiemap_extent_info *fi,
		struct iomap *iomap, u32 flags)
{
	switch (iomap->type) {
	case IOMAP_HOLE:
		/* skip holes */
		return 0;
	case IOMAP_DELALLOC:
		flags |= FIEMAP_EXTENT_DELALLOC | FIEMAP_EXTENT_UNKNOWN;
		break;
	case IOMAP_MAPPED:
		break;
	case IOMAP_UNWRITTEN:
		flags |= FIEMAP_EXTENT_UNWRITTEN;
		break;
	case IOMAP_INLINE:
		flags |= FIEMAP_EXTENT_DATA_INLINE;
		break;
	}

	if (iomap->flags & IOMAP_F_MERGED)
		flags |= FIEMAP_EXTENT_MERGED;
	if (iomap->flags & IOMAP_F_SHARED)
		flags |= FIEMAP_EXTENT_SHARED;

	return fiemap_fill_next_extent(fi, iomap->offset,
			iomap->addr != IOMAP_NULL_ADDR ? iomap->addr : 0,
			iomap->length, flags);
}

static loff_t
iomap_fiemap_actor(struct inode *inode, loff_t pos, loff_t length, void *data,
		struct iomap *iomap)
{
	struct fiemap_ctx *ctx = data;
	loff_t ret = length;

	if (iomap->type == IOMAP_HOLE)
		return length;

	ret = iomap_to_fiemap(ctx->fi, &ctx->prev, 0);
	ctx->prev = *iomap;
	switch (ret) {
	case 0:		/* success */
		return length;
	case 1:		/* extent array full */
		return 0;
	default:
		return ret;
	}
}

int iomap_fiemap(struct inode *inode, struct fiemap_extent_info *fi,
		loff_t start, loff_t len, const struct iomap_ops *ops)
{
	struct fiemap_ctx ctx;
	loff_t ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.fi = fi;
	ctx.prev.type = IOMAP_HOLE;

	ret = fiemap_check_flags(fi, FIEMAP_FLAG_SYNC);
	if (ret)
		return ret;

	if (fi->fi_flags & FIEMAP_FLAG_SYNC) {
		ret = filemap_write_and_wait(inode->i_mapping);
		if (ret)
			return ret;
	}

	while (len > 0) {
		ret = iomap_apply(inode, start, len, IOMAP_REPORT, ops, &ctx,
				iomap_fiemap_actor);
		/* inode with no (attribute) mapping will give ENOENT */
		if (ret == -ENOENT)
			break;
		if (ret < 0)
			return ret;
		if (ret == 0)
			break;

		start += ret;
		len -= ret;
	}

	if (ctx.prev.type != IOMAP_HOLE) {
		ret = iomap_to_fiemap(fi, &ctx.prev, FIEMAP_EXTENT_LAST);
		if (ret < 0)
			return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(iomap_fiemap);

static loff_t
iomap_seek_hole_actor(struct inode *inode, loff_t offset, loff_t length,
		      void *data, struct iomap *iomap)
{
	switch (iomap->type) {
	case IOMAP_UNWRITTEN:
		offset = page_cache_seek_hole_data(inode, offset, length,
						   SEEK_HOLE);
		if (offset < 0)
			return length;
		/* fall through */
	case IOMAP_HOLE:
		*(loff_t *)data = offset;
		return 0;
	default:
		return length;
	}
}

loff_t
iomap_seek_hole(struct inode *inode, loff_t offset, const struct iomap_ops *ops)
{
	loff_t size = i_size_read(inode);
	loff_t length = size - offset;
	loff_t ret;

	/* Nothing to be found before or beyond the end of the file. */
	if (offset < 0 || offset >= size)
		return -ENXIO;

	while (length > 0) {
		ret = iomap_apply(inode, offset, length, IOMAP_REPORT, ops,
				  &offset, iomap_seek_hole_actor);
		if (ret < 0)
			return ret;
		if (ret == 0)
			break;

		offset += ret;
		length -= ret;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(iomap_seek_hole);

static loff_t
iomap_seek_data_actor(struct inode *inode, loff_t offset, loff_t length,
		      void *data, struct iomap *iomap)
{
	switch (iomap->type) {
	case IOMAP_HOLE:
		return length;
	case IOMAP_UNWRITTEN:
		offset = page_cache_seek_hole_data(inode, offset, length,
						   SEEK_DATA);
		if (offset < 0)
			return length;
		/*FALLTHRU*/
	default:
		*(loff_t *)data = offset;
		return 0;
	}
}

loff_t
iomap_seek_data(struct inode *inode, loff_t offset, const struct iomap_ops *ops)
{
	loff_t size = i_size_read(inode);
	loff_t length = size - offset;
	loff_t ret;

	/* Nothing to be found before or beyond the end of the file. */
	if (offset < 0 || offset >= size)
		return -ENXIO;

	while (length > 0) {
		ret = iomap_apply(inode, offset, length, IOMAP_REPORT, ops,
				  &offset, iomap_seek_data_actor);
		if (ret < 0)
			return ret;
		if (ret == 0)
			break;

		offset += ret;
		length -= ret;
	}

	if (length <= 0)
		return -ENXIO;
	return offset;
}
EXPORT_SYMBOL_GPL(iomap_seek_data);
