/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_da_format.h"
#include "xfs_da_btree.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_inode_item.h"
#include "xfs_bmap.h"
#include "xfs_bmap_util.h"
#include "xfs_error.h"
#include "xfs_dir2.h"
#include "xfs_dir2_priv.h"
#include "xfs_ioctl.h"
#include "xfs_trace.h"
#include "xfs_log.h"
#include "xfs_icache.h"
#include "xfs_pnfs.h"
#include "xfs_iomap.h"

#include <linux/aio.h>
#include <linux/dcache.h>
#include <linux/falloc.h>
#include <linux/pagevec.h>
#include <linux/splice.h>

static const struct vm_operations_struct xfs_file_vm_ops;

/*
 * Locking primitives for read and write IO paths to ensure we consistently use
 * and order the inode->i_mutex, ip->i_lock and ip->i_iolock.
 */
static inline void
xfs_rw_ilock(
	struct xfs_inode	*ip,
	int			type)
{
	if (type & XFS_IOLOCK_EXCL)
		mutex_lock(&VFS_I(ip)->i_mutex);
	xfs_ilock(ip, type);
}

static inline void
xfs_rw_iunlock(
	struct xfs_inode	*ip,
	int			type)
{
	xfs_iunlock(ip, type);
	if (type & XFS_IOLOCK_EXCL)
		mutex_unlock(&VFS_I(ip)->i_mutex);
}

static inline void
xfs_rw_ilock_demote(
	struct xfs_inode	*ip,
	int			type)
{
	xfs_ilock_demote(ip, type);
	if (type & XFS_IOLOCK_EXCL)
		mutex_unlock(&VFS_I(ip)->i_mutex);
}

/*
 * Clear the specified ranges to zero through either the pagecache or DAX.
 * Holes and unwritten extents will be left as-is as they already are zeroed.
 */
int
xfs_zero_range(
	struct xfs_inode	*ip,
	xfs_off_t		pos,
	xfs_off_t		count,
	bool			*did_zero)
{
	return iomap_zero_range(VFS_I(ip), pos, count, did_zero, &xfs_iomap_ops);
}

int
xfs_update_prealloc_flags(
	struct xfs_inode	*ip,
	enum xfs_prealloc_flags	flags)
{
	struct xfs_trans	*tp;
	int			error;

	error = xfs_trans_alloc(ip->i_mount, &M_RES(ip->i_mount)->tr_writeid,
			0, 0, 0, &tp);
	if (error)
		return error;

	xfs_ilock(ip, XFS_ILOCK_EXCL);
	xfs_trans_ijoin(tp, ip, XFS_ILOCK_EXCL);

	if (!(flags & XFS_PREALLOC_INVISIBLE)) {
		VFS_I(ip)->i_mode &= ~S_ISUID;
		if (VFS_I(ip)->i_mode & S_IXGRP)
			VFS_I(ip)->i_mode &= ~S_ISGID;
		xfs_trans_ichgtime(tp, ip, XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);
	}

	if (flags & XFS_PREALLOC_SET)
		ip->i_d.di_flags |= XFS_DIFLAG_PREALLOC;
	if (flags & XFS_PREALLOC_CLEAR)
		ip->i_d.di_flags &= ~XFS_DIFLAG_PREALLOC;

	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
	if (flags & XFS_PREALLOC_SYNC)
		xfs_trans_set_sync(tp);
	return xfs_trans_commit(tp);
}

/*
 * Fsync operations on directories are much simpler than on regular files,
 * as there is no file data to flush, and thus also no need for explicit
 * cache flush operations, and there are no non-transaction metadata updates
 * on directories either.
 */
STATIC int
xfs_dir_fsync(
	struct file		*file,
	loff_t			start,
	loff_t			end,
	int			datasync)
{
	struct xfs_inode	*ip = XFS_I(file->f_mapping->host);
	struct xfs_mount	*mp = ip->i_mount;
	xfs_lsn_t		lsn = 0;

	trace_xfs_dir_fsync(ip);

	xfs_ilock(ip, XFS_ILOCK_SHARED);
	if (xfs_ipincount(ip))
		lsn = ip->i_itemp->ili_last_lsn;
	xfs_iunlock(ip, XFS_ILOCK_SHARED);

	if (!lsn)
		return 0;
	return _xfs_log_force_lsn(mp, lsn, XFS_LOG_SYNC, NULL);
}

STATIC int
xfs_file_fsync(
	struct file		*file,
	loff_t			start,
	loff_t			end,
	int			datasync)
{
	struct inode		*inode = file->f_mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	int			error = 0;
	int			log_flushed = 0;
	xfs_lsn_t		lsn = 0;

	trace_xfs_file_fsync(ip);

	error = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (error)
		return error;

	if (XFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	xfs_iflags_clear(ip, XFS_ITRUNCATED);

	if (mp->m_flags & XFS_MOUNT_BARRIER) {
		/*
		 * If we have an RT and/or log subvolume we need to make sure
		 * to flush the write cache the device used for file data
		 * first.  This is to ensure newly written file data make
		 * it to disk before logging the new inode size in case of
		 * an extending write.
		 */
		if (XFS_IS_REALTIME_INODE(ip))
			xfs_blkdev_issue_flush(mp->m_rtdev_targp);
		else if (mp->m_logdev_targp != mp->m_ddev_targp)
			xfs_blkdev_issue_flush(mp->m_ddev_targp);
	}

	/*
	 * All metadata updates are logged, which means that we just have to
	 * flush the log up to the latest LSN that touched the inode. If we have
	 * concurrent fsync/fdatasync() calls, we need them to all block on the
	 * log force before we clear the ili_fsync_fields field. This ensures
	 * that we don't get a racing sync operation that does not wait for the
	 * metadata to hit the journal before returning. If we race with
	 * clearing the ili_fsync_fields, then all that will happen is the log
	 * force will do nothing as the lsn will already be on disk. We can't
	 * race with setting ili_fsync_fields because that is done under
	 * XFS_ILOCK_EXCL, and that can't happen because we hold the lock shared
	 * until after the ili_fsync_fields is cleared.
	 */
	xfs_ilock(ip, XFS_ILOCK_SHARED);
	if (xfs_ipincount(ip)) {
		if (!datasync ||
		    (ip->i_itemp->ili_fsync_fields & ~XFS_ILOG_TIMESTAMP))
			lsn = ip->i_itemp->ili_last_lsn;
	}

	if (lsn) {
		error = _xfs_log_force_lsn(mp, lsn, XFS_LOG_SYNC, &log_flushed);
		ip->i_itemp->ili_fsync_fields = 0;
	}
	xfs_iunlock(ip, XFS_ILOCK_SHARED);

	/*
	 * If we only have a single device, and the log force about was
	 * a no-op we might have to flush the data device cache here.
	 * This can only happen for fdatasync/O_DSYNC if we were overwriting
	 * an already allocated file and thus do not have any metadata to
	 * commit.
	 */
	if ((mp->m_flags & XFS_MOUNT_BARRIER) &&
	    mp->m_logdev_targp == mp->m_ddev_targp &&
	    !XFS_IS_REALTIME_INODE(ip) &&
	    !log_flushed)
		xfs_blkdev_issue_flush(mp->m_ddev_targp);

	return error;
}

STATIC ssize_t
xfs_file_dio_aio_read(
	struct kiocb		*iocb,
	const struct iovec	*iovp,
	unsigned long		nr_segs,
	loff_t			pos)
{
	struct address_space	*mapping = iocb->ki_filp->f_mapping;
	struct inode		*inode = mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	loff_t			isize = i_size_read(inode);
	size_t			size = 0;
	struct xfs_buftarg	*target;
	ssize_t			ret = 0;
	loff_t			end;


	ret = generic_segment_checks(iovp, &nr_segs, &size, VERIFY_WRITE);
	if (ret < 0)
		return ret;
	end = iocb->ki_pos + size - 1;

	trace_xfs_file_direct_read(ip, size, iocb->ki_pos);

	if (!size)
		return 0; /* skip atime */

	if (XFS_IS_REALTIME_INODE(ip))
		target = ip->i_mount->m_rtdev_targp;
	else
		target = ip->i_mount->m_ddev_targp;

	/* DIO must be aligned to device logical sector size */
	if ((pos | size) & target->bt_logical_sectormask) {
		if (pos == isize)
			return 0;
		return -EINVAL;
	}

	file_accessed(iocb->ki_filp);

	xfs_rw_ilock(ip, XFS_IOLOCK_SHARED);
	if (mapping->nrpages) {
		ret = filemap_write_and_wait_range(mapping, iocb->ki_pos, end);
		if (ret)
			goto out_unlock;

		/*
		 * Invalidate whole pages. This can return an error if we fail
		 * to invalidate a page, but this should never happen on XFS.
		 * Warn if it does fail.
		 */
		ret = invalidate_inode_pages2_range(mapping,
				iocb->ki_pos >> PAGE_SHIFT, end >> PAGE_SHIFT);
		WARN_ON_ONCE(ret);
		ret = 0;
	}
	ret = __blockdev_direct_IO(READ, iocb, inode, target->bt_bdev,
			iovp, pos, nr_segs, xfs_get_blocks_direct, NULL, NULL, 0);
	if (ret > 0) {
		iocb->ki_pos = pos + ret;
	}

out_unlock:
	xfs_rw_iunlock(ip, XFS_IOLOCK_SHARED);
	return ret;
}

static noinline ssize_t
xfs_file_dax_read(
	struct kiocb		*iocb,
	const struct iovec	*iovp,
	unsigned long		nr_segs,
	loff_t			pos)
{
	struct xfs_inode	*ip = XFS_I(iocb->ki_filp->f_mapping->host);
	size_t			size = 0;
	ssize_t			ret = 0;

	ret = generic_segment_checks(iovp, &nr_segs, &size, VERIFY_WRITE);
	if (ret < 0)
		return ret;

	trace_xfs_file_dax_read(ip, size, iocb->ki_pos);

	if (!size)
		return 0; /* skip atime */

	xfs_rw_ilock(ip, XFS_IOLOCK_SHARED);
	ret = dax_iomap_rw(READ, iocb, iovp, nr_segs, pos,
			   size, &xfs_iomap_ops);
	xfs_rw_iunlock(ip, XFS_IOLOCK_SHARED);

	file_accessed(iocb->ki_filp);
	return ret;
}

STATIC ssize_t
xfs_file_buffered_aio_read(
	struct kiocb		*iocb,
	const struct iovec	*iovp,
	unsigned long		nr_segs,
	loff_t			pos)
{
	struct xfs_inode	*ip = XFS_I(file_inode(iocb->ki_filp));
	size_t			size = 0;
	ssize_t			ret;

	ret = generic_segment_checks(iovp, &nr_segs, &size, VERIFY_WRITE);
	if (ret < 0)
		return ret;

	trace_xfs_file_buffered_read(ip, size, iocb->ki_pos);
	xfs_rw_ilock(ip, XFS_IOLOCK_SHARED);
	ret = generic_file_aio_read(iocb, iovp, nr_segs, pos);
	xfs_rw_iunlock(ip, XFS_IOLOCK_SHARED);

	return ret;
}

STATIC ssize_t
xfs_file_aio_read(
	struct kiocb		*iocb,
	const struct iovec	*iovp,
	unsigned long		nr_segs,
	loff_t			pos)
{
	struct file		*file = iocb->ki_filp;
	struct inode		*inode = file->f_mapping->host;
	struct xfs_inode	*ip = XFS_I(file_inode(iocb->ki_filp));
	struct xfs_mount	*mp = ip->i_mount;
	size_t			ret = 0;

	XFS_STATS_INC(mp, xs_read_calls);

	BUG_ON(iocb->ki_pos != pos);

	if (XFS_FORCED_SHUTDOWN(mp))
		return -EIO;

	if (IS_DAX(inode))
		ret = xfs_file_dax_read(iocb, iovp, nr_segs, pos);
	else if (file->f_flags & O_DIRECT)
		ret = xfs_file_dio_aio_read(iocb, iovp, nr_segs, pos);
	else
		ret = xfs_file_buffered_aio_read(iocb, iovp, nr_segs, pos);

	if (ret > 0)
		XFS_STATS_ADD(ip->i_mount, xs_read_bytes, ret);
	return ret;
}

STATIC ssize_t
xfs_file_splice_read(
	struct file		*infilp,
	loff_t			*ppos,
	struct pipe_inode_info	*pipe,
	size_t			count,
	unsigned int		flags)
{
	struct xfs_inode	*ip = XFS_I(infilp->f_mapping->host);
	ssize_t			ret;

	XFS_STATS_INC(ip->i_mount, xs_read_calls);

	if (XFS_FORCED_SHUTDOWN(ip->i_mount))
		return -EIO;

	trace_xfs_file_splice_read(ip, count, *ppos);

	/*
	 * DAX inodes cannot ues the page cache for splice, so we have to push
	 * them through the VFS IO path. This means it goes through
	 * ->read_iter, which for us takes the XFS_IOLOCK_SHARED. Hence we
	 * cannot lock the splice operation at this level for DAX inodes.
	 */
	if (IS_DAX(VFS_I(ip))) {
		ret = default_file_splice_read(infilp, ppos, pipe, count,
					       flags);
		goto out;
	}

	xfs_rw_ilock(ip, XFS_IOLOCK_SHARED);
	ret = generic_file_splice_read(infilp, ppos, pipe, count, flags);
	xfs_rw_iunlock(ip, XFS_IOLOCK_SHARED);
out:
	if (ret > 0)
		XFS_STATS_ADD(ip->i_mount, xs_read_bytes, ret);
	return ret;
}

static ssize_t
xfs_file_splice_write_actor(
	struct pipe_inode_info	*pipe,
	struct splice_desc	*sd)
{
	struct file		*out = sd->u.file;
	ssize_t ret;

	ret = file_remove_privs(out);
	if (!ret) {
		file_update_time(out);
		ret = splice_from_pipe_feed(pipe, sd, pipe_to_file);
	}

	return ret;
}

/*
 * xfs_file_splice_write() does not use the generic file splice write path
 * because that takes the i_mutex, causing lock inversions with the IOLOCK.
 * Instead, we call splice_write_to_file() directly with our own actor that does
 * not take the i_mutex. This allows us to use the xfs_rw_ilock() functions like
 * the rest of the code and hence avoid lock inversions and deadlocks.
 */
STATIC ssize_t
xfs_file_splice_write(
	struct pipe_inode_info	*pipe,
	struct file		*outfilp,
	loff_t			*ppos,
	size_t			count,
	unsigned int		flags)
{
	struct inode		*inode = outfilp->f_mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	ssize_t			ret;

	/*
	 * For dax, we need to avoid the page cache.  Locking and stats will
	 * be handled in xfs_file_dio_aio_write().
	 */
	if (IS_DAX(inode))
		return default_file_splice_write(pipe, outfilp, ppos, count,
				flags);

	XFS_STATS_INC(ip->i_mount, xs_write_calls);

	if (XFS_FORCED_SHUTDOWN(ip->i_mount))
		return -EIO;

	xfs_rw_ilock(ip, XFS_IOLOCK_EXCL);

	trace_xfs_file_splice_write(ip, count, *ppos);

	ret = splice_write_to_file(pipe, outfilp, ppos, count, flags,
					xfs_file_splice_write_actor);
	if (ret > 0)
		XFS_STATS_ADD(ip->i_mount, xs_write_bytes, ret);

	xfs_rw_iunlock(ip, XFS_IOLOCK_EXCL);
	return ret;
}

/*
 * Zero any on disk space between the current EOF and the new, larger EOF.
 *
 * This handles the normal case of zeroing the remainder of the last block in
 * the file and the unusual case of zeroing blocks out beyond the size of the
 * file.  This second case only happens with fixed size extents and when the
 * system crashes before the inode size was updated but after blocks were
 * allocated.
 *
 * Expects the iolock to be held exclusive, and will take the ilock internally.
 */
int					/* error (positive) */
xfs_zero_eof(
	struct xfs_inode	*ip,
	xfs_off_t		offset,		/* starting I/O offset */
	xfs_fsize_t		isize,		/* current inode size */
	bool			*did_zeroing)
{
	ASSERT(xfs_isilocked(ip, XFS_IOLOCK_EXCL));
	ASSERT(offset > isize);

	trace_xfs_zero_eof(ip, isize, offset - isize);
	return xfs_zero_range(ip, isize, offset - isize, did_zeroing);
}

/*
 * Common pre-write limit and setup checks.
 *
 * Called with the iolocked held either shared and exclusive according to
 * @iolock, and returns with it held.  Might upgrade the iolock to exclusive
 * if called for a direct write beyond i_size.
 */
STATIC ssize_t
xfs_file_aio_write_checks(
	struct file		*file,
	loff_t			*pos,
	size_t			*count,
	int			*iolock)
{
	struct inode		*inode = file->f_mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	int			error = 0;
	unsigned long		flags;
	bool			drained_dio = false;

restart:
	error = generic_write_checks(file, pos, count, S_ISBLK(inode->i_mode));
	if (error)
		return error;

	error = xfs_break_layouts(inode, iolock, true);
	if (error)
		return error;

	/* For changing security info in file_remove_privs() we need i_mutex */
	if (*iolock == XFS_IOLOCK_SHARED && !IS_NOSEC(inode)) {
		xfs_rw_iunlock(ip, *iolock);
		*iolock = XFS_IOLOCK_EXCL;
		xfs_rw_ilock(ip, *iolock);
		goto restart;
	}
	/*
	 * If the offset is beyond the size of the file, we need to zero any
	 * blocks that fall between the existing EOF and the start of this
	 * write.  If zeroing is needed and we are currently holding the
	 * iolock shared, we need to update it to exclusive which implies
	 * having to redo all checks before.
	 *
	 * We need to serialise against EOF updates that occur in IO
	 * completions here. We want to make sure that nobody is changing the
	 * size while we do this check until we have placed an IO barrier (i.e.
	 * hold the XFS_IOLOCK_EXCL) that prevents new IO from being dispatched.
	 * The spinlock effectively forms a memory barrier once we have the
	 * XFS_IOLOCK_EXCL so we are guaranteed to see the latest EOF value
	 * and hence be able to correctly determine if we need to run zeroing.
	 */
	spin_lock_irqsave(&ip->i_size_lock, flags);
	if (*pos > i_size_read(inode)) {
		bool	zero = false;

		spin_unlock_irqrestore(&ip->i_size_lock, flags);
		if (!drained_dio) {
			if (*iolock == XFS_IOLOCK_SHARED) {
				xfs_rw_iunlock(ip, *iolock);
				*iolock = XFS_IOLOCK_EXCL;
				xfs_rw_ilock(ip, *iolock);
			}
			/*
			 * We now have an IO submission barrier in place, but
			 * AIO can do EOF updates during IO completion and hence
			 * we now need to wait for all of them to drain. Non-AIO
			 * DIO will have drained before we are given the
			 * XFS_IOLOCK_EXCL, and so for most cases this wait is a
			 * no-op.
			 */
			inode_dio_wait(inode);
			drained_dio = true;
			goto restart;
		}
		error = xfs_zero_eof(ip, *pos, i_size_read(inode), &zero);
		if (error)
			return error;
	} else
		spin_unlock_irqrestore(&ip->i_size_lock, flags);

	/*
	 * Updating the timestamps will grab the ilock again from
	 * xfs_fs_dirty_inode, so we have to call it after dropping the
	 * lock above.  Eventually we should look into a way to avoid
	 * the pointless lock roundtrip.
	 */
	if (likely(!(file->f_mode & FMODE_NOCMTIME))) {
		error = file_update_time(file);
		if (error)
			return error;
	}

	/*
	 * If we're writing the file then make sure to clear the setuid and
	 * setgid bits if the process is not being run by root.  This keeps
	 * people from modifying setuid and setgid binaries.
	 */
	if (!IS_NOSEC(inode))
		return file_remove_privs(file);
	return 0;
}

/*
 * xfs_file_dio_aio_write - handle direct IO writes
 *
 * Lock the inode appropriately to prepare for and issue a direct IO write.
 * By separating it from the buffered write path we remove all the tricky to
 * follow locking changes and looping.
 *
 * If there are cached pages or we're extending the file, we need IOLOCK_EXCL
 * until we're sure the bytes at the new EOF have been zeroed and/or the cached
 * pages are flushed out.
 *
 * In most cases the direct IO writes will be done holding IOLOCK_SHARED
 * allowing them to be done in parallel with reads and other direct IO writes.
 * However, if the IO is not aligned to filesystem blocks, the direct IO layer
 * needs to do sub-block zeroing and that requires serialisation against other
 * direct IOs to the same block. In this case we need to serialise the
 * submission of the unaligned IOs so that we don't get racing block zeroing in
 * the dio layer.  To avoid the problem with aio, we also need to wait for
 * outstanding IOs to complete so that unwritten extent conversion is completed
 * before we try to map the overlapping block. This is currently implemented by
 * hitting it with a big hammer (i.e. inode_dio_wait()).
 *
 * Returns with locks held indicated by @iolock and errors indicated by
 * negative return values.
 */
STATIC ssize_t
xfs_file_dio_aio_write(
	struct kiocb		*iocb,
	const struct iovec	*iovp,
	unsigned long		nr_segs,
	loff_t			pos,
	size_t			ocount)
{
	struct file		*file = iocb->ki_filp;
	struct address_space	*mapping = file->f_mapping;
	struct inode		*inode = mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	struct xfs_mount	*mp = ip->i_mount;
	ssize_t			ret = 0;
	size_t			count = ocount;
	int			unaligned_io = 0;
	int			iolock;
	loff_t			end;
	struct xfs_buftarg	*target = XFS_IS_REALTIME_INODE(ip) ?
					mp->m_rtdev_targp : mp->m_ddev_targp;

	/* DIO must be aligned to device logical sector size */
	if ((pos | count) & target->bt_logical_sectormask)
		return -EINVAL;

	/*
	 * Don't take the exclusive iolock here unless the I/O is unaligned to
	 * the file system block size.  We don't need to consider the EOF
	 * extension case here because xfs_file_aio_write_checks() will relock
	 * the inode as necessary for EOF zeroing cases and fill out the new
	 * inode size as appropriate.
	 */
	if ((iocb->ki_pos & mp->m_blockmask) ||
	    ((iocb->ki_pos + count) & mp->m_blockmask)) {
		unaligned_io = 1;
		iolock = XFS_IOLOCK_EXCL;
	} else {
		iolock = XFS_IOLOCK_SHARED;
	}

	xfs_rw_ilock(ip, iolock);

	ret = xfs_file_aio_write_checks(file, &pos, &count, &iolock);
	if (ret)
		goto out;
	end = pos + count - 1;

	if (mapping->nrpages) {
		ret = filemap_write_and_wait_range(mapping, pos, end);
		if (ret)
			goto out;

		/*
		 * Invalidate whole pages. This can return an error if we fail
		 * to invalidate a page, but this should never happen on XFS.
		 * Warn if it does fail.
		 */
		ret = invalidate_inode_pages2_range(mapping,
				pos >> PAGE_SHIFT, end >> PAGE_SHIFT);
		WARN_ON_ONCE(ret);
		ret = 0;
	}

	/*
	 * If we are doing unaligned IO, wait for all other IO to drain,
	 * otherwise demote the lock if we had to take the exclusive lock
	 * for other reasons in xfs_file_aio_write_checks.
	 */
	if (unaligned_io)
		inode_dio_wait(inode);
	else if (iolock == XFS_IOLOCK_EXCL) {
		xfs_rw_ilock_demote(ip, XFS_IOLOCK_EXCL);
		iolock = XFS_IOLOCK_SHARED;
	}

	trace_xfs_file_direct_write(ip, count, iocb->ki_pos);

	if (count != ocount)
		nr_segs = iov_shorten((struct iovec *)iovp, nr_segs, count);

	ret = __blockdev_direct_IO(WRITE, iocb, inode, target->bt_bdev, iovp,
			pos, nr_segs, xfs_get_blocks_direct, xfs_end_io_direct_write,
			NULL, DIO_ASYNC_EXTEND);

	/* see generic_file_direct_write() for why this is necessary */
	if (mapping->nrpages) {
		invalidate_inode_pages2_range(mapping,
					      pos >> PAGE_CACHE_SHIFT,
					      end >> PAGE_CACHE_SHIFT);
	}

	if (ret > 0) {
		pos += ret;
		iocb->ki_pos = pos;
	}

out:
	xfs_rw_iunlock(ip, iolock);

	/*
	 * No fallback to buffered IO on errors for XFS, direct IO will either
	 * complete fully or fail.
	 */
	ASSERT(ret < 0 || ret == count);
	return ret;
}

static noinline ssize_t
xfs_file_dax_write(
	struct kiocb		*iocb,
	const struct iovec	*iovp,
	unsigned long		nr_segs,
	loff_t			pos,
	size_t			ocount)
{
	struct file		*file = iocb->ki_filp;
	struct inode		*inode = iocb->ki_filp->f_mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	size_t			count = ocount;
	int			iolock = XFS_IOLOCK_EXCL;
	ssize_t			ret, error = 0;

	xfs_rw_ilock(ip, iolock);
	ret = xfs_file_aio_write_checks(file, &pos, &count, &iolock);
	if (ret)
		goto out;

	/* checks above may have moved pos for O_APPEND, keep iocb in sync */
	iocb->ki_pos = pos;

	trace_xfs_file_dax_write(ip, count, pos);

	ret = dax_iomap_rw(WRITE, iocb, iovp, nr_segs, pos,
			   count, &xfs_iomap_ops);
	if (ret > 0 && iocb->ki_pos > i_size_read(inode)) {
		i_size_write(inode, iocb->ki_pos);
		error = xfs_setfilesize(ip, pos, ret);
	}

out:
	xfs_rw_iunlock(ip, iolock);
	return error ? error : ret;
}

STATIC ssize_t
xfs_file_buffered_aio_write(
	struct kiocb		*iocb,
	const struct iovec	*iovp,
	unsigned long		nr_segs,
	loff_t			pos,
	size_t			ocount)
{
	struct file		*file = iocb->ki_filp;
	struct address_space	*mapping = file->f_mapping;
	struct inode		*inode = mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	ssize_t			ret;
	int			enospc = 0;
	int			iolock;
	size_t			count = ocount;

write_retry:
	iolock = XFS_IOLOCK_EXCL;
	xfs_rw_ilock(ip, iolock);

	ret = xfs_file_aio_write_checks(file, &pos, &count, &iolock);
	if (ret)
		goto out;

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = mapping->backing_dev_info;

	trace_xfs_file_buffered_write(ip, count, iocb->ki_pos);
	ret = iomap_file_buffered_write(iocb, iovp, nr_segs,
			pos, &iocb->ki_pos, count, &xfs_iomap_ops);

	/*
	 * If we hit a space limit, try to free up some lingering preallocated
	 * space before returning an error. In the case of ENOSPC, first try to
	 * write back all dirty inodes to free up some of the excess reserved
	 * metadata space. This reduces the chances that the eofblocks scan
	 * waits on dirty mappings. Since xfs_flush_inodes() is serialized, this
	 * also behaves as a filter to prevent too many eofblocks scans from
	 * running at the same time.
	 */
	if (ret == -EDQUOT && !enospc) {
		xfs_rw_iunlock(ip, iolock);
		enospc = xfs_inode_free_quota_eofblocks(ip);
		if (enospc)
			goto write_retry;
		iolock = 0;
	} else if (ret == -ENOSPC && !enospc) {
		struct xfs_eofblocks eofb = {0};

		enospc = 1;
		xfs_flush_inodes(ip->i_mount);

		xfs_rw_iunlock(ip, iolock);
		eofb.eof_flags = XFS_EOF_FLAGS_SYNC;
		xfs_icache_free_eofblocks(ip->i_mount, &eofb);
		goto write_retry;
	}

	current->backing_dev_info = NULL;
out:
	if (iolock)
		xfs_rw_iunlock(ip, iolock);
	return ret;
}

STATIC ssize_t
xfs_file_aio_write(
	struct kiocb		*iocb,
	const struct iovec	*iovp,
	unsigned long		nr_segs,
	loff_t			pos)
{
	struct file		*file = iocb->ki_filp;
	struct address_space	*mapping = file->f_mapping;
	struct inode		*inode = mapping->host;
	struct xfs_inode	*ip = XFS_I(inode);
	ssize_t			ret;
	size_t			ocount = 0;

	XFS_STATS_INC(ip->i_mount, xs_write_calls);

	BUG_ON(iocb->ki_pos != pos);

	ret = generic_segment_checks(iovp, &nr_segs, &ocount, VERIFY_READ);
	if (ret)
		return ret;

	if (ocount == 0)
		return 0;

	if (XFS_FORCED_SHUTDOWN(ip->i_mount)) {
		ret = -EIO;
		goto out;
	}

	if (IS_DAX(inode))
		ret = xfs_file_dax_write(iocb, iovp, nr_segs, pos, ocount);
	else if ((file->f_flags & O_DIRECT))
		ret = xfs_file_dio_aio_write(iocb, iovp, nr_segs, pos, ocount);
	else
		ret = xfs_file_buffered_aio_write(iocb, iovp, nr_segs, pos,
						  ocount);

	if (ret > 0) {
		ssize_t err;

		XFS_STATS_ADD(ip->i_mount, xs_write_bytes, ret);

		/* Handle various SYNC-type writes */
		err = generic_write_sync(file, pos, ret);
		if (err < 0)
			ret = err;
	}

out:
	return ret;
}

STATIC long
xfs_file_fallocate(
	struct file		*file,
	int			mode,
	loff_t			offset,
	loff_t			len)
{
	struct inode		*inode = file_inode(file);
	struct xfs_inode	*ip = XFS_I(inode);
	long			error;
	enum xfs_prealloc_flags	flags = 0;
	uint			iolock = XFS_IOLOCK_EXCL;
	loff_t			new_size = 0;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;
	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
		     FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_ZERO_RANGE))
		return -EOPNOTSUPP;

	xfs_ilock(ip, iolock);
	error = xfs_break_layouts(inode, &iolock, false);
	if (error)
		goto out_unlock;

	xfs_ilock(ip, XFS_MMAPLOCK_EXCL);
	iolock |= XFS_MMAPLOCK_EXCL;

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		error = xfs_free_file_space(ip, offset, len);
		if (error)
			goto out_unlock;
	} else if (mode & FALLOC_FL_COLLAPSE_RANGE) {
		unsigned blksize_mask = (1 << inode->i_blkbits) - 1;

		if (offset & blksize_mask || len & blksize_mask) {
			error = -EINVAL;
			goto out_unlock;
		}

		/*
		 * There is no need to overlap collapse range with EOF,
		 * in which case it is effectively a truncate operation
		 */
		if (offset + len >= i_size_read(inode)) {
			error = -EINVAL;
			goto out_unlock;
		}

		new_size = i_size_read(inode) - len;

		error = xfs_collapse_file_space(ip, offset, len);
		if (error)
			goto out_unlock;
	} else {
		flags |= XFS_PREALLOC_SET;

		if (!(mode & FALLOC_FL_KEEP_SIZE) &&
		    offset + len > i_size_read(inode)) {
			new_size = offset + len;
			error = inode_newsize_ok(inode, new_size);
			if (error)
				goto out_unlock;
		}

		if (mode & FALLOC_FL_ZERO_RANGE)
			error = xfs_zero_file_space(ip, offset, len);
		else
			error = xfs_alloc_file_space(ip, offset, len,
						     XFS_BMAPI_PREALLOC);
		if (error)
			goto out_unlock;
	}

	if (file->f_flags & O_DSYNC)
		flags |= XFS_PREALLOC_SYNC;

	error = xfs_update_prealloc_flags(ip, flags);
	if (error)
		goto out_unlock;

	/* Change file size if needed */
	if (new_size) {
		struct iattr iattr;

		iattr.ia_valid = ATTR_SIZE;
		iattr.ia_size = new_size;
		error = xfs_vn_setattr_size(file_dentry(file), &iattr);
	}

out_unlock:
	xfs_iunlock(ip, iolock);
	return error;
}


STATIC int
xfs_file_open(
	struct inode	*inode,
	struct file	*file)
{
	if (!(file->f_flags & O_LARGEFILE) && i_size_read(inode) > MAX_NON_LFS)
		return -EFBIG;
	if (XFS_FORCED_SHUTDOWN(XFS_M(inode->i_sb)))
		return -EIO;
	return 0;
}

STATIC int
xfs_dir_open(
	struct inode	*inode,
	struct file	*file)
{
	struct xfs_inode *ip = XFS_I(inode);
	int		mode;
	int		error;

	error = xfs_file_open(inode, file);
	if (error)
		return error;

	/*
	 * If there are any blocks, read-ahead block 0 as we're almost
	 * certain to have the next operation be a read there.
	 */
	mode = xfs_ilock_data_map_shared(ip);
	if (ip->i_d.di_nextents > 0)
		xfs_dir3_data_readahead(ip, 0, -1);
	xfs_iunlock(ip, mode);
	return 0;
}

STATIC int
xfs_file_release(
	struct inode	*inode,
	struct file	*filp)
{
	return xfs_release(XFS_I(inode));
}

STATIC int
xfs_file_readdir(
	struct file	*filp,
	void		*dirent,
	filldir_t	filldir)
{
	struct inode	*inode = file_inode(filp);
	xfs_inode_t	*ip = XFS_I(inode);
	size_t		bufsize;

	/*
	 * The Linux API doesn't pass down the total size of the buffer
	 * we read into down to the filesystem.  With the filldir concept
	 * it's not needed for correct information, but the XFS dir2 leaf
	 * code wants an estimate of the buffer size to calculate it's
	 * readahead window and size the buffers used for mapping to
	 * physical blocks.
	 *
	 * Try to give it an estimate that's good enough, maybe at some
	 * point we can change the ->readdir prototype to include the
	 * buffer size.  For now we use the current glibc buffer size.
	 */
	bufsize = (size_t)min_t(loff_t, 32768, ip->i_d.di_size);

	return xfs_readdir(ip, dirent, bufsize,
				(xfs_off_t *)&filp->f_pos, filldir);
}

STATIC loff_t
xfs_file_llseek(
	struct file	*file,
	loff_t		offset,
	int		whence)
{
	struct inode		*inode = file->f_mapping->host;

	if (XFS_FORCED_SHUTDOWN(XFS_I(inode)->i_mount))
		return -EIO;

	switch (whence) {
	default:
		return generic_file_llseek(file, offset, whence);
	case SEEK_HOLE:
		offset = iomap_seek_hole(inode, offset, &xfs_iomap_ops);
		break;
	case SEEK_DATA:
		offset = iomap_seek_data(inode, offset, &xfs_iomap_ops);
		break;
	}

	if (offset < 0)
		return offset;
	return vfs_setpos(file, offset, inode->i_sb->s_maxbytes);
}

/*
 * Locking for serialisation of IO during page faults. This results in a lock
 * ordering of:
 *
 * mmap_sem (MM)
 *   sb_start_pagefault(vfs, freeze)
 *     i_mmaplock (XFS - truncate serialisation)
 *       page_lock (MM)
 *         i_lock (XFS - extent map serialisation)
 */

/*
 * mmap()d file has taken write protection fault and is being made writable. We
 * can set the page state up correctly for a writable page, which means we can
 * do correct delalloc accounting (ENOSPC checking!) and unwritten extent
 * mapping.
 */
STATIC int
xfs_filemap_page_mkwrite(
	struct vm_area_struct	*vma,
	struct vm_fault		*vmf)
{
	struct inode		*inode = file_inode(vma->vm_file);
	int			ret;

	trace_xfs_filemap_page_mkwrite(XFS_I(inode));

	sb_start_pagefault(inode->i_sb);
	file_update_time(vma->vm_file);
	xfs_ilock(XFS_I(inode), XFS_MMAPLOCK_SHARED);

	if (IS_DAX(inode)) {
		ret = dax_iomap_fault(vmf, PE_SIZE_PTE, &xfs_iomap_ops);
	} else {
		ret = iomap_page_mkwrite(vma, vmf, &xfs_iomap_ops);
		ret = block_page_mkwrite_return(ret);
	}

	xfs_iunlock(XFS_I(inode), XFS_MMAPLOCK_SHARED);
	sb_end_pagefault(inode->i_sb);

	return ret;
}

STATIC int
xfs_filemap_fault(
	struct vm_area_struct	*vma,
	struct vm_fault		*vmf)
{
	struct inode		*inode = file_inode(vma->vm_file);
	int			ret;

	trace_xfs_filemap_fault(XFS_I(inode));

	/* DAX can shortcut the normal fault path on write faults! */
	if ((vmf->flags & FAULT_FLAG_WRITE) && IS_DAX(inode))
		return xfs_filemap_page_mkwrite(vma, vmf);

	xfs_ilock(XFS_I(inode), XFS_MMAPLOCK_SHARED);
	if (IS_DAX(inode)) {
		/*
		 * we do not want to trigger unwritten extent conversion on read
		 * faults - that is unnecessary overhead and would also require
		 * changes to xfs_get_blocks_direct() to map unwritten extent
		 * ioend for conversion on read-only mappings.
		 */
		ret = dax_iomap_fault(vmf, PE_SIZE_PTE, &xfs_iomap_ops);
	} else
		ret = filemap_fault(vma, vmf);
	xfs_iunlock(XFS_I(inode), XFS_MMAPLOCK_SHARED);

	return ret;
}

/*
 * Similar to xfs_filemap_fault(), the DAX fault path can call into here on
 * both read and write faults. Hence we need to handle both cases. There is no
 * ->huge_mkwrite callout for huge pages, so we have a single function here to
 * handle both cases here. @flags carries the information on the type of fault
 * occuring.
 */
STATIC int
xfs_filemap_huge_fault(
	struct vm_fault		*vmf,
	enum page_entry_size	pe_size)
{
	struct inode		*inode = file_inode(vmf->vma->vm_file);
	struct xfs_inode	*ip = XFS_I(inode);
	int			ret;

	if (!IS_DAX(inode))
		return VM_FAULT_FALLBACK;

	trace_xfs_filemap_huge_fault(ip);

	if (vmf->flags & FAULT_FLAG_WRITE) {
		sb_start_pagefault(inode->i_sb);
		file_update_time(vmf->vma->vm_file);
	}

	xfs_ilock(XFS_I(inode), XFS_MMAPLOCK_SHARED);
	ret = dax_iomap_fault(vmf, pe_size, &xfs_iomap_ops);
	xfs_iunlock(XFS_I(inode), XFS_MMAPLOCK_SHARED);

	if (vmf->flags & FAULT_FLAG_WRITE)
		sb_end_pagefault(inode->i_sb);

	return ret;
}

/*
 * pfn_mkwrite was originally inteneded to ensure we capture time stamp
 * updates on write faults. In reality, it's need to serialise against
 * truncate similar to page_mkwrite. Hence we cycle the XFS_MMAPLOCK_SHARED
 * to ensure we serialise the fault barrier in place.
 */
static int
xfs_filemap_pfn_mkwrite(
	struct vm_area_struct	*vma,
	struct vm_fault		*vmf)
{

	struct inode		*inode = file_inode(vma->vm_file);
	struct xfs_inode	*ip = XFS_I(inode);
	int			ret = VM_FAULT_NOPAGE;
	loff_t			size;

	trace_xfs_filemap_pfn_mkwrite(ip);

	sb_start_pagefault(inode->i_sb);
	file_update_time(vma->vm_file);

	/* check if the faulting page hasn't raced with truncate */
	xfs_ilock(ip, XFS_MMAPLOCK_SHARED);
	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (vmf->pgoff >= size)
		ret = VM_FAULT_SIGBUS;
	else if (IS_DAX(inode))
		ret = dax_pfn_mkwrite(vma, vmf);
	xfs_iunlock(ip, XFS_MMAPLOCK_SHARED);
	sb_end_pagefault(inode->i_sb);
	return ret;

}

static const struct vm_operations_struct xfs_file_vm_ops = {
	.fault		= xfs_filemap_fault,
	.huge_fault	= xfs_filemap_huge_fault,
	.page_mkwrite	= xfs_filemap_page_mkwrite,
	.remap_pages	= generic_file_remap_pages,
	.pfn_mkwrite	= xfs_filemap_pfn_mkwrite,
};

STATIC int
xfs_file_mmap(
	struct file	*filp,
	struct vm_area_struct *vma)
{
	file_accessed(filp);
	vma->vm_ops = &xfs_file_vm_ops;
	if (IS_DAX(file_inode(filp)))
		vma->vm_flags |= VM_MIXEDMAP | VM_HUGEPAGE;
	vma->vm_flags2 |= VM_PFN_MKWRITE | VM_HUGE_FAULT;
	return 0;
}

const struct file_operations xfs_file_operations = {
	.llseek		= xfs_file_llseek,
	.read		= do_sync_read,
	.write		= do_sync_write,
	.aio_read	= xfs_file_aio_read,
	.aio_write	= xfs_file_aio_write,
	.splice_read	= xfs_file_splice_read,
	.splice_write	= xfs_file_splice_write,
	.unlocked_ioctl	= xfs_file_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= xfs_file_compat_ioctl,
#endif
	.mmap		= xfs_file_mmap,
	.open		= xfs_file_open,
	.release	= xfs_file_release,
	.fsync		= xfs_file_fsync,
	.get_unmapped_area = thp_get_unmapped_area,
	.fallocate	= xfs_file_fallocate,
};

const struct file_operations xfs_dir_file_operations = {
	.open		= xfs_dir_open,
	.read		= generic_read_dir,
	.readdir	= xfs_file_readdir,
	.llseek		= generic_file_llseek,
	.unlocked_ioctl	= xfs_file_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= xfs_file_compat_ioctl,
#endif
	.fsync		= xfs_dir_fsync,
};
