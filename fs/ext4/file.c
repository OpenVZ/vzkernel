/*
 *  linux/fs/ext4/file.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext4 fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 *	(jj@sunsite.ms.mff.cuni.cz)
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/iomap.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/dax.h>
#include <linux/aio.h>
#include <linux/quotaops.h>
#include <linux/pagevec.h>
#include <linux/mman.h>
#include "ext4.h"
#include "ext4_jbd2.h"
#include "xattr.h"
#include "acl.h"

/*
 * Called when an inode is released. Note that this is different
 * from ext4_file_open: open gets called at every open, but release
 * gets called only when /all/ the files are closed.
 */
static int ext4_release_file(struct inode *inode, struct file *filp)
{
	if (ext4_test_inode_state(inode, EXT4_STATE_DA_ALLOC_CLOSE)) {
		ext4_alloc_da_blocks(inode);
		ext4_clear_inode_state(inode, EXT4_STATE_DA_ALLOC_CLOSE);
	}
	/* if we are the last writer on the inode, drop the block reservation */
	if ((filp->f_mode & FMODE_WRITE) &&
	    (atomic_read(&inode->i_writecount) == 1)) {
		if (ext4_test_inode_state(inode, EXT4_STATE_PFCACHE_CSUM))
			ext4_commit_data_csum(inode);
		if (!EXT4_I(inode)->i_reserved_data_blocks) {
			down_write(&EXT4_I(inode)->i_data_sem);
			ext4_discard_preallocations(inode);
			up_write(&EXT4_I(inode)->i_data_sem);
		}
	}
	if (is_dx(inode) && filp->private_data)
		ext4_htree_free_dir_info(filp->private_data);

	return 0;
}

static void ext4_unwritten_wait(struct inode *inode)
{
	wait_queue_head_t *wq = ext4_ioend_wq(inode);

	wait_event(*wq, (atomic_read(&EXT4_I(inode)->i_unwritten) == 0));
}

/*
 * This tests whether the IO in question is block-aligned or not.
 * Ext4 utilizes unwritten extents when hole-filling during direct IO, and they
 * are converted to written only after the IO is complete.  Until they are
 * mapped, these blocks appear as holes, so dio_zero_block() will assume that
 * it needs to zero out portions of the start and/or end block.  If 2 AIO
 * threads are at work on the same unwritten block, they must be synchronized
 * or one thread will zero the other's data, causing corruption.
 */
static int
ext4_unaligned_aio(struct inode *inode, size_t count, loff_t pos)
{
	struct super_block *sb = inode->i_sb;
	int blockmask = sb->s_blocksize - 1;
	loff_t final_size = pos + count;

	if (pos >= ALIGN(i_size_read(inode), sb->s_blocksize))
		return 0;

	if ((pos & blockmask) || (final_size & blockmask))
		return 1;

	return 0;
}

/* Is IO overwriting allocated and initialized blocks? */
static bool ext4_overwrite_io(struct inode *inode, loff_t pos, loff_t len)
{
	struct ext4_map_blocks map;
	unsigned int blkbits = inode->i_blkbits;
	int err, blklen;

	if (pos + len > i_size_read(inode))
		return false;

	map.m_lblk = pos >> blkbits;
	map.m_len = (EXT4_BLOCK_ALIGN(pos + len, blkbits) >> blkbits)
		- map.m_lblk;
	blklen = map.m_len;

	err = ext4_map_blocks(NULL, inode, &map, 0);
	/*
	 * 'err==len' means that all of the blocks have been preallocated,
	 * regardless of whether they have been initialized or not. To exclude
	 * unwritten extents, we need to check m_flags.
	 */
	return err == blklen && (map.m_flags & EXT4_MAP_MAPPED);
}

static ssize_t ext4_write_checks(struct kiocb *iocb, struct iov_iter *iter, loff_t *pos)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(iocb->ki_filp);
	size_t length = iov_iter_count(iter);
	ssize_t ret;

	ret = generic_write_checks(file, pos, &length, S_ISBLK(inode->i_mode));
	if (ret < 0)
		return ret;

	iocb->ki_pos = *pos;

	/*
	 * If we have encountered a bitmap-format file, the size limit
	 * is smaller than s_maxbytes, which is for extent-mapped files.
	 */
	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))) {
		struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);

		if ((*pos > sbi->s_bitmap_maxbytes ||
		    (*pos == sbi->s_bitmap_maxbytes && length > 0)))
			return -EFBIG;

		if (*pos + length > sbi->s_bitmap_maxbytes) {
			int err;

			err = iov_iter_shorten(iter,
					      sbi->s_bitmap_maxbytes - *pos);
			if (WARN_ON_ONCE(err))
				return err;
		}
	}
	return iov_iter_count(iter);
}

static ssize_t
ext4_file_dio_write(struct kiocb *iocb, struct iov_iter *iter, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct blk_plug plug;
	int unaligned_aio = 0;
	ssize_t ret;
	int overwrite = 0;
	size_t count = iov_iter_count(iter);

	if (ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS) &&
	    !is_sync_kiocb(iocb))
		unaligned_aio = ext4_unaligned_aio(inode, count, pos);

	/* Unaligned direct AIO must be serialized; see comment above */
	if (unaligned_aio) {
		mutex_lock(ext4_aio_mutex(inode));
		ext4_unwritten_wait(inode);
	}

	BUG_ON(iocb->ki_pos != pos);

	mutex_lock(&inode->i_mutex);
	blk_start_plug(&plug);

	iocb->private = &overwrite;

	/* Check whether we do a DIO overwrite or not */
	if (ext4_should_dioread_nolock(inode) && !unaligned_aio &&
	    ext4_overwrite_io(inode, iocb->ki_pos, count))
		overwrite = 1;

	ret = __generic_file_write_iter(iocb, iter, &iocb->ki_pos);
	/*
	 * Unaligned direct AIO must be the only IO in flight. Otherwise
	 * overlapping aligned IO after unaligned might result in data
	 * corruption.
	 */
	if (ret == -EIOCBQUEUED && unaligned_aio)
		ext4_unwritten_wait(inode);
	mutex_unlock(&inode->i_mutex);

	if (ret > 0) {
		ssize_t err;

		err = generic_write_sync(file, pos, ret);
		if (err < 0 && ret > 0)
			ret = err;
	}
	blk_finish_plug(&plug);

	if (unaligned_aio)
		mutex_unlock(ext4_aio_mutex(inode));

	return ret;
}

#ifdef CONFIG_FS_DAX
static ssize_t
ext4_file_dax_write(
	struct kiocb		*iocb,
	struct iov_iter		*iter,
	loff_t			pos)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t			ret;
	size_t			size = iov_iter_count(iter);

	inode_lock(inode);
	ret = ext4_write_checks(iocb, iter, &pos);
	if (ret < 0)
		goto out;
	ret = file_remove_privs(iocb->ki_filp);
	if (ret)
		goto out;
	ret = file_update_time(iocb->ki_filp);
	if (ret)
		goto out;
	ret = dax_iomap_rw(WRITE, iocb, iter, pos,
					size, &ext4_iomap_ops);
out:
	inode_unlock(inode);

	if (ret > 0) {
		int err;
		err = generic_write_sync(iocb->ki_filp, pos, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}
#endif

static ssize_t
ext4_file_write_iter(struct kiocb *iocb, struct iov_iter *iter, loff_t pos)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;
	int overwrite = 0;

	ret = ext4_write_checks(iocb, iter, &pos);
	if (ret <= 0)
		return ret;

#ifdef CONFIG_FS_DAX
	if (IS_DAX(inode))
		return ext4_file_dax_write(iocb, iter, pos);
#endif

	iocb->private = &overwrite; /* RHEL7 only - prevent DIO race */
	if (unlikely(io_is_direct(iocb->ki_filp)))
		ret = ext4_file_dio_write(iocb, iter, pos);
	else
		ret = generic_file_write_iter(iocb, iter, pos);

	return ret;
}

static ssize_t
ext4_file_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	struct iov_iter iter;

	iov_iter_init(&iter, iov, nr_segs, iov_length(iov, nr_segs), 0);

	return ext4_file_write_iter(iocb, &iter, pos);
}

#ifdef CONFIG_FS_DAX
static int ext4_dax_huge_fault(struct vm_fault *vmf,
		enum page_entry_size pe_size)
{
	int result, error = 0;
	int retries = 0;
	handle_t *handle = NULL;
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct super_block *sb = inode->i_sb;

	/*
	 * We have to distinguish real writes from writes which will result in a
	 * COW page; COW writes should *not* poke the journal (the file will not
	 * be changed). Doing so would cause unintended failures when mounted
	 * read-only.
	 *
	 * We check for VM_SHARED rather than vmf->cow_page since the latter is
	 * unset for pe_size != PE_SIZE_PTE (i.e. only in do_cow_fault); for
	 * other sizes, dax_iomap_fault will handle splitting / fallback so that
	 * we eventually come back with a COW page.
	 */
	bool write = (vmf->flags & FAULT_FLAG_WRITE) &&
		(vmf->vma->vm_flags & VM_SHARED);
	pfn_t pfn;

	if (write) {
		sb_start_pagefault(sb);
		file_update_time(vmf->vma->vm_file);
		down_read(&EXT4_I(inode)->i_mmap_sem);
retry:
		handle = ext4_journal_start_sb(sb, EXT4_HT_WRITE_PAGE,
					       EXT4_DATA_TRANS_BLOCKS(sb));
		if (IS_ERR(handle)) {
			up_read(&EXT4_I(inode)->i_mmap_sem);
			sb_end_pagefault(sb);
			return VM_FAULT_SIGBUS;
		}
	} else {
		down_read(&EXT4_I(inode)->i_mmap_sem);
	}
	result = dax_iomap_fault(vmf, pe_size, &pfn, &error, &ext4_iomap_ops);
	if (write) {
		ext4_journal_stop(handle);

		if ((result & VM_FAULT_ERROR) && error == -ENOSPC &&
		    ext4_should_retry_alloc(sb, &retries))
			goto retry;
		/* Handling synchronous page fault? */
		if (result & VM_FAULT_NEEDDSYNC)
			result = dax_finish_sync_fault(vmf, pe_size, pfn);
		up_read(&EXT4_I(inode)->i_mmap_sem);
		sb_end_pagefault(sb);
	} else {
		up_read(&EXT4_I(inode)->i_mmap_sem);
	}

	return result;
}

static inline int ext4_dax_fault(struct vm_area_struct *vma,
		struct vm_fault *vmf)
{
	return ext4_dax_huge_fault(vmf, PE_SIZE_PTE);
}

static const struct vm_operations_struct ext4_dax_vm_ops = {
	.fault		= ext4_dax_fault,
	.huge_fault	= ext4_dax_huge_fault,
	.page_mkwrite	= ext4_dax_fault,
	.pfn_mkwrite	= ext4_dax_fault,
};
#else
#define ext4_dax_vm_ops	ext4_file_vm_ops
#endif

static const struct vm_operations_struct ext4_file_vm_ops = {
	.fault		= ext4_filemap_fault,
	.page_mkwrite   = ext4_page_mkwrite,
	.map_pages	= filemap_map_pages,
};

static int ext4_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file->f_inode;

	/*
	 * f_op->mmap must be called with vma=NULL before taking mmap_sem;
	 * workaround for wrong i_mutex vs mmap_sem lock ordering in pfcache
	 * (PSBM-23133) - vdavydov@
	 */
	if (!vma) {
		if (ext4_test_inode_state(inode, EXT4_STATE_PFCACHE_CSUM)) {
			mutex_lock(&inode->i_mutex);
			ext4_truncate_data_csum(inode, -1);
			mutex_unlock(&inode->i_mutex);
		}
		return 0;
	}

	/*
	 * We don't support synchronous mappings for non-DAX files. At least
	 * until someone comes with a sensible use case.
	 */
	if (!IS_DAX(file_inode(file)) && (vma->vm_flags & VM_SYNC))
		return -EOPNOTSUPP;

	file_accessed(file);
	if (IS_DAX(file_inode(file))) {
		vma->vm_ops = &ext4_dax_vm_ops;
		vma->vm_flags |= VM_HUGEPAGE;
		vma->vm_flags2 |= VM_PFN_MKWRITE | VM_HUGE_FAULT;
	} else {
		vma->vm_ops = &ext4_file_vm_ops;
	}
	return 0;
}

static int ext4_sample_last_mounted(struct super_block *sb,
				    struct vfsmount *mnt)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	struct path path;
	char buf[64], *cp;
	handle_t *handle;
	int err;

	if (likely(sbi->s_mount_flags & EXT4_MF_MNTDIR_SAMPLED))
		return 0;

	if ((sb->s_flags & MS_RDONLY) || !sb_start_intwrite_trylock(sb))
		return 0;

	sbi->s_mount_flags |= EXT4_MF_MNTDIR_SAMPLED;
	/*
	 * Sample where the filesystem has been mounted and
	 * store it in the superblock for sysadmin convenience
	 * when trying to sort through large numbers of block
	 * devices or filesystem images.
	 */
	memset(buf, 0, sizeof(buf));
	path.mnt = mnt;
	path.dentry = mnt->mnt_root;
	cp = d_path(&path, buf, sizeof(buf));
	err = 0;
	if (IS_ERR(cp))
		goto out;

	handle = ext4_journal_start_sb(sb, EXT4_HT_MISC, 1);
	err = PTR_ERR(handle);
	if (IS_ERR(handle))
		goto out;
	BUFFER_TRACE(sbi->s_sbh, "get_write_access");
	err = ext4_journal_get_write_access(handle, sbi->s_sbh);
	if (err)
		goto out_journal;
	strlcpy(sbi->s_es->s_last_mounted, cp,
		sizeof(sbi->s_es->s_last_mounted));
	ext4_handle_dirty_super(handle, sb);
out_journal:
	ext4_journal_stop(handle);
out:
	sb_end_intwrite(sb);
	return err;
}

static int ext4_file_open(struct inode * inode, struct file * filp)
{
	int ret;

	ret = ext4_sample_last_mounted(inode->i_sb, filp->f_path.mnt);
	if (ret)
		return ret;

	/*
	 * Set up the jbd2_inode if we are opening the inode for
	 * writing and the journal is present
	 */
	if (filp->f_mode & FMODE_WRITE) {
		ret = ext4_inode_attach_jinode(inode);
		if (ret < 0)
			return ret;
	}

	if ((filp->f_mode & FMODE_WRITE) && inode->i_mapping->i_peer_file) {
		mutex_lock(&inode->i_mutex);
		ext4_close_pfcache(inode);
		mutex_unlock(&inode->i_mutex);
	}

	return dquot_file_open(inode, filp);
}

/*
 * ext4_llseek() handles both block-mapped and extent-mapped maxbytes values
 * by calling generic_file_llseek_size() with the appropriate maxbytes
 * value for each.
 */
loff_t ext4_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	loff_t maxbytes;

	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)))
		maxbytes = EXT4_SB(inode->i_sb)->s_bitmap_maxbytes;
	else
		maxbytes = inode->i_sb->s_maxbytes;

	switch (whence) {
	default:
		return generic_file_llseek_size(file, offset, whence,
						maxbytes, i_size_read(inode));
	case SEEK_HOLE:
		inode_lock(inode);
		offset = iomap_seek_hole(inode, offset, &ext4_iomap_ops);
		inode_unlock(inode);
		break;
	case SEEK_DATA:
		inode_lock(inode);
		offset = iomap_seek_data(inode, offset, &ext4_iomap_ops);
		inode_unlock(inode);
		break;
	}

	if (offset < 0)
		return offset;
	return vfs_setpos(file, offset, maxbytes);
}

#ifdef CONFIG_FS_DAX
static ssize_t
ext4_file_dax_read(
	struct kiocb		*iocb,
	const struct iovec	*iovp,
	unsigned long		nr_segs,
	loff_t			pos)
{
	size_t			size = iov_length(iovp, nr_segs);
	ssize_t			ret = 0;
	struct inode *inode = file_inode(iocb->ki_filp);
	struct iov_iter iter;

	if (!size)
		return 0; /* skip atime */

	inode_lock(inode);
	/*
	 * Recheck under inode lock - at this point we are sure it cannot
	 * change anymore
	 */
	if (!IS_DAX(inode)) {
		inode_unlock(inode);
		/* Fallback to buffered IO in case we cannot support DAX */
		return generic_file_aio_read(iocb, iovp, nr_segs, pos);
	}

	iov_iter_init(&iter, iovp, nr_segs, size, 0);

	ret = dax_iomap_rw(READ, iocb, &iter, pos,
					size, &ext4_iomap_ops);
	inode_unlock(inode);

	file_accessed(iocb->ki_filp);
	return ret;
}
#endif

static ssize_t
ext4_file_read(
	struct kiocb		*iocb,
	const struct iovec	*iovp,
	unsigned long		nr_segs,
	loff_t 			pos)
{
#ifdef CONFIG_FS_DAX
	if (IS_DAX(file_inode(iocb->ki_filp)))
		return ext4_file_dax_read(iocb, iovp, nr_segs, pos);
#endif
	return generic_file_aio_read(iocb, iovp, nr_segs, pos);
}

const struct file_operations_extend  ext4_file_operations = {
	.kabi_fops = {
		.llseek		= ext4_llseek,
		.read		= do_sync_read,
		.write		= do_sync_write,
		.aio_read	= ext4_file_read,
		.aio_write	= ext4_file_write,
		.unlocked_ioctl = ext4_ioctl,
#ifdef CONFIG_COMPAT
		.compat_ioctl	= ext4_compat_ioctl,
#endif
		.mmap		= ext4_file_mmap,
		.open		= ext4_file_open,
		.release	= ext4_release_file,
		.fsync		= ext4_sync_file,
		.get_unmapped_area = thp_get_unmapped_area,
		.splice_read	= generic_file_splice_read,
		.splice_write	= generic_file_splice_write,
		.fallocate	= ext4_fallocate,
	},
	.mmap_supported_flags = MAP_SYNC,
};

const struct inode_operations ext4_file_inode_operations = {
	.setattr	= ext4_setattr,
	.getattr	= ext4_getattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= ext4_listxattr,
	.removexattr	= generic_removexattr,
	.get_acl	= ext4_get_acl,
	.fiemap		= ext4_fiemap,
};

