#include <linux/module.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/bio.h>
#include <linux/pagemap.h>
#include <linux/blkdev.h>
#include <linux/kthread.h>
#include <linux/mount.h>
#include <linux/buffer_head.h>
#include <linux/falloc.h>
#include <linux/magic.h>

#include <linux/ploop/ploop.h>
#include <linux/ploop/ploop_if.h>
#include <linux/ploop/compat.h>
#include "ploop_events.h"
#include "io_direct_map.h"

#define CREATE_TRACE_POINTS
#include "io_direct_events.h"

/* from fs/ext4/ext4.h */
#define EXT4_EXTENTS_FL			0x00080000

#define MIN(a, b) (a < b ? a : b)

#define PLOOP_MAX_PREALLOC(plo) (128 * 1024 * 1024) /* 128MB */

#define PLOOP_MAX_EXTENT_MAP (64 * 1024 * 1024)    /* 64MB */
int max_extent_map_pages __read_mostly;
int min_extent_map_entries __read_mostly;

/* total sum of m->size for all ploop_mapping structs */
atomic_long_t ploop_io_images_size = ATOMIC_LONG_INIT(0);

/* Direct IO from/to file.
 *
 * Holes in image file are not allowed.
 */

static inline sector_t
dio_isec_to_phys(struct extent_map * em, sector_t isec)
{
	return (isec - em->start) + em->block_start;
}

DEFINE_BIO_CB(dio_endio_async)
{
	struct ploop_request * preq = bio->bi_private;

	if (!err && !bio_flagged(bio, BIO_UPTODATE))
		err = -EIO;
	if (err)
		PLOOP_REQ_SET_ERROR(preq, err);

	ploop_complete_io_request(preq);

	bio_put(bio);
}
END_BIO_CB(dio_endio_async)

struct bio_list_walk
{
	struct bio * cur;
	int idx;
	int bv_off;
};

static int cached_submit(struct ploop_io *io, iblock_t iblk,
	      struct ploop_request * preq,
	      struct bio_list * sbl, unsigned int size);

static void
dio_submit(struct ploop_io *io, struct ploop_request * preq,
	   unsigned long rw,
	   struct bio_list *sbl, iblock_t iblk, unsigned int size)
{
	struct bio_list bl;
	struct bio * bio = NULL;
	struct extent_map * em;
	sector_t sec, nsec;
	int err;
	struct bio_list_walk bw;
	int preflush;
	int postfua = 0;
	int write = !!(rw & REQ_WRITE);
	int bio_num;

	trace_submit(preq);

	preflush = !!(rw & REQ_FLUSH);

	if (test_and_clear_bit(PLOOP_REQ_FORCE_FLUSH, &preq->state))
		preflush = 1;

	if (test_and_clear_bit(PLOOP_REQ_FORCE_FUA, &preq->state))
		postfua = 1;

	if (!postfua && ploop_req_delay_fua_possible(rw, preq)) {

		/* Mark req that delayed flush required */
		set_bit(PLOOP_REQ_FORCE_FLUSH, &preq->state);
	} else if (rw & REQ_FUA) {
		postfua = 1;
	}

	rw &= ~(REQ_FLUSH | REQ_FUA);


	/* In case of eng_state != COMPLETE, we'll do FUA in
	 * ploop_index_update(). Otherwise, we should mark
	 * last bio as FUA here. */
	if (rw & REQ_FUA) {
		rw &= ~REQ_FUA;
		if (preq->eng_state == PLOOP_E_COMPLETE)
			postfua = 1;
	}

	bio_list_init(&bl);

	if (iblk == PLOOP_ZERO_INDEX)
		iblk = 0;

	if ((rw & REQ_WRITE) &&
	    !(io->files.file->f_mode & FMODE_WRITE)) {
		err = -EBADF;
		goto out;
	}

	sec = sbl->head->bi_sector;
	sec = ((sector_t)iblk << preq->plo->cluster_log) | (sec & ((1<<preq->plo->cluster_log) - 1));

	em = extent_lookup_create(io, sec, size);
	if (IS_ERR(em))
		goto out_em_err;

	if (write && em->block_start == BLOCK_UNINIT) {
		sector_t end = (sector_t)(iblk + 1) << preq->plo->cluster_log;
		sec = (sector_t)iblk << preq->plo->cluster_log;

		if (em->start <= sec)
			sec = em->end;
		extent_put(em);

		while (sec < end) {
			em = extent_lookup_create(io, sec, end - sec);
			if (IS_ERR(em))
				goto out_em_err;
			if (em->block_start != BLOCK_UNINIT)
				goto write_unint_fail;

			sec = em->end;
			extent_put(em);
		}

		goto write_unint;
	}

	ploop_prepare_io_request(preq);
	if (rw & REQ_WRITE)
		ploop_prepare_tracker(preq, sec);

	bw.cur = sbl->head;
	bw.idx = 0;
	bw.bv_off = 0;
	BUG_ON(bw.cur->bi_io_vec[0].bv_len & 511);

	bio = NULL;

	while (size > 0) {
		struct bio_vec * bv;
		int copy;

		bv = bw.cur->bi_io_vec + bw.idx;

		if (bw.bv_off >= bv->bv_len) {
			bw.idx++;
			bv++;
			bw.bv_off = 0;
			if (bw.idx >= bw.cur->bi_vcnt) {
				bw.cur = bw.cur->bi_next;
				bw.idx = 0;
				bv = bw.cur->bi_io_vec;
			}
			BUG_ON(bv->bv_len & 511);
		}

		if (sec >= em->end) {
			extent_put(em);
			em = extent_lookup_create(io, sec, size);
			if (IS_ERR(em))
				goto out_em_err;
			if (write && em->block_start == BLOCK_UNINIT)
				goto write_unint_fail;
		}

		nsec = dio_isec_to_phys(em, sec);

		if (em->block_start != BLOCK_UNINIT &&
		     (bio == NULL ||
		     bio->bi_sector + (bio->bi_size>>9) != nsec)) {

flush_bio:
			bio = bio_alloc(GFP_NOFS, 32);
			if (bio == NULL)
				goto enomem;
			bio_list_add(&bl, bio);
			bio->bi_bdev = io->files.bdev;
			bio->bi_sector = nsec;
		}

		copy = bv->bv_len - bw.bv_off;
		if (copy > ((em->end - sec) << 9))
			copy = (em->end - sec) << 9;

		if (em->block_start == BLOCK_UNINIT) {
			void *kaddr = kmap_atomic(bv->bv_page);
			memset(kaddr + bv->bv_offset + bw.bv_off, 0, copy);
			kunmap_atomic(kaddr);
		} else if (bio_add_page(bio, bv->bv_page, copy,
				 bv->bv_offset + bw.bv_off) != copy) {
			/* Oops, this chunk does not fit. Flush and start
			 * fresh bio.
			 */
			goto flush_bio;
		}

		bw.bv_off += copy;
		size -= copy >> 9;
		sec += copy >> 9;
	}
	extent_put(em);

	bio_num = 0;
	while (bl.head) {
		struct bio * b = bl.head;
		unsigned long rw2 = rw;

		bl.head = b->bi_next;
		atomic_inc(&preq->io_count);
		b->bi_next = NULL;
		b->bi_private = preq;
		b->bi_end_io = dio_endio_async;

		if (unlikely(preflush)) {
			rw2 |= REQ_FLUSH;
			preflush = 0;
		}
		if (unlikely(postfua && !bl.head))
			rw2 |= (REQ_FUA | ((bio_num) ? REQ_FLUSH : 0));

		ploop_acc_ff_out(preq->plo, rw2 | b->bi_rw);
		submit_bio(rw2, b);
		bio_num++;
	}

	ploop_complete_io_request(preq);
	return;


enomem:
	err = -ENOMEM;
	goto out;

write_unint:
	spin_lock_irq(&preq->plo->lock);
	ploop_add_lockout(preq, 0);
	spin_unlock_irq(&preq->plo->lock);

	err = cached_submit(io, iblk, preq, sbl, size);
	goto out;

write_unint_fail:
	extent_put(em);
	err = -EIO;
	ploop_msg_once(io->plo, "A part of cluster is in uninitialized extent.");
	goto out;

out_em_err:
	err = PTR_ERR(em);
out:
	while (bl.head) {
		struct bio * b = bl.head;
		bl.head = b->bi_next;
		b->bi_next = NULL;
		bio_put(b);
	}

	if (err)
		PLOOP_FAIL_REQUEST(preq, err);
}

struct bio_iter {
	struct bio     *bio;  /* traverses sbl */
	struct bio_vec *bv;   /* traverses bio->bi_io_vec */
	int             off;  /* offset in bv payload:
			       * 0 <= off < bv->bv_len */
};

static inline void bio_iter_init(struct bio_iter *biter, struct bio_list *sbl)
{
	biter->bio  = sbl->head;
	biter->bv   = biter->bio->bi_io_vec;
	biter->off  = 0;
}

static inline void bio_iter_advance(struct bio_iter *biter, int len)
{
	if (biter->bv->bv_len - biter->off > len) {
		biter->off += len;
		return;
	}

	BUG_ON (biter->bv->bv_len - biter->off != len);

	biter->bv++;
	biter->off = 0;

	if (biter->bv - biter->bio->bi_io_vec < biter->bio->bi_vcnt)
		return;

	biter->bio = biter->bio->bi_next;
	if (biter->bio)
		biter->bv = biter->bio->bi_io_vec;
}

static void bcopy_from_blist(struct page *page, int dst_off, /* dst */
			     struct bio_iter *biter,         /* src */
			     int copy_len)                   /* len */
{
	u8 *kdst = kmap_atomic(page);

	while (copy_len > 0) {
		u8 *ksrc;
		int copy = MIN(copy_len, biter->bv->bv_len - biter->off);

		ksrc = kmap_atomic(biter->bv->bv_page);
		memcpy(kdst + dst_off,
		       ksrc + biter->bv->bv_offset + biter->off,
		       copy);
		kunmap_atomic(ksrc);

		copy_len -= copy;
		dst_off  += copy;
		bio_iter_advance(biter, copy);
		BUG_ON (copy_len && !biter->bio);
	}

	kunmap_atomic(kdst);
}

static inline void bzero_page(struct page *page)
{
	void *kaddr = kmap_atomic(page);

	memset(kaddr, 0, PAGE_SIZE);

	kunmap_atomic(kaddr);
}


static int
cached_submit(struct ploop_io *io, iblock_t iblk, struct ploop_request * preq,
	      struct bio_list * sbl, unsigned int size)
{
	struct ploop_device * plo = preq->plo;
	int err = 0;
	loff_t pos, end_pos, start, end;
	loff_t clu_siz = 1 << (plo->cluster_log + 9);
	struct bio_iter biter;
	loff_t new_size;

	trace_cached_submit(preq);

	pos = (loff_t)iblk << (plo->cluster_log + 9);
	end_pos = pos + clu_siz;

	if (end_pos > i_size_read(io->files.inode) &&
	    io->files.file->f_op->fallocate &&
	    io->files.flags & EXT4_EXTENTS_FL) {
		if (unlikely(io->prealloced_size < clu_siz)) {
			loff_t prealloc = end_pos;
			if (prealloc > PLOOP_MAX_PREALLOC(plo))
				prealloc = PLOOP_MAX_PREALLOC(plo);
try_again:
			err = io->files.file->f_op->fallocate(io->files.file, 0,
							       pos, prealloc);
			if (err) {
				if (err == -ENOSPC && prealloc != clu_siz) {
					prealloc = clu_siz;
					goto try_again;
				} else {
					return err;
				}
			}

			io->prealloced_size = prealloc;
		}

		io->prealloced_size -= clu_siz;
	}

	bio_iter_init(&biter, sbl);
	mutex_lock(&io->files.inode->i_mutex);

	start = pos + ((sbl->head->bi_sector & ((1<<plo->cluster_log)-1)) << 9);
	end = start + (size << 9);
	ploop_prepare_tracker(preq, start>>9);

	while (pos < end_pos) {
		struct page * page;
		void * fsdata;

		err = pagecache_write_begin(io->files.file, io->files.mapping,
					    pos, PAGE_CACHE_SIZE, 0,
					    &page, &fsdata);
		if (err)
			break;

		if (pos < start || pos + PAGE_CACHE_SIZE > end)
			bzero_page(page);

		if (pos < end && pos + PAGE_CACHE_SIZE > start) {
			int dst_off = 0;
			int copy_len = PAGE_CACHE_SIZE;

			if (pos < start) {
				dst_off = start - pos;
				copy_len -= dst_off;
				if (pos + PAGE_CACHE_SIZE > end)
					copy_len = end - start;
			} else {
				if (pos + PAGE_CACHE_SIZE > end)
					copy_len = end - pos;
			}

			bcopy_from_blist(page, dst_off, &biter, copy_len);
		}

		err = pagecache_write_end(io->files.file, io->files.mapping,
					  pos, PAGE_CACHE_SIZE, PAGE_CACHE_SIZE,
					  page, &fsdata);
		if (err != PAGE_CACHE_SIZE) {
			if (err >= 0)
				err = -EIO;
			break;
		}
		err = 0;

		pos += PAGE_CACHE_SIZE;
	}
	mutex_unlock(&io->files.inode->i_mutex);

	new_size = i_size_read(io->files.inode);
	atomic_long_add(new_size - *io->size_ptr, &ploop_io_images_size);
	*io->size_ptr = new_size;

	if (!err)
		err = filemap_fdatawrite(io->files.mapping);

	if (!err) {
		spin_lock_irq(&plo->lock);
		ploop_acc_flush_skip_locked(plo, preq->req_rw);
		preq->iblock = iblk;
		list_add_tail(&preq->list, &io->fsync_queue);
		plo->st.bio_syncwait++;
		if ((test_bit(PLOOP_REQ_SYNC, &preq->state) ||
		     ++io->fsync_qlen >= plo->tune.fsync_max) &&
		    waitqueue_active(&io->fsync_waitq))
			wake_up_interruptible(&io->fsync_waitq);
		else if (!timer_pending(&io->fsync_timer))
			mod_timer(&io->fsync_timer, jiffies + plo->tune.fsync_delay);
		spin_unlock_irq(&plo->lock);
	}
	return err;
}

/* Submit the whole cluster. If preq contains only partial data
 * within the cluster, pad the rest of cluster with zeros.
 */
static void
dio_submit_pad(struct ploop_io *io, struct ploop_request * preq,
	       struct bio_list * sbl, unsigned int size,
	       struct extent_map *em)
{
	struct bio_list bl;
	struct bio * bio = NULL;
	sector_t sec, end_sec, nsec, start, end;
	struct bio_list_walk bw;
	int err;
	int preflush = !!(preq->req_rw & REQ_FLUSH);

	bio_list_init(&bl);

	/* sec..end_sec is the range which we are going to write */
	sec = (sector_t)preq->iblock << preq->plo->cluster_log;
	end_sec = sec + (1 << preq->plo->cluster_log);

	/* start..end is data that we have. The rest must be zero padded. */
	start = sec + (sbl->head->bi_sector & ((1<<preq->plo->cluster_log) - 1));
	end = start + size;

	if (IS_ERR(em))
		goto out_em_err;

#if 1
	/* GCC, shut up! */
	bw.cur = sbl->head;
	bw.idx = 0;
	bw.bv_off = 0;
	BUG_ON(bw.cur->bi_io_vec[0].bv_len & 511);
#endif

	ploop_prepare_io_request(preq);
	ploop_prepare_tracker(preq, start);

	bio = NULL;

	while (sec < end_sec) {
		struct page * page;
		unsigned int poff, plen;

		if (sec < start) {
			page = ZERO_PAGE(0);
			poff = 0;
			plen = start - sec;
			if (plen > (PAGE_SIZE>>9))
				plen = (PAGE_SIZE>>9);
		} else if (sec >= end) {
			page = ZERO_PAGE(0);
			poff = 0;
			plen = end_sec - sec;
			if (plen > (PAGE_SIZE>>9))
				plen = (PAGE_SIZE>>9);
		} else {
			/* sec >= start && sec < end */
			struct bio_vec * bv;

			if (sec == start) {
				bw.cur = sbl->head;
				bw.idx = 0;
				bw.bv_off = 0;
				BUG_ON(bw.cur->bi_io_vec[0].bv_len & 511);
			}
			bv = bw.cur->bi_io_vec + bw.idx;

			if (bw.bv_off >= bv->bv_len) {
				bw.idx++;
				bv++;
				bw.bv_off = 0;
				if (bw.idx >= bw.cur->bi_vcnt) {
					bw.cur = bw.cur->bi_next;
					bw.idx = 0;
					bw.bv_off = 0;
					bv = bw.cur->bi_io_vec;
				}
				BUG_ON(bv->bv_len & 511);
			}

			page = bv->bv_page;
			poff = bv->bv_offset + bw.bv_off;
			plen = (bv->bv_len - bw.bv_off) >> 9;
		}

		if (sec >= em->end) {
			extent_put(em);
			em = extent_lookup_create(io, sec, end_sec - sec);
			if (IS_ERR(em))
				goto out_em_err;
		}

		nsec = dio_isec_to_phys(em, sec);

		if (bio == NULL ||
		    bio->bi_sector + (bio->bi_size>>9) != nsec) {

flush_bio:
			bio = bio_alloc(GFP_NOFS, 32);
			if (bio == NULL)
				goto enomem;
			bio_list_add(&bl, bio);
			bio->bi_bdev = io->files.bdev;
			bio->bi_sector = nsec;
		}

		if (plen > em->end - sec)
			plen = em->end - sec;

		if (bio_add_page(bio, page, plen<<9, poff) != (plen<<9)) {
			/* Oops, this chunk does not fit. Flush and start
			 * new bio
			 */
			goto flush_bio;
		}

		bw.bv_off += (plen<<9);
		BUG_ON(plen == 0);
		sec += plen;
	}
	extent_put(em);

	while (bl.head) {
		unsigned long rw;
		struct bio * b = bl.head;

		bl.head = b->bi_next;
		atomic_inc(&preq->io_count);
		b->bi_next = NULL;
		b->bi_private = preq;
		b->bi_end_io = dio_endio_async;

		rw = sbl->head->bi_rw | WRITE;
		if (unlikely(preflush)) {
			rw |= REQ_FLUSH;
			preflush = 0;
		}
		ploop_acc_ff_out(preq->plo, rw | b->bi_rw);
		submit_bio(rw, b);
	}

	ploop_complete_io_request(preq);
	return;


enomem:
	err = -ENOMEM;
	goto out;

out_em_err:
	err = PTR_ERR(em);
out:
	while (bl.head) {
		struct bio * b = bl.head;
		bl.head = b->bi_next;
		b->bi_next = NULL;
		bio_put(b);
	}
	PLOOP_FAIL_REQUEST(preq, err);
}

static struct extent_map * dio_fallocate(struct ploop_io *io, u32 iblk, int nr)
{
	struct extent_map * em;
	mutex_lock(&io->files.inode->i_mutex);
	em = map_extent_get_block(io,
				  io->files.mapping,
				  (sector_t)iblk << io->plo->cluster_log,
				  1 << io->plo->cluster_log,
				  1, mapping_gfp_mask(io->files.mapping),
				  NULL);
	mutex_unlock(&io->files.inode->i_mutex);
	return em;
}


static void
dio_submit_alloc(struct ploop_io *io, struct ploop_request * preq,
		 struct bio_list * sbl, unsigned int size)
{
	int err;
	iblock_t iblk = io->alloc_head++;

	trace_submit_alloc(preq);

	if (!(io->files.file->f_mode & FMODE_WRITE)) {
		PLOOP_FAIL_REQUEST(preq, -EBADF);
		return;
	}

	/* io->fallocate is not a "posix" fallocate()!
	 *
	 * We require backing fs gave us _uninitialized_ blocks,
	 * otherwise it does not make sense to go that way.
	 *
	 * IMPORTANT: file _grows_ and dio_submit_alloc() cannot
	 * complete requests until i_size is commited to disk.
	 * Read this as: no hope to do this in a non-suboptimal way,
	 * linux updates i_size synchronously even when O_DIRECT AIO
	 * is requested. Even in PCSS we have to update i_size synchronously.
	 * Obviously, we will expand file by larger pieces
	 * and take some measures to avoid initialization of the blocks
	 * and the same time leakage of uninitizlized data
	 * to user of our device.
	 */
	if (io->files.em_tree->_get_extent) {
		struct extent_map * em;

		em = dio_fallocate(io, iblk, 1);
		if (unlikely(IS_ERR(em))) {
			PLOOP_FAIL_REQUEST(preq, PTR_ERR(em));
			return;
		}

		preq->iblock = iblk;
		preq->eng_state = PLOOP_E_DATA_WBI;

		dio_submit_pad(io, preq, sbl, size, em);
		return;
	}

	err = cached_submit(io, iblk, preq, sbl, size);
	if (err) {
		if (err == -ENOSPC)
			io->alloc_head--;
		PLOOP_FAIL_REQUEST(preq, err);
	}
	preq->eng_state = PLOOP_E_DATA_WBI;
}

/* When backing fs does not export any method to allocate new blocks
 * without initialization, we fallback to cached write with subsequent
 * fsync. Obviously, this is going to be utterly inefficient.
 *
 * Here is a workaround. We start writeback, but do not fsync()
 * immediately, but start a timer, which wakes up ploop_sync thread.
 *
 * Requests are queued to ploop_sync and when timer expires or we
 * have a lot of requests scheduled for sync, the thread call
 * real fsync.
 *
 * Still not sure this is an improvement. :-)
 */

static int dio_fsync_thread(void * data)
{
	struct ploop_io * io = data;
	struct ploop_device * plo = io->plo;

	set_user_nice(current, -20);

	spin_lock_irq(&plo->lock);
	while (!kthread_should_stop() || !list_empty(&io->fsync_queue)) {
		int err;
		LIST_HEAD(list);

		DEFINE_WAIT(_wait);
		for (;;) {
			prepare_to_wait(&io->fsync_waitq, &_wait, TASK_INTERRUPTIBLE);
			if (!list_empty(&io->fsync_queue) ||
			    kthread_should_stop())
				break;

			spin_unlock_irq(&plo->lock);
			schedule();
			spin_lock_irq(&plo->lock);
		}
		finish_wait(&io->fsync_waitq, &_wait);

		if (list_empty(&io->fsync_queue) && kthread_should_stop())
			break;

		INIT_LIST_HEAD(&list);
		list_splice_init(&io->fsync_queue, &list);
		spin_unlock_irq(&plo->lock);

		/* filemap_fdatawrite() has been made already */
		filemap_fdatawait(io->files.mapping);

		err = 0;
		if (io->files.file->f_op->fsync)
			err = io->files.file->f_op->FOP_FSYNC(io->files.file,
							      0);

		/* Do we need to invalidate page cache? Not really,
		 * because we use it only to create full new pages,
		 * which we overwrite completely. Probably, we should
		 * invalidate in a non-blocking way to reclaim memory
		 * faster than it happens with normal LRU logic.
		 */

		spin_lock_irq(&plo->lock);

		while (!list_empty(&list)) {
			struct ploop_request * preq;
			preq = list_entry(list.next, struct ploop_request, list);
			list_del(&preq->list);
			if (err)
				PLOOP_REQ_SET_ERROR(preq, err);
			list_add_tail(&preq->list, &plo->ready_queue);
			io->fsync_qlen--;
		}
		plo->st.bio_fsync++;

		if (test_bit(PLOOP_S_WAIT_PROCESS, &plo->state))
			wake_up_interruptible(&plo->waitq);
	}
	spin_unlock_irq(&plo->lock);
	return 0;
}

static int dio_fsync(struct file * file)
{
	int err, ret;
	struct address_space *mapping = file->f_mapping;

	ret = filemap_write_and_wait(mapping);
	err = 0;
	if (file->f_op && file->f_op->fsync) {
		err = file->f_op->FOP_FSYNC(file, 0);
		if (!ret)
			ret = err;
	}
	return ret;
}

/* Invalidate page cache. It is called with inode mutex taken
 * and mapping mapping must be synced. If some dirty pages remained,
 * it will fail.
 *
 * Retry with fs freeze is required to work around a race (bug?)
 * in ext3, where some blocks can be held by uncommited transaction.
 * The procedure is dangerous. No mutexes should be held, ploop
 * must not be quiesced.
 */

static int dio_invalidate_cache(struct address_space * mapping,
				struct block_device * bdev)
{
	int err;
	int attempt2 = 0;

retry:
	err = invalidate_inode_pages2(mapping);
	if (err) {
		printk("PLOOP: failed to invalidate page cache %d/%d\n", err, attempt2);
		if (attempt2)
			return err;
		attempt2 = 1;

		mutex_unlock(&mapping->host->i_mutex);
		thaw_bdev(bdev, freeze_bdev(bdev));
		mutex_lock(&mapping->host->i_mutex);
		goto retry;
	}
	return err;
}

static int dio_truncate(struct ploop_io *, struct file *, __u32);

static int dio_release_prealloced(struct ploop_io * io)
{
	int ret;

	if (!io->prealloced_size)
		return 0;

	ret = dio_truncate(io, io->files.file, io->alloc_head);
	if (ret)
		printk("Can't release %llu prealloced bytes: "
		       "truncate to %llu failed (%d)\n",
		       io->prealloced_size,
		       (loff_t)io->alloc_head << (io->plo->cluster_log + 9),
		       ret);
	else
		io->prealloced_size = 0;

	return ret;
}

static void dio_destroy(struct ploop_io * io)
{
	if (io->files.file) {
		struct file * file;
		struct ploop_delta * delta = container_of(io, struct ploop_delta, io);

		(void)dio_release_prealloced(io);

		if (io->files.em_tree) {
			io->files.em_tree = NULL;
			mutex_lock(&io->files.inode->i_mutex);
			ploop_dio_close(io, delta->flags & PLOOP_FMT_RDONLY);
			(void)dio_invalidate_cache(io->files.mapping, io->files.bdev);
			mutex_unlock(&io->files.inode->i_mutex);
		}

		del_timer_sync(&io->fsync_timer);

		if (io->fsync_thread) {
			kthread_stop(io->fsync_thread);
			io->fsync_thread = NULL;
		}

		file = io->files.file;
		mutex_lock(&delta->plo->sysfs_mutex);
		io->files.file = NULL;
		mutex_unlock(&delta->plo->sysfs_mutex);
		if (!(delta->flags & PLOOP_FMT_RDONLY))
			file_update_time(file);
		fput(file);
	}
}

static int dio_sync(struct ploop_io * io)
{
	struct file * file = io->files.file;

	if (file)
		dio_fsync(file);
	return 0;
}

static int dio_stop(struct ploop_io * io)
{
	struct file * file = io->files.file;

	if (file) {
		dio_fsync(file);
	}
	return 0;
}

static int dio_open(struct ploop_io * io)
{
	struct ploop_delta * delta = container_of(io, struct ploop_delta, io);
	int err = 0;
	struct file * file = io->files.file;
	struct extent_map_tree * em_tree;

	if (file == NULL)
		return -EBADF;

	io->files.mapping = file->f_mapping;
	io->files.inode = io->files.mapping->host;
	io->files.bdev = io->files.inode->i_sb->s_bdev;

	dio_fsync(file);

	mutex_lock(&io->files.inode->i_mutex);
	em_tree = ploop_dio_open(io, (delta->flags & PLOOP_FMT_RDONLY));
	err = PTR_ERR(em_tree);
	if (IS_ERR(em_tree))
		goto out;

	io->files.em_tree = em_tree;

	err = dio_invalidate_cache(io->files.mapping, io->files.bdev);
	if (err) {
		io->files.em_tree = NULL;
		ploop_dio_close(io, 0);
		goto out;
	}

	if (!(delta->flags & PLOOP_FMT_RDONLY) && !io->files.em_tree->_get_extent) {
		io->fsync_thread = kthread_create(dio_fsync_thread,
						  io, "ploop_fsync%d",
						  delta->plo->index);
		if (io->fsync_thread == NULL) {
			io->files.em_tree = NULL;
			ploop_dio_close(io, 0);
			goto out;
		}
		wake_up_process(io->fsync_thread);
	}

out:
	mutex_unlock(&io->files.inode->i_mutex);
	return err;
}

void fsync_timeout(unsigned long data)
{
	struct ploop_io * io = (void*)data;

	wake_up_interruptible(&io->fsync_waitq);
}

static int
dio_init(struct ploop_io * io)
{
	INIT_LIST_HEAD(&io->fsync_queue);
	init_waitqueue_head(&io->fsync_waitq);
	init_timer(&io->fsync_timer);
	io->fsync_timer.function = fsync_timeout;
	io->fsync_timer.data = (unsigned long)io;

	return 0;
}

struct dio_comp
{
	struct completion comp;
	atomic_t count;
	int error;
};

DEFINE_BIO_CB(dio_endio_sync)
{
	struct dio_comp * comp = bio->bi_private;

	if (!err && !bio_flagged(bio, BIO_UPTODATE))
		err = -EIO;
	if (err && !comp->error)
		comp->error = err;

	if (atomic_dec_and_test(&comp->count))
		complete(&comp->comp);

	bio_put(bio);
}
END_BIO_CB(dio_endio_sync)

static int
dio_sync_io(struct ploop_io * io, int rw, struct page * page,
	    unsigned int len, unsigned int off, sector_t sec)
{
	struct bio_list bl;
	struct bio * bio;
	struct dio_comp comp;
	struct extent_map * em;
	sector_t nsec;
	int err;

	BUG_ON(len & 511);
	BUG_ON(off & 511);

	bio_list_init(&bl);
	bio = NULL;
	em = NULL;

	init_completion(&comp.comp);
	atomic_set(&comp.count, 1);
	comp.error = 0;

	while (len > 0) {
		int copy;

		if (!em || sec >= em->end) {
			if (em)
				extent_put(em);
			em = extent_lookup_create(io, sec, len>>9);
			if (IS_ERR(em))
				goto out_em_err;
		}

		nsec = dio_isec_to_phys(em, sec);

		if (bio == NULL ||
		    bio->bi_sector + (bio->bi_size>>9) != nsec) {
flush_bio:
			bio = bio_alloc(GFP_NOFS, 32);
			if (bio == NULL)
				goto enomem;
			bio_list_add(&bl, bio);
			bio->bi_bdev = io->files.bdev;
			bio->bi_sector = nsec;
		}

		copy = len;
		if (copy > ((em->end - sec) << 9))
			copy = (em->end - sec) << 9;
		if (bio_add_page(bio, page, copy, off) != copy) {
			/* Oops. */
			goto flush_bio;
		}

		off += copy;
		len -= copy;
		sec += copy >> 9;
	}

	if (em)
		extent_put(em);

	while (bl.head) {
		struct bio * b = bl.head;
		bl.head = b->bi_next;

		b->bi_next = NULL;
		b->bi_end_io = dio_endio_sync;
		b->bi_private = &comp;
		atomic_inc(&comp.count);
		submit_bio(rw, b);
	}

	if (atomic_dec_and_test(&comp.count))
		complete(&comp.comp);

	wait_for_completion(&comp.comp);

	return comp.error;


enomem:
	err = -ENOMEM;
	goto out;

out_em_err:
	err = PTR_ERR(em);
out:
	while (bl.head) {
		struct bio * b = bl.head;
		bl.head = b->bi_next;
		b->bi_next = NULL;
		bio_put(b);
	}
	return err;
}

static int
dio_sync_read(struct ploop_io * io, struct page * page, unsigned int len,
	      unsigned int off, sector_t pos)
{
	return dio_sync_io(io, READ_SYNC, page, len, off, pos);
}

static int
dio_sync_write(struct ploop_io * io, struct page * page, unsigned int len,
	       unsigned int off, sector_t sec)
{
	int err;

	if (!(io->files.file->f_mode & FMODE_WRITE))
		return -EBADF;

	err = dio_sync_io(io, WRITE_SYNC, page, len, off, sec);

	if (sec < io->plo->track_end)
		ploop_tracker_notify(io->plo, sec);

	return err;
}

static int
dio_sync_iovec(struct ploop_io * io, int rw, struct page ** pvec,
	       unsigned int nr, sector_t sec)
{
	struct bio_list bl;
	struct bio * bio;
	struct dio_comp comp;
	unsigned int len = PAGE_SIZE * nr;
	unsigned int off;
	struct extent_map * em;
	int err;
	sector_t nsec;

	bio_list_init(&bl);
	bio = NULL;
	em = NULL;
	off = 0;

	init_completion(&comp.comp);
	atomic_set(&comp.count, 1);
	comp.error = 0;

	while (len > 0) {
		int copy;

		if (!em || sec >= em->end) {
			if (em)
				extent_put(em);
			em = extent_lookup_create(io, sec, len>>9);
			if (IS_ERR(em))
				goto out_em_err;
		}

		nsec = dio_isec_to_phys(em, sec);

		if (bio == NULL ||
		    bio->bi_sector + (bio->bi_size>>9) != nsec) {
flush_bio:
			bio = bio_alloc(GFP_NOFS, 32);
			if (bio == NULL)
				goto enomem;
			bio_list_add(&bl, bio);
			bio->bi_bdev = io->files.bdev;
			bio->bi_sector = nsec;
		}

		copy = len;
		if (copy > ((em->end - sec) << 9))
			copy = (em->end - sec) << 9;
		if (off/PAGE_SIZE != (off + copy + 1)/PAGE_SIZE)
			copy = PAGE_SIZE - (off & (PAGE_SIZE-1));
		if (bio_add_page(bio, pvec[off/PAGE_SIZE], copy,
				 off & (PAGE_SIZE-1) ) != copy) {
			/* Oops. */
			goto flush_bio;
		}

		off += copy;
		len -= copy;
		sec += copy >> 9;
	}

	if (em)
		extent_put(em);

	while (bl.head) {
		struct bio * b = bl.head;
		bl.head = b->bi_next;

		b->bi_next = NULL;
		b->bi_end_io = dio_endio_sync;
		b->bi_private = &comp;
		atomic_inc(&comp.count);
		submit_bio(rw, b);
	}

	if (atomic_dec_and_test(&comp.count))
		complete(&comp.comp);

	wait_for_completion(&comp.comp);

	return comp.error;


enomem:
	err = -ENOMEM;
	goto out;

out_em_err:
	err = PTR_ERR(em);
out:
	while (bl.head) {
		struct bio * b = bl.head;
		bl.head = b->bi_next;
		b->bi_next = NULL;
		bio_put(b);
	}
	return err;
}

static int
dio_sync_readvec(struct ploop_io * io, struct page ** pvec, unsigned int nr,
		 sector_t sec)
{
	return dio_sync_iovec(io, READ_SYNC, pvec, nr, sec);
}

static int
dio_sync_writevec(struct ploop_io * io, struct page ** pvec, unsigned int nr,
		  sector_t sec)
{
	int err;

	if (!(io->files.file->f_mode & FMODE_WRITE))
		return -EBADF;

	err = dio_sync_iovec(io, WRITE_SYNC, pvec, nr, sec);

	if (sec < io->plo->track_end)
		ploop_tracker_notify(io->plo, sec);

	return err;
}

/*
 * Allocate and zero new block in file. Do it through page cache.
 * It is assumed there is no point to optimize this, it is used
 * (for ploop1 format) only for allocation of index clusters. Another
 * use-case is growing raw delta, but this is assumed to be rare.
 */
static int dio_alloc_sync(struct ploop_io * io, loff_t pos, loff_t len)
{
	int err;
	int ret;
	struct page *pad = NULL;
	int pad_len = pos & (PAGE_CACHE_SIZE - 1);

	if (pos + len > i_size_read(io->files.inode) &&
	    io->files.file->f_op->fallocate) {
		err = io->files.file->f_op->fallocate(io->files.file, 0,
						       pos, len);
		if (err)
			return err;
	}

	if (pad_len) {
		BUILD_BUG_ON(PAGE_SIZE != PAGE_CACHE_SIZE);

		pad = alloc_page(GFP_NOFS);
		if (pad == NULL)
			return -ENOMEM;

		len += pad_len;
		pos -= pad_len;

		err = dio_sync_read(io, pad, pad_len, 0, pos >> 9);
		if (err) {
			put_page(pad);
			return err;
		}
	}

	err = 0;

	mutex_lock(&io->files.inode->i_mutex);

	while (len > 0) {
		struct page *page;
		void *fsdata;
		ret = pagecache_write_begin(io->files.file, io->files.mapping,
					    pos, PAGE_CACHE_SIZE, 0,
					    &page, &fsdata);
		if (ret) {
			err = ret;
			mutex_unlock(&io->files.inode->i_mutex);
			goto fail;
		}

		bzero_page(page);

		if (pad) {
			memcpy(page_address(page), page_address(pad), pad_len);
			put_page(pad);
			pad = NULL;
		}

		ret = pagecache_write_end(io->files.file, io->files.mapping,
					  pos, PAGE_CACHE_SIZE,
					  PAGE_CACHE_SIZE, page, fsdata);
		if (ret < 0 || ret != PAGE_CACHE_SIZE) {
			err = ret;
			mutex_unlock(&io->files.inode->i_mutex);
			goto fail;
		}

		len -= PAGE_CACHE_SIZE;
		pos += PAGE_CACHE_SIZE;
	}

	mutex_unlock(&io->files.inode->i_mutex);

	err = filemap_fdatawrite(io->files.mapping);
	if (err)
		goto fail;

	if (io->files.file->f_op && io->files.file->f_op->fsync) {
		err = io->files.file->f_op->FOP_FSYNC(io->files.file, 0);
		if (err)
			goto fail;
	}
	err = filemap_fdatawait(io->files.mapping);

fail:
	if (pad)
		put_page(pad);

	if (!err)
		io->alloc_head = pos >> (io->plo->cluster_log + 9);

	return err;
}

static void
dio_io_page(struct ploop_io * io, unsigned long rw,
	    struct ploop_request * preq, struct page * page,
	    sector_t sec)
{
	struct bio_list bl;
	struct bio * bio;
	unsigned int len;
	struct extent_map * em;
	sector_t nsec;
	int err;
	int off;
	int postfua;
	int bio_num;
	int preflush;

	preflush = !!(rw & REQ_FLUSH);
	postfua = !!(rw & REQ_FUA);
	rw &= ~(REQ_FUA|REQ_FLUSH);

	bio_list_init(&bl);
	bio = NULL;
	em = NULL;
	off = 0;

	ploop_prepare_io_request(preq);
	if (rw & REQ_WRITE)
		ploop_prepare_tracker(preq, sec);

	len = PAGE_SIZE;

	while (len > 0) {
		int copy;

		if (!em || sec >= em->end) {
			if (em)
				extent_put(em);
			em = extent_lookup_create(io, sec, len>>9);
			if (IS_ERR(em))
				goto out_em_err;
		}

		nsec = dio_isec_to_phys(em, sec);

		if (bio == NULL ||
		    bio->bi_sector + (bio->bi_size>>9) != nsec) {
flush_bio:
			bio = bio_alloc(GFP_NOFS, 32);
			if (bio == NULL)
				goto enomem;
			bio_list_add(&bl, bio);
			bio->bi_bdev = io->files.bdev;
			bio->bi_sector = nsec;
		}

		copy = len;
		if (copy > ((em->end - sec) << 9))
			copy = (em->end - sec) << 9;
		if (bio_add_page(bio, page, copy, off) != copy) {
			/* Oops. */
			goto flush_bio;
		}

		off += copy;
		len -= copy;
		sec += copy >> 9;
	}

	if (em)
		extent_put(em);

	bio_num = 0;
	while (bl.head) {
		unsigned long rw2 = rw;
		struct bio * b = bl.head;
		bl.head = b->bi_next;

		if (unlikely(preflush)) {
			rw2 |= REQ_FLUSH;
			preflush = 0;
		}

		if (unlikely(postfua && !bl.head))
			rw2 |= (REQ_FUA | ((bio_num) ? REQ_FLUSH : 0));

		b->bi_next = NULL;
		b->bi_end_io = dio_endio_async;
		b->bi_private = preq;
		atomic_inc(&preq->io_count);
		ploop_acc_ff_out(preq->plo, rw2 | b->bi_rw);
		submit_bio(rw2, b);
		bio_num++;
	}

	ploop_complete_io_request(preq);
	return;

enomem:
	err = -ENOMEM;
	goto out;

out_em_err:
	err = PTR_ERR(em);
out:
	while (bl.head) {
		struct bio * b = bl.head;
		bl.head = b->bi_next;
		b->bi_next = NULL;
		bio_put(b);
	}
	PLOOP_FAIL_REQUEST(preq, err);
}

static void
dio_read_page(struct ploop_io * io, struct ploop_request * preq,
	      struct page * page, sector_t sec)
{
	dio_io_page(io, READ | REQ_SYNC, preq, page, sec);
}

static void
dio_write_page(struct ploop_io * io, struct ploop_request * preq,
	       struct page * page, sector_t sec, int fua)
{
	if (!(io->files.file->f_mode & FMODE_WRITE)) {
		PLOOP_FAIL_REQUEST(preq, -EBADF);
		return;
	}

	dio_io_page(io, WRITE | (fua ? REQ_FUA : 0) | REQ_SYNC,
		    preq, page, sec);
}

static int
dio_fastmap(struct ploop_io * io, struct bio * orig_bio,
	    struct bio * bio, sector_t isec)
{
	struct request_queue * q;
	struct extent_map * em;
	int i;

	if (orig_bio->bi_size == 0) {
		bio->bi_vcnt   = 0;
		bio->bi_sector = 0;
		bio->bi_size   = 0;
		bio->bi_idx    = 0;

		bio->bi_rw   = orig_bio->bi_rw;
		bio->bi_bdev = io->files.bdev;
		return 0;
	}

	em = extent_lookup(io->files.em_tree, isec);

	if (em == NULL) {
		io->plo->st.fast_neg_noem++;
		return 1;
	}

	if (isec + (orig_bio->bi_size>>9) > em->end) {
		io->plo->st.fast_neg_shortem++;
		extent_put(em);
		return 1;
	}

	BUG_ON(bio->bi_max_vecs < orig_bio->bi_vcnt);

	memcpy(bio->bi_io_vec, orig_bio->bi_io_vec,
	       orig_bio->bi_vcnt * sizeof(struct bio_vec));

	bio->bi_sector = dio_isec_to_phys(em, isec);
	extent_put(em);

	bio->bi_bdev = io->files.bdev;
	bio->bi_rw = orig_bio->bi_rw;
	bio->bi_vcnt = orig_bio->bi_vcnt;
	bio->bi_size = orig_bio->bi_size;
	bio->bi_idx = orig_bio->bi_idx;

	q = bdev_get_queue(bio->bi_bdev);

	if (q->merge_bvec_fn == NULL)
		return 0;

	bio->bi_size = 0;
	bio->bi_vcnt = 0;

	for (i = 0; i < orig_bio->bi_vcnt; i++) {
		struct bio_vec * bv = &bio->bi_io_vec[i];
		struct bvec_merge_data bm_data = {
			.bi_bdev = bio->bi_bdev,
			.bi_sector = bio->bi_sector,
			.bi_size = bio->bi_size,
			.bi_rw = bio->bi_rw,
		};
		if (q->merge_bvec_fn(q, &bm_data, bv) < bv->bv_len) {
			io->plo->st.fast_neg_backing++;
			return 1;
		}
		bio->bi_size += bv->bv_len;
		bio->bi_vcnt++;
	}
	return 0;
}

/* Merge is disabled _only_ if we _have_ resolved mapping and
 * we are sure bio is going to be split in any case due to
 * file level fragmentation.
 */
static int
dio_disable_merge(struct ploop_io * io, sector_t isector, unsigned int len)
{
	int ret = 0;
	struct extent_map * em;

	em = extent_lookup(io->files.em_tree, isector);
	if (em) {
		if (isector + len > em->end)
			ret = 1;
		extent_put(em);
	}
	return ret;
}

static int dio_prepare_snapshot(struct ploop_io * io, struct ploop_snapdata *sd)
{
	int err;
	struct file * file = io->files.file;
	struct path	path;

	path.mnt = F_MNT(file);
	path.dentry = F_DENTRY(file);

	file = dentry_open(&path, O_RDONLY|O_LARGEFILE, current_cred());
	if (IS_ERR(file))
		return PTR_ERR(file);

	/* Sanity checks */

	if (io->files.mapping != file->f_mapping ||
	    io->files.inode != file->f_mapping->host ||
	    io->files.bdev != file->f_mapping->host->i_sb->s_bdev) {
		fput(file);
		return -EINVAL;
	}

	dio_fsync(file);

	mutex_lock(&io->files.inode->i_mutex);
	err = dio_invalidate_cache(io->files.mapping, io->files.bdev);
	mutex_unlock(&io->files.inode->i_mutex);

	if (err) {
		fput(file);
		return -EINVAL;
	}

	sd->file = file;
	return 0;
}

static int dio_complete_snapshot(struct ploop_io * io, struct ploop_snapdata *sd)
{
	struct file * file = io->files.file;
	int ret;

	ret = dio_release_prealloced(io);
	if (ret)
		return ret;

	mutex_lock(&io->plo->sysfs_mutex);
	io->files.file = sd->file;
	sd->file = NULL;
	mutex_unlock(&io->plo->sysfs_mutex);

	mutex_lock(&io->files.inode->i_mutex);
	ploop_dio_downgrade(io->files.mapping);
	BUG_ON((loff_t)io->alloc_head << (io->plo->cluster_log + 9) !=
	       i_size_read(io->files.inode));
	(void)invalidate_inode_pages2(io->files.mapping);
	mutex_unlock(&io->files.inode->i_mutex);

	if (io->fsync_thread) {
		kthread_stop(io->fsync_thread);
		io->fsync_thread = NULL;
	}

	fput(file);
	return 0;
}

static int dio_prepare_merge(struct ploop_io * io, struct ploop_snapdata *sd)
{
	int err;
	struct file * file = io->files.file;
	struct path	path;

	path.mnt = F_MNT(file);
	path.dentry = F_DENTRY(file);

	file = dentry_open(&path, O_RDWR|O_LARGEFILE, current_cred());
	if (IS_ERR(file))
		return PTR_ERR(file);

	/* Sanity checks */

	if (io->files.mapping != file->f_mapping ||
	    io->files.inode != file->f_mapping->host ||
	    io->files.bdev != file->f_mapping->host->i_sb->s_bdev) {
		fput(file);
		return -EINVAL;
	}

	dio_fsync(file);

	mutex_lock(&io->files.inode->i_mutex);

	err = dio_invalidate_cache(io->files.mapping, io->files.bdev);
	if (err) {
		mutex_unlock(&io->files.inode->i_mutex);
		fput(file);
		return err;
	}

	err = ploop_dio_upgrade(io);
	if (err) {
		mutex_unlock(&io->files.inode->i_mutex);
		fput(file);
		return err;
	}
	mutex_unlock(&io->files.inode->i_mutex);

	if (!io->files.em_tree->_get_extent) {
		io->fsync_thread = kthread_create(dio_fsync_thread,
						  io, "ploop_fsync%d",
						  io->plo->index);
		if (io->fsync_thread == NULL) {
			fput(file);
			return -ENOMEM;
		}
		wake_up_process(io->fsync_thread);
	}

	sd->file = file;
	return 0;
}

static int dio_truncate(struct ploop_io * io, struct file * file,
			__u32 alloc_head)
{
	int err;
	struct iattr newattrs;
	loff_t new_size;

	if (file->f_mapping != io->files.mapping)
		return -EINVAL;

	newattrs.ia_size = (u64)alloc_head << (io->plo->cluster_log + 9);
	newattrs.ia_valid = ATTR_SIZE;

	mutex_lock(&io->files.inode->i_mutex);
	if (io->files.em_tree)
		trim_extent_mappings(io->files.em_tree, newattrs.ia_size>>9);
	io->files.inode->i_flags &= ~S_SWAPFILE;
	err = notify_change(F_DENTRY(file), &newattrs, NULL);
	io->files.inode->i_flags |= S_SWAPFILE;
	mutex_unlock(&io->files.inode->i_mutex);

	new_size = i_size_read(io->files.inode);
	atomic_long_sub(*io->size_ptr - new_size, &ploop_io_images_size);
	*io->size_ptr = new_size;

	if (!err)
		err = dio_fsync(file);

	return err;
}

static int dio_start_merge(struct ploop_io * io, struct ploop_snapdata *sd)
{
	struct file * file = io->files.file;

	mutex_lock(&io->plo->sysfs_mutex);
	io->files.file = sd->file;
	sd->file = NULL;
	mutex_unlock(&io->plo->sysfs_mutex);

	fput(file);
	return 0;
}

static void dio_unplug(struct ploop_io * io)
{	
	/* Need more thinking how to implement unplug */
}

static int dio_congested(struct ploop_io * io, int bits)
{
	struct request_queue *bq;

	bq = bdev_get_queue(io->files.bdev);

	return bdi_congested(&bq->backing_dev_info, bits);
}

static void dio_queue_settings(struct ploop_io * io, struct request_queue * q)
{
	blk_queue_stack_limits(q, bdev_get_queue(io->files.bdev));
}

static void dio_issue_flush(struct ploop_io * io, struct ploop_request *preq)
{
	struct bio *bio;

	bio = bio_alloc(GFP_NOFS, 0);
	if (unlikely(!bio)) {
		PLOOP_FAIL_REQUEST(preq, -ENOMEM);
		return;
	}

	ploop_prepare_io_request(preq);
	bio->bi_end_io = dio_endio_async;
	bio->bi_bdev = io->files.bdev;
	bio->bi_private = preq;

	atomic_inc(&preq->io_count);
	preq->eng_state = PLOOP_E_COMPLETE;
	ploop_acc_ff_out(io->plo, preq->req_rw | bio->bi_rw);
	submit_bio(preq->req_rw, bio);
	ploop_complete_io_request(preq);
}

static int dio_dump(struct ploop_io * io)
{
	extern void dump_extent_map(struct extent_map_tree *tree);

	if (io->files.em_tree) {
		dump_extent_map(io->files.em_tree);
		return 0;
	}
	return -1;
}

static int dio_autodetect(struct ploop_io * io)
{
	struct file  * file  = io->files.file;
	struct inode * inode = file->f_mapping->host;
	char         * s_id  = inode->i_sb->s_id;

	int err;
	mm_segment_t fs;
	unsigned int flags;
	
	if (inode->i_sb->s_magic != EXT4_SUPER_MAGIC)
		return -1; /* not mine */

	if (inode->i_sb->s_bdev == NULL) {
		printk("File on FS EXT(%s) without backing device\n", s_id);
		return -1;
	}

	if (!file->f_op->fallocate)
		ploop_io_report_fn(file, KERN_WARNING
					"File on FS w/o fallocate");

	if (!file->f_op->unlocked_ioctl) {
		printk("Cannot run on EXT4(%s): no unlocked_ioctl\n", s_id);
		return -1;
	}

	fs = get_fs();
	set_fs(KERNEL_DS);
	flags = 0;
	err = file->f_op->unlocked_ioctl(file, FS_IOC_GETFLAGS, (long)&flags);
	set_fs(fs);

	if (err != 0) {
		printk("Cannot run on EXT4(%s): failed FS_IOC_GETFLAGS (%d)\n",
		       s_id, err);
		return -1;
	}

	io->files.flags = flags;
	if (!(flags & EXT4_EXTENTS_FL))
		ploop_io_report_fn(file, KERN_WARNING "File w/o extents");

	return 0;
}

static struct ploop_io_ops ploop_io_ops_direct =
{
	.id		=	PLOOP_IO_DIRECT,
	.name		=	"direct",
	.owner		=	THIS_MODULE,

	.unplug		=	dio_unplug,
	.congested	=	dio_congested,

	.alloc		=	dio_alloc_sync,
	.submit		=	dio_submit,
	.submit_alloc	=	dio_submit_alloc,
	.disable_merge	=	dio_disable_merge,
	.fastmap	=	dio_fastmap,
	.read_page	=	dio_read_page,
	.write_page	=	dio_write_page,
	.sync_read	=	dio_sync_read,
	.sync_write	=	dio_sync_write,
	.sync_readvec	=	dio_sync_readvec,
	.sync_writevec	=	dio_sync_writevec,

	.init		=	dio_init,
	.destroy	=	dio_destroy,
	.open		=	dio_open,
	.sync		=	dio_sync,
	.stop		=	dio_stop,
	.prepare_snapshot =	dio_prepare_snapshot,
	.complete_snapshot =	dio_complete_snapshot,
	.prepare_merge  =	dio_prepare_merge,
	.start_merge	=	dio_start_merge,
	.truncate	=	dio_truncate,

	.queue_settings	=	dio_queue_settings,
	.issue_flush	=	dio_issue_flush,

	.dump		=	dio_dump,

	.i_size_read	=	generic_i_size_read,
	.f_mode		=	generic_f_mode,

	.autodetect     =       dio_autodetect,
};

module_param(max_extent_map_pages, int, 0644);
MODULE_PARM_DESC(max_extent_map_pages, "Maximal amount of pages taken by all extent map caches");
module_param(min_extent_map_entries, int, 0644);
MODULE_PARM_DESC(min_extent_map_entries, "Minimal amount of entries in a single extent map cache");

static int __init pio_direct_mod_init(void)
{
	int err;

	if (max_extent_map_pages == 0)
		max_extent_map_pages = PLOOP_MAX_EXTENT_MAP >> PAGE_SHIFT;

	if (min_extent_map_entries == 0)
		min_extent_map_entries = 64;

	err = extent_map_init();
	if (!err) {
		err = ploop_register_io(&ploop_io_ops_direct);
		if (err)
			extent_map_exit();
	}

	return err;
}

static void __exit pio_direct_mod_exit(void)
{
	ploop_unregister_io(&ploop_io_ops_direct);
	extent_map_exit();
	BUG_ON(atomic_long_read(&ploop_io_images_size));
}

module_init(pio_direct_mod_init);
module_exit(pio_direct_mod_exit);

MODULE_LICENSE("GPL");
