#include <linux/module.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/pagemap.h>
#include <linux/kthread.h>
#include <linux/mount.h>
#include <linux/aio.h>

#include <linux/ploop/ploop.h>

/* from fs/inode/fuse.c */
#define FUSE_SUPER_MAGIC 0x65735546

#define KAIO_PREALLOC (128 * 1024 * 1024) /* 128 MB */

#define KAIO_MAX_PAGES_PER_REQ 32	  /* 128 KB */

/* This will be used as flag "ploop_kaio_open() succeeded" */
static struct extent_map_tree
{
} dummy_em_tree;

int ploop_kaio_open(struct file * file, int rdonly);
int ploop_kaio_close(struct address_space * mapping, int rdonly);
void ploop_kaio_downgrade(struct address_space * mapping);
int ploop_kaio_upgrade(struct address_space * mapping);

static int __kaio_truncate(struct ploop_io * io, struct file * file, u64 pos);
static int kaio_truncate(struct ploop_io * io, struct file * file, __u32 a_h);

static void __kaio_queue_fsync_req(struct ploop_request * preq, int prio)
{
	struct ploop_device * plo   = preq->plo;
	struct ploop_delta  * delta = ploop_top_delta(plo);
	struct ploop_io     * io    = &delta->io;

	if (prio)
		list_add(&preq->list, &io->fsync_queue);
	else
		list_add_tail(&preq->list, &io->fsync_queue);

	io->fsync_qlen++;
	if (waitqueue_active(&io->fsync_waitq))
		wake_up_interruptible(&io->fsync_waitq);
}

static void kaio_queue_fsync_req(struct ploop_request * preq)
{
	__kaio_queue_fsync_req(preq, 0);
}

static void kaio_queue_trunc_req(struct ploop_request * preq)
{
	__kaio_queue_fsync_req(preq, 1);
}

static void kaio_complete_io_state(struct ploop_request * preq)
{
	struct ploop_device * plo   = preq->plo;
	unsigned long flags;
	int post_fsync = 0;

	if (preq->error || !(preq->req_rw & REQ_FUA) ||
	    preq->eng_state == PLOOP_E_INDEX_READ ||
	    preq->eng_state == PLOOP_E_TRANS_INDEX_READ ||
	    preq->eng_state == PLOOP_E_DELTA_READ ||
	    preq->eng_state == PLOOP_E_TRANS_DELTA_READ) {
		ploop_complete_io_state(preq);
		return;
	}

	preq->req_rw &= ~REQ_FUA;

	/* Convert requested fua to fsync */
	if (test_and_clear_bit(PLOOP_REQ_FORCE_FUA, &preq->state) ||
	    test_and_clear_bit(PLOOP_REQ_KAIO_FSYNC, &preq->state))
		post_fsync = 1;

	if (!post_fsync &&
	    !ploop_req_delay_fua_possible(preq->req_rw, preq) &&
	    (preq->req_rw & REQ_FUA))
		post_fsync = 1;

	preq->req_rw &= ~REQ_FUA;

	if (post_fsync) {
		spin_lock_irqsave(&plo->lock, flags);
		kaio_queue_fsync_req(preq);
		plo->st.bio_syncwait++;
		spin_unlock_irqrestore(&plo->lock, flags);
	} else {
		ploop_complete_io_state(preq);
	}
}

static void kaio_complete_io_request(struct ploop_request * preq)
{
	if (atomic_dec_and_test(&preq->io_count))
		kaio_complete_io_state(preq);
}

struct kaio_req {
	struct ploop_request *preq;
	struct bio_vec	      bvecs[0];
};

static void kaio_rw_aio_complete(u64 data, long res)
{
	struct ploop_request * preq = (struct ploop_request *)data;

	if (unlikely(res < 0)) {
		struct bio *b = preq->aux_bio;
		printk("kaio_rw_aio_complete: kaio failed with err=%ld "
		       "(rw=%s; state=%ld/0x%lx; clu=%d; iblk=%d; aux=%ld)\n",
		       res, (preq->req_rw & REQ_WRITE) ? "WRITE" : "READ",
		       preq->eng_state, preq->state, preq->req_cluster,
		       preq->iblock, b ? b->bi_sector : -1);
		bio_list_for_each(b, &preq->bl)
			printk(" bio=%p: bi_sector=%ld bi_size=%d\n",
			       b, b->bi_sector, b->bi_size);
		PLOOP_REQ_SET_ERROR(preq, res);
	}

	kaio_complete_io_request(preq);
}

static void kaio_rw_kreq_complete(u64 data, long res)
{
	struct kaio_req *kreq = (struct kaio_req *)data;
	struct ploop_request *preq = kreq->preq;

	kfree(kreq);
	kaio_rw_aio_complete((u64)preq, res);
}

static struct kaio_req *kaio_kreq_alloc(struct ploop_request *preq, int *nr_p)
{
	static const int nr = KAIO_MAX_PAGES_PER_REQ;
	struct kaio_req *kreq;

	kreq = kmalloc(offsetof(struct kaio_req, bvecs[nr]), GFP_NOFS);
	if (kreq) {
		*nr_p = nr;
		kreq->preq = preq;
	}

	return kreq;
}

static int kaio_kernel_submit(struct file *file, struct kaio_req *kreq,
		size_t nr_segs, size_t count, loff_t pos, unsigned long rw)
{
	struct kiocb *iocb;
	unsigned short op;
	struct iov_iter iter;
	int err;

	iocb = aio_kernel_alloc(GFP_NOIO);
	if (!iocb)
		return -ENOMEM;

	if (rw & REQ_WRITE)
		op = IOCB_CMD_WRITE_ITER;
	else
		op = IOCB_CMD_READ_ITER;

	iov_iter_init_bvec(&iter, kreq->bvecs, nr_segs, count, 0);
	aio_kernel_init_iter(iocb, file, op, &iter, pos);
	aio_kernel_init_callback(iocb, kaio_rw_kreq_complete, (u64)kreq);

	err = aio_kernel_submit(iocb);
	if (err)
		printk("kaio_kernel_submit: aio_kernel_submit failed with "
		       "err=%d (rw=%s; state=%ld/0x%lx; pos=%lld; len=%ld)\n",
		       err, (rw & REQ_WRITE) ? "WRITE" : "READ",
		       kreq->preq->eng_state, kreq->preq->state, pos, count);
	return err;
}

/*
 * Pack as many bios from the list pointed by '*bio_pp' to kreq as possible,
 * but no more than 'size' bytes. Returns 'copy' equal to # bytes copied.
 *
 * <*bio_pp, *idx_p> plays the role of iterator to walk through bio list.
 * NB: the iterator is valid only while 'size' > 'copy'
 *
 * NB: at enter, '*nr_segs' depicts capacity of kreq;
 *     at return, it depicts actual payload
 */
static size_t kaio_kreq_pack(struct kaio_req *kreq, int *nr_segs,
			     struct bio **bio_pp, int *idx_p, size_t size)
{
	int kreq_nr_max = *nr_segs;
	struct bio *b = *bio_pp;
	int idx = *idx_p;
	struct bio_vec *src_bv = b->bi_io_vec + idx;
	struct bio_vec *dst_bv = kreq->bvecs;
	size_t copy = 0;

	BUG_ON(b->bi_idx);

	while (1) {
		int nr = min_t(int, kreq_nr_max, b->bi_vcnt - idx);
		BUG_ON(!nr);

		memcpy(dst_bv, src_bv, nr * sizeof(struct bio_vec));

		copy += bvec_length(dst_bv, nr);
		if (copy >= size) {
			*nr_segs = dst_bv - kreq->bvecs + nr;
			return size;
		}

		dst_bv += nr;
		src_bv += nr;
		idx += nr;

		if (b->bi_vcnt == idx) {
			b = b->bi_next;
			BUG_ON(!b);
			src_bv = b->bi_io_vec;
			idx = 0;
		}

		kreq_nr_max -= nr;
		if (kreq_nr_max == 0)
			break;
	}

	*bio_pp = b;
	*idx_p = idx;
	return copy;
}

/*
 * WRITE case:
 *
 * sbl is the list of bio; the first bio in the list and iblk specify
 * destination file offset; the content of bios in sbl is scattered source
 * buffer.
 *
 * The goal is to write source buffer to the file with given offset. We're
 * doing it by stuffing as many bvecs from source to kreqs as possible and
 * submitting kreqs to in-kernel aio.
 *
 * READ case:
 *
 * The same as WRITE, but here the file plays the role of source and the
 * content of bios in sbl plays the role of destination.
 */
static void kaio_sbl_submit(struct file *file, struct ploop_request *preq,
			    unsigned long rw, struct bio_list *sbl,
			    iblock_t iblk, size_t size)
{
	struct bio *bio = sbl->head;
	int idx = 0;

	loff_t off = bio->bi_sector;
	off = ((loff_t)iblk << preq->plo->cluster_log) |
		(off & ((1<<preq->plo->cluster_log) - 1));

	if (rw & REQ_WRITE)
		ploop_prepare_tracker(preq, off);

	off <<= 9;
	/* since now 'off' always points to a position in the file to X-mit */

	WARN_ONCE(!(file->f_flags & O_DIRECT), "File opened w/o O_DIRECT");

	ploop_prepare_io_request(preq);

	size <<= 9;
	while (size > 0) {
		struct kaio_req *kreq;
		int nr_segs;
		size_t copy;
		int err;

		kreq = kaio_kreq_alloc(preq, &nr_segs);
		if (!kreq) {
			PLOOP_REQ_SET_ERROR(preq, -ENOMEM);
			break;
		}

		copy = kaio_kreq_pack(kreq, &nr_segs, &bio, &idx, size);

		atomic_inc(&preq->io_count);
		err = kaio_kernel_submit(file, kreq, nr_segs, copy, off, rw);
		if (err) {
			PLOOP_REQ_SET_ERROR(preq, err);
			ploop_complete_io_request(preq);
			kfree(kreq);
			break;
		}

		off += copy;
		size -= copy;
	}

	kaio_complete_io_request(preq);
}

static void
kaio_submit(struct ploop_io *io, struct ploop_request * preq,
	     unsigned long rw,
	     struct bio_list *sbl, iblock_t iblk, unsigned int size)
{
	if (rw & REQ_FLUSH) {
		spin_lock_irq(&io->plo->lock);
		kaio_queue_fsync_req(preq);
		io->plo->st.bio_syncwait++;
		spin_unlock_irq(&io->plo->lock);
		return;
	}

	if (iblk == PLOOP_ZERO_INDEX)
		iblk = 0;

	kaio_sbl_submit(io->files.file, preq, rw, sbl, iblk, size);
}

/* returns non-zero if and only if preq was resubmitted */
static int kaio_resubmit(struct ploop_request * preq)
{
	struct ploop_delta * delta = ploop_top_delta(preq->plo);

	switch (preq->eng_state) {
	case PLOOP_E_ENTRY:
		return 0;
	case PLOOP_E_COMPLETE:
	case PLOOP_E_RELOC_NULLIFY:
	case PLOOP_E_DATA_WBI:
		if (preq->aux_bio) {
			struct bio_list tbl;
			tbl.head = tbl.tail = preq->aux_bio;
			kaio_submit(&delta->io, preq, preq->req_rw, &tbl,
				    preq->iblock, 1<<preq->plo->cluster_log);
		} else {
			kaio_submit(&delta->io, preq, preq->req_rw, &preq->bl,
				    preq->iblock, preq->req_size);
		}
		break;
	case PLOOP_E_TRANS_DELTA_READ:
		/* BUG_ON below guarantees that 'case PLOOP_E_DELTA_COPIED'
		 * is equivalent to the part of 'case PLOOP_E_TRANS_DELTA_READ'
		 * after bio_bcopy(). This is not trivial. */
		BUG_ON(!test_bit(PLOOP_REQ_TRANS, &preq->state));
		/* Fall through ... */
	case PLOOP_E_DELTA_READ:
		preq->eng_state = PLOOP_E_DELTA_COPIED; /* skip bcopy() */
		return 0;
	default:
		printk("Resubmit bad state %lu\n", preq->eng_state);
		BUG();
	}

	return 1;
}

static inline int io2level(struct ploop_io * io)
{
	struct ploop_delta *delta = container_of(io, struct ploop_delta, io);
	return delta->level;
}

static int kaio_fsync_thread(void * data)
{
	struct ploop_io * io = data;
	struct ploop_device * plo = io->plo;

	set_user_nice(current, -20);

	spin_lock_irq(&plo->lock);
	while (!kthread_should_stop() || !list_empty(&io->fsync_queue)) {
		int err;
		struct ploop_request * preq;

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

		preq = list_entry(io->fsync_queue.next, struct ploop_request, list);
		list_del(&preq->list);
		io->fsync_qlen--;
		if (!preq->prealloc_size)
			plo->st.bio_fsync++;
		spin_unlock_irq(&plo->lock);

		/* trick: preq->prealloc_size is actually new pos of eof */
		if (preq->prealloc_size) {
			err = kaio_truncate(io, io->files.file,
					    preq->prealloc_size >> (plo->cluster_log + 9));
			if (err)
				PLOOP_REQ_SET_ERROR(preq, -EIO);
		} else {
			struct file *file = io->files.file;
			err = vfs_fsync(file, 1);
			if (err) {
				printk("kaio_fsync_thread: vfs_fsync failed "
				       "with err=%d (i_ino=%ld of level=%d "
				       "on ploop%d)\n",
				       err, io->files.inode->i_ino,
				       io2level(io), plo->index);
				PLOOP_REQ_SET_ERROR(preq, -EIO);
			} else if (preq->req_rw & REQ_FLUSH) {
				BUG_ON(!preq->req_size);
				preq->req_rw &= ~REQ_FLUSH;
				if (kaio_resubmit(preq)) {
					spin_lock_irq(&plo->lock);
					continue;
				}
			}
		}

		spin_lock_irq(&plo->lock);
		list_add_tail(&preq->list, &plo->ready_queue);

		if (test_bit(PLOOP_S_WAIT_PROCESS, &plo->state))
			wake_up_interruptible(&plo->waitq);
	}
	spin_unlock_irq(&plo->lock);
	return 0;
}

static void
kaio_submit_alloc(struct ploop_io *io, struct ploop_request * preq,
		 struct bio_list * sbl, unsigned int size)
{
	struct ploop_delta *delta = container_of(io, struct ploop_delta, io);
	iblock_t iblk;
	int log = preq->plo->cluster_log + 9;
	loff_t clu_siz = 1 << log;

	if (delta->flags & PLOOP_FMT_RDONLY) {
		PLOOP_FAIL_REQUEST(preq, -EBADF);
		return;
	}

	iblk = io->alloc_head;

	if (unlikely(preq->req_rw & REQ_FLUSH)) {
		spin_lock_irq(&io->plo->lock);
		kaio_queue_fsync_req(preq);
		io->plo->st.bio_syncwait++;
		spin_unlock_irq(&io->plo->lock);
		return;
	}

	/* trick: preq->prealloc_size is actually new pos of eof */
	if (unlikely(preq->prealloc_size)) {
		BUG_ON(preq != io->prealloc_preq);
		io->prealloc_preq = NULL;

		io->prealloced_size = preq->prealloc_size - ((loff_t)iblk << log);
		preq->prealloc_size = 0; /* only for sanity */
	}

	if (unlikely(io->prealloced_size < clu_siz)) {
		if (!io->prealloc_preq) {
			loff_t pos = (((loff_t)(iblk + 1)  << log) |
				      (KAIO_PREALLOC - 1)) + 1;

			BUG_ON(preq->prealloc_size);
			preq->prealloc_size = pos;
			io->prealloc_preq   = preq;

			spin_lock_irq(&io->plo->lock);
			kaio_queue_trunc_req(preq);
			io->plo->st.bio_syncwait++;
			spin_unlock_irq(&io->plo->lock);
			return;
		} else { /* we're not first */
			list_add_tail(&preq->list,
				      &io->prealloc_preq->delay_list);
			return;
		}
	}

	io->prealloced_size -= clu_siz;
	io->alloc_head++;

	preq->iblock = iblk;
	preq->eng_state = PLOOP_E_DATA_WBI;

	kaio_sbl_submit(io->files.file, preq, REQ_WRITE, sbl, iblk, size);
}

static int kaio_release_prealloced(struct ploop_io * io)
{
	int ret;

	if (!io->prealloced_size)
		return 0;

	ret = kaio_truncate(io, io->files.file, io->alloc_head);
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

static void
kaio_destroy(struct ploop_io * io)
{
	if (io->files.file) {
		struct file * file;
		struct ploop_delta * delta = container_of(io, struct ploop_delta, io);

		if (io->fsync_thread) {
			kthread_stop(io->fsync_thread);
			io->fsync_thread = NULL;
		}

		(void)kaio_release_prealloced(io);

		if (io->files.em_tree) {
			mutex_lock(&io->files.inode->i_mutex);
			ploop_kaio_close(io->files.mapping, delta->flags & PLOOP_FMT_RDONLY);
			mutex_unlock(&io->files.inode->i_mutex);
		}

		file = io->files.file;
		mutex_lock(&delta->plo->sysfs_mutex);
		io->files.file = NULL;
		mutex_unlock(&delta->plo->sysfs_mutex);
		fput(file);
	}
}

static int
kaio_sync(struct ploop_io * io)
{
	struct file *file = io->files.file;

	return vfs_fsync(file, 0);
}

static int
kaio_stop(struct ploop_io * io)
{
	return 0;
}

static int
kaio_init(struct ploop_io * io)
{
	INIT_LIST_HEAD(&io->fsync_queue);
	init_waitqueue_head(&io->fsync_waitq);

	return 0;
}

static void
kaio_io_page(struct ploop_io * io, int op, struct ploop_request * preq,
	     struct page * page, sector_t sec)
{

	struct kiocb *iocb;
	struct iov_iter iter;
	loff_t pos = (loff_t) sec << 9;
	struct file *file = io->files.file;
	int err;

	ploop_prepare_io_request(preq);

	iocb = aio_kernel_alloc(GFP_NOIO);
	if (!iocb) {
		PLOOP_REQ_SET_ERROR(preq, -ENOMEM);
		goto out;
	}

	iov_iter_init_page(&iter, page, PAGE_SIZE, 0);
	aio_kernel_init_iter(iocb, file, op, &iter, pos);
	aio_kernel_init_callback(iocb, kaio_rw_aio_complete, (u64)preq);

	atomic_inc(&preq->io_count);

	err = aio_kernel_submit(iocb);
	if (err) {
		printk("kaio_io_page: aio_kernel_submit failed with "
		       "err=%d (rw=%s; state=%ld/0x%lx; pos=%lld)\n",
		       err, (op == IOCB_CMD_WRITE_ITER) ? "WRITE" : "READ",
		       preq->eng_state, preq->state, pos);
		PLOOP_REQ_SET_ERROR(preq, err);
	}

out:
	ploop_complete_io_request(preq);
}

static void
kaio_read_page(struct ploop_io * io, struct ploop_request * preq,
		struct page * page, sector_t sec)
{
	kaio_io_page(io, IOCB_CMD_READ_ITER, preq, page, sec);
}

static void
kaio_write_page(struct ploop_io * io, struct ploop_request * preq,
		 struct page * page, sector_t sec, int fua)
{
	ploop_prepare_tracker(preq, sec);

	/* No FUA in kaio, convert it to fsync */
	if (fua)
		set_bit(PLOOP_REQ_KAIO_FSYNC, &preq->state);

	kaio_io_page(io, IOCB_CMD_WRITE_ITER, preq, page, sec);
}

static int
kaio_sync_readvec(struct ploop_io * io, struct page ** pvec, unsigned int nr,
		   sector_t sec)
{
	return -EINVAL;
}

static int
kaio_sync_writevec(struct ploop_io * io, struct page ** pvec, unsigned int nr,
		    sector_t sec)
{
	return -EINVAL;
}

struct kaio_comp {
	struct completion comp;
	atomic_t count;
	int error;
};

static inline void kaio_comp_init(struct kaio_comp * c)
{
	init_completion(&c->comp);
	atomic_set(&c->count, 1);
	c->error = 0;
}

static void kaio_sync_io_complete(u64 data, long err)
{

	struct kaio_comp *comp = (struct kaio_comp *) data;

	if (unlikely(err < 0)) {
		if (!comp->error)
			comp->error = err;
	}

	if (atomic_dec_and_test(&comp->count))
		complete(&comp->comp);
}

static int
kaio_sync_io(struct ploop_io * io, int op, struct page * page,
	     unsigned int len, unsigned int off, sector_t sec)
{
	struct kiocb *iocb;
	struct iov_iter iter;
	struct bio_vec bvec;
	loff_t pos = (loff_t) sec << 9;
	struct file *file = io->files.file;
	struct kaio_comp comp;
	int err;

	kaio_comp_init(&comp);

	iocb = aio_kernel_alloc(GFP_NOIO);
	if (!iocb)
		return -ENOMEM;

	bvec.bv_page = page;
	bvec.bv_len = len;
	bvec.bv_offset = off;

	iov_iter_init_bvec(&iter, &bvec, 1, bvec_length(&bvec, 1), 0);
	aio_kernel_init_iter(iocb, file, op, &iter, pos);
	aio_kernel_init_callback(iocb, kaio_sync_io_complete, (u64)&comp);

	atomic_inc(&comp.count);

	err = aio_kernel_submit(iocb);
	if (err) {
		printk("kaio_sync_io: aio_kernel_submit failed with "
		       "err=%d (rw=%s; pos=%lld; len=%d off=%d)\n",
		       err, (op == IOCB_CMD_WRITE_ITER) ? "WRITE" : "READ",
		       pos, len, off);
		comp.error = err;
		if (atomic_dec_and_test(&comp.count))
			complete(&comp.comp);
	}

	if (atomic_dec_and_test(&comp.count))
		complete(&comp.comp);

	wait_for_completion(&comp.comp);

	if (!err && comp.error)
		printk("kaio_sync_io: kaio failed with err=%d "
		       "(rw=%s; pos=%lld; len=%d off=%d)\n",
		       comp.error,
		       (op == IOCB_CMD_WRITE_ITER) ? "WRITE" : "READ",
		       pos, len, off);

	return comp.error;
}

static int
kaio_sync_read(struct ploop_io * io, struct page * page, unsigned int len,
		unsigned int off, sector_t sec)
{
	return kaio_sync_io(io, IOCB_CMD_READ_ITER, page, len, off, sec);
}

static int
kaio_sync_write(struct ploop_io * io, struct page * page, unsigned int len,
		 unsigned int off, sector_t sec)
{
	int ret;

	ret = kaio_sync_io(io, IOCB_CMD_WRITE_ITER, page, len, off, sec);

	if (sec < io->plo->track_end)
		ploop_tracker_notify(io->plo, sec);

	return ret;
}

static int kaio_alloc_sync(struct ploop_io * io, loff_t pos, loff_t len)
{
	return __kaio_truncate(io, io->files.file, pos + len);
}

static int kaio_open(struct ploop_io * io)
{
	struct file * file = io->files.file;
	struct ploop_delta * delta = container_of(io, struct ploop_delta, io);
	int err;

	if (file == NULL)
		return -EBADF;

	io->files.mapping = file->f_mapping;
	io->files.inode = io->files.mapping->host;
	io->files.bdev = io->files.inode->i_sb->s_bdev;

	mutex_lock(&io->files.inode->i_mutex);
	err = ploop_kaio_open(file, delta->flags & PLOOP_FMT_RDONLY);
	mutex_unlock(&io->files.inode->i_mutex);

	if (err)
		return err;

	io->files.em_tree = &dummy_em_tree;

	if (!(delta->flags & PLOOP_FMT_RDONLY)) {
		io->fsync_thread = kthread_create(kaio_fsync_thread,
						  io, "ploop_fsync%d",
						  delta->plo->index);
		if (io->fsync_thread == NULL) {
			ploop_kaio_close(io->files.mapping, 0);
			return -ENOMEM;
		}

		wake_up_process(io->fsync_thread);
	}

	return 0;
}

static int kaio_prepare_snapshot(struct ploop_io * io, struct ploop_snapdata *sd)
{
	struct file * file = io->files.file;
	struct path   path;
	int err;

	path.mnt = F_MNT(file);
	path.dentry = F_DENTRY(file);

	file = dentry_open(&path, O_RDONLY|O_LARGEFILE|O_DIRECT,
			   current_cred());
	if (IS_ERR(file))
		return PTR_ERR(file);

	/* Sanity checks */
	if (io->files.mapping != file->f_mapping ||
	    io->files.inode != file->f_mapping->host) {
		fput(file);
		return -EINVAL;
	}

	err = vfs_fsync(file, 0);
	if (err) {
		fput(file);
		return err;
	}

	sd->file = file;
	return 0;
}

static int kaio_complete_snapshot(struct ploop_io * io, struct ploop_snapdata *sd)
{
	struct file * file = io->files.file;
	int ret;

	ret = kaio_release_prealloced(io);
	if (ret)
		return ret;

	mutex_lock(&io->plo->sysfs_mutex);
	io->files.file = sd->file;
	sd->file = NULL;
	mutex_unlock(&io->plo->sysfs_mutex);

	ploop_kaio_downgrade(io->files.mapping);

	if (io->fsync_thread) {
		kthread_stop(io->fsync_thread);
		io->fsync_thread = NULL;
	}

	fput(file);
	return 0;
}

static int kaio_prepare_merge(struct ploop_io * io, struct ploop_snapdata *sd)
{
	struct file * file = io->files.file;
	struct path   path;
	int err;

	path.mnt = F_MNT(file);
	path.dentry = F_DENTRY(file);

	file = dentry_open(&path, O_RDWR|O_LARGEFILE|O_DIRECT, current_cred());
	if (IS_ERR(file))
		return PTR_ERR(file);

	/* Sanity checks */
	if (io->files.mapping != file->f_mapping ||
	    io->files.inode != file->f_mapping->host) {
		err = -EINVAL;
		goto prep_merge_done;
	}

	err = vfs_fsync(file, 0);
	if (err)
		goto prep_merge_done;

	err = ploop_kaio_upgrade(io->files.mapping);
	if (err)
		goto prep_merge_done;

	io->fsync_thread = kthread_create(kaio_fsync_thread,
					  io, "ploop_fsync%d",
					  io->plo->index);
	if (io->fsync_thread == NULL) {
		err = -ENOMEM;
		goto prep_merge_done;
	}

	wake_up_process(io->fsync_thread);

	sd->file = file;

prep_merge_done:
	if (err)
		fput(file);
	return err;
}

static int kaio_start_merge(struct ploop_io * io, struct ploop_snapdata *sd)
{
	struct file * file = io->files.file;

	mutex_lock(&io->plo->sysfs_mutex);
	io->files.file = sd->file;
	sd->file = NULL;
	mutex_unlock(&io->plo->sysfs_mutex);

	fput(file);
	return 0;
}

static int __kaio_truncate(struct ploop_io * io, struct file * file, u64 pos)
{
	int err;
	struct iattr newattrs;

	if (file->f_mapping != io->files.mapping)
		return -EINVAL;

	newattrs.ia_size  = pos;
	newattrs.ia_valid = ATTR_SIZE;

	mutex_lock(&io->files.inode->i_mutex);
	io->files.inode->i_flags &= ~S_SWAPFILE;
	err = notify_change(F_DENTRY(file), &newattrs, NULL);
	io->files.inode->i_flags |= S_SWAPFILE;
	mutex_unlock(&io->files.inode->i_mutex);

	if (err) {
		printk("__kaio_truncate(i_ino=%ld of level=%d on ploop%d, "
		       "pos=%lld): notify_change failed with err=%d "
		       "(i_size=%lld)\n",
		       io->files.inode->i_ino, io2level(io), io->plo->index,
		       pos, err, i_size_read(io->files.inode));
		return err;
	}

	err = vfs_fsync(file, 0);

	if (err)
		printk("__kaio_truncate(i_ino=%ld of level=%d on ploop%d, "
		       "pos=%lld): vfs_fsync failed with err=%d\n",
		       io->files.inode->i_ino, io2level(io), io->plo->index,
		       pos, err);

	return err;
}

static int kaio_truncate(struct ploop_io * io, struct file * file,
			  __u32 alloc_head)
{
	return __kaio_truncate(io, file,
			       (u64)alloc_head << (io->plo->cluster_log + 9));
}

static void kaio_unplug(struct ploop_io * io)
{
	/* Need more thinking how to implement unplug */
}

static void kaio_queue_settings(struct ploop_io * io, struct request_queue * q)
{
	blk_set_stacking_limits(&q->limits);
}

static void kaio_issue_flush(struct ploop_io * io, struct ploop_request *preq)
{
	struct ploop_delta *delta = container_of(io, struct ploop_delta, io);

	preq->eng_state = PLOOP_E_COMPLETE;
	preq->req_rw &= ~REQ_FLUSH;

	spin_lock_irq(&io->plo->lock);

	if (delta->flags & PLOOP_FMT_RDONLY)
		list_add_tail(&preq->list, &io->plo->ready_queue);
	else
		kaio_queue_fsync_req(preq);

	spin_unlock_irq(&io->plo->lock);
}

static int kaio_autodetect(struct ploop_io * io)
{
	struct file  * file  = io->files.file;
	struct inode * inode = file->f_mapping->host;

	if (inode->i_sb->s_magic != FUSE_SUPER_MAGIC)
		return -1; /* not mine */

	if (!(file->f_flags & O_DIRECT)) {
		ploop_io_report_fn(file, "File opened w/o O_DIRECT");
		return -1;
	}

	if (file->f_mapping->a_ops->direct_IO_bvec == NULL) {
		printk("Cannot run kaio over fs (%s) w/o direct_IO_bvec\n",
		       file->f_mapping->host->i_sb->s_type->name);
		return -1;
	}

	if (file->f_mapping->a_ops->direct_IO_page == NULL) {
		printk("Cannot run kaio over fs (%s) w/o direct_IO_page\n",
		       file->f_mapping->host->i_sb->s_type->name);
		return -1;
	}

	return 0;
}

static struct ploop_io_ops ploop_io_ops_kaio =
{
	.id		=	PLOOP_IO_KAIO,
	.name		=	"kaio",
	.owner		=	THIS_MODULE,

	.unplug		=	kaio_unplug,

	.alloc		=	kaio_alloc_sync,
	.submit		=	kaio_submit,
	.submit_alloc	=	kaio_submit_alloc,
	.read_page	=	kaio_read_page,
	.write_page	=	kaio_write_page,
	.sync_read	=	kaio_sync_read,
	.sync_write	=	kaio_sync_write,
	.sync_readvec	=	kaio_sync_readvec,
	.sync_writevec	=	kaio_sync_writevec,

	.init		=	kaio_init,
	.destroy	=	kaio_destroy,
	.open		=	kaio_open,
	.sync		=	kaio_sync,
	.stop		=	kaio_stop,
	.prepare_snapshot =	kaio_prepare_snapshot,
	.complete_snapshot =	kaio_complete_snapshot,
	.prepare_merge	=	kaio_prepare_merge,
	.start_merge	=	kaio_start_merge,
	.truncate	=	kaio_truncate,

	.queue_settings	=	kaio_queue_settings,
	.issue_flush	=	kaio_issue_flush,

	.i_size_read	=	generic_i_size_read,
	.f_mode		=	generic_f_mode,

	.autodetect     =       kaio_autodetect,
};

static int __init pio_kaio_mod_init(void)
{
	return ploop_register_io(&ploop_io_ops_kaio);
}

static void __exit pio_kaio_mod_exit(void)
{
	ploop_unregister_io(&ploop_io_ops_kaio);
}

module_init(pio_kaio_mod_init);
module_exit(pio_kaio_mod_exit);

MODULE_LICENSE("GPL");
