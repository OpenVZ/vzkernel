/*
 *  drivers/block/ploop/io_nfs.c
 *
 *  Copyright (c) 2010-2017 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *  Copyright (c) 2019 Jelastic Inc.
 *
 */

#include <linux/module.h>

#include <linux/nfs_fs.h>

#include <linux/ploop/ploop.h>

#define MAX_NBIO_PAGES	32

struct workqueue_struct *nfsio_workqueue;

static struct nfs_pgio_header *nfsio_wbio_alloc(unsigned int pagecount);
static struct nfs_pgio_header *nfsio_rbio_alloc(unsigned int pagecount);
static struct nfs_commit_data *nfsio_cbio_alloc(void);
static void nfsio_rbio_release(void *);
static void nfsio_wbio_release(void *);
static void nfsio_cbio_release(void *);
static int verify_bounce(struct nfs_pgio_header * nreq);

extern int nfs_initiate_commit(struct rpc_clnt *clnt,
			       struct nfs_commit_data *data,
			       const struct nfs_rpc_ops *nfs_ops,
			       const struct rpc_call_ops *call_ops,
			       int how, int flags);

void nfsio_complete_io_state(struct ploop_request * preq)
{
	struct ploop_device * plo = preq->plo;
	unsigned long flags;

	spin_lock_irqsave(&plo->lock, flags);
	if (preq->error)
		set_bit(PLOOP_S_ABORT, &plo->state);

	if (!preq->error &&
	    test_bit(PLOOP_REQ_UNSTABLE, &preq->state)) {
		struct ploop_io * io = &map_writable_delta(preq)->io;
		list_add_tail(&preq->list, &io->fsync_queue);
		io->fsync_qlen++;
		if (waitqueue_active(&io->fsync_waitq))
			wake_up_interruptible(&io->fsync_waitq);
		plo->st.bio_syncwait++;
	} else {
		list_add_tail(&preq->list, &plo->ready_queue);
		if (waitqueue_active(&plo->waitq))
			wake_up_interruptible(&plo->waitq);
	}
	spin_unlock_irqrestore(&plo->lock, flags);
}


static inline void nfsio_prepare_io_request(struct ploop_request * preq)
{
	atomic_set(&preq->io_count, 1);
}

static inline void nfsio_complete_io_request(struct ploop_request * preq)
{
	if (atomic_dec_and_test(&preq->io_count))
		nfsio_complete_io_state(preq);
}

static void nfsio_read_result(struct rpc_task *task, void *calldata)
{
	int status;
	struct nfs_pgio_header *nreq = calldata;

	status = NFS_PROTO(nreq->inode)->read_done(task, nreq);
	if (status != 0)
		return;

	if (task->tk_status == -ESTALE) {
		set_bit(NFS_INO_STALE, &NFS_I(nreq->inode)->flags);
		nfs_mark_for_revalidate(nreq->inode);
	}
}

static void nfsio_read_release(void *calldata)
{
	struct nfs_pgio_header *nreq = calldata;
	struct ploop_request *preq = (struct ploop_request *) nreq->req;
	int status = nreq->task.tk_status;

	if (unlikely(status < 0))
		PLOOP_REQ_SET_ERROR(preq, status);

	ploop_complete_io_request(preq);

	nfsio_rbio_release(calldata);
}

static const struct rpc_call_ops nfsio_read_ops = {
	.rpc_call_done = nfsio_read_result,
	.rpc_release = nfsio_read_release,
};

static struct nfs_pgio_header *
rbio_init(loff_t pos, struct page * page, unsigned int off, unsigned int len,
	  void * priv, struct inode * inode)
{
	struct nfs_pgio_header * nreq;

	nreq = nfsio_rbio_alloc(MAX_NBIO_PAGES);
	if (unlikely(nreq == NULL))
		return NULL;

	nreq->args.offset = pos;
	nreq->args.pgbase = off;
	nreq->args.count = len;
	nreq->page_array.pagevec[0] = page;
	nreq->page_array.npages = 1;
	nreq->req = priv;
	nreq->inode = inode;
	nreq->args.fh = NFS_FH(inode);
	nreq->args.pages = nreq->page_array.pagevec;
	nreq->res.fattr = &nreq->fattr;
	nreq->res.eof = 0;
	return nreq;
}

static int
rbio_submit(struct ploop_io * io, struct nfs_pgio_header * nreq,
	    const struct rpc_call_ops * cb)
{
	struct nfs_open_context *ctx = nfs_file_open_context(io->files.file);
	struct inode *inode = io->files.inode;
	struct rpc_task *task;

	struct rpc_message msg = {
		.rpc_cred = ctx->cred,
	};

	struct rpc_task_setup task_setup_data = {
		.rpc_client = NFS_CLIENT(inode),
		.rpc_message = &msg,
		.callback_ops = cb,
		.workqueue = nfsio_workqueue,
		.flags = RPC_TASK_ASYNC,
	};

	nreq->res.count = nreq->args.count;
	nreq->cred = msg.rpc_cred;
	nreq->args.context = ctx;

	task_setup_data.task = &nreq->task;
	task_setup_data.callback_data = nreq;
	msg.rpc_argp = &nreq->args;
	msg.rpc_resp = &nreq->res;
	NFS_PROTO(inode)->read_setup(nreq, &msg);

	task = rpc_run_task(&task_setup_data);
	if (unlikely(IS_ERR(task)))
		return PTR_ERR(task);

	rpc_put_task(task);
	return 0;
}

static void
nfsio_submit_read(struct ploop_io *io, struct ploop_request * preq,
		  struct bio_list *sbl, iblock_t iblk, unsigned int size)
{
	struct inode *inode = io->files.inode;
	size_t rsize = NFS_SERVER(inode)->rsize;
	struct nfs_pgio_header *nreq = NULL;
	loff_t pos;
	unsigned int prev_end;
	struct bio * b;

	ploop_prepare_io_request(preq);

	pos = sbl->head->bi_sector;
	pos = ((loff_t)iblk << preq->plo->cluster_log) | (pos & ((1<<preq->plo->cluster_log) - 1));
	pos <<= 9;

	prev_end = PAGE_SIZE;

	for (b = sbl->head; b != NULL; b = b->bi_next) {
		int bv_idx;

		for (bv_idx = 0; bv_idx < b->bi_vcnt; bv_idx++) {
			struct bio_vec * bv = &b->bi_io_vec[bv_idx];

			if (nreq && nreq->args.count + bv->bv_len <= rsize) {
				if (nreq->page_array.pagevec[nreq->page_array.npages-1] == bv->bv_page &&
				    prev_end == bv->bv_offset) {
					nreq->args.count += bv->bv_len;
					pos += bv->bv_len;
					prev_end += bv->bv_len;
					continue;
				}
				if (nreq->page_array.npages < MAX_NBIO_PAGES &&
				    bv->bv_offset == 0 && prev_end == PAGE_SIZE) {
					nreq->args.count += bv->bv_len;
					nreq->page_array.pagevec[nreq->page_array.npages] = bv->bv_page;
					nreq->page_array.npages++;
					pos += bv->bv_len;
					prev_end = bv->bv_offset + bv->bv_len;
					continue;
				}
			}

			if (nreq) {
				int err;

				atomic_inc(&preq->io_count);

				err = rbio_submit(io, nreq, &nfsio_read_ops);
				if (err) {
					PLOOP_REQ_SET_ERROR(preq, err);
					ploop_complete_io_request(preq);
					goto out;
				}
			}

			nreq = rbio_init(pos, bv->bv_page, bv->bv_offset,
					 bv->bv_len, preq, inode);

			if (nreq == NULL) {
				PLOOP_REQ_SET_ERROR(preq, -ENOMEM);
				goto out;
			}

			pos += bv->bv_len;
			prev_end = bv->bv_offset + bv->bv_len;
		}
	}

	if (nreq) {
		int err;

		atomic_inc(&preq->io_count);

		err = rbio_submit(io, nreq, &nfsio_read_ops);
		if (err) {
			PLOOP_REQ_SET_ERROR(preq, err);
			ploop_complete_io_request(preq);
			goto out;
		}
	}

out:
	ploop_complete_io_request(preq);
}

static void nfsio_write_result(struct rpc_task *task, void *calldata)
{
	struct nfs_pgio_header *data = calldata;
	struct nfs_pgio_args	*argp = &data->args;
	struct nfs_pgio_res	*resp = &data->res;
	int status;

	status = NFS_PROTO(data->inode)->write_done(task, data);
	if (status != 0)
		return;

	if (task->tk_status >= 0 && resp->count < argp->count)
		task->tk_status = -EIO;
}

static void nfsio_write_release(void *calldata)
{
	struct nfs_pgio_header *nreq = calldata;
	struct ploop_request *preq = (struct ploop_request *) nreq->req;
	int status = nreq->task.tk_status;

	if (unlikely(status < 0))
		PLOOP_REQ_SET_ERROR(preq, status);

	if (!preq->error &&
	    nreq->res.verf->committed != NFS_FILE_SYNC) {
		if (!test_and_set_bit(PLOOP_REQ_UNSTABLE, &preq->state))
			memcpy(&preq->verf, &nreq->res.verf->verifier, 8);
	}
	nfsio_complete_io_request(preq);

	nfsio_wbio_release(calldata);
}

static const struct rpc_call_ops nfsio_write_ops = {
	.rpc_call_done = nfsio_write_result,
	.rpc_release = nfsio_write_release,
};

static struct nfs_pgio_header *
wbio_init(loff_t pos, struct page * page, unsigned int off, unsigned int len,
	  void * priv, struct inode * inode)
{
	struct nfs_pgio_header * nreq;

	nreq = nfsio_wbio_alloc(MAX_NBIO_PAGES);
	if (unlikely(nreq == NULL))
		return NULL;

	nreq->args.offset = pos;
	nreq->args.pgbase = off;
	nreq->args.count = len;
	nreq->page_array.pagevec[0] = page;
	nreq->page_array.npages = 1;
	nreq->req = priv;
	nreq->inode = inode;
	nreq->args.fh = NFS_FH(inode);
	nreq->args.pages = nreq->page_array.pagevec;
	nreq->args.stable = NFS_UNSTABLE;
	nreq->res.fattr = &nreq->fattr;
	nreq->res.verf = &nreq->verf;
	return nreq;
}

static int wbio_submit(struct ploop_io * io, struct nfs_pgio_header *nreq,
		       const struct rpc_call_ops * cb)
{
	struct nfs_open_context *ctx = nfs_file_open_context(io->files.file);
	struct inode *inode = io->files.inode;

	struct rpc_task *task;
	struct rpc_message msg = {
		.rpc_cred = ctx->cred,
	};

	struct rpc_task_setup task_setup_data = {
		.rpc_client = NFS_CLIENT(inode),
		.rpc_message = &msg,
		.callback_ops = cb,
		.workqueue = nfsio_workqueue,
		.flags = RPC_TASK_ASYNC,
	};

	if (verify_bounce(nreq))
		return -ENOMEM;

	nreq->res.count = nreq->args.count;
	nreq->args.context = ctx;
	nreq->cred = msg.rpc_cred;

	task_setup_data.task = &nreq->task;
	task_setup_data.callback_data = nreq;
	msg.rpc_argp = &nreq->args;
	msg.rpc_resp = &nreq->res;
	NFS_PROTO(inode)->write_setup(nreq, &msg);

	task = rpc_run_task(&task_setup_data);
	if (unlikely(IS_ERR(task)))
		return PTR_ERR(task);
	rpc_put_task(task);
	return 0;
}

static void
nfsio_submit_write(struct ploop_io *io, struct ploop_request * preq,
		   struct bio_list *sbl, iblock_t iblk, unsigned int size)
{
	struct inode *inode = io->files.inode;
	size_t wsize = NFS_SERVER(inode)->wsize;
	struct nfs_pgio_header *nreq = NULL;
	loff_t pos;
	struct bio * b;
	unsigned int prev_end;

	nfsio_prepare_io_request(preq);

	pos = sbl->head->bi_sector;
	pos = ((loff_t)iblk << preq->plo->cluster_log) | (pos & ((1<<preq->plo->cluster_log) - 1));
	ploop_prepare_tracker(preq, pos);
	pos <<= 9;

	prev_end = PAGE_SIZE;

	for (b = sbl->head; b != NULL; b = b->bi_next) {
		int bv_idx;

		for (bv_idx = 0; bv_idx < b->bi_vcnt; bv_idx++) {
			struct bio_vec * bv = &b->bi_io_vec[bv_idx];

			if (nreq && nreq->args.count + bv->bv_len <= wsize) {
				if (nreq->page_array.pagevec[nreq->page_array.npages-1] == bv->bv_page &&
				    prev_end == bv->bv_offset) {
					nreq->args.count += bv->bv_len;
					pos += bv->bv_len;
					prev_end += bv->bv_len;
					continue;
				}
				if (nreq->page_array.npages < MAX_NBIO_PAGES &&
				    bv->bv_offset == 0 && prev_end == PAGE_SIZE) {
					nreq->args.count += bv->bv_len;
					nreq->page_array.pagevec[nreq->page_array.npages] = bv->bv_page;
					nreq->page_array.npages++;
					pos += bv->bv_len;
					prev_end = bv->bv_offset + bv->bv_len;
					continue;
				}
			}

			if (nreq) {
				int err;
				atomic_inc(&preq->io_count);
				err = wbio_submit(io, nreq, &nfsio_write_ops);
				if (err) {
					PLOOP_REQ_SET_ERROR(preq, err);
					nfsio_complete_io_request(preq);
					goto out;
				}
			}

			nreq = wbio_init(pos, bv->bv_page, bv->bv_offset,
					 bv->bv_len, preq, inode);

			if (nreq == NULL) {
				PLOOP_REQ_SET_ERROR(preq, -ENOMEM);
				goto out;
			}

			prev_end = bv->bv_offset + bv->bv_len;
			pos += bv->bv_len;
		}
	}

	if (nreq) {
		int err;
		atomic_inc(&preq->io_count);
		err = wbio_submit(io, nreq, &nfsio_write_ops);
		if (err) {
			PLOOP_REQ_SET_ERROR(preq, err);
			nfsio_complete_io_request(preq);
		}
	}

out:
	nfsio_complete_io_request(preq);
}

static void
nfsio_submit(struct ploop_io *io, struct ploop_request * preq,
	     unsigned long rw,
	     struct bio_list *sbl, iblock_t iblk, unsigned int size)
{
	if (iblk == PLOOP_ZERO_INDEX)
		iblk = 0;

	if (rw & REQ_WRITE)
		nfsio_submit_write(io, preq, sbl, iblk, size);
	else
		nfsio_submit_read(io, preq, sbl, iblk, size);
}

struct bio_list_walk
{
	struct bio * cur;
	int idx;
	int bv_off;
};

static void
nfsio_submit_write_pad(struct ploop_io *io, struct ploop_request * preq,
		       struct bio_list *sbl, iblock_t iblk, unsigned int size)
{
	struct inode *inode = io->files.inode;
	size_t wsize = NFS_SERVER(inode)->wsize;
	struct nfs_pgio_header *nreq = NULL;
	struct bio_list_walk bw;
	unsigned prev_end;

	loff_t pos, end_pos, start, end;

	/* pos..end_pos is the range which we are going to write */
	pos = (loff_t)iblk << (preq->plo->cluster_log + 9);
	end_pos = pos + (1 << (preq->plo->cluster_log + 9));

	/* start..end is data that we have. The rest must be zero padded. */
	start = pos + ((sbl->head->bi_sector & ((1<<preq->plo->cluster_log) - 1)) << 9);
	end = start + (size << 9);

	nfsio_prepare_io_request(preq);
	ploop_prepare_tracker(preq, start >> 9);

	prev_end = PAGE_SIZE;

#if 1
	/* GCC, shut up! */
	bw.cur = sbl->head;
	bw.idx = 0;
	bw.bv_off = 0;
	BUG_ON(bw.cur->bi_io_vec[0].bv_len & 511);
#endif

	while (pos < end_pos) {
		struct page * page;
		unsigned int poff, plen;

		if (pos < start) {
			page = ZERO_PAGE(0);
			poff = 0;
			plen = start - pos;
			if (plen > PAGE_SIZE)
				plen = PAGE_SIZE;
		} else if (pos >= end) {
			page = ZERO_PAGE(0);
			poff = 0;
			plen = end_pos - pos;
			if (plen > PAGE_SIZE)
				plen = PAGE_SIZE;
		} else {
			/* pos >= start && pos < end */
			struct bio_vec * bv;

			if (pos == start) {
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
			plen = bv->bv_len - bw.bv_off;
		}

		if (nreq && nreq->args.count + plen <= wsize) {
			if (nreq->page_array.pagevec[nreq->page_array.npages-1] == page &&
			    prev_end == poff) {
				nreq->args.count += plen;
				pos += plen;
				bw.bv_off += plen;
				prev_end += plen;
				continue;
			}
			if (nreq->page_array.npages < MAX_NBIO_PAGES &&
			    poff == 0 && prev_end == PAGE_SIZE) {
				nreq->args.count += plen;
				nreq->page_array.pagevec[nreq->page_array.npages] = page;
				nreq->page_array.npages++;
				pos += plen;
				bw.bv_off += plen;
				prev_end = poff + plen;
				continue;
			}
		}

		if (nreq) {
			int err;
			atomic_inc(&preq->io_count);
			err = wbio_submit(io, nreq, &nfsio_write_ops);
			if (err) {
				PLOOP_REQ_SET_ERROR(preq, err);
				nfsio_complete_io_request(preq);
				goto out;
			}
		}

		nreq = wbio_init(pos, page, poff, plen, preq, inode);

		if (nreq == NULL) {
			PLOOP_REQ_SET_ERROR(preq, -ENOMEM);
			goto out;
		}

		prev_end = poff + plen;
		pos += plen;
		bw.bv_off += plen;
	}

	if (nreq) {
		int err;
		atomic_inc(&preq->io_count);
		err = wbio_submit(io, nreq, &nfsio_write_ops);
		if (err) {
			PLOOP_REQ_SET_ERROR(preq, err);
			nfsio_complete_io_request(preq);
		}
	}

out:
	nfsio_complete_io_request(preq);
}

static int
nfsio_submit_alloc(struct ploop_io *io, struct ploop_request * preq,
		 struct bio_list * sbl, unsigned int size)
{
	iblock_t iblk = io->alloc_head++;

	if (!(io->files.file->f_mode & FMODE_WRITE)) {
		PLOOP_FAIL_REQUEST(preq, -EBADF);
		return -1;
	}
	preq->iblock = iblk;
	preq->eng_state = PLOOP_E_DATA_WBI;

	nfsio_submit_write_pad(io, preq, sbl, iblk, size);
	return 1;
}

static void nfsio_destroy(struct ploop_io * io)
{
	if (io->fsync_thread) {
		kthread_stop(io->fsync_thread);
		io->fsync_thread = NULL;
	}

	if (io->files.file) {
		struct file * file = io->files.file;
		mutex_lock(&io->plo->sysfs_mutex);
		io->files.file = NULL;
		if (io->files.mapping)
			(void)invalidate_inode_pages2(io->files.mapping);
		mutex_unlock(&io->plo->sysfs_mutex);
		fput(file);
	}
}

static int nfsio_sync(struct ploop_io * io)
{
	return 0;
}

static int nfsio_stop(struct ploop_io * io)
{
	return 0;
}


static int
nfsio_init(struct ploop_io * io)
{
	INIT_LIST_HEAD(&io->fsync_queue);
	init_waitqueue_head(&io->fsync_waitq);
	return 0;
}


static void
nfsio_read_page(struct ploop_io * io, struct ploop_request * preq,
		struct page * page, sector_t sec)
{
	struct inode *inode = io->files.inode;
	struct nfs_pgio_header *nreq;
	int err;

	ploop_prepare_io_request(preq);

	nreq = rbio_init((loff_t)sec << 9, page, 0, PAGE_SIZE, preq, inode);
	if (nreq == NULL) {
		PLOOP_REQ_SET_ERROR(preq, -ENOMEM);
		goto out;
	}

	atomic_inc(&preq->io_count);

	err = rbio_submit(io, nreq, &nfsio_read_ops);
	if (err) {
		PLOOP_REQ_SET_ERROR(preq, err);
		ploop_complete_io_request(preq);
	}

out:
	ploop_complete_io_request(preq);
}

static void
nfsio_write_page(struct ploop_io * io, struct ploop_request * preq,
		 struct page * page, sector_t sec, unsigned long fua)
{
	struct inode *inode = io->files.inode;
	struct nfs_pgio_header *nreq;
	int err;

	nfsio_prepare_io_request(preq);
	ploop_prepare_tracker(preq, sec);

	nreq = wbio_init((loff_t)sec << 9, page, 0, PAGE_SIZE, preq, inode);

	if (nreq == NULL) {
		PLOOP_REQ_SET_ERROR(preq, -ENOMEM);
		goto out;
	}

	atomic_inc(&preq->io_count);
	err = wbio_submit(io, nreq, &nfsio_write_ops);
	if (err) {
		PLOOP_REQ_SET_ERROR(preq, err);
		nfsio_complete_io_request(preq);
	}

out:
	nfsio_complete_io_request(preq);
}

struct nfsio_comp
{
	struct completion comp;
	atomic_t count;
	int error;
	u64 * verf;
};

static inline void nfsio_comp_init(struct nfsio_comp * c)
{
	init_completion(&c->comp);
	atomic_set(&c->count, 1);
	c->error = 0;
}

static void nfsio_read_release_sync(void *calldata)
{
	struct nfs_pgio_header *nreq = calldata;
	struct nfsio_comp *comp = (struct nfsio_comp *) nreq->req;
	int status = nreq->task.tk_status;

	if (unlikely(status < 0)) {
		if (!comp->error)
			comp->error = status;
	}

	if (atomic_dec_and_test(&comp->count))
		complete(&comp->comp);

	nfsio_rbio_release(calldata);
}

static const struct rpc_call_ops nfsio_read_direct_sync_ops = {
	.rpc_call_done = nfsio_read_result,
	.rpc_release = nfsio_read_release_sync,
};



static int
nfsio_sync_readvec(struct ploop_io * io, struct page ** pvec, unsigned int nr,
		   sector_t sec)
{
	struct inode *inode = io->files.inode;
	size_t rsize = NFS_SERVER(inode)->rsize;
	struct nfs_pgio_header *nreq = NULL;
	loff_t pos;
	int i;
	struct nfsio_comp comp;

	nfsio_comp_init(&comp);

	pos = (loff_t)sec << 9;

	i = 0;
	while (i < nr) {
		int err;
		int k;

		nreq = rbio_init(pos, pvec[i], 0, PAGE_SIZE, &comp, inode);
		if (nreq == NULL) {
			comp.error = -ENOMEM;
			break;
		}

		nreq->page_array.npages = rsize / PAGE_SIZE;
		if (nreq->page_array.npages > nr - i)
			nreq->page_array.npages = nr - i;
		for (k = 0; k < nreq->page_array.npages; k++) {
			nreq->page_array.pagevec[k] = pvec[i + k];
		}
		nreq->args.count = nreq->page_array.npages*PAGE_SIZE;

		i += nreq->page_array.npages;
		pos += nreq->page_array.npages*PAGE_SIZE;

		atomic_inc(&comp.count);

		err = rbio_submit(io, nreq, &nfsio_read_direct_sync_ops);
		if (err) {
			comp.error = err;
			if (atomic_dec_and_test(&comp.count))
				complete(&comp.comp);
			break;
		}
	}

	if (atomic_dec_and_test(&comp.count))
		complete(&comp.comp);

	wait_for_completion(&comp.comp);

	return comp.error;
}

static void nfsio_write_release_sync(void *calldata)
{
	struct nfs_pgio_header *nreq = calldata;
	struct nfsio_comp *comp = (struct nfsio_comp *) nreq->req;
	int status = nreq->task.tk_status;

	if (unlikely(status < 0)) {
		if (!comp->error)
			comp->error = status;
	}

	if (atomic_dec_and_test(&comp->count))
		complete(&comp->comp);

	nfsio_wbio_release(calldata);
}

static const struct rpc_call_ops nfsio_write_direct_sync_ops = {
	.rpc_call_done = nfsio_write_result,
	.rpc_release = nfsio_write_release_sync,
};

static int
nfsio_sync_writevec(struct ploop_io * io, struct page ** pvec, unsigned int nr,
		    sector_t sec)
{
	struct inode *inode = io->files.inode;
	size_t wsize = NFS_SERVER(inode)->wsize;
	struct nfs_pgio_header *nreq;
	loff_t pos;
	int i;

	struct nfsio_comp comp;

	nfsio_comp_init(&comp);

	pos = (loff_t)sec << 9;

	i = 0;
	while (i < nr) {
		int err;
		int k;

		nreq = wbio_init(pos, pvec[i], 0, PAGE_SIZE, &comp, inode);
		if (nreq == NULL) {
			comp.error = -ENOMEM;
			break;
		}

		nreq->page_array.npages = wsize / PAGE_SIZE;
		if (nreq->page_array.npages > nr - i)
			nreq->page_array.npages = nr - i;
		for (k = 0; k < nreq->page_array.npages; k++) {
			nreq->page_array.pagevec[k] = pvec[i + k];
		}
		nreq->args.count = nreq->page_array.npages*PAGE_SIZE;
		nreq->args.stable = NFS_FILE_SYNC;

		i += nreq->page_array.npages;
		pos += nreq->page_array.npages*PAGE_SIZE;

		atomic_inc(&comp.count);

		err = wbio_submit(io, nreq, &nfsio_write_direct_sync_ops);
		if (err) {
			comp.error = err;
			if (atomic_dec_and_test(&comp.count))
				complete(&comp.comp);
			break;
		}
	}

	if (atomic_dec_and_test(&comp.count))
		complete(&comp.comp);

	wait_for_completion(&comp.comp);

	if (sec < io->plo->track_end)
		ploop_tracker_notify(io->plo, sec);

	return comp.error;
}

static int
nfsio_sync_read(struct ploop_io * io, struct page * page, unsigned int len,
		unsigned int off, sector_t sec)
{
	struct inode *inode = io->files.inode;
	struct nfs_pgio_header *nreq = NULL;
	int err;

	struct nfsio_comp comp;

	nfsio_comp_init(&comp);

	nreq = rbio_init((loff_t)sec << 9, page, off, len, &comp, inode);
	if (nreq == NULL)
		return -ENOMEM;

	atomic_inc(&comp.count);

	err = rbio_submit(io, nreq, &nfsio_read_direct_sync_ops);
	if (err) {
		comp.error = err;
		if (atomic_dec_and_test(&comp.count))
			complete(&comp.comp);
	}

	if (atomic_dec_and_test(&comp.count))
		complete(&comp.comp);

	wait_for_completion(&comp.comp);

	return comp.error;
}

static int
nfsio_sync_write(struct ploop_io * io, struct page * page, unsigned int len,
		 unsigned int off, sector_t sec)
{
	struct inode *inode = io->files.inode;
	struct nfs_pgio_header *nreq;
	struct nfsio_comp comp;
	int err;

	nfsio_comp_init(&comp);

	nreq = wbio_init((loff_t)sec << 9, page, off, len, &comp, inode);
	if (nreq == NULL)
		return -ENOMEM;

	nreq->args.stable = NFS_FILE_SYNC;

	atomic_inc(&comp.count);
	err = wbio_submit(io, nreq, &nfsio_write_direct_sync_ops);
	if (err) {
		comp.error = err;
		if (atomic_dec_and_test(&comp.count))
			complete(&comp.comp);
	}

	if (atomic_dec_and_test(&comp.count))
		complete(&comp.comp);

	wait_for_completion(&comp.comp);

	if (sec < io->plo->track_end)
		ploop_tracker_notify(io->plo, sec);

	return comp.error;
}

static int nfsio_alloc_sync(struct ploop_io * io, loff_t pos, loff_t len)
{
	int head_len = len & (PAGE_SIZE - 1);
	int nr_total = len >> PAGE_SHIFT;
	int nr = 1 << (io->plo->cluster_log + 9 - PAGE_SHIFT);
	struct page * pvec[nr];
	int i;
	int err = 0;

	for (i = 0; i < nr; i++)
		pvec[i] = ZERO_PAGE(0);

	if (head_len) {
		err = nfsio_sync_write(io, pvec[0], head_len, 0, pos >> 9);
		if (err)
			return err;

		pos += head_len;
	}

	while (nr_total > 0) {
		int n = (nr_total < nr) ? nr_total : nr;

		err = nfsio_sync_writevec(io, pvec, n, pos >> 9);
		if (err)
			return err;

		pos += n << PAGE_SHIFT;
		nr_total -= n;
	}

	io->alloc_head = pos >> (io->plo->cluster_log + 9);
	return 0;
}

static void nfsio_commit_result(struct rpc_task *task, void *calldata)
{
	struct nfs_commit_data *data = calldata;

	NFS_PROTO(data->inode)->commit_done(task, data);
}

static void nfsio_commit_release(void *calldata)
{
	struct nfs_commit_data *creq = calldata;
	struct nfsio_comp *comp = (struct nfsio_comp *) creq->dreq;
	int status = creq->task.tk_status;

	if (status < 0) {
		if (!comp->error)
			comp->error = status;
	}

	memcpy(comp->verf, &creq->verf.verifier, 8);

	if (atomic_dec_and_test(&comp->count))
		complete(&comp->comp);

	nfsio_cbio_release(calldata);
}

void nfsio_commit_prepare(struct rpc_task *task, void *calldata)
{
	struct nfs_commit_data *data = calldata;

	NFS_PROTO(data->inode)->commit_rpc_prepare(task, data);
}

static const struct rpc_call_ops nfsio_commit_ops = {
	.rpc_call_prepare = nfsio_commit_prepare,
	.rpc_call_done = nfsio_commit_result,
	.rpc_release = nfsio_commit_release,
};

static struct nfs_open_context *
nfsio_get_open_context(struct nfs_open_context *ctx)
{
	BUG_ON(!ctx);
	atomic_inc(&ctx->lock_context.count);
	return ctx;
}

static struct nfs_commit_data *
cbio_init(struct ploop_io * io, void * priv)
{
	struct inode *inode = io->files.inode;
	struct nfs_open_context *ctx;
	struct nfs_commit_data * creq;

	creq = nfsio_cbio_alloc();
	if (unlikely(creq == NULL))
		return NULL;

	ctx = nfs_file_open_context(io->files.file);

	creq->inode	  = inode;
	creq->cred	  = ctx->cred;
	creq->mds_ops     = &nfsio_commit_ops;
	creq->dreq	  = priv;

	creq->args.fh     = NFS_FH(inode);
	creq->args.offset = 0;
	creq->args.count  = 0;
	creq->context     = nfsio_get_open_context(ctx);
	creq->res.fattr   = &creq->fattr;
	creq->res.verf    = &creq->verf;

	return creq;
}

static int nfsio_commit(struct ploop_io *io, u64 * verf)
{
	struct inode *inode = io->files.inode;
	struct nfs_commit_data *creq;
	struct nfsio_comp comp;
	int err;

	nfsio_comp_init(&comp);
	comp.verf = verf;

	creq = cbio_init(io, &comp);
	if (unlikely(creq == NULL))
		return -ENOMEM;

	atomic_inc(&comp.count);

	err = nfs_initiate_commit(NFS_CLIENT(inode), creq,
				  NFS_PROTO(inode), creq->mds_ops, 0, 0);
	if (err) {
		comp.error = err;
		if (atomic_dec_and_test(&comp.count))
			complete(&comp.comp);
	}

	if (atomic_dec_and_test(&comp.count))
		complete(&comp.comp);

	wait_for_completion(&comp.comp);

	if (err)
		nfsio_cbio_release(creq);

	return comp.error;
}

/* Unfortunately, state machine does not record, what
 * it is doing exactly. We have to do some ugly "reverse engineering", which
 * is not good of course. _XXX_ The function is just a proof of concept,
 * it must be remade.
 */

static void resubmit(struct ploop_request * preq)
{
	struct ploop_delta * delta = ploop_top_delta(preq->plo);
	unsigned long sec;

	switch (preq->eng_state) {
	case PLOOP_E_INDEX_WB:
		delta = map_writable_delta(preq);
		map_index(delta, preq, &sec);
		nfsio_write_page(&delta->io, preq,
				 preq->sinfo.wi.tpage,
				 sec, 0);
		break;
	case PLOOP_E_DATA_WBI:
		if (preq->aux_bio) {
			struct bio_list tbl;
			tbl.head = tbl.tail = preq->aux_bio;
			nfsio_submit_write_pad(&delta->io, preq, &tbl,
					       preq->iblock, 1<<preq->plo->cluster_log);
		} else {
			nfsio_submit_write_pad(&delta->io, preq, &preq->bl,
					       preq->iblock, preq->req_size);
		}
		break;
	case PLOOP_E_COMPLETE:
	case PLOOP_E_RELOC_NULLIFY:
		if (preq->aux_bio) {
			struct bio_list tbl;
			tbl.head = tbl.tail = preq->aux_bio;
			nfsio_submit_write(&delta->io, preq, &tbl,
					   preq->iblock, 1<<preq->plo->cluster_log);
		} else {
			nfsio_submit_write(&delta->io, preq, &preq->bl,
					   preq->iblock, preq->req_size);
		}
		break;
	default:
		printk("Resubmit bad state %lu\n\n", preq->eng_state);
		BUG();
	}
}

static int nfsio_fsync_thread(void * data)
{
	struct ploop_io * io = data;
	struct ploop_device * plo = io->plo;

	set_user_nice(current, -20);

	spin_lock_irq(&plo->lock);
	while (!kthread_should_stop() || !list_empty(&io->fsync_queue)) {
		int err;
		LIST_HEAD(list);
		u64 verf;

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

		err = 0;
		if (!list_empty(&list)) {
			err = nfsio_commit(io, &verf);
		}

		spin_lock_irq(&plo->lock);

		while (!list_empty(&list)) {
			struct ploop_request * preq;
			preq = list_entry(list.next, struct ploop_request, list);
			list_del(&preq->list);
			clear_bit(PLOOP_REQ_UNSTABLE, &preq->state);
			io->fsync_qlen--;

			if (err) {
				PLOOP_REQ_SET_ERROR(preq, err);
			} else if (memcmp(&preq->verf, &verf, 8)) {
				/* Oops, server reboot. Must resubmit write. */
				spin_unlock_irq(&plo->lock);
				resubmit(preq);
				spin_lock_irq(&plo->lock);
				continue;
			}
			list_add_tail(&preq->list, &plo->ready_queue);
		}
		plo->st.bio_fsync++;

		if (waitqueue_active(&plo->waitq))
			wake_up_interruptible(&plo->waitq);
	}
	spin_unlock_irq(&plo->lock);
	return 0;
}

static int nfsio_open(struct ploop_io * io)
{
	struct ploop_delta * delta = container_of(io, struct ploop_delta, io);
	struct file * file = io->files.file;
	int err = 0;

	if (file == NULL)
		return -EBADF;

	err = invalidate_inode_pages2(file->f_mapping);
	if (err)
		return err;

	io->files.mapping = file->f_mapping;
	io->files.inode = io->files.mapping->host;
	io->files.bdev = NULL;

	if (!(delta->flags & PLOOP_FMT_RDONLY)) {
		io->fsync_thread = kthread_create(nfsio_fsync_thread,
						  io, "nfsio_commit%d",
						  delta->plo->index);
		if (IS_ERR(io->fsync_thread)) {
			err = PTR_ERR(io->fsync_thread);
			io->fsync_thread = NULL;
			goto out;
		}
		wake_up_process(io->fsync_thread);
	}

out:
	return err;
}

static int nfsio_prepare_snapshot(struct ploop_io * io, struct ploop_snapdata *sd)
{
	int err;
	struct file * file = io->files.file;
	struct path   path;

	path.mnt = F_MNT(file);
	path.dentry = F_DENTRY(file);

	file = dentry_open(&path, O_RDONLY|O_LARGEFILE, current_cred());
	if (IS_ERR(file))
		return PTR_ERR(file);

	/* Sanity checks */

	if (io->files.mapping != file->f_mapping ||
	    io->files.inode != file->f_mapping->host) {
		fput(file);
		return -EINVAL;
	}

	err = invalidate_inode_pages2(file->f_mapping);
	if (err) {
		fput(file);
		return err;
	}

	sd->file = file;
	return 0;
}

static int nfsio_complete_snapshot(struct ploop_io * io, struct ploop_snapdata *sd)
{
	struct file * file = io->files.file;

	mutex_lock(&io->plo->sysfs_mutex);
	io->files.file = sd->file;
	sd->file = NULL;
	(void)invalidate_inode_pages2(io->files.mapping);
	mutex_unlock(&io->plo->sysfs_mutex);

	if (io->fsync_thread) {
		kthread_stop(io->fsync_thread);
		io->fsync_thread = NULL;
	}

	fput(file);
	return 0;
}

static int nfsio_prepare_merge(struct ploop_io * io, struct ploop_snapdata *sd)
{
	int err;
	struct file * file = io->files.file;
	struct path   path;

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

	err = invalidate_inode_pages2(file->f_mapping);
	if (err) {
		fput(file);
		return err;
	}

	if (io->fsync_thread == NULL) {
		io->fsync_thread = kthread_create(nfsio_fsync_thread,
						  io, "nfsio_commit%d",
						  io->plo->index);
		if (IS_ERR(io->fsync_thread)) {
			io->fsync_thread = NULL;
			fput(file);
			return -ENOMEM;
		}
		wake_up_process(io->fsync_thread);
	}

	sd->file = file;
	return 0;
}

static int nfsio_start_merge(struct ploop_io * io, struct ploop_snapdata *sd)
{
	struct file * file = io->files.file;

	mutex_lock(&io->plo->sysfs_mutex);
	io->files.file = sd->file;
	sd->file = NULL;
	mutex_unlock(&io->plo->sysfs_mutex);

	fput(file);
	return 0;
}

static int nfsio_truncate(struct ploop_io * io, struct file * file,
			  __u32 alloc_head)
{
	int err;
	struct iattr newattrs;

	if (file->f_mapping != io->files.mapping)
		return -EINVAL;

	newattrs.ia_size = (u64)alloc_head << (io->plo->cluster_log + 9);
	newattrs.ia_valid = ATTR_SIZE;

	mutex_lock(&io->files.inode->i_mutex);
	err = notify_change(F_DENTRY(file), &newattrs, NULL);
	mutex_unlock(&io->files.inode->i_mutex);
	return err;
}

static int nfsio_autodetect(struct ploop_io * io)
{
	struct file * file = io->files.file;
	struct inode * inode = file->f_mapping->host;

	if (inode->i_sb->s_magic != NFS_SUPER_MAGIC)
		return -1; /* not mine */

	if (strcmp(file->f_mapping->host->i_sb->s_type->name, "nfs")) {
		printk("%s is not supported; use '-o vers=3' mounting nfs\n",
		       file->f_mapping->host->i_sb->s_type->name);
		return -1;
	}

	if (NFS_SERVER(file->f_mapping->host)->wsize < PAGE_SIZE ||
	    NFS_SERVER(file->f_mapping->host)->rsize < PAGE_SIZE) {
		printk("NFS server wsize/rsize too small: %d/%d\n",
		       NFS_SERVER(file->f_mapping->host)->wsize,
		       NFS_SERVER(file->f_mapping->host)->rsize);
		return -1;
	}

	return 0;
}

static struct ploop_io_ops ploop_io_ops_nfs =
{
	.id		=	PLOOP_IO_NFS,
	.name		=	"nfs",
	.owner		=	THIS_MODULE,

	.alloc		=	nfsio_alloc_sync,
	.submit		=	nfsio_submit,
	.submit_alloc	=	nfsio_submit_alloc,
	.read_page	=	nfsio_read_page,
	.write_page	=	nfsio_write_page,
	.sync_read	=	nfsio_sync_read,
	.sync_write	=	nfsio_sync_write,
	.sync_readvec	=	nfsio_sync_readvec,
	.sync_writevec	=	nfsio_sync_writevec,

	.init		=	nfsio_init,
	.destroy	=	nfsio_destroy,
	.open		=	nfsio_open,
	.sync		=	nfsio_sync,
	.stop		=	nfsio_stop,
	.prepare_snapshot =	nfsio_prepare_snapshot,
	.complete_snapshot =	nfsio_complete_snapshot,
	.io_prepare_merge  =	nfsio_prepare_merge,
	.start_merge	=	nfsio_start_merge,
	.truncate	=	nfsio_truncate,

	.i_size_read	=	generic_i_size_read,
	.f_mode		=	generic_f_mode,

	.autodetect     =       nfsio_autodetect,
};

union nfsio_bio
{
	struct {
		struct nfs_pgio_header	r;
		struct page		*padd[MAX_NBIO_PAGES];
	} ru;
	struct {
		struct nfs_pgio_header	w;
		struct page		*padd[MAX_NBIO_PAGES];
		u32			bounced;
	} wu;
	struct {
		struct nfs_commit_data c;
	} cu;
};

static struct kmem_cache *nfsio_bio_cachep;
static mempool_t *nfsio_bio_mempool;


static struct nfs_pgio_header *nfsio_rbio_alloc(unsigned int pagecount)
{
	union nfsio_bio * b = mempool_alloc(nfsio_bio_mempool, GFP_NOFS);
	struct nfs_pgio_header *p;

	if (b == NULL)
		return NULL;

	p = &b->ru.r;

	memset(b, 0, sizeof(*b));
	p->rw_mode = FMODE_READ;
	INIT_LIST_HEAD(&p->pages);
	p->page_array.npages = pagecount;
	p->page_array.pagevec = b->ru.padd;
	return p;
}

static struct nfs_pgio_header *nfsio_wbio_alloc(unsigned int pagecount)
{
	union nfsio_bio * b = mempool_alloc(nfsio_bio_mempool, GFP_NOFS);
	struct nfs_pgio_header *p;

	if (b == NULL)
		return NULL;

	p = &b->wu.w;

	memset(b, 0, sizeof(*b));
	p->rw_mode = FMODE_WRITE;
	INIT_LIST_HEAD(&p->pages);
	p->page_array.npages = pagecount;
	p->page_array.pagevec = b->wu.padd;
	return p;
}

static struct nfs_commit_data *nfsio_cbio_alloc(void)
{
	union nfsio_bio * b = mempool_alloc(nfsio_bio_mempool, GFP_NOFS);
	struct nfs_commit_data *p;

	if (b == NULL)
		return NULL;

	p = &b->cu.c;

	memset(b, 0, sizeof(*b));
	INIT_LIST_HEAD(&p->pages);
	return p;
}

void nfsio_wbio_release(void *data)
{
	struct nfs_pgio_header *p = data;
	union nfsio_bio * b = container_of(p, union nfsio_bio, wu.w);

	if (b->wu.bounced) {
		int i;

		for (i=0; i<32; i++) {
			if (b->wu.bounced & (1<<i))
				put_page(b->wu.w.page_array.pagevec[i]);
		}
	}

	mempool_free(b, nfsio_bio_mempool);
}

void nfsio_rbio_release(void *data)
{
	struct nfs_pgio_header *p = data;
	union nfsio_bio * b = container_of(p, union nfsio_bio, ru.r);
	mempool_free(b, nfsio_bio_mempool);
}

static void nfsio_put_open_context(struct nfs_open_context *ctx)
{
	if (atomic_dec_and_test(&ctx->lock_context.count))
		BUG();
}

void nfsio_cbio_release(void *data)
{
	struct nfs_commit_data *p = data;
	union nfsio_bio * b = container_of(p, union nfsio_bio, cu.c);
	nfsio_put_open_context(p->context);
	mempool_free(b, nfsio_bio_mempool);
}

int verify_bounce(struct nfs_pgio_header * nreq)
{
	int i;

	for (i = 0; i < nreq->page_array.npages; i++) {
		if (PageSlab(nreq->page_array.pagevec[i]) ||
		    page_count(nreq->page_array.pagevec[i]) == 0) {
			struct page * page;
			void *ksrc, *kdst;
			static int once;

			if (!once) {
				printk("ploop io_nfs got invalid page. XFS? Do not use this crap for Christ's sake.\n");
				once = 1;
			}

			page = alloc_page(GFP_NOFS|__GFP_HIGHMEM);
			if (!page)
				return -ENOMEM;

			ksrc = kmap_atomic(nreq->page_array.pagevec[i]);
			kdst = kmap_atomic(page);
			memcpy(kdst, ksrc, PAGE_SIZE);
			kunmap_atomic(kdst);
			kunmap_atomic(ksrc);
			nreq->page_array.pagevec[i] = page;
			((union nfsio_bio*)nreq)->wu.bounced |= (1<<i);
		}
	}
	return 0;
}


static int __init pio_nfs_mod_init(void)
{
	nfsio_bio_cachep = kmem_cache_create("nfsio_bio",
					     sizeof(union nfsio_bio),
					     0, SLAB_HWCACHE_ALIGN,
					     NULL
					     );
	if (nfsio_bio_cachep == NULL)
		return -ENOMEM;

	nfsio_bio_mempool = mempool_create_slab_pool(128,
						     nfsio_bio_cachep);
	if (nfsio_bio_mempool == NULL)
		return -ENOMEM;

	nfsio_workqueue = create_singlethread_workqueue("nfsio");
	if (nfsio_workqueue == NULL)
		return -ENOMEM;

	return ploop_register_io(&ploop_io_ops_nfs);
}

static void __exit pio_nfs_mod_exit(void)
{
	ploop_unregister_io(&ploop_io_ops_nfs);
	destroy_workqueue(nfsio_workqueue);
	mempool_destroy(nfsio_bio_mempool);
	kmem_cache_destroy(nfsio_bio_cachep);
}

module_init(pio_nfs_mod_init);
module_exit(pio_nfs_mod_exit);

MODULE_AUTHOR("Virtuozzo <devel@openvz.org>");
MODULE_DESCRIPTION("Virtuozzo backend driver for support ploop over NFS");
MODULE_LICENSE("GPL v2");
