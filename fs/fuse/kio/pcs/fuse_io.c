/*
 *  fs/fuse/kio/pcs/fuse_io.c
 *
 *  Copyright (c) 2018-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <net/sock.h>
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/pagemap.h>

#include "pcs_types.h"
#include "pcs_sock_io.h"
#include "pcs_rpc.h"
#include "pcs_sock_io.h"
#include "pcs_req.h"
#include "pcs_map.h"
#include "pcs_cs.h"
#include "pcs_cluster.h"
#include "log.h"
#include "fuse_prometheus.h"

#include "../../fuse_i.h"

static void intreq_complete(struct pcs_int_request *ireq)
{
	pcs_api_iorequest_t *req = ireq->apireq.req;

	BUG_ON(ireq->type != PCS_IREQ_API);

	if (pcs_if_error(&ireq->error)) {
		req->flags |= PCS_REQ_F_ERROR;
		if (ireq->error.value == PCS_ERR_NO_STORAGE ||
		    ireq->error.value == PCS_ERR_CSD_LACKING)
			req->flags |= PCS_REQ_F_NOSPACE;
	}
	req->complete(req);
}

static void on_read_done(struct pcs_fuse_req *r, size_t size)
{
	struct pcs_fuse_cluster *pfc = cl_from_req(r);

	DTRACE("do fuse_request_end req:%p op:%d err:%d\n", &r->req, r->req.in.h.opcode, r->req.out.h.error);

	if (r->req.out.h.error && r->req.args->page_zeroing) {
		int i;
		for (i = 0; i < r->exec.io.num_bvecs; i++) {
			BUG_ON(!r->exec.io.bvec[i].bv_page);
			clear_highpage(r->exec.io.bvec[i].bv_page);
		}
	}
	fuse_stat_account(pfc->fc, KFUSE_OP_READ, ktime_sub(ktime_get(), r->exec.ireq.ts));
	r->req.args->out_args[0].size = size;
	inode_dio_end(r->req.args->io_inode);
	fuse_request_end(pfc->fc, &r->req);
}

static void on_sync_done(struct pcs_fuse_req *r)
{
	struct pcs_fuse_cluster *pfc = cl_from_req(r);

	DTRACE("do fuse_request_end req:%p op:%d err:%d\n", &r->req, r->req.in.h.opcode, r->req.out.h.error);
	fuse_stat_account(pfc->fc, KFUSE_OP_FSYNC, ktime_sub(ktime_get(), r->exec.ireq.ts));
	fuse_request_end(pfc->fc, &r->req);
}

static void on_write_done(struct pcs_fuse_req *r, off_t pos, size_t size)
{
	struct fuse_args *args = r->req.args;
	struct fuse_io_args *ia = container_of(args, typeof(*ia), ap.args);
	struct fuse_write_out *out = &ia->write.out;
	struct pcs_fuse_cluster *pfc = cl_from_req(r);

	out->size = size;

	DTRACE("do fuse_request_end req:%p op:%d err:%d\n", &r->req, r->req.in.h.opcode, r->req.out.h.error);
	fuse_stat_account(pfc->fc, KFUSE_OP_WRITE, ktime_sub(ktime_get(), r->exec.ireq.ts));
	inode_dio_end(r->req.args->io_inode);
	fuse_request_end(pfc->fc, &r->req);
}

static void on_fallocate_done(struct pcs_fuse_req *r, off_t pos, size_t size)
{
	struct pcs_fuse_cluster *pfc = cl_from_req(r);

	DTRACE("do fuse_request_end req:%p op:%d err:%d\n", &r->req, r->req.in.h.opcode, r->req.out.h.error);
	fuse_stat_account(pfc->fc, KFUSE_OP_FALLOCATE, ktime_sub(ktime_get(), r->exec.ireq.ts));
	inode_dio_end(r->req.args->io_inode);

	fuse_request_end(pfc->fc, &r->req);
}

static void req_get_iter(void *data, unsigned int offset, struct iov_iter *it, unsigned int direction)
{
	struct pcs_fuse_req *r = data;

	iov_iter_bvec(it, direction, r->exec.io.bvec, r->exec.io.num_bvecs, r->exec.io.req.size);
	iov_iter_advance(it, offset);
}

static inline void set_io_buff(struct pcs_fuse_req *r, off_t offset, size_t size,
			       int zeroing)
{
	struct fuse_args *args = r->req.args;
	struct fuse_io_args *ia = container_of(args, typeof(*ia), ap.args);
	struct bio_vec *bvec;
	size_t count = size;
	int i;

	bvec = r->exec.io.bvec = r->exec.io.inline_bvec;
	r->exec.io.num_bvecs = ia->ap.num_pages;
	for (i = 0; i < ia->ap.num_pages; i++) {
		bvec->bv_page = ia->ap.pages[i];
		bvec->bv_offset = ia->ap.descs[i].offset;
		bvec->bv_len = ia->ap.descs[i].length;
		if (bvec->bv_len > count)
			bvec->bv_len = count;
		if (zeroing && bvec->bv_page &&
				bvec->bv_len != PAGE_SIZE)
			zero_user_segments(bvec->bv_page,
					0, bvec->bv_offset,
					bvec->bv_offset + bvec->bv_len,
					PAGE_SIZE);
		count -= bvec->bv_len;
		bvec++;
	}
	r->exec.io.req.pos = offset;
	r->exec.io.req.size = size;
}

static void prepare_io_(struct pcs_fuse_req *r, unsigned short type, off_t offset, size_t size,
		       void (*complete)(struct _pcs_api_iorequest_t *))
{
	/* Use inline request structure */
	struct pcs_int_request *ireq = &r->exec.ireq;

	TRACE("INIT r(%p) ireq:%p {%ld, %ld}\n", r, ireq, offset, size);

	/* Initialize IO request */
	switch (type)
	{
	case PCS_REQ_T_READ:
		set_io_buff(r, offset, size, r->req.args->page_zeroing);
		break;
	case PCS_REQ_T_WRITE:
		set_io_buff(r, offset, size, 0);
		break;
	case PCS_REQ_T_WRITE_ZERO:
	case PCS_REQ_T_WRITE_HOLE:
		r->exec.io.req.pos = offset;
		r->exec.io.req.size = size;
		break;
	}

	r->exec.io.req.type = type;
	r->exec.io.req.datasource = r;
	r->exec.io.req.get_iter = req_get_iter;
	r->exec.io.req.complete = complete;

	/* Initialize internal request structure */
	ireq->type = PCS_IREQ_API;
	ireq->ts = ktime_get();
	ireq->apireq.req = &r->exec.io.req;
	ireq->complete_cb = intreq_complete;
	ireq->completion_data.parent = 0;
	ireq->completion_data.ctx = r;
	ireq->completion_data.priv = r;
}

static void ioreq_complete(pcs_api_iorequest_t *ioreq)
{
	struct pcs_fuse_req *r = ioreq->datasource;

	BUG_ON(ioreq != &r->exec.io.req);

	if (ioreq->flags & PCS_REQ_F_ERROR) {
		if (ioreq->flags & PCS_REQ_F_NOSPACE)
			r->req.out.h.error = -ENOSPC;
		else
			r->req.out.h.error = -EIO;
	} else {
		r->req.out.h.error = 0;
	}

	switch (ioreq->type) {
	case PCS_REQ_T_READ:
		on_read_done(r, ioreq->size);
		break;
	case PCS_REQ_T_WRITE:
		on_write_done(r, ioreq->pos, ioreq->size);
		break;
	case PCS_REQ_T_SYNC:
		on_sync_done(r);
		break;
	case PCS_REQ_T_WRITE_HOLE:
	case PCS_REQ_T_WRITE_ZERO:
		on_fallocate_done(r, ioreq->pos, ioreq->size);
		break;
	default:
		BUG();
	}

}

void pcs_fuse_prep_io(struct pcs_fuse_req *r, unsigned short type, off_t offset, size_t size)
{
	prepare_io_(r, type, offset, size, ioreq_complete);
}

static void falloc_req_complete(struct pcs_int_request *ireq)
{
	struct pcs_fuse_req * r = ireq->completion_data.priv;
	struct pcs_fuse_cluster *pfc = cl_from_req(r);

	BUG_ON(ireq->type != PCS_IREQ_NOOP);

	DTRACE("do fuse_request_end req:%p op:%d err:%d\n", &r->req, r->req.in.h.opcode, r->req.out.h.error);
	fuse_stat_account(pfc->fc, KFUSE_OP_FALLOCATE, ktime_sub(ktime_get(), ireq->ts));
	inode_dio_end(r->req.args->io_inode);

	fuse_request_end(pfc->fc, &r->req);
}

void pcs_fuse_prep_fallocate(struct pcs_fuse_req *r)
{
	struct pcs_int_request *ireq = &r->exec.ireq;

	ireq->type = PCS_IREQ_NOOP;
	ireq->ts = ktime_get();
	ireq->complete_cb = falloc_req_complete;
	ireq->completion_data.parent = 0;
	ireq->completion_data.ctx = r;
	ireq->completion_data.priv = r;
}
