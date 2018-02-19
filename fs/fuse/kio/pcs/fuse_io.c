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
	r->req.out.args[0].size = size;
	request_end(pfc->fc, &r->req);
}

static void on_sync_done(struct pcs_fuse_req *r)
{
	struct pcs_fuse_cluster *pfc = cl_from_req(r);

	DTRACE("do fuse_request_end req:%p op:%d err:%d\n", &r->req, r->req.in.h.opcode, r->req.out.h.error);
	request_end(pfc->fc, &r->req);
}

static void on_write_done(struct pcs_fuse_req *r, off_t pos, size_t size)
{
	struct fuse_write_out *out = &r->req.misc.write.out;
	struct pcs_fuse_cluster *pfc = cl_from_req(r);

	out->size = size;

	DTRACE("do fuse_request_end req:%p op:%d err:%d\n", &r->req, r->req.in.h.opcode, r->req.out.h.error);
	request_end(pfc->fc, &r->req);
}

static void req_get_iter(void *data, unsigned int offset, struct iov_iter *it)
{
	struct pcs_fuse_req *r = data;

	iov_iter_init_bvec(it, r->exec.io.bvec, r->exec.io.num_bvecs, r->exec.io.req.size, 0);
	iov_iter_advance(it, offset);
}

static inline void set_io_buff(struct pcs_fuse_req *r, off_t offset, size_t size,
			       int is_bvec, int zeroing)
{
	int i;
	size_t count = 0;
	if (is_bvec) {
		r->exec.io.bvec = r->req.bvec;
		r->exec.io.num_bvecs = r->req.num_bvecs;
	} else {
		r->exec.io.bvec = r->exec.io.inline_bvec;
		r->exec.io.num_bvecs = r->req.num_pages;
		for (i = 0; i < r->req.num_pages && count < size; i++) {
			r->exec.io.bvec[i].bv_page = r->req.pages[i];
			r->exec.io.bvec[i].bv_offset = r->req.page_descs[i].offset;
			r->exec.io.bvec[i].bv_len = r->req.page_descs[i].length;
			count += r->exec.io.bvec[i].bv_len;
		}
	}
	count = 0;
	for (i = 0; i < r->exec.io.num_bvecs; i++) {
		count += r->exec.io.bvec[i].bv_len;
		if (zeroing && r->exec.io.bvec[i].bv_len < PAGE_SIZE)
			clear_highpage(r->exec.io.bvec[i].bv_page);
	}
	BUG_ON(size > count);
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
		BUG_ON(r->req.out.argbvec && r->req.out.argpages);
		set_io_buff(r, offset, size, r->req.out.argbvec, r->req.out.page_zeroing);
		break;
	case PCS_REQ_T_WRITE:
		BUG_ON(r->req.in.argbvec && r->req.in.argpages);
		set_io_buff(r, offset, size, r->req.in.argbvec, 0);
		break;
	}

	r->exec.io.req.type = type;
	r->exec.io.req.datasource = r;
	r->exec.io.req.get_iter = req_get_iter;
	r->exec.io.req.complete = complete;

	/* Initialize internal request structure */
	ireq->type = PCS_IREQ_API;
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
	default:
		BUG();
	}

}

void pcs_fuse_prep_io(struct pcs_fuse_req *r, unsigned short type, off_t offset, size_t size)
{
	prepare_io_(r, type, offset, size, ioreq_complete);
}
