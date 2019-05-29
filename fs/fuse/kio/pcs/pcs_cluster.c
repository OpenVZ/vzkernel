#include <net/sock.h>
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/highmem.h>

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

void pcs_cc_process_ireq_chunk(struct pcs_int_request *ireq);
static void ireq_process_(struct pcs_int_request *ireq);

static inline int is_file_inline(struct pcs_dentry_info *di)
{
	return di->fileinfo.attr.attrib & PCS_FATTR_INLINE;
}


void pcs_sreq_complete(struct pcs_int_request *sreq)
{
	struct pcs_int_request *ireq = sreq->completion_data.parent;
	struct pcs_cluster_core *cluster = sreq->cc;

	if (pcs_if_error(&sreq->error)) {
		if (!pcs_if_error(&ireq->error)) {
			/* If we decided to abort api request, do not redo chunk request
			 * even if the error is harmless. Otherwise, analyze sreq error
			 * and, most likely, resubmit request.
			 */
			if (ireq_check_redo(sreq)) {
				ireq_retry_inc(ireq);
				if (sreq->type != PCS_IREQ_CUSTOM) {
					map_notify_soft_error(sreq);

					if (!(sreq->flags & IREQ_F_ONCE)) {
						sreq->flags |= IREQ_F_ONCE;
						pcs_clear_error(&sreq->error);
						pcs_cc_submit(sreq->cc, sreq);
						return;
					}
				}
				pcs_clear_error(&sreq->error);
				ireq_delay(sreq);
				return;
			}
			pcs_copy_error(&ireq->error, &sreq->error);
		}

		if (sreq->type != PCS_IREQ_CUSTOM)
			map_notify_iochunk_error(sreq);
	}

	if (sreq->type != PCS_IREQ_CUSTOM) {
		if (!(sreq->flags & IREQ_F_CACHED))
			ireq->flags &= ~IREQ_F_CACHED;
		pcs_deaccount_ireq(sreq, &sreq->error);
	} else if (sreq->custom.destruct)
		sreq->custom.destruct(sreq);

	if (!pcs_sreq_detach(sreq))
		ireq_complete(ireq);

	if (sreq->type == PCS_IREQ_IOCHUNK && sreq->iochunk.flow)
		pcs_flow_put(sreq->iochunk.flow, &cluster->maps.ftab);

	ireq_destroy(sreq);
}

struct fiemap_iterator
{
	struct list_head	list;
	struct pcs_int_request 	*orig_ireq;
	wait_queue_head_t	wq;
	char			*buffer;
	unsigned int		fiemap_max;
	u32			*mapped;
	int			first_iter;

	u64			pos;
	struct pcs_int_request	ireq;
	pcs_api_iorequest_t	apireq;
	struct iov_iter		it;
};

static DEFINE_SPINLOCK(fiter_lock);
static LIST_HEAD(fiter_list);

static void queue_fiter_work(struct fiemap_iterator *fiter)
{
	struct pcs_cluster_core *cc = fiter->orig_ireq->cc;
	bool was_empty;

	spin_lock(&fiter_lock);
	was_empty = list_empty(&fiter_list);
	list_add_tail(&fiter->list, &fiter_list);
	spin_unlock(&fiter_lock);

	if (was_empty)
		queue_work(cc->wq, &cc->fiemap_work);
}

static void fiemap_iter_done(struct pcs_int_request * ireq)
{
	struct fiemap_iterator * fiter = container_of(ireq, struct fiemap_iterator, ireq);

	queue_fiter_work(fiter);
}

static void fiemap_get_iter(void * datasource, unsigned int offset, struct iov_iter *it)
{
	struct fiemap_iterator * iter = datasource;

	BUG_ON(offset >= PCS_FIEMAP_BUFSIZE);
	iov_iter_init_plain(it, iter->buffer, PCS_FIEMAP_BUFSIZE, 0);
	iov_iter_advance(it, offset);
}

static void xfer_fiemap_extents(struct fiemap_iterator * iter, u64 pos, char * buffer, unsigned int count)
{
	struct pcs_cs_fiemap_rec * r = (struct pcs_cs_fiemap_rec *)buffer;

	BUG_ON(count % sizeof(struct pcs_cs_fiemap_rec));
	count /= sizeof(struct pcs_cs_fiemap_rec);

	if (r[count - 1].flags & PCS_CS_FIEMAP_FL_OVFL) {
		/* Adjust next scan pos in case of overflow, overwriting size */
		u64 end = iter->apireq.pos + r[count - 1].offset + r[count - 1].size;
		if (end < pos + iter->apireq.size) {
			u64 adjusted_size = end - pos;
			if (adjusted_size < iter->apireq.size)
				iter->apireq.size = adjusted_size;
		}
	}

	if (iter->fiemap_max == 0) {
		*iter->mapped += count;
	} else {
		int i;

		for (i = 0; i < count; i++) {
			struct fiemap_extent e;
			struct iov_iter it;
			void * buf;
			size_t len;

			if (*iter->mapped >= iter->fiemap_max)
				return;

			memset(&e, 0, sizeof(e));
			e.fe_logical = e.fe_physical = iter->apireq.pos + r[i].offset;
			e.fe_length = r[i].size;
			if (r[i].flags & PCS_CS_FIEMAP_FL_ZERO)
				e.fe_flags |= FIEMAP_EXTENT_UNWRITTEN;
			if (r[i].flags & PCS_CS_FIEMAP_FL_CACHE)
				e.fe_flags |= FIEMAP_EXTENT_DELALLOC;

			iter->orig_ireq->apireq.req->get_iter(iter->orig_ireq->apireq.req->datasource,
							      offsetof(struct fiemap, fm_extents) +
							      *iter->mapped * sizeof(struct fiemap_extent),
							      &it);
			iov_iter_truncate(&it, sizeof(e));

			iov_iter_kmap_atomic(&it, &buf, &len);
			memcpy(buf, &e, len);
			kunmap_atomic(buf);
			if (len != sizeof(e)) {
				size_t fraglen;
				iov_iter_advance(&it, len);
				iov_iter_kmap_atomic(&it, &buf, &fraglen);
				BUG_ON(len + fraglen != sizeof(e));
				memcpy(buf, (char*)&e + len, fraglen);
				kunmap_atomic(buf);
			}
			(*iter->mapped)++;
		}
	}
}

static void fiemap_process_one(struct fiemap_iterator *fiter)
{
	struct pcs_int_request *orig_ireq = fiter->orig_ireq;
	struct pcs_dentry_info *di = orig_ireq->dentry;
	struct pcs_int_request *sreq;
	u64 pos, end;

	pos = fiter->pos;
	end = orig_ireq->apireq.req->pos + orig_ireq->apireq.req->size;

	if (fiter->first_iter) {
		fiter->first_iter = 0;
	} else {
		/* Xfer previous chunk and advance pos */
		if (pcs_if_error(&fiter->ireq.error)) {
			fiter->orig_ireq->error = fiter->ireq.error;
			goto out;
		}
		if (fiter->ireq.apireq.aux)
			xfer_fiemap_extents(fiter, pos, fiter->buffer,
					    fiter->ireq.apireq.aux);
		pos += fiter->apireq.size;
		fiter->pos = pos;
	}

	if (pos >= end)
		goto out;
	if (fiter->fiemap_max && *fiter->mapped >= fiter->fiemap_max)
		goto out;

	/* Queue next chunk */
	fiter->apireq.pos = pos;
	fiter->apireq.size = end - pos;
	fiter->ireq.ts = ktime_get();

	sreq = ireq_alloc(di);
	if (!sreq) {
		pcs_set_local_error(&orig_ireq->error, PCS_ERR_NOMEM);
		goto out;
	}
	sreq->dentry = di;
	sreq->type = PCS_IREQ_IOCHUNK;
	INIT_LIST_HEAD(&sreq->tok_list);
	sreq->tok_reserved = 0;
	sreq->tok_serno = 0;
	sreq->iochunk.map = NULL;
	sreq->iochunk.flow = pcs_flow_record(&di->mapping.ftab, 0, pos, end-pos, &di->cluster->maps.ftab);
	sreq->iochunk.cmd = PCS_REQ_T_FIEMAP;
	sreq->iochunk.cs_index = 0;
	sreq->iochunk.chunk = round_down(pos, DENTRY_CHUNK_SIZE(di));
	sreq->iochunk.offset = pos - sreq->iochunk.chunk;
	sreq->iochunk.dio_offset = 0;
	sreq->iochunk.size = end - pos;
	if (sreq->iochunk.offset + sreq->iochunk.size > DENTRY_CHUNK_SIZE(di))
		fiter->apireq.size = sreq->iochunk.size = DENTRY_CHUNK_SIZE(di) - sreq->iochunk.offset;
	sreq->iochunk.csl = NULL;
	sreq->iochunk.banned_cs.val = 0;
	sreq->iochunk.msg.destructor = NULL;
	sreq->iochunk.msg.rpc = NULL;

	pcs_sreq_attach(sreq, &fiter->ireq);
	sreq->complete_cb = pcs_sreq_complete;
	pcs_cc_process_ireq_chunk(sreq);
	return;
out:
	kvfree(fiter->buffer);
	kfree(fiter);
	ireq_complete(orig_ireq);
}

void fiemap_work_func(struct work_struct *w)
{
	struct fiemap_iterator *fiter;

	spin_lock(&fiter_lock);
	while (!list_empty(&fiter_list)) {
		fiter = list_first_entry(&fiter_list,
					 struct fiemap_iterator, list);
		list_del_init(&fiter->list);
		spin_unlock(&fiter_lock);

		fiemap_process_one(fiter);

		spin_lock(&fiter_lock);
	}
	spin_unlock(&fiter_lock);
}

static void process_ireq_fiemap(struct pcs_int_request *orig_ireq)
{
	struct pcs_dentry_info * di;
	struct fiemap_iterator * fiter;
	struct iov_iter *it;

	fiter = kmalloc(sizeof(struct fiemap_iterator), GFP_KERNEL);
	if (fiter == NULL) {
		pcs_set_local_error(&orig_ireq->error, PCS_ERR_NOMEM);
		ireq_complete(orig_ireq);
		return;
	}
	it = &fiter->it;

	fiter->orig_ireq = orig_ireq;
	init_waitqueue_head(&fiter->wq);
	di = orig_ireq->dentry;
	ireq_init(di, &fiter->ireq);
	fiter->ireq.type = PCS_IREQ_API;
	fiter->ireq.apireq.req = &fiter->apireq;
	fiter->ireq.completion_data.parent = NULL;
	fiter->ireq.complete_cb = fiemap_iter_done;
	fiter->apireq.datasource = fiter;
	fiter->apireq.get_iter = fiemap_get_iter;
	fiter->apireq.complete = NULL;
	fiter->buffer = kvmalloc(PCS_FIEMAP_BUFSIZE, GFP_KERNEL);
	if (fiter->buffer == NULL) {
		pcs_set_local_error(&orig_ireq->error, PCS_ERR_NOMEM);
		ireq_complete(orig_ireq);
		kfree(fiter);
		return;
	}
	atomic_set(&fiter->ireq.iocount, 0);
	fiter->fiemap_max = orig_ireq->apireq.aux;
	orig_ireq->apireq.req->get_iter(orig_ireq->apireq.req->datasource, 0, it);
	fiter->mapped = &((struct fiemap*)it->data)->fm_mapped_extents;

	fiter->first_iter = 1;
	fiter->pos = orig_ireq->apireq.req->pos;

	queue_fiter_work(fiter);
}

void pcs_cc_process_ireq_chunk(struct pcs_int_request *ireq)
{
	struct pcs_map_entry *map;

	TRACE(PCS_FILE_ID_FMT" [%llx]\n", ireq->dentry->fileinfo.attr.id,
	      (unsigned long long)ireq->iochunk.chunk);

	map = pcs_find_get_map(ireq->dentry, ireq->iochunk.chunk +
			   ((ireq->flags & IREQ_F_MAPPED) ? 0 : ireq->iochunk.offset));

	if (map_check_limit(map, ireq))
		return;
	if (ireq->iochunk.map)
		pcs_map_put(ireq->iochunk.map);
	ireq->iochunk.map = map;

	map_submit(map, ireq);
}

/* TODO Remove noinline in production */
static noinline void __pcs_cc_process_ireq_rw(struct pcs_int_request *ireq)
{
	struct pcs_dentry_info *di = ireq->dentry;
	u64 pos = ireq->apireq.req->pos;
	unsigned int sz = ireq->apireq.req->size;
	unsigned int dio_offset = 0;
	struct pcs_flow_node *fl;

	if (di->fileinfo.sys.map_type != PCS_MAP_PLAIN) {
		BUG_ON(1);
		return;
	}

	TRACE(DENTRY_FMT " %p op=%d at %llu [%llu]\n", DENTRY_ARGS(di), ireq, ireq->apireq.req->type,
	      (unsigned long long)ireq->apireq.req->pos, (unsigned long long)ireq->apireq.req->size);


	atomic_set(&ireq->iocount, 1);
	ireq->flags |= IREQ_F_CACHED;

	fl =  pcs_flow_record(&di->mapping.ftab, ireq->apireq.req->type == PCS_REQ_T_WRITE,
			      pos, sz, &di->cluster->maps.ftab);

	while (sz) {
		struct pcs_int_request *sreq;
		unsigned int len;
		u64 rpos, chunk, end_pos;

		rpos = map_file_to_chunk(pos, di->fileinfo.sys.chunk_size_lo, di->fileinfo.sys.stripe_depth, di->fileinfo.sys.strip_width);

		chunk = rpos & ~((u64)di->fileinfo.sys.chunk_size_lo - 1);
		end_pos = ((rpos / di->fileinfo.sys.strip_width) + 1) * (u64)di->fileinfo.sys.strip_width;

		sreq = ireq_alloc(di);
		if (!sreq) {
			pcs_set_local_error(&ireq->error, PCS_ERR_NOMEM);
			break;
		}

		sreq->dentry = di;
		sreq->type = PCS_IREQ_IOCHUNK;
		INIT_LIST_HEAD(&sreq->tok_list);
		sreq->tok_reserved = 0;
		sreq->tok_serno = 0;
		sreq->iochunk.map = NULL;
		sreq->iochunk.flow = pcs_flow_get(fl);
		sreq->iochunk.cmd = ireq->apireq.req->type;
		sreq->iochunk.cs_index = 0;
		sreq->iochunk.chunk = chunk;
		sreq->iochunk.offset = rpos % di->fileinfo.sys.chunk_size_lo;
		sreq->iochunk.dio_offset = dio_offset;
		len = di->fileinfo.sys.chunk_size_lo - sreq->iochunk.offset;
		if (len > sz)
			len = sz;
		if (rpos + len > end_pos)
			len = end_pos - rpos;
		sreq->iochunk.size = len;
		sreq->iochunk.csl = NULL;
		sreq->iochunk.banned_cs.val = 0;
		sreq->iochunk.msg.destructor = NULL;
		sreq->iochunk.msg.rpc = NULL;

		pcs_sreq_attach(sreq, ireq);
		sreq->complete_cb = pcs_sreq_complete;
		pcs_cc_process_ireq_chunk(sreq);

		pos += len;
		sz -= len;
		dio_offset += len;
	}
	pcs_flow_put(fl, &di->cluster->maps.ftab);
	if (atomic_dec_and_test(&ireq->iocount))
		ireq_complete(ireq);
}

static void pcs_cc_process_ireq_ioreq(struct pcs_int_request *ireq)
{
	if (ireq->apireq.req->type == PCS_REQ_T_SYNC) {
		map_inject_flush_req(ireq);
		return;
	}

	if (ireq->apireq.req->type == PCS_REQ_T_FIEMAP) {
		process_ireq_fiemap(ireq);
		return;
	}

	if (ireq->apireq.req->type != PCS_REQ_T_READ &&
	    ireq->apireq.req->type != PCS_REQ_T_WRITE &&
	    ireq->apireq.req->type != PCS_REQ_T_WRITE_HOLE &&
	    ireq->apireq.req->type != PCS_REQ_T_WRITE_ZERO) {
		pcs_set_local_error(&ireq->error, PCS_ERR_PROTOCOL);
		ireq_complete(ireq);
		return;
	}
	return __pcs_cc_process_ireq_rw(ireq);
}

static void process_ireq_token(struct pcs_int_request * ireq)
{
	struct pcs_int_request * parent = ireq->token.parent;

        if (parent) {
		int do_execute = 0;

		spin_lock(&parent->completion_data.child_lock);
		if (ireq->token.parent) {
			ireq_drop_tokens(parent);
			do_execute = 1;
		}
		spin_unlock(&parent->completion_data.child_lock);
		if (do_execute)
			ireq_process_(parent);
        }
        ireq_destroy(ireq);
}

static void ireq_process_(struct pcs_int_request *ireq)
{
	struct fuse_conn * fc = container_of(ireq->cc, struct pcs_fuse_cluster, cc)->fc;


	TRACE("enter " DENTRY_FMT " type=%u\n", DENTRY_ARGS(ireq->dentry), ireq->type);

	/* If fuse connection is dead we shoud fail all requests in flight */
	if (unlikely(!fc->initialized || fc->conn_error)) {
		ireq->flags |= IREQ_F_FATAL;
		pcs_set_local_error(&ireq->error, PCS_ERR_UNAVAIL);
		ireq_complete(ireq);
		return;
	}

	switch (ireq->type) {
	case PCS_IREQ_NOOP:
		ireq_complete(ireq);
		break;
	case PCS_IREQ_IOCHUNK:
		pcs_cc_process_ireq_chunk(ireq);
		break;
	case PCS_IREQ_API:
		pcs_cc_process_ireq_ioreq(ireq);
		break;
	case PCS_IREQ_FLUSH:
		process_flush_req(ireq);
		break;
	case PCS_IREQ_TRUNCATE:
		process_ireq_truncate(ireq);
		break;
	case PCS_IREQ_CUSTOM:
		ireq->custom.action(ireq);
		break;
	case PCS_IREQ_TOKEN:
		process_ireq_token(ireq);
		break;
	default:
		BUG();
		break;
	}
}

static void ireq_notify_err(struct pcs_int_request *ireq, pcs_error_t *err)
{
	if (ireq->completion_data.parent)
		ireq_notify_err(ireq->completion_data.parent, err);

	else if (ireq->completion_data.priv) {
		struct pcs_fuse_req *r = ireq->completion_data.priv;
		r->exec.ctl.last_err = *err;
	}
}

static void ireq_on_error_(struct pcs_int_request *ireq)
{
	/* Distinguish unrecoverable errors and recoverable ones.
	 * Recoverable errors must trigger restart.
	 */
	ireq_notify_err(ireq, &ireq->error);
	switch (ireq->error.value) {
		/* This can happen if we lost connection for long time and lease has been lost.
		 * We should try to reacquire lock. Server must reject reacquisition, if someone
		 * took the lock after us.
		 */
	case PCS_ERR_LEASE_REQUIRED:
	case PCS_ERR_LEASE_EXPIRED:
	case PCS_ERR_INTEGRITY_FAIL: {
		/* TODO:  tag ireq->dentry with EIO here */
	}
	case PCS_ERR_CSD_LACKING:
		/* To be completely equivalent to user space we should add option fail_on_nospace here */
		break;
	case PCS_ERR_INV_PARAMS:
	case PCS_ERR_NOT_FOUND:
	case PCS_ERR_NON_EMPTY_DIR:
	case PCS_ERR_NOT_DIR:
	case PCS_ERR_IS_DIR:
	case PCS_ERR_NO_STORAGE:
	case PCS_ERR_UNAVAIL:
		TRACE("fatal error:%d ireq->type:%d nodeid:%llu\n",
		      ireq->error.value, ireq->type,
		      ireq->dentry->inode->nodeid);
		ireq->flags |= IREQ_F_FATAL;
		break;
	case PCS_ERR_LEASE_CONFLICT:
		WARN_ON_ONCE(1);
		break;
	default:
		break;
	}
}

static int ireq_check_redo_(struct pcs_int_request *ireq)
{
	struct fuse_conn *fc = container_of(ireq->cc, struct pcs_fuse_cluster, cc)->fc;
	pcs_error_t *err = &ireq->error;

	if (ireq->flags & IREQ_F_FATAL)
		return 0;
	if (!fc->connected || fc->conn_error)
		return 0;

	if (ireq->completion_data.parent &&
	    pcs_if_error(&ireq->completion_data.parent->error) &&
	    !ireq_check_redo(ireq->completion_data.parent))
		return 0;

	/* Fatal errors */
	switch (err->value) {
	case PCS_ERR_PROTOCOL:
	case PCS_ERR_INV_PARAMS:
	case PCS_ERR_NOT_FOUND:
	case PCS_ERR_IS_DIR:
	case PCS_ERR_NOT_DIR:
		return 0;
	}

	/* Remote errors are never fatal */
	if (err->remote)
		return 1;

	/* Fatal errors */
	switch (err->value) {
	case PCS_ERR_NOMEM:
	case PCS_ERR_LEASE_REQUIRED:
	case PCS_ERR_LEASE_EXPIRED:
	case PCS_ERR_INTEGRITY_FAIL:
	case PCS_ERR_NO_STORAGE:
		return 0;
	}

	return 1;
}

int pcs_cluster_init(struct pcs_fuse_cluster *pfc, struct workqueue_struct *wq,
		     struct fuse_conn *fc, PCS_CLUSTER_ID_T *cl_id,
		     PCS_NODE_ID_T *id)
{
	struct pcs_cluster_core_attr attr;

	attr.cluster = *cl_id;
	attr.node = *id;
	attr.abort_timeout_ms = 0;

	pfc->fc = fc;

	/* core init */
	if (pcs_cc_init(&pfc->cc, wq, NULL, &attr))
		return -1;
	pfc->cc.fc = fc;
	pfc->cc.op.ireq_process	   = ireq_process_;
	pfc->cc.op.ireq_on_error   = ireq_on_error_;
	pfc->cc.op.ireq_check_redo = ireq_check_redo_;

	return 0;
}

void pcs_cluster_fini(struct pcs_fuse_cluster *pfc)
{
	pcs_cc_fini(&pfc->cc);
	kvfree(pfc);
}
