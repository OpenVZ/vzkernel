#include <net/sock.h>
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/rbtree.h>

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
				if (ireq_is_timed_out(sreq)) {
					DTRACE("timeout while IO request on \"" DENTRY_FMT "\" last_err=%u",
						DENTRY_ARGS(sreq->dentry), sreq->error.value);
				}
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

	map_submit(map, ireq, 0);
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

		rpos = map_file_to_chunk(pos, di->fileinfo.sys.chunk_size, di->fileinfo.sys.stripe_depth, di->fileinfo.sys.strip_width);

		chunk = rpos & ~((u64)di->fileinfo.sys.chunk_size - 1);
		end_pos = ((rpos / di->fileinfo.sys.strip_width) + 1) * (u64)di->fileinfo.sys.strip_width;

		sreq = ireq_alloc(di);
		if (!sreq) {
			pcs_set_local_error(&ireq->error, PCS_ERR_NOMEM);
			break;
		}

		sreq->dentry = di;
		sreq->type = PCS_IREQ_IOCHUNK;
		sreq->iochunk.map = NULL;
		sreq->iochunk.flow = pcs_flow_get(fl);
		sreq->iochunk.cmd = ireq->apireq.req->type;
		sreq->iochunk.cs_index = 0;
		sreq->iochunk.chunk = chunk;
		sreq->iochunk.offset = rpos % di->fileinfo.sys.chunk_size;
		sreq->iochunk.dio_offset = dio_offset;
		len = di->fileinfo.sys.chunk_size - sreq->iochunk.offset;
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

static void ireq_process_(struct pcs_int_request *ireq)
{
	TRACE("enter " DENTRY_FMT " type=%u\n", DENTRY_ARGS(ireq->dentry), ireq->type);

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
		goto fatal;
	}
	case PCS_ERR_CSD_LACKING:
		goto fatal;
		break;
	case PCS_ERR_INV_PARAMS:
	case PCS_ERR_NOT_FOUND:
	case PCS_ERR_NON_EMPTY_DIR:
	case PCS_ERR_NOT_DIR:
	case PCS_ERR_IS_DIR:
	case PCS_ERR_NO_STORAGE:
	case PCS_ERR_UNAVAIL:
fatal:
		printk(KERN_INFO "%s fatal error:%d nodeid:%llu", __func__,
		       ireq->error.value, ireq->dentry->inode->nodeid);
		ireq->flags |= IREQ_F_FATAL;
		break;
	case PCS_ERR_LEASE_CONFLICT:
		WARN_ON_ONCE(1);
		break;
	default:
		break;
		;
	}
}

static int ireq_check_redo_(struct pcs_int_request *ireq)
{
	pcs_error_t *err = &ireq->error;

	if (ireq->flags & IREQ_F_FATAL)
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
	pfc->cc.op.ireq_process	   = ireq_process_;
	pfc->cc.op.ireq_on_error   = ireq_on_error_;
	pfc->cc.op.ireq_check_redo = ireq_check_redo_;

	return 0;
}

void pcs_cluster_fini(struct pcs_fuse_cluster *pfc)
{
	pcs_cc_fini(&pfc->cc);
	kfree(pfc);
}
