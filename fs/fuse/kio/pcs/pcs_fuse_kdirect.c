/*
 * Implement kdirect API for PCS cluster client kernel implementation
 */
#include "../../fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/compat.h>
#include <linux/swap.h>
#include <linux/aio.h>
#include <linux/falloc.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/virtinfo.h>
#include <linux/file.h>
#include <linux/workqueue.h>
#include <linux/delay.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/debugfs.h>

#include "pcs_ioctl.h"
#include "pcs_cluster.h"
#include "pcs_rpc.h"
#include "fuse_ktrace.h"
#include "fuse_prometheus.h"

unsigned int pcs_loglevel = LOG_TRACE;
module_param(pcs_loglevel, uint, 0644);
MODULE_PARM_DESC(pcs_loglevel, "Trace level");

#ifdef CONFIG_DEBUG_KERNEL
static int set_sockio_fail_percent(const char *val, struct kernel_param *kp)
{
	unsigned *p;
	int rv;

	rv = param_set_uint(val, kp);
	if (rv)
		return rv;

	p = (unsigned *)kp->arg;
	if (*p > 100)
		*p = 100;

	return 0;
}

u32 sockio_fail_percent;
module_param_call(sockio_fail_percent, set_sockio_fail_percent,
		  param_get_uint, &sockio_fail_percent, 0644);
__MODULE_PARM_TYPE(sockio_fail_percent, "uint");
MODULE_PARM_DESC(sockio_fail_percent, "Sock io failing rate in percents");
#endif

static int fuse_ktrace_setup(struct fuse_conn * fc);
static int fuse_ktrace_remove(struct fuse_conn *fc);

static struct kmem_cache *pcs_fuse_req_cachep;
static struct kmem_cache *pcs_ireq_cachep;
static struct workqueue_struct *pcs_wq;
static struct fuse_kio_ops kio_pcs_ops;
static struct dentry *fuse_trace_root;

static void process_pcs_init_reply(struct fuse_conn *fc, struct fuse_req *req)
{
	struct pcs_fuse_cluster *pfc;
	struct fuse_ioctl_out *arg = &req->misc.ioctl.out;
	struct	pcs_ioc_init_kdirect *info = req->out.args[1].value;

	if ((req->out.h.error == -EPROTONOSUPPORT && !arg->result) ||
	    info->version.major != PCS_FAST_PATH_VERSION.major ||
	    info->version.minor != PCS_FAST_PATH_VERSION.minor) {
		pr_err("kio_pcs: version mismatch: must be %u.%u. "
		       "Fallback to plain fuse\n",
		       PCS_FAST_PATH_VERSION.major,
		       PCS_FAST_PATH_VERSION.minor);
		fc->flags &= ~FUSE_KDIRECT_IO;
		goto out;
	} else if (req->out.h.error || arg->result) {
		printk("Fail to initialize has_kdirect {%d,%d}\n",
		       req->out.h.error, arg->result);
		fc->conn_error = 1;
		goto out;
	}

	pfc = kvmalloc(sizeof(*pfc), GFP_KERNEL);
	if (!pfc) {
		fc->conn_error = 1;
		goto out;
	}

	if (pcs_cluster_init(pfc, pcs_wq, fc, &info->cluster_id, &info->node_id)) {
		fc->conn_error = 1;
		kvfree(pfc);
		goto out;
	}

	fuse_ktrace_setup(fc);
	fc->ktrace_level = LOG_TRACE;

	printk("FUSE: kio_pcs: cl: " CLUSTER_ID_FMT ", clientid: " NODE_FMT "\n",
	       CLUSTER_ID_ARGS(info->cluster_id), NODE_ARGS(info->node_id));

	spin_lock(&fc->lock);
	if (fc->initialized) {
		/* Parallel abort */
		fc->conn_error = 1;
	} else {
		/*
		 * It looks like all potential tasks, which can dereference
		 * fc->kio.op, are waiting for fuse_set_initialized().
		 */
		fc->kio.op = fc->kio.cached_op;
		fc->kio.ctx = pfc;
		pfc = NULL;
	}
	spin_unlock(&fc->lock);

	if (pfc) {
		fuse_ktrace_remove(fc);
		pcs_cluster_fini(pfc);
		kvfree(pfc);
	}
out:
	if (fc->conn_error)
		pr_err("Failed to initialize fuse kio\n");
	kfree(info);
	/*  We are called from	process_init_reply before connection
	 * was not initalized yet. Do it now. */
	fuse_set_initialized(fc);
	wake_up_all(&fc->blocked_waitq);

}

int kpcs_conn_init(struct fuse_conn *fc)
{
	struct fuse_req *req;
	struct fuse_ioctl_in *inarg;
	struct fuse_ioctl_out *outarg;
	struct pcs_ioc_init_kdirect *info;

	BUG_ON(!fc->conn_init);

	info = kzalloc(sizeof(*info), GFP_NOIO);
	if (!info)
		return -ENOMEM;

	req = fuse_request_alloc(fc, 0);
	if (IS_ERR(req)) {
		kfree(info);
		return PTR_ERR(req);
	}

	__set_bit(FR_BACKGROUND, &req->flags);
	memset(&req->misc.ioctl, 0, sizeof(req->misc.ioctl));
	/* filehandle and nodeid are null, but this is OK */
	inarg = &req->misc.ioctl.in;
	outarg = &req->misc.ioctl.out;
	inarg->cmd = PCS_IOC_INIT_KDIRECT;
	info->version = PCS_FAST_PATH_VERSION;

	req->in.h.opcode = FUSE_IOCTL;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(*inarg);
	req->in.args[0].value = inarg;
	req->in.args[1].size = sizeof(*info);
	req->in.args[1].value = info;
	req->out.numargs = 2;
	req->out.args[0].size = sizeof(*outarg);
	req->out.args[0].value = outarg;
	req->out.args[1].size = sizeof(*info);
	req->out.args[1].value = info;
	req->misc.ioctl.ctx = info;
	req->end = process_pcs_init_reply;

	fuse_request_send_background(fc, req);
	return 0;
}

void kpcs_conn_fini(struct fuse_conn *fc)
{
	if (fc->ktrace)
		fuse_ktrace_remove(fc);

	if (!fc->kio.ctx)
		return;

	TRACE("%s fc:%p\n", __FUNCTION__, fc);
	flush_workqueue(pcs_wq);
	pcs_cluster_fini((struct pcs_fuse_cluster *) fc->kio.ctx);
}

void kpcs_conn_abort(struct fuse_conn *fc)
{
	/* XXX: Implement abort pending kio */
}

static int kpcs_probe(struct fuse_conn *fc, char *name)
{
	return 1;
}

static int fuse_pcs_getfileinfo(struct fuse_conn *fc, struct file *file,
				struct pcs_mds_fileinfo *info)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req;
	struct fuse_ioctl_in *inarg;
	struct fuse_ioctl_out *outarg;
	struct pcs_ioc_fileinfo ioc_info;
	int err = 0;

	req = fuse_get_req(fc, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&req->misc.ioctl, 0, sizeof(req->misc.ioctl));
	inarg = &req->misc.ioctl.in;
	outarg = &req->misc.ioctl.out;

	req->in.h.opcode = FUSE_IOCTL;
	req->in.h.nodeid = ff->nodeid;

	inarg->cmd = PCS_IOC_GETFILEINFO;
	inarg->fh = ff->fh;
	inarg->arg = 0;
	inarg->flags = 0;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(*inarg);
	req->in.args[0].value = inarg;

	memset(&ioc_info, 0, sizeof(ioc_info));

	req->out.numargs = 2;
	req->out.args[0].size = sizeof(*outarg);
	req->out.args[0].value = outarg;
	req->out.args[1].size = sizeof(ioc_info);
	req->out.args[1].value = &ioc_info;

	fuse_request_send(fc, req);

	if (req->out.h.error || outarg->result) {
		TRACE("h.err:%d result:%d\n",
		      req->out.h.error, outarg->result);
		err = req->out.h.error ? req->out.h.error : outarg->result;
		fuse_put_request(fc, req);
		return err;
	} else
		*info = ioc_info.fileinfo;

	fuse_put_request(fc, req);
	return 0;
}

static int fuse_pcs_kdirect_claim_op(struct fuse_conn *fc, struct file *file,
				     bool claim)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req;
	struct fuse_ioctl_in *inarg;
	struct fuse_ioctl_out *outarg;
	int err = 0;

	req = fuse_get_req(fc, 0);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&req->misc.ioctl, 0, sizeof(req->misc.ioctl));
	inarg = &req->misc.ioctl.in;
	outarg = &req->misc.ioctl.out;

	req->in.h.opcode = FUSE_IOCTL;
	req->in.h.nodeid = ff->nodeid;

	if (claim)
		inarg->cmd = PCS_IOC_KDIRECT_CLAIM;
	else
		inarg->cmd = PCS_IOC_KDIRECT_RELEASE;

	inarg->fh = ff->fh;
	inarg->arg = 0;
	inarg->flags = 0;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(*inarg);
	req->in.args[0].value = inarg;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(*outarg);
	req->out.args[0].value = outarg;
	fuse_request_send(fc, req);
	if (req->out.h.error || outarg->result) {
		TRACE("h.err:%d result:%d\n",
		       req->out.h.error, outarg->result);
		err = req->out.h.error ? req->out.h.error : outarg->result;
	}

	fuse_put_request(fc, req);
	return err;
}
static void  fuse_size_grow_work(struct work_struct *w);

static int kpcs_do_file_open(struct fuse_conn *fc, struct file *file, struct inode *inode)
{
	struct pcs_mds_fileinfo info;
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct pcs_fuse_cluster *pfc = (struct pcs_fuse_cluster*)fc->kio.ctx;
	struct pcs_dentry_info *di = NULL;
	int ret;

	ret = fuse_pcs_getfileinfo(fc, file, &info);
	if (ret)
		return ret == -EOPNOTSUPP ? 0 : ret;

	if (info.sys.map_type != PCS_MAP_PLAIN) {
		TRACE("Unsupported map_type:%x, ignore\n", info.sys.map_type);
		return 0;
	}

	di = kzalloc(sizeof(*di), GFP_KERNEL);
	if (!di)
		return -ENOMEM;

	/* TODO Init fields */
	/* di.id.parent	    = id->parent; */
	/* di.id.name.data  = name; */
	/* di.id.name.len   = id->name.len; */

	spin_lock_init(&di->lock);
	INIT_LIST_HEAD(&di->size.queue);
	di->size.required = 0;
	di->size.op = PCS_SIZE_INACTION;
	INIT_WORK(&di->size.work, fuse_size_grow_work);

	pcs_mapping_init(&pfc->cc, &di->mapping);
	pcs_set_fileinfo(di, &info);
	di->cluster = &pfc->cc;
	di->inode = fi;
	TRACE("init id:%llu chunk_size:%d stripe_depth:%d strip_width:%d\n",
	      fi->nodeid, di->fileinfo.sys.chunk_size,
	      di->fileinfo.sys.stripe_depth, di->fileinfo.sys.strip_width);

	ret = fuse_pcs_kdirect_claim_op(fc, file, true);
	if (ret) {
		pcs_mapping_invalidate(&di->mapping);
		pcs_mapping_deinit(&di->mapping);
		kfree(di);
		/* Claim error means we cannot claim, just that */
		return 0;
	}
	/* TODO: Propper initialization of dentry should be here!!! */
	fi->private = di;
	return 0;
}

int kpcs_file_open(struct fuse_conn *fc, struct file *file, struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct pcs_dentry_info *di = fi->private;
	struct pcs_mds_fileinfo info;
	int ret;

	if (!S_ISREG(inode->i_mode))
		return 0;
	if (fi->nodeid - FUSE_ROOT_ID >= PCS_FUSE_INO_SPECIAL_)
		return 0;

	lockdep_assert_held(&inode->i_mutex);
	/* Already initialized. Update file size etc */
	if (di) {
		/*TODO: propper refcount for claim_cnt should be here */
		ret = fuse_pcs_getfileinfo(fc, file, &info);
		if (ret)
			return ret;
		spin_lock(&di->lock);
		pcs_set_fileinfo(di, &info);
		spin_unlock(&di->lock);
		return 0;
	}
	return kpcs_do_file_open(fc, file, inode);
}

void kpcs_inode_release(struct fuse_inode *fi)
{
	struct pcs_dentry_info *di = fi->private;

	if(!di)
		return;

	BUG_ON(!list_empty(&di->size.queue));
	pcs_mapping_invalidate(&di->mapping);
	pcs_mapping_deinit(&di->mapping);
	/* TODO: properly destroy dentry info here!! */
	kfree(di);
}

static void pcs_fuse_reply_handle(struct fuse_conn *fc, struct fuse_req *req)
{
	struct pcs_fuse_work *work = (struct pcs_fuse_work*) req->misc.ioctl.ctx;
	int err;

	err = req->out.h.error ? req->out.h.error : req->misc.ioctl.out.result;
	if (err) {
		/* TODO	 Fine grane error conversion here */
		pcs_set_local_error(&work->status, PCS_ERR_PROTOCOL);
	}
	queue_work(pcs_wq, &work->work);
}

#define MAX_CS_CNT 32
static void fuse_complete_map_work(struct work_struct *w)
{
	struct pcs_fuse_work *work = container_of(w, struct pcs_fuse_work, work);
	struct pcs_map_entry *m = (struct pcs_map_entry *)work->ctx;
	struct pcs_ioc_getmap *omap = (struct pcs_ioc_getmap *)work->ctx2;

	BUG_ON(!m);
	BUG_ON(!omap);
	pcs_copy_error_cond(&omap->error, &work->status);
	if (omap->cs_cnt > MAX_CS_CNT) {
		printk("Corrupted cs_cnt from userspace");
		pcs_set_local_error(&omap->error, PCS_ERR_PROTOCOL);
	}

	pcs_map_complete(m, omap);
	kfree(omap);
	kfree(work);
}

int fuse_map_resolve(struct pcs_map_entry *m, int direction)
{
	struct pcs_dentry_info *di = pcs_dentry_from_mapping(m->mapping);
	struct fuse_conn *fc = pcs_cluster_from_cc(di->cluster)->fc;
	struct fuse_req *req;
	struct fuse_ioctl_in *inarg;
	struct fuse_ioctl_out *outarg;
	struct pcs_ioc_getmap *map_ioc;
	struct pcs_fuse_work *reply_work;
	size_t map_sz;

	DTRACE("enter m: " MAP_FMT ", dir:%d \n", MAP_ARGS(m),	direction);

	BUG_ON(!(m->state & PCS_MAP_RESOLVING));

	map_sz = sizeof(*map_ioc) + MAX_CS_CNT * sizeof(struct pcs_cs_info);
	map_ioc = kzalloc(map_sz, GFP_NOIO);
	if (!map_ioc)
		return -ENOMEM;

	reply_work = kzalloc(sizeof(*reply_work), GFP_NOIO);
	if (!reply_work) {
		kfree(map_ioc);
		return -ENOMEM;
	}
	req = fuse_get_nonblock_req_for_background(fc, 0);
	if (IS_ERR(req)) {
		kfree(map_ioc);
		kfree(reply_work);
		return PTR_ERR(req);
	}

	memset(&req->misc.ioctl, 0, sizeof(req->misc.ioctl));
	inarg = &req->misc.ioctl.in;
	outarg = &req->misc.ioctl.out;
	inarg->cmd = PCS_IOC_GETMAP;
	map_ioc->cs_max = MAX_CS_CNT;

	/* fill ioc_map struct */
	if (pcs_map_encode_req(m, map_ioc, direction) != 0) {
		kfree(map_ioc);
		kfree(reply_work);
		fuse_put_request(fc, req);
		return 0;
	}

	/* Fill core ioctl */
	req->in.h.opcode = FUSE_IOCTL;
	/* FH is null, peer will lookup by nodeid */
	inarg->fh = 0;
	req->in.h.nodeid = di->inode->nodeid;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(*inarg);
	req->in.args[0].value = inarg;
	req->in.args[1].size = map_sz;
	req->in.args[1].value = map_ioc;

	req->out.numargs = 2;
	/* TODO: make this ioctl varsizable */
	req->out.argvar = 1;
	req->out.args[0].size = sizeof(*outarg);
	req->out.args[0].value = outarg;
	req->out.args[1].size = map_sz;
	req->out.args[1].value = map_ioc;

	INIT_WORK(&reply_work->work, fuse_complete_map_work);
	reply_work->ctx = m;
	reply_work->ctx2 = map_ioc;
	req->misc.ioctl.ctx = reply_work;
	req->end = pcs_fuse_reply_handle;

	fuse_request_send_background(fc, req);

	return 0;
}
static void pfocess_pcs_csconn_work(struct work_struct *w)
{
	struct pcs_fuse_work *work = container_of(w, struct pcs_fuse_work, work);
	struct pcs_rpc *ep  = (struct pcs_rpc *)work->ctx;
	struct socket *sock = (struct socket *)work->ctx2;
	BUG_ON(!ep);

	if (pcs_if_error(&work->status)) {
		mutex_lock(&ep->mutex);
		pcs_rpc_reset(ep);
		mutex_unlock(&ep->mutex);
		TRACE(PEER_FMT" fail with %d\n", PEER_ARGS(ep), work->status.value);
	} else	{
		if (sock)
			rpc_connect_done(ep, sock);
	}
	pcs_rpc_put(ep);
	kfree(work);
}

static void process_pcs_csconn_reply(struct fuse_conn *fc, struct fuse_req *req)
{
	struct pcs_ioc_csconn *csconn = (struct pcs_ioc_csconn *)req->in.args[1].value;
	struct fuse_ioctl_out *arg = &req->misc.ioctl.out;
	struct pcs_fuse_work *work = (struct pcs_fuse_work*) req->misc.ioctl.ctx;
	int is_open = csconn->flags & PCS_IOC_CS_OPEN;

	if (req->out.h.error || arg->result < 0) {
		pcs_set_local_error(&work->status, PCS_ERR_PROTOCOL);
		goto out;
	}
	/* Grab socket from caller's context (fuse-evloop) and do the rest in kwork */
	if (is_open) {
		struct socket *sock;
		struct file* filp;
		int err;

		filp = fget((unsigned int)arg->result);
		arg->result = 0;
		if (!filp) {
			pcs_set_local_error(&work->status, PCS_ERR_PROTOCOL);
			goto out;
		}
		sock = sock_from_file(filp, &err);
		if (!sock) {
			fput(filp);
			pcs_set_local_error(&work->status, PCS_ERR_PROTOCOL);
		} else
			TRACE("id: "NODE_FMT" sock:%p\n", NODE_ARGS(csconn->id), sock);
		work->ctx2 = sock;
	}
out:
	kfree(csconn);
	pcs_fuse_reply_handle(fc, req);

}

int fuse_pcs_csconn_send(struct fuse_conn *fc, struct pcs_rpc *ep, int flags)
{
	struct fuse_req *req;
	struct fuse_ioctl_in *inarg;
	struct fuse_ioctl_out *outarg;
	struct pcs_ioc_csconn *csconn;
	struct pcs_fuse_work *reply_work;

	/* Socket must being freed from kernelspace before requesting new one*/
	BUG_ON(!(flags & PCS_IOC_CS_REOPEN));

	TRACE("start %s cmd:%ld id:%lld flags:%x\n", __FUNCTION__,
	      PCS_IOC_CSCONN, ep->peer_id.val, flags);

	csconn = kzalloc(sizeof(*csconn), GFP_NOIO);
	if (!csconn)
		return -ENOMEM;

	reply_work = kzalloc(sizeof(*reply_work), GFP_NOIO);
	if (!reply_work) {
		kfree(csconn);
		return -ENOMEM;
	}

	req = fuse_get_nonblock_req_for_background(fc, 0);
	if (IS_ERR(req)) {
		kfree(csconn);
		kfree(reply_work);
		return PTR_ERR(req);
	}

	memset(&req->misc.ioctl, 0, sizeof(req->misc.ioctl));
	inarg = &req->misc.ioctl.in;
	outarg = &req->misc.ioctl.out;

	inarg->cmd = PCS_IOC_CSCONN;
	inarg->fh = 0;
	inarg->arg = 0;
	inarg->flags = 0;

	csconn->id.val = ep->peer_id.val;
	memcpy(&csconn->address, &ep->addr, sizeof(ep->addr));
	csconn->flags = flags;

	if (ep->flags & PCS_RPC_F_LOCAL)
		csconn->address.type = PCS_ADDRTYPE_UNIX;

	req->in.h.opcode = FUSE_IOCTL;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(*inarg);
	req->in.args[0].value = inarg;
	req->in.args[1].size = sizeof(*csconn);
	req->in.args[1].value = csconn;

	req->out.numargs = 1;
	req->out.args[0].size = sizeof(*outarg);
	req->out.args[0].value = outarg;

	INIT_WORK(&reply_work->work, pfocess_pcs_csconn_work);
	reply_work->ctx = pcs_rpc_get(ep);
	reply_work->ctx2 = NULL; /* return socket should be here */
	req->misc.ioctl.ctx = reply_work;

	req->end = process_pcs_csconn_reply;
	fuse_request_send_background(fc, req);

	return 0;
}

struct fuse_req *kpcs_req_alloc(struct fuse_conn *fc,
					unsigned npages, gfp_t flags)
{
	return fuse_generic_request_alloc(fc, pcs_fuse_req_cachep,
					  npages, flags);
}

/* IOHOOKS */

struct pcs_int_request * __ireq_alloc(void)
{
	return kmem_cache_alloc(pcs_ireq_cachep, GFP_NOIO);
}
void ireq_destroy(struct pcs_int_request *ireq)
{
	kmem_cache_free(pcs_ireq_cachep, ireq);
}

static int submit_size_grow(struct inode *inode, unsigned long long size)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff;
	struct fuse_setattr_in inarg;
	struct fuse_attr_out outarg;
	struct fuse_req *req;
	int err;

	/* Caller comes here w/o i_mutex, but vfs_truncate is blocked
	   at inode_dio_wait() see fuse_set_nowrite
	 */
	BUG_ON(!atomic_read(&inode->i_dio_count));

	TRACE("ino:%ld size:%lld \n",inode->i_ino, size);

	req = fuse_get_req_nopages(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));

	inarg.valid |= FATTR_SIZE;
	inarg.size = size;

	ff = fuse_write_file_get(fc, get_fuse_inode(inode));
	if (ff) {
		inarg.valid |= FATTR_FH;
		inarg.fh = ff->fh;
	}
	req->io_inode = inode;
	req->in.h.opcode = FUSE_SETATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;

	fuse_request_send(fc, req);

	err = req->out.h.error;
	fuse_release_ff(inode, ff);
	fuse_put_request(fc, req);

	return err;

}

static void fuse_size_grow_work(struct work_struct *w)
{
	struct pcs_dentry_info* di = container_of(w, struct pcs_dentry_info, size.work);
	struct inode *inode = &di->inode->inode;
	struct pcs_int_request* ireq, *next;
	unsigned long long size;
	int err;
	LIST_HEAD(pending_reqs);

	spin_lock(&di->lock);
	BUG_ON(di->size.op != PCS_SIZE_INACTION);

	size = di->size.required;
	if (!size) {
		BUG_ON(!list_empty(&di->size.queue));
		spin_unlock(&di->lock);
		TRACE("No more pending writes\n");
		return;
	}
	BUG_ON(di->fileinfo.attr.size >= size);

	list_splice_tail_init(&di->size.queue, &pending_reqs);
	di->size.op = PCS_SIZE_GROW;
	spin_unlock(&di->lock);

	err = submit_size_grow(inode, size);
	if (err) {
		spin_lock(&di->lock);
		di->size.op = PCS_SIZE_INACTION;
		list_splice_tail_init(&di->size.queue, &pending_reqs);
		di->size.required = 0;
		spin_unlock(&di->lock);

		pcs_ireq_queue_fail(&pending_reqs, err);
		return;
	}

	spin_lock(&di->lock);
	BUG_ON(di->size.required < size);
	di->size.op = PCS_SIZE_INACTION;

	list_for_each_entry_safe(ireq, next, &di->size.queue, list) {
		struct pcs_fuse_req *r = container_of(ireq, struct pcs_fuse_req, exec.ireq);

		BUG_ON(!r->exec.size_required);
		if (size >= r->exec.size_required) {
			TRACE("resubmit ino:%ld r(%p)->size:%lld required:%lld\n",
				inode->i_ino, r, r->exec.size_required, size);
			list_move(&ireq->list, &pending_reqs);
		}
	}

	if (list_empty(&di->size.queue))
		di->size.required = 0;
	spin_unlock(&di->lock);

	pcs_cc_requeue(di->cluster, &pending_reqs);
}

static void wait_grow(struct pcs_fuse_req *r, struct pcs_dentry_info *di, unsigned long long required)
{
	assert_spin_locked(&di->lock);
	BUG_ON(r->exec.size_required);
	BUG_ON(r->req.in.h.opcode != FUSE_WRITE && r->req.in.h.opcode != FUSE_FALLOCATE);
	BUG_ON(di->size.op != PCS_SIZE_INACTION && di->size.op != PCS_SIZE_GROW);

	TRACE("insert ino:%ld->required:%lld r(%p)->required:%lld\n", r->req.io_inode->i_ino,
	      di->size.required, r, required);
	r->exec.size_required = required;

	if (list_empty(&di->size.queue))
		queue_work(pcs_wq, &di->size.work);

	list_add_tail(&r->exec.ireq.list, &di->size.queue);

	di->size.required = max(di->size.required, required);
}

static void wait_shrink(struct pcs_fuse_req *r, struct pcs_dentry_info *di)
{
	assert_spin_locked(&di->lock);
	BUG_ON(r->exec.size_required);
	/* Writes already blocked via fuse_set_nowrite */
	BUG_ON(r->req.in.h.opcode != FUSE_READ);

	TRACE("insert ino:%ld r:%p\n", r->req.io_inode->i_ino, r);
	list_add_tail(&r->exec.ireq.list, &di->size.queue);
}

/*
 * Check i size boundary and deffer request if necessary
 * Ret code
 * 0: ready for submission
 * -1: should fail request
 * 1: request placed to pended queue
*/
static int pcs_fuse_prep_rw(struct pcs_fuse_req *r)
{
	struct fuse_inode *fi = get_fuse_inode(r->req.io_inode);
	struct pcs_dentry_info *di = pcs_inode_from_fuse(fi);
	int ret = 0;

	spin_lock(&di->lock);
	/* Deffer all requests if shrink requested to prevent livelock */
	if (di->size.op == PCS_SIZE_SHRINK) {
		wait_shrink(r, di);
		spin_unlock(&di->lock);
		return 1;
	}
	if (r->req.in.h.opcode == FUSE_READ) {
		size_t size;
		struct fuse_read_in *in = &r->req.misc.read.in;

		size = in->size;
		if (in->offset + in->size > di->fileinfo.attr.size) {
			if (in->offset >= di->fileinfo.attr.size) {
				r->req.out.args[0].size = 0;
				spin_unlock(&di->lock);
				return -1;
			}
			size = di->fileinfo.attr.size - in->offset;
		}
		pcs_fuse_prep_io(r, PCS_REQ_T_READ, in->offset, size, 0);
	} else if (r->req.in.h.opcode == FUSE_WRITE) {
		struct fuse_write_in *in = &r->req.misc.write.in;

		if (in->offset + in->size > di->fileinfo.attr.size) {
			wait_grow(r, di, in->offset + in->size);
			ret = 1;
		}
		pcs_fuse_prep_io(r, PCS_REQ_T_WRITE, in->offset, in->size, 0);
	} else if (r->req.in.h.opcode == FUSE_IOCTL) {
		size_t size;
		struct fiemap const *in = r->req.in.args[1].value;
		struct fiemap *out = r->req.out.args[1].value;

		*out = *in;
		out->fm_mapped_extents = 0;

		size = in->fm_length;
		if (in->fm_start + size > di->fileinfo.attr.size) {
			if (in->fm_start >= di->fileinfo.attr.size) {
				spin_unlock(&di->lock);
				return -1;
			}
			size = di->fileinfo.attr.size - in->fm_start;
		}
		pcs_fuse_prep_io(r, PCS_REQ_T_FIEMAP, in->fm_start, in->fm_extent_count*sizeof(struct fiemap_extent),
				 in->fm_extent_count);
		r->exec.io.req.size = size;
	} else {
		struct fuse_fallocate_in const *in = r->req.in.args[0].value;

		if (in->offset + in->length > di->fileinfo.attr.size) {
			wait_grow(r, di, in->offset + in->length);
			ret = 1;
		}

		if (in->mode & FALLOC_FL_PUNCH_HOLE)
			pcs_fuse_prep_io(r, PCS_REQ_T_WRITE_HOLE, in->offset, in->length, 0);
		else if (in->mode & FALLOC_FL_ZERO_RANGE)
			pcs_fuse_prep_io(r, PCS_REQ_T_WRITE_ZERO, in->offset, in->length, 0);
		else {
			if (ret) {
				pcs_fuse_prep_fallocate(r);
			} else {
				spin_unlock(&di->lock);
				return -1;
			}
		}
	}
	inode_dio_begin(r->req.io_inode);
	spin_unlock(&di->lock);

	return ret;
}

static void pcs_fuse_submit(struct pcs_fuse_cluster *pfc, struct fuse_req *req, int async)
{
	struct pcs_fuse_req *r = pcs_req_from_fuse(req);
	struct fuse_inode *fi = get_fuse_inode(req->io_inode);
	struct pcs_dentry_info *di = pcs_inode_from_fuse(fi);
	struct pcs_int_request* ireq;
	int ret;

	BUG_ON(!di);
	BUG_ON(req->cache != pcs_fuse_req_cachep);

	/* Init pcs_fuse_req */
	memset(&r->exec, 0, sizeof(r->exec));
	/* Use inline request structure */
	ireq = &r->exec.ireq;
	ireq_init(di, ireq);

	switch (r->req.in.h.opcode) {
	case FUSE_WRITE:
	case FUSE_READ:
		ret = pcs_fuse_prep_rw(r);
		if (!ret)
			goto submit;
		if (ret > 0)
			/* Pended, nothing to do. */
			return;
		break;
	case FUSE_FALLOCATE: {
		struct fuse_fallocate_in *inarg = (void*) req->in.args[0].value;

		if (pfc->fc->no_fallocate) {
			r->req.out.h.error = -EOPNOTSUPP;
			goto error;
		}

		if (inarg->offset >= di->fileinfo.attr.size)
			inarg->mode &= ~FALLOC_FL_ZERO_RANGE;

		if (inarg->mode & (FALLOC_FL_ZERO_RANGE|FALLOC_FL_PUNCH_HOLE)) {
			if ((inarg->offset & (PAGE_SIZE - 1)) || (inarg->length & (PAGE_SIZE - 1))) {
				r->req.out.h.error = -EINVAL;
				goto error;
			}
		}

		if (inarg->mode & FALLOC_FL_KEEP_SIZE) {
			if (inarg->offset + inarg->length > di->fileinfo.attr.size)
				inarg->length = di->fileinfo.attr.size - inarg->offset;
		}

		ret = pcs_fuse_prep_rw(r);
		if (!ret)
			goto submit;
		if (ret > 0)
			/* Pended, nothing to do. */
			return;
		break;
	}
	case FUSE_FSYNC:
	case FUSE_FLUSH:
		pcs_fuse_prep_io(r, PCS_REQ_T_SYNC, 0, 0, 0);
		goto submit;
	case FUSE_IOCTL:
		if (pfc->fc->no_fiemap) {
			r->req.out.h.error = -EOPNOTSUPP;
			goto error;
		}

		ret = pcs_fuse_prep_rw(r);
		if (!ret)
			goto submit;
		if (ret > 0)
			/* Pended, nothing to do. */
			return;
		break;
	}
	r->req.out.h.error = 0;
error:
	DTRACE("do fuse_request_end req:%p op:%d err:%d\n", &r->req, r->req.in.h.opcode, r->req.out.h.error);

	request_end(pfc->fc, &r->req);
	return;

submit:
	if (async)
		pcs_cc_submit(ireq->cc, ireq);
	else
		ireq_process(ireq);
}

static void kpcs_setattr_end(struct fuse_conn *fc, struct fuse_req *req)
{
	struct pcs_fuse_req *r = pcs_req_from_fuse(req);
	struct fuse_inode *fi = get_fuse_inode(req->io_inode);
	struct fuse_setattr_in *inarg = (void*) req->in.args[0].value;
	struct fuse_attr_out *outarg = (void*) req->out.args[0].value;
	struct pcs_dentry_info *di = fi->private;

	BUG_ON(req->in.h.opcode != FUSE_SETATTR);
	BUG_ON(!di);
	di = pcs_inode_from_fuse(fi);
	spin_lock(&di->lock);
	TRACE("update size: ino:%lu old_sz:%lld new:%lld\n",req->io_inode->i_ino,
	      di->fileinfo.attr.size, outarg->attr.size);

	if (!req->out.h.error) {
		di->fileinfo.attr.size = outarg->attr.size;
		if (outarg->attr.size != inarg->size) {
			pr_err("kio: failed to set requested size: %llu %llu\n",
				outarg->attr.size, inarg->size);
			req->out.h.error = -EIO;
		}
	}
	spin_unlock(&di->lock);
	if(r->end)
		r->end(fc, req);
}

static void _pcs_shrink_end(struct fuse_conn *fc, struct fuse_req *req)
{
	struct pcs_fuse_cluster *pfc = (struct pcs_fuse_cluster*)fc->kio.ctx;
	struct fuse_inode *fi = get_fuse_inode(req->io_inode);
	struct pcs_dentry_info *di = fi->private;
	LIST_HEAD(dispose);

	kpcs_setattr_end(fc, req);

	spin_lock(&di->lock);
	BUG_ON(di->size.op != PCS_SIZE_SHRINK);
	BUG_ON(di->size.required);

	list_splice_init(&di->size.queue, &dispose);
	di->size.op = PCS_SIZE_INACTION;
	spin_unlock(&di->lock);

	while (!list_empty(&dispose)) {
		struct pcs_int_request* ireq = list_first_entry(&dispose, struct pcs_int_request, list);
		struct pcs_fuse_req *r = container_of(ireq, struct pcs_fuse_req, exec.ireq);

		BUG_ON(r->exec.size_required);
		BUG_ON(r->req.in.h.opcode != FUSE_READ);

		TRACE("resubmit %p\n", &r->req);
		list_del_init(&ireq->list);
		pcs_fuse_submit(pfc, &r->req, 1);
	}
}

static void _pcs_grow_end(struct fuse_conn *fc, struct fuse_req *req)
{
	kpcs_setattr_end(fc, req);
}

static void pcs_kio_setattr_handle(struct fuse_inode *fi, struct fuse_req *req)
{
	struct pcs_fuse_req *r = pcs_req_from_fuse(req);
	struct fuse_setattr_in *inarg = (void*) req->in.args[0].value;
	struct pcs_dentry_info *di;

	BUG_ON(!fi);

	di = pcs_inode_from_fuse(fi);
	spin_lock(&di->lock);
	if (inarg->size < di->fileinfo.attr.size) {
		BUG_ON(di->size.op != PCS_SIZE_INACTION);
		di->size.op = PCS_SIZE_SHRINK;
	}
	spin_unlock(&di->lock);

	r->end = req->end;
	if (di->size.op == PCS_SIZE_SHRINK) {
		BUG_ON(!mutex_is_locked(&req->io_inode->i_mutex));
		/* wait for aio reads in flight */
		inode_dio_wait(req->io_inode);
		/*
		 * Writebackcache was flushed already so it is safe to
		 * drop pcs_mapping
		 */
		pcs_map_invalidate_tail(&di->mapping, inarg->size);
		req->end = _pcs_shrink_end;
	} else
		req->end = _pcs_grow_end;
}

static int pcs_kio_classify_req(struct fuse_conn *fc, struct fuse_req *req, bool lk)
{
	struct fuse_inode *fi = get_fuse_inode(req->io_inode);

	switch (req->in.h.opcode) {
	case FUSE_READ:
	case FUSE_WRITE:
	case FUSE_FSYNC:
	case FUSE_FLUSH:
	case FUSE_FALLOCATE:
		break;
	case FUSE_SETATTR: {
		struct fuse_setattr_in const *inarg = req->in.args[0].value;

		if (unlikely(!fi))
			goto fail;
		if (!fi->private)
			return 1;
		if (!(inarg->valid & FATTR_SIZE))
			return 1;
		if (lk)
			spin_unlock(&fc->bg_lock);
		pcs_kio_setattr_handle(fi, req);
		if (lk)
			spin_lock(&fc->bg_lock);
		return 1;
	}
	case FUSE_IOCTL: {
		struct fuse_ioctl_in const *inarg = req->in.args[0].value;

		if (inarg->cmd != FS_IOC_FIEMAP)
			return 1;

		break;
	}
	default:
		return 1;
	}

	if (unlikely(!fi))
		goto fail;
	if (!fi->private)
		return 1;

	return 0;

fail:
	WARN_ONCE(1, "Fuse kio: req cannot be processed w/o inode\n");
	return -EINVAL;
}

static int kpcs_req_send(struct fuse_conn* fc, struct fuse_req *req, bool bg, bool lk)
{
	struct pcs_fuse_cluster *pfc = (struct pcs_fuse_cluster*)fc->kio.ctx;
	int ret;

	if (!fc->initialized || fc->conn_error)
		return 1;

	BUG_ON(!pfc);
	/* HYPOTHESIS #1
	 * IFAIU at this point request can not belongs to any list
	 * so I cant avoid grab fc->lock here at all
	 */
	BUG_ON(!list_empty(&req->list));

	TRACE(" Enter req:%p op:%d end:%p bg:%d lk:%d\n", req, req->in.h.opcode, req->end, bg, lk);

	ret = pcs_kio_classify_req(fc, req, lk);
	if (ret) {
		if (ret < 0) {
			if (!bg)
				atomic_inc(&req->count);
			__clear_bit(FR_PENDING, &req->flags);
			req->out.h.error = ret;
			if (lk)
				spin_unlock(&fc->bg_lock);
			request_end(fc, req);
			if (lk)
				spin_lock(&fc->bg_lock);
			return 0;
		}
		return 1;
	}

	/* request_end below will do fuse_put_request() */
	if (!bg)
		atomic_inc(&req->count);
	else if (!lk) {
		spin_lock(&fc->bg_lock);
		if (fc->num_background + 1 >= fc->max_background ||
		    !fc->connected) {
			spin_unlock(&fc->bg_lock);
			return 1;
		}
		fc->num_background++;
		fc->active_background++;

		if (fc->num_background == fc->congestion_threshold &&
		    fc->bdi_initialized) {
			set_bdi_congested(&fc->bdi, BLK_RW_SYNC);
			set_bdi_congested(&fc->bdi, BLK_RW_ASYNC);
		}
		spin_unlock(&fc->bg_lock);
	}
	__clear_bit(FR_PENDING, &req->flags);

	pcs_fuse_submit(pfc, req, lk);
	if (!bg)
		wait_event(req->waitq,
			   test_bit(FR_FINISHED, &req->flags) && !req->end);

	return 0;
}

static void fuse_trace_free(struct fuse_ktrace *tr)
{
	relay_close(tr->rchan);
	free_percpu(tr->ovfl);
	if (tr->prometheus_dentry) {
		debugfs_remove(tr->prometheus_dentry);
	}
	if (tr->prometheus_hist) {
		int cpu;

		for_each_possible_cpu(cpu) {
			struct kfuse_histogram ** histp;
			histp = per_cpu_ptr(tr->prometheus_hist, cpu);
			if (*histp)
				free_page((unsigned long)*histp);
		}
		free_percpu(tr->prometheus_hist);
	}
	free_percpu(tr->buf);
	debugfs_remove(tr->dir);
	kfree(tr);
}

static int fuse_ktrace_remove(struct fuse_conn *fc)
{
	struct fuse_ktrace *tr;

	tr = xchg(&fc->ktrace, NULL);
	if (!tr)
		return -EINVAL;

	if (atomic_dec_and_test(&tr->refcnt))
		fuse_trace_free(tr);
	return 0;
}

static int subbuf_start_callback(struct rchan_buf *buf, void *subbuf,
				 void *prev_subbuf, size_t prev_padding)
{
	return !relay_buf_full(buf);
}

static struct dentry * create_buf_file_callback(const char *filename,
						struct dentry *parent,
						umode_t mode,
						struct rchan_buf *buf,
						int *is_global)
{
	return debugfs_create_file(filename, mode, parent, buf,
				   &relay_file_operations);
}

static int remove_buf_file_callback(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return 0;
}


static struct rchan_callbacks relay_callbacks = {
	.subbuf_start		= subbuf_start_callback,
	.create_buf_file	= create_buf_file_callback,
	.remove_buf_file	= remove_buf_file_callback,
};

void fuse_stat_account(struct fuse_conn * fc, int op, ktime_t val)
{
	struct fuse_ktrace * tr = fc->ktrace;

	BUG_ON(op >= KFUSE_OP_MAX);

	if (tr) {
		struct kfuse_histogram ** histp;
		int cpu;

		cpu = get_cpu();
		histp = per_cpu_ptr(tr->prometheus_hist, cpu);
		if (histp && *histp) {
			struct kfuse_stat_rec * rec = (*histp)->metrics + op;
			int bucket;
			unsigned long long lat = ktime_to_ns(val)/1000;

			if (lat < 1000)
				bucket = (lat/100);
			else if (lat < 10000)
				bucket = 9*1 + (lat/1000);
			else if (lat < 100000)
				bucket = 9*2 + (lat/10000);
			else if (lat < 1000000)
				bucket = 9*3 + (lat/100000);
			else if (lat < 10000000)
				bucket = 9*4 + (lat/1000000);
			else
				bucket = 9*5 + 1;

			rec->buckets[bucket]++;
			rec->sum += lat;
		}
		put_cpu();
	}
}

static int prometheus_file_open(struct inode *inode, struct file *filp)
{
	struct fuse_ktrace * tr = inode->i_private;

	atomic_inc(&tr->refcnt);
	filp->private_data = tr;

	return generic_file_open(inode, filp);
}

static int prometheus_file_release(struct inode *inode, struct file *filp)
{
	struct fuse_ktrace * tr = inode->i_private;

	if (atomic_dec_and_test(&tr->refcnt))
		fuse_trace_free(tr);

	return 0;
}

static ssize_t prometheus_file_read(struct file *filp,
				    char __user *buffer,
				    size_t count,
				    loff_t *ppos)
{
	struct fuse_ktrace * tr = filp->private_data;
	struct kfuse_histogram * hist;
	int cpu;

	if (*ppos >= sizeof(struct kfuse_histogram))
		return 0;
	if (*ppos + count > sizeof(struct kfuse_histogram))
		count = sizeof(struct kfuse_histogram) - *ppos;

	hist = (void*)get_zeroed_page(GFP_KERNEL);
	if (!hist)
		return -ENOMEM;

	if (!tr->prometheus_hist)
		return -EINVAL;

	for_each_possible_cpu(cpu) {
		struct kfuse_histogram ** histp;

		histp = per_cpu_ptr(tr->prometheus_hist, cpu);
		if (histp && *histp) {
			int i, k;
			for (i = 0; i < KFUSE_OP_MAX; i++) {
				for (k = 0; k < KFUSE_PROM_MAX; k++) {
					hist->metrics[i].buckets[k] += (*histp)->metrics[i].buckets[k];
				}
				hist->metrics[i].sum += (*histp)->metrics[i].sum;
			}
		}
	}

	if (copy_to_user(buffer, (char*)hist + *ppos, count))
		count = -EFAULT;
	else
		*ppos += count;

	free_page((unsigned long)hist);
	return count;
}

const struct file_operations prometheus_file_operations = {
	.open		= prometheus_file_open,
	.read		= prometheus_file_read,
	.release	= prometheus_file_release,
};

static int fuse_ktrace_setup(struct fuse_conn * fc)
{
	int ret;
	struct fuse_ktrace * tr = NULL;
	struct fuse_ktrace * old_tr;
	struct dentry * dir;
	struct kfuse_histogram * __percpu * hist;
	char name[16];

	if (!fuse_trace_root)
		return -ENOENT;

	tr = kzalloc(sizeof(*tr), GFP_KERNEL);
	if (!tr)
		return -ENOMEM;

	ret = -ENOMEM;
	tr->ovfl = alloc_percpu(unsigned long);
	if (!tr->ovfl)
		goto err;

	ret = -ENOENT;

	snprintf(name, sizeof(name), "%u", fc->dev);

	dir = debugfs_create_dir(name, fuse_trace_root);

	if (!dir)
		goto err;

	tr->dir = dir;
	tr->rchan = relay_open("trace", dir, FUSE_KTRACE_SIZE,
				FUSE_KTRACE_NR, &relay_callbacks, tr);
	if (!tr->rchan)
		goto err;

	tr->prometheus_dentry = debugfs_create_file("prometheus", S_IFREG|0444, dir, tr,
						    &prometheus_file_operations);
	hist = (void*)alloc_percpu(void *);
	if (hist) {
		int cpu;

		BUILD_BUG_ON(sizeof(struct kfuse_histogram) > PAGE_SIZE);

		for_each_possible_cpu(cpu) {
			struct kfuse_histogram ** histp;
			histp = per_cpu_ptr(hist, cpu);
			*histp = (void*)get_zeroed_page(GFP_KERNEL);
		}
		tr->prometheus_hist = hist;
	}

	tr->buf = __alloc_percpu(KTRACE_LOG_BUF_SIZE, 16);

	atomic_set(&tr->refcnt, 1);

	ret = -EBUSY;
	old_tr = xchg(&fc->ktrace, tr);
	if (old_tr) {
		(void) xchg(&fc->ktrace, old_tr);
		goto err;
	}

	return 0;

err:
	if (tr && atomic_dec_and_test(&tr->refcnt))
		fuse_trace_free(tr);
	return ret;
}

void __kfuse_trace(struct fuse_conn * fc, unsigned long ip, const char * fmt, ...)
{
	struct fuse_ktrace * tr;
        va_list va;
	int cpu;

	cpu = get_cpu();
	tr = fc->ktrace;
	if (tr) {
		u8 * buf = per_cpu_ptr(tr->buf, cpu);
		struct fuse_trace_hdr * t;
		int len;

		va_start(va, fmt);
		len = vsnprintf(buf, KTRACE_LOG_BUF_SIZE, fmt, va);
		va_end(va);
		t = fuse_trace_prepare(tr, FUSE_KTRACE_STRING, len + 1);
		if (t)
			memcpy(t + 1, buf, len + 1);
		FUSE_TRACE_COMMIT(tr);
		if (ip)
			__trace_puts(ip, buf, len);
		else
			pr_debug("%s", buf);
	}
	put_cpu();
}

static struct fuse_kio_ops kio_pcs_ops = {
	.name		= "pcs",
	.owner		= THIS_MODULE,
	.probe		= kpcs_probe,

	.conn_init	= kpcs_conn_init,
	.conn_fini	= kpcs_conn_fini,
	.conn_abort	= kpcs_conn_abort,
	.req_alloc	= kpcs_req_alloc,
	.req_send	= kpcs_req_send,
	.file_open	= kpcs_file_open,
	.inode_release	= kpcs_inode_release,
};


static int __init kpcs_mod_init(void)
{
	int err = -ENOMEM;
	pcs_fuse_req_cachep = kmem_cache_create("pcs_fuse_request",
						sizeof(struct pcs_fuse_req),
						0, 0, NULL);

	if (!pcs_fuse_req_cachep)
		return err;

	pcs_ireq_cachep = kmem_cache_create("pcs_ireq",
					    sizeof(struct pcs_int_request),
					    0, SLAB_MEM_SPREAD, NULL);
	if (!pcs_ireq_cachep)
		goto free_fuse_cache;

	pcs_map_cachep = kmem_cache_create("pcs_map",
					    sizeof(struct pcs_map_entry),
					    0, SLAB_RECLAIM_ACCOUNT|SLAB_ACCOUNT, NULL);
	if (!pcs_map_cachep)
		goto free_ireq_cache;

	pcs_wq = alloc_workqueue("pcs_cluster", WQ_MEM_RECLAIM, 0);
	if (!pcs_wq)
		goto free_map_cache;

	if (fuse_register_kio(&kio_pcs_ops))
		goto free_wq;

	fuse_trace_root = debugfs_create_dir("fuse", NULL);

	printk("%s fuse_c:%p ireq_c:%p pcs_wq:%p\n", __FUNCTION__,
	       pcs_fuse_req_cachep, pcs_ireq_cachep, pcs_wq);

	return 0;
free_wq:
	destroy_workqueue(pcs_wq);
free_map_cache:
	kmem_cache_destroy(pcs_map_cachep);
free_ireq_cache:
	kmem_cache_destroy(pcs_ireq_cachep);
free_fuse_cache:
	kmem_cache_destroy(pcs_fuse_req_cachep);
	return err;
}

static void __exit kpcs_mod_exit(void)
{
	if (fuse_trace_root)
		debugfs_remove(fuse_trace_root);

	fuse_unregister_kio(&kio_pcs_ops);
	destroy_workqueue(pcs_wq);
	kmem_cache_destroy(pcs_map_cachep);
	kmem_cache_destroy(pcs_ireq_cachep);
	kmem_cache_destroy(pcs_fuse_req_cachep);
}

module_init(kpcs_mod_init);
module_exit(kpcs_mod_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Virtuozzo <devel@openvz.org>");
