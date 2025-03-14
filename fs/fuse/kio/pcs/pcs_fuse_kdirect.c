/*
 *  fs/fuse/kio/pcs/pcs_fuse_kdirect.c
 *
 *  Copyright (c) 2018-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

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
#include <linux/fiemap.h>

#include "pcs_ioctl.h"
#include "pcs_cluster.h"
#include "pcs_rpc.h"
#include "fuse_ktrace.h"
#include "fuse_prometheus.h"

unsigned int pcs_loglevel = LOG_TRACE;
module_param(pcs_loglevel, uint, 0644);
MODULE_PARM_DESC(pcs_loglevel, "Trace level");

u64 fast_path_version;
module_param(fast_path_version, ullong, 0444);
MODULE_PARM_DESC(fast_path_version, "Fast path protocol version");

unsigned int debugfs_tracing = DEBUGFS_TRACE;
module_param(debugfs_tracing, uint, 0644);
MODULE_PARM_DESC(debugfs_tracing, "Enable/Disbale debugfs tracing");

bool rdmaio_use_map_for_mr = false;
module_param(rdmaio_use_map_for_mr, bool, 0644);
MODULE_PARM_DESC(rdmaio_use_map_for_mr, "Enable/Disbale usage of map for RDMA MRs");

bool rdmaio_use_dma_mr_for_rdma_rw = true;
module_param(rdmaio_use_dma_mr_for_rdma_rw, bool, 0644);
MODULE_PARM_DESC(rdmaio_use_dma_mr_for_rdma_rw,
		 "Enable/Disbale usage of DMA memory region for RDMA read/write requests");

unsigned int rdmaio_cq_count = 0;
module_param(rdmaio_cq_count, uint, 0644);
MODULE_PARM_DESC(rdmaio_cq_count, "RDMA CQ count");

unsigned int rdmaio_cq_period = 0;
module_param(rdmaio_cq_period, uint, 0644);
MODULE_PARM_DESC(rdmaio_cq_period, "RDMA CQ period in microsecond");

unsigned int rdmaio_queue_depth = 8;
module_param(rdmaio_queue_depth, uint, 0644);
MODULE_PARM_DESC(rdmaio_queue_depth, "RDMA queue depth");

#ifdef CONFIG_DEBUG_KERNEL

static int set_io_fail_percent(const char *val, const struct kernel_param *kp)
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
module_param_call(sockio_fail_percent, set_io_fail_percent,
		  param_get_uint, &sockio_fail_percent, 0644);
__MODULE_PARM_TYPE(sockio_fail_percent, "uint");
MODULE_PARM_DESC(sockio_fail_percent, "Sock io failing rate in percents");

bool rdmaio_io_failing = false;
module_param(rdmaio_io_failing, bool, 0644);
MODULE_PARM_DESC(rdmaio_io_failing, "Enable/Disbale RDMA io failing");

#endif

static int fuse_ktrace_setup(struct fuse_conn * fc);
static int fuse_ktrace_remove(struct fuse_conn *fc);

static struct kmem_cache *pcs_fuse_req_cachep;
static struct kmem_cache *pcs_ireq_cachep;
static struct workqueue_struct *pcs_wq;
struct workqueue_struct *pcs_cleanup_wq;
static struct fuse_kio_ops kio_pcs_ops;
static struct dentry *fuse_trace_root;

static void process_pcs_init_reply(struct fuse_mount *fm, struct fuse_args *args,
				   int error)
{
	struct fuse_conn *fc = fm->fc;
	struct fuse_io_args *ia = container_of(args, typeof(*ia), ap.args);
	struct pcs_fuse_cluster *pfc;
	struct fuse_ioctl_out *arg = &ia->ioctl.out;
	struct	pcs_ioc_init_kdirect *info = args->out_args[1].value;

	if ((error == -EPROTONOSUPPORT && !arg->result) ||
	    info->version.major != PCS_FAST_PATH_VERSION.major ||
	    info->version.minor != PCS_FAST_PATH_VERSION.minor) {
		pr_err("kio_pcs: version mismatch: must be %u.%u. "
		       "Fallback to plain fuse\n",
		       PCS_FAST_PATH_VERSION.major,
		       PCS_FAST_PATH_VERSION.minor);
		fc->kdirect_io = 0;
		goto out;
	} else if (error || arg->result) {
		printk("Fail to initialize has_kdirect {%d,%d}\n",
		       error, arg->result);
		fc->conn_error = 1;
		goto out;
	}

	pfc = kvmalloc(sizeof(*pfc), GFP_KERNEL);
	if (!pfc) {
		fc->conn_error = 1;
		goto out;
	}

	if (pcs_cluster_init(pfc, pcs_wq, fc, info)) {
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
	}
out:
	if (fc->conn_error)
		pr_err("Failed to initialize fuse kio\n");
	kfree(ia);
	kfree(info);
	/*  We are called from	process_init_reply before connection
	 * was not initalized yet. Do it now. */
	fuse_set_initialized(fc);
	wake_up_all(&fc->blocked_waitq);

}

int kpcs_conn_init(struct fuse_mount *fm)
{
	struct fuse_conn *fc = fm->fc;
	struct fuse_io_args *ia;
	struct fuse_ioctl_in *inarg;
	struct fuse_ioctl_out *outarg;
	struct pcs_ioc_init_kdirect *info;
	int err;

	BUG_ON(!fc->conn_init);

	info = kzalloc(sizeof(*info), GFP_NOIO);
	if (!info)
		return -ENOMEM;

	ia = kzalloc(sizeof(*ia), GFP_NOIO);
	if (!ia) {
		kfree(info);
		return -ENOMEM;
	}

	ia->ap.args.kio_internal = true;
	/* filehandle and nodeid are null, but this is OK */
	inarg = &ia->ioctl.in;
	outarg = &ia->ioctl.out;
	inarg->cmd = PCS_IOC_INIT_KDIRECT;
	info->version = PCS_FAST_PATH_VERSION;

	ia->ap.args.opcode = FUSE_IOCTL;
	ia->ap.args.in_numargs = 2;
	ia->ap.args.in_args[0].size = sizeof(*inarg);
	ia->ap.args.in_args[0].value = inarg;
	ia->ap.args.in_args[1].size = sizeof(*info);
	ia->ap.args.in_args[1].value = info;
	ia->ap.args.out_numargs = 2;
	ia->ap.args.out_args[0].size = sizeof(*outarg);
	ia->ap.args.out_args[0].value = outarg;
	ia->ap.args.out_args[1].size = sizeof(*info);
	ia->ap.args.out_args[1].value = info;
	ia->ioctl.ctx = info;
	ia->ap.args.end = process_pcs_init_reply;
	ia->ap.args.force = true;
	ia->ap.args.nocreds = true;

	err = fuse_simple_background(fm, &ia->ap.args, GFP_NOIO);
	if (err)
		process_pcs_init_reply(fm, &ia->ap.args, err);

	return 0;
}

void kpcs_conn_fini(struct fuse_mount *fm)
{
	struct fuse_conn *fc = fm->fc;

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


static int fuse_pcs_getfileinfo(struct file *file, struct pcs_mds_fileinfo *info)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_io_args ia = {};
	struct fuse_ioctl_in *inarg;
	struct fuse_ioctl_out *outarg;
	struct pcs_ioc_fileinfo ioc_info = {};
	int err = 0;

	ia.ap.args.kio_internal = true;
	inarg = &ia.ioctl.in;
	outarg = &ia.ioctl.out;

	ia.ap.args.opcode = FUSE_IOCTL;
	ia.ap.args.nodeid = ff->nodeid;

	inarg->cmd = PCS_IOC_GETFILEINFO;
	inarg->fh = ff->fh;
	inarg->arg = 0;
	inarg->flags = 0;
	ia.ap.args.in_numargs = 1;
	ia.ap.args.in_args[0].size = sizeof(*inarg);
	ia.ap.args.in_args[0].value = inarg;

	ia.ap.args.out_numargs = 2;
	ia.ap.args.out_args[0].size = sizeof(*outarg);
	ia.ap.args.out_args[0].value = outarg;
	ia.ap.args.out_args[1].size = sizeof(ioc_info);
	ia.ap.args.out_args[1].value = &ioc_info;

	err = fuse_simple_request(ff->fm, &ia.ap.args);
	if (err || outarg->result) {
		TRACE("%s:%d h.err:%d result:%d\n", __FUNCTION__, __LINE__,
		      err, outarg->result);
		err = err ? : outarg->result;
		return err;
	} else
		*info = ioc_info.fileinfo;

	return 0;
}

static int fuse_pcs_kdirect_claim_op(struct file *file, bool claim)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_io_args ia = {};
	struct fuse_ioctl_in *inarg;
	struct fuse_ioctl_out *outarg;
	int err = 0;

	ia.ap.args.kio_internal = true;
	inarg = &ia.ioctl.in;
	outarg = &ia.ioctl.out;

	ia.ap.args.opcode = FUSE_IOCTL;
	ia.ap.args.nodeid = ff->nodeid;

	if (claim)
		inarg->cmd = PCS_IOC_KDIRECT_CLAIM;
	else
		inarg->cmd = PCS_IOC_KDIRECT_RELEASE;

	inarg->fh = ff->fh;
	inarg->arg = 0;
	inarg->flags = 0;
	ia.ap.args.in_numargs = 1;
	ia.ap.args.in_args[0].size = sizeof(*inarg);
	ia.ap.args.in_args[0].value = inarg;
	ia.ap.args.out_numargs = 1;
	ia.ap.args.out_args[0].size = sizeof(*outarg);
	ia.ap.args.out_args[0].value = outarg;
	err = fuse_simple_request(ff->fm, &ia.ap.args);
	if (err || outarg->result) {
		TRACE("%s:%d h.err:%d result:%d\n", __FUNCTION__, __LINE__,
		      err, outarg->result);
		err = -EOPNOTSUPP;
	}

	return err;
}
static void  fuse_size_grow_work(struct work_struct *w);

static int kpcs_do_file_open(struct file *file, struct inode *inode)
{
	struct pcs_mds_fileinfo info;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct pcs_fuse_cluster *pfc = (struct pcs_fuse_cluster*)fc->kio.ctx;
	struct pcs_dentry_info *di = NULL;
	int ret;

	ret = fuse_pcs_getfileinfo(file, &info);
	if (ret)
		return ret == -EOPNOTSUPP ? 0 : ret;

	if (info.sys.map_type != PCS_MAP_PLAIN) {
		TRACE("Unsupported map_type:%x, ignore\n", info.sys.map_type);
		return 0;
	}

	if (info.sys.chunk_size_hi) {
		TRACE("Unsupported chunk_size_hi:%x\n", info.sys.chunk_size_hi);
		pr_warn_once("kio: fpath doesn't support jumbo chunks\n");
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
	di->stat.created_ts = jiffies;
	if (pcs_fuse_io_stat_alloc(&di->stat.io)) {
		kfree(di);
		return -ENOMEM;
	}
	if (pcs_fuse_fstat_alloc(&di->stat.lat)) {
		pcs_fuse_io_stat_free(&di->stat.io);
		kfree(di);
		return -ENOMEM;
	}

	pcs_mapping_init(&pfc->cc, &di->mapping);
	pcs_set_fileinfo(di, &info);
	di->cluster = &pfc->cc;
	di->inode = fi;
	INIT_LIST_HEAD(&di->kq);
	spin_lock_init(&di->kq_lock);
	TRACE("init id:%llu chunk_size:%d stripe_depth:%d strip_width:%d\n",
	      fi->nodeid, di->fileinfo.sys.chunk_size_lo,
	      di->fileinfo.sys.stripe_depth, di->fileinfo.sys.strip_width);

	ret = fuse_pcs_kdirect_claim_op(file, true);
	if (ret) {
		pcs_mapping_invalidate(&di->mapping);
		pcs_mapping_deinit(&di->mapping);
		kfree(di);
		/* Claim error means we cannot claim, just that */
		return (ret == -EOPNOTSUPP ? 0: ret);
	}
	/* TODO: Propper initialization of dentry should be here!!! */
	fi->private = di;
	return 0;
}

int kpcs_file_open(struct file *file, struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct pcs_dentry_info *di = fi->private;
	struct pcs_mds_fileinfo info;
	int ret = 0;

	if (!S_ISREG(inode->i_mode))
		return 0;
	if (fi->nodeid - FUSE_ROOT_ID >= PCS_FUSE_INO_SPECIAL_)
		return 0;

	lockdep_assert_held(&inode->i_rwsem);
	/* Already initialized. Update file size etc */
	if (di) {
		/*TODO: propper refcount for claim_cnt should be here */
		ret = fuse_pcs_getfileinfo(file, &info);
		if (ret)
			return ret;
		spin_lock(&di->lock);
		pcs_set_fileinfo(di, &info);
		spin_unlock(&di->lock);
		return 0;
	}

	if (!test_bit(FUSE_I_KIO_OPEN_TRY_MADE, &fi->state)) {
		ret = kpcs_do_file_open(file, inode);
		if (!ret)
			set_bit(FUSE_I_KIO_OPEN_TRY_MADE, &fi->state);
	}

	return ret;
}

static void kpcs_file_close(struct file *file, struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct pcs_dentry_info *di = fi->private;

	lockdep_assert_held(&inode->i_rwsem);

	TRACE("file close - fi: %p, di: %p", fi, di);

	if (!di)
		return;

	WARN_ON_ONCE(!list_empty(&di->size.queue));
	WARN_ON_ONCE(!list_empty(&di->kq));
	pcs_mapping_invalidate(&di->mapping);
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
	pcs_fuse_fstat_free(&di->stat.lat);
	pcs_fuse_io_stat_free(&di->stat.io);
	kfree(di);
}

static void pcs_fuse_reply_handle(struct fuse_mount *fm, struct fuse_args *args,
				  int error)
{
	struct fuse_io_args *ia = container_of(args, typeof(*ia), ap.args);
	struct pcs_fuse_work *work = (struct pcs_fuse_work*) ia->ioctl.ctx;
	int err;

	err = error ? : ia->ioctl.out.result;
	if (err) {
		/* TODO	 Fine grane error conversion here */
		pcs_set_local_error(&work->status, PCS_ERR_PROTOCOL);
	}
	kfree(ia);
	queue_work(pcs_wq, &work->work);
}

static void fuse_complete_map_work(struct work_struct *w)
{
	struct pcs_fuse_work *work = container_of(w, struct pcs_fuse_work, work);
	struct pcs_map_entry *m = (struct pcs_map_entry *)work->ctx;
	struct pcs_ioc_getmap *omap = (struct pcs_ioc_getmap *)work->ctx2;

	BUG_ON(!m);
	BUG_ON(!omap);

	if (pcs_if_error(&work->status)) {
		pcs_copy_error(&omap->error, &work->status);
	} else if (omap->cs_cnt > PCS_MAX_CS_CNT) {
		printk("Corrupted cs_cnt from userspace");
		pcs_set_local_error(&omap->error, PCS_ERR_PROTOCOL);
	}

	pcs_map_complete(m, omap);
	kfree(omap);
	kfree(work);
}

int fuse_map_resolve(struct pcs_map_entry *m, int direction)
{
	struct pcs_dentry_info *di;
	struct fuse_mount *fm;
	struct fuse_io_args *ia;
	struct fuse_ioctl_in *inarg;
	struct fuse_ioctl_out *outarg;
	struct pcs_ioc_getmap *map_ioc;
	struct pcs_fuse_work *reply_work;
	size_t map_sz;
	int err;

	spin_lock(&m->lock);

	if (m->state & PCS_MAP_DEAD) {
		spin_unlock(&m->lock);
		pcs_map_put(m);
		return 0;
	}
	di = pcs_dentry_from_mapping(m->mapping);
	fm = get_fuse_mount(&di->inode->inode);

	DTRACE("enter m: " MAP_FMT ", dir:%d \n", MAP_ARGS(m),	direction);

	BUG_ON(!(m->state & PCS_MAP_RESOLVING));

	spin_unlock(&m->lock);

	map_sz = sizeof(*map_ioc) + PCS_MAX_CS_CNT * sizeof(struct pcs_cs_info);
	map_ioc = kzalloc(map_sz, GFP_NOIO);
	if (!map_ioc)
		return -ENOMEM;

	reply_work = kzalloc(sizeof(*reply_work), GFP_NOIO);
	if (!reply_work) {
		kfree(map_ioc);
		return -ENOMEM;
	}
	ia = kzalloc(sizeof(*ia), GFP_NOIO);
	if (!ia) {
		kfree(map_ioc);
		kfree(reply_work);
		return -ENOMEM;
	}

	ia->ap.args.kio_internal = true;
	inarg = &ia->ioctl.in;
	outarg = &ia->ioctl.out;
	inarg->cmd = PCS_IOC_GETMAP;
	map_ioc->cs_max = PCS_MAX_CS_CNT;

	/* fill ioc_map struct */
	if (pcs_map_encode_req(m, map_ioc, direction) != 0) {
		kfree(map_ioc);
		kfree(reply_work);
		kfree(ia);
		return 0;
	}

	/* Fill core ioctl */
	ia->ap.args.opcode = FUSE_IOCTL;
	/* FH is null, peer will lookup by nodeid */
	inarg->fh = 0;
	ia->ap.args.nodeid = di->inode->nodeid;
	ia->ap.args.in_numargs = 2;
	ia->ap.args.in_args[0].size = sizeof(*inarg);
	ia->ap.args.in_args[0].value = inarg;
	ia->ap.args.in_args[1].size = map_sz;
	ia->ap.args.in_args[1].value = map_ioc;

	ia->ap.args.out_numargs = 2;
	/* TODO: make this ioctl varsizable */
	ia->ap.args.out_argvar = 1;
	ia->ap.args.out_args[0].size = sizeof(*outarg);
	ia->ap.args.out_args[0].value = outarg;
	ia->ap.args.out_args[1].size = map_sz;
	ia->ap.args.out_args[1].value = map_ioc;

	INIT_WORK(&reply_work->work, fuse_complete_map_work);
	reply_work->ctx = m;
	reply_work->ctx2 = map_ioc;
	ia->ioctl.ctx = reply_work;
	ia->ap.args.end = pcs_fuse_reply_handle;
	ia->ap.args.nonblocking = true;
	ia->ap.args.force = true;
	ia->ap.args.nocreds = true;

	err = fuse_simple_background(fm, &ia->ap.args, GFP_NOIO);
	if (err)
		pcs_fuse_reply_handle(fm, &ia->ap.args, err);

	return 0;
}

struct fuse_req *kpcs_req_alloc(struct fuse_mount *fm, gfp_t flags)
{
	return fuse_generic_request_alloc(fm, pcs_fuse_req_cachep, flags);
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
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_file *ff;
	struct fuse_setattr_in inarg;
	struct fuse_attr_out outarg;
	FUSE_ARGS(args);
	int err;

	/* Caller comes here w/o i_mutex, but vfs_truncate is blocked
	   at fuse_write_dio_wait see fuse_set_nowrite
	 */
	BUG_ON(!fuse_write_dio_count(fi));

	TRACE("ino:%ld size:%lld \n",inode->i_ino, size);

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));

	inarg.valid |= FATTR_SIZE;
	inarg.size = size;

	ff = __fuse_write_file_get(fm->fc, get_fuse_inode(inode));
	if (ff) {
		inarg.valid |= FATTR_FH;
		inarg.fh = ff->fh;
	}
	args.io_inode = inode;
	args.opcode = FUSE_SETATTR;
	args.nodeid = get_node_id(inode);
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.out_numargs = 1;
	args.out_args[0].size = sizeof(outarg);
	args.out_args[0].value = &outarg;

	err = fuse_simple_request(fm, &args);
	fuse_release_ff(inode, ff);

	return err;

}

static void fuse_size_grow_work(struct work_struct *w)
{
	struct pcs_dentry_info* di = container_of(w, struct pcs_dentry_info, size.work);
	struct inode *inode = &di->inode->inode;
	struct pcs_int_request *ireq, *next;
	u64 size, old_size;
	int err;
	LIST_HEAD(pending_reqs);

	spin_lock(&di->lock);
	BUG_ON(di->size.op != PCS_SIZE_INACTION);

	old_size = DENTRY_SIZE(di);
	size = di->size.required;
	if (!size) {
		BUG_ON(!list_empty(&di->size.queue));
		spin_unlock(&di->lock);
		TRACE("No more pending writes\n");
		return;
	}
	BUG_ON(old_size >= size);

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

	TRACE("insert ino:%ld->required:%lld r(%p)->required:%lld\n",
	      r->req.args->io_inode->i_ino, di->size.required, r,
	      required);
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
	BUG_ON(r->req.in.h.opcode != FUSE_READ && r->req.in.h.opcode != FUSE_FSYNC && r->req.in.h.opcode != FUSE_FLUSH);

	TRACE("insert ino:%ld r:%p\n", r->req.args->io_inode->i_ino, r);
	list_add_tail(&r->exec.ireq.list, &di->size.queue);
}

static bool kqueue_insert(struct pcs_dentry_info *di, struct fuse_req *req)
{
	struct fuse_file *ff = req->args->ff;

	spin_lock(&di->kq_lock);
	if (ff && test_bit(FUSE_S_FAIL_IMMEDIATELY, &ff->ff_state)) {
		spin_unlock(&di->kq_lock);
		return false;
	}
	list_add_tail(&req->list, &di->kq);
	spin_unlock(&di->kq_lock);
	return true;
}

static inline int req_wait_grow_queue(struct pcs_fuse_req *r, off_t offset, size_t size)
{
	struct pcs_dentry_info *di = get_pcs_inode(r->req.args->io_inode);
	struct fuse_inode *fi = get_fuse_inode(r->req.args->io_inode);

	if (!kqueue_insert(di, &r->req))
		return -EIO;

	BUG_ON(r->req.in.h.opcode != FUSE_WRITE && r->req.in.h.opcode != FUSE_FALLOCATE);
	fuse_write_dio_begin(fi);

	wait_grow(r, di, offset + size);
	return 1;
}

/*
 * Check i size boundary and deffer request if necessary
 * Ret code
 * 0: ready for submission
 * -EIO: should fail request
 * -EPERM: Nope
 * 1: request placed to pended queue
*/
static int pcs_fuse_prep_rw(struct pcs_fuse_req *r)
{
	struct fuse_req *req = &r->req;
	struct fuse_args *args = req->args;
	struct fuse_io_args *ia = container_of(args, typeof(*ia), ap.args);
	struct pcs_dentry_info *di = get_pcs_inode(args->io_inode);
	struct fuse_inode *fi = get_fuse_inode(args->io_inode);
	int ret = 0;

	spin_lock(&di->lock);
	/* Deffer all requests if shrink requested to prevent livelock */
	if (di->size.op == PCS_SIZE_SHRINK) {
		wait_shrink(r, di);
		ret = 1;
		goto out;
	}

	switch (req->in.h.opcode) {
	case FUSE_READ: {
		size_t size;
		struct fuse_read_in *in = &ia->read.in;

		size = in->size;
		if (in->offset + in->size > di->fileinfo.attr.size) {
			if (in->offset >= di->fileinfo.attr.size) {
				args->out_args[0].size = 0;
				ret = -EPERM;
				goto out;
			}
			size = di->fileinfo.attr.size - in->offset;
		}

		pcs_fuse_prep_io(r, PCS_REQ_T_READ, in->offset, size, 0);
		break;
	}
	case FUSE_WRITE: {
		struct fuse_write_in *in = &ia->write.in;

		if (in->offset + in->size > di->fileinfo.attr.size) {
			pcs_fuse_prep_io(r, PCS_REQ_T_WRITE, in->offset,
					 in->size, 0);
			ret = req_wait_grow_queue(r, in->offset, in->size);
			goto out;
		}

		pcs_fuse_prep_io(r, PCS_REQ_T_WRITE, in->offset, in->size, 0);
		break;
	}
	case FUSE_IOCTL: {
		size_t size;
		struct fiemap const *in = args->in_args[1].value;
		struct fiemap *out = args->out_args[1].value;

		*out = *in;
		out->fm_mapped_extents = 0;

		size = in->fm_length;
		if (in->fm_start + size > di->fileinfo.attr.size) {
			if (in->fm_start >= di->fileinfo.attr.size) {
				ret = -EPERM;
				goto out;
			}
			size = di->fileinfo.attr.size - in->fm_start;
		}

		pcs_fuse_prep_io(r, PCS_REQ_T_FIEMAP, in->fm_start,
				 in->fm_extent_count*sizeof(struct fiemap_extent),
				 in->fm_extent_count);
		r->exec.io.req.size = size;
		break;
	}
	case FUSE_FALLOCATE: {
		struct fuse_fallocate_in const *in = args->in_args[0].value;
		u16 type = PCS_REQ_T_MAX;

		if (in->mode & FALLOC_FL_PUNCH_HOLE)
			type = PCS_REQ_T_WRITE_HOLE;
		else if (in->mode & FALLOC_FL_ZERO_RANGE)
			type = PCS_REQ_T_WRITE_ZERO;

		if (in->offset + in->length > di->fileinfo.attr.size) {
			if (type < PCS_REQ_T_MAX)
				pcs_fuse_prep_io(r, type, in->offset,
						 in->length, 0);
			else
				pcs_fuse_prep_fallocate(r);
			ret = req_wait_grow_queue(r, in->offset, in->length);
			goto out;
		}

		if (type < PCS_REQ_T_MAX) {
			pcs_fuse_prep_io(r, type, in->offset, in->length, 0);
		} else {
			ret = -EPERM; /* NOPE */
			goto out;
		}
		break;
	}
	case FUSE_FSYNC:
	case FUSE_FLUSH:
		pcs_fuse_prep_io(r, PCS_REQ_T_SYNC, 0, 0, 0);
		break;
	default:
		BUG();
	}

	if (!kqueue_insert(di, req))
		ret = -EIO;
	else if (req->in.h.opcode == FUSE_READ || req->in.h.opcode == FUSE_FSYNC || req->in.h.opcode == FUSE_FLUSH)
		fuse_read_dio_begin(fi);
	else
		fuse_write_dio_begin(fi);

out:
	spin_unlock(&di->lock);
	return ret;
}

static void pcs_fuse_submit(struct pcs_fuse_cluster *pfc, struct fuse_req *req)
{
	struct pcs_fuse_req *r = pcs_req_from_fuse(req);
	struct fuse_args *args = req->args;
	struct fuse_inode *fi = get_fuse_inode(args->io_inode);
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

	switch (req->in.h.opcode) {
	case FUSE_WRITE:
	case FUSE_READ:
	case FUSE_FSYNC:
	case FUSE_FLUSH:
		ret = pcs_fuse_prep_rw(r);
		if (likely(!ret))
			goto submit;
		if (ret > 0)
			return; /* Pended, nothing to do. */
		if (ret != -EPERM) {
			req->out.h.error = ret;
			goto error;
		}
		break;
	case FUSE_FALLOCATE: {
		struct fuse_fallocate_in *inarg = (void*) args->in_args[0].value;

		if (pfc->fc->no_fallocate) {
			req->out.h.error = -EOPNOTSUPP;
			goto error;
		}

		if (inarg->offset >= di->fileinfo.attr.size)
			inarg->mode &= ~FALLOC_FL_ZERO_RANGE;

		if (inarg->mode == FALLOC_FL_KEEP_SIZE)
			break; /* NOPE */

		WARN_ON_ONCE(!inode_is_locked(&fi->inode));
		if (inarg->mode & (FALLOC_FL_ZERO_RANGE|FALLOC_FL_PUNCH_HOLE)) {
			if ((inarg->offset & (PAGE_SIZE - 1)) || (inarg->length & (PAGE_SIZE - 1))) {
				req->out.h.error = -EINVAL;
				goto error;
			}
		}

		if (inarg->mode & FALLOC_FL_KEEP_SIZE) {
			if (inarg->offset > di->fileinfo.attr.size)
				break; /* NOPE */
			if (inarg->offset + inarg->length > di->fileinfo.attr.size)
				inarg->length = di->fileinfo.attr.size - inarg->offset;
		}

		ret = pcs_fuse_prep_rw(r);
		if (likely(!ret))
			goto submit;
		if (ret > 0)
			return; /* Pended, nothing to do. */
		if (ret != -EPERM) {
			req->out.h.error = ret;
			goto error;
		}
		break;
	}
	case FUSE_IOCTL:
		if (pfc->fc->no_fiemap) {
			req->out.h.error = -EOPNOTSUPP;
			goto error;
		}

		ret = pcs_fuse_prep_rw(r);
		if (likely(!ret))
			goto submit;
		if (ret > 0)
			return; /* Pended, nothing to do. */
		if (ret != -EPERM) {
			req->out.h.error = ret;
			goto error;
		}
		break;
	}
	req->out.h.error = 0;
error:
	DTRACE("do fuse_request_end req:%p op:%d err:%d\n", req, req->in.h.opcode, req->out.h.error);

	__fuse_request_end(req, false);
	return;

submit:
	ireq_process(ireq);
}

static void kpcs_setattr_end(struct fuse_mount *fm, struct fuse_args *args, int error)
{
	struct fuse_req *req = args->req;
	struct pcs_fuse_req *r = pcs_req_from_fuse(req);
	struct fuse_inode *fi = get_fuse_inode(args->io_inode);
	struct fuse_setattr_in *inarg = (void*) args->in_args[0].value;
	struct fuse_attr_out *outarg = (void*) args->out_args[0].value;
	struct pcs_dentry_info *di = pcs_inode_from_fuse(fi);

	BUG_ON(req->in.h.opcode != FUSE_SETATTR);
	TRACE("update size: ino:%lu old_sz:%lld new:%lld, error: %d\n",
	      args->io_inode->i_ino, di->fileinfo.attr.size, outarg->attr.size,
	      error);

	if (error)
		goto fail;

	if (outarg->attr.size == inarg->size)
		pcs_mapping_truncate(di, outarg->attr.size);
	else {
		pr_err("kio: failed to set requested size: %llu %llu\n",
			outarg->attr.size, inarg->size);
		error = req->out.h.error = -EIO;
	}

	spin_lock(&di->lock);
	di->fileinfo.attr.size = outarg->attr.size;
	spin_unlock(&di->lock);

fail:
	if(r->end)
		r->end(fm, args, error);
}

static void _pcs_shrink_end(struct fuse_mount *fm, struct fuse_args *args, int error)
{
	struct fuse_conn *fc = fm->fc;
	struct pcs_fuse_cluster *pfc = (struct pcs_fuse_cluster*)fc->kio.ctx;
	struct fuse_inode *fi = get_fuse_inode(args->io_inode);
	struct pcs_dentry_info *di = fi->private;
	LIST_HEAD(dispose);

	kpcs_setattr_end(fm, args, error);

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
		BUG_ON(r->req.in.h.opcode != FUSE_READ && r->req.in.h.opcode != FUSE_FSYNC && r->req.in.h.opcode != FUSE_FLUSH);

		TRACE("resubmit %p\n", &r->req);
		list_del_init(&ireq->list);
		pcs_fuse_submit(pfc, &r->req);
	}
}

static void _pcs_grow_end(struct fuse_mount *fm, struct fuse_args *args, int error)
{
	kpcs_setattr_end(fm, args, error);
}

static void pcs_kio_setattr_handle(struct fuse_inode *fi, struct fuse_req *req)
{
	struct fuse_args *args = req->args;
	struct pcs_fuse_req *r = pcs_req_from_fuse(req);
	struct fuse_setattr_in *inarg = (void*) args->in_args[0].value;
	struct pcs_dentry_info *di;

	BUG_ON(!fi);

	di = pcs_inode_from_fuse(fi);
	spin_lock(&di->lock);
	if (inarg->size < di->fileinfo.attr.size) {
		BUG_ON(di->size.op != PCS_SIZE_INACTION);
		di->size.op = PCS_SIZE_SHRINK;
	}
	spin_unlock(&di->lock);

	r->end = args->end;
	__set_bit(FR_ASYNC, &req->flags);
	if (di->size.op == PCS_SIZE_SHRINK) {
		BUG_ON(!inode_is_locked(args->io_inode));
		/* wait for aio reads in flight */
		fuse_dio_wait(fi);

		args->end = _pcs_shrink_end;
	} else
		args->end = _pcs_grow_end;
}

static int pcs_kio_classify_req(struct fuse_req *req, bool lk)
{
	struct fuse_conn *fc = req->fm->fc;
	struct fuse_args *args = req->args;
	struct fuse_inode *fi = get_fuse_inode(args->io_inode);

	if (test_bit(FR_KIO_INTERNAL, &req->flags))
		return 1;

	switch (req->in.h.opcode) {
	case FUSE_READ:
	case FUSE_WRITE:
	case FUSE_FSYNC:
	case FUSE_FLUSH:
	case FUSE_FALLOCATE:
		break;
	case FUSE_SETATTR: {
		struct fuse_setattr_in const *inarg = args->in_args[0].value;

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
		struct fuse_ioctl_in const *inarg = args->in_args[0].value;

		switch (inarg->cmd) {
			case FS_IOC_FIEMAP:
				break;
			case PCS_IOC_NOCSUMONREAD:
			case PCS_IOC_NOWRITEDELAY:
				return -EOPNOTSUPP;
			case PCS_IOC_INIT_KDIRECT:
			case PCS_IOC_GETFILEINFO:
			case PCS_IOC_KDIRECT_CLAIM:
			case PCS_IOC_KDIRECT_RELEASE:
			case PCS_IOC_GETMAP:
				return -EPERM;
			default:
				return 1;
		}
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

static int kpcs_req_classify(struct fuse_req *req, bool bg, bool lk)
{
	struct fuse_conn* fc = req->fm->fc;
	struct pcs_fuse_cluster *pfc = (struct pcs_fuse_cluster*)fc->kio.ctx;
	int ret;

	if (!fc->initialized || fc->conn_error)
		return 1;

	BUG_ON(!pfc);
	DTRACE("Classify req:%p op:%d end:%p bg:%d lk:%d\n", req, req->in.h.opcode,
							  req->args->end, bg, lk);
	ret = pcs_kio_classify_req(req, lk);
	if (likely(!ret))
		return 0;

	if (ret < 0) {
		if (!bg)
			refcount_inc(&req->count);
		__clear_bit(FR_PENDING, &req->flags);
		req->out.h.error = ret;
		if (lk)
			spin_unlock(&fc->bg_lock);
		__fuse_request_end(req, false);
		if (lk)
			spin_lock(&fc->bg_lock);
		return ret;
	}
	return 1;
}

static void kpcs_req_send(struct fuse_req *req, bool bg)
{
	struct fuse_conn *fc = req->fm->fc;
	struct pcs_fuse_cluster *pfc = (struct pcs_fuse_cluster*)fc->kio.ctx;

	/* At this point request can not belongs to any list
	 * so we can avoid grab fc->lock here at all.
	 */
	BUG_ON(!list_empty(&req->list));

	TRACE("Send req:%p op:%d end:%p bg:%d\n",
		req, req->in.h.opcode, req->args->end, bg);

	/* __request_end below will do fuse_put_request() */
	if (!bg)
		refcount_inc(&req->count);
	__clear_bit(FR_PENDING, &req->flags);

	pcs_fuse_submit(pfc, req);
	if (!bg)
		wait_event(req->waitq,
			   test_bit(FR_FINISHED, &req->flags) && !req->args->end);
	return;
}

static void fuse_trace_free(struct fuse_ktrace *tr)
{
	relay_close(tr->rchan);
	free_percpu(tr->ovfl);
	if (tr->prometheus_dentry) {
		debugfs_remove(tr->prometheus_dentry);
	}
	if (tr->prometheus_metrics)
		free_percpu(tr->prometheus_metrics);
	free_percpu(tr->buf);
	debugfs_remove(tr->dir);
	if (tr->fc)
		fuse_conn_put(tr->fc);
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

void fuse_stat_observe(struct fuse_conn *fc, int op, ktime_t val)
{
	struct fuse_ktrace * tr = fc->ktrace;

	BUG_ON(op >= KFUSE_HISTOGRAM_MAX);

	if (tr) {
		struct kfuse_metrics *metrics;
		int cpu;

		cpu = get_cpu();
		metrics = per_cpu_ptr(tr->prometheus_metrics, cpu);
		if (metrics) {
			struct kfuse_histogram *rec = &metrics->hists[op];
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

void fuse_stat_account(struct fuse_conn *fc, int op, u64 val)
{
	struct fuse_ktrace *tr = fc->ktrace;

	BUG_ON(op >= KFUSE_OP_MAX);

	if (tr) {
		struct kfuse_metrics *metrics;
		int cpu;

		cpu = get_cpu();
		metrics = per_cpu_ptr(tr->prometheus_metrics, cpu);
		if (metrics) {
			struct kfuse_counter *cnt = &metrics->cnts[op];
			cnt->val_total += val;
			++cnt->events;
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

static void prometheus_req_iter(struct fuse_file *ff, struct fuse_req *req,
				void *ctx)
{
	struct kfuse_metrics *stats = ctx;
	struct pcs_fuse_req *r = pcs_req_from_fuse(req);
	struct pcs_int_request *ireq = &r->exec.ireq;
	s64 duration;

	duration = ktime_to_ms(ktime_sub(ktime_get(), ireq->ts));

	if (duration >= 8 * MSEC_PER_SEC)
		stats->stucked_reqs_cnt_8s++;
	if (duration >= 30 * MSEC_PER_SEC)
		stats->stucked_reqs_cnt_30s++;
	if (duration >= 120 * MSEC_PER_SEC)
		stats->stucked_reqs_cnt_120s++;
}

/* NOTE: old versions of userspace could read only histograms */
static ssize_t prometheus_file_read(struct file *filp,
				    char __user *buffer,
				    size_t count,
				    loff_t *ppos)
{
	struct fuse_ktrace *tr = filp->private_data;
	struct kfuse_metrics *stats;
	int cpu;

	if (*ppos >= sizeof(struct kfuse_metrics))
		return 0;
	if (*ppos + count > sizeof(struct kfuse_metrics))
		count = sizeof(struct kfuse_metrics) - *ppos;

	stats = (void *)get_zeroed_page(GFP_KERNEL);
	BUILD_BUG_ON(sizeof(*stats) > PAGE_SIZE);
	if (!stats)
		return -ENOMEM;

	if (!tr->prometheus_metrics)
		return -EINVAL;

	for_each_possible_cpu(cpu) {
		struct kfuse_metrics *m;

		m = per_cpu_ptr(tr->prometheus_metrics, cpu);
		if (m) {
			int i, k;
			/* aggregate histograms from each cpu */
			for (i = 0; i < KFUSE_HISTOGRAM_MAX; i++) {
				for (k = 0; k < KFUSE_PROM_MAX; k++) {
					stats->hists[i].buckets[k] += m->hists[i].buckets[k];
				}
				stats->hists[i].sum += m->hists[i].sum;
			}

			/* aggregate counters from each cpu */
			for (i = 0; i < KFUSE_OP_MAX; i++) {
				stats->cnts[i].events += m->cnts[i].events;
				stats->cnts[i].val_total += m->cnts[i].val_total;
			}
		}
	}

	spin_lock(&tr->fc->lock);
	pcs_kio_req_list(tr->fc, prometheus_req_iter, stats);
	spin_unlock(&tr->fc->lock);

	if (copy_to_user(buffer, (char *)stats + *ppos, count))
		count = -EFAULT;
	else
		*ppos += count;

	free_page((unsigned long)stats);
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
	struct kfuse_metrics __percpu * metrics;
	int cpu;
	char name[16];

	if (!fuse_trace_root)
		return -ENOENT;

	tr = kzalloc(sizeof(*tr), GFP_KERNEL);
	if (!tr)
		return -ENOMEM;

	tr->fc = fuse_conn_get(fc);

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

	ret = -ENOMEM;

	metrics = alloc_percpu(struct kfuse_metrics);
	if (!metrics)
		goto err;
	for_each_possible_cpu(cpu) {
		struct kfuse_metrics *m;
		m = per_cpu_ptr(metrics, cpu);
		memset(m, 0, sizeof(*m));
	}
	tr->prometheus_metrics = metrics;

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
		if (unlikely(debugfs_tracing)) {
			if (ip)
				__trace_puts(ip, buf, len);
			else
				pr_debug("%s\n", buf);
		}
	}
	put_cpu();
}

void pcs_kio_file_list(struct fuse_conn *fc, kio_file_itr kfile_cb, void *ctx)
{
	struct fuse_file *ff;

	assert_spin_locked(&fc->lock);

	list_for_each_entry(ff, &fc->conn_files, fl) {
		struct pcs_dentry_info *di;
		struct fuse_inode *fi;

		if (!ff->ff_dentry)
			continue;

		fi = get_fuse_inode(ff->ff_dentry->d_inode);
		if (!fi->private)
			continue;

		di = pcs_inode_from_fuse(fi);
		kfile_cb(ff, di, ctx);
	}
}

struct kreq_list_ctx {
	kio_req_itr cb;
	void *ctx;
};

static void kpcs_req_list_itr(struct fuse_file *ff, struct pcs_dentry_info *di,
			      void *ctx)
{
	struct fuse_req *req;
	struct kreq_list_ctx *kreq_ctx = ctx;

	spin_lock(&di->kq_lock);
	list_for_each_entry(req, &di->kq, list) {
		kreq_ctx->cb(ff, req, kreq_ctx->ctx);
	}
	spin_unlock(&di->kq_lock);
}

void pcs_kio_req_list(struct fuse_conn *fc, kio_req_itr kreq_cb, void *ctx)
{
	struct kreq_list_ctx kreq_ctx = {
		.cb = kreq_cb,
		.ctx = ctx,
	};
	pcs_kio_file_list(fc, kpcs_req_list_itr, &kreq_ctx);
}

static void kpcs_kill_lreq_itr(struct fuse_file *ff, struct pcs_dentry_info *di,
			       void *ctx)
{
	struct inode *inode = ctx;

	spin_lock(&di->kq_lock);
	fuse_kill_requests(ff->fm->fc, inode, &di->kq);
	spin_unlock(&di->kq_lock);
}

static void kpcs_kill_requests(struct fuse_conn *fc, struct inode *inode)
{
	pcs_kio_file_list(fc, kpcs_kill_lreq_itr, inode);
}

static struct fuse_kio_ops kio_pcs_ops = {
	.name		= "pcs",
	.owner		= THIS_MODULE,
	.probe		= kpcs_probe,

	.conn_init	= kpcs_conn_init,
	.conn_fini	= kpcs_conn_fini,
	.conn_abort	= kpcs_conn_abort,
	.req_alloc	= kpcs_req_alloc,
	.req_classify	= kpcs_req_classify,
	.req_send	= kpcs_req_send,
	.file_open	= kpcs_file_open,
	.file_close	= kpcs_file_close,
	.inode_release	= kpcs_inode_release,
	.kill_requests	= kpcs_kill_requests,
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

	pcs_cleanup_wq = alloc_workqueue("pcs_cleanup_wq", WQ_MEM_RECLAIM, 0);
	if (!pcs_cleanup_wq)
		goto free_wq;

	fast_path_version = PCS_FAST_PATH_VERSION.full;

	if (fuse_register_kio(&kio_pcs_ops))
		goto free_cleanup_wq;

	fuse_trace_root = debugfs_create_dir("fuse", NULL);

	printk("%s fuse_c:%p ireq_c:%p pcs_wq:%p\n", __FUNCTION__,
	       pcs_fuse_req_cachep, pcs_ireq_cachep, pcs_wq);

	return 0;
free_cleanup_wq:
	destroy_workqueue(pcs_cleanup_wq);
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
	destroy_workqueue(pcs_cleanup_wq);
	destroy_workqueue(pcs_wq);
	kmem_cache_destroy(pcs_map_cachep);
	kmem_cache_destroy(pcs_ireq_cachep);
	kmem_cache_destroy(pcs_fuse_req_cachep);
}

module_init(kpcs_mod_init);
module_exit(kpcs_mod_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Virtuozzo <devel@openvz.org>");
