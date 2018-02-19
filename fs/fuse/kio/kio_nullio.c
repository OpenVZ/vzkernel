#include <linux/module.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>

#include "../fuse_i.h"

static struct fuse_kio_ops nullio_ops;
static struct kmem_cache *nullio_req_cachep;

struct nullio_req {
	struct fuse_req req;
	char payload[0];
};

static inline struct nullio_req *nullreq_from_fuse(struct fuse_req *req)
{
	return container_of(req, struct nullio_req, req);
}

static int fake_read = 1;
static int fake_write = 0;
static unsigned int payload_sz = 0;

module_param(fake_read, int, S_IRUGO);
MODULE_PARM_DESC(fake_read, "Fake read request (0=off, 1=on, default on)");

module_param(fake_write, int, S_IRUGO);
MODULE_PARM_DESC(fake_write, "Fake write request (0=off, 1=on, default off)");

module_param(payload_sz, uint, S_IRUGO);
MODULE_PARM_DESC(payload_sz, "Payload size for added to fuse_req, default 0");

/* Conn hooks */
static int nullio_probe(struct fuse_conn *fc, char *name)
{
	if (!strncmp(name, nullio_ops.name, FUSE_KIO_NAME))
		return 1;

	return 0;
}

static int nullio_conn_init(struct fuse_conn *fc)
{
	/* Just for sanity checks */
	fc->kio.ctx = nullio_req_cachep;
	pr_debug("nullio_conn_init\n");

	/*This one is mandatary */
	fuse_set_initialized(fc);
	wake_up_all(&fc->blocked_waitq);

	return 0;
}

static void nullio_conn_fini(struct fuse_conn *fc)
{
	BUG_ON(fc->kio.ctx != nullio_req_cachep);
	pr_debug("nullio_conn_fini\n");

}

static void nullio_conn_abort(struct fuse_conn *fc)
{
	BUG_ON(fc->kio.ctx != nullio_req_cachep);
	pr_debug("nullio_conn_abort\n");
}

/* Request hooks */
static struct fuse_req *nullio_req_alloc(struct fuse_conn *fc, unsigned npages,
					 gfp_t flags)
{
	struct nullio_req *r;
	struct fuse_req *req;

	req = fuse_generic_request_alloc(fc, nullio_req_cachep, npages, flags);
	r = nullreq_from_fuse(req);
	memset(r->payload, 0, payload_sz);
	return req;
}

static int nullio_req_send(struct fuse_conn *fc, struct fuse_req *req, bool bg,
			   bool locked)
{
	/* pass though all requests on uninitalized connection */
	if (!fc->initialized)
		return 1;

	BUG_ON(fc->kio.ctx != nullio_req_cachep);
	BUG_ON(req->cache != nullio_req_cachep);
	switch (req->in.h.opcode) {
	case FUSE_WRITE: {
		struct fuse_write_in *in = &req->misc.write.in;
		struct fuse_write_out *out = &req->misc.write.out;

		if (!fake_write)
			return 1;
		/* Fake complete */
		out->size = in->size;
		break;
	}
	case FUSE_READ: {
		if (!fake_read)
			return 1;
		break;
	}
	default:
		/* fall back to generic fuse io-flow */
		return 1;
	}
	/* Simulate immidiate completion path. */
	__clear_bit(FR_BACKGROUND, &req->flags);
	__clear_bit(FR_PENDING, &req->flags);
	/* request_end below will do fuse_put_request() */
	if (!bg)
		atomic_inc(&req->count);

	/* Finally complete */
	req->out.h.error = 0;
	request_end(fc, req);
	return 0;
}

/* Inode scope hooks */
static int nullio_file_open(struct fuse_conn *fc, struct file *file,
			    struct inode *inode)
{
	BUG_ON(fc->kio.ctx != nullio_req_cachep);

	if (S_ISREG(inode->i_mode)) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		fi->private  = nullio_req_cachep;
	}
	return 0;
}

static void nullio_inode_release(struct fuse_inode *fi)
{
	if (!fi->private)
		return;

	BUG_ON(fi->private != nullio_req_cachep);
}

static struct fuse_kio_ops nullio_ops = {
	.name		= "nullio",
	.owner		= THIS_MODULE,
	.probe		= nullio_probe,

	.conn_init	= nullio_conn_init,
	.conn_fini	= nullio_conn_fini,
	.conn_abort	= nullio_conn_abort,
	.req_alloc	= nullio_req_alloc,
	.req_send	= nullio_req_send,
	.file_open	= nullio_file_open,
	.inode_release	= nullio_inode_release,
};

static int __init kio_nullio_mod_init(void)
{
	int err;

	nullio_req_cachep = kmem_cache_create("nullio_fuse_request",
					      sizeof(struct fuse_req) +
					      payload_sz,
					      0, 0, NULL);
	if (!nullio_req_cachep)
		return -ENOMEM;

	err = -EINVAL;
	if (fuse_register_kio(&nullio_ops))
		goto free_cache;

	return 0;

free_cache:
	kmem_cache_destroy(nullio_req_cachep);
	return err;
}

static void __exit kio_nullio_mod_exit(void)
{
	fuse_unregister_kio(&nullio_ops);
	kmem_cache_destroy(nullio_req_cachep);
}

module_init(kio_nullio_mod_init);
module_exit(kio_nullio_mod_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Virtuozzo <devel@openvz.org>");
