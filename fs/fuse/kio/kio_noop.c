#include <linux/module.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/printk.h>

#include "../fuse_i.h"

static struct fuse_kio_ops noop_ops;
static struct kmem_cache *noop_req_cachep;

/* Conn hooks */

static int noop_probe(struct fuse_conn *fc, char *name)
{
	if (!strncmp(name, noop_ops.name, FUSE_KIO_NAME))
		return 1;

	return 0;
}

static int noop_conn_init(struct fuse_conn *fc)
{
	/* Just for sanity checks */
	fc->kio.ctx = noop_req_cachep;
	pr_debug("fuse_kio_noop: init");

	/*This one is mandatary */
	fuse_set_initialized(fc);
	wake_up_all(&fc->blocked_waitq);

	return 0;
}

static void noop_conn_fini(struct fuse_conn *fc)
{
	BUG_ON(fc->kio.ctx != noop_req_cachep);
	pr_debug("fuse_kio_noop: fini");

}

static void noop_conn_abort(struct fuse_conn *fc)
{
	BUG_ON(fc->kio.ctx != noop_req_cachep);
	pr_debug("fuse_kio_noop: abort");
}

/* Request hooks */
static struct fuse_req *noop_req_alloc(struct fuse_conn *fc, unsigned npages,
				       gfp_t flags)
{
	return fuse_generic_request_alloc(fc, noop_req_cachep, npages, flags);
}

static int noop_req_send(struct fuse_conn *fc, struct fuse_req *req, bool bg,
			 bool locked)
{
	/* Do not intercept request for unconnected channel */
	if (!fc->initialized)
		return 1;

	BUG_ON(fc->kio.ctx != noop_req_cachep);
	BUG_ON(req->cache != noop_req_cachep);

	/* fall back to generic fuse io-flow */
	return 1;
}

/* Optional inode scope hooks
static int noop_file_open(struct fuse_conn *fc, struct file *file,
			  struct inode *inode)
{
	return 0;
}

static void noop_inode_release(struct fuse_inode *fi)
{
}
*/

static struct fuse_kio_ops noop_ops = {
	.name		= "noop",
	.owner		= THIS_MODULE,
	.probe		= noop_probe,

	.conn_init	= noop_conn_init,
	.conn_fini	= noop_conn_fini,
	.conn_abort	= noop_conn_abort,
	.req_alloc	= noop_req_alloc,
	.req_send	= noop_req_send,
	/* Optional inode state hooks
	 *.file_open	= noop_file_open,
	 *.inode_release= noop_inode_release,
	 */
};

static int __init kio_noop_mod_init(void)
{
	int err;

	noop_req_cachep = kmem_cache_create("noop_fuse_request",
					    sizeof(struct fuse_req),
					    0, 0, NULL);
	if (!noop_req_cachep)
		return -ENOMEM;

	err = -EINVAL;
	if (fuse_register_kio(&noop_ops))
		goto free_cache;

	return 0;

free_cache:
	kmem_cache_destroy(noop_req_cachep);
	return err;
}

static void __exit kio_noop_mod_exit(void)
{
	fuse_unregister_kio(&noop_ops);
	kmem_cache_destroy(noop_req_cachep);
}

module_init(kio_noop_mod_init);
module_exit(kio_noop_mod_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Virtuozzo <devel@openvz.org>");
