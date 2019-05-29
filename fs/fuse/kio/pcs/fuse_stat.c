#include <net/sock.h>
#include <linux/types.h>

#include "fuse_stat.h"
#include "pcs_cluster.h"

extern struct super_block *fuse_control_sb;

static struct dentry *fuse_kio_add_dentry(struct dentry *parent,
					  struct fuse_conn *fc,
					  const char *name,
					  int mode, int nlink,
					  const struct inode_operations *iop,
					  const struct file_operations *fop,
					  void *ctx)
{
	struct inode *inode;
	struct dentry *dentry = d_alloc_name(parent, name);

	if (!dentry)
		return NULL;

	inode = new_inode(fc->sb);
	if (!inode) {
		dput(dentry);
		return NULL;
	}

	inode->i_ino = get_next_ino();
	inode->i_mode = mode;
	inode->i_uid = fc->user_id;
	inode->i_gid = fc->group_id;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	if (iop)
		inode->i_op = iop;
	inode->i_fop = fop;
	set_nlink(inode, nlink);
	inode->i_private = ctx;
	d_add(dentry, inode);

	return dentry;
}

static void fuse_kio_rm_dentry(struct dentry *dentry)
{
	d_inode(dentry)->i_private = NULL;
	d_drop(dentry);
	dput(dentry);
}

void pcs_fuse_stat_init(struct pcs_fuse_stat *stat)
{
	struct fuse_conn *fc =
		container_of(stat, struct pcs_fuse_cluster, cc.stat)->fc;

	mutex_lock(&fuse_mutex);
	if (!fuse_control_sb)
		goto out;

	stat->kio_stat = fuse_kio_add_dentry(fc->conn_ctl, fc, "kio_stat",
					     S_IFDIR | S_IXUSR, 2,
					     &simple_dir_inode_operations,
					     &simple_dir_operations, fc);
	if (!stat->kio_stat) {
		pr_err("kio: can't create kio stat directory");
		goto out;
	}

	/* Stat initialize */
out:
	mutex_unlock(&fuse_mutex);
}

void pcs_fuse_stat_fini(struct pcs_fuse_stat *stat)
{
	if (!stat->kio_stat)
		return;

	mutex_lock(&fuse_mutex);
	if (fuse_control_sb)
		fuse_kio_rm_dentry(stat->kio_stat);
	mutex_unlock(&fuse_mutex);
}
