#include <net/sock.h>
#include <linux/types.h>

#include "pcs_req.h"
#include "fuse_stat.h"
#include "pcs_cluster.h"

extern struct super_block *fuse_control_sb;


static inline void fuse_val_stat_update(struct fuse_val_stat *s, u64 val)
{
	if (!s->events)
		s->val_min = s->val_max = val;
	else if (val < s->val_min)
		s->val_min = val;
	else if (val > s->val_max)
		s->val_max = val;
	s->val_total += val;
	++s->events;
}

static inline void fuse_val_cnt_up(struct fuse_val_cnt *c)
{
	if (!c->glob.events) {
		c->glob = c->curr;
	} else {
		c->glob.val_min   = min(c->curr.val_min, c->glob.val_min);
		c->glob.val_max   = max(c->curr.val_max, c->glob.val_max);
		c->glob.val_total = c->curr.val_total + c->glob.val_total;
		c->glob.events    = c->curr.events + c->glob.events;
	}
	c->last = c->curr;
	memset(&c->curr, 0, sizeof(c->curr));
}

static inline unsigned long long fuse_evt_rate(struct fuse_val_stat const* s, unsigned period)
{
	return DIV_ROUND_UP(s->events, period);
}

static inline unsigned long long fuse_val_rate(struct fuse_val_stat const* s, unsigned period)
{
	return DIV_ROUND_UP(s->val_total, period);
}

static inline unsigned long long fuse_val_aver(struct fuse_val_stat const* s)
{
	return s->events ? s->val_total / s->events : 0;
}

static inline unsigned long long fuse_val_cnt_total(struct fuse_val_cnt const* c)
{
	return c->curr.val_total + c->glob.val_total;
}

static inline unsigned long long fuse_val_cnt_events(struct fuse_val_cnt const* c)
{
	return c->curr.events + c->glob.events;
}

#define EVT_RATE(s)   fuse_evt_rate(&(s), STAT_TIMER_PERIOD)
#define VAL_RATE(s)   fuse_val_rate(&(s), STAT_TIMER_PERIOD)
#define VAL_AVER(s)   fuse_val_aver(&(s))
#define CNT_TOTAL(c)  fuse_val_cnt_total(&(c))
#define CNT_EVENTS(c) fuse_val_cnt_events(&(c))

static int pcs_fuse_iostat_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct pcs_fuse_stat *stat;
	struct pcs_fuse_io_stat io_stat;

	if (!inode)
		return 0;

	mutex_lock(&fuse_mutex);
	stat = inode->i_private;
	if (!stat) {
		mutex_unlock(&fuse_mutex);
		return 0;
	}

	seq_printf(m, "# operation  ops/sec  bytes/sec   total            req_min req_avg req_max (bytes)\n");

	spin_lock(&stat->lock);
	io_stat = stat->io;
	spin_unlock(&stat->lock);

	seq_printf(m, "read         %-8llu %-11llu %-16llu %-6llu  %-6llu  %-6llu\n",
		   EVT_RATE(io_stat.read_bytes.last), VAL_RATE(io_stat.read_bytes.last),
		   CNT_TOTAL(io_stat.read_bytes), io_stat.read_bytes.last.val_min,
		   VAL_AVER(io_stat.read_bytes.last), io_stat.read_bytes.last.val_max);
	seq_printf(m, "write        %-8llu %-11llu %-16llu %-6llu  %-6llu  %-6llu\n",
		   EVT_RATE(io_stat.write_bytes.last), VAL_RATE(io_stat.write_bytes.last),
		   CNT_TOTAL(io_stat.write_bytes), io_stat.write_bytes.last.val_min,
		   VAL_AVER(io_stat.write_bytes.last), io_stat.write_bytes.last.val_max);
	seq_printf(m, "sync         %-8llu             %-16llu\n",
		   EVT_RATE(io_stat.flush_cnt.last), CNT_EVENTS(io_stat.flush_cnt));
	mutex_unlock(&fuse_mutex);

	return 0;
}

static int pcs_fuse_iostat_open(struct inode *inode, struct file *file)
{
	return single_open(file, pcs_fuse_iostat_show, inode);
}

static const struct file_operations pcs_fuse_iostat_ops = {
	.owner   = THIS_MODULE,
	.open    = pcs_fuse_iostat_open,
	.read    = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static inline
struct fuse_val_cnt *req_stat_entry(struct pcs_fuse_io_stat *io, u32 type)
{
	switch (type) {
		case PCS_CS_READ_RESP:
			return &io->read_bytes;
		case PCS_CS_WRITE_SYNC_RESP:
		case PCS_CS_WRITE_RESP:
			return &io->write_bytes;
		case PCS_CS_SYNC_RESP:
			return &io->flush_cnt;
		default:
			break;
	}
	WARN_ON_ONCE(1);
	return NULL;
}

void pcs_fuse_stat_io_count(struct pcs_int_request *ireq, struct pcs_msg *resp)
{
	struct pcs_cluster_core *cc = ireq->cc;
	struct pcs_fuse_stat *stat = &cc->stat;
	struct pcs_cs_iohdr *h = (struct pcs_cs_iohdr *)msg_inline_head(resp);
	struct fuse_val_cnt *se = req_stat_entry(&stat->io, h->hdr.type);
	u64 size = h->hdr.type != PCS_CS_SYNC_RESP ? ireq->iochunk.size : 0;

	if (unlikely(!se))
		return;

	spin_lock(&stat->lock);
	fuse_val_stat_update(&se->curr, size);
	spin_unlock(&stat->lock);
}

static void pcs_fuse_stat_work(struct work_struct *w)
{
	struct pcs_cluster_core *cc =
		container_of(w, struct pcs_cluster_core, stat.work.work);
	struct pcs_fuse_stat *stat = &cc->stat;

	spin_lock(&stat->lock);
	fuse_val_cnt_up(&stat->io.read_bytes);
	fuse_val_cnt_up(&stat->io.write_bytes);
	fuse_val_cnt_up(&stat->io.flush_cnt);
	spin_unlock(&stat->lock);

	mod_delayed_work(cc->wq, &cc->stat.work, STAT_TIMER_PERIOD * HZ);
}

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
	struct pcs_cluster_core *cc =
		container_of(stat, struct pcs_cluster_core, stat);
	struct fuse_conn *fc = container_of(cc,struct pcs_fuse_cluster, cc)->fc;

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

	memset(&stat->io.read_bytes, 0, sizeof(stat->io.read_bytes));
	memset(&stat->io.write_bytes, 0, sizeof(stat->io.write_bytes));
	memset(&stat->io.flush_cnt, 0, sizeof(stat->io.flush_cnt));

	spin_lock_init(&stat->lock);
	INIT_DELAYED_WORK(&stat->work, pcs_fuse_stat_work);
	mod_delayed_work(cc->wq, &stat->work, STAT_TIMER_PERIOD * HZ);

	stat->iostat = fuse_kio_add_dentry(stat->kio_stat, fc, "iostat",
					   S_IFREG | S_IRUSR, 1, NULL,
					   &pcs_fuse_iostat_ops, stat);

out:
	mutex_unlock(&fuse_mutex);
}

void pcs_fuse_stat_fini(struct pcs_fuse_stat *stat)
{
	if (!stat->kio_stat)
		return;

	mutex_lock(&fuse_mutex);
	if (fuse_control_sb) {
		if (stat->iostat)
			fuse_kio_rm_dentry(stat->iostat);
		fuse_kio_rm_dentry(stat->kio_stat);
	}
	mutex_unlock(&fuse_mutex);

	cancel_delayed_work_sync(&stat->work);
}
