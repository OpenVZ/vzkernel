#include <net/sock.h>
#include <linux/types.h>

#include "pcs_req.h"
#include "fuse_stat.h"
#include "pcs_cluster.h"

extern struct super_block *fuse_control_sb;

static u64 lat_oreder_list[] = {
	[LAT_ORDER1] = 20 * USEC_PER_MSEC,
	[LAT_ORDER2] = 50 * USEC_PER_MSEC,
	[LAT_ORDER3] = 100 * USEC_PER_MSEC,
	[LAT_ORDER4] = 200 * USEC_PER_MSEC,
	[LAT_ORDER5] = 500 * USEC_PER_MSEC,
};


static void fuse_latency_update(struct fuse_lat_stat *s, u64 lat)
{
	int i;

	s->count++;

	for (i = LAT_ORDER1; i <= LAT_ORDER5; i++) {
		if (likely(lat <= lat_oreder_list[i])) {
			s->lat[i]++;
			return;
		}
	}
	s->lat[LAT_ORDER_OTHER]++;
	return;
}

static inline void fuse_latency_count(struct fuse_lat_cnt *c, u64 val)
{
	fuse_latency_update(&c->curr, val);
	fuse_latency_update(&c->glob, val);
}

static inline void fuse_latency_cnt_up(struct fuse_lat_cnt *c)
{
	BUILD_BUG_ON(sizeof(c->last) != sizeof(c->curr));

	memcpy(&c->last, &c->curr, sizeof(c->last));
	memset(&c->curr, 0, sizeof(c->curr));
}

static const char *fuse_kio_op_name(unsigned opcode)
{
	switch (opcode) {
		case FUSE_READ:
			return "READ";
		case FUSE_WRITE:
			return "WRITE";
		case FUSE_FSYNC:
			return "FSYNC";
		case FUSE_FLUSH:
			return "FLUSH";
		case FUSE_FALLOCATE:
			return "FALLOCATE";
		default:
			break;
	}
	return "UNKNOWN";
}

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
static inline unsigned long long fuse_val_cnt_min(struct fuse_val_cnt const* c)
{
	return min(c->curr.val_min, c->glob.val_min);
}

static inline unsigned long long fuse_val_cnt_max(struct fuse_val_cnt const* c)
{
	return max(c->curr.val_max, c->glob.val_max);
}

#define EVT_RATE(s)   fuse_evt_rate(&(s), STAT_TIMER_PERIOD)
#define VAL_RATE(s)   fuse_val_rate(&(s), STAT_TIMER_PERIOD)
#define VAL_AVER(s)   fuse_val_aver(&(s))
#define CNT_TOTAL(c)  fuse_val_cnt_total(&(c))
#define CNT_EVENTS(c) fuse_val_cnt_events(&(c))
#define CNT_MIN(c)    fuse_val_cnt_min(&(c))
#define CNT_MAX(c)    fuse_val_cnt_max(&(c))

static int do_show_cs_stats(struct pcs_cs *cs, void *ctx)
{
	struct seq_file *m = ctx;
	int rpc_state = cs->rpc ? cs->rpc->state : PCS_RPC_UNCONN;
	unsigned int in_flight_avg = cs_get_avg_in_flight_lock(cs);
	struct pcs_perf_stat_cnt iolat, netlat;
	struct pcs_perf_rate_cnt read_ops_rate, write_ops_rate, sync_ops_rate;

	spin_lock(&cs->stat.lock);
	iolat = cs->stat.iolat;
	netlat = cs->stat.netlat;
	read_ops_rate = cs->stat.read_ops_rate;
	write_ops_rate = cs->stat.write_ops_rate;
	sync_ops_rate = cs->stat.sync_ops_rate;
	spin_unlock(&cs->stat.lock);

	seq_printf(m, "%-10llu %d=%-8s %-10llu %-10llu %-10llu %-12llu %-12llu %-12llu %-12llu %-10u\n",
		NODE_ARGS(cs->id), rpc_state, pcs_rpc_state_name(rpc_state),
		read_ops_rate.rate / STAT_TIMER_PERIOD,
		write_ops_rate.rate / STAT_TIMER_PERIOD,
		sync_ops_rate.rate / STAT_TIMER_PERIOD,
		netlat.avg, pcs_perfcounter_stat_max(&netlat),
		iolat.avg, pcs_perfcounter_stat_max(&iolat),
		in_flight_avg);
	return 0;
}

static int pcs_fuse_cs_stats_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct pcs_cluster_core *cc;
	struct pcs_fuse_stat *stat;

	if (!inode)
		return 0;

	mutex_lock(&fuse_mutex);
	stat = inode->i_private;
	if (!stat) {
		mutex_unlock(&fuse_mutex);
		return 0;
	}

	seq_printf(m, "# csid     rpc        rd_ops     wr_ops     sync_ops   net_lat_avg  net_lat_max  io_lat_avg   io_lat_max   avg_in_flight\n");

	cc = container_of(stat, struct pcs_cluster_core, stat);
	pcs_cs_for_each_entry(&cc->css, do_show_cs_stats, m);

	mutex_unlock(&fuse_mutex);

	return 0;
}

static int pcs_fuse_cs_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, pcs_fuse_cs_stats_show, inode);
}

static const struct file_operations pcs_fuse_cs_stats_ops = {
	.owner   = THIS_MODULE,
	.open    = pcs_fuse_cs_stats_open,
	.read    = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

#define MAX_PERCENT 100
static int latency_npercl_format(struct fuse_lat_stat *s, u8 percl, char *buf,
				 size_t sz)
{
	u64 cnt = s->count, nper;
	int i;

	BUG_ON(percl > MAX_PERCENT);

	if (!cnt)
		return 0;

	nper = cnt * (MAX_PERCENT - percl);
	if (s->lat[LAT_ORDER_OTHER] * MAX_PERCENT >= nper)
		return scnprintf(buf, sz, "%u%% > %llums", MAX_PERCENT - percl,
				 lat_oreder_list[LAT_ORDER_OTHER - 1] / 1000);

	for(i = LAT_ORDER_OTHER - 1; i >= 0; i--) {
		if (s->lat[i] * MAX_PERCENT >= nper)
			return scnprintf(buf, sz, "%u%% <= %llums", percl,
					 lat_oreder_list[i] / 1000);
	}
	BUG();
	return 0;
}

#define LAT_LINE_MAX 27
static void latency_percl_print(struct fuse_lat_stat *s, struct seq_file *m)
{
	int n, icnt = LAT_LINE_MAX;
	char buf[LAT_LINE_MAX];

	seq_printf(m, "(");
	n = latency_npercl_format(s, 95, buf, sizeof(buf) - 1);
	if (n) {
		seq_printf(m,"%.*s, ", n, buf);
		icnt -= n;
		icnt -= 2;
	}
	n = latency_npercl_format(s, 99, buf, sizeof(buf) - 1);
	if (n) {
		seq_printf(m, "%.*s", n, buf);
		icnt -= n;
	}

	WARN_ON(icnt < 0);
	seq_printf(m, ")%*s", max(icnt, 0), "");
}

static void fuse_kio_fstat_lat_itr(struct fuse_file *ff,
				   struct pcs_dentry_info *di, void *ctx)
{
	struct seq_file *m = ctx;
	struct fuse_io_cnt *fstat = &di->stat;
	umode_t mode = di->inode->inode.i_mode;
	abs_time_t now = jiffies;
	struct fuse_lat_cnt io_lat;
	struct fuse_lat_cnt net_lat;
	struct fuse_lat_cnt pending_lat;

	seq_printf(m, "%s%s %7u/%-7llu %-5u",
		   mode & S_IRUGO ? "r": "", mode & S_IWUGO ? "w": "",
		   atomic_read(&ff->count), (now - di->stat.created_ts) / 1000, 0);

	spin_lock(&fstat->lock);
	io_lat = fstat->io_lat;
	net_lat = fstat->net_lat;
	pending_lat = fstat->pending_lat;
	spin_unlock(&fstat->lock);

	latency_percl_print(&net_lat.last, m);
	latency_percl_print(&net_lat.glob, m);

	latency_percl_print(&io_lat.last, m);
	latency_percl_print(&io_lat.glob, m);

	latency_percl_print(&pending_lat.last, m);
	latency_percl_print(&pending_lat.glob, m);

	seq_dentry(m, ff->ff_dentry, "");
	seq_putc(m, '\n');
}

static int pcs_fuse_fstat_lat_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct pcs_fuse_stat *stat;
	struct fuse_conn *fc;

	if (!inode)
		return 0;

	mutex_lock(&fuse_mutex);
	stat = inode->i_private;
	if (!stat) {
		mutex_unlock(&fuse_mutex);
		return 0;
	}

	seq_printf(m, "# rw open/age inactive  net_lat\t\t\t     net_lat_global\t\t  io_lat\t\t       io_lat_global\t\t    plat\t\t\t plat_global\t\t      path\n");

	fc = container_of(stat, struct pcs_fuse_cluster, cc.stat)->fc;
	if (fc) {
		spin_lock(&fc->lock);
		pcs_kio_file_list(fc, fuse_kio_fstat_lat_itr, m);
		spin_unlock(&fc->lock);
	}
	mutex_unlock(&fuse_mutex);


	return 0;
}

static int pcs_fuse_fstat_lat_open(struct inode *inode, struct file *file)
{
	return single_open(file, pcs_fuse_fstat_lat_show, inode);
}

static const struct file_operations pcs_fuse_fstat_lat_ops = {
	.owner   = THIS_MODULE,
	.open    = pcs_fuse_fstat_lat_open,
	.read    = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static void fuse_fstat_up_itr(struct fuse_file *ff, struct pcs_dentry_info *di,
			      void *ctx)
{
	struct fuse_io_cnt *fstat = &di->stat;

	spin_lock(&fstat->lock);
	fuse_latency_cnt_up(&fstat->io_lat);
	fuse_latency_cnt_up(&fstat->net_lat);
	fuse_latency_cnt_up(&fstat->pending_lat);

	fuse_val_cnt_up(&fstat->io.read_bytes);
	fuse_val_cnt_up(&fstat->io.write_bytes);
	fuse_val_cnt_up(&fstat->io.flush_cnt);
	spin_unlock(&fstat->lock);
}

static void pcs_fuse_stat_files_up(struct pcs_cluster_core *cc)
{
	struct fuse_conn *fc = container_of(cc, struct pcs_fuse_cluster, cc)->fc;
	if (fc) {
		spin_lock(&fc->lock);
		pcs_kio_file_list(fc, fuse_fstat_up_itr, NULL);
		spin_unlock(&fc->lock);
	}
}

static void fuse_kio_fstat_itr(struct fuse_file *ff, struct pcs_dentry_info *di,
			       void *ctx)
{
	struct fuse_io_cnt *fstat = &di->stat;
	struct seq_file *m = ctx;
	umode_t mode = di->inode->inode.i_mode;
	abs_time_t now = jiffies;
	struct pcs_fuse_io_stat io_stat;

	seq_printf(m, "%s%s %7u/%-7llu %-7u %-4u ",
		   mode & S_IRUGO ? "r": "", mode & S_IWUGO ? "w": "",
		   atomic_read(&ff->count), (now - fstat->created_ts) / 1000, 0, 0);

	spin_lock(&fstat->lock);
	io_stat = fstat->io;
	spin_unlock(&fstat->lock);

	seq_printf(m, "%-6llu %-10llu %-13llu ", EVT_RATE(io_stat.read_bytes.last),
		   VAL_RATE(io_stat.read_bytes.last), CNT_TOTAL(io_stat.read_bytes));
	seq_printf(m, "%-6llu %-10llu %-13llu ", EVT_RATE(io_stat.write_bytes.last),
		   VAL_RATE(io_stat.write_bytes.last), CNT_TOTAL(io_stat.write_bytes));
	seq_printf(m, "%-6llu %-7llu ", EVT_RATE(io_stat.flush_cnt.last),
		   CNT_TOTAL(io_stat.flush_cnt));
	seq_printf(m, "%-6llu %-6llu %-6llu ", CNT_MIN(io_stat.read_bytes),
		   VAL_AVER(io_stat.read_bytes.glob), CNT_MAX(io_stat.read_bytes));
	seq_printf(m, "%-6llu %-6llu %-6llu ", CNT_MIN(io_stat.write_bytes),
		   VAL_AVER(io_stat.write_bytes.glob), CNT_MAX(io_stat.write_bytes));
	seq_dentry(m, ff->ff_dentry, "");
	seq_putc(m, '\n');
}

static int pcs_fuse_fstat_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct pcs_fuse_stat *stat;
	struct fuse_conn *fc;

	if (!inode)
		return 0;

	mutex_lock(&fuse_mutex);
	stat = inode->i_private;
	if (!stat) {
		mutex_unlock(&fuse_mutex);
		return 0;
	}

	seq_printf(m, "# rw open/age inactive handles rd/sec rbytes/sec rtotal        wr/sec wbytes/sec wtotal      sync/sec stotal  rmin   ravg   rmax   wmin   wavg   wmax   path\n");

	fc = container_of(stat, struct pcs_fuse_cluster, cc.stat)->fc;
	if (fc) {
		spin_lock(&fc->lock);
		pcs_kio_file_list(fc, fuse_kio_fstat_itr, m);
		spin_unlock(&fc->lock);
	}
	mutex_unlock(&fuse_mutex);

	return 0;
}

static int pcs_fuse_fstat_open(struct inode *inode, struct file *file)
{
	return single_open(file, pcs_fuse_fstat_show, inode);
}

static const struct file_operations pcs_fuse_fstat_ops = {
	.owner   = THIS_MODULE,
	.open    = pcs_fuse_fstat_open,
	.read    = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static void fuse_kio_stat_req_itr(struct fuse_file *ff, struct fuse_req *req,
				  void *ctx)
{
	struct seq_file *m = ctx;
	struct pcs_fuse_req *r = pcs_req_from_fuse(req);
	struct pcs_int_request *ireq = &r->exec.ireq;

	seq_printf(m, "%-16s ", fuse_kio_op_name(req->in.h.opcode));
	seq_printf(m, "%-8llu %-8llu ", ktime_to_ms(ktime_sub(ktime_get(), ireq->ts)), req->in.h.unique);
	seq_printf(m, "%5u/%-5u %-5u ", 0, atomic_read(&r->exec.ctl.retry_cnt), r->exec.ctl.last_err.value);
	seq_printf(m, "%-16s ", pcs_strerror(r->exec.ctl.last_err.value));
	seq_dentry(m, ff->ff_dentry, "");
	seq_putc(m, '\n');
}

static int pcs_fuse_requests_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct pcs_fuse_stat *stat;
	struct fuse_conn *fc;

	if (!inode)
		return 0;

	mutex_lock(&fuse_mutex);
	stat = inode->i_private;
	if (!stat) {
		mutex_unlock(&fuse_mutex);
		return 0;
	}

	seq_printf(m, "# type duration(msec)     id      stage/retry  errno status           path\n");

	fc = container_of(stat, struct pcs_fuse_cluster, cc.stat)->fc;
	if (fc) {
		spin_lock(&fc->lock);
		pcs_kio_req_list(fc, fuse_kio_stat_req_itr, m);
		spin_unlock(&fc->lock);
	}
	mutex_unlock(&fuse_mutex);

	return 0;
}

static int pcs_fuse_requests_open(struct inode *inode, struct file *file)
{
	return single_open(file, pcs_fuse_requests_show, inode);
}

static const struct file_operations pcs_fuse_requests_ops = {
	.owner   = THIS_MODULE,
	.open    = pcs_fuse_requests_open,
	.read    = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

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

void pcs_fuse_stat_io_count(struct pcs_int_request *ireq, struct pcs_msg *resp,
			    u32 io_lat, u32 net_lat)
{
	struct pcs_cluster_core *cc = ireq->cc;
	struct pcs_fuse_stat *stat = &cc->stat;
	struct fuse_io_cnt *fstat = &ireq->dentry->stat;
	struct pcs_cs_iohdr *h = (struct pcs_cs_iohdr *)msg_inline_head(resp);
	struct fuse_val_cnt *se = req_stat_entry(&stat->io, h->hdr.type);
	u64 size = h->hdr.type != PCS_CS_SYNC_RESP ? ireq->iochunk.size : 0;

	if (likely(se)) {
		spin_lock(&stat->lock);
		fuse_val_stat_update(&se->curr, size);
		spin_unlock(&stat->lock);
	}

	se = req_stat_entry(&fstat->io, h->hdr.type);
	if (likely(se)) {
		u32 pending_lat = ktime_to_us(ktime_sub(ireq->ts_sent, ireq->ts));

		spin_lock(&fstat->lock);
		fuse_latency_count(&fstat->pending_lat, pending_lat);
		fuse_latency_count(&fstat->io_lat, io_lat);
		fuse_latency_count(&fstat->net_lat, net_lat);

		fuse_val_stat_update(&se->curr, size);
		spin_unlock(&fstat->lock);
	}
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

	pcs_fuse_stat_files_up(cc);

	pcs_cs_set_stat_up(&cc->css);

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

	stat->requests = fuse_kio_add_dentry(stat->kio_stat, fc, "requests",
					     S_IFREG | S_IRUSR, 1, NULL,
					     &pcs_fuse_requests_ops, stat);

	stat->fstat = fuse_kio_add_dentry(stat->kio_stat, fc, "fstat",
					  S_IFREG | S_IRUSR, 1, NULL,
					  &pcs_fuse_fstat_ops, stat);

	stat->fstat_lat = fuse_kio_add_dentry(stat->kio_stat, fc, "fstat_lat",
					      S_IFREG | S_IRUSR, 1, NULL,
					      &pcs_fuse_fstat_lat_ops, stat);

	stat->cs_stats = fuse_kio_add_dentry(stat->kio_stat, fc, "cs_stats",
					     S_IFREG | S_IRUSR, 1, NULL,
					     &pcs_fuse_cs_stats_ops, stat);
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
		if (stat->requests)
			fuse_kio_rm_dentry(stat->requests);
		if (stat->fstat)
			fuse_kio_rm_dentry(stat->fstat);
		if (stat->fstat_lat)
			fuse_kio_rm_dentry(stat->fstat_lat);
		if (stat->cs_stats)
			fuse_kio_rm_dentry(stat->cs_stats);
		fuse_kio_rm_dentry(stat->kio_stat);
	}
	mutex_unlock(&fuse_mutex);

	cancel_delayed_work_sync(&stat->work);
}
