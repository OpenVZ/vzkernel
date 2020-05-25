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

#define CURR_IDX(__iostat) atomic_read(&(__iostat)->idx)
#define LAST_IDX(__iostat) !CURR_IDX(__iostat)

#define CURR(__iostat) period[CURR_IDX(__iostat)]
#define LAST(__iostat) period[LAST_IDX(__iostat)]

#define STAT_SWITCH(__stat) \
	atomic_set(&(__stat)->idx, !atomic_read(&(__stat)->idx));

#define STAT_SEQ_READ_BARRIER(__stat)           \
	while(read_seqretry(&(__stat)->seqlock, \
			    read_seqbegin(&(__stat)->seqlock)));


static inline void fuse_val_stat_update(struct fuse_val_stat *s, u64 val)
{
	/*
	 * Sanity check. In case s == NULL, stack protector cookie is
	 * corrupted, quite difficult to debug.
	 */
	BUG_ON(!s);

	preempt_disable();
	if (!__this_cpu_read(s->events)) {
		__this_cpu_write(s->val_min, val);
		__this_cpu_write(s->val_max, val);
	} else if (val < __this_cpu_read(s->val_min))
		__this_cpu_write(s->val_min, val);
	else if (val > __this_cpu_read(s->val_max))
		__this_cpu_write(s->val_max, val);
	this_cpu_add(s->val_total, val);
	this_cpu_inc(s->events);
	preempt_enable();
}

void fuse_latency_update(struct fuse_lat_stat *s, u64 val)
{
	int i;

	/*
	 * Sanity check. In case s == NULL, stack protector cookie is
	 * corrupted, quite difficult to debug.
	 */
	BUG_ON(!s);
	this_cpu_inc(s->count);
	for (i = LAT_ORDER1; i <= LAT_ORDER5; i++) {
		if (likely(val <= lat_oreder_list[i])) {
			this_cpu_inc(s->lat[i]);
			return;
		}
	}
	this_cpu_inc(s->lat[LAT_ORDER_OTHER]);
}

static inline void fuse_latency_count(struct pcs_fuse_io_lat_sync *lat,
				      u32 pending_lat, u32 io_lat, u32 net_lat)
{
	struct pcs_fuse_io_lat *curr;

	write_seqlock(&lat->seqlock);
	preempt_disable();
	curr = lat->CURR(lat);
	fuse_latency_update(&curr->pending_lat, pending_lat);
	fuse_latency_update(&curr->io_lat, io_lat);
	fuse_latency_update(&curr->net_lat, net_lat);
	preempt_enable();
	write_sequnlock(&lat->seqlock);
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

static inline unsigned long long fuse_evt_rate(struct fuse_val_stat const *s, unsigned period)
{
	return DIV_ROUND_UP(s->events, period);
}

static inline unsigned long long fuse_val_rate(struct fuse_val_stat const *s, unsigned period)
{
	return DIV_ROUND_UP(s->val_total, period);
}

static inline unsigned long long fuse_val_aver(struct fuse_val_stat const *s)
{
	return s->events ? s->val_total / s->events : 0;
}

static inline unsigned long long fuse_val_cnt_min(struct fuse_val_stat *s1,
						  struct fuse_val_stat *s2)
{
	return min(s1->val_min, s2->val_min);
}

static inline unsigned long long fuse_val_cnt_max(struct fuse_val_stat *s1,
						  struct fuse_val_stat *s2)
{
	return max(s1->val_max, s2->val_max);
}

#define EVT_RATE(s) fuse_evt_rate(&(s), STAT_TIMER_PERIOD)
#define VAL_RATE(s) fuse_val_rate(&(s), STAT_TIMER_PERIOD)
#define VAL_AVER(s) fuse_val_aver(&(s))
#define CNT_MIN(_s1, _s2) fuse_val_cnt_min(&(_s1), &(_s2))
#define CNT_MAX(_s1, _s2) fuse_val_cnt_max(&(_s1), &(_s2))

static inline void fuse_val_stat_sum(struct fuse_val_stat *s,
				     struct fuse_val_stat *add)
{
	if (!add->events)
		return;

	if (!s->events)
		*s = *add;
	else {
		s->val_min = min(s->val_min, add->val_min);
		s->val_max = max(s->val_max, add->val_max);
		s->val_total += add->val_total;
		s->events += add->events;
	}
}

static void stat_period_read(struct pcs_fuse_io_stat __percpu *in,
			     struct pcs_fuse_io_stat *out)
{
	int cpu;
	bool inited = false;

	for_each_possible_cpu(cpu) {
		struct pcs_fuse_io_stat *stat = per_cpu_ptr(in, cpu);
		if (inited) {
			fuse_val_stat_sum(&out->read_bytes,
					  &stat->read_bytes);
			fuse_val_stat_sum(&out->write_bytes,
					  &stat->write_bytes);
			fuse_val_stat_sum(&out->flush_cnt,
					  &stat->flush_cnt);
		} else {
			*out = *stat;
			inited = true;
		}
	}
}

static void fuse_iostat_up(struct pcs_fuse_io_stat_sync *iostat)
{
	struct pcs_fuse_io_stat lstat;
	int cpu;

	spin_lock(&iostat->lock);
	for_each_possible_cpu(cpu) {
		struct pcs_fuse_io_stat *last =
			per_cpu_ptr(iostat->LAST(iostat), cpu);
		memset(last, 0, sizeof(*last));
	}
	STAT_SWITCH(iostat);
	STAT_SEQ_READ_BARRIER(iostat);

	stat_period_read(iostat->LAST(iostat), &lstat);

	fuse_val_stat_sum(&iostat->glob.read_bytes, &lstat.read_bytes);
	fuse_val_stat_sum(&iostat->glob.write_bytes, &lstat.write_bytes);
	fuse_val_stat_sum(&iostat->glob.flush_cnt, &lstat.flush_cnt);
	spin_unlock(&iostat->lock);
}

static inline void fuse_iolat_sum(struct fuse_lat_stat *s,
				  struct fuse_lat_stat *add)
{
	if (!add->count)
		return;

	if (!s->count)
		*s = *add;
	else {
		int i;
		for (i = LAT_ORDER1; i <= LAT_ORDER_OTHER; i++)
			s->lat[i] += add->lat[i];
		s->count += add->count;
	}
}

static void lat_period_read(struct pcs_fuse_io_lat __percpu *in,
			    struct pcs_fuse_io_lat *out)
{
	int cpu;
	bool inited = false;

	for_each_possible_cpu(cpu) {
		struct pcs_fuse_io_lat *stat = per_cpu_ptr(in, cpu);
		if (inited) {
			fuse_iolat_sum(&out->io_lat, &stat->io_lat);
			fuse_iolat_sum(&out->net_lat, &stat->net_lat);
			fuse_iolat_sum(&out->pending_lat, &stat->pending_lat);
		} else {
			*out = *stat;
			inited = true;
		}
	}
}

static void fuse_fstat_lat_up(struct pcs_fuse_io_lat_sync *lat)
{
	struct pcs_fuse_io_lat lstat;
	int cpu;

	spin_lock(&lat->lock);
	for_each_possible_cpu(cpu) {
		struct pcs_fuse_io_lat *last = per_cpu_ptr(lat->LAST(lat), cpu);
		memset(last, 0, sizeof(*last));
	}
	STAT_SWITCH(lat);
	STAT_SEQ_READ_BARRIER(lat);

	lat_period_read(lat->LAST(lat), &lstat);

	fuse_iolat_sum(&lat->glob.io_lat, &lstat.io_lat);
	fuse_iolat_sum(&lat->glob.net_lat, &lstat.net_lat);
	fuse_iolat_sum(&lat->glob.pending_lat, &lstat.pending_lat);
	spin_unlock(&lat->lock);
}

static void fuse_fstat_up_itr(struct fuse_file *ff, struct pcs_dentry_info *di,
			      void *ctx)
{
	struct fuse_io_cnt *fstat = &di->stat;
	fuse_iostat_up(&fstat->io);
	fuse_fstat_lat_up(&fstat->lat);
}

static void fuse_stat_files_up(struct pcs_cluster_core *cc)
{
	struct fuse_conn *fc = container_of(cc, struct pcs_fuse_cluster, cc)->fc;
	if (fc) {
		spin_lock(&fc->lock);
		pcs_kio_file_list(fc, fuse_fstat_up_itr, NULL);
		spin_unlock(&fc->lock);
	}
}

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
		return scnprintf(buf, sz, "%u%% > %llu", MAX_PERCENT - percl,
				 lat_oreder_list[LAT_ORDER_OTHER - 1] / 1000);

	for(i = LAT_ORDER_OTHER - 1; i >= 0; i--) {
		if (s->lat[i] * MAX_PERCENT >= nper)
			return scnprintf(buf, sz, "%u%% <= %llu", percl,
					 lat_oreder_list[i] / 1000);
	}
	BUG();
	return 0;
}

#define LAT_LINE_MAX 23
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

static int do_show_cs_stats(struct pcs_cs *cs, void *ctx)
{
	struct seq_file *m = ctx;
	int rpc_state = cs->rpc ? cs->rpc->state : PCS_RPC_UNCONN;
	unsigned int in_flight_avg = cs->in_flight_avg;
	struct fuse_lat_stat iolat = {}, netlat = {};
	struct pcs_perf_rate_cnt read_ops_rate = {}, write_ops_rate = {},
				 sync_ops_rate = {};
	unsigned seq;

	do {
		int cpu;

		seq = read_seqbegin(&cs->stat.seqlock);
		for_each_possible_cpu(cpu) {
			struct fuse_lat_stat *pcpu_iolat, *pcpu_netlat;
			struct pcs_perf_rate_cnt *pcpu_read_rate,
						 *pcpu_write_rate,
						 *pcpu_sync_rate;

			pcpu_iolat = per_cpu_ptr(cs->stat.iolat, cpu);
			pcpu_netlat = per_cpu_ptr(cs->stat.netlat, cpu);
			pcpu_read_rate = per_cpu_ptr(cs->stat.read_ops_rate, cpu);
			pcpu_write_rate = per_cpu_ptr(cs->stat.write_ops_rate, cpu);
			pcpu_sync_rate = per_cpu_ptr(cs->stat.sync_ops_rate, cpu);

			fuse_iolat_sum(&iolat, pcpu_iolat);
			fuse_iolat_sum(&netlat, pcpu_netlat);
			pcs_cs_stat_rate_sum(&read_ops_rate, pcpu_read_rate);
			pcs_cs_stat_rate_sum(&write_ops_rate, pcpu_write_rate);
			pcs_cs_stat_rate_sum(&sync_ops_rate, pcpu_sync_rate);
		}
	} while (read_seqretry(&cs->stat.seqlock, seq));

	seq_printf(m, "%-10llu %d=%-8s %-10llu %-10llu %-11llu",
		NODE_ARGS(cs->id), rpc_state, pcs_rpc_state_name(rpc_state),
		read_ops_rate.rate / STAT_TIMER_PERIOD,
		write_ops_rate.rate / STAT_TIMER_PERIOD,
		sync_ops_rate.rate / STAT_TIMER_PERIOD);
	latency_percl_print(&iolat, m);
	latency_percl_print(&netlat, m);
	seq_printf(m, "%-10u\n", in_flight_avg);
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
	if (!stat)
		goto out;

	seq_printf(m, "# csid     rpc        rd_ops     wr_ops     sync_ops   net_lat\t\t\tio_lat\t\t\t avg_in_flight\n");

	cc = container_of(stat, struct pcs_cluster_core, stat);
	pcs_cs_for_each_entry(&cc->css, do_show_cs_stats, m);
out:
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

static ssize_t pcs_fuse_storage_version_read(struct file *file,
					     char __user *buf, size_t len,
					     loff_t *ppos)
{
	struct pcs_fuse_stat *stat;
	struct pcs_cluster_core *cc;
	char ver[32];
	size_t size;
	ssize_t ret = 0;

	mutex_lock(&fuse_mutex);

	stat = file_inode(file)->i_private;
	if (!stat)
		goto out;
	cc = container_of(stat, struct pcs_cluster_core, stat);

	size = snprintf(ver, sizeof(ver), "%d\n",
			atomic_read(&cc->storage_version));
	ret = simple_read_from_buffer(buf, len, ppos, ver, size);

out:
	mutex_unlock(&fuse_mutex);

	return ret;
}

static ssize_t pcs_fuse_storage_version_write(struct file *file,
					      const char __user *buf,
					      size_t count, loff_t *ppos)
{
	struct pcs_fuse_stat *stat;
	struct pcs_cluster_core *cc;
	unsigned int ver;
	int err;

	if (*ppos)
		return -EINVAL;

	err = kstrtouint_from_user(buf, count, 0, &ver);
	if (err)
		return err;

	mutex_lock(&fuse_mutex);

	stat = file_inode(file)->i_private;
	if (!stat)
		goto out;
	cc = container_of(stat, struct pcs_cluster_core, stat);

	pcs_cc_update_storage_versions(cc, ver);

out:
	mutex_unlock(&fuse_mutex);

	return count;
}

static const struct file_operations pcs_fuse_storage_version_ops = {
	.owner   = THIS_MODULE,
	.open    = nonseekable_open,
	.read    = pcs_fuse_storage_version_read,
	.write   = pcs_fuse_storage_version_write,
	.llseek  = no_llseek,
};

static void fuse_kio_fstat_lat_itr(struct fuse_file *ff,
				   struct pcs_dentry_info *di, void *ctx)
{
	struct seq_file *m = ctx;
	struct pcs_fuse_io_lat_sync *lat = &di->stat.lat;
	umode_t mode = di->inode->inode.i_mode;
	abs_time_t now = jiffies;
	struct pcs_fuse_io_lat lstat, gstat;

	seq_printf(m, "%s%s %6u/%-6llu %-7u",
		   mode & S_IRUGO ? "r": "", mode & S_IWUGO ? "w": "",
		   atomic_read(&ff->count), (now - di->stat.created_ts) / 1000, 0);

	spin_lock(&lat->lock);
	lat_period_read(lat->LAST(lat), &lstat);
	gstat = lat->glob;
	spin_unlock(&lat->lock);

	latency_percl_print(&lstat.net_lat, m);
	latency_percl_print(&gstat.net_lat, m);

	latency_percl_print(&lstat.io_lat, m);
	latency_percl_print(&gstat.io_lat, m);

	latency_percl_print(&lstat.pending_lat, m);
	latency_percl_print(&gstat.pending_lat, m);

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
	if (!stat)
		goto out;

	seq_printf(m, "# rw open/age inactive  net_lat\t\t\t net_lat_global\t\t  io_lat\t\t   io_lat_global\t    plat\t\t     plat_global\t      path\n");

	fc = container_of(stat, struct pcs_fuse_cluster, cc.stat)->fc;
	if (fc) {
		spin_lock(&fc->lock);
		pcs_kio_file_list(fc, fuse_kio_fstat_lat_itr, m);
		spin_unlock(&fc->lock);
	}
out:
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

static void fuse_kio_fstat_itr(struct fuse_file *ff, struct pcs_dentry_info *di,
			       void *ctx)
{
	struct fuse_io_cnt *fstat = &di->stat;
	struct pcs_fuse_io_stat_sync *iostat = &fstat->io;
	struct seq_file *m = ctx;
	umode_t mode = di->inode->inode.i_mode;
	abs_time_t now = jiffies;
	struct pcs_fuse_io_stat lstat, gstat;

	seq_printf(m, "%s%s %7u/%-7llu %-7u %-4u ",
		   mode & S_IRUGO ? "r": "", mode & S_IWUGO ? "w": "",
		   atomic_read(&ff->count), (now - fstat->created_ts) / 1000, 0, 0);

	spin_lock(&iostat->lock);
	stat_period_read(iostat->LAST(iostat), &lstat);
	gstat = iostat->glob;
	spin_unlock(&iostat->lock);

	seq_printf(m, "%-6llu %-10llu %-13llu ", EVT_RATE(lstat.read_bytes),
		   VAL_RATE(lstat.read_bytes), gstat.read_bytes.val_total);
	seq_printf(m, "%-6llu %-10llu %-13llu ", EVT_RATE(lstat.write_bytes),
		   VAL_RATE(lstat.write_bytes), gstat.write_bytes.val_total);
	seq_printf(m, "%-6llu %-7llu ", EVT_RATE(lstat.flush_cnt),
		   gstat.flush_cnt.val_total);
	seq_printf(m, "%-6llu %-6llu %-6llu ", CNT_MIN(lstat.read_bytes, gstat.read_bytes),
		   VAL_AVER(gstat.read_bytes), CNT_MAX(lstat.read_bytes, gstat.read_bytes));
	seq_printf(m, "%-6llu %-6llu %-6llu ", CNT_MIN(lstat.write_bytes, gstat.read_bytes),
		   VAL_AVER(gstat.write_bytes), CNT_MAX(lstat.write_bytes, gstat.read_bytes));
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
	if (!stat)
		goto out;

	seq_printf(m, "# rw open/age inactive handles rd/sec rbytes/sec rtotal        wr/sec wbytes/sec wtotal      sync/sec stotal  rmin   ravg   rmax   wmin   wavg   wmax   path\n");

	fc = container_of(stat, struct pcs_fuse_cluster, cc.stat)->fc;
	if (fc) {
		spin_lock(&fc->lock);
		pcs_kio_file_list(fc, fuse_kio_fstat_itr, m);
		spin_unlock(&fc->lock);
	}
out:
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
	.llseek  = seq_lseek,
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
	if (!stat)
		goto out;

	seq_printf(m, "# type duration(msec)     id      stage/retry  errno status           path\n");

	fc = container_of(stat, struct pcs_fuse_cluster, cc.stat)->fc;
	if (fc) {
		spin_lock(&fc->lock);
		pcs_kio_req_list(fc, fuse_kio_stat_req_itr, m);
		spin_unlock(&fc->lock);
	}
out:
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
       .llseek  = seq_lseek,
       .release = single_release,
};

static int pcs_fuse_iostat_show(struct seq_file *m, void *v)
{
	struct inode *inode = m->private;
	struct pcs_fuse_stat *stat;
	struct pcs_fuse_io_stat_sync *iostat;
	struct pcs_fuse_io_stat last_stat, glob_stat;

	if (!inode)
		return 0;

	mutex_lock(&fuse_mutex);
	stat = inode->i_private;
	if (!stat)
		goto out;

	seq_printf(m, "# operation  ops/sec  bytes/sec   total            req_min req_avg req_max (bytes)\n");

	iostat = &stat->io;

	spin_lock(&iostat->lock);
	stat_period_read(iostat->LAST(iostat), &last_stat);
	glob_stat = iostat->glob;
	spin_unlock(&iostat->lock);

	seq_printf(m, "read         %-8llu %-11llu %-16llu %-6llu  %-6llu  %-6llu\n",
		   EVT_RATE(last_stat.read_bytes), VAL_RATE(last_stat.read_bytes),
		   glob_stat.read_bytes.val_total, last_stat.read_bytes.val_min,
		   VAL_AVER(last_stat.read_bytes), last_stat.read_bytes.val_max);
	seq_printf(m, "write        %-8llu %-11llu %-16llu %-6llu  %-6llu  %-6llu\n",
		   EVT_RATE(last_stat.write_bytes), VAL_RATE(last_stat.write_bytes),
		   glob_stat.write_bytes.val_total, last_stat.write_bytes.val_min,
		   VAL_AVER(last_stat.write_bytes), last_stat.write_bytes.val_max);
	seq_printf(m, "sync         %-8llu             %-16llu\n",
		   EVT_RATE(last_stat.flush_cnt), glob_stat.flush_cnt.events);
out:
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
struct fuse_val_stat *req_stat_entry(struct pcs_fuse_io_stat *io, u32 type)
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
	return NULL;
}

static void fuse_iostat_count(struct pcs_fuse_io_stat_sync *iostat,
			      u64 size, u32 type)
{
	struct fuse_val_stat *se;

	write_seqlock(&iostat->seqlock);
	se = req_stat_entry(iostat->CURR(iostat), type);
	if (!se)
		goto out_unlock;

	fuse_val_stat_update(se, size);
out_unlock:
	write_sequnlock(&iostat->seqlock);
}

void pcs_fuse_stat_io_count(struct pcs_int_request *ireq, struct pcs_msg *resp,
			    u32 io_lat, u32 net_lat)
{
	struct pcs_fuse_stat *stat = &ireq->cc->stat;
	struct fuse_io_cnt *fstat = &ireq->dentry->stat;
	struct pcs_cs_iohdr *h = (struct pcs_cs_iohdr *)msg_inline_head(resp);
	u64 size = h->hdr.type != PCS_CS_SYNC_RESP ? ireq->iochunk.size : 0;
	u32 pending_lat = ktime_to_us(ktime_sub(ireq->ts_sent, ireq->ts));

	fuse_iostat_count(&stat->io, size, h->hdr.type);
	fuse_iostat_count(&fstat->io, size, h->hdr.type);

	fuse_latency_count(&fstat->lat, pending_lat, io_lat, net_lat);
}

static void pcs_fuse_stat_work(struct work_struct *w)
{
	struct pcs_cluster_core *cc =
		container_of(w, struct pcs_cluster_core, stat.work.work);
	struct pcs_fuse_stat *stat = &cc->stat;

	fuse_iostat_up(&stat->io);
	fuse_stat_files_up(cc);
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

int pcs_fuse_fstat_alloc(struct pcs_fuse_io_lat_sync *lat)
{
	atomic_set(&lat->idx, 0);
	lat->CURR(lat) = alloc_percpu(struct pcs_fuse_io_lat);
	if (!lat->CURR(lat))
		return -ENOMEM;

	lat->LAST(lat) = alloc_percpu(struct pcs_fuse_io_lat);
	if (!lat->LAST(lat))
		goto fail;

	memset(&lat->glob, 0, sizeof(lat->glob));

	seqlock_init(&lat->seqlock);
	spin_lock_init(&lat->lock);
	return 0;
fail:
	free_percpu(lat->CURR(lat));
	return -ENOMEM;
}

void pcs_fuse_fstat_free(struct pcs_fuse_io_lat_sync *lat)
{
	free_percpu(lat->LAST(lat));
	free_percpu(lat->CURR(lat));
}

int pcs_fuse_io_stat_alloc(struct pcs_fuse_io_stat_sync *iostat)
{
	atomic_set(&iostat->idx, 0);
	iostat->CURR(iostat) = alloc_percpu(struct pcs_fuse_io_stat);
	if (!iostat->CURR(iostat))
		return -ENOMEM;

	iostat->LAST(iostat) = alloc_percpu(struct pcs_fuse_io_stat);
	if (!iostat->LAST(iostat))
		goto fail;

	memset(&iostat->glob, 0, sizeof(iostat->glob));

	seqlock_init(&iostat->seqlock);
	spin_lock_init(&iostat->lock);
	return 0;
fail:
	free_percpu(iostat->CURR(iostat));
	return -ENOMEM;
}

void pcs_fuse_io_stat_free(struct pcs_fuse_io_stat_sync *iostat)
{
	free_percpu(iostat->LAST(iostat));
	free_percpu(iostat->CURR(iostat));
}

void pcs_fuse_stat_init(struct pcs_fuse_stat *stat)
{
	struct pcs_cluster_core *cc =
		container_of(stat, struct pcs_cluster_core, stat);
	struct fuse_conn *fc = container_of(cc,struct pcs_fuse_cluster, cc)->fc;

	mutex_lock(&fuse_mutex);
	if (!fuse_control_sb)
		goto fail1;

	if (pcs_fuse_io_stat_alloc(&stat->io))
		goto fail1;

	stat->kio_stat = fuse_kio_add_dentry(fc->conn_ctl, fc, "kio_stat",
					     S_IFDIR | S_IXUSR, 2,
					     &simple_dir_inode_operations,
					     &simple_dir_operations, fc);
	if (!stat->kio_stat) {
		pr_err("kio: can't create kio stat directory");
		goto fail2;
	}

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
	stat->storage_version = fuse_kio_add_dentry(stat->kio_stat, fc,
						    "storage_version",
						    S_IFREG | S_IRUSR | S_IWUSR, 1, NULL,
						    &pcs_fuse_storage_version_ops,
						    stat);
	mutex_unlock(&fuse_mutex);
	return;

fail2:
	pcs_fuse_io_stat_free(&stat->io);
fail1:
	stat->kio_stat = NULL;
	mutex_unlock(&fuse_mutex);
}

void pcs_fuse_stat_fini(struct pcs_fuse_stat *stat)
{
	mutex_lock(&fuse_mutex);
	if (!stat->kio_stat) {
		mutex_unlock(&fuse_mutex);
		return;
	}

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
		if (stat->storage_version)
			fuse_kio_rm_dentry(stat->storage_version);
		fuse_kio_rm_dentry(stat->kio_stat);
	}
	mutex_unlock(&fuse_mutex);

	cancel_delayed_work_sync(&stat->work);
	pcs_fuse_io_stat_free(&stat->io);
}
