#ifndef _FUSE_STAT_H_
#define _FUSE_STAT_H_ 1

#define STAT_TIMER_PERIOD 5

struct pcs_msg;
struct pcs_int_request;

struct fuse_val_stat {
	u64 events;
	u64 val_total;
	u64 val_min;
	u64 val_max;
};

struct fuse_val_cnt {
	struct fuse_val_stat  curr;
	struct fuse_val_stat  last;
	struct fuse_val_stat  glob;
};

struct pcs_fuse_io_stat {
	struct fuse_val_cnt read_bytes;
	struct fuse_val_cnt write_bytes;
	struct fuse_val_cnt flush_cnt;
};

struct pcs_fuse_stat {
	struct pcs_fuse_io_stat io;
	struct delayed_work     work;
	spinlock_t              lock;

	struct dentry *kio_stat;
	struct dentry *iostat;
	struct dentry *requests;
	struct dentry *fstat;
	struct dentry *fstat_lat;
};

enum {
	LAT_ORDER1 = 0,
	LAT_ORDER2 = 1,
	LAT_ORDER3 = 2,
	LAT_ORDER4 = 3,
	LAT_ORDER5 = 4,
	LAT_ORDER_OTHER = 5,
};

#define LATENCY_ORDER_MAX (LAT_ORDER_OTHER + 1)

struct fuse_lat_stat {
	u64 lat[LATENCY_ORDER_MAX];
	u64 count;
};

struct fuse_lat_cnt {
	struct fuse_lat_stat  curr;
	struct fuse_lat_stat  last;
	struct fuse_lat_stat  glob;
};

struct fuse_io_cnt {
	struct pcs_fuse_io_stat io;

	struct fuse_lat_cnt io_lat;
	struct fuse_lat_cnt net_lat;
	struct fuse_lat_cnt pending_lat;

	abs_time_t created_ts;
	spinlock_t lock;
};

void pcs_fuse_stat_init(struct pcs_fuse_stat *stat);
void pcs_fuse_stat_fini(struct pcs_fuse_stat *stat);

void pcs_fuse_stat_io_count(struct pcs_int_request *ireq, struct pcs_msg *resp,
			    u32 io_lat, u32 net_lat);

#endif /* _FUSE_STAT_H_ */
