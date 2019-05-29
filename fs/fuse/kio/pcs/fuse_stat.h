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

struct pcs_fuse_io_stat {
	struct fuse_val_stat read_bytes;
	struct fuse_val_stat write_bytes;
	struct fuse_val_stat flush_cnt;
} ____cacheline_aligned;

struct pcs_fuse_io_stat_sync {
	struct pcs_fuse_io_stat glob;
	struct pcs_fuse_io_stat __percpu *period[2];
	atomic_t idx;
	seqlock_t seqlock;
	spinlock_t lock;
};

struct pcs_fuse_stat {
	struct pcs_fuse_io_stat_sync io;
	struct delayed_work work;

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

struct pcs_fuse_io_lat {
	struct fuse_lat_stat io_lat;
	struct fuse_lat_stat net_lat;
	struct fuse_lat_stat pending_lat;
} ____cacheline_aligned;

struct pcs_fuse_io_lat_sync {
	struct pcs_fuse_io_lat glob;
	struct pcs_fuse_io_lat __percpu *period[2];
	atomic_t idx;
	seqlock_t seqlock;
	spinlock_t lock;
};

struct fuse_io_cnt {
	struct pcs_fuse_io_stat_sync io;
	struct pcs_fuse_io_lat_sync lat;

	abs_time_t created_ts;
};

void pcs_fuse_stat_init(struct pcs_fuse_stat *stat);
void pcs_fuse_stat_fini(struct pcs_fuse_stat *stat);

void pcs_fuse_stat_io_count(struct pcs_int_request *ireq, struct pcs_msg *resp,
			    u32 io_lat, u32 net_lat);
void fuse_latency_update(struct fuse_lat_stat *s, u64 val);

int pcs_fuse_io_stat_alloc(struct pcs_fuse_io_stat_sync *iostat);
void pcs_fuse_io_stat_free(struct pcs_fuse_io_stat_sync *iostat);

int pcs_fuse_fstat_alloc(struct pcs_fuse_io_lat_sync *lat);
void pcs_fuse_fstat_free(struct pcs_fuse_io_lat_sync *lat);

#endif /* _FUSE_STAT_H_ */
