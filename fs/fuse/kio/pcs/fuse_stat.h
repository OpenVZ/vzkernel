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
};

void pcs_fuse_stat_init(struct pcs_fuse_stat *stat);
void pcs_fuse_stat_fini(struct pcs_fuse_stat *stat);

void pcs_fuse_stat_io_count(struct pcs_int_request *ireq, struct pcs_msg *resp);

int pcs_fuse_io_stat_alloc(struct pcs_fuse_io_stat_sync *iostat);
void pcs_fuse_io_stat_free(struct pcs_fuse_io_stat_sync *iostat);

#endif /* _FUSE_STAT_H_ */
