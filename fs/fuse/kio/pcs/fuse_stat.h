#ifndef _FUSE_STAT_H_
#define _FUSE_STAT_H_ 1

#define STAT_TIMER_PERIOD 5

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
};

void pcs_fuse_stat_init(struct pcs_fuse_stat *stat);
void pcs_fuse_stat_fini(struct pcs_fuse_stat *stat);

void pcs_fuse_stat_io_count(struct pcs_int_request *ireq, struct pcs_msg *resp);

#endif /* _FUSE_STAT_H_ */
