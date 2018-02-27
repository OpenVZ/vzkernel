#ifndef __FUSE_PROMETHEUS_PROT__
#define __FUSE_PROMETHEUS_PROT__ 1

#define KFUSE_OP_READ		0
#define KFUSE_OP_WRITE		1
#define KFUSE_OP_FSYNC		2
#define KFUSE_OP_FALLOCATE	3
#define KFUSE_OP_MAX		4

#define KFUSE_PROM_MAX		(9*5 + 1)

struct kfuse_stat_rec
{
	u64	value;
	u64	count;
};

struct kfuse_histogram
{
	struct kfuse_stat_rec	buckets[KFUSE_OP_MAX][KFUSE_PROM_MAX+1];
};

#endif /* __FUSE_PROMETHEUS_PROT__ */
