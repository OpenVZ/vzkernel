#ifndef __FUSE_PROMETHEUS_PROT__
#define __FUSE_PROMETHEUS_PROT__ 1

#define KFUSE_OP_CS_READ	0
#define KFUSE_OP_CS_WRITE	1
#define KFUSE_OP_CS_SYNC	2
#define KFUSE_OP_CS_WRITE_HOLE	3
#define KFUSE_OP_CS_WRITE_ZERO	4
#define KFUSE_OP_CS_FIEMAP	5

#define KFUSE_OP_READ		6
#define KFUSE_OP_WRITE		7
#define KFUSE_OP_FSYNC		8
#define KFUSE_OP_FALLOCATE	9
#define KFUSE_OP_MAX		10

#define KFUSE_PROM_MAX		(9*5 + 2)

struct kfuse_stat_rec
{
	u64	buckets[KFUSE_PROM_MAX];
	u64	sum;
};

struct kfuse_histogram
{
	struct kfuse_stat_rec	metrics[KFUSE_OP_MAX];
};

#endif /* __FUSE_PROMETHEUS_PROT__ */
