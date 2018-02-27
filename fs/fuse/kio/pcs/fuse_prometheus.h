#ifndef __FUSE_PROMETHEUS_H__
#define __FUSE_PROMETHEUS_H__ 1

#include "fuse_prometheus_prot.h"

struct fuse_prometheus_data
{
	struct kfuse_histogram __percpu *histo;
};

#endif /* __FUSE_PROMETHEUS_H__ */
