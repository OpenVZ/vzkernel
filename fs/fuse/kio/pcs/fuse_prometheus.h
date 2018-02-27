/*
 *  fs/fuse/kio/pcs/fuse_prometheus.h
 *
 *  Copyright (c) 2018-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef __FUSE_PROMETHEUS_H__
#define __FUSE_PROMETHEUS_H__ 1

#include "fuse_prometheus_prot.h"

struct fuse_prometheus_data
{
	struct kfuse_histogram __percpu *histo;
};

#endif /* __FUSE_PROMETHEUS_H__ */
