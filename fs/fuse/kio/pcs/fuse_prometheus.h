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

struct fuse_rpc_error {
	PCS_NET_ADDR_T addr;
	u64 err[PCS_RPC_ERR_MAX];
};

struct fuse_rpc_error_metric {
	struct fuse_rpc_error m;
	struct list_head list;
};

struct fuse_error_metrics {
	struct mutex mutex;
	struct list_head fuse_rpc_error_metric_list;
};

void fuse_rpc_error_account(struct fuse_error_metrics *metrics,
	PCS_NET_ADDR_T const *addr, unsigned int err, u64 val);

#endif /* __FUSE_PROMETHEUS_H__ */
