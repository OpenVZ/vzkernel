/*
 *  fs/fuse/kio/pcs/fuse_stat.h
 *
 *  Copyright (c) 2018-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef _FUSE_STAT_H_
#define _FUSE_STAT_H_ 1

struct pcs_fuse_stat {
	struct dentry *kio_stat;
};

void pcs_fuse_stat_init(struct pcs_fuse_stat *stat);
void pcs_fuse_stat_fini(struct pcs_fuse_stat *stat);

#endif /* _FUSE_STAT_H_ */