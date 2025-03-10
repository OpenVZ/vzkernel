/*
 *  fs/fuse/kio/pcs/pcs_client_types.h
 *
 *  Copyright (c) 2018-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef _PCS_CLIENT_TYPES_H_
#define _PCS_CLIENT_TYPES_H_ 1

#include "pcs_prot_types.h"
#include "pcs_mds_prot.h"
#include "pcs_flow_detect.h"
#include "fuse_stat.h"

/* Values of lease. It is value, not bitmask. */
#define PCS_LEASE_NONE		0
#define PCS_LEASE_READ		1
#define PCS_LEASE_WRITE		2
#define PCS_LEASE_VALIDATE	3

struct pcs_dentry_name {
	const char		*data;
	int			len;
};

struct pcs_dentry_id {
	PCS_FILE_ID_T		parent;
	struct pcs_dentry_name	name;
};

struct pcs_map_set {
	struct list_lru		lru;
	struct list_lru		dirty_lru;
	struct list_head	dirty_queue;
	spinlock_t		lock;
	atomic_t		count;
	atomic_t		dirty_count;
	int			map_thresh;
	int			map_dirty_thresh;
	int			map_max;
	struct shrinker		shrinker;

	/* TODO: temproraly disabled */
	struct pcs_flow_table_global ftab;
};

struct pcs_mapping {
	struct pcs_cluster_core	*cluster;
	unsigned		chunk_size_bits;
	unsigned long		nrmaps;
	struct radix_tree_root  map_tree; /* GFP_ATOMIC */
	spinlock_t		map_lock;
	struct pcs_flow_table	ftab;
};


typedef enum {
	PCS_SIZE_INACTION,
	PCS_SIZE_GROW,
	PCS_SIZE_SHRINK,
} size_op_t;

struct fuse_inode;
struct pcs_dentry_info {
	struct pcs_dentry_id	id;
	struct pcs_mds_fileinfo	fileinfo;
	PCS_FILETIME_T		local_mtime;
	struct pcs_mapping	mapping;
	struct pcs_cluster_core	*cluster;
	spinlock_t		lock;
	struct {
		struct work_struct	work;
		struct list_head	queue;
		unsigned long long	required;
		size_op_t op;
	} size;
	struct fuse_inode	*inode;
	struct list_head	kq;
	spinlock_t		kq_lock;

	struct fuse_io_cnt stat;
};

static inline void pcs_clear_fileinfo(struct pcs_dentry_info *i)
{
	struct pcs_mds_fileinfo *mi = (struct pcs_mds_fileinfo *)&i->fileinfo;

	memset(mi, 0, sizeof(*mi));
}

static inline void pcs_set_fileinfo(struct pcs_dentry_info *i, const struct pcs_mds_fileinfo *finfo)
{
	struct pcs_mds_fileinfo *mi = &i->fileinfo;

	*mi = *finfo;

	if (mi->sys.stripe_depth == 0) {
		mi->sys.stripe_depth = 1;
		mi->sys.strip_width = mi->sys.chunk_size_lo;
	}
	i->mapping.chunk_size_bits = ilog2(mi->sys.chunk_size_lo);

}

/* Size constants */
#define PCS_MAX_SYMLINK_SIZE	4095
#define PCS_DFLT_MSS_WRITE	(64*1024)
#define PCS_DFLT_MSS_READ	(128*1024)
#define PCS_DFLT_MSS_LOCAL	(512*1024)

/* Minimal delay before retrying failed operation. */
#define PCS_ERROR_DELAY		200
/* Maximum delay before retrying failed operation. */
#define PCS_ERROR_DELAY_MAX	5000
#define PCS_LEASE_RETRY		3

#define PCS_INFO_DIR_COMPAT	".pstorage.info"
#define PCS_INFO_DIR ".vstorage.info"

/* Special magic suffix. readlink() on a name which such suffix from fuse-mouted pcs
 * gives URI of file, which can be accessible via pcs api. If the file is pstorage symlink,
 * it returns its contents to run it though VFS layer again: we cannot do this internally.
 */
#define PCS_API_URI_SUFFIX "#._PSTORAGE_URI_"

enum {
	PCS_REQ_T_READ = 0,
	PCS_REQ_T_WRITE = 1,
	PCS_REQ_T_SYNC = 2,
	PCS_REQ_T_WRITE_HOLE = 3,
	PCS_REQ_T_WRITE_ZERO = 4,
	PCS_REQ_T_FIEMAP = 5,
	PCS_REQ_T_MAX = 6,
};

static inline int pcs_req_direction(int reqno)
{
	switch (reqno) {
	case PCS_REQ_T_READ:
	case PCS_REQ_T_FIEMAP:
		return 0;
	default:
		return 1;
	}
}

/* Request flags */
#define PCS_REQ_F_ERROR		2
#define PCS_REQ_F_NOSPACE	4
#define PCS_REQ_F_CACHED	0x10

struct iov_iter;
typedef struct _pcs_api_iorequest_t {
	off_t		pos;
	size_t		size;
	unsigned short	type;
	unsigned short	flags;

	void		*datasource;
	void		(*get_iter)(void *datasource, unsigned int offset, struct iov_iter *it,
				    unsigned int direction);

	void		(*complete)(struct _pcs_api_iorequest_t *);
} pcs_api_iorequest_t;

typedef struct _pcs_api_csconnreq_t {
	PCS_NODE_ID_T   id;    /* CS id */
	PCS_NET_ADDR_T  addr;  /* CS addr */
	int             error; /* pcs_errors.h */
	void		(*complete)(struct _pcs_api_csconnreq_t *, int);
} pcs_api_csconnreq_t;

/*
 * Useful macro
 */

#define PCS_FILE_ID_FMT       "[%08llx]"
#define PCS_FILE_ID_ARGS(id)  (unsigned long long)(id)
#define DENTRY_FMT            PCS_FILE_ID_FMT "/" PCS_FILE_ID_FMT
#define DENTRY_ARGS(de)	      PCS_FILE_ID_ARGS((de)->id.parent), PCS_FILE_ID_ARGS((de)->fileinfo.attr.id)

#define DENTRY_SIZE(de)       ((de)->fileinfo.attr.size)
#define DENTRY_CHUNK_SIZE(de) ((de)->fileinfo.sys.chunk_size_lo)
#define DENTRY_CHUNK_SIZE_BITS(de) ((de)->mapping.chunk_size_bits)

void pcs_mapset_limit(struct pcs_map_set *maps, int limit);


/* Inode id comparison function */
static inline int pcs_dentry_id_cmp(struct pcs_dentry_id const *a, struct pcs_dentry_id const *b)
{
	int res;
	res = memcmp(&a->parent, &b->parent, sizeof(a->parent));
	if (res)
		return res;
	res = a->name.len - b->name.len;
	if (res)
		return res;
	return memcmp(a->name.data, b->name.data, a->name.len);
}

#endif  /* _PCS_CLIENT_TYPES_H_ */
