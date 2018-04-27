#ifndef _PCS_CS_PROT_H_
#define _PCS_CS_PROT_H_ 1

#include "pcs_rpc_prot.h"

#define PCS_CS_FLUSH_WEIGHT	(128*1024)
#define PCS_CS_HOLE_WEIGHT	(4096)

struct pcs_cs_sync_data
{
	PCS_INTEGRITY_SEQ_T	integrity_seq;	/* Invariant. Changed only on CS host crash */
	PCS_SYNC_SEQ_T		sync_epoch;	/* Invariant. Changed on CSD startup. */
	PCS_SYNC_SEQ_T		sync_dirty;	/* Sync number of CS upon completion of local write */
	PCS_SYNC_SEQ_T		sync_current;	/* Current sync number of CS. If > sync_dirty, write is synced */

	u64			misc;		/* Message received by CS */
	u32			ts_io;		/* Local IO finished */
	u32			ts_net;		/* Net finished */
	u64			_reserved;	/* For future extensions */
} __attribute__((aligned(8)));

/* IO req/resp flags. Older version have flag field zero, so zero value should be neutral.
 * We have room for 12 flags.
 */
#define PCS_CS_IO_CACHED	(1ULL<<63)	/* Resp: result is read from cache or written ahead to journal */
#define PCS_CS_IO_SEQ		(1ULL<<62)	/* Req: request is part of sequential flow */

#define PCS_CS_RESET_TS_RECV(sdata, ts)	do { (sdata)->misc = ((u64)ts & 0xFFFFFFFFFFFFFULL); } while (0)
#define PCS_CS_SET_TS_RECV(sdata, ts)	do { (sdata)->misc = ((sdata)->misc & ~0xFFFFFFFFFFFFFULL) | ((u64)ts & 0xFFFFFFFFFFFFFULL); } while (0)
#define PCS_CS_ADD_TS_RECV(sdata, ts)	do { (sdata)->misc |= ((u64)ts & 0xFFFFFFFFFFFFFULL); } while (0)
#define PCS_CS_GET_TS_RECV(sdata)	((sdata)->misc & 0xFFFFFFFFFFFFFULL)

struct pcs_cs_sync_resp {
	PCS_NODE_ID_T		cs_id;
	struct pcs_cs_sync_data	sync;
} __attribute__((aligned(8)));

struct pcs_cs_fiemap_rec
{
	u32	offset;
	u32	size;
	u32	flags;
#define PCS_CS_FIEMAP_FL_OVFL	1
#define PCS_CS_FIEMAP_FL_ZERO	2
#define PCS_CS_FIEMAP_FL_CACHE	4
	u32	_reserved;
} __attribute__((aligned(8)));

struct pcs_cs_iohdr {
	struct pcs_rpc_hdr	hdr;

	PCS_MAP_VERSION_T	map_version;
	PCS_CHUNK_UID_T		uid;
	u64			offset;
	u32			size;
	u32			iocontext;
	union {
		u64			_reserved;	/* For future extensions */
		u64			hole_mask;	/* Used only in REPLICATEX responces */
		u32			fiemap_count;	/* Used only in FIEMAP request, limit on number of extents to return */
	};
	struct pcs_cs_sync_data	sync;		/* Filled in all requests and responses */
	struct pcs_cs_sync_resp sync_resp[0];	/* Used only in response to write/sync */
} __attribute__((aligned(8)));


/* Maximal message size. Actually, random */
#define PCS_CS_MSG_MAX_SIZE	(1024*1024 + sizeof(struct pcs_cs_iohdr))

#define PCS_CS_READ_REQ		(PCS_RPC_CS_CLIENT_BASE)
#define PCS_CS_READ_RESP	(PCS_CS_READ_REQ|PCS_RPC_DIRECTION)

#define PCS_CS_WRITE_REQ	(PCS_RPC_CS_CLIENT_BASE + 2)
#define PCS_CS_WRITE_RESP	(PCS_CS_WRITE_REQ|PCS_RPC_DIRECTION)

#define PCS_CS_REPLICATE_REQ	(PCS_RPC_CS_CLIENT_BASE + 4)
#define PCS_CS_REPLICATE_RESP	(PCS_CS_REPLICATE_REQ|PCS_RPC_DIRECTION)

#define PCS_CS_SYNC_REQ		(PCS_RPC_CS_CLIENT_BASE + 6)
#define PCS_CS_SYNC_RESP	(PCS_CS_SYNC_REQ|PCS_RPC_DIRECTION)

#define PCS_CS_WRITE_SYNC_REQ	(PCS_RPC_CS_CLIENT_BASE + 8)
#define PCS_CS_WRITE_SYNC_RESP	(PCS_CS_WRITE_SYNC_REQ|PCS_RPC_DIRECTION)

struct pcs_cs_cong_notification {
	struct pcs_rpc_hdr	hdr;

	PCS_XID_T		xid;	/* XID of request triggered congestion notification */
} __attribute__((aligned(8)));

#define PCS_CS_CONG_NOTIFY	(PCS_RPC_CS_CLIENT_BASE + 10)

#define PCS_CS_WRITE_ZERO_REQ	(PCS_RPC_CS_CLIENT_BASE + 12)
#define PCS_CS_WRITE_ZERO_RESP	(PCS_CS_WRITE_ZERO_REQ|PCS_RPC_DIRECTION)

#define PCS_CS_WRITE_HOLE_REQ	(PCS_RPC_CS_CLIENT_BASE + 14)
#define PCS_CS_WRITE_HOLE_RESP	(PCS_CS_WRITE_HOLE_REQ|PCS_RPC_DIRECTION)

#define PCS_CS_REPLICATEX_REQ	(PCS_RPC_CS_CLIENT_BASE + 16)
#define PCS_CS_REPLICATEX_RESP	(PCS_CS_REPLICATEX_REQ|PCS_RPC_DIRECTION)

#define PCS_CS_FIEMAP_REQ	(PCS_RPC_CS_CLIENT_BASE + 18)
#define PCS_CS_FIEMAP_RESP	(PCS_CS_FIEMAP_REQ|PCS_RPC_DIRECTION)

////////////////////////////////////////////
//// from pcs_mds_cs_prot.h
//// required for PCS_CS_MAP_PROP_REQ/ping to work
struct pcs_cs_fs_info {
	u64	free_space;
	u64	total_space;
};

struct pcs_cs_node_desc {
	s32			state;	 /* CS_OBJ_XXX */
	u8			flags;	 /* CS_OBJF_XXX */
	u8			role;
	u16			csum_lo;
	u32			status;	 /* PCS_ERR_XXX filled in response */
	u16			csum_hi;
	u8			parent_idx; /* Index of parent in replica tree. Undefined for root. */
	u8			source_idx; /* Index of replication source for this replica */
	u64			dirty_mask; /* Initialized by CS before forwarding the map downstream */
	struct pcs_cs_info	info;	 /* CS id and address */
	struct pcs_cs_fs_info	fs_info; /* Filled by CS in response */
} __attribute__((aligned(8)));

struct pcs_cs_map_prop {
	struct pcs_mds_hdr	hdr;

	PCS_CHUNK_UID_T		chunk_uid;
	/* Messages with version less or equal to the current one (if available) will be ignored unless
	 * the CS_MAPF_PING flag is set. Otherwise the version is ignored as well as chunk state/flags.
	 */
	PCS_MAP_VERSION_T	version;
	/* During replication this version indicates the newest dirty mask version allowed to be using for recovery. */
	PCS_MAP_VERSION_T	dirty_version;
	u32			flags;	/* CS_MAPF_XXX */
	u32			chunk_size;
	/* The maximum number of nodes in the chain. Intended to be using in timeout calculation. */
	u16			chain_nodes;
	u16			reserved;
	u32			nnodes;
	struct pcs_cs_node_desc	nodes[0];
} __attribute__((aligned(8)));

#define CS_OBJ_UNKNOWN		-1
#define CS_MAPF_PING		0x1000
#define PCS_CS_MAP_PROP_REQ	(PCS_RPC_CS_CS_BASE + 2)
#define PCS_CS_MAP_PROP_RESP	(PCS_CS_MAP_PROP_REQ | PCS_RPC_DIRECTION)
//////////////////////////////////////////// end pcs_mds_cs_prot.h


#endif /* _PCS_CS_PROT_H_ */
