#ifndef _PCS_MDS_PROT_H_
#define _PCS_MDS_PROT_H_ 1

#include "pcs_rpc_prot.h"


/* This file contains client interface to MDS.
 */

/* ---- limits */

#define PCS_MDS_MAX_MSG_SIZE		0x21000 /* So we can transfer fuse request in single message */
#define PCS_MDS_MAX_RESP_MSG_SIZE	PCS_MDS_MAX_MSG_SIZE
#define PCS_MDS_MAX_PATH		0x10000

/* ---- basic structures */

/* The generation value represents the last paxos commit number. It is sent back and forth
 * to the client to ensure the mds already have all commits necessary to process client request.
 * Such approach guarantees consistency even if several mds are processing client requests in parallel.
 */

typedef u64 PCS_MDS_GEN_T;

#define PCS_MDS_GEN_UNDEFINED 0

/* signof(v1 - v2), -1 if v1 is older than v2 */
static inline int mds_gen_compare(PCS_MDS_GEN_T v1, PCS_MDS_GEN_T v2)
{
	if (v1 == PCS_MDS_GEN_UNDEFINED || v2 == PCS_MDS_GEN_UNDEFINED)
		return 0;
	if ((s64)(v1 - v2) < 0)
		return -1;
	return 0;
}

/* Common header of all messages */
struct pcs_mds_hdr
{
	struct pcs_rpc_hdr	h;
	PCS_MDS_GEN_T		mds_gen;
	PCS_CONFIG_SEQ_T	cfg_version;
	u32			cluster_version;
	u32			flags; /* PCS_MDS_F_XXX */
	u32			reserved;
} __attribute__((aligned(8)));

/* Request header flags */
#define PCS_MDS_F_IS_MASTER   1	    /* Set on reply if server is master */
#define PCS_MDS_F_NEED_MASTER 2	    /* Request will fail with PCS_ERR_MDS_NOT_MASTER error if server is not master */
#define PCS_MDS_F_CLNT_VERSION 0x80 /* Client supply its version in the message */
/* Check client version (passed in cluster_version) is not less than the cluster version.
 * Returns PCS_ERR_CLNT_VERSION otherwise. */
#define PCS_MDS_F_CHK_VERSION 0x100

/*
 * CS information
 */

typedef u16 pcs_cs_io_prio_t;
typedef u8  pcs_cs_net_prio_t;

/* CS info flags */
enum {
	CS_FL_LOCAL	  = 1,	  /* CS is on the same host as the client */
	CS_FL_LOCAL_SOCK  = 2,	  /* CS listens on local socket */
	CS_FL_INACTIVE	  = 0x10, /* CS is not sending pings for some time */
	CS_FL_REPLICATING = 0x20, /* This CS is replicating this map */
	CS_FL_FAILED	  = 0x40, /* This CS has failed */
	CS_FL_ROLE	  = 0xFF00,/* Role of this CS in raid array, 0..depth-1 are data chunks, the rest are syndrome */
	CS_FL_ROLE_LOG	  = 8,
};

#define CS_FL_ROLE_GET(flags) (((flags) & CS_FL_ROLE) >> CS_FL_ROLE_LOG)
#define CS_FL_ROLE_FLAGS(role) (CS_FL_ROLE & ((role) << CS_FL_ROLE_LOG))

struct pcs_cs_info {
	/* CS node id */
	PCS_NODE_ID_T		id;
	/* Integrity sequence number updated every time the CS restarts without properly flushing all client's data */
	PCS_INTEGRITY_SEQ_T	integrity_seq;
	/* Access priority (higher values are preferable) based on the IO activity, 0 means unknown */
	pcs_cs_io_prio_t	io_prio;
	/* Network priority (higher values are preferable) based on the network distance, 0 means unknown */
	pcs_cs_net_prio_t	net_prio;
	/* QoS level of this CS (higher values are preferable) */
	u8			qos;
	/* Flags (CS_FL_XXX) */
	u32			flags;
	u32			reserved;
	/* Primary network address */
	PCS_NET_ADDR_T		addr;
} __attribute__((aligned(8)));

struct pcs_cs_addr_info
{
	PCS_NODE_ID_T		id;
	PCS_INTEGRITY_SEQ_T	integrity_seq;
	u32			naddr;
	PCS_NET_ADDR_T		addr[1];
} __attribute__((aligned(8)));

/* ---- connection request
 * The following structure serves as a payload for RPC connect messages to deliver MDS server list to the client.
 */

#define PCS_MDS_CONNECT_PAYLOAD PCS_RPC_APP_PAYLOAD_BASE

struct pcs_mds_node_info {
	PCS_NODE_ID_T	id;
	PCS_NET_ADDR_T	addr;
} __attribute__((aligned(8)));

struct pcs_mds_conn_payload
{
	PCS_MDS_GEN_T		mds_gen;	 /* The last commit sequence number */
	PCS_MASTER_GENID_T	mds_master_ver;	 /* The mds epoch number (see master field of PCS_MAP_VERSION_T) */
	u16			mds_list_len;	 /* The number of MDSes in list */
	s16			mds_master_idx;	 /* The index of the master in the list (negative means no master is known) */
	struct pcs_mds_node_info mds_list[1];	  /* The list of MDS */
} __attribute__((aligned(8)));

/* ---- chunk server resolution request/response
 * Client issues it to resolve server ID to network address
 * The message is the same for request and response
 */

#define PCS_MDS_CS_RESOLVE_REQ	(PCS_RPC_MDS_CLIENT_BASE + 0x20)
#define PCS_MDS_CS_RESOLVE_RESP	(PCS_MDS_CS_RESOLVE_REQ | PCS_RPC_DIRECTION)

struct pcs_mds_cs_resolve_msg
{
	struct pcs_mds_hdr	hdr;
	struct pcs_cs_addr_info	info; /* in/out */
} __attribute__((aligned(8)));

/* ---- lease requests
 * Lease provides the mechanism for mutual exclusion of the operations referencing the particular name. The name for
 * which the lease is being requested may or may not refer to the existing file. Getting exclusive lease for non yet existing
 * file is required to ensure exclusive file creation semantic.
 *
 * Once the lease is granted it must be updated periodically by the client alive requests and released ultimately. Failing
 * to release exclusive lease by the client will have strong performance impact since the MDS will take care to stop corresponding
 * IO operations if the file will be lately accessed by another client.
 *
 * The message type is pcs_mds_lease_msg (same for request and response). If the lease can not be acquired the pcs_rpc_error_resp
 * will be returned.
 */

#define PCS_MDS_LEASE_REQ	(PCS_RPC_MDS_CLIENT_BASE + 2)
#define PCS_MDS_LEASE_RESP	(PCS_MDS_LEASE_REQ | PCS_RPC_DIRECTION)

/* Lease flags. */
enum
{
/* Release lease if being held. */
	PCS_LEASE_NONE = 0,
/* Shared lease. May be acquired for reading (not mandatory though). */
	PCS_LEASE_SHARED,
/* Exclusive lease. Mandatory for file creation, deletion, rename, truncation, resizing and write access. */
	PCS_LEASE_EXCL,
/* Lease type mask */
	PCS_LEASE_TYPE_MASK = PCS_LEASE_SHARED|PCS_LEASE_EXCL,
/* Just refresh the lease. Return error if the lease wasn't exist prior to the call. */
	PCS_LEASE_REFRESH = 0x10,
/* Use timeout from the message instead of the system-wide. */
	PCS_LEASE_CUSTOM_TOUT = 0x20,
/* Update all leases granted to the client. The name argument is ignored. If set no other flags are allowed. */
	PCS_LEASE_ALIVE = 0x100,
/* Release all leases granted to the client. The name argument is ignored. */
	PCS_LEASE_DROP_ALL = 0x200,
/* Query file existence. Just saves one file message in some common use cases. */
	PCS_LEASE_QUERY_FILE = 0x1000,
/* Update file modification time */
	PCS_LEASE_UP_FILE_MTIME = 0x2000,
/* Enforce strict path checking on file lookup.
 * If it is set an attempt to lookup file with dir object lacking in the path will fail with PCS_ERR_NOT_FOUND error.
 */
	PCS_LEASE_POSIX_PATH = 0x10000,
/* The following bits are reserved, they can't be set by the client. */
	PCS_LEASE_RESERVED_ = 0xff000000,
};

/* Result flags */
enum
{
	PCS_LRES_GRANTED  = 0x1,
	PCS_LRES_RELEASED = 0x2,
/* File exists flag. The file existence is being checked if PCS_LEASE_QUERY_FILE is set on input.
 * If the flag is set the file_id is valid on output.
 */
	PCS_LRES_FILE_EXISTS = 0x100,
/* The lease ID is returned (for compatibility with old code) */
	PCS_LRES_ID_VALID    = 0x200,
};

struct pcs_mds_lease_msg
{
	struct pcs_mds_hdr	hdr;
	u32			flags;	  /* request flags */
	u32			result;	  /* result flags */
	u32			tout;	  /* Lease expiration timeout (in milliseconds) on output.
					   * May be specified on input with PCS_LEASE_CUSTOM_TOUT flag.
					   * Client may use custom timeout to create lease with shorter lifetime than
					   * the default one.
					   */
	u32			reserved;
	struct pcs_mds_fileinfo	finfo;	  /* file info (valid on output if PCS_LRES_FILE_EXISTS result flag is set) */
	union {
		PCS_FILE_ID_T	root;	  /* root dir ID on input */
		PCS_FILE_ID_T	lease_id; /* lease inode id on output */
	};
	struct pcs_path		name;	  /* path relative to the root dir */
} __attribute__((aligned(8)));

/*
 * Refresh the list of leases identified by their IDs. The requet message type is struct pcs_mds_lease_refresh_msg.
 * The request will always succeed returning just pcs_mds_hdr.
 */

#define PCS_MDS_LEASE_REFRESH_REQ	(PCS_RPC_MDS_CLIENT_BASE + 10)
#define PCS_MDS_LEASE_REFRESH_RESP	(PCS_MDS_LEASE_REFRESH_REQ | PCS_RPC_DIRECTION)

struct pcs_mds_lease_refresh_msg
{
	struct pcs_mds_hdr	hdr;
	u64			reserved;
	u32			nfailed;     /* The number of leases that were failed to refresh */
	u32			nleases;     /* The number of lease ID that follows */
	PCS_FILE_ID_T		lease_id[0]; /* The array of lease ID to refresh */
} __attribute__((aligned(8)));

/* ---- file request
 * Supports file create, rename, delete and query operations.
 * The file model assumes that every file has single name as well as fixed length ID assigned to it by MDS itself. The file create and rename
 * operations are made immune to MDS crashes so they can be safely restarted by the client. The MDS is using the client ID to detect restarted
 * operations so the client must ensure its uniqueness.
 *
 * The file attributes are filled on output whenever the file is referenced. The replication and optionally size (with PCS_FFL_RESIZE flag)
 * attributes may be used on input as well. The operation to be done is defined by the combination of the op and flags fields.
 *
 * The message type is pcs_mds_file_msg (same for request and response). On failure the pcs_rpc_error_resp will be returned.
*/

#define PCS_MDS_FILE_REQ	(PCS_RPC_MDS_CLIENT_BASE + 4)
#define PCS_MDS_FILE_RESP	(PCS_MDS_FILE_REQ | PCS_RPC_DIRECTION)

/* File map type (storage type) */
enum
{
	PCS_MAP_PLAIN = 0, /* Plain replicas */
	PCS_MAP_RAID6 = 1, /* RAID6 encoded replicas */
	PCS_MAP_RS    = 2, /* Reed-Solomon encoded replicas */
	PCS_MAP_PLAIN_LOGSTREAM = 3, /* PCS_MAP_PLAIN, but LOGSTREAM is to be used */
	/* Combined map types are implemented by the client as a collection of files placed in
	 * the container directory - see PCS_FATTR_CONTAINER.
	 */
	PCS_MAP_COMBINED = 0x80,
	PCS_MAP_LS = PCS_MAP_COMBINED, /* Log structured storage */
};

/* Max inline file size */
#define PCS_MAX_INLINE_SIZE 0x100000 /* 1Mb */

/* File operation. It determines the treatment of the file name and ID parameters in the message. */
enum
{
/* Identify file by its ID. May be used to update file attributes depending on other flags.
 * Combined with PCS_FFL_DELETE will delete the file.
 */
	PCS_FOP_TOUCH = 0,
/* Similar to TOUCH but identify file by name, setting ID on output.
 */
	PCS_FOP_RESOLVE,
/* Rename the file with specified ID. The exclusive lease on both the current file name and the new one is required.
 * If the file with new name exists it will be replaced. If the client wants to ensure
 * exclusive rename semantic it must check the target existence first (via pcs_mds_lease_msg message). Fails if
 * the file with requested ID does not exists. Note that rename operation will succeed if restarted.
 */
	PCS_FOP_RENAME,
/* Rename file replacing the existing target identified by info.attr.id renaming the target
 * at the same time. The source file is identified by info.attr.src_id.
 * This operation is intended to use in scenarios when the file being deleted as
 * a result of the rename operation is open by the client and should be renamed onto the
 * temporary file.
 */
	PCS_FOP_REPLACE,
};

/* File operation flags */
enum
{
/* Update existing file size.
 * Valid with PCS_FOP_TOUCH, PCS_FOP_RESOLVE operations.
 * The exclusive lease on the file is required.
 */
	PCS_FFL_RESIZE = 1,

/* Create file if not yet exists. Valid with PCS_FOP_RESOLVE operation.
 * The exclusive lease on the file name is required. If the client wants to ensure exclusive
 * creation semantic it must check it existence first (via pcs_mds_lease_msg message).
 * Note that create operation will succeed if restarted. If the object is already created it will
 * be leave intact, the response will contain it attributes.
*/
	PCS_FFL_CREATE = 0x10,

/* Create file in container with specific map type (see PCS_MAP_XXX) passed in message as info.repl.policy.create_type.
 * The lease may be acquired at the container level.
 */
	PCS_FFL_CREATE_IN_CONTAINER = 0x20,

/* Delete the file being referenced. Valid with PCS_FOP_TOUCH, PCS_FOP_RESOLVE.
 * The exclusive lease on the file is required. Not compatible with any other flags.
 * Note that delete operation will succeed if restarted.
 */
	PCS_FFL_DELETE = 0x100,

/* Enforce strict path checking. If the flag is set:
 *     - an attempt to create or resolve file with dir object lacking in the path will fail with PCS_ERR_NOT_FOUND error
 *     - an attempt to delete or rename object with child objects will fail with PCS_ERR_NON_EMPTY_DIR error
 */
	PCS_FFL_POSIX_PATH = 0x10000,

/* Recursive action */
	PCS_FFL_RECURSIVE = 0x100000,
};

/* File operation result */
enum {
	PCS_FRES_FILE_CREATED  = 0x1,
	PCS_FRES_FILE_RENAMED  = 0x2,
	PCS_FRES_FILE_DELETED  = 0x8,
/* Note that upon replacing the existing file on rename both PCS_FRES_FILE_RENAMED and PCS_FRES_FILE_DELETED will be set. */
};

struct pcs_mds_file_msg
{
	struct pcs_mds_hdr	hdr;
	u32			op;
	u32			flags;
	u32			result;
	u32			reserved;
	PCS_FILE_ID_T		root; /* root dir ID on input */
	struct pcs_mds_fileinfo info; /* file info */
	struct pcs_path		name; /* the path relative to the root */
} __attribute__((aligned(8)));

/* The aligned size of the pcs_path structure with 1 byte reserved for terminating 0.
 * Note that the client is not required to zero-pad strings though the strings returned
 * by MDS are always zero padded.
 */
#define PCS_MDS_FILENAME_SZ_ALIGN(sz)  PCS_PATH_SZ_ALIGN(sz)
#define PCS_MDS_FILENAME_SZ_ALIGNED(n) PCS_PATH_SZ_ALIGNED(n)

/* ---- file attributes request
 * Get/set the particular file attributes with optional possibility to apply them recursively.
 * The message may contain data of arbitrary size depending on the op parameter.
 * The valid_mask parameter may contain the bitmask of the individual valid data attributes.
 * Some operations may support getting/setting parameters of the filesystem root which is
 * equivalent to changing global configuration with optional possibility to apply new
 * settings to all existing files.
 */

#define PCS_MDS_FATTR_REQ	(PCS_RPC_MDS_CLIENT_BASE + 6)
#define PCS_MDS_FATTR_RESP	(PCS_MDS_FATTR_REQ | PCS_RPC_DIRECTION)

struct pcs_mds_fattr_msg
{
	struct pcs_mds_hdr	hdr;
	u32			op;	      /* PCS_FA_XXX */
	u32			reserved;     /* currently 0 */
	union {
		u64		valid_mask;   /* bitmask of valid attributes */
		struct {
			/* The offset and the size of the addressed data range. Used for associated
			 * data addressing (PCS_FA_DATA). Otherwise ignored.
			 */
			u32	attr_offset;
			u32	attr_size;
		};
	};
	PCS_FILETIME_T		modify_ts;    /* modification time if appropriate */
	/* the following field is reserved for the case when we can have more than one version of the attribute data structure */
	u32			data_version; /* currently 0 */
	u32			data_size;    /* the size in bytes of the attribute data */
	PCS_FILE_ID_T		root;	      /* root dir ID on input */
	struct pcs_path		name;	      /* the path relative to the root */
	/*
	 * The offset of the data relative to the name is PCS_MDS_FILENAME_SZ_ALIGNED(name)
	 */
};

/* The op field content */
enum {
	PCS_FA_SET	   = 0x80000000,       /* Set attributes */
	PCS_FA_RECURSIVE   = 0x40000000,       /* Set recursively */
	PCS_FA_BY_ID	   = 0x20000000,       /* Identify file by ID, path is ignored. Use it with root=0 to adress the root itself. */
	PCS_FA_MASK_	   = (PCS_FA_BY_ID-1), /* The bitmask for attribute type */
	/* File attributes (set only). Currently only PCS_FATTR_INLINE may be set/cleared and only on the directory. */
	PCS_FA_ATTRIB = 0x1,
	/* Associated data. The file must have PCS_FATTR_INLINE attribute. The total size of the data equals to the size of the file. */
	PCS_FA_DATA = 0x10,
	/* System attributes represented by struct pcs_mds_sys_info (set only) */
	PCS_FA_SYS = 0x80,
	/* Replication attributes represented by struct pcs_mds_repl_info (set only) */
	PCS_FA_REPL = 0x100,
	/* Hot hosts represented by struct pcs_mds_hot_hosts (get only) */
	PCS_FA_HOT_HOSTS = 0x200,
	/* Don't set anything, just drop all leases */
	PCS_FA_DROP_LEASES = 0x10000,
	/* .. whatever you need .. */
};

/* Valid mask for system attributes (PCS_FA_SYS) */
enum {
	PCS_FA_SYS_MAP_TYPE	= 0x1,
	PCS_FA_SYS_CHUNK_SIZE	= 0x10,
	PCS_FA_SYS_STRIPE_DEPTH = 0x100,
	PCS_FA_SYS_REDUNDANCY	= 0x200,
	PCS_FA_SYS_TOLERANCE	= 0x400,
	PCS_FA_SYS_STRIP_WIDTH	= 0x1000,
};

/* Valid mask for replication attributes (PCS_FA_REPL) */
enum {
	PCS_FA_REPL_REPLICAS  = 1,
	PCS_FA_REPL_PLACEMENT = 0x10,
	PCS_FA_REPL_QOS	      = 0x100,
};

#define PCS_N_HOT_HOSTS 8

/* Hot hosts structure */
struct pcs_mds_hot_hosts {
	struct {
		PCS_NODE_ID_T	id;
		u64		nrepl;
	} host[PCS_N_HOT_HOSTS];
} __attribute__((aligned(8)));

/* ---- read dir request
 * Read directory.
 * The directory information is maintained by MDS treating / as path separator.
 * The following paths are considered identical: /a/b, /a/b/, a/b, a//b
 *
 * The message type is pcs_mds_readdir_msg (same for request and response). On failure the pcs_rpc_error_resp will be returned.
 */

#define PCS_MDS_READDIR_REQ	(PCS_RPC_MDS_CLIENT_BASE + 8)
#define PCS_MDS_READDIR_RESP	(PCS_MDS_READDIR_REQ | PCS_RPC_DIRECTION)

/* The dir entry flags */
enum {
	/* The entry corresponds to the file */
	PCS_DFL_FILE = 1,
	/* The entry corresponds to the directory (file with PCS_FATTR_DIR) */
	PCS_DFL_DIR  = 2,
	/* The entry has child objects */
	PCS_DFL_HAS_CHILDREN = 4,
	/* The entry corresponds to symlin (file with PCS_FATTR_LINK) */
	PCS_DFL_LINK = 8,
	/* The entry is storage container */
	PCS_DFL_CONTAINER = 0x40,
	/* The dir end marker, the name is empty */
	PCS_DFL_END  = 0x100,
	/* Entry is using extended format */
	PCS_DFL_EX_INFO = 0x10000,
	/* Entry is followed by symlink target */
	PCS_DFL_EX_LINK = 0x20000
};

struct pcs_mds_dentry
{
	u32			flags;
	u32			reserved;
	PCS_FILE_ID_T		id;
	struct pcs_path		name;
} __attribute__((aligned(8)));

#define PCS_MDS_DENTRY_SZ(d)	     (offsetof(struct pcs_mds_dentry, name.str) + (d).name.sz)
#define PCS_MDS_DENTRY_SZ_ALIGN(sz)  (offsetof(struct pcs_mds_dentry, name) + PCS_MDS_FILENAME_SZ_ALIGN(sz))
#define PCS_MDS_DENTRY_SZ_ALIGNED(d) (offsetof(struct pcs_mds_dentry, name) + PCS_MDS_FILENAME_SZ_ALIGNED((d).name))

struct pcs_mds_dentry_ex
{
	u32			flags;
	u32			reserved;
	struct pcs_mds_fileinfo	info;
	struct pcs_path		name;
} __attribute__((aligned(8)));

#define PCS_MDS_DENTRY_EX_SZ(d)		(offsetof(struct pcs_mds_dentry_ex, name.str) + (d).name.sz)
#define PCS_MDS_DENTRY_EX_SZ_ALIGN(sz)	(offsetof(struct pcs_mds_dentry_ex, name) + PCS_MDS_FILENAME_SZ_ALIGN(sz))
#define PCS_MDS_DENTRY_EX_SZ_ALIGNED(d) (offsetof(struct pcs_mds_dentry_ex, name) + PCS_MDS_FILENAME_SZ_ALIGNED((d).name))

/* The request flags */
enum {
/* The directory is identified by its ID, the path argument is ignored
 */
	PCS_READDIR_BY_ID = 0x100,
/* Enforce strict path checking on path lookup.
 * If it is set:
 *    - an attempt to resolve path with dir object lacking will fail with PCS_ERR_NOT_FOUND error
 *    - an attempt to resolve not a directory will fail with PCS_ERR_NOT_DIR error
 *    - child entries without dir/file objects wont be returned
 */
	PCS_READDIR_POSIX_PATH = 0x10000,
/* Query extended info - returns pcs_mds_dentry_ex structures.
 */
	PCS_READDIR_EX_INFO = 0x100000,
/* Pack links target right after extended info.
 */
	PCS_READDIR_EX_LINKS = 0x200000,
};

struct pcs_mds_readdir_msg
{
	struct pcs_mds_hdr	hdr;
	/* (in) The maximum number of entries to return, 0 - no limit */
	u32			dent_max;
	/* (in/out) The number of entries that follows */
	u32			dent_cnt;
	/* (in) The number of entries to skip */
	u32			dent_skip;
	/* (in) The limit on the message size in bytes, 0 - no limit */
	u32			max_size;
	/* (in) Flag bits */
	u32			flags;
	/* Reserved for future use */
	u32			reserved;
	/* (in) root dir ID or the directory ID if PCS_READDIR_BY_ID flag is set */
	PCS_FILE_ID_T		root;
	/* (in) The path relative to the root (ignored if PCS_READDIR_BY_ID flag is set) */
	struct pcs_path		path;
	/* After the end of the path the number of pcs_mds_dentry are being placed sequentially with 8 byte alignment,
	 * see PCS_MDS_FILENAME_SZ_ALIGNED, PCS_MDS_DENTRY_SZ_ALIGNED, PCS_MDS_FIRST_DENTRY_OFFSET for details.
	 * In case there are more than dent_max-1 entries in the dir referred by path or max_size limit is exceeded
	 * the directory content may be returned by several calls. Every next call may either specify the dent_skip
	 * count or pass the last returned entry as the single element of the pcs_mds_dentry list on input.
	 * Either dent_max or max_size must have nonzero values on input. The response may have zero dent_cnt
	 * only in case the max_size is too small for the dentry to be returned.
	 */
} __attribute__((aligned(8)));

#define PCS_MDS_FIRST_DENTRY_OFFSET(msg) (offsetof(struct pcs_mds_readdir_msg, path) + PCS_MDS_FILENAME_SZ_ALIGNED((msg).path))

/* ---- chunk map request/response
 * Before client may start IO the replication path must be set up.
 * Client will be given the map version and the id of the chunk server the IO
 * messages must be sent to. All other details are hidden inside MDS to CS protocol.
 * In case the IO request returns error the client must set last_err accordingly identifying
 * failed CS by offender field, request new map and restart failed IO operation.
 *
 * The message type is pcs_mds_map_msg (same for request and response).
 */

#define PCS_MDS_MAP_REQ		(PCS_RPC_MDS_CLIENT_BASE + 0x10)
#define PCS_MDS_MAP_RESP	(PCS_MDS_MAP_REQ | PCS_RPC_DIRECTION)

/*
 * Mode bits
 */
#define PCS_MDS_MAP_MODE_READ	1
#define PCS_MDS_MAP_MODE_WRITE	2
/*
 * The retry bit must be set in case we are requesting the map after IO failure.
 * The corresponding last_err, offender, version and root fields must be set in such case in accordance to the failed map.
 */
#define PCS_MDS_MAP_RETRY 0x100
/* The dirty bit must be set when client completed some write, but it is still not synced */
#define PCS_MDS_MAP_DIRTY 0x200
/* "new" bit is set by client on RAID maps, which require allocation of new chunk. In this case
 * "chunk_size" usually uninitialized by client defines size of chunk to be allocated by MDS.
 * NOTE: all map requests on the last chunk may have "chunk_size" non-zero and this means
 * client wishes to expand the last chunk.
 */
#define PCS_MDS_MAP_NEW	  0x400
/* This bit is set by client in request, if it contains physical size of chunk for CS.
 * It is used when MDS cannot calculate size of chunk on CS only from logical chunk size,
 * which is the case for RAID encoded files with variable strip size. Unless this bit is set,
 * physical size of chunk on CS is calculated from logical chunk size by formulae already
 * implemented in MDS.
 *
 * MDS sets this flag when it returns physical size of chunk in "psize_ret", otherwise
 * this flag must be cleared in messages in MDS->client direction. Normally, MDS should
 * return "psize_ret" when it has chunk_psize in hands.
 */
#define PCS_MDS_MAP_PSIZE 0x800

/* Dirty chunk size is 1M to cover 64M chunk with 64 bits. */
#define PCS_DIRTY_CHUNK_SIZE	(1024*1024)

/* Map flags */
#define PCS_MDS_MAP_ZERO_CHUNK	1	/* The chunk is not yet allocated, valid in response to read-only requests */

struct pcs_mds_map_msg
{
	struct pcs_mds_hdr	hdr;
	PCS_CHUNK_ID_T		chunkid;	/* The chunk id (file ID, offset pair) - must be provided on input */
	u16			mode;		/* read/write mode and other client supplied flags */
	u16			flags;		/* flags set by the server (replicating) */
	union {
		u32		last_err;	/* last error returned by CS if requesting map on IO retry (in) */
		u32		psize_ret;	/* length of chunk on CS (out) */
	};
	PCS_NODE_ID_T		offender;	/* the failed CS id on retry */
	PCS_MAP_VERSION_T	version;	/* in (on retry) / out */
	PCS_CHUNK_UID_T		uid;		/* chunk unique id on out */
	union {
		u32		read_tout;	/* read	 timeout (msec) on out */
		u32		chunk_psize;	/* physical size of chunk on CS on in */
	};
	u32			write_tout;	/* write timeout (msec) on out */
	struct pcs_cs_info	root;		/* in (on retry) / out */
	union {
		struct {
			u32	chunk_size;	/* The chunk size */
			u32	child_cs_cnt;	/* The number of non-root CS entries that follows */
		};
		u64		zero_chunk_size;/* Size of hole, valid with PCS_MDS_MAP_ZERO_CHUNK */
	};
	/* The list of non-root chunk servers. Any of them may be used as the target for read requests */
	struct pcs_cs_info	child_cs_list[0];

} __attribute__((aligned(8)));

/* known types for ID generators */
enum {
	MDS_MID_GEN_TYPE = 0,
	MDS_CSID_GEN_TYPE,
	MDS_CID_GEN_TYPE,
};

/* ---- monitor mds state
 */

#define PCS_MDS_MONITOR_REQ		(PCS_RPC_MDS_CLIENT_BASE + 0x14)
#define PCS_MDS_MONITOR_RESP		(PCS_MDS_MONITOR_REQ | PCS_RPC_DIRECTION)

#define PCS_PERFCNT_MAXSIZE		PCS_MDS_MAX_RESP_MSG_SIZE

enum
{
	PCS_PC_GEN_UPTIME		= 1, /* Milliseconds since program start */
	PCS_PC_GEN_BUILD_VERSION	= 2, /* Build version string */
	PCS_PC_GEN_LOAD			= 4, /* Activity time in msec */
	PCS_PC_GEN_VERSION		= 5, /* MDS's version */

	PCS_PC_LJ_TX_COUNT		= 0x10, /* The local journal transaction count / rate */
	PCS_PC_LJ_TX_TOTAL_SZ		= 0x11, /* The local journal transaction total size / rate */
	PCS_PC_LJ_COMMIT_COUNT		= 0x12, /* The local journal commit count / rate */
	PCS_PC_LJ_WRITE_TOTAL		= 0x13,	/* The total time spent writing the local journal (msec) */
	PCS_PC_LJ_WRITE_TIME		= 0x14,	/* The mean local journal transaction writing time (msec) */

	PCS_PC_RJ_STATUS		= 0x20, /* RJ_STATE_XXX, see rjournal.h */
	PCS_PC_RJ_ROUND			= 0x21, /* transaction number */
	PCS_PC_RJ_MASTER_KNOWN		= 0x22, /* is master known? */
	PCS_PC_RJ_MASTER_ID		= 0x23, /* master node id */
	PCS_PC_RJ_MASTER_EPOCH		= 0x24, /* master generation number */
	PCS_PC_RJ_MASTER_UPTIME		= 0x25, /* time since last master change (ms) */
	PCS_PC_RJ_NODES_STATE		= 0x26, /* paxos node's state */

	PCS_PC_REPL_NORM		= 0x31, /* normal number of replicas */
	PCS_PC_REPL_LIMIT		= 0x32, /* minimal number of replicas,
						   one cannot write to a chunk
						   that has less or equal
						   number of replicas */
	PCS_PC_REPL_MAX			= 0x33, /* maximum number of replicas */

	PCS_PC_CL_VERSION		= 0x40, /* MDS cluster version */
	PCS_PC_CL_TOTAL_SPACE_TIER	= 0x41, /* total space per tier */
	PCS_PC_CL_FREE_SPACE_TIER	= 0x42, /* free space per tier */
	PCS_PC_CL_TOTAL_EFFECTIVE_TIER	= 0x43, /* effective total space available for chunks allocation in tier */
	PCS_PC_CL_AVAIL_SPACE_TIER	= 0x44, /* the amount of free space available for chunks allocation in tier */

	PCS_PC_CL_TOTAL_EFFECTIVE_X	= 0x45, /* effective total space matrix per tier and locality */
	PCS_PC_CL_AVAIL_SPACE_X		= 0x46, /* effective available space matrix per tier and locality */

	PCS_PC_CL_STOR_VERSION		= 0x50, /* storage cluster version */
	PCS_PC_CL_TOTAL_SPACE		= 0x51, /* total space in the cluster */
	PCS_PC_CL_FREE_SPACE		= 0x52, /* free space in the cluster */
	PCS_PC_CL_AVAIL_SPACE		= 0x53, /* the amount of free space available for chunks allocation in the cluster */
	PCS_PC_CL_TOTAL_EFFECTIVE	= 0x54, /* effective total space available for chunks allocation in the cluster */
	PCS_PC_CL_AVAIL_RAW		= 0x55, /* same as PCS_PC_CL_AVAIL_SPACE but ignoring license limitations */
	PCS_PC_CL_TOTAL_RAW		= 0x56, /* same as PCS_PC_CL_TOTAL_EFFECTIVE but ignoring license limitations */

	PCS_PC_CL_STATUS		= 0x58, /* cluster status (pcs_cluster_status_t) */

	PCS_PC_CL_NODES			= 0x60, /* CS count */
	PCS_PC_CL_NODES_ACTIVE		= 0x61, /* count of CSs that send pings */
	PCS_PC_CL_NODES_INACTIVE	= 0x62, /* inactive CS count */
	PCS_PC_CL_NODES_OFFLINE		= 0x63, /* offline CS count */
	PCS_PC_CL_NODES_DROPPED		= 0x64, /* count of CSs dropped by administrator */
	PCS_PC_CL_NODES_AVAIL		= 0x68, /* available for allocation CS count */
	PCS_PC_CL_NODES_REPLICATING	= 0x69, /* nodes participating in cooperative replication */
	PCS_PC_CL_AVER_COST		= 0x6a, /* the average allocation cost for available CS */
	PCS_PC_CL_NODES_FAILED		= 0x6b, /* failed CS nodes count */
	PCS_PC_CL_NODES_NOSPACE		= 0x6c, /* count of CS nodes without space available for allocation */
	PCS_PC_CL_NODES_HOT		= 0x6d, /* count of CS nodes considered hot */

	/* cluster chunk info */
	PCS_PC_CL_CHUNKS_VOID		= 0x70, /* unused chunks */
	PCS_PC_CL_CHUNKS_PENDING	= 0x71, /* top priority queue for replication, chunk is blocked, client is waiting */
	PCS_PC_CL_CHUNKS_BLOCKED	= 0x72, /* have too few replicas, writing is impossible */
	PCS_PC_CL_CHUNKS_URGENT		= 0x73, /* chunks that have limit replicas */
	PCS_PC_CL_CHUNKS_DEGRADED	= 0x74, /* chunks that have > limit and < normal replicas */
	PCS_PC_CL_CHUNKS_STANDBY	= 0x75, /* chunks with temporary standby replicas */
	PCS_PC_CL_CHUNKS_HEALTHY	= 0x76, /* chunks that have >= normal and <= max replicas */
	PCS_PC_CL_CHUNKS_OVERCOMMITTED	= 0x77, /* chunks that have > max replicas */
	PCS_PC_CL_CHUNKS_REPLICATING	= 0x78, /* chunks that replicate now */
	PCS_PC_CL_CHUNKS_OFFLINE	= 0x79, /* chunks that have no replicas */
	PCS_PC_CL_REPL_DELETING		= 0x7a, /* replicas queued for deletion */
	PCS_PC_CL_CHUNKS_REPLICATED	= 0x7b,	/* the replicated chunks total / rate */
	PCS_PC_CL_CHUNKS_REBALANCE_TOTAL= 0x7c, /* the total number of chunks being rebalanced (including committing) */
	PCS_PC_CL_CHUNKS_REBALANCE_COMM = 0x7d, /* the number of rebalanced chunks being committed */
	PCS_PC_CL_CHUNKS_REPLICATE	= 0x7e, /* the number of replicas to add on replication */
	PCS_PC_CL_CHUNKS_UNIQUE		= 0x7f, /* the number of chunks with single replica */

	PCS_PC_REQ_IN			= 0x81, /* number of input requests */
	PCS_PC_REQ_OUT			= 0x82, /* number of output request */
	PCS_PC_REQ_IN_ERR		= 0x84, /* number of input requests with errors */
	PCS_PC_REQ_IN_ERR_CODE		= 0x85, /* code of the last error */
	PCS_PC_REQ_IN_ERR_UPTIME	= 0x86, /* time since last error (ms) */
	PCS_PC_REQ_IN_LATENCY		= 0x87, /* avg processing time (ms) */
	PCS_PC_REQ_IN_COMMIT_LATENCY	= 0x88, /* avg processing time for requests updating metadata (ms) */
	PCS_PC_REQ_IN_MAP_LATENCY	= 0x89, /* avg processing time for map requests (ms) */
	PCS_PC_REQ_PENDING		= 0x8e, /* number of requests being currently processed */

	PCS_PC_LEASE_CNT		= 0x101, /* number of currently active leases */
	PCS_PC_LEASE_CLIENTS		= 0x103, /* number of clients that have leases */

	PCS_PC_FS_TOTAL_SIZE		= 0x110, /* Total size of all files in bytes */
	PCS_PC_FS_INODES		= 0x111, /* inode count */
	PCS_PC_FS_FILES			= 0x112, /* file count */
	PCS_PC_FS_FILE_MAPS		= 0x113, /* file map count */
	PCS_PC_FS_CHUNK_MAPS		= 0x114, /* chunk map count */
	PCS_PC_FS_CHUNK_NODES		= 0x115, /* number of all replicas of all chunks */

	PCS_PC_STOR_STAT		= 0x200, /* struct pcs_perf_stor_stat */

	/* cluster ops info */
	/* rates are calculated in 5s intervals, every rate is a tuple:
	 * (1) total number of events, (2) 5 sec diff, (3) avg for last 1m interval, (4) avg for 5m, (5) avg for 15m */
	PCS_PC_CL_READS			= 0x1101, /* bytes read rate */
	PCS_PC_CL_WRITES		= 0x1102, /* bytes written rate */
	PCS_PC_CL_REPL_READS		= 0x1103, /* replication bytes read rate */
	PCS_PC_CL_REPL_WRITES		= 0x1104, /* replication bytes write rate */
	PCS_PC_CL_READ_OPS		= 0x1106, /* read ops rate */
	PCS_PC_CL_WRITE_OPS		= 0x1107, /* write ops rate */
	PCS_PC_CL_MAPS			= 0x1108, /* map request rate */
	PCS_PC_CL_FSYNC			= 0x1109, /* fsync() rate */
	PCS_PC_CL_SYNC			= 0x110a, /* syncfs() rate */

	PCS_PC_CL_IO_LOAD_AVER		= 0x1200, /* average IO load (queue length) across cluster
						   * (queue length 1.0 corresponds to 5000000) */
	PCS_PC_CL_IO_LOAD_MAX		= 0x1201, /* maximum IO load (queue length) across cluster */
	PCS_PC_CL_IO_LAST_BALANCED	= 0x1210, /* the number of hot CSs balanced last time */
	PCS_PC_CL_IO_LAST_BALANCE_UPTIME= 0x1211, /* time since last balance attempt (ms) */

	PCS_PC_MDS_NODES		= 0x1800, /* the number of MDS nodes in cluster */
	PCS_PC_MISC_FEATURE_MASK	= 0x1801, /* returns 2 64bit feature mask registers */
	PCS_PC_MDS_HOST_INFO		= 0x1802, /* return pcs_host_info for MDS */
	PCS_PC_MDS_HOST_VER_INFO	= 0x1803, /* return pcs_mds_host_info  */

	PCS_PC_MEM_POOLS		= 0x2000, /* overall memory pools statistics */
	PCS_PC_MEM_POOL			= 0x2001, /* the particular memory pool statistics */
	PCS_PC_MEM_LJ_USED		= 0x2011, /* mem allocated for local journal */
	PCS_PC_MEM_RJ_USED		= 0x2012, /* mem allocated for replicated journal */
	PCS_PC_MEM_RJ_CACHE		= 0x2018, /* the total size of the paxos cache	*/
	PCS_PC_MEM_PGS_ALLOCATED	= 0x2020, /* the total number of pages allocated for memory pools */
	PCS_PC_MEM_PGS_FREE		= 0x2021, /* the current number of free pool pages */
	PCS_PC_MEM_PGS_STANDBY		= 0x2022, /* the current number of standby pool pages */

	PCS_PC_MEM_SNAPSHOTS		= 0x2030, /* the number of snapshots */
	PCS_PC_MEM_SNAP_OBJS		= 0x2031, /* the number of objects tracked */
	PCS_PC_MEM_SNAP_OBJS_ORPHAN	= 0x2032, /* the number of deleted objects tracked */
	PCS_PC_MEM_SNAP_COPIES		= 0x2033, /* the number of serialized object copies */
	PCS_PC_MEM_SNAP_COPIES_ORPHAN	= 0x2034, /* the number of serialized copies of the deleted objects */

	PCS_PC_MEM_LAST,			  /* max id used in mem info */

	PCS_PC_PROC_MEM_RSS		= 0x3101, /* number of pages the process has in real memory */
	PCS_PC_PROC_MEM_VSIZE		= 0x3102, /* virtual memory size of process in pages */

	PCS_PC_CS_LIST			= 0x4000, /* CS list */

	PCS_PC_CS_ID			= 0x20000, /* CS id */
	PCS_PC_CS_CHUNKS		= 0x20001, /* number of chunks in CS */
	PCS_PC_CS_REG_UPTIME		= 0x20002, /* time since last mds registration (ms) */
	PCS_PC_CS_REG_ADDR		= 0x20003, /* CS IP addresses currently registered */
	PCS_PC_CS_VERSION		= 0x20004, /* CS version */
	PCS_PC_CS_ADM_STATUS		= 0x20005, /* administration status, see PCS_CS_ADM_* */
	PCS_PC_CS_ACT_STATUS		= 0x20006, /* activity status,	     see PCS_CS_ACT_* */
	PCS_PC_CS_AVAIL			= 0x20008, /* 1 if CS is available for allocation */
	PCS_PC_CS_COST			= 0x2000a, /* allocation cost if available */
	PCS_PC_CS_QOS			= 0x2000b, /* qos assigned for CS */
	PCS_PC_CS_NET_ADDR		= 0x2000e, /* the CS connection source network address */
	PCS_PC_CS_LOCATION		= 0x2000f, /* the CS location and host id */

	PCS_PC_CS_ERR_STATUS		= 0x20010, /* the CS error status - if non-zero the CS is not currently used for chunks allocation */
	PCS_PC_CS_LAST_ERR		= 0x20011, /* local error status, see PCS_MAP_ERR_* */
	PCS_PC_CS_LAST_ERR_UPTIME	= 0x20012, /* time since last local error (ms) */
	PCS_PC_CS_LAST_LINK_ERR		= 0x20013, /* link error status, see PCS_MAP_ERR_* */
	PCS_PC_CS_LAST_LINK_ERR_UPTIME	= 0x20014, /* time since last link error (ms) */

	PCS_PC_CS_TOTAL_SPACE		= 0x20051, /* total space on CS */
	PCS_PC_CS_FREE_SPACE		= 0x20052, /* free space on CS */
	PCS_PC_CS_AVAIL_SPACE		= 0x20053, /* the amount of space available for chunk allocation on CS */

	/* CS chunks info, see PCS_PC_CL_CHUNKS_* */
	PCS_PC_CS_CHUNKS_VOID		= 0x20071,
	PCS_PC_CS_CHUNKS_BLOCKED	= 0x20072,
	PCS_PC_CS_CHUNKS_URGENT		= 0x20073,
	PCS_PC_CS_CHUNKS_DEGRADED	= 0x20074,
	PCS_PC_CS_CHUNKS_HEALTHY	= 0x20075,
	PCS_PC_CS_CHUNKS_OVERCOMMITTED	= 0x20076,
	PCS_PC_CS_CHUNKS_REPLICATING	= 0x20077,
	PCS_PC_CS_CHUNKS_OFFLINE	= 0x20078,
	PCS_PC_CS_REPL_DELETING		= 0x20079,
	PCS_PC_CS_CHUNKS_UNIQUE		= 0x2007f,

	/* CS ops info, see PCS_PC_CL_* */
	PCS_PC_CS_READS			= 0x20101,
	PCS_PC_CS_WRITES		= 0x20102,
	PCS_PC_CS_REPL_READS		= 0x20103,
	PCS_PC_CS_REPL_WRITES		= 0x20104,
	PCS_PC_CS_IO_WAIT		= 0x20105,
	PCS_PC_CS_READ_OPS		= 0x20106,
	PCS_PC_CS_WRITE_OPS		= 0x20107,
	PCS_PC_CS_MAPS			= 0x20108,
	PCS_PC_CS_FSYNC			= 0x20109,
	PCS_PC_CS_SYNC			= 0x2010a,
	PCS_PC_CS_FEATURES		= 0x2010b,
	PCS_PC_CS_CLIENT_STAT		= 0x2010c,
	PCS_PC_CS_LATENCY		= 0x2010d,
	PCS_PC_CS_LATENCY_MAX		= 0x2010e,
	PCS_PC_CS_J_FULL		= 0x2010f,
	PCS_PC_CS_IO_QUEUE		= 0x20110,
	PCS_PC_CS_RMW_OPS		= 0x20111,
	PCS_PC_CS_SYNC_WAIT		= 0x20112,
	PCS_PC_CS_SYNC_LATENCY		= 0x20113,
	PCS_PC_CS_SYNC_LATENCY_MAX	= 0x20114,
	PCS_PC_CS_CRMW_OPS		= 0x20115,
	PCS_PC_CS_SMART_FAMILY		= 0x20120,
	PCS_PC_CS_SMART_DEVICE		= 0x20121,
	PCS_PC_CS_SMART_SN		= 0x20122,
	PCS_PC_CS_SMART_VENDOR_ATTR	= 0x20123,

	/* clients related info */
	PCS_PC_CLIENTS_LIST	     = 0x20200,

	PCS_PC_CLIENT_ID	     = 0x20201,
	PCS_PC_CLIENT_LEASES	     = 0x20202,
	PCS_PC_CLIENT_ADDR	     = 0x20203,
	PCS_PC_CLIENT_READS	     = 0x20204,
	PCS_PC_CLIENT_WRITES	     = 0x20205,
	PCS_PC_CLIENT_READ_OPS	     = 0x20206,
	PCS_PC_CLIENT_WRITE_OPS	     = 0x20207,
	PCS_PC_CLIENT_FSYNC	     = 0x20208,
	PCS_PC_CLIENT_PERIOD	     = 0x20209,
	PCS_PC_CLIENT_IOWAIT	     = 0x2020a,
	PCS_PC_CLIENT_LATENCY_MAX    = 0x2020b,
	PCS_PC_CLIENT_LATENCY	     = 0x2020c,
	PCS_PC_CLIENT_HOST_INFO	     = 0x2020d,
	PCS_PC_CLIENT_IO_QUEUE	     = 0x2020e,
	PCS_PC_CLIENT_RMW_OPS	     = 0x2020f,

	PCS_PC_LICENSE_KEYNUM	     = 0x20301,
	PCS_PC_LICENSE_STATUS	     = 0x20302,
	PCS_PC_LICENSE_CAPACITY	     = 0x20303,
	PCS_PC_LICENSE_EXPIRATION    = 0x20304,

	PCS_PC_SH_LEASE_INFO	     = 0x20401,
	PCS_PC_EX_LEASE_INFO	     = 0x20402,

	PCS_PC_NETSTAT_NODE_INFO     = 0x20501, /* struct pcs_netstat_node_info */

	PCS_PC_DISK_INFO	     = 0x20601,
	PCS_PC_DISK_INFO_SERVICE     = 0x20602,
	PCS_PC_DISK_INFO_ID	     = 0x20603,
	PCS_PC_DISK_INFO_LIST	     = 0x20604, /* struct pcs_mds_disk_info_msg */
	PCS_PC_DISK_INFO_CNT	     = 0x20605,
	PCS_PC_DISK_INFO_HOST	     = 0x20606,
	PCS_PC_DISK_INFO_CAPACITY    = 0x20607,
};

/* Bits for PCS_PC_CS_FEATURES */
enum {
	PCS_CS_FEATURE_JOURNAL		= 1,
	PCS_CS_FEATURE_CHECKSUM		= 2,
	PCS_CS_JOURNAL_CLEAN		= 4,
	PCS_CS_USE_DIRECT_IO		= 8,
	PCS_CS_FAILED_STORAGE		= 0x10,
	PCS_CS_FAILED_CSUM		= 0x20,
	PCS_CS_FAILED_JOURNAL		= 0x40,
	PCS_CS_FAILED_JCSUM		= 0x80,
	PCS_CS_FAILED_REPO		= 0x100,
	PCS_CS_FAILED_TIMEOUT		= 0x200,
};

#define PCS_CS_FAILED_MASK ((u64)PCS_CS_FAILED_STORAGE|PCS_CS_FAILED_CSUM|PCS_CS_FAILED_JOURNAL| \
		PCS_CS_FAILED_JCSUM|PCS_CS_FAILED_REPO|PCS_CS_FAILED_TIMEOUT)

/* The user-friendly cluster status */
typedef enum {
	PCS_CL_STATUS_UNKNOWN,	/* Not enough information yet. MDS is ether not master or master not so long ago */
	PCS_CL_STATUS_HEALTHY,	/* No inactive CS */
	PCS_CL_STATUS_DEGRADED,	/* Some CS are inactive */
	PCS_CL_STATUS_FAILURE,	/* Too many inactive CS. Automatic replication is automatically disabled. */
} pcs_cluster_status_t;

/* The CS activity status */
typedef enum {
	PCS_CS_ACT_ACTIVE,	/* CS is sending pings. */
	PCS_CS_ACT_INACTIVE,	/* Not sending ping for some time. Replication is not yet started. */
	PCS_CS_ACT_OFFLINE,	/* Not sending ping for quite some time, chunks are being replicated. */
	PCS_CS_ACT_DROPPED,	/* Dropped by administrator. Such CS is banned forever so it's activity status doesn't matter anymore. */
	PCS_CS_ACT_STATES_
} pcs_cs_activity_status_t;

struct pcs_mds_monitor_resp_msg
{
	struct pcs_mds_hdr	hdr;
	struct pcs_perf_counter	counters[0];
} __attribute__((aligned(8)));

/* The perf counter types structures */

struct pcs_pc_lease_info { /* PCS_PC_XX_LEASE_INFO */
	PCS_NODE_ID_T	clnt_id;
	u32		age_sec;	/* How long it exists */
	s32		valid_sec;	/* How long it will be valid (negative if expired) */
	PCS_NET_ADDR_T	clnt_addr;
} __attribute__((aligned(8)));

struct pcs_mds_host_info { /* PCS_PC_MDS_HOST_VER_INFO */
	u32			version;
	u32			mds_id;
	struct pcs_host_info	host;
} __attribute__((aligned(8)));

struct pcs_smart_vendor_attr { /* PCS_PC_CS_SMART_VENDOR_ATTR */
	u32 id;
	u32 flag;
	u32 value;
	u32 worst;
	u32 thresh;
	u64 reserved;
	u64 raw_value;
} __attribute__((aligned(8)));

/* Request key values */
enum {
	PCS_PC_GET_INFO = 0,	/* General server info */
	PCS_PC_GET_CS_LIST,	/* The list of known CSs */
	PCS_PC_GET_CS_INFO,	/* The particular CS info (CS ID as index) */
	PCS_PC_GET_CLNT_LIST,	/* The list of the client ID/IP/leases */
	PCS_PC_GET_CLNT_TOP,	/* Not yet implemented */
	PCS_PC_GET_CLNT_INFO,	/* The particular client info (ID as index) */
	PCS_PC_GET_FILE_LEASES, /* The particular file lease owners ID/IP/lease type/age as the array of PCS_PC_LEASE_INFO */
	PCS_PC_GET_NETSTAT,	/* Get array of PCS_PC_NETSTAT_NODE_INFO */
	PCS_PC_GET_STOR_STAT,	/* Get array of struct pcs_perf_stor_stat entries given the directory ID as index */
	PCS_PC_GET_MDS_INFO = 0x10, /* Get cluster MDSs host info as the array of PCS_PC_MDS_HOST_VER_INFO accompanied by PCS_PC_MDS_NODES entry */
};

struct pcs_mds_monitor_req_msg
{
	struct pcs_mds_hdr	hdr;
	u32	_reserved;
	u32	key;
	u64	index;
} __attribute__((aligned(8)));

/* ---- file map query request/response
 * Returns the mapping of the file chunks to chunk servers as long as some valuable information
 * regarding data integrity and chunk placement.
 *
 * The message type is pcs_mds_file_map_info_msg (same for request and response).
 */

#define PCS_MDS_FILE_MAP_INFO_REQ		(PCS_RPC_MDS_CLIENT_BASE + 0x18)
#define PCS_MDS_FILE_MAP_INFO_RESP		(PCS_MDS_FILE_MAP_INFO_REQ | PCS_RPC_DIRECTION)

/* Chunk flags */
enum {
	PCS_CH_FL_DEGRADED	= 1,		/* The number of online replicas is less than normal */
	PCS_CH_FL_BLOCKED	= 2,		/* Not enough online replicas, writing is blocked */
	PCS_CH_FL_OFFLINE	= 4,		/* No online replicas, any access is impossible */
	PCS_CH_FL_OVERCOMMITTED	= 0x10,		/* Too many replicas, trimming is required */
	PCS_CH_FL_REPLICATING	= 0x100,	/* Replication is in progress (to the last replica) */
	PCS_CH_FL_ERROR		= 0x400,	/* Chunk has error flag on it */
	PCS_CH_FL_HARD_ERROR	= 0x800,	/* Some replicas have hard (unrecoverable) error flag */
	PCS_CH_FL_NOT_REGISTERED= 0x1000,	/* Some CS are not registered (so their location info is not available) */
	PCS_CH_FL_XINFO		= 0x4000,	/* The struct pcs_mds_chunk_info is followed by pcs_mds_chunk_xinfo extended info */
	PCS_CH_FL_LOC_INFO	= 0x8000,	/* Extended format with per-replica location info */
};

struct pcs_mds_chunk_replica_loc_info {
	PCS_NODE_ID_T		cs_id;
	struct pcs_host_info	host;
};

struct pcs_mds_chunk_info
{
	u64		offset;		/* Chunk offset */
	u32		flags;		/* Flags (PCS_CH_FL_XXX) */
	u32		nreplicas;	/* The number of valid replicas */
	union {
		/* The array of replica info */
		PCS_NODE_ID_T replicas[1];
		struct pcs_mds_chunk_replica_loc_info replicas_loc[1];
	};
} __attribute__((aligned(8)));

/* Extension for the above structure */
struct pcs_mds_chunk_xinfo
{
	u32		size; /* Chunk size */
	u32		reserved[3];
} __attribute__((aligned(8)));

/* Request flags */
enum {
	PCS_MDS_FILE_MAP_FL_SKIP       = 1,	/* Skip chunk at last_offset (input). Used to restart query after incomplete response.
						 * If not set the start_offset is ignored on input. */
	PCS_MDS_FILE_MAP_FL_OMIT_CHUNKS= 0x1000,/* Omit chunk data on output (input). Other fields will be valid though. */
	PCS_MDS_FILE_MAP_FL_EOF	       = 0x8000,/* No more chunks in the file (output) - if not set the response is incomplete. */
	PCS_MDS_FILE_MAP_FL_XINFO      = 0x80000,/* Retrieve extended chunk info if available */
	PCS_MDS_FILE_MAP_FL_LOC_INFO   = 0x100000,/* Retrieve extended location info (see struct pcs_mds_chunk_replica_loc_info) */
};

/* The maximum locality value corresponding to the same host placement */
#define PCS_HOST_LOCALITY (PCS_LOCATION_PATH_LEN+1)

struct pcs_mds_file_map_info_msg
{
	struct pcs_mds_hdr		hdr;
	PCS_FILE_ID_T			file_id;	/* File id on input */
	PCS_NODE_ID_T			home_id;	/* The ID of the 'home' node */
	u64				total_chunks;	/* The total number of chunks */
	u64				last_offset;	/* Last chunk offset - valid on output */
	u32				req_flags;	/* The request flags (PCS_MDS_FILE_MAP_FL_XXX) */
	u16				chunk_flags;	/* The OR-ed bitmap of chunk flags (PCS_CH_FL_XXX) */
	u8				qos;		/* Tier */
	u8				placement;	/* The placement policy */
	u64				reserved[10];	/* Currently not used */
	u64				per_qos_repl[PCS_NQOS];	/* Replicas per tier */
	u8				repl_norm;	/* Replication factor */
	u8				repl_min;	/* The minimum number of replicas allowed */
	u8				repl_min_actual;/* Actual minimum number of uptodate replicas */
	u8				repl_max_actual;/* Actual maximum number of uptodate replicas */
	u32				nchunks;	/* The number of chunks that follows */
	struct pcs_mds_chunk_info	chunks[0];	/* Chunk info array */
} __attribute__((aligned(8)));

#define PCS_MDS_NETSTAT_REPORT		(PCS_RPC_MDS_CLIENT_BASE + 0x1C)

/* Network stat for the particular link */
struct pcs_connstat_rec
{
	PCS_NODE_ID_T	id;
	u32		retrans;
	/* The following values are in microseconds */
	u32		lat_min;
	u32		lat_max;
	u32		lat_cnt;
	u64		lat_avg;
} __attribute__((aligned(8)));

/* Network stat averaged over all in/out links at the particular network node */
struct pcs_netstat_node_info
{
	PCS_NODE_ID_T	id;
	u32		retrans;
	/* The following values are in microseconds, ~0U means no data available */
	u32		lat_avg;  /* average over all links */
	u32		lat_mmax; /* median of per link maximums */
	u32		lat_max;  /* top maximum over all links */
} __attribute__((aligned(8)));

struct pcs_mds_netstat_req
{
	struct pcs_mds_hdr		hdr;
	u32				count;
	u32				reserved;
	u64				reserved2[2];
	struct pcs_connstat_rec		data[0];
} __attribute__((aligned(8)));

/*
 * Punch hole request - drop chunks in given range. In case the range size
 * is zero it drops the single chunk starting with given offset or returns error
 * if no such chunk exists. Currently this is the only supported scenario.
 */

#define PCS_MDS_PUNCH_HOLE_REQ	(PCS_RPC_MDS_CLIENT_BASE + 0x24)
#define PCS_MDS_PUNCH_HOLE_RESP	(PCS_MDS_PUNCH_HOLE_REQ | PCS_RPC_DIRECTION)

struct pcs_mds_punch_hole_msg
{
	struct pcs_mds_hdr	hdr;
	PCS_FILE_ID_T		fileid; /* File ID */
	u64			offset; /* Start offset */
	u64			size;	/* The hole size (may be zero - see comment above) */
	u64			reserved[3];
} __attribute__((aligned(8)));

#define PCS_MDS_DATA_OBJ_REQ  (PCS_RPC_MDS_CLIENT_BASE + 0x30)
#define PCS_MDS_DATA_OBJ_RESP (PCS_MDS_DATA_OBJ_REQ | PCS_RPC_DIRECTION)

/*
 * Data objects are uniquely identified by (key, type) pair.
 */

#define PCS_MDS_DATA_OBJ_MAX_SIZE 0x20000

enum {
	PCS_DOP_SET = 1,
	PCS_DOP_GET = 2,
	// delete is currently not supported for safety
};

struct pcs_mds_data_obj_msg
{
	struct pcs_mds_hdr	hdr;
	u32			op;
	u32			flags;
	u64			reserved[4];
	u64			key;
	u64			attr;
	u32			type;
	u32			size;
	// Object data follows
} __attribute__((aligned(8)));

/*
 * Administration API.
 */

#define PCS_RPC_MDS_ADMIN_BASE	(PCS_RPC_MDS_CLIENT_BASE + 0x80)

/* ---- add mds node
 * Add new mds node. The message type is pcs_mds_node_add_msg (same for request and response).
 */

#define PCS_MDS_NODE_ADD_REQ	(PCS_RPC_MDS_ADMIN_BASE + 2)
#define PCS_MDS_NODE_ADD_RESP	(PCS_MDS_NODE_ADD_REQ | PCS_RPC_DIRECTION)

struct pcs_mds_node_add_msg
{
	struct pcs_mds_hdr	hdr;
	PCS_NODE_ID_T		id;
	PCS_NET_ADDR_T		addr;

} __attribute__((aligned(8)));

/* ---- remove mds node
 * Remove existing mds node. The message type is pcs_mds_node_rm_msg (same for request and response).
 */

#define PCS_MDS_NODE_RM_REQ	(PCS_RPC_MDS_ADMIN_BASE + 4)
#define PCS_MDS_NODE_RM_RESP	(PCS_MDS_NODE_RM_REQ | PCS_RPC_DIRECTION)

struct pcs_mds_node_rm_msg
{
	struct pcs_mds_hdr	hdr;
	PCS_NODE_ID_T		id;

} __attribute__((aligned(8)));

/* ---- remove cs node
 * Adding new (empty) CS node does not require any special commands. It will be added upon registration.
 * Removing CS node with some chunks allocated is the more complex process. First the node may be marked
 * as releasing to initiate migration of the chunks to other nodes. After that the node may be ultimately dropped.
 * The node being releasing may still contain valid data. It may go back to normal state if admin decided to cancel
 * releasing. On the contrary dropping node drops all chunks immediately so that they will never be accessed again.
 * Dropping the CS node is irreversible.
 *
 * The node control operations return just pcs_mds_hdr on success.
 */

#define PCS_MDS_CS_SET_STATUS_REQ	(PCS_RPC_MDS_ADMIN_BASE + 6)
#define PCS_MDS_CS_SET_STATUS_RESP	(PCS_MDS_CS_SET_STATUS_REQ | PCS_RPC_DIRECTION)

struct pcs_mds_cs_set_status_msg
{
	struct pcs_mds_hdr	hdr;
	PCS_NODE_ID_T		id;
	u32			status;
	u32			flags;

} __attribute__((aligned(8)));

/* CS administration status */
typedef enum {
	PCS_CS_ADM_NORMAL = 0,
	/* Further chunk allocation suppressed, going to be dropped as soon as all chunks will have replicas on another CS.
	 * This status is being set manually by Administrator.
	 */
	PCS_CS_ADM_RELEASING,
	/* The hard IO error was detected so this CS is no longer considered reliable. */
	PCS_CS_ADM_FAILED,
	/* Same as PCS_CS_ADM_RELEASING but CS is considered failed */
	PCS_CS_ADM_FAILED_RELEASING,
	/* The CS is no longer used, its ID is banned forever */
	PCS_CS_ADM_DROPPED = 0x10,
} pcs_cs_adm_status_t;

/* Flags */
enum {
	/* Force setting the particular status. Normally MDS does not allow setting dropped
	 * status if it leads to the unrecoverable data loss. The following flag helps to overcome
	 * this limitation.
	 */
	PCS_CS_ADM_FORCE = 1,
};

/* ---- client control
 * The request type is pcs_mds_clnt_ctl_msg. The response type is struct pcs_mds_hdr on success.
 */

#define PCS_MDS_CLNT_CTL_REQ	(PCS_RPC_MDS_ADMIN_BASE + 0x10)
#define PCS_MDS_CLNT_CTL_RESP	(PCS_MDS_CLNT_CTL_REQ | PCS_RPC_DIRECTION)

/* Operation bits */
enum {
	PCS_MDS_CLNT_REVOKE_LEASES = 1,
	PCS_MDS_CLNT_FINIT_LEASES  = 2,
	PCS_MDS_CLNT_BAN	   = 0x10000,
};

struct pcs_mds_clnt_ctl_msg
{
	struct pcs_mds_hdr	hdr;
	PCS_NODE_ID_T		clnt_id;
	u32			op;
	u32			reserved;
	PCS_FILETIME_T		modify_ts;
};

/*
 * Configuration interface.
 * The configuration data is replicated among all MDS servers. Some data may belong to CS servers, they may query it by
 * the public API described below.
 */

/* The message containing the array of configuration items */
struct pcs_mds_cfg_msg {
	struct pcs_mds_hdr	hdr;
	/* The configuration sequence number. Always valid on output. If set to PCS_CONFIG_SEQ_ANY
	 * the configuration will be updated regardless of the current version. Otherwise the operation
	 * will fail with PCS_ERR_CFG_VERSION if the current version differs from one provided by client.
	 */
	PCS_CONFIG_SEQ_T	version;
	unsigned		nitems;
	struct pcs_cfg_item	items[1];
} __attribute__((aligned(8)));

/* ---- Get configuration request
 * Get configuration data set matching the specified classes bitmap. The request type is struct pcs_mds_cfg_get_msg.
 * The response type is struct pcs_mds_cfg_msg. On failure the pcs_rpc_error_resp will be returned.
 */

#define PCS_MDS_CFG_GET_REQ	(PCS_RPC_MDS_ADMIN_BASE + 0x20)
#define PCS_MDS_CFG_GET_RESP	(PCS_MDS_CFG_GET_REQ | PCS_RPC_DIRECTION)

struct pcs_mds_cfg_get_msg {
	struct pcs_mds_hdr	hdr;
	/* The bitmap of the matching classes */
	u16			classes;
	u16			reserved[3];
} __attribute__((aligned(8)));

/* ---- Set configuration request
 * Set configuration data set. The request type is struct pcs_mds_cfg_msg. The response type is struct pcs_mds_hdr on success.
 * On failure the pcs_rpc_error_resp will be returned. The configuration will be updated in a single transaction so the data set will
 * be either applied entirely or rejected as a whole.
 */

#define PCS_MDS_CFG_SET_REQ	(PCS_RPC_MDS_ADMIN_BASE + 0x22)
#define PCS_MDS_CFG_SET_RESP	(PCS_MDS_CFG_SET_REQ | PCS_RPC_DIRECTION)

/* ---- request new MDS ID ---- */
#define PCS_MDS_GEN_ID_REQ	(PCS_RPC_MDS_ADMIN_BASE + 0x24)
#define PCS_MDS_GEN_ID_RESP	(PCS_MDS_GEN_ID_REQ | PCS_RPC_DIRECTION)

struct pcs_mds_gen_id_msg
{
	struct pcs_mds_hdr	hdr;
	PCS_NODE_ID_T		id;
} __attribute__((aligned(8)));



#define PCS_MDS_DISK_INFO_REQ	(PCS_RPC_MDS_ADMIN_BASE + 0x88)
#define PCS_MDS_DISK_INFO_RESP (PCS_MDS_DISK_INFO_REQ | PCS_RPC_DIRECTION)

#define PCS_MDS_DISK_ID_LEN	64

struct pcs_mds_disk_info_msg {
	struct pcs_mds_hdr	hdr;
	PCS_NODE_ID_T		host_id;
	u8			disk_id[PCS_MDS_DISK_ID_LEN];
	u32			cnt;
	struct pcs_perf_counter info[0];
} __attribute__((aligned(8)));

/* ---- That's all for now */

/* The function translates bytes offset in file to byte offset in actual storage.
 * This map is identical for plain layout and non trivial for RAID0 layout.
 */
static inline u64 map_file_to_chunk(u64 pos, unsigned int chunk_size, unsigned int stripe_depth, unsigned int strip_width)
{
	unsigned int strip_off, chunk_idx;
	u64 base, strip_idx, chunk_off;
	u64 group_size;

	if (stripe_depth == 1)
		return pos;

	group_size = (u64)chunk_size * stripe_depth;

	base = (pos / group_size) * group_size;
	pos -= base;

	strip_off = pos % strip_width;
	strip_idx = pos / strip_width;
	chunk_idx = strip_idx % stripe_depth;
	chunk_off = strip_idx / stripe_depth;

	return base + (chunk_idx * (chunk_size / strip_width) + chunk_off) * strip_width + strip_off;
}

#endif /* _PCS_MDS_PROT_H_ */
