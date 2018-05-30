#ifndef _PCS_PROT_TYPES_H_
#define _PCS_PROT_TYPES_H_ 1

#include "pcs_types.h"
/* #include "pcs_net_addr.h" */
/* #include "cluster_id.h" */

/*
 * Base types definitions shared by all the components.
 */

/* Current version */
#define PCS_VERSION 121

#define PCS_VZ7_VERSION 100

/* milliseconds since Jan 1970 */
typedef u64 PCS_FILETIME_T;

typedef u64 PCS_FILE_ID_T;

#define PCS_NODE_TYPE_BITS	2
#define PCS_NODE_TYPE_SHIFT	10
#define PCS_NODE_TYPE_MASK	(((1ULL << PCS_NODE_TYPE_BITS) - 1) << PCS_NODE_TYPE_SHIFT)
#define PCS_NODE_ID_MASK	(~PCS_NODE_TYPE_MASK)

typedef struct __pre_aligned(8) _PCS_CHUNK_ID_T {
	PCS_FILE_ID_T	fileid;
	u64		offset;
} PCS_CHUNK_ID_T __aligned(8);

typedef struct __pre_aligned(8) _PCS_XID_T {
	PCS_NODE_ID_T	origin;
	u64		val;
} PCS_XID_T __aligned(8);

/* Optional location of the machine. For now it is assumed that network topology
 * and power supply topology are congruent. Default is all 0s.
 */
#define PCS_LOCATION_PATH_LEN 3

struct __pre_aligned(8) pcs_location
{
	union {
		struct {
		u16	site;
		u16	room;
		u16	cabinet;
		u16	reserved;
		};
		u16	path[PCS_LOCATION_PATH_LEN];
	};
} __aligned(8);

struct __pre_aligned(8) pcs_host_info {
	PCS_NODE_ID_T		host_id;
	struct pcs_location	location;
} __aligned(8);

#define PCS_HOST_INFO_EQ(a, b) (!memcmp(&(a), &(b), offsetof(struct pcs_host_info, location.path[PCS_LOCATION_PATH_LEN])))
#define PCS_TOPO_PATH_FMT     "%u.%u.%u"
#define PCS_HOST_ID_FMT	      "%016llx"
#define PCS_HOST_INFO_FMT     PCS_TOPO_PATH_FMT "." PCS_HOST_ID_FMT
#define PCS_TOPO_PATH_ARGS(p) (p)[0], (p)[1], (p)[2]
#define PCS_HOST_INFO_ARGS(h) PCS_TOPO_PATH_ARGS((h).location.path), (unsigned long long)(h).host_id.val

typedef u32 PCS_MASTER_GENID_T;
typedef u32 PCS_CLUSTER_GENID_T;
typedef u32 PCS_FILE_GENID_T;
typedef u32 PCS_LOST_LEASE_GENID_T;
typedef u64 PCS_CHUNK_GENID_T;
typedef u64 PCS_CHUNK_UID_T;
typedef u64 PCS_LEASE_GEN_T;
typedef u32 PCS_POLICY_GEN_T;

typedef struct {
	u32 major;
	u32 minor;
} PCS_FAST_PATH_VERSION_T;

/*
 * File attributes
 */

struct __pre_aligned(8) pcs_mds_fattr
{
	PCS_FILE_ID_T		id;	      /* internal ID */
	u32			attrib;	      /* attribute flags */
	u32			reserved;     /* reserved for future use */
	union {
	struct {
		u64		size;	      /* the logical size size */
		u64		phy_size;     /* physical size */
	};
	struct {
		PCS_FILE_ID_T	src_id;	      /* ID of the source - used as some API operation parameter only */
		PCS_FILETIME_T	create_ts;    /* file create timestamp (on create input only) */
	};
	};
	PCS_NODE_ID_T		create_cid;   /* file create client ID */
	PCS_FILETIME_T		modify_ts;    /* last file modification timestamp */
	PCS_LEASE_GEN_T		xlease_gen;   /* lease generation updated on every exclusive lease release */
	struct pcs_host_info	last_host;    /* last requested lease client host info */
};

struct __pre_aligned(8) pcs_mds_sys_info {
	u32	map_type;     /* reserved for RAID */
	u32	chunk_size;   /* global constant */
	u8	stripe_depth; /* for RAID6/RS  */
	u8	redundancy;   /* number of checksums for RAID6/RS */
	u8	tolerance;    /* write-tolerance (how much lost replicas we can tolerate still allowing writing) */
	u8	reserved8;
	u32	strip_width;  /* length of strip for RAID6/RS */
	u32	lease_tout;   /* lease expiration timeout (in milliseconds) */
	u32	reserved;
} __aligned(8);

#define PCS_CHUNK_SIZE_MIN 4096u
#define PCS_CHUNK_SIZE_MAX 2147483648u
#define PCS_STRIPE_DEPTH_MAX 64
#define PCS_REDUNDANCY_MAX 5
#define PCS_RAID6_REDUNDANCY 2


__pre_packed struct pcs_mds_repl_policy {
	u8	placement;	/* The placement policy. The 0 value corresponds to the maximum physical diversity. Increasing this
				 * number increases placement locality reducing transport latency (see comment on PCS_PLACEMENT_POLICY_CNT).
				 */
	u8	qos;		/* The default QoS */
	u8	create_type;	/* Map type for new file. Valid as parameter for PCS_MDS_FILE_REQ only if the
				 * PCS_FFL_CREATE_IN_CONTAINER flag is set.
				 */
	u8	reserved[3];
} __packed;

struct __pre_aligned(8) pcs_mds_repl_info {
	u8	norm;		/* The number of replicas to maintain */
	u8	limit;		/* The minimum number of replicas required to write file */
	struct pcs_mds_repl_policy policy; /* Replicas allocation policy */
} __aligned(8);

/* The location defines path to the host so we have 2 more entries in the full path - host itself and the CS node */
#define PCS_TOPO_MAX_PATH (PCS_LOCATION_PATH_LEN+2)

/* The number of placement policies. The policy 0 force the topmost component of the path to be different for different chunks.
 * The policy equal to PCS_LOCATION_PATH_LEN force placing replicas on different hosts. The policy equal to PCS_LOCATION_PATH_LEN+1
 * allows for placing replicas on the same host. Higher values are meaningless since replicas can't be allocated on the same CS more than once.
 */
#define PCS_PLACEMENT_POLICY_CNT PCS_TOPO_MAX_PATH

/* The maximum allowed number of replicas */
#define PCS_REPL_MAX 64

/* The number of QoS levels supported */
#define PCS_NQOS 4

/* Replication info validation macro */
#define PCS_PLACEMENT_VALID(pl) ((pl) < PCS_PLACEMENT_POLICY_CNT)
#define PCS_QOS_VALID(q)	((q) < PCS_NQOS)
#define PCS_POLICY_VALID(p)	(PCS_PLACEMENT_VALID((p).placement) && PCS_QOS_VALID((p).qos))
#define PCS_REPLICAS_VALID_(r)	((r).limit <= (r).norm && (r).norm <= PCS_REPL_MAX)
#define PCS_REPLICAS_VALID(r)	(PCS_REPLICAS_VALID_(r) && (r).limit > 0)
#define PCS_REPL_VALID(r)	(PCS_REPLICAS_VALID(r) && PCS_POLICY_VALID((r).policy))

struct __pre_aligned(8) pcs_mds_fileinfo
{
	struct pcs_mds_fattr		attr;  /* attributes */
	struct pcs_mds_sys_info		sys;   /* system info */
	struct pcs_mds_repl_info	repl;  /* replication info */
} __aligned(8);

/*
 * Version numbers
 */

/* The version number corresponding to the deleted file */
#define PCS_FILE_GEN_DELETED 0

static inline int pcs_compare_master_ver(PCS_MASTER_GENID_T v1, PCS_MASTER_GENID_T v2)
{
	return (int)(v1 - v2);
}

typedef struct __pre_aligned(8) _PCS_MAP_VERSION_T {
	/* Master generation is being incremented every time the master MDS is changed
	 * invalidating all maps issued by the previous master
	 */
	PCS_MASTER_GENID_T	master;
	/* Cluster generation is being incremented every time we are dropping one of the CS servers.
	 */
	PCS_CLUSTER_GENID_T	cluster;
	/* The file generation incremented every time we are changing the file size.
	 */
	PCS_FILE_GENID_T	file;
	/* The lost lease generation is being incremented every time the exclusive lease is expired and revoked to
	 * invalidate all maps issued to the previous client.
	 */
	PCS_LOST_LEASE_GENID_T	lost_lease;
	/* The chunk generation is being incremented every time the chunk replica set is changed to invalidate all maps
	 * referencing the old replica set.
	 */
	PCS_CHUNK_GENID_T	chunk;
} PCS_MAP_VERSION_T;

static inline void map_version_init(PCS_MAP_VERSION_T * v)
{
	memset(v, 0, sizeof(*v));
}

/* Returns negative value if v1 is older than v2, positive if v1 is newer than v2, 0 if they are equal */
static inline int map_version_compare(PCS_MAP_VERSION_T const* v1, PCS_MAP_VERSION_T const* v2)
{
	int d;

	if ((d = v1->master - v2->master))
		return d;

	if ((d = v1->cluster - v2->cluster))
		return d;

	if (v1->file == PCS_FILE_GEN_DELETED) {
		if (v2->file != PCS_FILE_GEN_DELETED)
			return 1;
	} else {
		if (v2->file == PCS_FILE_GEN_DELETED)
			return -1;
	}

	if ((d = v1->file - v2->file))
		return d;

	if ((d = v1->lost_lease - v2->lost_lease))
		return d;

	return (int)(v1->chunk - v2->chunk);
}

static inline int map_version_equal(PCS_MAP_VERSION_T * v1, PCS_MAP_VERSION_T *v2)
{
	return 0 == map_version_compare(v1, v2);
}

/* Other version numbers */
typedef u32 PCS_INTEGRITY_SEQ_T;
typedef u32 PCS_SYNC_SEQ_T;

static inline int pcs_sync_seq_compare(PCS_SYNC_SEQ_T seq1, PCS_SYNC_SEQ_T seq2)
{
	return (int)(seq1 - seq2);
}


//// TODO: dmonakhov perf counted termproraly disabled
/*
 * Performance counter.
 */

struct __pre_aligned(8) pcs_perf_counter
{
	u16	len;
	u16	_reserved;
	u32	key;
	u64	value[0];
} __aligned(8);

#include "pcs_perfcounters.h"

#define PCS_PERF_CNT_NEXT(p) ((struct pcs_perf_counter*)((char*)(p) + (p)->len))

/* Core perf counters ID */
enum {
	PCS_PC_RPC_MSG_COUNT	= 0x10001, /* number of currently processed RPC messages */
	PCS_PC_RPC_CONNS	= 0x10002, /* number of RPC connections */
};

/*
 * Configuration interface.
 */

typedef u16 pcs_cfg_type_t;
typedef u16 pcs_cfg_cls_t;

struct __pre_aligned(8) pcs_cfg_data {
	pcs_cfg_type_t	type;
	pcs_cfg_cls_t	cls;
	u32		size;
	union {
		s64	slong;
		u64	ulong;
		char	string[1];
	};
} __aligned(8);

/* Configuration classes */
enum {
	PCS_CFG_GENERIC = 1,
	PCS_CFG_MDS	= 2,
	PCS_CFG_CS	= 4,
	PCS_CFG_CLIENT	= 8,
	PCS_CFG_INT	= 0x1000,
};

/* Item type */
enum {
	PCS_DATA_NONE  = 0,	/* Used to delete the item regardless of its type */
	PCS_DATA_SLONG = 1,	/* Signed 64 bit value */
	PCS_DATA_ULONG,		/* Unsigned 64 bit value */
	PCS_DATA_STRING = 0x10
};

/* The size of the data item. String data will include the terminating 0 */
#define PCS_CFG_DATA_SZ(d) (offsetof(struct pcs_cfg_data, string)+(d).size+((d).type==PCS_DATA_STRING))

struct __pre_aligned(8) pcs_cfg_item {
	unsigned		name_len;
	unsigned		pad;
	union {
	struct pcs_cfg_data	data;
	char			buff[1];
	};
} __aligned(8);

/* The name offset in the name buffer. Equals to the size of the configuration data. */
#define PCS_CFG_NAME_OFF(i) PCS_CFG_DATA_SZ((i).data)
/* The total size of the data item */
#define PCS_CFG_ITEM_SZ(i)  PCS_ALIGN(offsetof(struct pcs_cfg_item, buff)+PCS_CFG_NAME_OFF(i)+(i).name_len+1)

/* Configuration sequence number incremented every time the configuration is being updated */
typedef u32 PCS_CONFIG_SEQ_T;

/* The following configuration sequence numbers have special meaning */
#define PCS_CONFIG_SEQ_ANY ((PCS_CONFIG_SEQ_T)~0U)	/* Don't care on set */
#define PCS_CONFIG_SEQ_INI 0				/* Initial (default) configuration */

#define PCS_EVT_REC_SZ_ALIGN(msg_sz)  PCS_ALIGN(offsetof(struct pcs_evt_rec, msg[msg_sz]))
#define PCS_EVT_REC_SZ_ALIGNED(descr) PCS_EVT_REC_SZ_ALIGN((descr).size)

/* Generic path representation */
struct __pre_aligned(8) pcs_path {
	u32			sz;
	char			str[1];
} __aligned(8);

/* The size of the pcs_path structure with 1 byte reserved for terminating 0 */
#define PCS_PATH_SZ_(sz) (offsetof(struct pcs_path,str)+(sz)+1)
#define PCS_PATH_SZ(path) PCS_PATH_SZ_((path).sz)

/* Path alignment */
#define PCS_PATH_SZ_ALIGN(sz)	PCS_ALIGN(PCS_PATH_SZ_(sz))
#define PCS_PATH_SZ_ALIGNED(n)	PCS_PATH_SZ_ALIGN((n).sz)
#define PCS_PATH_PAD_SZ(sz)	(PCS_PATH_SZ_ALIGN(sz)-offsetof(struct pcs_path,str)-(sz))

static inline int cmp_path(struct pcs_path const* p_a, struct pcs_path const* p_b)
{
	unsigned _sz = p_a->sz < p_b->sz ? p_a->sz : p_b->sz;
	int r = memcmp(p_a->str, p_b->str, _sz);
	if (r) return r;
	return (int)p_a->sz - (int)p_b->sz;
}

/* Generic constant string representation */
struct pcs_cstr {
	unsigned sz;
	const char* str;
};

static inline int cmp_cstr(struct pcs_cstr const* s_a, struct pcs_cstr const* s_b)
{
	unsigned _sz = s_a->sz < s_b->sz ? s_a->sz : s_b->sz;
	int r = memcmp(s_a->str, s_b->str, _sz);
	if (r) return r;
	return (int)s_a->sz - (int)s_b->sz;
}

/* File attribute bits */
enum
{
	/* Attributes used internally by the system components */
	PCS_FATTR_INTERNAL_ = 0xff,

	/* Attributes has the physical file size maintained */
	PCS_FATTR_HAS_PSIZE_ = 0x10,

	/* The file object represents the directory */
	PCS_FATTR_DIR = 0x1000,

	/* The file object represents symbolic link */
	PCS_FATTR_LINK = 0x2000,

	/* The directory is the container for combined storage (set with PCS_FATTR_DIR only).
	 * It has several important properties:
	 *  - only files are allowed as child objects
	 *  - child leases can't be created, the only lease must be acquired on the container
	 *  - client may implement IO on the container on its own
	 */
	PCS_FATTR_CONTAINER = 0x10000,

	/* Our file-inode abstraction is quite generic. The file may be attached to inide tree at any level.
	 * Inodes are being created or deleted automatically while the files are managed by clients. The file may
	 * have child objects but there is no way to create an empty inode except for creating the special file object
	 * with PCS_FATTR_DIR bit set. Resizing of such object as well as IO requests will fail with PCS_ERR_IS_DIR.
	 *
	 * The client may either don't care about directory tree or have an assumption that all directories in path must
	 * be created prior to the file itself. In the latter case it should set flag PCS_FFL_POSIX_PATH in operation request.
	 * If it is set:
	 *     - an attempt to create or resolve file with dir object lacking in the path will fail with PCS_ERR_NOT_FOUND error
	 *     - an attempt to delete or rename object with child objects will fail with PCS_ERR_NON_EMPTY_DIR error
	 */

	/*
	   The file has inline data. MDS prohibits IO map query for the files with this flag set. The client in turn direct
	   read/write requests to MDS getting/setting file-associated data (see PCS_FA_DATA). May be set on the directory only.
	   Newly created files inherit it from the parent directory.
	 */
	PCS_FATTR_INLINE    = 0x1000000,
	/*
	   The file consists of variable-length chunks where only the last one is writable. May be set on the directory only.
	   Newly created files inherit it from the parent directory.
	*/
	PCS_FATTR_LOGSTREAM = 0x2000000,

	/* Don't cache content on the client */
	PCS_FATTR_NO_CLNT_CACHE = 0x10000000,

	/* The following attributes are being inherited from the parent directory */
	PCS_FATTR_INHERITABLE_MASK = 0xff000000,
};

/*
 * Formatters
 */

#define VER_FMT "%u:%u:%u:%u:%llu"
#define VER_ARGS(v) (v).master, (v).cluster, (v).file, (v).lost_lease, (unsigned long long)(v).chunk

#define XID_FMT "[%u.%llu:%llu]"
#define XID_ARGS(x) (unsigned)(((x).origin.val & PCS_NODE_TYPE_MASK) >> PCS_NODE_TYPE_SHIFT), \
		NODE_ARGS((x).origin), (unsigned long long)((x).val)

#define CLUSTER_ID_FMT	"%08x%08x%08x%08x"
#define CLUSTER_ID_ARGS(x)	(*((unsigned int*)&((x).uuid[12]))), \
		*((unsigned int*)&((x).uuid[8])),	\
		*((unsigned int*)&((x).uuid[4])),	\
		*((unsigned int*)&((x).uuid[0]))

#define NODE_FMT "%llu"
#define NODE_ARGS(id) (unsigned long long)((id).val)

#define PEER_FMT "%s#" NODE_FMT
#define PEER_ARGS(r)  pcs_role_to_str((r)->peer_role), NODE_ARGS((r)->peer_id)

#define CUID_FMT "O%08llx"
#define CUID_ARGS(id) (unsigned long long)(id)


#endif /* _PCS_PROT_TYPES_H_ */
