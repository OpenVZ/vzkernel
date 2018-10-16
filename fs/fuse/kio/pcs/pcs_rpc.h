#ifndef _PCS_RPC_H_
#define _PCS_RPC_H_ 1

//#include "pcs_defs.h"
#include "pcs_rpc_prot.h"
#include "pcs_sock_io.h"

struct pcs_msg;

#define PCS_RPC_HASH_SIZE	1024

enum
{
	PCS_RPC_UNCONN	= 0,		/* Not connected */
	PCS_RPC_CONNECT	= 1,		/* Connect in progress */
	PCS_RPC_AUTH	= 2,		/* Connected. Auth request sent. */
	PCS_RPC_AUTHWAIT= 3,		/* Accepted. Waiting for auth request from peer. */
	PCS_RPC_APPWAIT = 4,		/* Auth complete, client is notified */
	PCS_RPC_WORK	= 5,		/* Established */
	PCS_RPC_HOLDDOWN = 6,		/* Not connected. Connect must not be reinitiated. */
	PCS_RPC_ABORT	= 7,		/* Aborted. Not reconnected automatically. */
	PCS_RPC_DESTROY	= 8		/* Destruction in progress */
};

enum {
	RPC_AFFINITY_NONE   = 0,
	RPC_AFFINITY_RETENT = 1,
	RPC_AFFINITY_SPREAD = 2,
};

struct pcs_rpc_params
{
	unsigned int	alloc_hdr_size;
	unsigned int	max_msg_size;

	unsigned int	connect_timeout;
	unsigned int	holddown_timeout;
	unsigned int	response_timeout;

	unsigned int	max_conn_retry;

	unsigned int	flags;
};

#define MAX_BUILD_VERSION_LENGTH 30

#define RPC_GC_MAX_CLASS 4

struct rpc_gc_class
{
	struct list_lru		lru;
};


/* from: cluster_id.h */
typedef union __pre_aligned(8) _PCS_CLUSTER_ID_T {
	unsigned char uuid[16];		/* For now it is opaque string */
	u64	      val[2];
} PCS_CLUSTER_ID_T __aligned(8);

#define PCS_CLUSTER_ID_VALID(clid) ((clid).val[0] || (clid).val[1])
/////////////////////////////

#define PCS_RPC_CPU_SLICE (100 * HZ / 1000) /* 100ms */
struct pcs_rpc
{
	struct hlist_node	link;		/* Link in hash table */
	struct list_head	lru_link;	/* Link in LRU */
	struct rpc_gc_class	*gc;
	struct pcs_rpc_engine	*eng;		/* Reference to eng, where this peer is assigned to */

	unsigned int		state;
	unsigned int		flags;
#define PCS_RPC_F_HASHED		1
#define PCS_RPC_F_PASSIVE		2
#define PCS_RPC_F_PEER_ID		4
#define PCS_RPC_F_NO_RETRY		8
#define PCS_RPC_F_DEAD			0x10
#define PCS_RPC_F_LISTEN		0x20
#define PCS_RPC_F_ACQ_ID		0x40
#define PCS_RPC_F_PEER_VERIFIED		0x80
#define PCS_RPC_F_CLNT_PEER_ID		0x100 /* peer id set by pcs_rpc_set_peer_id */
#define PCS_RPC_F_ACCT			0x200
#define PCS_RPC_F_LOCAL			0x400 /* local AF_UNIX connection */
#define PCS_RPC_F_PEER_AUTHORIZED	0x800 /* peer authorized by secure method */
#define PCS_RPC_F_LOCALAUTH		0x1000 /* skip authenitication, it is provided by transport */

	struct pcs_rpc_params	params;

	atomic_t		refcnt;
	int			retries;
	PCS_NODE_ID_T		peer_id;
	u8			peer_role;
	unsigned int		peer_flags;
	u32			peer_version;
	struct pcs_host_info	peer_host;
	char			peer_build_version[MAX_BUILD_VERSION_LENGTH+1];
	struct work_struct	work;
	struct delayed_work	timer_work;
	PCS_NET_ADDR_T		addr;
/* TODO Reanable local sockets */
#if 0
	struct sockaddr_un *	sun;
#endif
	struct pcs_ioconn *	conn;		/* Active connection for the peer */

	struct pcs_rpc_ops *	ops;

	struct list_head	pending_queue;	/* Queue of requests sent to the peer */
	struct list_head	state_queue;	/* Queue of requests waiting for proper peer state */

	spinlock_t		q_lock;		/* Protects queues lists below*/
	struct list_head	input_queue;	/* Queue of requests waiting to be handled */
	int			cpu;
	unsigned long		cpu_stamp;

	struct mutex		mutex;
	u64			accounted;
	u32			netlat_min;
	u32			netlat_max;
	atomic_t		netlat_cnt;
	atomic64_t		netlat_avg;

	struct delayed_work	calendar_work;
	unsigned		kill_arrow;
#define RPC_MAX_CALENDAR	PCS_MSG_MAX_CALENDAR
	struct hlist_head	kill_calendar[RPC_MAX_CALENDAR];
	struct llist_node	cleanup_node;

	struct pcs_cs *		private;
};

struct pcs_rpc_engine
{
	spinlock_t		lock;
	struct hlist_head	ht[PCS_RPC_HASH_SIZE];
	struct hlist_head	unhashed;
	unsigned int		nrpcs;

	PCS_CLUSTER_ID_T	cluster_id;
	PCS_NODE_ID_T		local_id;
	unsigned int		flags;
#define PCS_KNOWN_MYID		1
#define PCS_KNOWN_CLUSTERID	2
#define PCS_KNOWN_HOSTID	4
	u8			role;
	struct pcs_host_info	my_host;

	atomic64_t		xid_generator;		/* Current XID */
	int			msg_count;
	int			accounted_rpcs;
	u64			msg_allocated;

	u64			mem_pressure_thresh;
	u64			mem_limit;

	int			local_sndbuf;
	int			tcp_sndbuf;
	int			tcp_rcvbuf;
	struct delayed_work	stat_work;
	int			max_connections;
	int			max_gc_index;
	struct rpc_gc_class	gc[RPC_GC_MAX_CLASS];

};

struct pcs_rpc_ops
{
	/* Called on each incoming request to process msg */
	int			(*demux_request)(struct pcs_rpc *, struct pcs_msg * msg);

	/* Called on receiving response before done callback */
	void			(*hook_response)(struct pcs_rpc *, struct pcs_msg * msg);

	/* Called after rpc header is received to allocate msg */
	struct pcs_msg *	(*get_hdr)(struct pcs_rpc *, struct pcs_rpc_hdr * h);

	/* Called when rpc enters ABORT state due to peer abort */
	void			(*state_change)(struct pcs_rpc *, int error);

	void			(*connect)(struct pcs_rpc *);

	/* Incoming connection was aborted */
	void			(*client_aborted)(struct pcs_rpc *ep, int error);

	/* Called when peer asks to keep waiting on a request */
	void			(*keep_waiting)(struct pcs_rpc *, struct pcs_msg * req, struct pcs_msg * msg);

	/* Submit connection statistics */
	void			(*send_stats)(struct pcs_rpc_engine *, struct pcs_msg * msg);
};


static inline struct pcs_rpc * pcs_rpc_get(struct pcs_rpc * p)
{
	BUG_ON(atomic_read(&p->refcnt) <=0);
	atomic_inc(&p->refcnt);
	return p;
}

extern void __pcs_rpc_put(struct pcs_rpc *ep);

static inline void pcs_rpc_put(struct pcs_rpc * p)
{
	BUG_ON(atomic_read(&p->refcnt) <=0);
	if (atomic_dec_and_test(&p->refcnt))
		__pcs_rpc_put(p);
}

/* Function provided by rpc engine */
void pcs_rpc_engine_init(struct pcs_rpc_engine * eng, u8 role);
void pcs_rpc_engine_fini(struct pcs_rpc_engine * eng);
void pcs_rpc_init_gc(struct pcs_rpc_engine * eng, unsigned int limit);
void pcs_rpc_get_new_xid(struct pcs_rpc_engine *eng, PCS_XID_T *xid);

void pcs_rpc_set_local_id(struct pcs_rpc_engine *eng, PCS_NODE_ID_T *id);
void pcs_rpc_set_cluster_id(struct pcs_rpc_engine * eng, PCS_CLUSTER_ID_T * id);
void pcs_rpc_set_host_id(struct pcs_rpc_engine *eng, PCS_NODE_ID_T *host_id);

/* Main set of functions */
struct pcs_rpc * pcs_rpc_alloc_ep(void);
void pcs_rpc_attach_new_ep(struct pcs_rpc * ep, struct pcs_rpc_engine * eng);
void pcs_rpc_configure_new_ep(struct pcs_rpc * ep, struct pcs_rpc_params *parm,
				struct pcs_rpc_ops * ops);
/* All 3 above in one call */
struct pcs_rpc * pcs_rpc_create(struct pcs_rpc_engine * eng, struct pcs_rpc_params *parm,
				struct pcs_rpc_ops * ops);
void pcs_rpc_close(struct pcs_rpc * ep);
void pcs_rpc_reset(struct pcs_rpc * ep);

int pcs_rpc_listen_ext(struct pcs_rpc * ep, PCS_NET_ADDR_T * addr, int flags);
static inline int pcs_rpc_listen(struct pcs_rpc * ep, PCS_NET_ADDR_T * addr)
{
	return pcs_rpc_listen_ext(ep, addr, 0);
}

int pcs_rpc_listen_local(struct pcs_rpc * ep, const char *path, int noauth);
void pcs_rpc_queue(struct pcs_rpc * ep, struct pcs_msg * msg);
void pcs_rpc_kick_queue(struct pcs_rpc * ep);
void pcs_rpc_respond(struct pcs_rpc * ep, struct pcs_msg * msg);
void pcs_rpc_call(struct pcs_rpc * ep, struct pcs_msg * msg);
void pcs_rpc_connect(struct pcs_rpc * ep);
void pcs_rpc_cancel_request(struct pcs_msg * msg);
void pcs_msg_del_calendar(struct pcs_msg * msg);

/* Setting/getting parameters */
void pcs_rpc_set_peer_id(struct pcs_rpc * ep, PCS_NODE_ID_T * id, u8 role);
int pcs_rpc_set_address(struct pcs_rpc * ep, PCS_NET_ADDR_T * addr);

int pcs_rpc_set_local(struct pcs_rpc * ep, const char *path, int noauth);
int pcs_rpc_get_local_addr(struct pcs_rpc * ep, PCS_NET_ADDR_T * addr);

/* Service functions, which are supposed to be used from callbacks */
void pcs_rpc_sent(struct pcs_msg * msg);
struct pcs_msg * pcs_rpc_lookup_xid(struct pcs_rpc * ep, PCS_XID_T * xid);
void rpc_work_input(struct pcs_msg * msg);

void pcs_rpc_error_respond(struct pcs_rpc * ep, struct pcs_msg * msg, int err);
void rpc_abort(struct pcs_rpc * ep, int fatal, int error);
/* Message allocation/initialization */
struct pcs_msg * pcs_alloc_response(struct pcs_rpc_hdr * req_hdr, int size);
struct pcs_msg * pcs_alloc_aligned_response(struct pcs_rpc_hdr * req_hdr, int size, int hdrlen);
struct pcs_msg * pcs_rpc_alloc_error_response(struct pcs_rpc * ep, struct pcs_rpc_hdr * req_hdr, int err, int size);
struct pcs_msg * pcs_rpc_alloc_input_msg(struct pcs_rpc * ep, int datalen);
struct pcs_msg * pcs_rpc_alloc_aligned_msg(struct pcs_rpc * ep, int datalen, int hdrlen);
struct pcs_msg * pcs_rpc_alloc_output_msg(int datalen);
struct pcs_msg * pcs_rpc_clone_msg(struct pcs_msg * msg);
void pcs_rpc_deaccount_msg(struct pcs_msg * msg);
void pcs_rpc_init_input_msg(struct pcs_rpc * ep, struct pcs_msg * msg, int account);
void pcs_rpc_init_output_msg(struct pcs_msg * msg);
void pcs_rpc_init_response(struct pcs_msg * msg, struct pcs_rpc_hdr * req_hdr, int size);

/* Allocate message and initialize header */
struct pcs_msg * pcs_rpc_alloc_msg_w_hdr(int type, int size);

void pcs_rpc_set_memlimits(struct pcs_rpc_engine * eng, u64 thresh, u64 limit);
void pcs_rpc_account_adjust(struct pcs_msg * msg, int adjustment);

struct pcs_perf_counter;
void perfcnt_collect_rpc(char ** ptr, int * max_size, struct pcs_rpc_engine const*);

int pcs_is_zero_cluster_id(PCS_CLUSTER_ID_T *id);
int pcs_cluster_id_eq(PCS_CLUSTER_ID_T *id1, PCS_CLUSTER_ID_T *id2);

void rpc_trace_health(struct pcs_rpc * ep);
void pcs_rpc_enumerate_rpc(struct pcs_rpc_engine *eng, void (*cb)(struct pcs_rpc *ep, void *arg), void *arg);
void pcs_rpc_set_sock(struct pcs_rpc *ep, struct pcs_sockio * sio);
void rpc_connect_done(struct pcs_rpc *ep, struct socket *sock);

static inline struct pcs_rpc *pcs_rpc_from_work(struct work_struct *wr)
{
	return container_of(wr, struct pcs_rpc, work);
}

#endif /* _PCS_RPC_H_ */
