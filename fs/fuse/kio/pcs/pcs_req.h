#ifndef _PCS_REQ_H_
#define _PCS_REQ_H_ 1

#include <linux/workqueue.h>
#include "pcs_error.h"
#include "pcs_sock_io.h"
#include "pcs_map.h"
#include "pcs_cs_prot.h"
#include "pcs_rpc.h"
#include "pcs_cs.h"
#include "fuse_stat.h"
#include "../../fuse_i.h"

///////////////////////////

enum
{
	PCS_IREQ_API	= 0,	/* IO request from API */
	PCS_IREQ_IOCHUNK= 1,	/* Internal IO request */
	PCS_IREQ_LEASE	= 2,	/* Lease op request */
	PCS_IREQ_FILE	= 3,	/* File op request */
	PCS_IREQ_READDIR= 4,	/* Readdir request */
	PCS_IREQ_NOOP	= 5,	/* NOOP request */
	PCS_IREQ_FINI	= 6,	/* Stop pcs process */
	PCS_IREQ_TRUNCATE=7,	/* Internal map truncate request */
	PCS_IREQ_FLUSH	= 8,	/* Sync request */
	PCS_IREQ_STATFS	= 9,	/* statfs request */
	PCS_IREQ_LOOKUP	= 10,	/* lookup request */
	PCS_IREQ_CSCONN = 11,	/* connect to CS and auth */
	PCS_IREQ_CUSTOM = 16,	/* generic request */
	PCS_IREQ_WRAID	= 17,	/* compound raid6 write request */
	PCS_IREQ_RRAID	= 18,	/* compound raid6 read request */
	PCS_IREQ_GETMAP = 19,   /* get mapping for kdirect mode */
	PCS_IREQ_TOKEN  = 20,   /* dummy token to allocate congestion window */
	PCS_IREQ_KAPI	= 65	/* IO request from kernel API */
};

/* Generic request, all internal messages are queued using this struct.
 * Messages can be of various "type".
 */

struct pcs_int_request
{
	struct pcs_cluster_core* cc;

	struct list_head	list;
	struct pcs_dentry_info*	dentry;

	unsigned int		type;
	pcs_error_t		error;
	int			flags;
#define IREQ_F_FATAL		1
#define IREQ_F_ONCE		2
#define IREQ_F_SEQ_READ		4
#define IREQ_F_RND_WEIGHT	8
#define IREQ_F_CACHED		0x10
#define IREQ_F_SEQ		0x20
#define IREQ_F_MAPPED		0x40
#define IREQ_F_MAP_REQUIRED	0x80
#define IREQ_F_LOC_TOKEN	0x100
#define IREQ_F_NOFLUSH		0x200
#define IREQ_F_WB_SUSP		0x400
#define IREQ_F_RECV_SPLICE	0x800

	atomic_t		iocount;

	int			qdepth;
	ktime_t			ts;
	ktime_t			ts_sent;
	PCS_NODE_ID_T		wait_origin;

	struct {
		struct pcs_int_request *	parent;
		void*				ctx;
		void*				priv;
		struct hlist_head		child_list;
		struct hlist_node		child_node;
		spinlock_t			child_lock;
	} completion_data;

	void (*complete_cb)(struct pcs_int_request *ireq);

	abs_time_t		create_ts;

	pcs_timer_t		timer;
	unsigned		last_delay;

	/* TODO: work struct only required for API request.
	   Probably should be embeded to apireq
	*/
	struct work_struct worker;

	/* The following tok_* fields are sequenced by completion_data.child_lock
	 * NOTE: cs->lock can be taken under this lock.
	 */
	struct list_head	tok_list;
	u64                     tok_reserved;
	u64                     tok_serno;

	union {
		struct {
			struct pcs_map_entry	*map;
			//// Temproraly disable flow
			struct pcs_flow_node	*flow;
			u8			cmd;
			u8			role;
			short			cs_index;
			u64			size;
			u64			dio_offset;
			u64			chunk;
			u64			offset;
			struct pcs_cs_list	*csl;
			PCS_NODE_ID_T		banned_cs;
			struct pcs_msg		msg;
			struct pcs_cs_iohdr	hbuf;		/* Buffer for header.
								 * A little ugly
								 */
		} iochunk;

		struct {
			struct pcs_map_entry	*map;		/* map to flush */
			struct pcs_cs_list	*csl;
			struct pcs_msg		*msg;
		} flushreq;

		struct {
			struct pcs_int_request  *parent;
			struct list_head	tok_link;
			int			cs_index;
		} token;

		struct {
			u64			offset;
			int			phase;
			PCS_MAP_VERSION_T	version;
			struct list_head	waiters;
		} truncreq;

		struct {
			unsigned int		flags;
			unsigned int		tout;
			int			retries;
		} leasereq;

		struct {
			unsigned int		op;
			unsigned int		flags;
			union {
				struct pcs_dentry_info	*dst_de;	/* Only for rename */
				off_t			new_size;	/* Only for resize */
				const char		*data;		/* Only for symlink */
			} arg;
		} filereq;

		struct {
			pcs_api_csconnreq_t *req; /* Client request */
			struct pcs_cluster_core	 *clu; /* dentry == NULL */
			struct pcs_msg	    msg;
			int		    out_fd;
		} csconnreq;

		struct {
			void			(*action)(struct pcs_int_request *ireq);
			void			(*destruct)(struct pcs_int_request *ireq);
			void*			ctx;
		} custom;

		struct {
			pcs_api_iorequest_t *	req;		/* Client request */
			unsigned int		dio_offset;	/* MBZ */
			u64			aux;
			void*			h;		/* API handle */
		} apireq;

	};
};

// FROM pcs_cluste_core.h

struct pcs_clnt_config
{
	int		map_timeout;
	int		abort_timeout;
	int		kernel_cache_en;
	int		wmss;
	int		rmss;
	int		lmss;
	int		lic_status;
	int		io_locality;
	int		io_tweaks;
	int		net_10gbit;
	int		local_sndbuf;
	int		tcp_sndbuf;
	int		tcp_rcvbuf;
};

struct pcs_cluster_core
{
	struct list_head	work_queue;	/* Internal queue */
	struct list_head	completion_queue;/* Internal queue for ireqs to complete */
	struct work_struct	main_job;
	struct work_struct	completion_job;
	struct work_struct	fiemap_work;

	struct pcs_cs_set	css;		/* Table of all CSs */
	struct pcs_map_set	maps;		/* Global map data */
	struct pcs_rpc_engine	eng;		/* RPC engine */
	struct workqueue_struct *wq;
////	struct pcs_ratelimit	rlim;		/* Rate limiter */
////	struct pcs_rng		rng;
	/* <SKIP */
	struct pcs_fuse_stat	stat;

	struct {
		struct pcs_clnt_config	def;
		struct pcs_clnt_config	curr;
		PCS_CONFIG_SEQ_T	sn;
		int			in_progress;
	} cfg;

	int			io_tweaks;
	int			iolat_cutoff;
	int			netlat_cutoff;
	int			use_unix_socket;

	/*
	 * Our cluster core may be integrated onto the various implementations by customizing the following request processing methods.
	 * The core does not provide any of them out of the box. Note that only the first one is mandatory.
	 */
	struct {
		void (*ireq_process)   (struct pcs_int_request *);
		void (*ireq_on_error)  (struct pcs_int_request *);
		int  (*ireq_check_redo)(struct pcs_int_request *);
	} op;

	int (*abort_callback)(struct pcs_cluster_core *cc, struct pcs_int_request *ireq);
	struct fuse_conn *fc;
	spinlock_t		lock;
};

static inline struct pcs_cluster_core *cc_from_csset(struct pcs_cs_set * css)
{
	return container_of(css, struct pcs_cluster_core, css);
}

static inline struct pcs_cluster_core *cc_from_cs(struct pcs_cs * cs)
{
	return cc_from_csset(cs->css);
}

static inline struct pcs_cluster_core *cc_from_maps(struct pcs_map_set *maps)
{
	return container_of(maps, struct pcs_cluster_core, maps);
}

void pcs_cc_submit(struct pcs_cluster_core *cc, struct pcs_int_request* ireq);
void pcs_cc_requeue(struct pcs_cluster_core *cc, struct list_head * q);
////// FROM pcs_cluster.h
static inline void pcs_sreq_attach(struct pcs_int_request * sreq, struct pcs_int_request * parent)
{
	sreq->completion_data.parent = parent;
	sreq->ts = parent->ts;
	spin_lock(&parent->completion_data.child_lock);
	hlist_add_head(&sreq->completion_data.child_node, &parent->completion_data.child_list);
	atomic_inc(&parent->iocount);
	spin_unlock(&parent->completion_data.child_lock);
}

static inline int pcs_sreq_detach(struct pcs_int_request * sreq)
{
	struct pcs_int_request * parent = sreq->completion_data.parent;

	BUG_ON(!parent);
	BUG_ON(!atomic_read(&parent->iocount));

	spin_lock(&parent->completion_data.child_lock);
	hlist_del(&sreq->completion_data.child_node);
	spin_unlock(&parent->completion_data.child_lock);

	return !atomic_dec_and_test(&parent->iocount);
}


static inline struct pcs_int_request *ireq_from_msg(struct pcs_msg *msg)
{
	return container_of(msg, struct pcs_int_request, iochunk.msg);
}

static inline void ireq_process(struct pcs_int_request *ireq)
{
	(ireq->cc->op.ireq_process)(ireq);
}

static inline void ireq_on_error(struct pcs_int_request *ireq)
{
	if (ireq->cc->op.ireq_on_error) (ireq->cc->op.ireq_on_error)(ireq);
}

static inline void ireq_complete(struct pcs_int_request *ireq)
{
	BUG_ON(!hlist_empty(&ireq->completion_data.child_list));

	if (pcs_if_error(&ireq->error))
		ireq_on_error(ireq);
	ireq->complete_cb(ireq);
}

static inline int ireq_check_redo(struct pcs_int_request *ireq)
{
	if (ireq->flags & IREQ_F_FATAL)
		return 0;
	if (ireq->cc->op.ireq_check_redo)
		return (ireq->cc->op.ireq_check_redo)(ireq);
	return 1;
}

struct pcs_int_request * __ireq_alloc(void);
struct pcs_int_request *ireq_alloc(struct pcs_dentry_info *di);
struct pcs_int_request *ireq_alloc_by_cluster(struct pcs_cluster_core *cc);
void ireq_init(struct pcs_dentry_info *di, struct pcs_int_request *);
void ireq_init_by_cluster(struct pcs_cluster_core *cc, struct pcs_int_request *);
void ireq_destroy(struct pcs_int_request *);

void ireq_delay(struct pcs_int_request *ireq);
void ireq_handle_hole(struct pcs_int_request *ireq);

void pcs_process_ireq(struct pcs_int_request *ireq);

void pcs_ireq_queue_fail(struct list_head *queue, int error);

typedef void (*kio_file_itr)(struct fuse_file *ff, struct pcs_dentry_info *di,
			     void *ctx);
void pcs_kio_file_list(struct fuse_conn *fc, kio_file_itr kfile_cb, void *ctx);
typedef void (*kio_req_itr)(struct fuse_file *ff, struct fuse_req *req,
			    void *ctx);
void pcs_kio_req_list(struct fuse_conn *fc, kio_req_itr kreq_cb, void *ctx);

#endif /* _PCS_REQ_H_ */
