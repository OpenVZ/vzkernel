#ifndef _PCS_CLUSTER_H_
#define _PCS_CLUSTER_H_ 1

#include "pcs_req.h"
#include "../../fuse_i.h"
struct fuse_conn;

/* Try to follows pcs/client/fused structure style */
struct pcs_fuse_exec_ctx {
	struct pcs_int_request	ireq;
	/* The file size control block */
	struct {
		unsigned long long	required;
		unsigned char		granted;
		unsigned char		waiting;
	} size;
	struct {
		pcs_api_iorequest_t	req;
		struct bio_vec		*bvec;
		unsigned		num_bvecs;
		/* Fuck mem economy, make it simple for testing purpose
		   TODO: IMPLEMENT  fuse_req iterator similar to bvec one */
		struct bio_vec inline_bvec[FUSE_MAX_PAGES_PER_REQ];
	} io;
	struct {
		unsigned		retry_cnt;
		pcs_error_t		last_err;
	} ctl;
};

struct pcs_fuse_req {
	struct fuse_req req;
	void (*end)(struct fuse_conn *, struct fuse_req *);
	struct pcs_fuse_exec_ctx exec;	/* Zero initialized context */
};

struct pcs_fuse_cluster {
	struct pcs_cluster_core cc;
	struct fuse_conn *fc;
};

struct pcs_fuse_work {
	struct work_struct work;
	pcs_error_t status;
	void *ctx;
	void *ctx2;
};

int pcs_cluster_init(struct pcs_fuse_cluster *c, struct workqueue_struct *,
		     struct fuse_conn *fc, PCS_CLUSTER_ID_T *cl_id,
		     PCS_NODE_ID_T *id);
void pcs_cluster_fini(struct pcs_fuse_cluster *c);

static inline struct pcs_fuse_req *pcs_fuse_req_from_work(struct pcs_fuse_exec_ctx *ctx)
{
	return container_of(ctx, struct pcs_fuse_req, exec);
}

static inline struct fuse_req *fuse_req_from_pcs(struct pcs_fuse_req *r)
{
	return (struct fuse_req *)r;
}

static inline struct pcs_fuse_req *pcs_req_from_fuse(struct fuse_req *req)
{
	return container_of(req, struct pcs_fuse_req, req);
}

static inline struct pcs_fuse_cluster *pcs_cluster_from_cc(struct pcs_cluster_core *c)
{
	return container_of(c, struct pcs_fuse_cluster, cc);
}

static inline struct pcs_dentry_info *pcs_inode_from_fuse(struct fuse_inode *fi)
{

	BUG_ON(!fi->private);

	return (struct pcs_dentry_info *)fi->private;
}

static inline struct pcs_fuse_cluster *cl_from_req(struct pcs_fuse_req *r)
{
	return pcs_cluster_from_cc(r->exec.ireq.cc);
}

static inline struct pcs_cluster_core *cc_from_rpc(struct pcs_rpc_engine *eng)
{
	return container_of(eng, struct pcs_cluster_core, eng);
}

/* from pcs_cluter_core.h */
struct pcs_cluster_core_attr {
	PCS_CLUSTER_ID_T	cluster;
	PCS_NODE_ID_T		node;

	/* Timeouts */
	int			abort_timeout_ms;
};
int pcs_cc_init(struct pcs_cluster_core *cc, struct workqueue_struct *wq,
		const char *cluster_name, struct pcs_cluster_core_attr *attr);
void pcs_cc_fini(struct pcs_cluster_core *cc);

void pcs_fuse_prep_io(struct pcs_fuse_req *r, unsigned short type, off_t offset, size_t size);
int fuse_pcs_csconn_send(struct fuse_conn *fc, struct pcs_rpc *ep, int flags);


static inline void pcs_cc_set_abort_timeout(struct pcs_cluster_core *cc, int timeout)
{
	cc->cfg.def.abort_timeout = cc->cfg.curr.abort_timeout = timeout;
}

#endif /* _PCS_CLUSTER_H_ */
