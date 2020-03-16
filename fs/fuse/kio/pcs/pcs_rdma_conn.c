#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <rdma/rdma_cm.h>

#include "pcs_types.h"
#include "pcs_rdma_io.h"
#include "pcs_rpc.h"
#include "pcs_cluster.h"
#include "pcs_auth.h"
#include "log.h"
#include "fuse_ktrace.h"

#define RESOLVE_TIMEOUT_MS 5000

enum {
    RDMA_MAX_RESP_RES = 0xFF,
    RDMA_MAX_INIT_DEPTH = 0xFF
};

struct pcs_rdmaconnect
{
	struct pcs_rpc *ep;

	struct rdma_cm_id *cmid;
	struct pcs_rdmaio *rio;

	struct pcs_rdma_id id;

	enum rdma_cm_event_type cm_event;
	struct completion cm_done;
};

extern unsigned int rdmaio_queue_depth;

static void
conn_param_init(struct rdma_conn_param *cp, struct pcs_rdmaio_conn_req *cr)
{
	memset(cp, 0, sizeof(*cp));

	if (cr) {
		cp->private_data     = cr;
		cp->private_data_len = sizeof(*cr);
	}

	/* these two guys are about RDMA reads: see man rdma_connect(3) */
	cp->responder_resources = RDMA_MAX_RESP_RES;
	cp->initiator_depth     = RDMA_MAX_INIT_DEPTH;

	cp->flow_control        = 1; /* does not matter */
	cp->retry_count         = 0; /* # retransmissions when no ACK received */
	cp->rnr_retry_count     = 0; /* # RNR retransmissions */
}

static int pcs_rdma_cm_event_handler(struct rdma_cm_id *cmid,
				     struct rdma_cm_event *event)
{
	struct pcs_rdma_id *id = cmid->context;
	struct pcs_rdmaconnect *rc = container_of(id, struct pcs_rdmaconnect, id);
	struct rdma_conn_param conn_param;

	TRACE("event: %d, status: %d\n", event->event, event->status);

	rc->cm_event = event->event;
	switch (event->event) {
		case RDMA_CM_EVENT_ADDR_RESOLVED:
			if (rdma_resolve_route(cmid, RESOLVE_TIMEOUT_MS))
				complete(&rc->cm_done);
			break;
		case RDMA_CM_EVENT_ROUTE_RESOLVED:
			rc->rio = pcs_rdma_create(sizeof(struct pcs_rpc_hdr),
						  rc->cmid, rdmaio_queue_depth, rc->ep);
			if (!rc->rio) {
				complete(&rc->cm_done);
				break;
			}
			rc->cmid = NULL;

			conn_param_init(&conn_param, &rc->rio->conn_req);
			if (rdma_connect(cmid, &conn_param)) {
				TRACE("rdma_connect failed: rio: 0x%p\n", rc->rio);
				complete(&rc->cm_done);
			}
			break;
		case RDMA_CM_EVENT_ESTABLISHED:
			cmid->context = &rc->rio->id;
			complete(&rc->cm_done);
			break;
		case RDMA_CM_EVENT_REJECTED:
			TRACE("pcs_rdma_cm_event_handler reject: %s, rio: 0x%p\n",
			      rdma_reject_msg(cmid, event->status), rc->rio);
			complete(&rc->cm_done);
			break;
		default:
			complete(&rc->cm_done);
	}

	return 0;
}

static int pcs_rdma_event_handler(struct rdma_cm_id *cmid,
		struct rdma_cm_event *event)
{
	struct pcs_rdma_id *id = cmid->context;
	return id->event_handler(cmid, event);
}

void pcs_rdmaconnect_start(struct pcs_rpc *ep)
{
	struct pcs_rdmaconnect rc = {};
	struct sockaddr *sa = &ep->sh.sa;
	int ret;

	BUG_ON(!mutex_is_locked(&ep->mutex));

	TRACE("rdma connection start\n");

	rc.ep = ep;
	rc.id.event_handler = pcs_rdma_cm_event_handler;
	init_completion(&rc.cm_done);

	rc.cmid = rdma_create_id(&init_net, pcs_rdma_event_handler, &rc.id,
				 RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(rc.cmid)) {
		TRACE("rdma_create_id failed: %ld\n", PTR_ERR(rc.cmid));
		goto fail;
	}

	ret = rdma_resolve_addr(rc.cmid, NULL, sa, RESOLVE_TIMEOUT_MS);
	if (ret) {
		TRACE("rdma_resolve_addr failed: %d\n", ret);
		goto fail_cm;
	}

	wait_for_completion(&rc.cm_done);
	if (rc.cm_event != RDMA_CM_EVENT_ESTABLISHED) {
		TRACE("rdma connection failed: %d\n", rc.cm_event);
		goto fail_cm;
	}

	TRACE(PEER_FMT " state: %d, rio: 0x%p\n", PEER_ARGS(ep), ep->state, rc.rio);
	cancel_delayed_work(&ep->timer_work);
	ep->retries++;

	ep->conn = &rc.rio->netio.ioconn;
	rc.rio->send_timeout = PCS_SIO_TIMEOUT;
	rc.rio->rio_state = RIO_STATE_ESTABLISHED;
	rc.rio->netio.ioconn.destruct = pcs_rdma_ioconn_destruct;
	rc.rio->netio.tops = &pcs_rdma_netio_tops;
	rc.rio->netio.getmsg = rpc_get_hdr;
	rc.rio->netio.eof = rpc_eof_cb;
	if (ep->gc)
		list_lru_add(&ep->gc->lru, &ep->lru_link);

	if (ep->flags & PCS_RPC_F_CLNT_PEER_ID)
		ep->flags |= PCS_RPC_F_PEER_ID;

	ep->state = PCS_RPC_AUTH;
	ret = rpc_client_start_auth(ep, PCS_AUTH_DIGEST,
				    cc_from_rpc(ep->eng)->cluster_name);
	if (ret < 0) {
		TRACE("rdma authorization failed: %d, rio: 0x%p",
		      ret, rc.rio);
		goto fail; /* since ep->conn is initialized,
			    * rio will be freed in pcs_rpc_reset()
			    */
	}

	TRACE("rdma connection established: rio: 0x%p\n", rc.rio);

	ep->state = PCS_RPC_APPWAIT;
	pcs_rpc_enable(ep, 0);
	return;

fail_cm:
	if (rc.rio)
		pcs_rdma_destroy(rc.rio);
	if (rc.cmid)
		rdma_destroy_id(rc.cmid);
fail:
	pcs_rpc_reset(ep);
	return;
}
