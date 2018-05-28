/* An attempt of universal rpc layer.
 *
 * All the components (except for MDS) used to assume asymmetrical communication:
 * if some connection is open actively, it sends requests, but does not receive requests.
 * If it is open passively, it receives requests, but sends only responses.
 * This layer does not impose this limitation.
 *
 * API:
 * pcs_rpc_create(struct pcs_rpc_engine * eng, struct pcs_rpc_params *parm, struct rpc_ops * ops)
 *   - create new rpc client with requested parameters/ops
 * pcs_rpc_close(struct pcs_rpc * ep)
 *   - close client. Probably it will not be destroyed immediately, but it is guaranteed
 *     that ops will not be called anymore. If some messages are queued inside rpc engine,
 *     they will be completed before return from pcs_rpc_close(), but if messages are somewhere
 *     under control of client, msg->done() can be called later.
 */

#include <net/sock.h>
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/types.h>


#include "pcs_types.h"
#include "pcs_sock_io.h"
#include "pcs_rpc.h"
#include "pcs_cluster.h"
#include "log.h"

static void timer_work(struct work_struct *w);
static int rpc_gc_classify(struct pcs_rpc * ep);

static unsigned int rpc_hash(PCS_NODE_ID_T * id)
{
	return *(unsigned int*)id % PCS_RPC_HASH_SIZE;
}

static struct pcs_rpc *
pcs_rpc_lookup(struct pcs_rpc_engine * eng, PCS_NODE_ID_T * id) __attribute__((unused));

static struct pcs_rpc *
pcs_rpc_lookup(struct pcs_rpc_engine * eng, PCS_NODE_ID_T * id)
{
	struct pcs_rpc * ep;

	hlist_for_each_entry(ep, &eng->ht[rpc_hash(id)], link) {
		if (memcmp(&ep->peer_id, id, sizeof(ep->peer_id)) == 0)
			return pcs_rpc_get(ep);
	}
	return NULL;
}
static void rpc_add_hash(struct pcs_rpc * ep) __attribute__ ((unused));
static void rpc_del_hash(struct pcs_rpc * ep) __attribute__ ((unused));

static void rpc_add_hash(struct pcs_rpc * ep)
{
	if (!hlist_unhashed(&ep->link))
		hlist_del(&ep->link);

	if (!(ep->flags & PCS_RPC_F_HASHED)) {
		ep->flags |= PCS_RPC_F_HASHED;
		pcs_rpc_get(ep);
	}

	hlist_add_head(&ep->link, &ep->eng->ht[rpc_hash(&ep->peer_id)]);
}

static void rpc_del_hash(struct pcs_rpc * ep)
{
	if (ep->flags & PCS_RPC_F_HASHED) {
		ep->flags &= ~PCS_RPC_F_HASHED;
		hlist_del(&ep->link);
		hlist_add_head(&ep->link, &ep->eng->unhashed);
		pcs_rpc_put(ep);
	}
}


struct pcs_msg * pcs_rpc_lookup_xid(struct pcs_rpc * ep, PCS_XID_T * xid)
{
	struct pcs_msg * msg;

	/* TODO: lookup may be optimized by using has instead of list */
	list_for_each_entry(msg, &ep->pending_queue, list) {
		struct pcs_rpc_hdr * h = (struct pcs_rpc_hdr *)msg_inline_head(msg);
		if (memcmp(&h->xid, xid, sizeof(PCS_XID_T)) == 0)
			return msg;
	}
	return NULL;
}

static void pcs_set_rpc_error(pcs_error_t * err, int error, struct pcs_rpc * ep)
{
	err->value = error;

	if (error == PCS_ERR_NOMEM) {
		/* Sad exception, NOMEM is defintely a local error. XXX Find a way to beautify this. */
		err->remote = 0;
	} else {
		err->remote = 1;
		err->offender = ep->peer_id;
	}
}

static void pcs_msg_add_calendar(struct pcs_msg * msg,	bool update)
{
	unsigned int kill_slot;
	struct pcs_rpc *ep = msg->rpc;

	BUG_ON(!ep);
	kill_slot = update? msg->rpc->kill_arrow + ((msg->timeout + HZ -1) / HZ) : msg->kill_slot;
	kill_slot = kill_slot & (RPC_MAX_CALENDAR - 1);
	hlist_add_head(&msg->kill_link, &ep->kill_calendar[kill_slot]);
	msg->kill_slot = kill_slot;

	if (unlikely(!timer_pending(&ep->calendar_work.timer))) {
		struct pcs_cluster_core *cc = cc_from_rpc(ep->eng);

		mod_delayed_work(cc->wq, &ep->calendar_work, HZ);
	}

}

void pcs_msg_del_calendar(struct pcs_msg * msg)
{
	int kill_slot = msg->kill_slot;

	if (hlist_unhashed(&msg->kill_link))
		return;

	BUG_ON(kill_slot >= RPC_MAX_CALENDAR);
	BUG_ON(!msg->rpc);
	BUG_ON((msg->kill_slot != kill_slot));

	hlist_del_init(&msg->kill_link);

}

void rpc_abort(struct pcs_rpc * ep, int fatal, int error)
{
	int state = ep->state;
	struct list_head failed_list;

	BUG_ON(!mutex_is_locked(&ep->mutex));
	TRACE("ep:%p->state:%d fatal:%d error:%d\n", ep, state, fatal, error);

	ep->flags &= ~(PCS_RPC_F_PEER_VERIFIED | PCS_RPC_F_PEER_AUTHORIZED);
	ep->flags &= ~PCS_RPC_F_PEER_ID;

	if (state == PCS_RPC_DESTROY || state == PCS_RPC_ABORT)
		return;

	/* Passively open connections are not reconnected */
	if (ep->flags & (PCS_RPC_F_PASSIVE|PCS_RPC_F_NO_RETRY|PCS_RPC_F_DEAD))
		fatal = 1;

	ep->state = fatal ? PCS_RPC_ABORT : PCS_RPC_UNCONN;
	cancel_delayed_work(&ep->timer_work);

	pcs_rpc_get(ep);
	INIT_LIST_HEAD(&failed_list);

	while (!list_empty(&ep->pending_queue)) {
		struct pcs_msg * msg = list_first_entry(&ep->pending_queue, struct pcs_msg, list);
		list_move_tail(&msg->list, &failed_list);
		TRACE("aborted msg to " PEER_FMT ", tmo=%d, err=%d, %ld", PEER_ARGS(ep),
		      msg->timeout, error, (long)(msg->start_time + msg->timeout - jiffies));
		pcs_msg_del_calendar(msg);
		msg->stage = PCS_MSG_STAGE_NONE;
	}
	if (fatal) {
		while (!list_empty(&ep->state_queue)) {
			struct pcs_msg * msg = list_first_entry(&ep->state_queue, struct pcs_msg, list);
			list_move_tail(&msg->list, &failed_list);
			TRACE("aborted unsent msg to " PEER_FMT ", tmo=%d, err=%d", PEER_ARGS(ep),
			      msg->timeout, error);
			pcs_msg_del_calendar(msg);
			msg->stage = PCS_MSG_STAGE_NONE;
		}
	}

	if (ep->conn) {
		struct pcs_ioconn * ioconn = ep->conn;
		struct pcs_sockio * sio = sio_from_ioconn(ioconn);

		ep->conn = NULL;
		if (ep->gc)
			list_lru_del(&ep->gc->lru, &ep->lru_link);

		sio->parent = NULL;
		pcs_sock_error(sio, error);
	}

	if (ep->state == PCS_RPC_UNCONN) {
		struct pcs_cluster_core *cc = cc_from_rpc(ep->eng);

		ep->state = PCS_RPC_HOLDDOWN;
		queue_delayed_work(cc->wq, &ep->timer_work, ep->params.holddown_timeout);
	}

	while (!list_empty(&failed_list)) {
		struct pcs_msg * msg = list_first_entry(&failed_list, struct pcs_msg, list);
		list_del_init(&msg->list);
		pcs_set_rpc_error(&msg->error, error, ep);
		BUG_ON(!hlist_unhashed(&msg->kill_link));
		msg->done(msg);
	}

	if (ep->state != PCS_RPC_ABORT)
		goto out;

	if (!(ep->flags & PCS_RPC_F_DEAD)) {
		/* RPC is aborted, notify its owner. Owner is supposed to close us. */
		if (ep->ops->state_change)
			ep->ops->state_change(ep, error);
	}

out:
	pcs_rpc_put(ep);
}

/* Client close. */
void pcs_rpc_close(struct pcs_rpc * ep)
{
	mutex_lock(&ep->mutex);
	BUG_ON(ep->flags & PCS_RPC_F_DEAD);
	BUG_ON(ep->flags & PCS_RPC_F_PASSIVE);

	ep->flags |= PCS_RPC_F_DEAD;
	rpc_abort(ep, 1, PCS_ERR_NET_ABORT);
	ep->state = PCS_RPC_DESTROY;
	mutex_unlock(&ep->mutex);

	pcs_rpc_put(ep);

}

void pcs_rpc_attach_new_ep(struct pcs_rpc * ep, struct pcs_rpc_engine * eng)
{
	eng->nrpcs++;
	hlist_add_head(&ep->link, &eng->unhashed);
	ep->eng = eng;
	ep->state = PCS_RPC_UNCONN;
	ep->flags = 0;
	atomic_set(&ep->refcnt, 1);
	ep->retries = 0;
	ep->peer_role = PCS_NODE_ROLE_TEST;
	ep->peer_flags = 0;
	ep->peer_version = ~0U;
	ep->conn = NULL;
	ep->private = NULL;
	INIT_LIST_HEAD(&ep->pending_queue);
	INIT_LIST_HEAD(&ep->state_queue);
	INIT_LIST_HEAD(&ep->input_queue);
	INIT_LIST_HEAD(&ep->lru_link);

	spin_lock_init(&ep->q_lock);
	mutex_init(&ep->mutex);
	ep->accounted = 0;
	ep->netlat_min = ~0U;
	ep->netlat_max = 0;
	atomic_set(&ep->netlat_cnt, 0);
	atomic64_set(&ep->netlat_avg, 0);
	ep->cpu = WORK_CPU_UNBOUND;

	ep->gc = NULL;
	if (eng->max_gc_index)
		ep->gc = &eng->gc[0];

	if (!timer_pending(&eng->stat_work.timer)) {
		struct pcs_cluster_core *cc = cc_from_rpc(eng);

		mod_delayed_work(cc->wq, &eng->stat_work, PCS_MSG_MAX_CALENDAR * HZ);
	}
}

void pcs_rpc_destroy(struct pcs_rpc * ep)
{
	BUG_ON(ep->state != PCS_RPC_DESTROY);
	BUG_ON(ep->flags & PCS_RPC_F_HASHED);
	BUG_ON(!(ep->flags & PCS_RPC_F_DEAD));
	BUG_ON(!list_empty(&ep->input_queue));
	BUG_ON(!list_empty(&ep->state_queue));
	BUG_ON(!list_empty(&ep->pending_queue));
	BUG_ON(timer_pending(&ep->timer_work.timer));

	/* pcs_free(ep->sun); */
	/* ep->sun = NULL; */
	if (ep->gc)
		list_lru_del(&ep->gc->lru, &ep->lru_link);
	hlist_del(&ep->link);
	ep->eng->nrpcs--;
	cancel_delayed_work_sync(&ep->calendar_work);
	if (ep->eng->nrpcs == 0)
		cancel_delayed_work_sync(&ep->eng->stat_work);

	memset(ep, 0xFF, sizeof(*ep));
	kfree(ep);
}

static void rpc_eof_cb(struct pcs_sockio * sio)
{
	struct pcs_rpc * ep = sio->parent;

	if (ep == NULL)
		return;

	/* Dead socket is finally closed, we could already open another one.
	 * I feel inconvenient about this.
	 */
	if (&sio->ioconn != ep->conn)
		return;

	rpc_abort(ep, 0, PCS_ERR_NET_ABORT);
}


struct pcs_msg * pcs_rpc_alloc_error_response(struct pcs_rpc * ep, struct pcs_rpc_hdr * req_hdr, int err, int size)
{
	struct pcs_msg * eresp;
	struct pcs_rpc_error_resp * eh;

	BUG_ON(size < sizeof(struct pcs_rpc_error_resp));

	eresp = pcs_alloc_response(req_hdr, size);
	if (eresp) {
		eh = (struct pcs_rpc_error_resp *)eresp->_inline_buffer;
		eh->hdr.type = PCS_RPC_ERROR_RESP;
		eh->offender = ep->eng->local_id;
		eh->code = err;
		eh->npayloads = 0;
		memset(&eh->payload, 0, sizeof(eh->payload));
	}
	return eresp;
}

void pcs_rpc_error_respond(struct pcs_rpc * ep, struct pcs_msg * msg, int err)
{
	struct pcs_msg * eresp;
	struct pcs_rpc_hdr * h = (struct pcs_rpc_hdr *)msg->_inline_buffer;

	if (ep->state < PCS_RPC_AUTH || ep->state > PCS_RPC_WORK)
		return;

	eresp = pcs_rpc_alloc_error_response(ep, h, err, sizeof(struct pcs_rpc_error_resp));
	if (eresp) {
		struct pcs_sockio *sio = sio_from_ioconn(ep->conn);
		pcs_sock_sendmsg(sio, eresp);
	}
}

/* After client gets csconn_complete() callback, he makes some actions and completes switch
 * to WORK state calling this function.
 */
static void pcs_rpc_enable(struct pcs_rpc * ep, int error)
{
	struct pcs_cluster_core *cc = cc_from_rpc(ep->eng);

	BUG_ON(!mutex_is_locked(&ep->mutex));
	BUG_ON(ep->state != PCS_RPC_APPWAIT);

	if (error) {
		rpc_abort(ep, 1, error);
		return;
	}

	if (ep->gc) {
		int idx = rpc_gc_classify(ep);

		if (ep->eng->gc + idx != ep->gc) {
			list_lru_del(&ep->gc->lru, &ep->lru_link);
			ep->gc = ep->eng->gc + idx;
			list_lru_add(&ep->gc->lru, &ep->lru_link);
		}
	}
	TRACE("ep(%p)->state: WORK\n", ep);
	ep->state = PCS_RPC_WORK;
	queue_work(cc->wq, &ep->work);
}

static void handle_response(struct pcs_rpc * ep, struct pcs_msg * msg)
{
	struct pcs_rpc_hdr * h = (struct pcs_rpc_hdr *)msg->_inline_buffer;
	struct pcs_msg * req;

	/* Use of iocount is unusual and deserves an explanation. If response
	 * is processed synchronously, this iocount is unnecessary.
	 * But if done() needs to queue response, it can increase iocount to hold the message
	 * for itself.
	 */
	pcs_msg_io_start(msg, pcs_free_msg);
	req = pcs_rpc_lookup_xid(ep, &h->xid);
	if (req == NULL)
		goto drop;

	pcs_msg_del_calendar(req);
	list_del(&req->list);
	if (h->type == PCS_RPC_ERROR_RESP) {
		struct pcs_rpc_error_resp * eh = (struct pcs_rpc_error_resp *)msg->_inline_buffer;

		if (msg->size < sizeof(struct pcs_rpc_error_resp))
			pcs_set_rpc_error(&req->error, PCS_ERR_PROTOCOL, ep);
		else {
			req->error = (pcs_error_t){ .value = eh->code, .remote = 1, .offender = eh->offender };
			req->response = msg;
		}
	} else {
		struct pcs_rpc_hdr * req_h = (struct pcs_rpc_hdr *)msg_inline_head(req);

		if ((req_h->type ^ h->type) & ~PCS_RPC_DIRECTION)
			pcs_set_rpc_error(&req->error, PCS_ERR_PROTOCOL, ep);
		else
			req->response = msg;
	}

	if (ep->ops->hook_response)
		ep->ops->hook_response(ep, req);

	req->stage = PCS_MSG_STAGE_DONE;
	BUG_ON(!hlist_unhashed(&msg->kill_link));
	req->done(req);

drop:
	pcs_msg_io_end(msg);
}

static void handle_keep_waiting(struct pcs_rpc * ep, struct pcs_msg * msg)
{
	struct pcs_rpc_keep_waiting * h = (struct pcs_rpc_keep_waiting *)msg->_inline_buffer;
	struct pcs_msg * req;

	if (h->hdr.len < sizeof(struct pcs_rpc_keep_waiting))
		return;

	TRACE("Received keep wait from " NODE_FMT " for request " XID_FMT,
	      NODE_ARGS(h->hdr.xid.origin), XID_ARGS(h->xid));

	req = pcs_rpc_lookup_xid(ep, &h->xid);
	if (!req)
		return;

	if (ep->ops->keep_waiting)
		ep->ops->keep_waiting(ep, req, msg);

	/* Restart kill timer as if message arrived right now */
	if (!hlist_unhashed(&req->kill_link)) {
		pcs_msg_del_calendar(req);
		pcs_msg_add_calendar(req, 1);
	}

	/* Requeue message to tail of pending queue and restart RPC timer */
	if (req->stage == PCS_MSG_STAGE_WAIT) {
		req->start_time = jiffies;
		list_move_tail(&req->list, &ep->pending_queue);
	}
}

void pcs_rpc_cancel_request(struct pcs_msg * msg)
{
	pcs_msg_del_calendar(msg);
	list_del(&msg->list);
	msg->stage = PCS_MSG_STAGE_NONE;
	pcs_set_rpc_error(&msg->error, PCS_ERR_CANCEL_KEEPWAIT, msg->rpc);
	msg->done(msg);
}

void rpc_work_input(struct pcs_msg * msg)
{
	struct pcs_rpc * ep = msg->rpc;
	struct pcs_rpc_hdr * h = (struct pcs_rpc_hdr *)msg->_inline_buffer;

	if (ep == NULL || ep->state != PCS_RPC_WORK)
		goto drop;

	msg->done = pcs_free_msg;

	if (RPC_IS_RESPONSE(h->type)) {
		handle_response(ep, msg);
		return;
	} else if (h->type == PCS_RPC_KEEP_WAITING) {
		handle_keep_waiting(ep, msg);
	} else {
		int res;

		res = ep->ops->demux_request(ep, msg);
		/* Successfully demuxed */
		if (res == 0)
			return;

		/* Client can return error code to pass back to requestor */
		pcs_rpc_error_respond(ep, msg, res);
	}

drop:
	pcs_free_msg(msg);
}

struct pcs_msg * rpc_get_hdr(struct pcs_sockio * sio)
{
	struct pcs_rpc * ep = sio->parent;
	struct pcs_rpc_hdr * h = (struct pcs_rpc_hdr*)sio_inline_buffer(sio);
	struct pcs_msg * msg;
	void (*next_input)(struct pcs_msg *);

	if (ep == NULL)
		return NULL;

	/* Fatal stream format error */
	if (h->len < sizeof(struct pcs_rpc_hdr) || h->len > ep->params.max_msg_size) {
		pcs_log(0, "Bad message header %u %u\n", h->len, h->type);
		return NULL;
	}

	switch (ep->state) {
	case PCS_RPC_WORK:
		/* Client can override get_hdr to allocate special buffer. */
		if (ep->ops->get_hdr) {
			msg = ep->ops->get_hdr(ep, h);
			if (msg)
				return msg;
		}
		next_input = rpc_work_input;
		break;
	default:
		pcs_log(0, "Received msg in bad state %u\n", ep->state);
		BUG();
		return NULL;

	}

	msg = pcs_rpc_alloc_input_msg(ep, h->len);
	if (!msg) {
		pcs_sock_throttle(sio);
		return NULL;
	}

	memcpy(msg->_inline_buffer, h, sizeof(struct pcs_rpc_hdr));
	msg->done = next_input;
	msg->size = h->len;
	msg->private = NULL;
	return msg;
}


/* Start connect. It is triggered by a message sent to this peer or can be called
 * explicitly, if caller needs to steal csconn from userspace
 */
void pcs_rpc_connect(struct pcs_rpc * ep)
{

	/* Nothing to do, connect is already initiated or in holddown state */
	if (ep->state != PCS_RPC_UNCONN)
		return;

	if (ep->flags & PCS_RPC_F_LOCAL) {
		/* TODO, local path is temprorally disabled */
		BUG_ON(1);
	} else {
		TRACE("Connecting to node " NODE_FMT "\n", NODE_ARGS(ep->peer_id));


		BUG_ON(!ep->ops->connect);
		ep->ops->connect(ep);
	}
}

/* Send notification, which does not require waiting for response from peer.
 * Also it is used internally as "raw" submit.
 */
static void pcs_rpc_send(struct pcs_rpc * ep, struct pcs_msg * msg, bool requeue)
{
	struct pcs_sockio *sio = sio_from_ioconn(ep->conn);

	BUG_ON(!mutex_is_locked(&ep->mutex));
	BUG_ON(msg->rpc != (requeue ? ep: NULL));

	TRACE("ENTER ep:%p state:%d msg:%p\n", ep, ep->state, msg);

	if (!requeue) {
		msg->rpc = pcs_rpc_get(ep);
		if (msg->timeout) {
			pcs_msg_add_calendar(msg, 1);
		} else {
			msg->kill_slot = RPC_MAX_CALENDAR;
			INIT_HLIST_NODE(&msg->kill_link);
		}
	} else /* Requeued messages must be scheduled in calendar */
		BUG_ON(msg->timeout && hlist_unhashed(&msg->kill_link));

	if (ep->state == PCS_RPC_WORK) {
		BUG_ON(ep->conn == NULL);
		if (msg->size)
			pcs_sock_sendmsg(sio, msg);
		else {
			pcs_msg_del_calendar(msg);
			msg->done(msg);
		}
		return;
	}

	if (ep->state == PCS_RPC_ABORT || ep->state == PCS_RPC_DESTROY) {
		pcs_set_rpc_error(&msg->error, PCS_ERR_NET_ABORT, ep);
		pcs_msg_del_calendar(msg);
		msg->done(msg);
		return;
	}

	list_add_tail(&msg->list, &ep->state_queue);
	msg->stage = PCS_MSG_STAGE_UNSENT;

	if (ep->state == PCS_RPC_UNCONN)
		pcs_rpc_connect(ep);
}

void pcs_rpc_kick_queue(struct pcs_rpc * ep)
{
	struct pcs_cluster_core *cc = cc_from_rpc(ep->eng);

	queue_work_on(ep->cpu, cc->wq, &ep->work);
}

void pcs_rpc_queue(struct pcs_rpc * ep, struct pcs_msg * msg)
{
	int was_idle;

	spin_lock(&ep->q_lock);
	was_idle = list_empty(&ep->input_queue);
	list_add_tail(&msg->list, &ep->input_queue);

	/* Naive socket-to-cpu binding approach */
	if (time_is_before_jiffies(ep->cpu_stamp) && was_idle) {
		ep->cpu_stamp = jiffies + PCS_RPC_CPU_SLICE;
		ep->cpu = smp_processor_id();
	}
	spin_unlock(&ep->q_lock);

	if (was_idle)
		pcs_rpc_kick_queue(ep);
}

static void calendar_work(struct work_struct *w)
{
	struct pcs_rpc * ep = container_of(w, struct pcs_rpc, calendar_work.work);
	int kill_slot = ep->kill_arrow & (RPC_MAX_CALENDAR - 1);
	struct pcs_cluster_core *cc = cc_from_rpc(ep->eng);
	struct hlist_head * bucket;
	int i, count = 0;

	mutex_lock(&ep->mutex);
	bucket = &ep->kill_calendar[kill_slot];
	while (!hlist_empty(bucket)) {
		struct pcs_msg * msg = hlist_entry(bucket->first, struct pcs_msg, kill_link);
		struct pcs_rpc_hdr * h = (struct pcs_rpc_hdr *)msg_inline_head(msg);

		(void)h;
		TRACE("killing msg to " PEER_FMT " type=%u xid=" XID_FMT " stage=%d tmo=%d exp=%ld rem=%ld\n",
		      PEER_ARGS(msg->rpc), h->type, XID_ARGS(h->xid),
		      msg->stage, msg->timeout,
		      (long)(msg->start_time + msg->timeout - jiffies),
		      (long)(msg->start_time + msg->rpc->params.response_timeout - jiffies));

		pcs_msg_del_calendar(msg);
		switch (msg->stage) {
		case PCS_MSG_STAGE_SEND:
			if (pcs_sock_cancel_msg(msg)) {
				/* The message is under network IO right now. We cannot kill it
				 * without destruction of the whole connection. So, we just reschedule
				 * kill. When IO will complete, it will be killed not even waiting
				 * for response. But if IO stucks, we will violate deadline, alas.
				 * I hope it is the only place, where we violate deadline now.
				 */
				msg->kill_slot = (msg->kill_slot + 1 ) & (RPC_MAX_CALENDAR - 1);
				pcs_msg_add_calendar(msg, 0);
				continue;
			}
			break;
		default:
			list_del(&msg->list);
			break;
		}

		if (msg->stage == PCS_MSG_STAGE_WAIT) {
			/* Leave rpc timer running. If it expires before any (late) response
			 * is received, rpc will be shutdown
			 */
			pcs_set_rpc_error(&msg->error, PCS_ERR_RESPONSE_TIMEOUT, msg->rpc);
		} else {
			msg->stage = PCS_MSG_STAGE_SENT;
			pcs_set_rpc_error(&msg->error, PCS_ERR_WRITE_TIMEOUT, msg->rpc);
		}
		BUG_ON(!hlist_unhashed(&msg->kill_link));
		msg->done(msg);
		count++;
	}
	if (count)
		printk("%s %d messages to "PEER_FMT" destroyed\n", __FUNCTION__,
		       count, PEER_ARGS(ep));

	for (i=0; i < RPC_MAX_CALENDAR-1; i++) {
		kill_slot = (ep->kill_arrow  + i) & (RPC_MAX_CALENDAR - 1);

		if (!hlist_empty(&ep->kill_calendar[kill_slot])) {
			/* FIXME: suboptimal scheduling */
			mod_delayed_work(cc->wq, &ep->calendar_work, HZ);
			break;
		}
	}
	ep->kill_arrow++;
	mutex_unlock(&ep->mutex);
}

static void update_xmit_timeout(struct pcs_rpc *ep)
{
	struct pcs_sockio *sio = sio_from_ioconn(ep->conn);
	struct pcs_cluster_core *cc = cc_from_rpc(ep->eng);
	struct pcs_msg * msg;
	unsigned long timeout = 0;
	unsigned long tx;

	BUG_ON(ep->state != PCS_RPC_WORK);

	if (list_empty(&ep->pending_queue) && list_empty(&sio->write_queue)) {
		if (timer_pending(&ep->timer_work.timer))
			cancel_delayed_work(&ep->timer_work);
		return;
	}
	if (!list_empty(&ep->pending_queue)) {
		msg = list_first_entry(&ep->pending_queue, struct pcs_msg, list);

		timeout = msg->start_time + ep->params.response_timeout;
	}
	if (!list_empty(&sio->write_queue)) {
		msg = list_first_entry(&sio->write_queue, struct pcs_msg, list);
		tx = msg->start_time + sio->send_timeout;
		if (time_after(tx, timeout))
			timeout = tx;
	}
	if (time_is_before_jiffies(timeout))
		timeout = 0;
	else
		timeout -= jiffies;

	mod_delayed_work(cc->wq, &ep->timer_work, timeout);

}
static void rpc_queue_work(struct work_struct *w)
{
	LIST_HEAD(input_q);
	LIST_HEAD(complete_q);
	LIST_HEAD(state_q);
	struct pcs_rpc *ep = pcs_rpc_from_work(w);
	int repeat;

	pcs_rpc_get(ep);
again:
	spin_lock(&ep->q_lock);
	list_splice_tail_init(&ep->input_queue, &input_q);
	spin_unlock(&ep->q_lock);

	mutex_lock(&ep->mutex);

	TRACE("Handle queues\n");

	/* Process messages which are already in the sock queue */
	if (ep->state == PCS_RPC_WORK) {
		struct pcs_sockio *sio = sio_from_ioconn(ep->conn);

		pcs_sockio_xmit(sio);
	}

	/* Process delayed ones */
	while (!list_empty(&input_q)) {
		struct pcs_msg * msg = list_first_entry(&input_q, struct pcs_msg, list);

		list_del_init(&msg->list);
		pcs_rpc_send(ep, msg, 0);
	}
	list_splice_tail_init(&ep->state_queue, &state_q);
	while (!list_empty(&state_q)) {
		struct pcs_msg * msg = list_first_entry(&state_q, struct pcs_msg, list);

		/* Original code allow msg->ep can be from alien RPC. This is very
		   strange assumption. Seems this is impossible, and crewup my locking */
		BUG_ON(msg->rpc != ep);

		list_del_init(&msg->list);
		pcs_rpc_send(ep, msg, 1);
	}
	repeat = 0;
	if (ep->state == PCS_RPC_WORK) {
		struct pcs_sockio *sio = sio_from_ioconn(ep->conn);

		if (pcs_sockio_delayed_seg(sio))
			repeat = 1;
		update_xmit_timeout(ep);
	}
	mutex_unlock(&ep->mutex);
	if (repeat)
		goto again;
	pcs_rpc_put(ep);

}

struct pcs_rpc * pcs_rpc_alloc_ep(void)
{
	return kzalloc(sizeof(struct pcs_rpc), GFP_NOIO);
}

void pcs_rpc_configure_new_ep(struct pcs_rpc * ep, struct pcs_rpc_params *parm, struct pcs_rpc_ops * ops)
{
	int i;

	ep->params = *parm;
	ep->ops = ops;
	ep->kill_arrow = 0;

	INIT_WORK(&ep->work, rpc_queue_work);
	INIT_DELAYED_WORK(&ep->timer_work, timer_work);
	INIT_DELAYED_WORK(&ep->calendar_work, calendar_work);

	for (i = 0; i < RPC_MAX_CALENDAR; i++)
		INIT_HLIST_HEAD(&ep->kill_calendar[i]);
}

struct pcs_rpc * pcs_rpc_create(struct pcs_rpc_engine * eng, struct pcs_rpc_params *parm, struct pcs_rpc_ops * ops)
{
	struct pcs_rpc * ep = pcs_rpc_alloc_ep();
	pcs_rpc_attach_new_ep(ep, eng);
	pcs_rpc_configure_new_ep(ep, parm, ops);
	return ep;
}

void pcs_rpc_sent(struct pcs_msg * msg)
{
	struct pcs_rpc * ep = msg->rpc;

	BUG_ON(!mutex_is_locked(&ep->mutex));

	msg->start_time = jiffies;
	list_add_tail(&msg->list, &ep->pending_queue);
	msg->stage = PCS_MSG_STAGE_WAIT;

	if (!timer_pending(&ep->timer_work.timer)) {
		struct pcs_cluster_core *cc = cc_from_rpc(ep->eng);

		mod_delayed_work(cc->wq, &ep->timer_work, ep->params.response_timeout);
	}

	if (msg->timeout) {
		BUG_ON(msg->kill_slot >= RPC_MAX_CALENDAR);

		pcs_msg_add_calendar(msg, 0);
	} else
		INIT_HLIST_NODE(&msg->kill_link);
}

static void rpc_call_sent_cb(struct pcs_msg * clone)
{
	struct pcs_msg * msg = clone->private;
	struct pcs_rpc * ep = clone->rpc;

	BUG_ON(!mutex_is_locked(&ep->mutex));

	/* Inherit kill slot */
	msg->kill_slot = clone->kill_slot;

	///// TODO: dmonakhov@ optimize states
	if (pcs_if_error(&clone->error)) {
		switch (ep->state) {
		case PCS_RPC_UNCONN:
		case PCS_RPC_HOLDDOWN:
		case PCS_RPC_CONNECT:
		case PCS_RPC_AUTH:
		case PCS_RPC_AUTHWAIT:
			if (clone->timeout ||
			    clone->error.value == PCS_ERR_WRITE_TIMEOUT ||
			    clone->error.value == PCS_ERR_RESPONSE_TIMEOUT)
				break;

			pcs_clear_error(&clone->error);
			list_add_tail(&clone->list, &ep->state_queue);
			if (ep->state == PCS_RPC_UNCONN)
				pcs_rpc_connect(ep);
			return;
		}

		pcs_copy_error(&msg->error, &clone->error);
		msg->done(msg);
		pcs_free_msg(clone);
		return;
	}

	/*
	 * TODO: We should performs peiodic rpc health check as userspace do
	 * via rpc_trace_health
	 */
	pcs_rpc_sent(msg);
	pcs_free_msg(clone);
}

/* "User-friendly" send. It is not quite optimal (uses redundant clone), but appropriate
 * for most of simple rpc calls
 */

static void rpc_msg_output_destructor(struct pcs_msg * msg)
{
	if (msg->rpc)
		pcs_rpc_put(msg->rpc);
	memset(msg, 0xFF, sizeof(*msg));
	kfree(msg);
}

struct pcs_msg * pcs_rpc_clone_msg(struct pcs_msg * msg)
{
	struct pcs_msg *cloned_msg = pcs_clone_msg(msg);

	if (cloned_msg)
		cloned_msg->destructor = rpc_msg_output_destructor;
	return cloned_msg;
}

void pcs_rpc_call(struct pcs_rpc * ep, struct pcs_msg * msg)
{
	struct pcs_msg * clone;

	BUG_ON(msg->rpc != NULL);
	msg->rpc = pcs_rpc_get(ep);

	clone = pcs_rpc_clone_msg(msg);
	if (clone == NULL) {
		pcs_set_local_error(&msg->error, PCS_ERR_NOMEM);
		BUG_ON(!hlist_unhashed(&msg->kill_link));
		msg->done(msg);
		return;
	}

	pcs_clear_error(&clone->error);
	clone->rpc = NULL;
	clone->done = rpc_call_sent_cb;
	clone->timeout = msg->timeout;

	pcs_rpc_queue(ep, clone);
}
/* TODO: This pace may not scale well, in fact xid should be unique only
   across RPC so it may be reasonable to make it percpu
*/
void pcs_rpc_get_new_xid(struct pcs_rpc_engine *eng, PCS_XID_T *xid)
{
	xid->origin = eng->local_id;
	/* Remember, xids should be unique per peer. The only reliable way to ensure this is
	 * to generate xids globally.
	 */
	xid->val = atomic64_inc_return(&eng->xid_generator);
}

static int rpc_check_memlimit(struct pcs_rpc * ep)
{
	struct pcs_rpc_engine * eng = ep->eng;

	if ((ep->flags & PCS_RPC_F_ACCT) &&
	    eng->msg_allocated >= eng->mem_pressure_thresh) {
		/* If congestion avoidance works, this should not happen.
		 * However, if this happens we must do something.
		 */
		if (eng->msg_allocated > eng->mem_limit) {
			pcs_log(LOG_ERR, "Hard memory limit exceeded");
			return 1;
		}
		if (ep->peer_role == PCS_NODE_ROLE_CN) {
			/* CN contributes 3 (repl.norm) times of memory pressure on cluster */
			if (3 * ep->accounted * eng->accounted_rpcs >= eng->msg_allocated) {
				TRACE("Soft memory limit exceeded " PEER_FMT, PEER_ARGS(ep));
				return 1;
			}
		} else {
			if (ep->accounted * eng->accounted_rpcs >= eng->msg_allocated) {
				TRACE("Soft memory limit exceeded " PEER_FMT, PEER_ARGS(ep));
				return 1;
			}
		}
	}
	return 0;
}

void pcs_rpc_deaccount_msg(struct pcs_msg * msg)
{
	struct pcs_rpc * ep = msg->rpc;

	msg->rpc = NULL;
	ep->eng->msg_count--;

	if (msg->accounted) {
		ep->accounted -= msg->accounted;
		ep->eng->msg_allocated -= msg->accounted;
		if (ep->accounted == 0)
			ep->eng->accounted_rpcs--;
		msg->accounted = 0;
		if (ep->state == PCS_RPC_WORK)
			pcs_sock_unthrottle((struct pcs_sockio *)ep->conn);
	}
	pcs_rpc_put(ep);
}

static void pcs_rpc_account_msg(struct pcs_rpc * ep, struct pcs_msg * msg, int accounted)
{
	msg->accounted = 0;
	msg->rpc = pcs_rpc_get(ep);

	ep->eng->msg_count++;

	if (ep->flags & PCS_RPC_F_ACCT) {
		msg->accounted = accounted;

		if (ep->accounted == 0)
			ep->eng->accounted_rpcs++;

		ep->eng->msg_allocated += accounted;
		ep->accounted += accounted;
	}
}

void pcs_rpc_account_adjust(struct pcs_msg * msg, int adjustment)
{
	if (msg->accounted && (msg->rpc->flags & PCS_RPC_F_ACCT)) {
		struct pcs_rpc * ep = msg->rpc;

		msg->accounted += adjustment;
		ep->eng->msg_allocated += adjustment;
		ep->accounted += adjustment;
	}
}

static void pcs_rpc_input_destructor(struct pcs_msg * msg)
{
	pcs_rpc_deaccount_msg(msg);
	kfree(msg);
}

/* get_iter() handler for messages with embedded payload right after pcs_msg */
void pcs_rpc_get_iter_inline(struct pcs_msg * msg, int offset, struct iov_iter *it)
{
	BUG_ON(offset >= msg->size);

	iov_iter_init_plain(it, msg->_inline_buffer, msg->size, 0);
	iov_iter_advance(it, offset);
}

void pcs_rpc_init_input_msg(struct pcs_rpc * ep, struct pcs_msg * msg, int account)
{
	pcs_msg_io_init(msg);
	msg->timeout = 0;
	INIT_HLIST_NODE(&msg->kill_link);
	pcs_rpc_account_msg(ep, msg, account);
	msg->destructor = pcs_rpc_input_destructor;
}

struct pcs_msg * pcs_rpc_alloc_input_msg(struct pcs_rpc * ep, int datalen)
{
	struct pcs_msg * msg;

	if (rpc_check_memlimit(ep))
		return NULL;

	msg = kzalloc(sizeof(struct pcs_msg) + datalen, GFP_NOIO);
	if (msg) {
		pcs_rpc_init_input_msg(ep, msg, sizeof(struct pcs_msg) + datalen);
		msg->size = datalen;
		msg->get_iter = pcs_rpc_get_iter_inline;
	}
	return msg;
}


static void pcs_msg_output_destructor(struct pcs_msg * msg)
{
	if (msg->rpc)
		pcs_rpc_put(msg->rpc);
	kfree(msg);
}

void pcs_rpc_init_output_msg(struct pcs_msg * msg)
{
	pcs_msg_io_init(msg);
	pcs_clear_error(&msg->error);
	msg->timeout = 0;
	msg->rpc = NULL;
	INIT_HLIST_NODE(&msg->kill_link);
	msg->destructor = pcs_msg_output_destructor;
}

struct pcs_msg * pcs_rpc_alloc_output_msg(int datalen)
{
	struct pcs_msg * msg;

	msg = kzalloc(sizeof(struct pcs_msg) + datalen, GFP_NOIO);
	if (msg) {
		pcs_rpc_init_output_msg(msg);
		msg->size = datalen;
		msg->get_iter = pcs_rpc_get_iter_inline;
	}
	return msg;
}

void pcs_rpc_init_response(struct pcs_msg * msg, struct pcs_rpc_hdr * req_hdr, int size)
{
	struct pcs_rpc_hdr * h;

	h = (struct pcs_rpc_hdr *)msg->_inline_buffer;
	h->len = size;
	h->type = req_hdr->type | PCS_RPC_DIRECTION;
	h->xid = req_hdr->xid;
}

struct pcs_msg * pcs_alloc_response(struct pcs_rpc_hdr * req_hdr, int size)
{
	struct pcs_msg * msg;

	msg = pcs_rpc_alloc_output_msg(size);
	if (msg == NULL)
		return NULL;

	pcs_rpc_init_response(msg, req_hdr, size);

	return msg;
}

void pcs_rpc_set_peer_id(struct pcs_rpc * ep, PCS_NODE_ID_T * id, u8 role)
{
	BUG_ON(ep->flags & (PCS_RPC_F_PEER_ID|PCS_RPC_F_HASHED));
	ep->peer_role = role;
	memcpy(&ep->peer_id, id, sizeof(PCS_NODE_ID_T));
	ep->flags |= PCS_RPC_F_CLNT_PEER_ID;
}

int pcs_rpc_set_address(struct pcs_rpc * ep, PCS_NET_ADDR_T * addr)
{
	BUG_ON(ep->state != PCS_RPC_UNCONN);

	ep->addr = *addr;
	return 0;
}

/* Reset rpc engine, move it to unconnected state ready for further connects. */
void pcs_rpc_reset(struct pcs_rpc * ep)
{
	rpc_abort(ep, 1, PCS_ERR_NET_ABORT);
	ep->retries = 0;
	if (ep->state == PCS_RPC_ABORT)
		ep->state = PCS_RPC_UNCONN;
}

static void timer_work(struct work_struct *w)
{
	struct pcs_rpc * ep = container_of(w, struct pcs_rpc, timer_work.work);

	mutex_lock(&ep->mutex);
	switch (ep->state) {
	case PCS_RPC_HOLDDOWN:
		ep->state = PCS_RPC_UNCONN;
		pcs_rpc_connect(ep);
		break;

	case PCS_RPC_WORK: {
		int err = list_empty(&ep->pending_queue) ? PCS_ERR_RESPONSE_TIMEOUT : PCS_ERR_WRITE_TIMEOUT;

		TRACE("rpc timer expired, killing connection to " PEER_FMT ", %d",
		      PEER_ARGS(ep), err);
		rpc_abort(ep, 0, err);
		break;
	}
	/* TODO CLEAN unused states */
	case PCS_RPC_AUTHWAIT:
	case PCS_RPC_AUTH:
	case PCS_RPC_CONNECT:
		BUG_ON(1);
		break;
	}
	mutex_unlock(&ep->mutex);
}

static void connstat_work(struct work_struct *w)
{
	struct pcs_rpc_engine * eng = container_of(w, struct pcs_rpc_engine, stat_work.work);
	struct pcs_cluster_core *cc = cc_from_rpc(eng);

	pcs_log(LOG_INFO, "TODO send connstat-s\n");
	(void)eng;
	/* account_connstat(eng); */
	mod_delayed_work(cc->wq, &eng->stat_work, PCS_MSG_MAX_CALENDAR * HZ);
}


void pcs_rpc_engine_init(struct pcs_rpc_engine * eng, u8 role)
{
	int i;
	memset(eng, 0, sizeof(*eng));
	eng->role = role;
	for (i = 0; i < RPC_GC_MAX_CLASS; i++)
		list_lru_init(&eng->gc[i].lru);

	INIT_DELAYED_WORK(&eng->stat_work, connstat_work);

}

void pcs_rpc_engine_fini(struct pcs_rpc_engine * eng)
{
	unsigned int i;

	for (i = 0; i < PCS_RPC_HASH_SIZE; i++) {
		while (!hlist_empty(&eng->ht[i])) {
			struct pcs_rpc * ep = hlist_entry(eng->ht[i].first, struct pcs_rpc, link);

			pcs_rpc_close(ep);
		}
	}

	while (!hlist_empty(&eng->unhashed)) {
		struct pcs_rpc * ep = hlist_entry(eng->unhashed.first, struct pcs_rpc, link);

		pcs_rpc_close(ep);
	}

	for (i = 0; i < RPC_GC_MAX_CLASS; i++) {
		BUG_ON(list_lru_count(&eng->gc[i].lru));
		list_lru_destroy(&eng->gc[i].lru);
	}
}

void pcs_rpc_set_host_id(struct pcs_rpc_engine *eng, PCS_NODE_ID_T *host_id)
{
	eng->my_host.host_id.val = host_id->val;
	eng->flags |= PCS_KNOWN_HOSTID;
}

void pcs_rpc_set_cluster_id(struct pcs_rpc_engine * eng, PCS_CLUSTER_ID_T * id)
{
	memcpy(&eng->cluster_id, id, sizeof(*id));
	eng->flags |= PCS_KNOWN_CLUSTERID;
}

void pcs_rpc_set_location(struct pcs_rpc_engine * eng, struct pcs_location * loc)
{
	memcpy(&eng->my_host.location, loc, sizeof(*loc));
}

static int rpc_gc_classify(struct pcs_rpc * ep)
{
	BUG_ON(ep->eng->role != PCS_NODE_ROLE_TOOL);

	return 0;
}

void pcs_rpc_init_gc(struct pcs_rpc_engine * eng, unsigned int limit)
{
	eng->max_connections = limit;

	switch (eng->role) {
	case PCS_NODE_ROLE_MDS:
		eng->max_gc_index = 3;
		break;
	case PCS_NODE_ROLE_CS:
		eng->max_gc_index = 4;
		break;
	case PCS_NODE_ROLE_CN:
		eng->max_gc_index = 2;
		break;
	default:
		eng->max_gc_index = 1;
	}
}


void pcs_rpc_set_memlimits(struct pcs_rpc_engine * eng, u64 thresh, u64 limit)
{
	eng->mem_pressure_thresh = thresh;
	eng->mem_limit = limit;
}

void rpc_connect_done(struct pcs_rpc *ep, struct socket *sock)
{
	struct pcs_sockio * sio;

	mutex_lock(&ep->mutex);

	TRACE(PEER_FMT " ->state:%d sock:%p\n", PEER_ARGS(ep), ep->state, sock);
	cancel_delayed_work(&ep->timer_work);
	ep->retries++;

	if (ep->state != PCS_RPC_CONNECT) {
		pcs_log(LOG_ERR, "Invalid state: %u", ep->state);
		BUG();
	}

	sio = pcs_sockio_init(sock, ep->params.alloc_hdr_size,
			      sizeof(struct pcs_rpc_hdr));
	if (sio == NULL)
		BUG();

	ep->conn = &sio->ioconn;
	sio->parent = ep;
	sio->get_msg = rpc_get_hdr;
	sio->eof = rpc_eof_cb;
	//pcs_ioconn_register(ep->conn);
	ep->retries = 0;
	if (ep->gc)
		list_lru_add(&ep->gc->lru, &ep->lru_link);

	if (ep->flags & PCS_RPC_F_CLNT_PEER_ID)
		ep->flags |= PCS_RPC_F_PEER_ID;
	ep->state = PCS_RPC_APPWAIT;
	pcs_rpc_enable(ep, 0);
	mutex_unlock(&ep->mutex);

}
