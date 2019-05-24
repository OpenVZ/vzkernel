#include <net/sock.h>
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/rbtree.h>

#include "pcs_types.h"
#include "pcs_sock_io.h"
#include "pcs_rpc.h"
#include "pcs_sock_io.h"
#include "pcs_req.h"
#include "pcs_map.h"
#include "pcs_cs.h"
#include "pcs_cs_prot.h"
#include "pcs_cluster.h"
#include "pcs_ioctl.h"
#include "log.h"
#include "fuse_ktrace.h"

/* Lock order: cs->lock -> css->lock (lru, hash, bl_list) */


struct pcs_rpc_params cn_rpc_params = {
	.alloc_hdr_size		= sizeof(struct pcs_rpc_hdr),
	.max_msg_size		= PCS_CS_MSG_MAX_SIZE,
	.holddown_timeout	= HZ,
	.connect_timeout	= 5*HZ,
	.response_timeout	= 30*HZ,
	.max_conn_retry		= 3,
	.flags			= 0,
};

static void cs_aborting(struct pcs_rpc *ep, int error);
static struct pcs_msg *cs_get_hdr(struct pcs_rpc *ep, struct pcs_rpc_hdr *h);
static int cs_input(struct pcs_rpc *ep, struct pcs_msg *msg);
static void cs_keep_waiting(struct pcs_rpc *ep, struct pcs_msg *req, struct pcs_msg *msg);
static void cs_connect(struct pcs_rpc *ep);
static void pcs_cs_isolate(struct pcs_cs *cs, struct list_head *dispose);
static void pcs_cs_destroy(struct pcs_cs *cs);

struct pcs_rpc_ops cn_rpc_ops = {
	.demux_request		= cs_input,
	.get_hdr		= cs_get_hdr,
	.state_change		= cs_aborting,
	.keep_waiting		= cs_keep_waiting,
	.connect		= cs_connect,
};

struct pcs_cs *pcs_cs_alloc(struct pcs_cs_set *css,
			     struct pcs_cluster_core *cc)
{
	struct pcs_cs *cs;

	cs = kzalloc(sizeof(struct pcs_cs), GFP_NOIO);
	if (cs == NULL)
		return NULL;

	INIT_HLIST_NODE(&cs->hlist);
	INIT_LIST_HEAD(&cs->lru_link);
	spin_lock_init(&cs->lock);
	cs->css = css;
	cs->cwnd = PCS_CS_INIT_CWND;
	cs->eff_cwnd = PCS_CS_INIT_CWND;
	cs->ssthresh = PCS_CS_INIT_CWND;

	pcs_cs_init_cong_queue(cs);
	pcs_cs_init_active_list(cs);

	cs->io_prio = -1;

	INIT_LIST_HEAD(&cs->flow_lru);
	INIT_LIST_HEAD(&cs->bl_link);

	cs->rpc = pcs_rpc_create(&cc->eng, &cn_rpc_params, &cn_rpc_ops);
	if (cs->rpc == NULL) {
		kfree(cs);
		return NULL;
	}
	cs->rpc->private = cs;
	INIT_LIST_HEAD(&cs->map_list);
	return cs;
}

unsigned int pcs_cs_hash(PCS_NODE_ID_T *id)
{
	return *(unsigned int *)id % PCS_CS_HASH_SIZE;
}

static struct pcs_cs *
__lookup_cs(struct pcs_cs_set *csset, PCS_NODE_ID_T *id)
{
	struct pcs_cs *cs;
	hlist_for_each_entry_rcu(cs, &csset->ht[pcs_cs_hash(id)], hlist) {
		if (memcmp(&cs->id, id, sizeof(cs->id)) == 0)
			return cs;
	}
	return NULL;
}

static struct pcs_cs *
lookup_and_lock_cs(struct pcs_cs_set *csset, PCS_NODE_ID_T *id)
{
	struct pcs_cs *cs;
retry:
	rcu_read_lock();
	cs = __lookup_cs(csset, id);
	if (!cs) {
		rcu_read_unlock();
		return NULL;
	}
	spin_lock(&cs->lock);
	rcu_read_unlock();
	if (cs->is_dead) {
		spin_unlock(&cs->lock);
		goto retry;
	}
	return cs;
}

static void add_cs(struct pcs_cs_set *csset, struct pcs_cs *cs)
{
	unsigned int hash = pcs_cs_hash(&cs->id);

	assert_spin_locked(&csset->lock);

	list_add_tail(&cs->lru_link, &csset->lru);
	csset->ncs++;
	hlist_add_head_rcu(&cs->hlist, &csset->ht[hash]);
}

static inline int netaddr_cmp(PCS_NET_ADDR_T const *addr1, PCS_NET_ADDR_T const *addr2, int ignore_port)
{
	unsigned int d;
	size_t sz = 0;

	d = addr1->type - addr2->type;
	if (d)
		return d;
	d = addr1->port - addr2->port;
	if (!ignore_port && d)
		return d;

	switch (addr1->type) {
	case PCS_ADDRTYPE_IP:
	case PCS_ADDRTYPE_RDMA:
		sz = sizeof(struct in_addr);
		break;
	case PCS_ADDRTYPE_IP6:
		sz = sizeof(struct in6_addr);
		break;
	default:
		BUG();
	}

	return memcmp(addr1->address, addr2->address, sz);
}

static int pcs_netaddr_cmp(PCS_NET_ADDR_T const *addr1, PCS_NET_ADDR_T const *addr2)
{
	return netaddr_cmp(addr1, addr2, 0);
}

/* Return locked cs */
struct pcs_cs *pcs_cs_find_create(struct pcs_cs_set *csset, PCS_NODE_ID_T *id, PCS_NET_ADDR_T *addr, int flags)
{
	struct pcs_cs *cs;

again:
	cs = lookup_and_lock_cs(csset, id);
	if (cs) {
		/* If rpc is connected, leave it connected until failure.
		 * After current connect fails, reconnect will be done to new address
		 */
		if (addr) {
			if (addr->type != PCS_ADDRTYPE_NONE) {
				if (pcs_netaddr_cmp(&cs->addr, addr)) {
					cs->addr = *addr;
					cs->addr_serno++;

					FUSE_KTRACE(cc_from_csset(csset)->fc,
						    "Port change CS" NODE_FMT " seq=%d",
						    NODE_ARGS(*id), cs->addr_serno);
					pcs_rpc_set_address(cs->rpc, addr);

					if (!(flags & CS_FL_INACTIVE)) {
						pcs_map_notify_addr_change(cs);
						cs_whitelist(cs, "addr update");
					}
				}
			} else {
				if (WARN_ON_ONCE(!(flags & CS_FL_INACTIVE))) {
					spin_unlock(&cs->lock);
					return NULL;
				}
			}
		}
		if (flags & CS_FL_LOCAL_SOCK)
			cs->rpc->flags |= PCS_RPC_F_LOCAL;
		else
			cs->rpc->flags &= ~PCS_RPC_F_LOCAL;
		return cs;
	}
	BUG_ON(addr == NULL);

	cs = pcs_cs_alloc(csset, cc_from_csset(csset));
	if (!cs)
		return NULL;

	cs->id = *id;

	cs->addr = *addr;
	cs->addr_serno = 1;

	pcs_rpc_set_peer_id(cs->rpc, id, PCS_NODE_ROLE_CS);
	pcs_rpc_set_address(cs->rpc, addr);

	if (flags & CS_FL_LOCAL_SOCK)
		cs->rpc->flags |= PCS_RPC_F_LOCAL;
	else
		cs->rpc->flags &= ~PCS_RPC_F_LOCAL;

	spin_lock(&cs->lock);
	spin_lock(&csset->lock);
	if (__lookup_cs(csset, id)) {
		spin_unlock(&csset->lock);
		cs->is_dead = 1;
		spin_unlock(&cs->lock);
		pcs_cs_destroy(cs);
		goto again;
	}
	add_cs(csset, cs);
	spin_unlock(&csset->lock);
	return cs;
}

void cs_log_io_times(struct pcs_int_request * ireq, struct pcs_msg * resp, unsigned int max_iolat)
{
	/* Ugly. Need to move fc ref to get rid of pcs_cluster_core */
	struct fuse_conn * fc = container_of(ireq->cc, struct pcs_fuse_cluster, cc)->fc;
	struct pcs_cs_iohdr * h = (struct pcs_cs_iohdr *)msg_inline_head(resp);
	int reqt = h->hdr.type != PCS_CS_SYNC_RESP ? ireq->iochunk.cmd : PCS_REQ_T_SYNC;

	fuse_stat_account(fc, reqt, ktime_sub(ktime_get(), ireq->ts_sent));
	if (fc->ktrace && fc->ktrace_level >= LOG_TRACE) {
		int n = 1;
		struct fuse_trace_hdr * t;

		if (h->hdr.type != PCS_CS_READ_RESP && h->hdr.type != PCS_CS_FIEMAP_RESP) {
			struct pcs_cs_sync_resp * srec;

			for (srec = (struct pcs_cs_sync_resp*)(h + 1);
			     (void*)(srec + 1) <= (void*)h + h->hdr.len;
			     srec++)
				n++;
		}

		t = FUSE_TRACE_PREPARE(fc->ktrace, FUSE_KTRACE_IOTIMES, sizeof(struct fuse_tr_iotimes_hdr) +
				       n*sizeof(struct fuse_tr_iotimes_cs));
		if (t) {
			struct fuse_tr_iotimes_hdr * th = (struct fuse_tr_iotimes_hdr *)(t + 1);
			struct fuse_tr_iotimes_cs * ch = (struct fuse_tr_iotimes_cs *)(th + 1);

			th->chunk = ireq->iochunk.chunk;
			th->offset = h->hdr.type != PCS_CS_SYNC_RESP ? ireq->iochunk.chunk + ireq->iochunk.offset : 0;
			th->size = h->hdr.type != PCS_CS_SYNC_RESP ? ireq->iochunk.size : 0;
			th->start_time = ktime_to_us(ireq->ts);
			th->local_delay = ktime_to_us(ktime_sub(ireq->ts_sent, ireq->ts));
			th->lat = t->time - ktime_to_us(ireq->ts_sent);
			th->ino = ireq->dentry->fileinfo.attr.id;
			th->type = h->hdr.type;
			th->cses = 1;

			ch->csid = resp->rpc->peer_id.val;
			ch->misc = h->sync.misc;
			ch->ts_net = h->sync.ts_net;
			ch->ts_io = h->sync.ts_io;
			ch++;

			if (h->hdr.type != PCS_CS_READ_RESP && h->hdr.type != PCS_CS_FIEMAP_RESP) {
				struct pcs_cs_sync_resp * srec;

				for (srec = (struct pcs_cs_sync_resp*)(h + 1);
				     (void*)(srec + 1) <= (void*)h + h->hdr.len;
				     srec++) {
					ch->csid = srec->cs_id.val;
					ch->misc = srec->sync.misc;
					ch->ts_net = srec->sync.ts_net;
					ch->ts_io = srec->sync.ts_io;
					ch++;
					th->cses++;
				}
			}
		}
		FUSE_TRACE_COMMIT(fc->ktrace);
	}
}

void pcs_cs_update_stat(struct pcs_cs *cs, u32 iolat, u32 netlat, int op_type)
{
	pcs_perfcounter_stat_update(&cs->stat.iolat, iolat);
	pcs_perfcounter_stat_update(&cs->stat.netlat, netlat);
	switch (op_type) {
	case PCS_CS_WRITE_SYNC_RESP:
	case PCS_CS_WRITE_RESP:
		cs->stat.write_ops_rate.total++;
		break;
	case PCS_CS_READ_RESP:
		cs->stat.read_ops_rate.total++;
		break;
	case PCS_CS_SYNC_RESP:
		cs->stat.sync_ops_rate.total++;
		break;
	}
}

static void cs_response_done(struct pcs_msg *msg)
{
	struct pcs_int_request *ireq = ireq_from_msg(msg);
	unsigned int resp_size = 0;

	if (!pcs_if_error(&msg->error)) {
		struct pcs_cs_iohdr *h = (struct pcs_cs_iohdr *)msg_inline_head(msg->response);

		if (h->sync.misc & PCS_CS_IO_CACHED)
			ireq->flags |= IREQ_F_CACHED;

		resp_size = h->hdr.len - sizeof(struct pcs_cs_iohdr);

		pcs_map_verify_sync_state(ireq->dentry, ireq, msg);
	} else {
		FUSE_KTRACE(ireq->cc->fc, XID_FMT " IO error %d %lu, ireq:%p : %llu:%u+%u",
		      XID_ARGS(ireq->iochunk.hbuf.hdr.xid), msg->error.value,
		      msg->error.remote ? (unsigned long)msg->error.offender.val : 0UL,
		      ireq, (unsigned long long)ireq->iochunk.chunk,
		      (unsigned)ireq->iochunk.offset,
		      (unsigned)ireq->iochunk.size);
	}

	pcs_copy_error_cond(&ireq->error, &msg->error);
	if (msg->rpc) {
		pcs_rpc_put(msg->rpc);
		msg->rpc = NULL;
	}
	if (ireq->type == PCS_IREQ_IOCHUNK && ireq->iochunk.cmd == PCS_REQ_T_FIEMAP) {
		ireq->completion_data.parent->apireq.aux = resp_size;
		ireq->completion_data.parent->apireq.req->pos = ireq->iochunk.chunk;
	}
	ireq_complete(ireq);
}

static void cs_get_read_response_iter(struct pcs_msg *msg, int offset, struct iov_iter *it)
{
	if (offset < sizeof(struct pcs_cs_iohdr)) {
		iov_iter_init_plain(it, msg->_inline_buffer,
				  sizeof(struct pcs_cs_iohdr), 0);
		iov_iter_advance(it, offset);
		TRACE("return msg:%p->size:%d off:%d it_len:%ld\n\n", msg, msg->size, offset, iov_iter_count(it));
		return;
	} else {
		struct pcs_msg *req = msg->private;
		struct pcs_int_request *ireq = req->private2;
		struct pcs_int_request *parent = ireq->completion_data.parent;

		if (parent->type == PCS_IREQ_API) {
			pcs_api_iorequest_t *ar = parent->apireq.req;

			/* Read directly to memory given by user */
			BUG_ON(ireq->iochunk.cmd != PCS_REQ_T_READ && ireq->iochunk.cmd != PCS_REQ_T_FIEMAP);

			offset -= (unsigned int)sizeof(struct pcs_cs_iohdr);
			ar->get_iter(ar->datasource, ireq->iochunk.dio_offset, it);
			iov_iter_truncate(it, msg->size - sizeof(struct pcs_cs_iohdr));
			iov_iter_advance(it, offset);

			TRACE("return msg:%p->size:%d off:%d it_len:%ld\n\n", msg, msg->size, offset, iov_iter_count(it));
			return;
		} else
			BUG();
	}
}

static void cs_connect(struct pcs_rpc *ep)
{
	struct pcs_cluster_core *cc = cc_from_rpc(ep->eng);
	struct pcs_fuse_cluster *pfc = pcs_cluster_from_cc(cc);

	ep->state = PCS_RPC_CONNECT;
	if (fuse_pcs_csconn_send(pfc->fc, ep, PCS_IOC_CS_OPEN))
		pcs_rpc_reset(ep);
}

static struct pcs_msg *cs_get_hdr(struct pcs_rpc *ep, struct pcs_rpc_hdr *h)
{
	struct pcs_msg *msg, *resp;
	struct pcs_rpc_hdr *req_h;
	struct pcs_int_request *ireq;

	if (!RPC_IS_RESPONSE(h->type))
		return NULL;

	if (h->type != PCS_CS_READ_RESP && h->type != PCS_CS_FIEMAP_RESP)
		return NULL;

	/* The goal is to avoid allocation new msg and reuse one inlined in ireq */

	msg = pcs_rpc_lookup_xid(ep, &h->xid);
	if (msg == NULL)
		return NULL;

	req_h = (struct pcs_rpc_hdr *)msg_inline_head(msg);
	if (req_h->type != (h->type & ~PCS_RPC_DIRECTION))
		return NULL;

	ireq = msg->private2;
	if (ireq->type != PCS_IREQ_IOCHUNK)
		return NULL;
	if (ireq->iochunk.cmd == PCS_REQ_T_READ) {
		if (ireq->iochunk.size + sizeof(struct pcs_cs_iohdr) != h->len)
			return NULL;
	} else if (ireq->iochunk.cmd == PCS_REQ_T_FIEMAP) {
		if (PCS_FIEMAP_BUFSIZE + sizeof(struct pcs_cs_iohdr) < h->len)
			return NULL;
	} else
		return NULL;

	resp = pcs_rpc_alloc_input_msg(ep, sizeof(struct pcs_cs_iohdr));
	if (!resp)
		return NULL;

	memcpy(resp->_inline_buffer, h, sizeof(struct pcs_rpc_hdr));
	resp->size = h->len;
	resp->private = msg;
	resp->get_iter = cs_get_read_response_iter;
	resp->done = rpc_work_input;
	pcs_msg_del_calendar(msg);

	return resp;
}

static void cs_get_data(struct pcs_msg *msg, int offset, struct iov_iter *it)
{
	struct pcs_int_request *ireq = ireq_from_msg(msg);

	if (offset < sizeof(struct pcs_cs_iohdr)) {
		iov_iter_init_plain(it, (char *)&ireq->iochunk.hbuf,
				  sizeof(struct pcs_cs_iohdr), 0);
		iov_iter_advance(it, offset);
		TRACE("return msg:%p->size:%d off:%d it_len:%ld\n\n", msg, msg->size, offset, iov_iter_count(it));

		return;
	} else {
		struct pcs_int_request *parent = ireq->completion_data.parent;
		if (parent->type == PCS_IREQ_API) {
			pcs_api_iorequest_t *ar = parent->apireq.req;

			BUG_ON(ireq->iochunk.cmd != PCS_REQ_T_WRITE);

			offset -= (unsigned int)sizeof(struct pcs_cs_iohdr);
			ar->get_iter(ar->datasource, ireq->iochunk.dio_offset, it);
			iov_iter_truncate(it, ireq->iochunk.size);
			iov_iter_advance(it, offset);

			TRACE("return msg:%p->size:%d off:%d it_len:%ld\n\n", msg, msg->size, offset, iov_iter_count(it));
			return;
		} else
			BUG();
	}
}

static void cs_sent(struct pcs_msg *msg)
{
	msg->done = cs_response_done;
	if (pcs_if_error(&msg->error)) {
		msg->done(msg);
		return;
	}
	pcs_rpc_sent(msg);
}

void pcs_cs_submit(struct pcs_cs *cs, struct pcs_int_request *ireq)
{
	struct pcs_msg *msg = &ireq->iochunk.msg;
	struct pcs_cs_iohdr *ioh;
	struct pcs_cs_list *csl = ireq->iochunk.csl;
	struct pcs_map_entry *map = ireq->iochunk.map; /* ireq keeps reference to map */

	msg->private = cs;

	BUG_ON(msg->rpc);
	msg->private2 = ireq;

	ioh = &ireq->iochunk.hbuf;
	ioh->hdr.len = sizeof(struct pcs_cs_iohdr);
	switch (ireq->iochunk.cmd) {
	case PCS_REQ_T_READ:
		ioh->hdr.type = PCS_CS_READ_REQ;
		break;
	case PCS_REQ_T_WRITE:
		ioh->hdr.type = (ireq->dentry->fileinfo.attr.attrib & PCS_FATTR_IMMEDIATE_WRITE) ?
				PCS_CS_WRITE_SYNC_REQ : PCS_CS_WRITE_REQ;
		ioh->hdr.len += ireq->iochunk.size;
		break;
	case PCS_REQ_T_WRITE_HOLE:
		ioh->hdr.type = PCS_CS_WRITE_HOLE_REQ;
		break;
	case PCS_REQ_T_WRITE_ZERO:
		ioh->hdr.type = PCS_CS_WRITE_ZERO_REQ;
		break;
	case PCS_REQ_T_FIEMAP:
		ioh->hdr.type = PCS_CS_FIEMAP_REQ;
		break;
	}
	pcs_rpc_get_new_xid(&cc_from_cs(cs)->eng, &ioh->hdr.xid);
	ioh->offset = ireq->iochunk.offset;
	ioh->size = ireq->iochunk.size;
	ioh->iocontext = (u32)ireq->dentry->fileinfo.attr.id;
	ioh->_reserved = 0;
	if (ireq->iochunk.cmd == PCS_REQ_T_FIEMAP)
		ioh->fiemap_count = PCS_FIEMAP_CHUNK_COUNT;
	memset(&ioh->sync, 0, sizeof(ioh->sync));

	if (ireq->flags & IREQ_F_SEQ)
		ioh->sync.misc = PCS_CS_IO_SEQ;

	if (ireq->dentry->fileinfo.attr.attrib & PCS_FATTR_IMMEDIATE_WRITE)
		ioh->sync.misc |= PCS_CS_IO_SYNC;

	msg->size = ioh->hdr.len;
	msg->rpc = NULL;
	pcs_clear_error(&msg->error);
	msg->done = cs_sent;
	msg->get_iter = cs_get_data;

	if ((map->state & PCS_MAP_DEAD) || (map->cs_list != csl)) {
		ireq->error.value = PCS_ERR_CSD_STALE_MAP;
		ireq->error.remote = 1;
		ireq->error.offender = csl->cs[0].info.id;
		ireq_complete(ireq);
		return;
	}

	ioh->map_version = csl->version;
	/* vstorage never changes once allocated chunk id, so we can copy it
	 * directly from map.
	 */
	ioh->uid = map->id;
	if (pcs_req_direction(ireq->iochunk.cmd))
		msg->timeout = csl->write_timeout;
	else
		msg->timeout = csl->read_timeout;
	ireq->ts_sent = ktime_get();
	ireq->wait_origin.val = 0;


	DTRACE(XID_FMT " About to send msg:%p, ireq:%p, cmd:%u,"
		" id:"CUID_FMT" v:"VER_FMT" - %llu:%u+%u\n",
		XID_ARGS(ireq->iochunk.hbuf.hdr.xid), msg, ireq,
		ireq->iochunk.cmd, CUID_ARGS(ioh->uid),
		VER_ARGS(ioh->map_version),
		(unsigned long long)ireq->iochunk.chunk,
		(unsigned)ireq->iochunk.offset,
		(unsigned)ireq->iochunk.size);

/* TODO reanable ratelimiting */
#if 0
	if (cc_from_cs(cs)->rlim.rate)
		pcs_submit_ratelimited(&cc_from_cs(cs)->rlim, ireq);
	else
		pcs_rpc_send(cs->rpc, msg);
#endif
	pcs_rpc_queue(cs->rpc, msg);
}

static void handle_congestion(struct pcs_cs *cs, struct pcs_rpc_hdr *h)
{
	struct pcs_cs *who;

	FUSE_KTRACE(cc_from_csset(cs->css)->fc, "Received congestion notification from CS" NODE_FMT, NODE_ARGS(h->xid.origin));

	if (cs->id.val == h->xid.origin.val) {
		who = cs;
		spin_lock(&who->lock);
	} else
		who = lookup_and_lock_cs(cs->css, &h->xid.origin);

	if (who && !who->cwr_state) {
		/* Unless node is already reducing congestion window, shrink it
		 * to half of min(in_flight, cwnd) and enter congestion reduction state,
		 * where we ignore further congestion notifications until window is reduced
		 */
		if (who->cwnd >= PCS_CS_INIT_CWND)
			who->ssthresh = who->cwnd;
		else
			who->ssthresh = PCS_CS_INIT_CWND;
		if (who->in_flight < who->cwnd)
			who->cwnd = who->in_flight;
		who->cwnd /= 2;
		if (who->cwnd == 0)
			who->cwnd = 1;
		if (who->eff_cwnd > who->cwnd)
			who->eff_cwnd = who->cwnd;
		if (who->in_flight >= who->eff_cwnd)
			who->cwr_state = 1;
	}
	spin_unlock(&who->lock);
}

static int may_reroute(struct pcs_cs_list *csl, PCS_NODE_ID_T cs_id)
{
	int i;
	int legit = 0;

	for (i = csl->nsrv - 1; i >= 0; i--) {
		struct pcs_cs *cs;

		cs = rcu_dereference_protected(csl->cs[i].cslink.cs,
					       atomic_read(&csl->refcnt) > 0);
		if (cs->id.val == cs_id.val)
			continue;
		if (test_bit(CS_SF_FAILED, &cs->state))
			continue;
		if (cs_is_blacklisted(cs))
			continue;
		if (test_bit(i, &csl->blacklist) &&
		    jiffies < READ_ONCE(csl->blacklist_expires))
			continue;
		legit++;
	}
	return legit;
}

static void cs_keep_waiting(struct pcs_rpc *ep, struct pcs_msg *req, struct pcs_msg *msg)
{
	struct pcs_rpc_hdr *h = (struct pcs_rpc_hdr *)msg_inline_head(msg);
	struct pcs_cs *cs = ep->private;
	struct pcs_cs *who;

	/* Some CS reported it cannot complete local IO in time, close congestion window */
	who = lookup_and_lock_cs(cs->css, &h->xid.origin);
	if (who) {
		struct pcs_int_request *ireq = req->private2;
		abs_time_t lat = 0; /* GCC bug */
		if (ireq) {
			lat = ktime_to_us(ktime_sub(ktime_get(), ireq->ts_sent));
			cs_update_io_latency(who, lat);

			ireq->wait_origin = h->xid.origin;
		}

		if (!who->cwr_state) {
			FUSE_KTRACE(cc_from_csset(cs->css)->fc, "Congestion window on CS" NODE_FMT " reducing %d/%d/%d", NODE_ARGS(h->xid.origin),
				    who->in_flight, who->eff_cwnd, who->cwnd);
			if (who->cwnd >= PCS_CS_INIT_CWND)
				who->ssthresh = who->cwnd;
			else
				who->ssthresh = PCS_CS_INIT_CWND;
			if (who->in_flight < who->cwnd)
				who->cwnd = who->in_flight;
			who->cwnd /= 2;
			if (who->cwnd == 0)
				who->cwnd = 1;
			if (who->eff_cwnd > who->cwnd)
				who->eff_cwnd = who->cwnd;
			if (who->in_flight >= who->eff_cwnd)
				who->cwr_state = 1;
		}

		if (ireq && ireq->type == PCS_IREQ_IOCHUNK && !pcs_req_direction(ireq->iochunk.cmd)) {
			/* Force CS reselection */
			pcs_map_force_reselect(who);

			/* If request still has no banned CS and delayed for too long,
			 * cancel and reroute
			 */
			if (ireq->iochunk.banned_cs.val == 0 && lat >= PCS_MAX_READ_IO_LATENCY*1000
			    && may_reroute(ireq->iochunk.csl, h->xid.origin)) {
				ireq->iochunk.banned_cs = h->xid.origin;
				spin_unlock(&who->lock);
				FUSE_KTRACE(ireq->cc->fc, "Canceling read on CS" NODE_FMT, NODE_ARGS(h->xid.origin));
				pcs_rpc_cancel_request(req);
				return;
			}
		}

		spin_unlock(&who->lock);
	}

}

static int cs_input(struct pcs_rpc *ep, struct pcs_msg *msg)
{
	struct pcs_rpc_hdr *h = (struct pcs_rpc_hdr *)msg->_inline_buffer;

	switch (h->type) {
	case PCS_CS_CONG_NOTIFY:
		handle_congestion(ep->private, h);
		msg->done(msg);
		return 0;
	default:
		FUSE_KLOG(cc_from_rpc(ep->eng)->fc, LOG_ERR, "Unsupported message type %u", h->type);
		return PCS_ERR_PROTOCOL;
	}
}

void pcs_cs_notify_error(struct pcs_cluster_core *cc, pcs_error_t *err)
{
	struct list_head queue;
	struct pcs_cs *cs;

	INIT_LIST_HEAD(&queue);

	/* Filter out errors specific for particular chunk.
	 * Probably, we should handle only timeouts here.
	 */
	switch (err->value) {
	case PCS_ERR_CSD_STALE_MAP:
	case PCS_ERR_CSD_REPLICATING:
	case PCS_ERR_PROTOCOL:
	case PCS_ERR_CSD_RO_MAP:
		return;
	}

	cs = lookup_and_lock_cs(&cc->css, &err->offender);
	if (cs == NULL)
		return;

	list_splice_tail_init(&cs->active_list, &queue);
	list_splice_tail_init(&cs->cong_queue, &queue);
	cs->cong_queue_len = 0;
	cs_blacklist(cs, err->value, "notify error");
	spin_unlock(&cs->lock);

	pcs_cc_requeue(cc, &queue);

}

static void pcs_cs_isolate(struct pcs_cs *cs, struct list_head *dispose)
{
	assert_spin_locked(&cs->lock);

	list_splice_tail_init(&cs->active_list, dispose);
	list_splice_tail_init(&cs->cong_queue, dispose);
	cs->cong_queue_len = 0;

	cs->is_dead = 1;
	spin_lock(&cs->css->lock);
	hlist_del_rcu(&cs->hlist);
	list_del(&cs->lru_link);
	list_del(&cs->bl_link);
	cs->css->ncs--;

	if (list_empty(&cs->css->bl_list))
		cancel_delayed_work(&cs->css->bl_work);
	spin_unlock(&cs->css->lock);

	pcs_cs_truncate_maps(cs);

	BUG_ON(cs->nmaps);

	if (!list_empty(&cs->flow_lru))
		pcs_flow_cs_unbind_all(cs);
	BUG_ON(cs->nflows);
}

static void pcs_cs_destroy(struct pcs_cs *cs)
{
	BUG_ON(!list_empty(&cs->active_list));
	BUG_ON(!list_empty(&cs->cong_queue));
	BUG_ON(!cs->is_dead);

	if (cs->rpc) {
		pcs_rpc_close(cs->rpc);
		cs->rpc = NULL;
	}
	kfree_rcu(cs, rcu);
}

void cs_aborting(struct pcs_rpc *ep, int error)
{
	pcs_rpc_reset(ep);
}

/* Latency is difficult value to use for any decisions.
 * It is sampled at random, we do not know what is happening while
 * we have no samples. For now we do the following: arriving samples
 * are locked and used as if latency stays at this value until the next sample.
 * If we have no samples, latency value slowly decays. This prepared value
 * is used to take EWMA.
 */

static unsigned int lat_decay(unsigned int lat, unsigned decay_period,
				 abs_time_t now, abs_time_t stamp)
{
	unsigned int interval;

	if (now < stamp + decay_period)
		return lat;

	if (stamp  == 0 || now > stamp + 30 * decay_period)
		return 0;

	interval = (now - stamp) / decay_period;

	return lat >>= interval;

}

unsigned int __cs_get_avg_latency(struct pcs_cs *cs, abs_time_t now)
{
	return lat_decay(atomic_read(&cs->latency_avg), CS_LAT_DECAY_INTERVAL,
			 now, READ_ONCE(cs->latency_stamp));
}

unsigned int cs_get_avg_latency(struct pcs_cs *cs)
{
	return __cs_get_avg_latency(cs, jiffies);
}
unsigned int __cs_get_avg_net_latency(struct pcs_cs *cs, abs_time_t now)
{
	return lat_decay(READ_ONCE(cs->net_latency_avg), CS_LAT_DECAY_INTERVAL,
			 now, READ_ONCE(cs->net_latency_stamp));

}

unsigned int cs_get_avg_net_latency(struct pcs_cs *cs)
{
	return __cs_get_avg_net_latency(cs, jiffies);
}

void cs_account_latency(struct pcs_cs *cs, unsigned int cost)
{
	unsigned lat;
	abs_time_t now = jiffies;

	lat = __cs_get_avg_latency(cs, now);

	atomic_add(cost, &cs->latency_avg);
	WRITE_ONCE(cs->latency_stamp, now);
}

void cs_update_io_latency(struct pcs_cs *cs, u32 lat)
{
	abs_time_t now = jiffies;
	u32 cur_latency;

	cur_latency = __cs_get_avg_latency(cs, jiffies);

	atomic_add((int)(lat - cur_latency) >> CS_LAT_EWMA_LOG, &cs->latency_avg);
	WRITE_ONCE(cs->last_latency, lat);
	WRITE_ONCE(cs->latency_stamp, now);
}


void cs_update_net_latency(struct pcs_cs *cs, u32 lat)
{
	abs_time_t now = jiffies;
	struct pcs_rpc *ep = cs->rpc;
	u32 cur_latency;

	cur_latency = __cs_get_avg_net_latency(cs, now);

	cur_latency += ((int)(lat - cur_latency) >> CS_LAT_EWMA_LOG);

	WRITE_ONCE(cs->net_latency_avg, cur_latency);
	WRITE_ONCE(cs->net_latency_stamp, now);

	if (lat < READ_ONCE(ep->netlat_min))
		WRITE_ONCE(ep->netlat_min, lat);
	if (lat > READ_ONCE(ep->netlat_max))
		WRITE_ONCE(ep->netlat_max, lat);
	atomic_inc(&ep->netlat_cnt);
	atomic64_add(lat, &ep->netlat_avg);
}

unsigned int cs_get_avg_in_flight(struct pcs_cs *cs)
{
	assert_spin_locked(&cs->lock);

	if (cs->in_flight == 0) {
		abs_time_t now;

		now = jiffies;

		if (now >= cs->idle_stamp + CS_LAT_DECAY_INTERVAL) {
			if (cs->idle_stamp == 0 || now > cs->idle_stamp + 30*CS_LAT_DECAY_INTERVAL) {
				cs->in_flight_avg = 0;
			} else {
				unsigned int interval;

				interval = (now - cs->idle_stamp)/CS_LAT_DECAY_INTERVAL;
				cs->idle_stamp = now;
				cs->in_flight_avg >>= interval;
			}
			if (cs->cwnd > PCS_CS_INIT_CWND) {
				unsigned int cwnd = PCS_CS_INIT_CWND;
				TRACE("Congestion window on CS#" NODE_FMT " was not used, shrink %u -> %u", NODE_ARGS(cs->id),
					cs->cwnd, cwnd);
				if (cs->cwnd > cs->ssthresh)
					cs->ssthresh = cs->cwnd;
				cs->cwnd = cwnd;
				if (cs->eff_cwnd > cwnd)
					cs->eff_cwnd = cwnd;
			}
		}
	}

	return cs->in_flight_avg;
}

void cs_increment_in_flight(struct pcs_cs *cs, unsigned int to_add)
{
	unsigned int avg;

	spin_lock(&cs->lock);
	avg = cs_get_avg_in_flight(cs);

	cs->in_flight += to_add;

	cs->in_flight_avg = avg + (((int)(cs->in_flight - avg)) >> CS_LAT_EWMA_LOG);

	if (cs->in_flight > cs->in_flight_hwm) {
		cs->in_flight_hwm = cs->in_flight;
		cs->in_flight_hwm_stamp = jiffies;
		FUSE_KDTRACE(cc_from_csset(cs->css)->fc, "HWM on CS" NODE_FMT " is %u", NODE_ARGS(cs->id), cs->in_flight);
	}
	spin_unlock(&cs->lock);
}

void cs_decrement_in_flight(struct pcs_cs *cs, unsigned int to_dec)
{
	assert_spin_locked(&cs->lock);

	cs->in_flight -= to_dec;

	BUG_ON((int)cs->in_flight < 0);

	if (cs->in_flight < cs->eff_cwnd) {
		cs->cwr_state = 0;
		pcs_cs_activate_cong_queue(cs);
	}
	if (cs->in_flight == 0)
		cs->idle_stamp = jiffies;
}

/* Check that cwnd was used recently. If it was not used, drop it. */

void cs_cwnd_use_or_lose(struct pcs_cs *cs)
{
	assert_spin_locked(&cs->lock);

	if (cs->in_flight_hwm < cs->cwnd && cs->cwnd > PCS_CS_INIT_CWND) {
		abs_time_t now = jiffies;

		if (now > cs->in_flight_hwm_stamp + CS_LAT_DECAY_INTERVAL) {
			unsigned int cwnd;

			cwnd = cs->in_flight_hwm;
			if (cwnd < PCS_CS_INIT_CWND)
				cwnd = PCS_CS_INIT_CWND;

			FUSE_KTRACE(cc_from_csset(cs->css)->fc, "Congestion window on CS#" NODE_FMT " was not used, shrink %u -> %u", NODE_ARGS(cs->id),
				    cs->cwnd, cwnd);
			if (cs->cwnd > cs->ssthresh)
				cs->ssthresh = cs->cwnd;
			cs->cwnd = cwnd;
			if (cs->eff_cwnd > cwnd)
				cs->eff_cwnd = cwnd;
			cs->in_flight_hwm_stamp = now;
			cs->in_flight_hwm = cs->in_flight;
		}
	}
}

static void cs_probe_done(struct pcs_msg *msg)
{
	struct pcs_cs_set *css = msg->private;
	struct pcs_cs *cs;

	cs = lookup_and_lock_cs(css, &msg->rpc->peer_id);

	if (cs) {
		if (!pcs_if_error(&msg->error)) {
			cs_whitelist(cs, "probe");
		} else {
			FUSE_KTRACE(cc_from_csset(css)->fc, "probe error %d", msg->error.value);
			cs_blacklist(cs, msg->error.value, "probe");
		}
		cs->use_count--;
	}
	spin_unlock(&cs->lock);
	pcs_free_msg(msg);
}

static struct pcs_msg *cs_prep_probe(struct pcs_cs *cs)
{
	struct pcs_msg *msg;
	struct pcs_cs_map_prop *m;
	unsigned int msg_sz = offsetof(struct pcs_cs_map_prop, nodes) + sizeof(struct pcs_cs_node_desc);


	msg = pcs_rpc_alloc_output_msg(msg_sz);
	if (!msg)
		return NULL;

	m = (struct pcs_cs_map_prop *)msg_inline_head(msg);
	memset(m, 0, msg_sz);

	m->hdr.h.type = PCS_CS_MAP_PROP_REQ;
	m->hdr.h.len = msg_sz;

	m->flags = CS_MAPF_PING;
	m->nnodes = 1;
	m->nodes[0].state     = CS_OBJ_UNKNOWN;
	m->nodes[0].info.id   = cs->id;
	m->nodes[0].info.addr = cs->rpc->addr;

	msg->done = cs_probe_done;
	msg->private = cs->css;
	msg->timeout = PCS_CS_BLACKLIST_TIMER / 2;
	return msg;
}

static void bl_timer_work(struct work_struct *w)
{
	struct pcs_cs_set *css = container_of(w, struct pcs_cs_set, bl_work.work);
	struct pcs_cluster_core *cc = cc_from_csset(css);
	LIST_HEAD(local_lst);
	LIST_HEAD(to_blacklist);
	LIST_HEAD(to_resubmit);

	spin_lock(&css->lock);
	list_splice_tail_init(&css->bl_list, &local_lst);
	spin_unlock(&css->lock);
	if (list_empty(&local_lst))
		return;

	while (!list_empty(&local_lst)) {
		struct pcs_cs *cs;
		struct pcs_msg *msg;

		cs = list_first_entry(&local_lst, struct pcs_cs, bl_link);

		spin_lock(&cs->lock);
		BUG_ON(cs->is_dead);
		list_move(&cs->bl_link, &to_blacklist);
		if (cs->use_count) {
			spin_unlock(&cs->lock);
			continue;
		}
		if (!cs->nmaps) {
			pcs_cs_isolate(cs, &to_resubmit);
			spin_unlock(&cs->lock);
			pcs_cs_destroy(cs);
			continue;
		}
		cs->use_count++;
		spin_unlock(&cs->lock);
		msg = cs_prep_probe(cs);
		if (msg)
			pcs_rpc_call(cs->rpc, msg);
		spin_lock(&cs->lock);
		if (!msg)
			cs->use_count--;
		spin_unlock(&cs->lock);
	}
	spin_lock(&css->lock);
	list_splice(&to_blacklist, &css->bl_list);
	if (list_empty(&css->bl_list))
		mod_delayed_work(cc->wq, &css->bl_work, PCS_CS_BLACKLIST_TIMER);
	spin_unlock(&css->lock);

	pcs_cc_requeue(cc, &to_resubmit);
}

void pcs_csset_init(struct pcs_cs_set *css)
{
	unsigned int i;

	for (i = 0; i < PCS_CS_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&css->ht[i]);

	INIT_LIST_HEAD(&css->lru);
	INIT_LIST_HEAD(&css->bl_list);
	INIT_DELAYED_WORK(&css->bl_work, bl_timer_work);
	css->ncs = 0;
	spin_lock_init(&css->lock);
	atomic64_set(&css->csl_serno_gen, 0);
}

static void pcs_cs_wait_unused(struct pcs_cs *cs)
{
	assert_spin_locked(&cs->lock);
	cs->use_count++;
	while (cs->use_count != 1) {
		spin_unlock(&cs->lock);
		schedule_timeout(1);
		spin_lock(&cs->lock);
	}
	cs->use_count--;
}

void pcs_csset_fini(struct pcs_cs_set *css)
{
	unsigned int i;
	LIST_HEAD(to_resubmit);

	for (i = 0; i < PCS_CS_HASH_SIZE; i++) {
		spin_lock(&css->lock);
		while (!hlist_empty(&css->ht[i])) {
			struct pcs_cs *cs;

			rcu_read_lock();
			cs = hlist_entry(css->ht[i].first, struct pcs_cs, hlist);
			spin_unlock(&css->lock);

			spin_lock(&cs->lock);
			if (cs->is_dead) {
				spin_unlock(&cs->lock);
				rcu_read_unlock();
				spin_lock(&css->lock);
				continue;
			}
			rcu_read_unlock();
			pcs_cs_wait_unused(cs);
			pcs_cs_isolate(cs, &to_resubmit);
			spin_unlock(&cs->lock);
			pcs_cs_destroy(cs);

			spin_lock(&css->lock);
		}
		spin_unlock(&css->lock);

	}
	cancel_delayed_work_sync(&css->bl_work);
	/* NOTE: It looks like	must being empty at destruction */
	BUG_ON(!list_empty(&to_resubmit));
	pcs_cc_requeue(cc_from_csset(css), &to_resubmit);

	BUG_ON(timer_pending(&css->bl_work.timer));
	BUG_ON(!list_empty(&css->bl_list));
	BUG_ON(!list_empty(&css->lru));
	BUG_ON(css->ncs);


}

int pcs_cs_for_each_entry(struct pcs_cs_set *set, int (*cb)(struct pcs_cs *cs, void *arg), void *arg)
{
	int rc = 0;
	unsigned int i;
	struct pcs_cs *cs;
	struct hlist_node *node;

	spin_lock(&set->lock);
	for (i = 0; i < PCS_CS_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(cs, node, &set->ht[i], hlist) {
			rc = cb(cs, arg);
			if (rc < 0) {
				spin_lock(&set->lock);
				return rc;
			}
		}
	}
	spin_unlock(&set->lock);
	return rc;
}

static int do_update_stat(struct pcs_cs *cs, void *arg)
{
	(void)arg;
	pcs_cs_stat_up(cs);
	return 0;
}

void pcs_cs_set_stat_up(struct pcs_cs_set *set)
{
	pcs_cs_for_each_entry(set, do_update_stat, 0);
}

int pcs_cs_cong_enqueue_cond(struct pcs_int_request *ireq, struct pcs_cs *cs)
{
	int queued = 0;

	spin_lock(&cs->lock);
	if (cs->in_flight >= cs->eff_cwnd) {
		list_add_tail(&ireq->list, &cs->cong_queue);
		cs->cong_queue_len++;
		if (!ireq->qdepth)
			ireq->qdepth = cs->cong_queue_len;
		queued = 1;
	}
	spin_unlock(&cs->lock);
	return queued;
}
