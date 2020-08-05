#include <linux/module.h>
#include <linux/slab.h>
#include <linux/highmem.h>

#include <rdma/ib_verbs.h>

#include "pcs_types.h"
#include "pcs_rdma_io.h"
#include "pcs_rdma_rw.h"
#include "pcs_cluster.h"
#include "pcs_rpc.h"
#include "log.h"

#define RDMA_THRESHOLD (5*1024)

#define RDMA_MAX_MSG_PAYLOAD (32 << PAGE_SHIFT)
#define RDMA_MAX_SEGMENTS 256

enum {
	PCS_RDMA_IO_ERROR,
	PCS_RDMA_IO_CQE,
};

//#undef TRACE
//#define TRACE(fmt, args...) printk(KERN_ERR "%s:%d: " fmt, __func__, __LINE__, ## args)

struct rio_job
{
	struct list_head list;

	int (*work)(struct rio_job *job);
	void (*destroy)(struct rio_job *job);
};

struct rio_cqe
{
	enum ib_wc_status status;
	int ib_wr_count;
	void (*done)(struct rio_cqe *cqe, bool sync_mode);
};

struct rio_rx {
	struct list_head list;

	struct pcs_rdmaio *rio;
	struct rio_cqe cqe;
	struct ib_sge sge;
	struct ib_recv_wr wr;

	char *buf;
	dma_addr_t dma_addr;
};

enum {
	TX_FREE,                   /* free tx request available for use */
	TX_WAIT_FOR_TX_COMPL,      /* tx request sent, wait for TX completion */
	TX_WAIT_FOR_READ_ACK,      /* wait for peer to ack RDMA read */
	TX_MSG_DONE,               /* default: call msg->done() */
	TX_SUBMIT_RDMA_READ_ACK,   /* let our peer know that our RDMA_READ is done */
};

struct rio_tx {
	struct list_head list;  /* either member of rio->dev->free_txs or rio->active_txs */
	struct pcs_msg *msg;    /* msg to call ->done() when we're done */
	u64 xid;                /* xid that we've read from wire; used to construct ACK */
	int tx_state;           /* what we should do on TX completion; see enum above */

	char *buf;
	dma_addr_t dma_addr;

	struct pcs_rdmaio *rio;

	struct rio_cqe cqe;
	struct rio_cqe err_cqe;

	union {
		struct {
			struct ib_sge sge;
			struct ib_send_wr wr;
			struct pcs_rdma_msg msg;
		} send;

		struct {
			struct ib_sge sge;
			struct ib_rdma_wr wr;
			struct pcs_rdma_msg msg;
		} rdma_mr;

		struct pcs_rdma_rw rdma_rw;
	};

	void (*cleanup)(struct rio_tx *tx);
};

struct rio_rdma_read_job {
	struct rio_job job;

	struct pcs_rdmaio *rio;
	struct pcs_msg *msg;
	int offset;
	struct pcs_remote_buf rb;
};

struct pcs_rdma_device {
	struct ib_device *ib_dev;
	struct ib_pd *pd;

	struct list_head free_txs; /* list head of free TX frames */
	int free_txs_cnt;

	struct pcs_ib_mr_pool ib_mr_pool;
	struct pcs_rdma_mr_pool sd_mr_pool;
	struct pcs_rdma_mr_pool rd_mr_pool;
};

extern bool rdmaio_use_map_for_mr;
extern bool rdmaio_use_dma_mr_for_rdma_rw;
extern unsigned int rdmaio_cq_count;
extern unsigned int rdmaio_cq_period;

static void rio_abort(struct pcs_rdmaio *rio, int error);

static void rio_rx_done(struct rio_cqe *cqe, bool sync_mode);
static void rio_tx_done(struct rio_cqe *cqe, bool sync_mode);
static void rio_tx_err_occured(struct rio_cqe *cqe, bool sync_mode);

/* Only called when rio->write_queue is not empty */
static struct pcs_msg *rio_dequeue_msg(struct pcs_rdmaio *rio)
{
	struct pcs_msg *msg = list_first_entry(&rio->write_queue,
					       struct pcs_msg, list);
	list_del_init(&msg->list);
	return msg;
}

/* Only called when rio->reserved_queue is not empty */
static struct pcs_msg *rio_dequeue_reserved_msg(struct pcs_rdmaio *rio)
{
	struct pcs_msg *msg = list_first_entry(&rio->reserved_queue,
					       struct pcs_msg, list);
	list_del_init(&msg->list);
	return msg;
}

static void rio_msg_sent(struct pcs_rdmaio *rio, struct rio_tx *tx, struct pcs_msg *msg, int done)
{
	if (done) {
		pcs_msg_sent(msg);
		msg->done(msg);
	} else {
		tx->msg = msg;
		list_add_tail(&tx->list, &rio->active_txs);
	}
}

static struct rio_tx *rio_alloc_tx(struct pcs_rdma_device *dev,
				   int state)
{
	struct rio_tx *tx;

	tx = RE_NULL(kzalloc(sizeof(struct rio_tx), GFP_NOIO));
	if (!tx)
		return NULL;

	tx->buf = RE_NULL(ib_dma_alloc_coherent(dev->ib_dev, RIO_MSG_SIZE,
						&tx->dma_addr,
						GFP_NOIO | __GFP_NOWARN));
	if (!tx->buf) {
		kfree(tx);
		return NULL;
	}

	tx->tx_state = state;

	return tx;
}

static void rio_free_tx(struct pcs_rdma_device *dev, struct rio_tx *tx)
{
	ib_dma_free_coherent(dev->ib_dev, RIO_MSG_SIZE, tx->buf, tx->dma_addr);
	kfree(tx);
}

static struct rio_tx *rio_get_tx(struct pcs_rdma_device *dev)
{
	struct rio_tx *tx;

	if (list_empty(&dev->free_txs))
		return NULL;

	tx = list_first_entry(&dev->free_txs, struct rio_tx, list);
	list_del(&tx->list);
	dev->free_txs_cnt--;
	BUG_ON(dev->free_txs_cnt < 0);

	BUG_ON(tx->tx_state != TX_FREE);

	tx->tx_state = TX_MSG_DONE;
	tx->xid = 0;

	return tx;
}

static void rio_put_tx(struct pcs_rdma_device *dev, struct rio_tx *tx)
{
	BUG_ON(tx->tx_state == TX_FREE);

	if (tx->cleanup) {
		tx->cleanup(tx);
		tx->cleanup = NULL;
	}
	tx->msg = NULL;
	tx->xid = 0;
	tx->tx_state = TX_FREE;

	list_add(&tx->list, &dev->free_txs);
	dev->free_txs_cnt++;
}

static bool rio_init_rx(struct rio_rx *rx, struct ib_device *dev)
{
	rx->buf = RE_NULL(ib_dma_alloc_coherent(dev, RIO_MSG_SIZE,
						&rx->dma_addr,
						GFP_NOIO | __GFP_NOWARN));
	return rx->buf;
}

static void rio_fini_rx(struct rio_rx *rx, struct ib_device *dev)
{
	ib_dma_free_coherent(dev, RIO_MSG_SIZE, rx->buf, rx->dma_addr);
}

enum {
	SUBMIT_REGULAR,
	SUBMIT_NOOP,
	SUBMIT_RDMA_READ_ACK,
};

static inline void rio_cqe_init(struct rio_cqe *cqe, int ib_wr_count,
				void (*done)(struct rio_cqe *cqe, bool sync_mode))
{
	cqe->status = IB_WC_SUCCESS;
	cqe->ib_wr_count = ib_wr_count;
	cqe->done = done;
}

static inline void rio_job_init(struct rio_job *job,
				int (*work)(struct rio_job *job),
				void (*destroy)(struct rio_job *job))
{
	INIT_LIST_HEAD(&job->list);
	job->work = work;
	job->destroy = destroy;
}

static inline void rio_post_tx_job(struct pcs_rdmaio *rio,
				   struct rio_job *job)
{
	list_add_tail(&job->list, &rio->tx_jobs);
}

static inline void rio_perform_tx_jobs(struct pcs_rdmaio *rio)
{
	struct rio_job *job, *tmp;

	list_for_each_entry_safe(job, tmp, &rio->tx_jobs, list) {
		if (job->work(job) == -EAGAIN)
			break;
		list_del(&job->list);
		job->destroy(job);
	}
}

static int rio_rx_post(struct pcs_rdmaio *rio, struct rio_rx *rx,
		       u32 length)
{
	int ret;

	if (rio->rio_state == RIO_STATE_ABORTED)
		return -ECONNABORTED;

	rx->rio = rio;

	rx->sge.addr = rx->dma_addr;
	rx->sge.length = length;
	rx->sge.lkey = rio->dev->pd->local_dma_lkey;

	memset(&rx->wr, 0, sizeof(rx->wr));
	rx->wr.wr_id = (uintptr_t)&rx->cqe;
	rx->wr.sg_list = &rx->sge;
	rx->wr.num_sge = 1;

	rio_cqe_init(&rx->cqe, 1, rio_rx_done);

	ret = RE_INV(ib_post_recv(rio->cmid->qp, &rx->wr, NULL));
	if (ret) {
		TRACE("ib_post_recv failed: %d, rio: 0x%p\n", ret, rio);
	} else {
		rio->n_rx_posted++;
	}

	return ret;
}

static int rio_tx_post(struct pcs_rdmaio *rio, struct rio_tx *tx,
		       struct ib_send_wr *send_wr)
{
	struct ib_send_wr *wr;
	int ib_wr_count = 0;
	int ret;

	if (rio->rio_state == RIO_STATE_ABORTED)
		return -ECONNABORTED;

	tx->rio = rio;

	for (wr = send_wr; wr; wr = wr->next) {
		BUG_ON(wr->wr_id);
		BUG_ON(wr->send_flags & IB_SEND_SIGNALED);
		if (wr->next) {
			wr->wr_id = (uintptr_t)&tx->err_cqe;
			wr->send_flags = 0;
		} else {
			wr->wr_id = (uintptr_t)&tx->cqe;
			wr->send_flags = IB_SEND_SIGNALED;
		}
		ib_wr_count++;
	}

	rio_cqe_init(&tx->cqe, ib_wr_count, rio_tx_done);
	rio_cqe_init(&tx->err_cqe, 0, rio_tx_err_occured);

	if (rio->n_tx_posted + ib_wr_count > rio->max_send_wr) {
		TRACE("ib send queue overflow: rio: 0x%p\n", rio);
		return -ENOMEM;
	}

	ret = RE_INV(ib_post_send(rio->cmid->qp, send_wr, NULL));
	if (ret) {
		TRACE("ib_post_send failed: %d, rio: 0x%p\n", ret, rio);
	} else {
		rio->n_tx_posted += ib_wr_count;
	}

	return ret;
}

static int rio_tx_post_send(struct pcs_rdmaio *rio, struct rio_tx *tx,
			    u32 length, struct ib_send_wr *first_wr,
			    struct ib_send_wr *last_wr)
{
	struct ib_send_wr *send_wr;

	tx->send.sge.addr = tx->dma_addr;
	tx->send.sge.length = length;
	tx->send.sge.lkey = rio->dev->pd->local_dma_lkey;

	memset(&tx->send.wr, 0, sizeof(tx->send.wr));
	tx->send.wr.opcode = IB_WR_SEND;
	tx->send.wr.sg_list = &tx->send.sge;
	tx->send.wr.num_sge = 1;

	send_wr = &tx->send.wr;
	if (first_wr && last_wr) {
		last_wr->next = send_wr;
		send_wr = first_wr;
	}

	return rio_tx_post(rio, tx, send_wr);
}

static int rio_tx_post_rdma_mr_read(struct pcs_rdmaio *rio, struct rio_tx *tx,
				    u64 remote_addr, u32 rkey, u32 length)
{
	struct ib_send_wr *send_wr;

	tx->rdma_mr.sge.addr = tx->rdma_mr.msg.iova;
	tx->rdma_mr.sge.length = length;
	tx->rdma_mr.sge.lkey = tx->rdma_mr.msg.lkey;

	memset(&tx->rdma_mr.wr, 0, sizeof(tx->rdma_mr.wr));
	tx->rdma_mr.wr.wr.opcode = IB_WR_RDMA_READ;
	tx->rdma_mr.wr.wr.sg_list = &tx->rdma_mr.sge;
	tx->rdma_mr.wr.wr.num_sge = 1;
	tx->rdma_mr.wr.remote_addr = remote_addr;
	tx->rdma_mr.wr.rkey = rkey;

	send_wr = &tx->rdma_mr.wr.wr;
	if (tx->rdma_mr.msg.first_wr && tx->rdma_mr.msg.last_wr) {
		tx->rdma_mr.msg.last_wr->next = send_wr;
		send_wr = tx->rdma_mr.msg.first_wr;
	}

	return rio_tx_post(rio, tx, send_wr);
}

static int rio_tx_post_rdma_rw_read(struct pcs_rdmaio *rio, struct rio_tx *tx)
{
	if (!tx->rdma_rw.nr_wrs)
		return -EINVAL;
	return rio_tx_post(rio, tx, &tx->rdma_rw.wrs->wr);
}

static void rio_tx_cleanup_rdma_mr(struct rio_tx *tx)
{
	pcs_rdma_msg_destroy(&tx->rdma_mr.msg);
}

static void rio_tx_cleanup_rdma_rw(struct rio_tx *tx)
{
	pcs_rdma_rw_destroy(&tx->rdma_rw);
}

static int rio_submit_rdma_read(struct pcs_rdmaio *rio, struct pcs_msg *msg,
				int offset, struct pcs_remote_buf *rb, bool allow_again)
{
	struct pcs_rdma_device *dev = rio->dev;
	struct rio_tx *tx;

	tx = RE_NULL(rio_get_tx(dev));
	if (!tx) {
		if (allow_again)
			return -EAGAIN;
		goto fail;
	}

	BUG_ON(!rb);

	tx->tx_state = TX_SUBMIT_RDMA_READ_ACK;
	tx->msg = msg;
	tx->xid = rb->xid;

	if (rdmaio_use_dma_mr_for_rdma_rw) {
		if (pcs_rdma_rw_init_from_msg(&tx->rdma_rw, rio->cmid->device,
					      DMA_FROM_DEVICE, rb->rbuf, rb->rkey,
					      rio->dev->pd->local_dma_lkey, msg, offset,
					      offset + rb->rlen, GFP_NOIO, rio->cmid->qp->max_read_sge)) {
			TRACE("pcs_rdma_rw_init_from_msg failed, try fallback: rio: 0x%p\n", rio);
			goto fallback;
		}
		tx->cleanup = rio_tx_cleanup_rdma_rw;

		if (rio_tx_post_rdma_rw_read(rio, tx)) {
			TRACE("rio_tx_post_rdma_rw_read failed: rio: 0x%p\n", rio);
			goto fail;
		}
	} else {
fallback:
		if (pcs_rdma_msg_init(&tx->rdma_mr.msg, msg, offset, offset + rb->rlen,
				      &dev->rd_mr_pool, rdmaio_use_map_for_mr)) {
			TRACE("rio_rdma_mr_init failed: rio: 0x%p\n", rio);
			goto fail;
		}
		tx->cleanup = rio_tx_cleanup_rdma_mr;

		if (rio_tx_post_rdma_mr_read(rio, tx, rb->rbuf, rb->rkey, rb->rlen)) {
			TRACE("rio_tx_post_rdma_mr_read failed: rio: 0x%p\n", rio);
			goto fail;
		}
	}

	return 0;

fail:
	if (tx)
		rio_put_tx(dev, tx);
	pcs_free_msg(msg);
	rio_abort(rio, PCS_ERR_NET_ABORT);

	return -EIO;
}

static int rio_rdma_read_job_work(struct rio_job *j)
{
	struct rio_rdma_read_job *job = container_of(j, struct rio_rdma_read_job, job);
	struct pcs_rdmaio *rio = job->rio;

	if (rio->rio_state != RIO_STATE_ESTABLISHED) {
		pcs_free_msg(job->msg);
		return 0;
	}

	return rio_submit_rdma_read(rio, job->msg, job->offset,
				    &job->rb, true);
}

static void rio_rdma_read_job_destroy(struct rio_job *j)
{
	struct rio_rdma_read_job *job = container_of(j, struct rio_rdma_read_job, job);
	kfree(job);
}

static inline struct rio_rdma_read_job* rio_rdma_read_job_alloc(struct pcs_rdmaio *rio,
								struct pcs_msg *msg,
								int offset,
								struct pcs_remote_buf *rb)
{
	struct rio_rdma_read_job *job;

	job = RE_NULL(kzalloc(sizeof(struct rio_rdma_read_job), GFP_NOIO));
	if (!job)
		return NULL;

	rio_job_init(&job->job, rio_rdma_read_job_work, rio_rdma_read_job_destroy);
	job->rio = rio;
	job->msg = msg;
	job->offset = offset;
	memcpy(&job->rb, rb, sizeof(job->rb));

	return job;
}

static int msg_is_large(struct pcs_msg *msg)
{
	int hdr_len = sizeof(struct pcs_rdmaio_hdr);
	return msg->size + hdr_len > RDMA_THRESHOLD;
}

static int rio_init_msg(char *buf, int payload_size, int credits, int submit_type,
			struct pcs_remote_buf **rb, struct pcs_rdma_ack **rack)
{
	struct pcs_rdmaio_hdr *hdr = (struct pcs_rdmaio_hdr *)buf;
	int hdr_len = sizeof(*hdr);
	int type = RIO_MSG_IMMEDIATE;
	int addon_len = 0;

	switch (submit_type) {
	case SUBMIT_NOOP:
		type = RIO_MSG_NOOP;
		break;
	case SUBMIT_REGULAR:
		if (hdr_len + payload_size > RDMA_THRESHOLD) {
			type = RIO_MSG_RDMA_READ_REQ;
			*rb = (struct pcs_remote_buf *)(buf + hdr_len);
			addon_len = sizeof(struct pcs_remote_buf);
		}
		break;
	case SUBMIT_RDMA_READ_ACK:
		type = RIO_MSG_RDMA_READ_ACK;
		*rack = (struct pcs_rdma_ack *)(buf + hdr_len);
		addon_len = sizeof(struct pcs_rdma_ack);
		break;
	default:
		BUG();
	}

	hdr->magic = RIO_MAGIC;
	hdr->version = RIO_VERSION;
	hdr->type = type;
	hdr->size = hdr_len + addon_len;
	hdr->credits = credits;

	return hdr->size;
}

static void rio_update_msg_immediate(char *buf, int copied)
{
	struct pcs_rdmaio_hdr *hdr = (struct pcs_rdmaio_hdr *)buf;

	hdr->size += copied;
}

static void rio_tx_cleanup_send(struct rio_tx *tx)
{
	pcs_rdma_msg_destroy(&tx->send.msg);
}

static int rio_submit(struct pcs_rdmaio *rio, struct pcs_msg *msg, int type, u64 xid, int status,
		      bool allow_again)
{
	struct pcs_rdma_device *dev = rio->dev;
	struct rio_tx *tx;
	struct ib_send_wr *first_tx_wr = NULL;
	struct ib_send_wr *last_tx_wr = NULL;
	int credits = rio->n_os_credits;
	int msg_size = msg ? msg->size : 0;
	struct pcs_remote_buf *rb = NULL;
	struct pcs_rdma_ack *rack = NULL;
	int hdr_len;
	size_t tx_length;
	char *payload;
	int offset = 0;
	struct iov_iter it;

	tx = RE_NULL(rio_get_tx(dev));
	if (!tx) {
		if (allow_again)
			return -EAGAIN;
		goto fail;
	}

	hdr_len = rio_init_msg(tx->buf, msg_size, credits, type, &rb, &rack);
	tx_length = hdr_len;
	payload = tx->buf + hdr_len;

	if (rack) {
		rack->xid    = xid;
		rack->status = status;
	} else if (rb) {
		rio->xid_generator++;
		rb->xid = tx->xid = rio->xid_generator;
		tx->tx_state = TX_WAIT_FOR_TX_COMPL;
	}

	iov_iter_init_bad(&it);
	while (offset < msg_size) {
		struct page *page;
		void *buf;
		size_t copy;

		if (!iov_iter_count(&it))
			msg->get_iter(msg, offset, &it);

		page = iov_iter_kmap(&it, &buf, &copy);

		if (copy > msg_size - offset)
			copy = msg_size - offset;

		if (hdr_len + offset + copy > RDMA_THRESHOLD) {
			if (tx_length < hdr_len + rio->hdr_size) {
				copy = RDMA_THRESHOLD - offset - hdr_len;
			} else {
				if (page)
					kunmap(page);

				if (pcs_rdma_msg_init(&tx->send.msg, msg, offset, msg_size,
						      &dev->sd_mr_pool, rdmaio_use_map_for_mr)) {
					TRACE("rio_rdma_mr_init failed: rio: 0x%p\n", rio);
					goto fail;
				}
				tx->cleanup = rio_tx_cleanup_send;
				first_tx_wr = tx->send.msg.first_wr;
				last_tx_wr = tx->send.msg.last_wr;
				rb->rbuf = tx->send.msg.iova;
				rb->rkey = tx->send.msg.rkey;
				rb->rlen = msg_size - offset;
				break;
			}
		}

		memcpy(payload + offset, buf, copy);
		tx_length += copy;

		offset += copy;
		rio_update_msg_immediate(tx->buf, copy);

		if (page)
			kunmap(page);
		iov_iter_advance(&it, copy);
	}

	if (rio_tx_post_send(rio, tx, tx_length, first_tx_wr, last_tx_wr)) {
		TRACE("rio_tx_post_send failed: rio: 0x%p\n", rio);
		goto fail;
	}

	rio->n_os_credits -= credits;
	if (msg) {
		rio->n_peer_credits--;
		if (rb)
			rio->n_reserved_credits--;
		BUG_ON(rio->n_peer_credits < 0);
		BUG_ON(rio->n_reserved_credits < 0);

		/*
		 * It's possible to see RX completion for response to this message
		 * *before* we see TX completion for this message. This will result
		 * in RPC's handle_response failing to find corresponding TX by xid.
		 *
		 * Thus, we shouldn't wait for TX completion to tell upper layer that
		 * the message has been sent and do it right after
		 * rio_tx_post_send completes (similar to TCP). If
		 * rio_tx_post_send() fails eventually, we will receive TX
		 * completion with an error flag and cancel all
		 * outstanding/pending RPC requests. So we are not going to
		 * lose an error.
		 *
		 * But, if the message is big enough to trigger RDMA READ
		 * transfer, we are going to call ->done() callback after we
		 * receive RDMA_READ_ACK message from our peer. Since messages
		 * in a single RX queue are guaranteed to come in order, there
		 * is no race in this case.
		 */
		rio_msg_sent(rio, tx, msg, rb == NULL);
	}

	return 0;

fail:
	if (tx)
		rio_put_tx(dev, tx);
	if (msg)
		list_add(&msg->list, &rio->write_queue);
	rio_abort(rio, PCS_ERR_NET_ABORT);

	return -EIO;
}

static inline void rio_enable_kick(struct pcs_rdmaio *rio)
{
	rio->no_kick--;
	BUG_ON(rio->no_kick < 0);
}

static inline void rio_disable_kick(struct pcs_rdmaio *rio)
{
	rio->no_kick++;
}

static inline void rio_kick_write_queue(struct pcs_rdmaio *rio)
{
	if (rio->no_kick)
		return;
	rio_disable_kick(rio);

	rio_perform_tx_jobs(rio);

	/* Main loop sending large messages from reserved_queue */
	while (rio->rio_state == RIO_STATE_ESTABLISHED &&
	       rio->dev->free_txs_cnt > rio->queue_depth &&
	       !list_empty(&rio->reserved_queue) && rio->n_peer_credits &&
	       rio->n_reserved_credits) {
		struct pcs_msg *msg = rio_dequeue_reserved_msg(rio);
		if (rio_submit(rio, msg, SUBMIT_REGULAR, 0, 0, true) == -EAGAIN) {
			list_add(&msg->list, &rio->reserved_queue);
			break;
		}
	}

	/* Main loop sending ordinary messages from write_queue */
	while (rio->rio_state == RIO_STATE_ESTABLISHED &&
	       rio->dev->free_txs_cnt > rio->queue_depth &&
	       !list_empty(&rio->write_queue) && rio->n_peer_credits) {
		struct pcs_msg *msg = rio_dequeue_msg(rio);

		if (!rio->n_reserved_credits && msg_is_large(msg)) {
			list_add_tail(&msg->list, &rio->reserved_queue);
		} else if (rio_submit(rio, msg, SUBMIT_REGULAR, 0, 0, true) == -EAGAIN) {
			list_add(&msg->list, &rio->write_queue);
			break;
		}
	}

	/* Return credits by NOOP only if we have many enough to return AND
	 * we cannot piggyback it by sending a message from write_queue */
	if (rio->rio_state == RIO_STATE_ESTABLISHED &&
	    rio->dev->free_txs_cnt > rio->queue_depth &&
	    rio->n_os_credits >= rio->n_th_credits)
		rio_submit(rio, NULL, SUBMIT_NOOP, 0, 0, true);

	rio_enable_kick(rio);
}

static void rio_handle_tx(struct pcs_rdmaio *rio, struct rio_tx *tx, int ok)
{
	struct pcs_msg *msg = tx->msg;
	u64 xid = tx->xid;

	/* override remote success if we already aborted */
	if (rio->rio_state == RIO_STATE_ABORTED)
		ok = 0;

	if (!ok)
		rio_abort(rio, PCS_ERR_NET_ABORT);

	switch (tx->tx_state) {
		case TX_SUBMIT_RDMA_READ_ACK:
			rio_put_tx(rio->dev, tx);
			rio_submit(rio, NULL, SUBMIT_RDMA_READ_ACK, xid, !ok, false);
			break;
		case TX_WAIT_FOR_TX_COMPL:
		case TX_WAIT_FOR_READ_ACK:
			if (++tx->tx_state != TX_MSG_DONE)
				return;
		case TX_MSG_DONE:
			rio_put_tx(rio->dev, tx);
			break;
		default:
			BUG();
	}

	if (msg) {
		if (!ok)
			pcs_set_local_error(&msg->error, PCS_ERR_NET_ABORT);

		rio_msg_sent(rio, NULL, msg, 1);
	}
}

/*
 * rio wire header is already stripped, buf points to payload data (pcs_rpc hdr)
 */
static int rio_handle_rx_immediate(struct pcs_rdmaio *rio, char *buf, int len,
				   struct pcs_remote_buf *rb, int *throttle)
{
	struct pcs_msg *msg;
	u32 msg_size;
	int offset = rio->hdr_size;
	struct iov_iter it;

	if (len < rio->hdr_size) {
		TRACE("rio read short msg: %d < %d, rio: 0x%p\n", len,
		      rio->hdr_size, rio);
		return PCS_ERR_NET_ABORT;
	}

	msg = rio->netio.getmsg(&rio->netio, buf, &msg_size);
	if (msg == NULL) {
		int err = 0;
		if (rio->throttled)
			*throttle = 1;
		else
			err = PCS_ERR_NOMEM;
		return err;
	} else if (msg == PCS_TRASH_MSG) {
		TRACE("rio drop trash msg: %u, rio: 0x%p\n", msg_size, rio);
		return 0;
	}

	if (msg->size != len + (rb ? rb->rlen : 0)) {
		TRACE("rio read wrong len: %d != %d (%llx/%x/%d), rio: 0x%p",
		      len, msg->size, rb ? rb->rbuf : 0ULL,
		      rb ? rb->rkey : 0, rb ? rb->rlen : -1,
		      rio);
		pcs_free_msg(msg);
		return PCS_ERR_NET_ABORT;
	}

	iov_iter_init_bad(&it);
	while (offset < len) {
		struct page *page;
		size_t body_len;
		void *body;

		if (!iov_iter_count(&it))
			msg->get_iter(msg, offset, &it);

		page = iov_iter_kmap(&it, &body, &body_len);

		if (body_len > len - offset)
			body_len = len - offset;

		memcpy(body, buf + offset, body_len);
		if (page)
			kunmap(page);

		offset += body_len;
		iov_iter_advance(&it, body_len);
	}

	if (len == msg->size) {
		msg->done(msg);
	} else if (rio_submit_rdma_read(rio, msg, offset, rb, true) == -EAGAIN) {
		struct rio_rdma_read_job *job;
		job = rio_rdma_read_job_alloc(rio, msg, offset, rb);
		if (!job)
			rio_submit_rdma_read(rio, msg, offset, rb, false);
		else
			rio_post_tx_job(rio, &job->job);
	}

	return 0;
}

static int rio_handle_rx_read_ack(struct pcs_rdmaio *rio,
				  struct pcs_rdma_ack *rack)
{
	struct rio_tx *tx;

	list_for_each_entry(tx, &rio->active_txs, list)
		if (tx->xid == rack->xid) {
			list_del(&tx->list);
			rio_handle_tx(rio, tx, !rack->status);
			return 0;
		}

	return PCS_ERR_NET_ABORT;
}

/*
 * When we see RX coming from the wire very first time, flag "pended" is
 * false and we naturally update n_rx_posted and n_peer_credits.
 *
 * Later on, due to throttling, the RX may reside in pended_rxs for a while.
 * Then, handling unthrottle event, we will see this RX again, the "pended"
 * flag is true. This means we should not touch n_rx_posted and
 * n_peer_credits again.
 */
static void rio_handle_rx(struct pcs_rdmaio *rio, struct rio_rx *rx,
			  enum ib_wc_status status, int pended)
{
	int ok = (status == IB_WC_SUCCESS) &&
		 (rio->rio_state == RIO_STATE_ESTABLISHED);
	char *payload = NULL;
	int payload_size = 0;
	int credits = 0;
	int throttle = 0;
	int type;
	int err = PCS_ERR_NET_ABORT;
	struct pcs_remote_buf *rb   = NULL;
	struct pcs_rdma_ack *rack = NULL;

	if (!ok) {
		rio_abort(rio, PCS_ERR_NET_ABORT);
		return;
	}

	type = rio_parse_hdr(rx->buf, &payload, &payload_size, &credits, &rb, &rack,
			     rio->queue_depth);

	switch (type) {
	case RIO_MSG_IMMEDIATE:
	case RIO_MSG_RDMA_READ_REQ:
		err = rio_handle_rx_immediate(rio, payload, payload_size, rb, &throttle);
		if (err)
			goto do_abort;
		break;
	case RIO_MSG_NOOP:
		/* for now, it only returns credits */
		break;
	case RIO_MSG_RDMA_READ_ACK:
		BUG_ON(!rack);
		err = rio_handle_rx_read_ack(rio, rack);
		if (err)
			goto do_abort;
		break;
	default:
		goto do_abort;
	}

	if (!throttle) {
		if (rio_rx_post(rio, rx, RIO_MSG_SIZE)) {
			TRACE("rio_rx_post failed: rio: 0x%p\n", rio);
			rio_abort(rio, PCS_ERR_NET_ABORT);
			return;
		}

		if (type != RIO_MSG_NOOP &&
		    type != RIO_MSG_RDMA_READ_ACK)
			rio->n_os_credits++;

		if (type == RIO_MSG_RDMA_READ_ACK)
			rio->n_reserved_credits++;

		BUG_ON(rio->n_reserved_credits > rio->queue_depth);
		if (rio->n_os_credits > rio->queue_depth) {
			TRACE("n_os_credits overflow: rio: 0x%p\n", rio);
			rio_abort(rio, PCS_ERR_NET_ABORT);
			return;
		}
	} else
		list_add(&rx->list, &rio->pended_rxs);

	if (!pended)
		rio->n_peer_credits += credits;

	return;

do_abort:
	rio_abort(rio, err);
}

static void rio_handle_pended_rxs(struct pcs_rdmaio *rio)
{
	LIST_HEAD(local);

	list_splice_init(&rio->pended_rxs, &local);

	while (!list_empty(&local)) {
		struct rio_rx *rx;

		rx = list_first_entry(&local, struct rio_rx, list);
		list_del(&rx->list);

		rio_handle_rx(rio, rx, IB_WC_SUCCESS, 1);
	}
}

static void rio_rx_done(struct rio_cqe *cqe, bool sync_mode)
{
	struct rio_rx *rx = container_of(cqe, struct rio_rx, cqe);
	struct pcs_rdmaio *rio = rx->rio;

	rio->n_rx_posted -= cqe->ib_wr_count;
	BUG_ON(rio->n_rx_posted < 0);

	if (sync_mode) {
		if (!rio_rx_post(rio, rx, RIO_MSG_SIZE))
			rio->n_os_credits++;
	} else {
		rio_handle_rx(rio, rx, cqe->status, 0);
	}
}

static void rio_tx_err_occured(struct rio_cqe *cqe, bool sync_mode)
{
	TRACE("status: %d\n", cqe->status);
}

static void rio_tx_done(struct rio_cqe *cqe, bool sync_mode)
{
	struct rio_tx *tx = container_of(cqe, struct rio_tx, cqe);
	struct pcs_rdmaio *rio = tx->rio;

	if (cqe->status == IB_WC_SUCCESS)
		cqe->status = tx->err_cqe.status;

	rio->n_tx_posted -= cqe->ib_wr_count;
	BUG_ON(rio->n_tx_posted < 0);

	if (sync_mode)
		rio_put_tx(rio->dev, tx);
	else
		rio_handle_tx(rio, tx, cqe->status == IB_WC_SUCCESS);
}

static inline struct rio_cqe* rio_poll_cq(struct pcs_rdmaio *rio)
{
	struct rio_cqe *cqe = NULL;

	if (rio->wc_idx >= rio->wc_cnt) {
		rio->wc_cnt = ib_poll_cq(rio->cq, ARRAY_SIZE(rio->wcs),
					 rio->wcs);
		rio->wc_idx = 0;
	}

	if (rio->wc_idx < rio->wc_cnt) {
		cqe = (void*)rio->wcs[rio->wc_idx].wr_id;
		if (cqe->status == IB_WC_SUCCESS &&
		    rio->wcs[rio->wc_idx].status != IB_WC_SUCCESS)
			cqe->status = rio->wcs[rio->wc_idx].status;
		rio->wc_idx++;
	}

	return cqe;
}

static inline int rio_req_notify_cq(struct pcs_rdmaio *rio)
{
	return ib_req_notify_cq(rio->cq, IB_CQ_NEXT_COMP |
				IB_CQ_REPORT_MISSED_EVENTS);
}

static void pcs_rdma_cq_comp_handler(struct ib_cq *cq, void *private)
{
	struct pcs_rdmaio *rio = private;
	struct pcs_rpc *ep = rio->netio.parent;

	set_bit(PCS_RDMA_IO_CQE, &rio->io_flags);
	wake_up(&rio->waitq);
	pcs_rpc_kick_queue(ep);
}

static inline int rio_comp_perform(struct pcs_rdmaio *rio)
{
	struct rio_cqe *cqe;
	int count = 0;

	while ((cqe = rio_poll_cq(rio))) {
		rio_disable_kick(rio);
		cqe->done(cqe, false);
		rio_enable_kick(rio);

		rio_kick_write_queue(rio);
		count++;
	}

	return count;
}

static void pcs_rdma_cq_event_handler(struct ib_event *event, void *private)
{
	struct pcs_rdmaio *rio = private;
	TRACE("rio: 0x%p\n", rio);
}

static int pcs_rdma_io_event_handler(struct rdma_cm_id *cmid,
		struct rdma_cm_event *event)
{
	struct pcs_rdma_id *id = cmid->context;
	struct pcs_rdmaio *rio = container_of(id, struct pcs_rdmaio, id);
	struct pcs_rpc *ep = rio->netio.parent;

	TRACE("rio: 0x%p, event: %d, status: %d\n", rio, event->event, event->status);

	set_bit(PCS_RDMA_IO_ERROR, &rio->io_flags);
	pcs_rpc_kick_queue(ep);

	return 0;
}

static void pcs_rdma_qp_event_handler(struct ib_event *event, void *context)
{
	struct pcs_rdmaio *rio = context;
	TRACE("rio: 0x%p, event: %d\n", rio, event->event);
}

static struct pcs_rdma_device *pcs_rdma_device_create(struct rdma_cm_id *cmid,
						      int queue_depth,
						      int send_queue_depth)
{
	struct pcs_rdma_device *dev;
	struct rio_tx *tx;
	u32 max_num_sg = min_t(u32, RDMA_MAX_SEGMENTS,
			       cmid->device->attrs.max_fast_reg_page_list_len);
	int i;

	dev = RE_NULL(kzalloc(sizeof(*dev), GFP_NOIO));
	if (!dev)
		return NULL;

	dev->ib_dev = cmid->device;

	INIT_LIST_HEAD(&dev->free_txs);
	for (i = 0; i < send_queue_depth; i++) {
		tx = rio_alloc_tx(dev, TX_MSG_DONE);
		if (!tx) {
			TRACE("rio_alloc_tx failed: dev: 0x%p\n", dev);
			goto free_bufs;
		}
		rio_put_tx(dev, tx);
	}

	dev->pd = RE_PTR_INV(ib_alloc_pd(dev->ib_dev, 0));
	if (IS_ERR(dev->pd)) {
		TRACE("ib_alloc_pd failed: dev: 0x%p\n", dev);
		goto free_bufs;
	}

	if (pcs_ib_mr_pool_init(&dev->ib_mr_pool, dev->pd, IB_MR_TYPE_MEM_REG,
			    max_num_sg,
			    queue_depth * 2)) {
		TRACE("pcs_ib_mr_pool_init failed: dev: 0x%p\n", dev);
		goto free_pd;
	}

	if (pcs_rdma_mr_pool_init(&dev->sd_mr_pool, RDMA_MAX_MSG_PAYLOAD,
				  queue_depth, dev->ib_dev, dev->pd, DMA_TO_DEVICE,
				  GFP_NOIO, &dev->ib_mr_pool)) {
		TRACE("pcs_rdma_mr_pool_init failed: dev: 0x%p\n", dev);
		goto free_ib_mr;
	}

	if (pcs_rdma_mr_pool_init(&dev->rd_mr_pool, RDMA_MAX_MSG_PAYLOAD,
				  queue_depth, dev->ib_dev, dev->pd, DMA_FROM_DEVICE,
				  GFP_NOIO, &dev->ib_mr_pool)) {
		TRACE("pcs_rdma_mr_pool_init failed: dev: 0x%p\n", dev);
		goto free_sd_mr;
	}

	return dev;

free_sd_mr:
	pcs_rdma_mr_pool_destroy(&dev->sd_mr_pool);
free_ib_mr:
	pcs_ib_mr_pool_destroy(&dev->ib_mr_pool);
free_pd:
	ib_dealloc_pd(dev->pd);
free_bufs:
	while ((tx = rio_get_tx(dev)))
		rio_free_tx(dev, tx);
	kfree(dev);
	return NULL;
}

static void pcs_rdma_device_destroy(struct pcs_rdma_device *dev)
{
	struct rio_tx *tx;

	pcs_rdma_mr_pool_destroy(&dev->rd_mr_pool);
	pcs_rdma_mr_pool_destroy(&dev->sd_mr_pool);
	pcs_ib_mr_pool_destroy(&dev->ib_mr_pool);

	ib_dealloc_pd(dev->pd);

	while ((tx = rio_get_tx(dev)))
		rio_free_tx(dev, tx);

	kfree(dev);
}

struct pcs_rdmaio* pcs_rdma_create(int hdr_size, struct rdma_cm_id *cmid,
				   int queue_depth, struct pcs_rpc *ep)
{
	struct pcs_rdmaio *rio;
	struct rio_rx *rx;
	struct ib_cq_init_attr cq_attr = {};
	struct ib_qp_init_attr qp_attr = {};
	int recv_queue_depth = queue_depth * 2 + 2;
	int send_queue_depth = queue_depth * 4 + 4;
	int rx_descs_siz = recv_queue_depth * sizeof(struct rio_rx);
	static atomic_t comp_vector = ATOMIC_INIT(-1);
	unsigned int cq_count = rdmaio_cq_count;
	unsigned int cq_period = rdmaio_cq_period;
	int max_recv_wr, i;

	BUG_ON(!mutex_is_locked(&ep->mutex));

	BUILD_BUG_ON((TX_WAIT_FOR_READ_ACK - TX_WAIT_FOR_TX_COMPL) != 1);
	BUILD_BUG_ON((TX_MSG_DONE - TX_WAIT_FOR_READ_ACK) != 1);

	if (queue_depth < RIO_QUEUE_DEPTH)
		queue_depth = RIO_QUEUE_DEPTH;
	else if (queue_depth > RIO_MAX_QUEUE_DEPTH)
		queue_depth = RIO_MAX_QUEUE_DEPTH;

	rio = RE_NULL(kzalloc(sizeof(struct pcs_rdmaio), GFP_NOIO));
	if (!rio)
		return NULL;

	rio->netio.parent = pcs_rpc_get(ep);
	rio->id.event_handler = pcs_rdma_io_event_handler;

	init_waitqueue_head(&rio->waitq);

	rio->rio_state = RIO_STATE_CONNECTING;
	rio->rio_error = PCS_ERR_NET_ABORT;

	rio->hdr_size = hdr_size;
	rio->queue_depth = queue_depth;
	rio->send_queue_depth = send_queue_depth;

	INIT_LIST_HEAD(&rio->tx_jobs);
	INIT_LIST_HEAD(&rio->pended_rxs);

	rio->n_peer_credits = queue_depth;
	rio->n_reserved_credits = queue_depth;
	rio->n_os_credits = 0;
	rio->n_th_credits = queue_depth / 2;

	rio->cmid = cmid;

	INIT_LIST_HEAD(&rio->write_queue);
	INIT_LIST_HEAD(&rio->reserved_queue);

	rio->no_kick = 0;
	rio->throttled = 0;

	INIT_LIST_HEAD(&rio->active_txs);

	rio->xid_generator = 0;

	rio->conn_req.magic = RIO_MAGIC;
	rio->conn_req.version = RIO_VERSION;
	rio->conn_req.queue_depth = queue_depth;
	rio->conn_req.msg_size = RIO_MSG_SIZE;

	rio->rx_descs = RE_NULL(kzalloc(rx_descs_siz, GFP_NOIO | __GFP_NOWARN));
	if (!rio->rx_descs)
		goto free_rio;

	rio->recv_queue_depth = 0;
	for (i = 0; i < recv_queue_depth; i++) {
		if (!rio_init_rx(rio->rx_descs + i, rio->cmid->device)) {
			TRACE("rio_init_rx failed: rio: 0x%p\n", rio);
			goto free_bufs;
		}
		rio->recv_queue_depth++;
	}

	rio->dev = pcs_rdma_device_create(rio->cmid, queue_depth, send_queue_depth);
	if (!rio->dev) {
		TRACE("pcs_rdma_device_create failed: rio: 0x%p\n", rio);
		goto free_bufs;
	}

	max_recv_wr = recv_queue_depth;
	rio->max_send_wr = max_t(int, send_queue_depth * 4,
				 DIV_ROUND_UP(send_queue_depth * (RDMA_MAX_MSG_PAYLOAD >> PAGE_SHIFT),
					      rio->cmid->device->attrs.max_send_sge));

	cq_attr.cqe = max_recv_wr + rio->max_send_wr;
	cq_attr.comp_vector = (unsigned int)atomic_inc_return(&comp_vector) %
		rio->cmid->device->num_comp_vectors;
	rio->cq = RE_PTR_INV(ib_create_cq(rio->cmid->device, pcs_rdma_cq_comp_handler,
					  pcs_rdma_cq_event_handler, rio, &cq_attr));
	if (IS_ERR(rio->cq)) {
		TRACE("ib_alloc_cq failed: rio: 0x%p\n", rio);
		goto free_dev;
	}
	if (cq_count && cq_period) {
		int ret = rdma_set_cq_moderation(rio->cq, cq_count, cq_period);
		TRACE("rio: 0x%p, set cq moderation: cq_count %u, cq_period: %u, ret: %d\n",
		      rio, cq_count, cq_period, ret);
	}
	ib_req_notify_cq(rio->cq, IB_CQ_NEXT_COMP);

	qp_attr.event_handler = pcs_rdma_qp_event_handler;
	qp_attr.qp_context = rio;
	qp_attr.cap.max_send_wr = rio->max_send_wr;
	qp_attr.cap.max_send_sge = rio->cmid->device->attrs.max_send_sge;
	qp_attr.cap.max_recv_wr = max_recv_wr;
	qp_attr.cap.max_recv_sge = 1;
	qp_attr.send_cq = rio->cq;
	qp_attr.recv_cq = rio->cq;
	qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	qp_attr.qp_type = IB_QPT_RC;

	TRACE("rio: 0x%p, max_send wr/sge: %u/%u, max_recv wr/sge: %u/%u\n",
	      rio, qp_attr.cap.max_send_wr, qp_attr.cap.max_send_sge,
	      qp_attr.cap.max_recv_wr, qp_attr.cap.max_recv_sge);
	if (RE_INV(rdma_create_qp(rio->cmid, rio->dev->pd, &qp_attr))) {
		TRACE("rdma_create_qp failed: rio: 0x%p\n", rio);
		goto free_cq;
	}

	for (rx = rio->rx_descs; rx - rio->rx_descs < recv_queue_depth; rx++)
		if (rio_rx_post(rio, rx, RIO_MSG_SIZE)) {
			TRACE("rio_rx_post failed: rio: 0x%p\n", rio);
			break;
		}

	if (rio->n_rx_posted != recv_queue_depth)
		goto free_qp;

	TRACE("rio: 0x%p, dev: 0x%p, queue_depth: %d\n", rio, rio->dev, queue_depth);

	return rio;

free_qp:
	rdma_destroy_qp(rio->cmid);
free_cq:
	ib_destroy_cq(rio->cq);
free_dev:
	pcs_rdma_device_destroy(rio->dev);
free_bufs:
	for (i = 0; i < rio->recv_queue_depth; i++)
		rio_fini_rx(rio->rx_descs + i, rio->cmid->device);
	kfree(rio->rx_descs);
free_rio:
	pcs_rpc_put(rio->netio.parent);
	kfree(rio);
	return NULL;
}

static void rio_cleanup(struct pcs_rdmaio *rio)
{
	rio_perform_tx_jobs(rio);

	while (!list_empty(&rio->write_queue)) {
		struct pcs_msg * msg = rio_dequeue_msg(rio);

		pcs_msg_sent(msg);
		pcs_set_local_error(&msg->error, rio->rio_error);
		msg->done(msg);
	}

	while (!list_empty(&rio->reserved_queue)) {
		struct pcs_msg * msg = rio_dequeue_reserved_msg(rio);

		pcs_msg_sent(msg);
		pcs_set_local_error(&msg->error, rio->rio_error);
		msg->done(msg);
	}

	while (!list_empty(&rio->active_txs)) {
		struct rio_tx *tx = list_first_entry(&rio->active_txs,
						     struct rio_tx, list);
		struct pcs_msg *msg = tx->msg;
		list_del(&tx->list);

		BUG_ON(!msg);
		rio_put_tx(rio->dev, tx);
		pcs_set_local_error(&msg->error, rio->rio_error);
		rio_msg_sent(rio, NULL, msg, 1);
	}
}

static void rio_abort(struct pcs_rdmaio *rio, int error)
{
	struct pcs_netio *netio = &rio->netio;
	struct ib_qp_attr qp_attr = { .qp_state = IB_QPS_ERR };

	if (rio->rio_state == RIO_STATE_ABORTED) /* already handled  */
		return;

	rio->rio_state = RIO_STATE_ABORTED;
	rio->rio_error = error;

	if (rdma_disconnect(rio->cmid))
		TRACE("rdma_disconnect failed: rio: 0x%p\n", rio);

	if (ib_modify_qp(rio->cmid->qp, &qp_attr, IB_QP_STATE))
		TRACE("ib_modify_qp failed: rio: 0x%p\n", rio);

	if (netio->eof) {
		void (*eof)(struct pcs_netio *) = netio->eof;
		netio->eof = NULL;
		(*eof)(netio);
	}
}

static LLIST_HEAD(rio_destroy_list);

static void rio_destroy(struct work_struct *work)
{
	struct llist_node *list = llist_del_all(&rio_destroy_list);
	struct pcs_rdmaio *rio, *tmp;

	if (unlikely(!list))
		return;

	llist_for_each_entry_safe(rio, tmp, list, destroy_node) {
		struct pcs_rpc *ep = rio->netio.parent;
		int i;

		mutex_lock(&ep->mutex);

		TRACE("rio: 0x%p\n", rio);

		while (rio->n_rx_posted || rio->n_tx_posted) {
			rio_req_notify_cq(rio);
			wait_event_timeout(rio->waitq, rio_comp_perform(rio),
					   ep->params.response_timeout);
		}
		rio_cleanup(rio);

		rdma_destroy_qp(rio->cmid);
		ib_destroy_cq(rio->cq);

		BUG_ON(!list_empty(&rio->tx_jobs));
		BUG_ON(!list_empty(&rio->write_queue));
		BUG_ON(!list_empty(&rio->reserved_queue));
		BUG_ON(!list_empty(&rio->active_txs));
		BUG_ON(rio->dev->free_txs_cnt != rio->send_queue_depth);

		pcs_rdma_device_destroy(rio->dev);
		for (i = 0; i < rio->recv_queue_depth; i++)
			rio_fini_rx(rio->rx_descs + i, rio->cmid->device);
		kfree(rio->rx_descs);

		rdma_destroy_id(rio->cmid);

		memset(rio, 0xFF, sizeof(*rio));
		kfree(rio);

		mutex_unlock(&ep->mutex);

		pcs_rpc_put(ep);
	}
}

static DECLARE_WORK(rio_destroy_work, rio_destroy);

void pcs_rdma_destroy(struct pcs_rdmaio *rio)
{
	struct pcs_netio *netio = &rio->netio;
	struct pcs_rpc *ep = netio->parent;

	TRACE("rio: 0x%p\n", rio);

	BUG_ON(!mutex_is_locked(&ep->mutex));

	netio->eof = NULL;
	rio_abort(rio, PCS_ERR_NET_ABORT);

	if (llist_add(&rio->destroy_node, &rio_destroy_list))
		queue_work(pcs_cleanup_wq, &rio_destroy_work);
}

void pcs_rdma_ioconn_destruct(struct pcs_ioconn *ioconn)
{
	struct pcs_rdmaio *rio = rio_from_ioconn(ioconn);
	struct pcs_rpc *ep = rio->netio.parent;

	TRACE("rio: 0x%p\n", rio);

	BUG_ON(!mutex_is_locked(&ep->mutex));

	BUG_ON(rio->rio_state != RIO_STATE_ABORTED);
	if (llist_add(&rio->destroy_node, &rio_destroy_list))
		queue_work(pcs_cleanup_wq, &rio_destroy_work);
}

static void pcs_rdma_throttle(struct pcs_netio *netio)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);
	struct pcs_rpc *ep = netio->parent;

	TRACE("rio: 0x%p\n", rio);

	BUG_ON(!mutex_is_locked(&ep->mutex));

	if (rio->throttled || rio->rio_state != RIO_STATE_ESTABLISHED)
		return;

	rio->throttled = 1;
}

static void pcs_rdma_unthrottle(struct pcs_netio *netio)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);
	struct pcs_rpc *ep = netio->parent;

	TRACE("rio: 0x%p\n", rio);

	BUG_ON(!mutex_is_locked(&ep->mutex));

	if (!rio->throttled || rio->rio_state != RIO_STATE_ESTABLISHED)
		return;

	rio->throttled = 0;

	if (!list_empty(&rio->pended_rxs))
		rio_handle_pended_rxs(rio);
}

static void pcs_rdma_send_msg(struct pcs_netio *netio, struct pcs_msg *msg)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);
	struct pcs_rpc *ep = netio->parent;

	BUG_ON(!mutex_is_locked(&ep->mutex));

	if (rio->rio_state != RIO_STATE_ESTABLISHED) {
		pcs_msg_sent(msg);
		pcs_set_local_error(&msg->error, rio->rio_error);
		msg->done(msg);
		return;
	}

	msg->netio = netio;

	list_add_tail(&msg->list, &rio->write_queue);
	msg->start_time = jiffies;
	msg->stage = PCS_MSG_STAGE_SEND;

	rio_kick_write_queue(rio);
}

static int pcs_rdma_cancel_msg(struct pcs_msg *msg)
{
	struct pcs_rpc *ep = msg->netio->parent;

	TRACE("msg: 0x%p\n", msg);

	BUG_ON(!mutex_is_locked(&ep->mutex));

	if (list_empty(&msg->list))
		return -EBUSY;

	list_del_init(&msg->list);
	msg->stage = PCS_MSG_STAGE_SENT;

	return 0;
}

static void pcs_rdma_abort_io(struct pcs_netio *netio, int error)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);
	struct pcs_rpc *ep = netio->parent;

	TRACE("rio: 0x%p\n", rio);

	BUG_ON(!mutex_is_locked(&ep->mutex));

	if (rio->rio_state != RIO_STATE_ESTABLISHED)
		return;

	netio->eof = NULL;
	rio_abort(rio, error);
}

static void pcs_rdma_xmit(struct pcs_netio *netio)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);
	struct pcs_rpc *ep = netio->parent;

	BUG_ON(!mutex_is_locked(&ep->mutex));

	if (rio->rio_state != RIO_STATE_ESTABLISHED)
		return;

	if (test_bit(PCS_RDMA_IO_ERROR, &rio->io_flags))
		rio_abort(rio, PCS_ERR_NET_ABORT);

	while (test_and_clear_bit(PCS_RDMA_IO_CQE, &rio->io_flags)) {
		do {
			rio_comp_perform(rio);
		} while (rio_req_notify_cq(rio) > 0);
	}

	rio_kick_write_queue(rio);
}

static int pcs_rdma_flush(struct pcs_netio *netio)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);
	struct pcs_rpc *ep = netio->parent;

	BUG_ON(!mutex_is_locked(&ep->mutex));

	if (rio->rio_state != RIO_STATE_ESTABLISHED)
		return 0;

	return test_bit(PCS_RDMA_IO_CQE, &rio->io_flags);
}

static unsigned long pcs_rdma_next_timeout(struct pcs_netio *netio)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);
	struct pcs_rpc *ep = netio->parent;
	struct pcs_msg *msg;

	BUG_ON(!mutex_is_locked(&ep->mutex));

	if (list_empty(&rio->write_queue))
		return 0;

	msg = list_first_entry(&rio->write_queue, struct pcs_msg, list);
	return msg->start_time + rio->send_timeout;
}

static int pcs_rdma_sync_send(struct pcs_netio *netio, struct pcs_msg *msg)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);
	struct pcs_rpc *ep = netio->parent;
	int credits = rio->n_os_credits;
	struct pcs_remote_buf *rb;
	struct pcs_rdma_ack *rack;
	struct rio_tx *tx;
	struct rio_cqe *cqe;
	int hdr_len;
	int ret;

	BUG_ON(!mutex_is_locked(&ep->mutex));

	if (rio->rio_state != RIO_STATE_ESTABLISHED ||
	    !rio->n_peer_credits)
		return -EINVAL;

	tx = RE_NULL(rio_get_tx(rio->dev));
	if (!tx)
		return -ENOMEM;

	hdr_len = rio_init_msg(tx->buf, msg->size, credits, SUBMIT_REGULAR, &rb, &rack);
	if (hdr_len + msg->size > RDMA_THRESHOLD) {
		rio_put_tx(rio->dev, tx);
		return -EINVAL;
	}

	memcpy(tx->buf + hdr_len, msg->_inline_buffer, msg->size);
	rio_update_msg_immediate(tx->buf, msg->size);

	ret = rio_tx_post_send(rio, tx, hdr_len + msg->size,
			       NULL, NULL);
	if (ret) {
		rio_put_tx(rio->dev, tx);
		return ret;
	}
	rio->n_os_credits -= credits;
	rio->n_peer_credits--;

	wait_event_timeout(rio->waitq, (cqe = rio_poll_cq(rio)),
			   ep->params.connect_timeout);
	if (rio_req_notify_cq(rio) > 0)
		pcs_rpc_kick_queue(ep);

	if (!cqe)
		return -ETIMEDOUT;

	ret = cqe == &tx->cqe && cqe->status == IB_WC_SUCCESS ?
		0 : -EFAULT;
	cqe->done(cqe, true);

	return ret;
}

static int pcs_rdma_sync_recv(struct pcs_netio *netio, struct pcs_msg **msg)
{
	struct pcs_rdmaio *rio = rio_from_netio(netio);
	struct pcs_rpc *ep = netio->parent;
	struct rio_rx *rx;
	struct rio_cqe *cqe;
	int   type;
	char *payload;
	int payload_size;
	int credits;
	struct pcs_remote_buf *rb = NULL;
	struct pcs_rdma_ack *rack;
	int ret = 0;

	BUG_ON(!mutex_is_locked(&ep->mutex));

	if (rio->rio_state != RIO_STATE_ESTABLISHED)
		return -EINVAL;

	wait_event_timeout(rio->waitq, (cqe = rio_poll_cq(rio)),
			   ep->params.connect_timeout);
	if (rio_req_notify_cq(rio) > 0)
		pcs_rpc_kick_queue(ep);

	if (!cqe)
		return -ETIMEDOUT;

	if (cqe->done != rio_rx_done || cqe->status != IB_WC_SUCCESS) {
		ret = -EFAULT;
		goto out;
	}

	rx = container_of(cqe, struct rio_rx, cqe);

	type = rio_parse_hdr(rx->buf, &payload, &payload_size, &credits, &rb, &rack,
			     rio->queue_depth);
	if (type != RIO_MSG_IMMEDIATE || rb) {
		ret = -EFAULT;
		goto out;
	}
	rio->n_peer_credits += credits;

	*msg = pcs_rpc_alloc_output_msg(payload_size);
	if (!*msg) {
		ret = -ENOMEM;
		goto out;
	}

	memcpy((*msg)->_inline_buffer, payload, payload_size);

out:
	cqe->done(cqe, true);
	return ret;
}

struct pcs_netio_tops pcs_rdma_netio_tops = {
	.throttle		= pcs_rdma_throttle,
	.unthrottle		= pcs_rdma_unthrottle,
	.send_msg		= pcs_rdma_send_msg,
	.cancel_msg		= pcs_rdma_cancel_msg,
	.abort_io		= pcs_rdma_abort_io,
	.xmit			= pcs_rdma_xmit,
	.flush			= pcs_rdma_flush,
	.next_timeout		= pcs_rdma_next_timeout,
	.sync_send		= pcs_rdma_sync_send,
	.sync_recv		= pcs_rdma_sync_recv,
};
