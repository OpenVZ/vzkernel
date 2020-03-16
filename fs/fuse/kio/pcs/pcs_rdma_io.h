#ifndef _PCS_RMDA_IO_H_
#define _PCS_RMDA_IO_H_ 1

#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/llist.h>

#include <rdma/rdma_cm.h>

#include "pcs_types.h"
#include "pcs_rpc.h"
#include "pcs_sock_io.h"
#include "pcs_error.h"
#include "pcs_net.h"
#include "pcs_rdma_prot.h"
#include "log.h"

#define RIO_IB_WC_MAX 64

enum {
	RIO_STATE_CONNECTING,   /* needn't rdma_disconnect (yet) */
	RIO_STATE_ESTABLISHED,  /* main "working" state */
	RIO_STATE_ABORTED,      /* rio_abort was called at least once */
};

extern struct pcs_netio_tops pcs_rdma_netio_tops;

struct pcs_rdma_id
{
	int (*event_handler)(struct rdma_cm_id *cmid, struct rdma_cm_event *event);
};

struct pcs_rdmaio
{
	/*
	 * That's not very obvious, we need two poll-able objects: netio.iocomp
	 * and compc. The former handles DISCONNECT event. The latter (compc)
	 * handles WQE completion events. */
	struct pcs_netio netio;
	struct pcs_rdma_id id;

	struct llist_node destroy_node;

	wait_queue_head_t waitq;
	unsigned long io_flags; /* atomic bit ops */

	int rio_state; /* see enum above */
	int rio_error;

	int hdr_size;  /* minimum allowed payload */

	/*
	 * It's easier to have the same queue_depth for both directions.
	 * rdma_connect gets a value from a tunable and sends it via
	 * conn_param; rdma_listen sees it in conn request event and
	 * blindly accepts the value. */
	int queue_depth;
	int send_queue_depth;
	int max_send_wr;

	int send_timeout;

	struct ib_wc wcs[RIO_IB_WC_MAX];
	int wc_cnt;
	int wc_idx;

	struct list_head tx_jobs; /* list head of TX jobs */

	struct rio_rx *rx_descs; /* plain array of RX descriptors */
	char *rx_bufs;           /* MR-ed area for payload of RXs */
	size_t rx_bufs_size;
	dma_addr_t rx_bufs_dma;
	struct list_head pended_rxs; /* list head of pended RX frames */

	int n_rx_posted; /* # posted RXs */
	int n_tx_posted; /* # posted TXs */

	int n_peer_credits; /* what we think about peer's n_rx_posted */
	int n_reserved_credits; /* limits # RDMA in flight */

	int n_os_credits;   /* outstanding credits: # RXs we re-post-ed,
			     * but have not returned to our peer (yet) */

	int n_th_credits;   /* threshold: when to return outstanding
			     * credits urgently */

	struct pcs_rdma_device *dev;
	struct rdma_cm_id *cmid;
	struct ib_cq *cq;

	struct list_head write_queue;
	struct list_head reserved_queue; /* out of reserved credits */

	int no_kick;   /* do not kick processing write_queue */
	int throttled; /* pcs_rpc asked us to quiesce */

	struct list_head active_txs; /* list head of active TX frames: tx->msg->done()
				      * is postponed until ACK from our peer */

	u64 xid_generator; /* provides unique (per rio) xids */

	struct pcs_rdmaio_conn_req conn_req;
};

#define rio_from_netio(nio) container_of(nio, struct pcs_rdmaio, netio)
#define rio_from_ioconn(conn) container_of(conn, struct pcs_rdmaio, netio.ioconn)

struct pcs_rdmaio* pcs_rdma_create(int hdr_size, struct rdma_cm_id *cmid,
		int queue_depth, struct pcs_rpc *ep);
void pcs_rdma_destroy(struct pcs_rdmaio *rio);
void pcs_rdma_ioconn_destruct(struct pcs_ioconn *ioconn);

#endif /* _PCS_RMDA_IO_H_ */
