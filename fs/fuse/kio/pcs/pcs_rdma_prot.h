#ifndef _PCS_RDMA_PROT_H_
#define _PCS_RDMA_PROT_H_ 1

/* PCS RDMA network protocol v1 */

#define RIO_MAGIC 0x5078614d
#define RIO_VERSION 1

#define RIO_MSG_SIZE	   (2*4096) /* max size of any wire message */

#define RIO_QUEUE_DEPTH     8   /* TODO: make it tunable */
#define RIO_MAX_QUEUE_DEPTH 128 /* for conn_param sanity checks */

/* negotiated by rdma_connect/rdma_accept */
struct pcs_rdmaio_conn_req {
	u32 magic;       /* RIO_MAGIC */
	u32 version;     /* RIO_VERSION */
	u32 queue_depth; /* RIO_QUEUE_DEPTH */
	u32 msg_size;    /* RIO_MSG_SIZE */
} __attribute__((aligned(8)));

/* negotiated by rdma_connect/rdma_accept */
struct pcs_rdmaio_rej {
	struct pcs_rdmaio_conn_req cr;
	u32 error;       /* errno */
} __attribute__((aligned(8)));

/* "type" field of pcs_rdmaio_msg */
enum {
	RIO_MSG_IMMEDIATE = 0,
	RIO_MSG_NOOP,
	RIO_MSG_RDMA_READ_REQ,
	RIO_MSG_RDMA_READ_ACK,
	RIO_MAX_TYPE_VALUE
};

/* sent/recieved by rdma_post_send/rdma_post_recv */
struct pcs_rdmaio_hdr {
	u32 magic;       /* RIO_MAGIC */
	u16 version;     /* RIO_VERSION */
	u16 type;        /* RIO_MSG_IMMEDIATE/... */
	u32 size;        /* total size of wire message */
	u32 credits;     /* # credits to return */
} __attribute__((aligned(8)));

struct pcs_remote_buf {
	u64 xid;
	u64 rbuf;
	u32 rkey;
	u32 rlen;
} __attribute__((aligned(8)));

struct pcs_rdma_ack {
	u64 xid;
	u32 status;
} __attribute__((aligned(8)));

static inline int rio_parse_hdr(char *buf, char **payload, int *payload_size,
				int *credits, struct pcs_remote_buf **rb,
				struct pcs_rdma_ack **rack,
				int queue_depth)
{
	struct pcs_rdmaio_hdr *hdr = (struct pcs_rdmaio_hdr *)buf;

	if (hdr->magic != RIO_MAGIC) {
		TRACE("wrong rio msg magic: 0x%x\n", hdr->magic);
		return -1;
	}

	if (hdr->version != RIO_VERSION) {
		TRACE("wrong rio msg version: 0x%x\n", hdr->version);
		return -1;
	}

	if (hdr->type >= RIO_MAX_TYPE_VALUE) {
		TRACE("wrong rio msg type: 0x%x\n", hdr->type);
		return -1;
	}

	if (hdr->size > RIO_MSG_SIZE) {
		TRACE("wrong rio msg size: 0x%x\n", hdr->size);
		return -1;
	}

	if (hdr->credits > queue_depth) {
		TRACE("wrong rio msg credits: 0x%x\n", hdr->credits);
		return -1;
	}

	if (hdr->type == RIO_MSG_RDMA_READ_REQ &&
	    hdr->size - sizeof(*hdr) < sizeof(struct pcs_remote_buf)) {
		TRACE("short rdma read req: 0x%x\n", hdr->size);
		return -1;
	}

	if (hdr->type == RIO_MSG_RDMA_READ_ACK &&
	    hdr->size != sizeof(*hdr) + sizeof(struct pcs_rdma_ack)) {
		TRACE("wrong size rdma read ack: 0x%x\n", hdr->size);
		return -1;
	}

	*payload = buf + sizeof(*hdr);
	*payload_size = hdr->size - sizeof(*hdr);
	*credits = hdr->credits;

	if (hdr->type == RIO_MSG_RDMA_READ_REQ) {
		*rb = (struct pcs_remote_buf *)*payload;
		*payload += sizeof(struct pcs_remote_buf);
		*payload_size -= sizeof(struct pcs_remote_buf);
	} else if (hdr->type == RIO_MSG_RDMA_READ_ACK) {
		*rack = (struct pcs_rdma_ack *)*payload;
		*payload += sizeof(struct pcs_rdma_ack);
		*payload_size -= sizeof(struct pcs_rdma_ack);
	}

	return hdr->type;
}

#endif /* _PCS_RDMA_PROT_H_ */
