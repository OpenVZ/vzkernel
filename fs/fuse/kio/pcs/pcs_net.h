#ifndef _PCS_NET_H_
#define _PCS_NET_H_ 1

#include "pcs_types.h"
#include "pcs_ioconn.h"

struct pcs_msg;
struct pcs_netio;
struct pcs_rpc;

struct pcs_netio_tops {
	/* suspend polling events on netio->ioconn.fd */
	void  (*throttle)(struct pcs_netio *netio);

	/* resume polling events on netio->ioconn.fd */
	void  (*unthrottle)(struct pcs_netio *netio);

	/* queue message for sending */
	void  (*send_msg)(struct pcs_netio *netio, struct pcs_msg *msg);

	/* try to cancel message send */
	int   (*cancel_msg)(struct pcs_msg *msg);

	/* tear down connection, finilize all in-flight messages with error */
	void  (*abort_io)(struct pcs_netio *netio, int error);

	/* try to transmit messages */
	void  (*xmit)(struct pcs_netio *netio);

	/* try to flush messages */
	int   (*flush)(struct pcs_netio *netio);

	/* get next timeout */
	unsigned long (*next_timeout)(struct pcs_netio *netio);
};

struct pcs_netio {
	struct pcs_ioconn ioconn;
	struct pcs_rpc *parent;

	/* transport methods */
	struct pcs_netio_tops *tops;

	/* callbacks */

	/* create pcs_msg by inline_buffer pointing to the head of new incoming message */
	struct pcs_msg *(*getmsg)(struct pcs_netio *netio, char *inline_buffer,
				  u32 *msg_size);

	/* report "connection closed" event: graceful shutdown or abort_io. Notice, that
	 * the handler could be called twice: once on graceful shutdown and from abort_io()
	 */
	void  (*eof)(struct pcs_netio *netio);
};

#endif /* _PCS_NET_H_ */
