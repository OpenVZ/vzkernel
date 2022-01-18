/*
 *  fs/fuse/kio/pcs/pcs_sock_conn.c
 *
 *  Copyright (c) 2018-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <net/sock.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/tcp.h>

#include "pcs_types.h"
#include "pcs_sock_io.h"
#include "pcs_rpc.h"
#include "pcs_cluster.h"
#include "pcs_auth.h"
#include "log.h"
#include "fuse_ktrace.h"

static inline void pcs_sock_keepalive(struct socket *sock)
{
	sock_set_keepalive(sock->sk);
	if (sock->sk->sk_family == PF_INET || sock->sk->sk_family == PF_INET6) {
		tcp_sock_set_keepidle(sock->sk, 60);
		tcp_sock_set_keepcnt(sock->sk, 5);
		tcp_sock_set_keepintvl(sock->sk, 5);
	}
}

static inline void pcs_sock_cork(struct socket *sock)
{
	tcp_sock_set_cork(sock->sk, true);
}

int pcs_netaddr2sockaddr(PCS_NET_ADDR_T const* addr, struct sockaddr *sa, int *salen)
{
	BUG_ON(!sa);
	if (addr->type == PCS_ADDRTYPE_IP || addr->type == PCS_ADDRTYPE_RDMA) {
		struct sockaddr_in *saddr4 = (struct sockaddr_in *)sa;
		*saddr4 = (struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_port = (u16)addr->port,
		};
		memcpy(&saddr4->sin_addr, addr->address, sizeof(saddr4->sin_addr));
		*salen = sizeof(*saddr4);
	} else if (addr->type == PCS_ADDRTYPE_IP6) {
		struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)sa;
		*saddr6 = (struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_port = (u16)addr->port,
		};
		memcpy(&saddr6->sin6_addr, addr->address, sizeof(saddr6->sin6_addr));
		*salen = sizeof(*saddr6);
	} else
		return -EINVAL;

	return 0;
}

void pcs_sockconnect_start(struct pcs_rpc *ep)
{
	struct pcs_sockio *sio;
	struct sockaddr *sa = &ep->sh.sa;
	struct socket *sock;
	int err, alloc_max = ep->params.alloc_hdr_size;

	BUG_ON(!mutex_is_locked(&ep->mutex));

	sio = kzalloc(sizeof(struct pcs_sockio) + alloc_max, GFP_NOIO);
	if (!sio) {
		TRACE("Can't allocate sio\n");
		goto fail;
	}

	INIT_LIST_HEAD(&sio->write_queue);
	iov_iter_kvec(&sio->read_iter, READ, NULL, 0, 0);
	iov_iter_kvec(&sio->write_iter, WRITE, NULL, 0, 0);
	sio->hdr_max = sizeof(struct pcs_rpc_hdr);
	sio->flags = sa->sa_family != AF_UNIX ? PCS_SOCK_F_CORK : 0;

	err = sock_create(sa->sa_family, SOCK_STREAM, 0, &sock);
	if (err < 0) {
		TRACE("Can't create socket: %d\n", err);
		goto fail2;
	}
	pcs_clear_error(&sio->error);

	err = sock->ops->connect(sock, sa, ep->sh.sa_len, O_NONBLOCK);
	if (err != 0 && err != -EINPROGRESS) {
		TRACE("Failed connection: %d\n", err);
		sock_release(sock);
		goto fail2;
	}
	pcs_sock_keepalive(sock);
	if (sa->sa_family == PF_INET || sa->sa_family == PF_INET6) {
		pcs_sock_cork(sock);
		sio->flags |= PCS_SOCK_F_CORK;
	}

	TRACE(PEER_FMT " ->state:%d sock:%p\n", PEER_ARGS(ep), ep->state, sock);
	cancel_delayed_work(&ep->timer_work);
	ep->retries++;

	ep->conn = &sio->netio.ioconn;
	sio->send_timeout = PCS_SIO_TIMEOUT;
	sio->socket = sock;
	sio->netio.ioconn.destruct = pcs_sock_ioconn_destruct;
	sio->netio.parent = pcs_rpc_get(ep);
	sio->netio.tops = &pcs_sock_netio_tops;
	sio->netio.getmsg = rpc_get_hdr;
	sio->netio.eof = rpc_eof_cb;
	if (ep->gc)
		list_lru_add(&ep->gc->lru, &ep->lru_link);

	if (ep->flags & PCS_RPC_F_CLNT_PEER_ID)
		ep->flags |= PCS_RPC_F_PEER_ID;

	ep->state = PCS_RPC_AUTH;
	err = rpc_client_start_auth(ep, PCS_AUTH_DIGEST,
				    cc_from_rpc(ep->eng)->cluster_name);
	if (err < 0) {
		FUSE_KLOG(cc_from_rpc(ep->eng)->fc, LOG_ERR,
			  "Authorization failed: %d", err);
		goto fail; /* since ep->conn is initialized,
			    * sio will be freed in pcs_rpc_reset()
			    */
	}
	write_lock_bh(&sock->sk->sk_callback_lock);
	/*
	 * Backup original callbaks.
	 * TCP and unix sockets do not have sk_user_data set.
	 * So we avoid taking sk_callback_lock in callbacks,
	 * since this seems to be able to result in performance.
	 */
	WARN_ON_ONCE(sock->sk->sk_user_data);
	sio->orig.user_data = sock->sk->sk_user_data;
	sio->orig.data_ready = sock->sk->sk_data_ready;
	sio->orig.write_space = sock->sk->sk_write_space;
	sio->orig.error_report = sock->sk->sk_error_report;

	sock->sk->sk_sndtimeo = PCS_SIO_TIMEOUT;
	sock->sk->sk_allocation = GFP_NOFS;

	rcu_assign_sk_user_data(sock->sk, sio);
	smp_wmb(); /* Pairs with smp_rmb() in callbacks */
	sock->sk->sk_data_ready = pcs_sk_data_ready;
	sock->sk->sk_write_space = pcs_sk_write_space;
	sock->sk->sk_error_report = pcs_sk_error_report;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	ep->state = PCS_RPC_APPWAIT;
	pcs_rpc_enable(ep, 0);
	return;
fail2:
	kfree(sio);
fail:
	pcs_rpc_reset(ep);
	return;
}
