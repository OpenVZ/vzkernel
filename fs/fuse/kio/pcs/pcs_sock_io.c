#include <net/sock.h>
#include <net/tcp.h>
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/highmem.h>

#include "pcs_types.h"
#include "pcs_sock_io.h"
#include "pcs_rpc.h"
#include "log.h"


static inline struct pcs_rpc * sock_to_rpc(struct sock *sk)
{

	return ((struct pcs_sockio *)sk->sk_user_data)->parent;
}

static void sio_msg_sent(struct pcs_msg * msg)
{
	msg->stage = PCS_MSG_STAGE_SENT;
	if (msg->timeout) {
		BUG_ON(msg->rpc == NULL);
		BUG_ON(msg->kill_slot >= PCS_MSG_MAX_CALENDAR);
		pcs_msg_del_calendar(msg);
	}
}

void sio_push(struct pcs_sockio * sio)
{
	TRACE(PEER_FMT" flush \n", PEER_ARGS(sio->parent));
	if (sio->flags & PCS_SOCK_F_CORK) {
		int optval = 1;
		int ret;
		ret = kernel_setsockopt(sio->ioconn.socket, SOL_TCP, TCP_NODELAY,
					(char *)&optval, sizeof(optval));
		if (ret)
			TRACE("kernel_setsockopt(TCP_NODELAY) failed: %d",  ret);

	}
}

//// TODO:dmonakhov@ implement unregister and close,
//// socket close must being synchronized with userspace THINK
//// caseA: userspace close socket and wait for kernelspace
//// caseB: kernelspace want to close socket and have to somehow
////	    notify about this to userspace (NEW API REQUIRED)
static void pcs_restore_sockets(struct pcs_ioconn *ioconn);
void pcs_ioconn_unregister(struct pcs_ioconn *ioconn)
{
	if (!test_bit(PCS_IOCONN_BF_DEAD, &ioconn->flags)) {
		set_bit(PCS_IOCONN_BF_DEAD, &ioconn->flags);
		pcs_restore_sockets(ioconn);
	}

}

void pcs_ioconn_close(struct pcs_ioconn *ioconn)
{
	kernel_sock_shutdown(ioconn->socket, SHUT_RDWR);
}

void sio_abort(struct pcs_sockio * sio, int error)
{
	if (sio->current_msg) {
		pcs_free_msg(sio->current_msg);
		sio->current_msg = NULL;
	}

	sio->flags &= ~(PCS_SOCK_F_POOLOUT|PCS_SOCK_F_POOLIN);
	while (!list_empty(&sio->write_queue)) {
		struct pcs_msg * msg = list_first_entry(&sio->write_queue, struct pcs_msg, list);
		list_del(&msg->list);
		sio->write_queue_len -= msg->size;
		sio_msg_sent(msg);

		pcs_set_local_error(&msg->error, error);
		BUG_ON(!hlist_unhashed(&msg->kill_link));
		msg->done(msg);
	}
	pcs_ioconn_unregister(&sio->ioconn);
	pcs_ioconn_close(&sio->ioconn);
	pcs_set_local_error(&sio->error, error);
	if (sio->eof) {
		void (*eof)(struct pcs_sockio *) = sio->eof;
		sio->eof = NULL;
		(*eof)(sio);
	}
}


void pcs_sock_abort(struct pcs_sockio * sio)
{
	if (!sio)
		return;

	sio_abort(sio, PCS_ERR_NET_ABORT);
}

void pcs_sock_error(struct pcs_sockio * sio, int error)
{
	sio_abort(sio, error);
}

static char trash_buf[PAGE_SIZE];

static void rcv_get_iter(struct pcs_msg *msg, int read_off, struct iov_iter *it)
{
	if (likely(msg != PCS_TRASH_MSG))
		msg->get_iter(msg, read_off, it);
}

static struct page *rcv_iov_iter_kmap(struct pcs_msg *msg, struct iov_iter *it,
				      void **buf, size_t *len)
{
	if (unlikely(msg == PCS_TRASH_MSG)) {
		*buf = trash_buf;
		*len = sizeof(trash_buf);
		return NULL;
	}

	return iov_iter_kmap(it, buf, len);
}

static void rcv_iov_iter_advance(struct pcs_msg *msg, struct iov_iter *it, int n)
{
	if (likely(msg != PCS_TRASH_MSG))
		iov_iter_advance(it, n);
}

static void rcv_msg_done(struct pcs_msg *msg)
{
	if (likely(msg != PCS_TRASH_MSG))
		msg->done(msg);
}

#ifdef CONFIG_DEBUG_KERNEL
static bool pcs_should_fail_sock_io(void)
{
	extern u32 sockio_fail_percent;

	if (sockio_fail_percent <= prandom_u32() % 100)
		return false;

	return true;
}
#else
static bool pcs_should_fail_sock_io(void)
{
	return false;
}
#endif

static int do_send_one_seg(struct socket *sock, struct iov_iter *it, bool more)
{
	int ret = -EIO;
	size_t offset, len;
	struct page *page;
	int flags = (MSG_DONTWAIT | MSG_NOSIGNAL) | (more ? MSG_MORE : MSG_EOR);

	DTRACE("sock(%p)  len:%ld, more:%d\n", sock, iov_iter_count(it), more);

	if (pcs_should_fail_sock_io())
		goto out;

	page = iov_iter_get_page(it, &offset, &len);
	if (!page) {
		/* No page, fallback to memcopy */
		struct msghdr msg = { .msg_flags = flags};
		struct page *page;
		struct kvec vec;

		page = iov_iter_kmap(it, &vec.iov_base, &vec.iov_len);
		ret = kernel_sendmsg(sock, &msg, &vec, 1, vec.iov_len);
		if (page)
			kunmap(page);
	} else {
		/* Zerocopy */
		ret = kernel_sendpage(sock, page, offset, len, flags);
		put_page(page);
	}

out:
	DTRACE("sock(%p) len:%ld, more:%d ret:%d\n", sock, iov_iter_count(it), more, ret);
	return ret;
}

static int do_sock_recv(struct socket *sock, void *buf, size_t len)
{

	struct kvec iov = {buf, len};
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	int ret = -EIO;

	if (pcs_should_fail_sock_io())
		goto out;

	ret =  kernel_recvmsg(sock, &msg, &iov, 1, len, msg.msg_flags);
out:
	TRACE("RET: "PEER_FMT" len:%ld ret:%d\n", PEER_ARGS(sock_to_rpc(sock->sk)),
	      len, ret);
	return ret;
}

static void pcs_sockio_recv(struct pcs_sockio *sio)
{
	struct pcs_ioconn* conn = &sio->ioconn;
	struct iov_iter *it = &sio->read_iter;
	struct pcs_rpc *ep = sio->parent;
	int count = 0;
	u32 msg_size;
	unsigned long loop_timeout = jiffies + PCS_SIO_SLICE;

	(void)ep;
	TRACE("ENTER:" PEER_FMT " sio:%p cur_msg:%p\n", PEER_ARGS(ep), sio, sio->current_msg);

	while(!test_bit(PCS_IOCONN_BF_DEAD, &conn->flags)) {
		int n;
		struct pcs_msg * msg;

		if (test_bit(PCS_IOCONN_BF_ERROR, &conn->flags)) {
			sio_abort(sio, PCS_ERR_NET_ABORT);
			return;
		}
		if (!sio->current_msg) {
			/* New message */

			int copy = (int)(sio->hdr_max - sio->hdr_ptr);

			sio->read_offset = 0;
			n = 0;

			if (copy)
				n = do_sock_recv(conn->socket, (char *)sio_inline_buffer(sio) + sio->hdr_ptr, copy);

			if (n > 0 || n == copy /* recv return 0 when copy is 0 */) {
				sio->hdr_ptr += n;
				if(sio->hdr_ptr != sio->hdr_max)
					return;

				msg = sio->get_msg(sio, &msg_size);
				if (msg == NULL) {
					if (sio->hdr_ptr < sio->hdr_max)
						continue;
					if (sio->flags & PCS_SOCK_F_THROTTLE)
						continue;
					sio_abort(sio, PCS_ERR_NOMEM);
					return;
				}
				sio->read_offset = sio->hdr_ptr;
				sio->hdr_ptr = 0;
				sio->current_msg = msg;
				sio->current_msg_size = msg_size;
				rcv_get_iter(msg, sio->read_offset, it);
				TRACE(PEER_FMT" msg:%p read_off:%d iov_size:%ld\n", PEER_ARGS(ep), msg, sio->read_offset,
				      iov_iter_count(it));
			} else {
				if (n == -EAGAIN || n == 0)
					return;

				sio_abort(sio, PCS_ERR_NET_ABORT);
				return;
			}
		} else { /* Continue recevining message */
			msg = sio->current_msg;
			msg_size = sio->current_msg_size;;

			while (sio->read_offset < msg_size) {
				void *buf;
				size_t len;
				struct page *page;

				if (!iov_iter_count(it))
					/* Current iter is exhausted, init new one */
					rcv_get_iter(msg, sio->read_offset, it);

				TRACE(PEER_FMT" msg:%p->size:%d off:%d it_count:%ld\n",
				      PEER_ARGS(ep), msg, msg_size, sio->read_offset,
				      iov_iter_count(it));

				if (msg != PCS_TRASH_MSG)
					BUG_ON(iov_iter_count(it) > msg_size - sio->read_offset);

				page = rcv_iov_iter_kmap(msg, it, &buf, &len);
				if (len > msg_size - sio->read_offset)
					len = msg_size - sio->read_offset;
				n = do_sock_recv(conn->socket, buf, len);
				if (page)
					kunmap(page);

				if (n > 0) {
					sio->read_offset += n;
					rcv_iov_iter_advance(msg, it, n);
				} else {
					if (n == -EAGAIN || n == 0)
						return;
					sio_abort(sio, PCS_ERR_NET_ABORT);
					return;
				}
			}
			sio->current_msg = NULL;
			iov_iter_init_bad(&sio->read_iter);
			rcv_msg_done(msg);
			if (++count >= PCS_SIO_PREEMPT_LIMIT ||
			    time_is_before_jiffies(loop_timeout)) {
				sio->flags |= PCS_SOCK_F_POOLIN;
				break;
			}
		}
	}
	if (count && !list_empty(&ep->lru_link) && ep->gc)
		list_lru_add(&ep->gc->lru, &ep->lru_link);

}

static void pcs_sockio_send(struct pcs_sockio *sio)
{
	struct pcs_ioconn* conn = &sio->ioconn;
	struct iov_iter *it = &sio->write_iter;
	unsigned long loop_timeout = jiffies + PCS_SIO_SLICE;
	struct pcs_msg * msg;
	int done = 0;
	int count = 0;
	struct pcs_rpc *ep = sio->parent;
	(void)ep;

	while (!list_empty(&sio->write_queue)) {
		msg = list_first_entry(&sio->write_queue, struct pcs_msg, list);

		TRACE(PEER_FMT" sio(%p) offset:%d msg:%p\n", PEER_ARGS(ep), sio, sio->write_offset, msg);

		/* This is original check, but it is not clear how connection can becomes
		   dead before sio_abort() was called. Let's simplify it with BUG_ON
		if (conn->dead) {
			pcs_set_local_error(&msg->error, PCS_ERR_NET_ABORT);
			goto done;
		}
		*/
		BUG_ON(test_bit(PCS_IOCONN_BF_DEAD, &conn->flags));

		if (test_bit(PCS_IOCONN_BF_ERROR, &conn->flags)) {
			sio_abort(sio, PCS_ERR_NET_ABORT);
			return;
		}

		/* TODO: cond resched here? */
		while (sio->write_offset < msg->size) {
			size_t left = msg->size - sio->write_offset;
			int n;

			TRACE(PEER_FMT "offset:%d msg:%p left:%ld, it->len:%ld\n", PEER_ARGS(ep), sio->write_offset, msg,
			      left, iov_iter_count(it));

			if (!iov_iter_count(it)) {
				/* Current iter is exhausted, init new one */
				msg->get_iter(msg, sio->write_offset, it);
			}
			BUG_ON(iov_iter_count(it) > left);
			n = do_send_one_seg(conn->socket, it, iov_iter_single_seg_count(it) < left);
			if (n > 0) {
				sio->write_offset += n;
				iov_iter_advance(it, n);
				done = 1;
			} else {
				if (n == 0)
					WARN_ON(1);

				if (n == -EAGAIN) {
					unsigned long timeout = msg->start_time + sio->send_timeout;
					if (time_is_before_jiffies(timeout))
						sio_abort(sio, PCS_ERR_WRITE_TIMEOUT);
					return;
				}
				sio_abort(sio, PCS_ERR_NET_ABORT);
				return;
			}
		}
		list_del_init(&msg->list);
		sio->write_queue_len -= msg->size;

		if (sio->write_queue_len == 0) {
			if (sio->write_wakeup)
				sio->write_wakeup(sio);
		}
		sio->write_offset = 0;
		iov_iter_init_bad(it);
		sio_msg_sent(msg);
		msg->done(msg);
		if (++count >= PCS_SIO_PREEMPT_LIMIT ||
		    time_is_before_jiffies(loop_timeout)) {
			sio->flags |= PCS_SOCK_F_POOLOUT;
			break;
		}
	}
	if (done)
		sio_push(sio);
}

void pcs_sockio_xmit(struct pcs_sockio *sio)
{
	struct pcs_rpc *ep = sio->parent;

	BUG_ON(!mutex_is_locked(&ep->mutex));

	sio->flags &= ~(PCS_SOCK_F_POOLOUT|PCS_SOCK_F_POOLIN);
	pcs_sockio_recv(sio);
	pcs_sockio_send(sio);
}

int pcs_sockio_delayed_seg(struct pcs_sockio *sio)
{
	return sio->flags & (PCS_SOCK_F_POOLOUT|PCS_SOCK_F_POOLIN);
}

void pcs_sock_sendmsg(struct pcs_sockio * sio, struct pcs_msg *msg)
{
	DTRACE("sio(%p) msg:%p\n", sio, msg);

	if (pcs_if_error(&sio->error)) {
		pcs_set_local_error(&msg->error, sio->error.value);
		msg->done(msg);
		return;
	}
	msg->sio = sio;

	list_add_tail(&msg->list, &sio->write_queue);
	sio->write_queue_len += msg->size;
	msg->start_time = jiffies;
	msg->stage = PCS_MSG_STAGE_SEND;

	if (!(sio->flags & PCS_SOCK_F_POOLOUT))
		sio->flags |= PCS_SOCK_F_POOLOUT;

}

/* Try to cancel message send. If it is impossible, because message is in the middle
 * of write, so nothing and return an error.
 */
int pcs_sock_cancel_msg(struct pcs_msg * msg)
{
	struct pcs_sockio * sio = msg->sio;

	BUG_ON(msg->sio == NULL);

	if (sio->write_offset && sio->write_queue.next == &msg->list)
		return -EBUSY;

	list_del_init(&msg->list);
	sio->write_queue_len -= msg->size;
	msg->stage = PCS_MSG_STAGE_SENT;

	if (!sio->write_queue_len) {
		if (sio->write_wakeup)
			sio->write_wakeup(sio);
	}

	return 0;
}

int pcs_sock_queuelen(struct pcs_sockio * sio)
{
	return sio->write_queue_len;
}

static void pcs_restore_sockets(struct pcs_ioconn *ioconn)
{

	struct sock *sk;

	sk = ioconn->socket->sk;

	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data =    ioconn->orig.user_data;
	sk->sk_data_ready =   ioconn->orig.data_ready;
	sk->sk_write_space =  ioconn->orig.write_space;
	sk->sk_error_report = ioconn->orig.error_report;
	//sock->sk->sk_state_change = pcs_state_chage;
	write_unlock_bh(&sk->sk_callback_lock);

	sk->sk_sndtimeo = MAX_SCHEDULE_TIMEOUT;
	sk->sk_rcvtimeo = MAX_SCHEDULE_TIMEOUT;
}

void pcs_sock_ioconn_destruct(struct pcs_ioconn *ioconn)
{
	struct pcs_sockio * sio = sio_from_ioconn(ioconn);

	BUG_ON(sio->current_msg);
	BUG_ON(!list_empty(&sio->write_queue));
	BUG_ON(sio->write_queue_len);

	pcs_ioconn_close(ioconn);

	memset(sio, 0xFF, sizeof(*sio));
	kfree(sio);
}

static void pcs_sk_data_ready(struct sock *sk, int count)
{
	struct pcs_sockio *sio = sk->sk_user_data;
	struct pcs_rpc *ep = sio->parent;

	TRACE(PEER_FMT" queue count:%d \n", PEER_ARGS(ep), count);

	pcs_rpc_kick_queue(ep);
}
static void pcs_sk_write_space(struct sock *sk)
{
	struct pcs_sockio *sio = sk->sk_user_data;
	struct pcs_rpc *ep = sio->parent;

	TRACE(PEER_FMT" queue \n", PEER_ARGS(ep));

	pcs_rpc_kick_queue(ep);

}

/* TODO this call back does not look correct, sane locking/error handling is required */
static void pcs_sk_error_report(struct sock *sk)
{
	struct pcs_sockio * sio = sio_from_ioconn(sk->sk_user_data);

	if (test_bit(PCS_IOCONN_BF_DEAD, &sio->ioconn.flags) ||
		test_bit(PCS_IOCONN_BF_ERROR, &sio->ioconn.flags))
		return;

	set_bit(PCS_IOCONN_BF_ERROR, &sio->ioconn.flags);
	pcs_rpc_kick_queue(sio->parent);
}

struct pcs_sockio * pcs_sockio_init(struct socket *sock,
				    int alloc_max, int hdr_max)
{
	struct pcs_sockio * sio;
	struct sock *sk;

	sio = kzalloc(sizeof(struct pcs_sockio) + alloc_max, GFP_NOIO);
	if (!sio)
		return NULL;

	INIT_LIST_HEAD(&sio->write_queue);
	iov_iter_init_bad(&sio->read_iter);
	iov_iter_init_bad(&sio->write_iter);
	sio->hdr_max = hdr_max;
	sio->flags = sock->sk->sk_family != AF_UNIX ? PCS_SOCK_F_CORK : 0;

	//// TODO:dmonakhov init ioconn here
	INIT_LIST_HEAD(&sio->ioconn.list);
	sk = sock->sk;
	write_lock_bh(&sk->sk_callback_lock);

	/* Backup original callbaks */
	sio->ioconn.orig.user_data = sk->sk_user_data;
	sio->ioconn.orig.data_ready = sk->sk_data_ready;
	sio->ioconn.orig.write_space = sk->sk_write_space;
	sio->ioconn.orig.error_report = sk->sk_error_report;
	//sio->ioconn.orig_state_change = sk->sk_state_change;

	sk->sk_user_data = sio;
	sk->sk_data_ready = pcs_sk_data_ready;
	sk->sk_write_space = pcs_sk_write_space;
	sk->sk_error_report = pcs_sk_error_report;
	sk->sk_allocation = GFP_NOFS;

	//sock->sk->sk_state_change = pcs_state_chage;

	sk->sk_sndtimeo = PCS_SIO_TIMEOUT;
	sio->send_timeout = PCS_SIO_TIMEOUT;
	sio->ioconn.socket = sock;
	sio->ioconn.destruct = pcs_sock_ioconn_destruct;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	pcs_clear_error(&sio->error);
	return sio;
}

void pcs_sockio_start(struct pcs_sockio * sio)
{
	//// TODO: dmonakhov
	////pcs_ioconn_register(&sio->ioconn);
}

static void pcs_deaccount_msg(struct pcs_msg * msg)
{
	msg->sio = NULL;
}

static void pcs_account_msg(struct pcs_sockio * sio, struct pcs_msg * msg)
{
	msg->sio = sio;

}

static void pcs_msg_input_destructor(struct pcs_msg * msg)
{
	pcs_deaccount_msg(msg);
	memset(msg, 0xFF, sizeof(*msg));
	kfree(msg);
}

/* get_iter() handler for messages with embedded payload right after pcs_msg */
void pcs_get_iter_inline(struct pcs_msg * msg, int offset, struct iov_iter *it)
{
	BUG_ON(offset >= msg->size);

	iov_iter_init_plain(it, msg->_inline_buffer, msg->size, 0);
	iov_iter_advance(it, offset);
}

struct pcs_msg * pcs_alloc_input_msg(struct pcs_sockio * sio, int datalen)
{
	struct pcs_msg * msg;

	msg = kmalloc(sizeof(struct pcs_msg) + datalen, GFP_NOIO);
	if (msg) {

		pcs_msg_io_init(msg);
		pcs_account_msg(sio, msg);
		msg->destructor = pcs_msg_input_destructor;
		msg->get_iter = pcs_get_iter_inline;
	}
	return msg;
}

static void pcs_io_msg_output_destructor(struct pcs_msg * msg)
{
	BUG_ON(msg->rpc);
	memset(msg, 0xFF, sizeof(*msg));
	kfree(msg);
}


struct pcs_msg * pcs_alloc_output_msg(int datalen)
{
	struct pcs_msg * msg;

	msg = kmalloc(sizeof(struct pcs_msg) + datalen, GFP_NOIO);
	if (msg) {
		pcs_msg_io_init(msg);
		msg->rpc = NULL;
		msg->sio = NULL;
		msg->destructor = pcs_io_msg_output_destructor;
		msg->get_iter = pcs_get_iter_inline;
	}
	return msg;
}

void pcs_free_msg(struct pcs_msg * msg)
{
	if (msg == PCS_TRASH_MSG)
		return;

	pcs_msg_io_fini(msg);

	if (msg->destructor)
		msg->destructor(msg);
}

/* iter_iter() handler for cloned messages */
static void get_iter_clone(struct pcs_msg * msg, int offset, struct iov_iter *it)
{
	struct pcs_msg * parent = msg->private;

	BUG_ON(offset >= msg->size);

	parent->get_iter(parent, offset, it);
}

void pcs_clone_done(struct pcs_msg * msg)
{
	struct pcs_msg * parent = msg->private;

	pcs_copy_error_cond(&parent->error, &msg->error);

	pcs_msg_io_end(parent);

	pcs_free_msg(msg);
}

struct pcs_msg * pcs_clone_msg(struct pcs_msg * msg)
{
	struct pcs_msg * clone;

	clone = kmalloc(sizeof(struct pcs_msg), GFP_NOIO);
	if (clone) {
		pcs_msg_io_init(clone);
		clone->rpc = NULL;
		clone->size = msg->size;
		clone->timeout = 0;
		clone->done = pcs_clone_done;
		clone->destructor = pcs_io_msg_output_destructor;
		clone->private = msg;
		clone->get_iter = get_iter_clone;
	}
	return clone;
}

/* iter_iter() handler for cloned messages */
static void get_iter_cow_clone(struct pcs_msg * msg, int offset, struct iov_iter *it)
{
	struct pcs_msg * parent = msg->private;

	BUG_ON(offset >= msg->size);

	if (offset < msg->_inline_len) {
		iov_iter_init_plain(it, msg->_inline_buffer, msg->_inline_len, 0);
		iov_iter_advance(it, offset);
	} else {
		parent->get_iter(parent, offset, it);
	}
}

struct pcs_msg * pcs_cow_msg(struct pcs_msg * msg, int copy_len)
{
	struct pcs_msg * clone;

	clone = kmalloc(sizeof(struct pcs_msg) + copy_len, GFP_NOIO);
	if (clone) {
		pcs_msg_io_init(clone);
		clone->rpc = NULL;
		clone->size = msg->size;
		clone->timeout = 0;
		clone->done = pcs_clone_done;
		clone->destructor = pcs_io_msg_output_destructor;
		clone->private = msg;
		BUG_ON(copy_len > SHRT_MAX);
		clone->_inline_len = (short)copy_len;
		memcpy(clone->_inline_buffer, msg_inline_head(msg), copy_len);
		clone->get_iter = get_iter_cow_clone;
	}
	return clone;
}

void pcs_sock_throttle(struct pcs_sockio * sio)
{
	if ((sio->flags & PCS_SOCK_F_THROTTLE) ||
	    test_bit(PCS_IOCONN_BF_DEAD, &sio->ioconn.flags))
		return;

	DTRACE("Throttle on socket %p rpc=%p", sio, sio->parent);
	sio->flags |= PCS_SOCK_F_THROTTLE;
}

void pcs_sock_unthrottle(struct pcs_sockio * sio)
{
	if (!(sio->flags & PCS_SOCK_F_THROTTLE) ||
	    test_bit(PCS_IOCONN_BF_DEAD, &sio->ioconn.flags))
		return;

	DTRACE("Unthrottle on socket %p rpc=%p", sio, sio->parent);
	sio->flags &= ~PCS_SOCK_F_THROTTLE;
	if ((sio->flags & PCS_SOCK_F_EOF))
		return;
}
