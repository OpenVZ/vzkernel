#ifndef _PCS_SOCK_IO_H_
#define _PCS_SOCK_IO_H_ 1

#include <linux/net.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <linux/fs.h>

#include "pcs_types.h"
////#include "pcs_process.h"
#include "pcs_error.h"
#include "pcs_net.h"
#include "log.h"

#define PCS_MSG_MAX_CALENDAR	64
#define PCS_SIO_TIMEOUT		(60*HZ)

#define PCS_SIO_PREEMPT_LIMIT	16
#define PCS_SIO_SLICE (5 * HZ / 1000) /* 5ms */

extern struct pcs_netio_tops pcs_sock_netio_tops;


struct pcs_api_channel
{
	unsigned	sio_count;
	unsigned	msg_count;
};

__pre_packed struct pcs_msg
{
	struct __pre_aligned(16) {
		struct list_head list;

		pcs_error_t	error;
		abs_time_t	start_time;

		void		*private;
		void		*private2;	/* Huh? Need to do something else here. */
		struct pcs_msg	*response;	/* Consider removing. It can be done passing the second
						 * argument to done();
						 */
		struct pcs_netio *netio;
		struct pcs_rpc	*rpc;

		int		size;
		int		_iocount;
		unsigned short	timeout;
		unsigned char	kill_slot;
		unsigned char	stage;
		abs_time_t	io_start_time;

		struct hlist_node	kill_link;

		void		(*get_iter)(struct pcs_msg *, int offset, struct iov_iter *it);

		void		(*done)(struct pcs_msg *);
		void		(*destructor)(struct pcs_msg *);
		void		*pool;
		struct iovec	_inline_iovec;
		int		accounted;

		short		_align_offset;
		short		_inline_len;
	} __aligned(16);
	u64		__pad16_8;
	char		_inline_buffer[0];
} __packed;

static inline void * pcs_msg_aligned_data(struct pcs_msg * msg, int offset)
{
	return (void*)((char *)msg + msg->_align_offset + offset);
}

enum
{
	PCS_MSG_STAGE_NONE	= 0,	/* Initial state */
	PCS_MSG_STAGE_UNSENT	= 1,	/* Message queued somewhere before send */
	PCS_MSG_STAGE_SEND	= 2,	/* Message queued on socket queue */
	PCS_MSG_STAGE_SENT	= 3,	/* Message is sent */
	PCS_MSG_STAGE_WAIT	= 4,	/* Message is waiting for respnose */
	PCS_MSG_STAGE_DONE	= 5,	/* Response received */
};

enum
{
	PCS_SOCK_F_THROTTLE		= 1,
	PCS_SOCK_F_CORK			= 2,
	PCS_SOCK_F_DYNAMIC_SIZE		= 4,
	PCS_SOCK_F_EOF			= 8,
	PCS_SOCK_F_POOLIN		= 0x10,
	PCS_SOCK_F_POOLOUT		= 0x20,
};

enum
{
	PCS_IOCONN_BF_DEAD		= 0,
	PCS_IOCONN_BF_ERROR		= 1, /* Notify from ->sk_error_report */
};

struct pcs_sockio
{
	struct pcs_netio	netio;

	struct socket		*socket;
	unsigned long		io_flags;	/* atomic bit ops */
	/* Save original socket->sk callbacks */
	struct {
		void			*user_data;
		void			(*state_change)(struct sock *sk);
		void			(*error_report)(struct sock *sk);
		void			(*data_ready)(struct sock *sk, int bytes);
		void			(*write_space)(struct sock *sk);
	} orig;

	struct list_head	write_queue;
	int			write_queue_len;
	spinlock_t		q_lock;

	pcs_error_t		error;
	int			send_timeout;
	int			hdr_ptr;
	int			hdr_max;
	unsigned int		flags;
	u32			retrans;

	struct pcs_msg		*current_msg;
#define PCS_TRASH_MSG ((void *)~0UL)
	u32			current_msg_size;
	int			read_offset;
	int			write_offset;
	struct iov_iter		read_iter;
	struct iov_iter		write_iter;
	struct mutex		mutex;
	void			(*write_wakeup)(struct pcs_sockio *);
	struct rcu_head		rcu;

	char			_inline_buffer[0];
};

void pcs_sk_data_ready(struct sock *sk, int count);
void pcs_sk_write_space(struct sock *sk);
void pcs_sk_error_report(struct sock *sk);

#define sio_from_netio(nio) container_of(nio, struct pcs_sockio, netio)
#define sio_from_ioconn(conn) container_of(conn, struct pcs_sockio, netio.ioconn)

struct pcs_msg * pcs_alloc_input_msg(struct pcs_sockio * sio, int datalen);
struct pcs_msg * pcs_alloc_output_msg(int datalen);
struct pcs_msg * pcs_clone_msg(struct pcs_msg * msg);
struct pcs_msg * pcs_cow_msg(struct pcs_msg * msg, int data_len);
void pcs_clone_done(struct pcs_msg * msg);
void pcs_free_msg(struct pcs_msg * msg);
void pcs_get_iter_inline(struct pcs_msg * msg, int offset, struct iov_iter*it);
void pcs_sock_ioconn_destruct(struct pcs_ioconn *ioconn);
void pcs_msg_sent(struct pcs_msg * msg);

static inline void * msg_inline_head(struct pcs_msg * msg)
{
	struct iov_iter i;
	void *map, *buf;
	size_t len;

	msg->get_iter(msg, 0, &i);
	map = iov_iter_kmap_atomic(&i, &buf, &len);
	/* inline head always kernel memory */
	BUG_ON(map);
	BUG_ON(len > msg->size);

	return buf;
}

static inline void * sio_inline_buffer(struct pcs_sockio * sio)
{
	return sio->_inline_buffer;
}

static inline void pcs_msg_io_init(struct pcs_msg * msg)
{
	pcs_clear_error(&msg->error);
	msg->_iocount = 0;
	msg->done = pcs_free_msg;
}

static inline void pcs_msg_io_start(struct pcs_msg * msg, void (*done)(struct pcs_msg *))
{
	BUG_ON(msg->_iocount != 0);
	msg->_iocount = 1;
	msg->done = done;
}

static inline struct pcs_msg * pcs_msg_io_sched(struct pcs_msg * msg)
{
	BUG_ON(msg->_iocount <= 0);
	msg->_iocount++;
	return msg;
}

static inline void pcs_msg_io_end(struct pcs_msg * msg)
{
	BUG_ON(msg->_iocount <= 0);
	if (--msg->_iocount == 0)
		msg->done(msg);
}

static inline void pcs_msg_io_fini(struct pcs_msg * msg)
{
	BUG_ON(msg->_iocount != 0);
}

#endif /* _PCS_SOCK_IO_H_ */
