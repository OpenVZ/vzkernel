/*
 *  linux/kernel/bc/net.c
 *
 *  Copyright (C) 1998-2004  Andrey V. Savochkin <saw@saw.sw.com.sg>
 *  Copyright (C) 2005 SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 * TODO:
 *   - sizeof(struct inode) charge
 *   = tcp_mem_schedule() feedback based on ub limits
 *   + measures so that one socket won't exhaust all send buffers,
 *     see bug in bugzilla
 *   = sk->socket check for NULL in snd_wakeups
 *     (tcp_write_space checks for NULL itself)
 *   + in tcp_close(), orphaned socket abortion should be based on ubc
 *     resources (same in tcp_out_of_resources)
 *     Beancounter should also have separate orphaned socket counter...
 *   + for rcv, in-order segment should be accepted
 *     if only barrier is exceeded
 *   = tcp_rmem_schedule() feedback based on ub limits
 *   - repair forward_alloc mechanism for receive buffers
 *     It's idea is that some buffer space is pre-charged so that receive fast
 *     path doesn't need to take spinlocks and do other heavy stuff
 *   + tcp_prune_queue actions based on ub limits
 *   + window adjustments depending on available buffers for receive
 *   - window adjustments depending on available buffers for send
 *   + race around usewreserv
 *   + avoid allocating new page for each tiny-gram, see letter from ANK
 *   + rename ub_sock_lock
 *   + sk->sleep wait queue probably can be used for all wakeups, and
 *     sk->ub_wait is unnecessary
 *   + for UNIX sockets, the current algorithm will lead to
 *     UB_UNIX_MINBUF-sized messages only for non-blocking case
 *   - charge for af_packet sockets
 *   + all datagram sockets should be charged to NUMUNIXSOCK
 *   - we do not charge for skb copies and clones staying in device queues
 *   + live-lock if number of sockets is big and buffer limits are small
 *     [diff-ubc-dbllim3]
 *   - check that multiple readers/writers on the same socket won't cause fatal
 *     consequences
 *   - check allocation/charge orders
 *   + There is potential problem with callback_lock.  In *snd_wakeup we take
 *     beancounter first, in sock_def_error_report - callback_lock first.
 *     then beancounter.  This is not a problem if callback_lock taken
 *     readonly, but anyway...
 *   - SKB_CHARGE_SIZE doesn't include the space wasted by slab allocator
 * General kernel problems:
 *   - in tcp_sendmsg(), if allocation fails, non-blocking sockets with ASYNC
 *     notification won't get signals
 *   - datagram_poll looks racy
 *
 */

#include <linux/net.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/socket.h>
#include <linux/module.h>
#include <linux/sched.h>

#include <net/sock.h>
#include <net/tcp.h>

#include <bc/beancounter.h>
#include <bc/net.h>
#include <bc/debug.h>

/* by some reason it is not used currently */
#define UB_SOCK_MAINTAIN_WMEMPRESSURE	0


/* Skb truesize definition. Bad place. Den */

static inline int skb_chargesize_head(struct sk_buff *skb)
{
	return skb_charge_size(skb_end_pointer(skb) - skb->head +
				sizeof(struct skb_shared_info));
}

int skb_charge_fullsize(struct sk_buff *skb)
{
	int chargesize;
	struct sk_buff *skbfrag;

	chargesize = skb_chargesize_head(skb) +
		PAGE_SIZE * skb_shinfo(skb)->nr_frags;
	if (likely(skb_shinfo(skb)->frag_list == NULL))
		return chargesize;
	for (skbfrag = skb_shinfo(skb)->frag_list;
	     skbfrag != NULL;
	     skbfrag = skbfrag->next) {
		chargesize += skb_charge_fullsize(skbfrag);
	}
	return chargesize;
}
EXPORT_SYMBOL(skb_charge_fullsize);

static int ub_sock_makewreserv_locked(struct sock *sk,
		int bufid, unsigned long size);

int __ub_too_many_orphans(struct sock *sk, int count)
{

	struct ubparm *ub_sock;

	ub_sock = &sock_bc(sk)->ub->ub_parms[UB_NUMTCPSOCK];
	if (sock_has_ubc(sk) && (count >= ub_sock->barrier >> 2))
			return 1;
	return 0;
}

/*
 * Queueing
 */

static void ub_sock_snd_wakeup(struct user_beancounter *ub)
{
	struct list_head *p;
	struct sock *sk;
	struct sock_beancounter *skbc;
	struct socket *sock;

	while (!list_empty(&ub->ub_other_sk_list)) {
		p = ub->ub_other_sk_list.next;
		skbc = list_entry(p, struct sock_beancounter, ub_sock_list);
		sk = skbc_sock(skbc);

		sock = sk->sk_socket;
		if (sock == NULL) {
			/* sk being destroyed */
			list_del_init(&skbc->ub_sock_list);
			continue;
		}

		ub_debug(UBD_NET_SLEEP,
				"Checking queue, waiting %lu, reserv %lu\n",
				skbc->ub_waitspc, skbc->poll_reserv);
		if (ub_sock_makewreserv_locked(sk, UB_OTHERSOCKBUF,
					skbc->ub_waitspc))
			break;

		list_del_init(&skbc->ub_sock_list);

		/*
		 * See comments in ub_tcp_snd_wakeup.
		 * Locking note: both unix_write_space and
		 * sock_def_write_space take callback_lock themselves.
		 * We take it here just to be on the safe side and to
		 * act the same way as ub_tcp_snd_wakeup does.
		 */
		sock_hold(sk);
		spin_unlock(&ub->ub_lock);

		read_lock(&sk->sk_callback_lock);
		sk->sk_write_space(sk);
		read_unlock(&sk->sk_callback_lock);

		sock_put(sk);

		spin_lock(&ub->ub_lock);
	}
}

static void ub_tcp_snd_wakeup(struct user_beancounter *ub)
{
	struct list_head *p;
	struct sock *sk;
	struct sock_beancounter *skbc;
	struct socket *sock;

	while (!list_empty(&ub->ub_tcp_sk_list)) {
		p = ub->ub_tcp_sk_list.next;
		skbc = list_entry(p, struct sock_beancounter, ub_sock_list);
		sk = skbc_sock(skbc);

		sock = sk->sk_socket;
		if (sock == NULL) {
			/* sk being destroyed */
			list_del_init(&skbc->ub_sock_list);
			continue;
		}

		ub_debug(UBD_NET_SLEEP,
				"Checking queue, waiting %lu, reserv %lu\n",
				skbc->ub_waitspc, skbc->poll_reserv);
		if (ub_sock_makewreserv_locked(sk, UB_TCPSNDBUF,
					skbc->ub_waitspc))
			break;

		list_del_init(&skbc->ub_sock_list);

		/*
		 * Send async notifications and wake up.
		 * Locking note: we get callback_lock here because
		 * tcp_write_space is over-optimistic about calling context
		 * (socket lock is presumed).  So we get the lock here although
		 * it belongs to the callback.
		 */
		sock_hold(sk);
		spin_unlock(&ub->ub_lock);

		read_lock(&sk->sk_callback_lock);
		sk->sk_write_space(sk);
		read_unlock(&sk->sk_callback_lock);

		sock_put(sk);

		spin_lock(&ub->ub_lock);
	}
}

int ub_sock_snd_queue_add(struct sock *sk, int res, unsigned long size)
{
	unsigned long flags;
	struct sock_beancounter *skbc;
	struct user_beancounter *ub;

	if (!sock_has_ubc(sk))
		return 0;

	skbc = sock_bc(sk);
	ub = skbc->ub;
	spin_lock_irqsave(&ub->ub_lock, flags);
	ub_debug(UBD_NET_SLEEP, "attempt to charge for %lu\n", size);
	if (!ub_sock_makewreserv_locked(sk, res, size)) {
		/*
		 * It looks a bit hackish, but it is compatible with both
		 * wait_for_xx_ubspace and poll.
		 * This __set_current_state is equivalent to a wakeup event
		 * right after spin_unlock_irqrestore.
		 */
		__set_current_state(TASK_RUNNING);
		spin_unlock_irqrestore(&ub->ub_lock, flags);
		return 0;
	}

	ub_debug(UBD_NET_SLEEP, "Adding sk to queue\n");
	skbc->ub_waitspc = size;
	if (!list_empty(&skbc->ub_sock_list)) {
		ub_debug(UBD_NET_SOCKET,
				"re-adding socket to beancounter %p.\n", ub);
		goto out;
	}

	switch (res) {
		case UB_TCPSNDBUF:
			list_add_tail(&skbc->ub_sock_list,
					&ub->ub_tcp_sk_list);
			break;
		case UB_OTHERSOCKBUF:
			list_add_tail(&skbc->ub_sock_list,
					&ub->ub_other_sk_list);
			break;
		default:
			BUG();
	}
out:
	spin_unlock_irqrestore(&ub->ub_lock, flags);
	return -ENOMEM;
}

EXPORT_SYMBOL(ub_sock_snd_queue_add);

long ub_sock_wait_for_space(struct sock *sk, long timeo, unsigned long size)
{
	DECLARE_WAITQUEUE(wait, current);

	add_wait_queue(sk_sleep(sk), &wait);
	for (;;) {
		if (signal_pending(current))
			break;
		set_current_state(TASK_INTERRUPTIBLE);
		if (!ub_sock_make_wreserv(sk, UB_OTHERSOCKBUF, size))
			break;

		if (sk->sk_shutdown & SEND_SHUTDOWN)
			break;
		if (sk->sk_err)
			break;
		ub_sock_snd_queue_add(sk, UB_OTHERSOCKBUF, size);
		timeo = schedule_timeout(timeo);
	}
	__set_current_state(TASK_RUNNING);
	remove_wait_queue(sk_sleep(sk), &wait);
	return timeo;
}

void ub_sock_sndqueuedel(struct sock *sk)
{
	struct user_beancounter *ub;
	struct sock_beancounter *skbc;
	unsigned long flags;

	if (!sock_has_ubc(sk))
		return;
	skbc = sock_bc(sk);

	/* race with write_space callback of other socket */
	ub = skbc->ub;
	spin_lock_irqsave(&ub->ub_lock, flags);
	list_del_init(&skbc->ub_sock_list);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

/*
 * Helpers
 */

static inline void __ub_skb_set_charge(struct sk_buff *skb, struct sock *sk,
		       unsigned long size, int resource)
{
	WARN_ON_ONCE(skb_bc(skb)->ub != NULL);

	skb_bc(skb)->ub = sock_bc(sk)->ub;
	skb_bc(skb)->charged = size;
	skb_bc(skb)->resource = resource;

	/* Ugly. Ugly. Skb in sk writequeue can live without ref to sk */
	if (skb->sk == NULL)
		skb->sk = sk;
}

void ub_skb_set_charge(struct sk_buff *skb, struct sock *sk,
		       unsigned long size, int resource)
{
	if (!sock_has_ubc(sk))
		return;

	if (sock_bc(sk)->ub == NULL)
		BUG();

	__ub_skb_set_charge(skb, sk, size, resource);
}

EXPORT_SYMBOL(ub_skb_set_charge);

static inline void ub_skb_set_uncharge(struct sk_buff *skb)
{
	skb_bc(skb)->ub = NULL;
	skb_bc(skb)->charged = 0;
	skb_bc(skb)->resource = 0;
}

static void ub_update_rmem_thres(struct sock_beancounter *skub)
{
	struct user_beancounter *ub;

	if (skub && skub->ub) {
		ub = skub->ub;
		ub->ub_rmem_thres = ub->ub_parms[UB_TCPRCVBUF].barrier /
			(ub->ub_parms[UB_NUMTCPSOCK].held + 1);
	}
}

static inline void ub_sock_wcharge_dec(struct sock *sk,
		unsigned long chargesize)
{
	/* The check sk->sk_family != PF_NETLINK is made as the skb is
	 * queued to the kernel end of socket while changed to the user one.
	 * Den */
	if (unlikely(sock_bc(sk)->ub_wcharged) && sk->sk_family != PF_NETLINK) {
		if (sock_bc(sk)->ub_wcharged > chargesize)
			sock_bc(sk)->ub_wcharged -= chargesize;
		else
			sock_bc(sk)->ub_wcharged = 0;
	}
}

/*
 * Charge socket number
 */

static inline void sk_alloc_beancounter(struct sock *sk)
{
	struct sock_beancounter *skbc;

	skbc = sock_bc(sk);
	memset(skbc, 0, sizeof(struct sock_beancounter));
}

static inline void sk_free_beancounter(struct sock *sk)
{
}

static int __sock_charge(struct sock *sk, int res)
{
	struct sock_beancounter *skbc;
	struct user_beancounter *ub;
	unsigned long added_reserv, added_forw;
	unsigned long flags;

	ub = get_exec_ub();
	if (unlikely(ub == NULL))
		return 0;

	sk_alloc_beancounter(sk);
	skbc = sock_bc(sk);
	INIT_LIST_HEAD(&skbc->ub_sock_list);

	spin_lock_irqsave(&ub->ub_lock, flags);
	if (unlikely(__charge_beancounter_locked(ub, res, 1, UB_HARD) < 0))
		goto out_limit;

	added_reserv = 0;
	added_forw = 0;
	if (res == UB_NUMTCPSOCK) {
		added_reserv = skb_charge_size(MAX_TCP_HEADER +
				1500 - sizeof(struct iphdr) -
					sizeof(struct tcphdr));
		added_reserv *= 4;
		ub->ub_parms[UB_TCPSNDBUF].held += added_reserv;
		if (!ub_barrier_farsz(ub, UB_TCPSNDBUF)) {
			ub->ub_parms[UB_TCPSNDBUF].held -= added_reserv;
			added_reserv = 0;
		}
		skbc->poll_reserv = added_reserv;
		ub_adjust_maxheld(ub, UB_TCPSNDBUF);

		added_forw = SK_MEM_QUANTUM * 4;
		ub->ub_parms[UB_TCPRCVBUF].held += added_forw;
		if (!ub_barrier_farsz(ub, UB_TCPRCVBUF)) {
			ub->ub_parms[UB_TCPRCVBUF].held -= added_forw;
			added_forw = 0;
		}
		skbc->forw_space = added_forw;
		ub_adjust_maxheld(ub, UB_TCPRCVBUF);
	}
	spin_unlock_irqrestore(&ub->ub_lock, flags);

	skbc->ub = get_beancounter(ub);
	return 0;

out_limit:
	spin_unlock_irqrestore(&ub->ub_lock, flags);
	sk_free_beancounter(sk);
	return -ENOMEM;
}

int ub_tcp_sock_charge(struct sock *sk)
{
	int ret;

	ret = __sock_charge(sk, UB_NUMTCPSOCK);
	ub_update_rmem_thres(sock_bc(sk));

	return ret;
}

int ub_other_sock_charge(struct sock *sk)
{
	return __sock_charge(sk, UB_NUMOTHERSOCK);
}

EXPORT_SYMBOL(ub_other_sock_charge);

int ub_sock_charge(struct sock *sk, int family, int type)
{
	return (IS_TCP_SOCK(family, type) ?
			ub_tcp_sock_charge(sk) : ub_other_sock_charge(sk));
}

EXPORT_SYMBOL(ub_sock_charge);

/*
 * Uncharge socket number
 */

void ub_sock_uncharge(struct sock *sk)
{
	int is_tcp_sock;
	unsigned long flags;
	struct sock_beancounter *skbc;
	struct user_beancounter *ub;
	unsigned long reserv, forw;

	if (unlikely(!sock_has_ubc(sk)))
		return;

	is_tcp_sock = IS_TCP_SOCK(sk->sk_family, sk->sk_type);
	skbc = sock_bc(sk);
	ub_debug(UBD_NET_SOCKET, "Calling ub_sock_uncharge on %p\n", sk);

	ub = skbc->ub;

	spin_lock_irqsave(&ub->ub_lock, flags);
	if (!list_empty(&skbc->ub_sock_list)) {
		ub_debug(UBD_NET_SOCKET,
			 "ub_sock_uncharge: removing from ub(%p) queue.\n",
			 skbc);
		list_del_init(&skbc->ub_sock_list);
	}

	reserv = skbc->poll_reserv;
	forw = skbc->forw_space;
	__uncharge_beancounter_locked(ub,
			(is_tcp_sock ? UB_TCPSNDBUF : UB_OTHERSOCKBUF),
			reserv);
	if (forw)
		__uncharge_beancounter_locked(ub,
				(is_tcp_sock ? UB_TCPRCVBUF : UB_DGRAMRCVBUF),
				forw);
	__uncharge_beancounter_locked(ub,
			(is_tcp_sock ? UB_NUMTCPSOCK : UB_NUMOTHERSOCK), 1);

	ub_sock_wcharge_dec(sk, reserv);
	if (unlikely(skbc->ub_wcharged))
		printk(KERN_WARNING
		       "ub_sock_uncharge: wch=%lu for ub %p (%s).\n",
		       skbc->ub_wcharged, ub, ub->ub_name);
	skbc->poll_reserv = 0;
	skbc->forw_space = 0;
	spin_unlock_irqrestore(&ub->ub_lock, flags);

	put_beancounter(ub);
	sk_free_beancounter(sk);
}

/*
 * Special case for netlink_dump - (un)charges precalculated size
 */

int ub_nlrcvbuf_charge(struct sk_buff *skb, struct sock *sk)
{
	int ret;
	unsigned long chargesize;

	if (unlikely(!sock_has_ubc(sk)))
		return 0;

	chargesize = skb_charge_fullsize(skb);
	ret = charge_beancounter(sock_bc(sk)->ub,
			UB_OTHERSOCKBUF, chargesize, UB_HARD);
	if (ret < 0)
		return ret;
	ub_skb_set_charge(skb, sk, chargesize, UB_OTHERSOCKBUF);
	return ret;
}

/*
 * Poll reserve accounting
 *
 * This is the core of socket buffer management (along with queueing/wakeup
 * functions.  The rest of buffer accounting either call these functions, or
 * repeat parts of their logic for some simpler cases.
 */

static int ub_sock_makewreserv_locked(struct sock *sk,
		int bufid, unsigned long size)
{
	unsigned long wcharge_added;
	struct sock_beancounter *skbc;
	struct user_beancounter *ub;

	skbc = sock_bc(sk);
	if (skbc->poll_reserv >= size) /* no work to be done */
		goto out;

	ub = skbc->ub;
	ub->ub_parms[bufid].held += size - skbc->poll_reserv;

	wcharge_added = 0;
	/*
	 * Logic:
	 *  1) when used memory hits barrier, we set wmem_pressure;
	 *     wmem_pressure is reset under barrier/2;
	 *     between barrier/2 and barrier we limit per-socket buffer growth;
	 *  2) each socket is guaranteed to get (limit-barrier)/maxsockets
	 *     calculated on the base of memory eaten after the barrier is hit
	 */
	skbc = sock_bc(sk);
#if UB_SOCK_MAINTAIN_WMEMPRESSURE
	if (!ub_hfbarrier_hit(ub, bufid)) {
		if (ub->ub_wmem_pressure)
			ub_debug(UBD_NET_SEND, "makewres: pressure -> 0 "
				"sk %p sz %lu pr %lu hd %lu wc %lu sb %d.\n",
				sk, size, skbc->poll_reserv,
				ub->ub_parms[bufid].held,
				skbc->ub_wcharged, sk->sk_sndbuf);
		ub->ub_wmem_pressure = 0;
	}
#endif
	if (ub_barrier_hit(ub, bufid)) {
#if UB_SOCK_MAINTAIN_WMEMPRESSURE
		if (!ub->ub_wmem_pressure)
			ub_debug(UBD_NET_SEND, "makewres: pressure -> 1 "
				"sk %p sz %lu pr %lu hd %lu wc %lu sb %d.\n",
				sk, size, skbc->poll_reserv,
				ub->ub_parms[bufid].held,
				skbc->ub_wcharged, sk->sk_sndbuf);
		ub->ub_wmem_pressure = 1;
#endif
		if (sk->sk_family == PF_NETLINK)
			goto unroll;
		wcharge_added = size - skbc->poll_reserv;
		skbc->ub_wcharged += wcharge_added;
		if (skbc->ub_wcharged * ub->ub_parms[bid2sid(bufid)].limit +
				ub->ub_parms[bufid].barrier >
					ub->ub_parms[bufid].limit)
			goto unroll_wch;
	}
	if (ub->ub_parms[bufid].held > ub->ub_parms[bufid].limit)
		goto unroll;

	ub_adjust_maxheld(ub, bufid);
	skbc->poll_reserv = size;
out:
	return 0;

unroll_wch:
	skbc->ub_wcharged -= wcharge_added;
unroll:
	ub_debug(UBD_NET_SEND,
			"makewres: deny "
			"sk %p sz %lu pr %lu hd %lu wc %lu sb %d.\n",
			sk, size, skbc->poll_reserv, ub->ub_parms[bufid].held,
			skbc->ub_wcharged, sk->sk_sndbuf);
	ub->ub_parms[bufid].failcnt++;
	ub->ub_parms[bufid].held -= size - skbc->poll_reserv;

	if (sk->sk_socket != NULL) {
		set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);
		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
	}
	return -ENOMEM;
}

int ub_sock_make_wreserv(struct sock *sk, int bufid, unsigned long size)
{
	struct sock_beancounter *skbc;
	unsigned long flags;
	int err;

	skbc = sock_bc(sk);

	/*
	 * This function provides that there is sufficient reserve upon return
	 * only if sk has only one user.  We can check poll_reserv without
	 * serialization and avoid locking if the reserve already exists.
	 */
	if (unlikely(!sock_has_ubc(sk)) || likely(skbc->poll_reserv >= size))
		return 0;

	spin_lock_irqsave(&skbc->ub->ub_lock, flags);
	err = ub_sock_makewreserv_locked(sk, bufid, size);
	spin_unlock_irqrestore(&skbc->ub->ub_lock, flags);

	return err;
}

EXPORT_SYMBOL(ub_sock_make_wreserv);

int ub_sock_get_wreserv(struct sock *sk, int bufid, unsigned long size)
{
	struct sock_beancounter *skbc;

	if (unlikely(!sock_has_ubc(sk)))
		return 0;

	/* optimize for the case if socket has sufficient reserve */
	ub_sock_make_wreserv(sk, bufid, size);
	skbc = sock_bc(sk);
	if (likely(skbc->poll_reserv >= size)) {
		skbc->poll_reserv -= size;
		return 0;
	}
	return -ENOMEM;
}

EXPORT_SYMBOL(ub_sock_get_wreserv);

static void ub_sock_do_ret_wreserv(struct sock *sk, int bufid,
		unsigned long size, unsigned long ressize)
{
	struct sock_beancounter *skbc;
	struct user_beancounter *ub;
	unsigned long extra;
	unsigned long flags;

	skbc = sock_bc(sk);
	ub = skbc->ub;

	extra = 0;
	spin_lock_irqsave(&ub->ub_lock, flags);
	skbc->poll_reserv += size;
	if (skbc->poll_reserv > ressize) {
		extra = skbc->poll_reserv - ressize;
		ub_sock_wcharge_dec(sk, extra);
		skbc->poll_reserv = ressize;

		__uncharge_beancounter_locked(ub, bufid, extra);
		if (bufid == UB_TCPSNDBUF)
			ub_tcp_snd_wakeup(ub);
		else
			ub_sock_snd_wakeup(ub);
	}
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

void ub_sock_ret_wreserv(struct sock *sk, int bufid,
		unsigned long size, unsigned long ressize)
{
	struct sock_beancounter *skbc;

	if (unlikely(!sock_has_ubc(sk)))
		return;

	skbc = sock_bc(sk);
	/* check if the reserve can be kept */
	if (ub_barrier_farsz(skbc->ub, bufid)) {
		skbc->poll_reserv += size;
		return;
	}
	ub_sock_do_ret_wreserv(sk, bufid, size, ressize);
}

/*
 * UB_DGRAMRCVBUF
 */

static int ub_dgramrcvbuf_charge(struct sock *sk, struct sk_buff *skb)
{
	unsigned long chargesize;

	chargesize = skb_charge_fullsize(skb);
	if (charge_beancounter(sock_bc(sk)->ub, UB_DGRAMRCVBUF,
				 chargesize, UB_HARD))
		return -ENOMEM;

	ub_skb_set_charge(skb, sk, chargesize, UB_DGRAMRCVBUF);
	return 0;
}

int ub_sockrcvbuf_charge(struct sock *sk, struct sk_buff *skb)
{
	if (unlikely(!sock_has_ubc(sk)))
		return 0;

	if (IS_TCP_SOCK(sk->sk_family, sk->sk_type))
		return ub_tcprcvbuf_charge(sk, skb);
	else
		return ub_dgramrcvbuf_charge(sk, skb);
}

EXPORT_SYMBOL(ub_sockrcvbuf_charge);

static void ub_sockrcvbuf_uncharge(struct sk_buff *skb)
{
	uncharge_beancounter(skb_bc(skb)->ub, UB_DGRAMRCVBUF,
			     skb_bc(skb)->charged);
	ub_skb_set_uncharge(skb);
}

/*
 * UB_TCPRCVBUF
 */

int ub_sock_tcp_chargerecv(struct sock *sk, struct sk_buff *skb,
			    enum ub_severity strict)
{
	int retval;
	unsigned long flags;
	struct user_beancounter *ub;
	struct sock_beancounter *skbc;
	unsigned long chargesize;

	if (unlikely(!sock_has_ubc(sk)))
		return 0;
	skbc = sock_bc(sk);

	chargesize = skb_charge_fullsize(skb);
	if (likely(skbc->forw_space >= chargesize)) {
		skbc->forw_space -= chargesize;
		__ub_skb_set_charge(skb, sk, chargesize, UB_TCPRCVBUF);
		return 0;
	}

	/*
	 * Memory pressure reactions:
	 *  1) set UB_RMEM_KEEP (clearing UB_RMEM_EXPAND)
	 *  2) set UB_RMEM_SHRINK and tcp_clamp_window()
	 *     tcp_collapse_queues() if rmem_alloc > rcvbuf
	 *  3) drop OFO, tcp_purge_ofo()
	 *  4) drop all.
	 * Currently, we do #2 and #3 at once (which means that current
	 * collapsing of OFO queue in tcp_collapse_queues() is a waste of time,
	 * for example...)
	 * On memory pressure we jump from #0 to #3, and when the pressure
	 * subsides, to #1.
	 */
	retval = 0;
	ub = sock_bc(sk)->ub;
	spin_lock_irqsave(&ub->ub_lock, flags);
	ub->ub_parms[UB_TCPRCVBUF].held += chargesize;
	if (ub->ub_parms[UB_TCPRCVBUF].held >
			ub->ub_parms[UB_TCPRCVBUF].barrier &&
			strict != UB_FORCE)
		goto excess;
	ub_adjust_maxheld(ub, UB_TCPRCVBUF);
	spin_unlock_irqrestore(&ub->ub_lock, flags);

out:
	if (retval == 0)
		ub_skb_set_charge(skb, sk, chargesize, UB_TCPRCVBUF);
	return retval;

excess:
	ub->ub_rmem_pressure = UB_RMEM_SHRINK;
	if (strict == UB_HARD)
		retval = -ENOMEM;
	if (ub->ub_parms[UB_TCPRCVBUF].held > ub->ub_parms[UB_TCPRCVBUF].limit)
		retval = -ENOMEM;
	/*
	 * We try to leave numsock*maxadvmss as a reserve for sockets not
	 * queueing any data yet (if the difference between the barrier and the
	 * limit is enough for this reserve).
	 */
	if (ub->ub_parms[UB_TCPRCVBUF].held +
			ub->ub_parms[UB_NUMTCPSOCK].limit * ub->ub_maxadvmss
			> ub->ub_parms[UB_TCPRCVBUF].limit &&
			atomic_read(&sk->sk_rmem_alloc))
		retval = -ENOMEM;
	if (retval) {
		ub->ub_parms[UB_TCPRCVBUF].held -= chargesize;
		ub->ub_parms[UB_TCPRCVBUF].failcnt++;
	}
	ub_adjust_maxheld(ub, UB_TCPRCVBUF);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
	goto out;
}
EXPORT_SYMBOL(ub_sock_tcp_chargerecv);

static void ub_tcprcvbuf_uncharge(struct sk_buff *skb)
{
	unsigned long flags;
	unsigned long held, bar;
	int prev_pres;
	struct user_beancounter *ub;

	ub = skb_bc(skb)->ub;
	if (ub_barrier_farsz(ub, UB_TCPRCVBUF)) {
		sock_bc(skb->sk)->forw_space += skb_bc(skb)->charged;
		ub_skb_set_uncharge(skb);
		return;
	}

	spin_lock_irqsave(&ub->ub_lock, flags);
	if (ub->ub_parms[UB_TCPRCVBUF].held < skb_bc(skb)->charged) {
		printk(KERN_ERR "Uncharging %d for tcprcvbuf of %p with %lu\n",
				skb_bc(skb)->charged,
				ub, ub->ub_parms[UB_TCPRCVBUF].held);
		/* ass-saving bung */
		skb_bc(skb)->charged = ub->ub_parms[UB_TCPRCVBUF].held;
	}
	ub->ub_parms[UB_TCPRCVBUF].held -= skb_bc(skb)->charged;
	held = ub->ub_parms[UB_TCPRCVBUF].held;
	bar = ub->ub_parms[UB_TCPRCVBUF].barrier;
	prev_pres = ub->ub_rmem_pressure;
	if (held <= bar - (bar >> 2))
		ub->ub_rmem_pressure = UB_RMEM_EXPAND;
	else if (held <= bar)
		ub->ub_rmem_pressure = UB_RMEM_KEEP;
	spin_unlock_irqrestore(&ub->ub_lock, flags);

	ub_skb_set_uncharge(skb);
}


/*
 * UB_OTHERSOCKBUF and UB_TCPSNDBUF
 */

static void ub_socksndbuf_uncharge(struct sk_buff *skb)
{
	unsigned long flags;
	struct user_beancounter *ub;
	unsigned long chargesize;

	ub = skb_bc(skb)->ub;
	chargesize = skb_bc(skb)->charged;

	spin_lock_irqsave(&ub->ub_lock, flags);
	__uncharge_beancounter_locked(ub, UB_OTHERSOCKBUF, chargesize);
	if (skb->sk != NULL && sock_has_ubc(skb->sk))
		ub_sock_wcharge_dec(skb->sk, chargesize);
	ub_sock_snd_wakeup(ub);
	spin_unlock_irqrestore(&ub->ub_lock, flags);

	ub_skb_set_uncharge(skb);
}

/* expected to be called under socket lock */
static void ub_tcpsndbuf_uncharge(struct sk_buff *skb)
{
	if (WARN_ON(!skb->sk))
		return;
	/*
	 * ub_sock_ret_wreserv call is abused here, we just want to uncharge
	 * skb size.  However, to reduce duplication of the code doing
	 * ub_hfbarrier_hit check, ub_wcharged reduction, and wakeup we call
	 * a function that already does all of this.  2006/04/27  SAW
	 */
	ub_sock_ret_wreserv(skb->sk, UB_TCPSNDBUF, skb_bc(skb)->charged,
			sock_bc(skb->sk)->poll_reserv);
	ub_skb_set_uncharge(skb);
}

void ub_skb_uncharge(struct sk_buff *skb)
{
	switch (skb_bc(skb)->resource) {
		case UB_TCPSNDBUF:
			ub_tcpsndbuf_uncharge(skb);
			break;
		case UB_TCPRCVBUF:
			ub_tcprcvbuf_uncharge(skb);
			break;
		case UB_DGRAMRCVBUF:
			ub_sockrcvbuf_uncharge(skb);
			break;
		case UB_OTHERSOCKBUF:
			ub_socksndbuf_uncharge(skb);
			break;
	}
}

EXPORT_SYMBOL(ub_skb_uncharge);	/* due to skb_orphan()/conntracks */

/*
 * Other sock reserve managment
 */

int ub_sock_getwres_other(struct sock *sk, unsigned long size)
{
	struct sock_beancounter *skbc;
	struct user_beancounter *ub;
	unsigned long flags;
	int err;

	if (unlikely(!sock_has_ubc(sk)))
		return 0;

	/*
	 * Nothing except beancounter lock protects skbc->poll_reserv.
	 * So, take the lock and do the job.
	 */
	skbc = sock_bc(sk);
	ub = skbc->ub;
	spin_lock_irqsave(&ub->ub_lock, flags);
	err = ub_sock_makewreserv_locked(sk, UB_OTHERSOCKBUF, size);
	if (!err)
		skbc->poll_reserv -= size;
	spin_unlock_irqrestore(&ub->ub_lock, flags);

	return err;
}
EXPORT_SYMBOL(ub_sock_getwres_other);

void ub_sock_retwres_other(struct sock *sk,
		unsigned long size, unsigned long ressize)
{
	if (unlikely(!sock_has_ubc(sk)))
		return;

	ub_sock_do_ret_wreserv(sk, UB_OTHERSOCKBUF, size, ressize);
}

/*
 * TCP send buffers accouting. Paged part
 */

int ub_sock_tcp_chargepage(struct sock *sk)
{
	struct sock_beancounter *skbc;
	unsigned long extra;
	int err;

	if (unlikely(!sock_has_ubc(sk)))
		return 0;

	skbc = sock_bc(sk);
	ub_sock_make_wreserv(sk, UB_TCPSNDBUF, PAGE_SIZE);
	if (likely(skbc->poll_reserv >= PAGE_SIZE)) {
		skbc->poll_reserv -= PAGE_SIZE;
		return 0;
	}

	/*
	 * Ok, full page is not available.
	 * However, this function must succeed if poll previously indicated
	 * that write is possible.  We better make a forced charge here
	 * than reserve a whole page in poll.
	 */
	err = ub_sock_make_wreserv(sk, UB_TCPSNDBUF, SOCK_MIN_UBCSPACE);
	if (unlikely(err < 0))
		goto out;
	if (skbc->poll_reserv < PAGE_SIZE) {
		extra = PAGE_SIZE - skbc->poll_reserv;
		err = charge_beancounter(skbc->ub, UB_TCPSNDBUF, extra,
				UB_FORCE);
		if (err < 0)
			goto out;
		skbc->poll_reserv += extra;
	}
	skbc->poll_reserv -= PAGE_SIZE;
	return 0;

out:
	return err;
}

void ub_sock_tcp_detachpage(struct sock *sk)
{
	struct sk_buff *skb;

	if (unlikely(!sock_has_ubc(sk)))
		return;

	/* The page is just detached from socket. The last skb in queue
	   with paged part holds referrence to it */
	skb = skb_peek_tail(&sk->sk_write_queue);
	if (skb == NULL) {
	   	/* If the queue is empty - all data is sent and page is about
		   to be freed */
		ub_sock_ret_wreserv(sk, UB_TCPSNDBUF, PAGE_SIZE,
				sock_bc(sk)->poll_reserv);
	} else {
		/* Last skb is a good aproximation for a last skb with
		   paged part */
		skb_bc(skb)->charged += PAGE_SIZE;
	}
}

/*
 * TCPSNDBUF charge functions below are called in the following cases:
 *  - sending of SYN, SYN-ACK, FIN, the latter charge is forced by
 *    some technical reasons in TCP code;
 *  - fragmentation of TCP packets.
 * These functions are allowed but not required to use poll_reserv.
 * Originally, these functions didn't do that, since it didn't make
 * any sense.  Now, since poll_reserv now has a function of general reserve,
 * they use it.
 */
int ub_sock_tcp_chargesend(struct sock *sk, struct sk_buff *skb,
			    enum ub_severity strict)
{
	int ret;
	unsigned long chargesize;
	struct sock_beancounter *skbc;
	struct user_beancounter *ub;
	unsigned long flags;

	if (unlikely(!sock_has_ubc(sk)))
		return 0;

	skbc = sock_bc(sk);
	chargesize = skb_charge_fullsize(skb);
	if (likely(skbc->poll_reserv >= chargesize)) {
		skbc->poll_reserv -= chargesize;
		__ub_skb_set_charge(skb, sk, chargesize, UB_TCPSNDBUF);
		/* XXX hack, see ub_skb_set_charge */
		skb->sk = sk;
		return 0;
	}

	ub = skbc->ub;
	spin_lock_irqsave(&ub->ub_lock, flags);
	ret = __charge_beancounter_locked(ub, UB_TCPSNDBUF,
			chargesize, strict);
	/*
	 * Note: this check is not equivalent of the corresponding check
	 * in makewreserv.  It's similar in spirit, but an equivalent check
	 * would be too long and complicated here.
	 */
	if (!ret && ub_barrier_hit(ub, UB_TCPSNDBUF))
		skbc->ub_wcharged += chargesize;
	spin_unlock_irqrestore(&ub->ub_lock, flags);
	if (likely(!ret))
		ub_skb_set_charge(skb, sk, chargesize, UB_TCPSNDBUF);
	return ret;
}
EXPORT_SYMBOL(ub_sock_tcp_chargesend);

/*
 * Initialization
 */

int __init skbc_cache_init(void)
{
	return 0;
}
