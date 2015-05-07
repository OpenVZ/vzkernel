/*
 *  include/bc/net.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __BC_NET_H_
#define __BC_NET_H_

/*
 * UB_NUMXXXSOCK, UB_XXXBUF accounting
 */

#include <bc/sock.h>
#include <bc/beancounter.h>

#ifdef CONFIG_BEANCOUNTERS
#undef CONFIG_BEANCOUNTERS
#define CONFIG_BEANCOUNTERS_WILL_BE_BACK
#endif
#undef __BC_DECL_H_
#undef UB_DECLARE_FUNC
#undef UB_DECLARE_VOID_FUNC
#include <bc/decl.h>

#define bid2sid(__bufid) \
	((__bufid) == UB_TCPSNDBUF ? UB_NUMTCPSOCK : UB_NUMOTHERSOCK)

#define SOCK_MIN_UBCSPACE ((int)((2048 - sizeof(struct skb_shared_info)) & \
			~(SMP_CACHE_BYTES-1)))
#define SOCK_MIN_UBCSPACE_CH skb_charge_size(SOCK_MIN_UBCSPACE)

static inline int ub_skb_alloc_bc(struct sk_buff *skb, gfp_t gfp_mask)
{
#ifdef CONFIG_BEANCOUNTERS
	memset(skb_bc(skb), 0, sizeof(struct skb_beancounter));
#endif
	return 0;
}

static inline void ub_skb_free_bc(struct sk_buff *skb)
{
}

#define IS_TCP_SOCK(__family, __type) \
		(((__family) == PF_INET || (__family) == PF_INET6) && (__type) == SOCK_STREAM)

/* number of sockets */
UB_DECLARE_FUNC(int, ub_sock_charge(struct sock *sk, int family, int type))
UB_DECLARE_FUNC(int, ub_tcp_sock_charge(struct sock *sk)) 
UB_DECLARE_FUNC(int, ub_other_sock_charge(struct sock *sk))
UB_DECLARE_VOID_FUNC(ub_sock_uncharge(struct sock *sk))

/* management of queue for send space */
UB_DECLARE_FUNC(long, ub_sock_wait_for_space(struct sock *sk, long timeo, 
			unsigned long size))
UB_DECLARE_FUNC(int, ub_sock_snd_queue_add(struct sock *sk, int resource, 
			unsigned long size))
UB_DECLARE_VOID_FUNC(ub_sock_sndqueuedel(struct sock *sk))

/* send space */
UB_DECLARE_FUNC(int, ub_sock_make_wreserv(struct sock *sk, int bufid,
			unsigned long size))
UB_DECLARE_FUNC(int, ub_sock_get_wreserv(struct sock *sk, int bufid,
			unsigned long size))
UB_DECLARE_VOID_FUNC(ub_sock_ret_wreserv(struct sock *sk, int bufid,
			unsigned long size, unsigned long ressize))
UB_DECLARE_FUNC(int, ub_sock_tcp_chargesend(struct sock *sk,
			struct sk_buff *skb, enum ub_severity strict))
UB_DECLARE_FUNC(int, ub_sock_tcp_chargepage(struct sock *sk))
UB_DECLARE_VOID_FUNC(ub_sock_tcp_detachpage(struct sock *sk))

UB_DECLARE_FUNC(int, ub_nlrcvbuf_charge(struct sk_buff *skb, struct sock *sk))

/* receive space */
UB_DECLARE_FUNC(int, ub_sockrcvbuf_charge(struct sock *sk, struct sk_buff *skb))
UB_DECLARE_FUNC(int, ub_sock_tcp_chargerecv(struct sock *sk,
			struct sk_buff *skb, enum ub_severity strict))

/* skb destructor */
UB_DECLARE_VOID_FUNC(ub_skb_uncharge(struct sk_buff *skb))

static inline int ub_sock_makewres_other(struct sock *sk, unsigned long size)
{
	return ub_sock_make_wreserv(sk, UB_OTHERSOCKBUF, size);
}

static inline int ub_sock_makewres_tcp(struct sock *sk, unsigned long size)
{
	return ub_sock_make_wreserv(sk, UB_TCPSNDBUF, size);
}

UB_DECLARE_FUNC(int, ub_sock_getwres_other(struct sock *sk,
			unsigned long size))

static inline int ub_sock_getwres_tcp(struct sock *sk, unsigned long size)
{
	return ub_sock_get_wreserv(sk, UB_TCPSNDBUF, size);
}

UB_DECLARE_VOID_FUNC(ub_sock_retwres_other(struct sock *sk,
			unsigned long size, unsigned long ressize))

static inline void ub_sock_retwres_tcp(struct sock *sk, unsigned long size,
		unsigned long ressize)
{
	ub_sock_ret_wreserv(sk, UB_TCPSNDBUF, size, ressize);
}

static inline int ub_sock_sndqueueadd_other(struct sock *sk, unsigned long sz)
{
	return ub_sock_snd_queue_add(sk, UB_OTHERSOCKBUF, sz);
}

static inline int ub_sock_sndqueueadd_tcp(struct sock *sk, unsigned long sz)
{
	return ub_sock_snd_queue_add(sk, UB_TCPSNDBUF, sz);
}

static inline int ub_tcpsndbuf_charge(struct sock *sk,
		struct sk_buff *skb)
{
	return ub_sock_tcp_chargesend(sk, skb, UB_HARD);
}

static inline int ub_tcpsndbuf_charge_forced(struct sock *sk,
		struct sk_buff *skb)
{
	return ub_sock_tcp_chargesend(sk, skb, UB_FORCE);
}

static inline int ub_tcprcvbuf_charge(struct sock *sk, struct sk_buff *skb)
{
	return ub_sock_tcp_chargerecv(sk, skb, UB_SOFT);
}

static inline int ub_tcprcvbuf_charge_forced(struct sock *sk,
		struct sk_buff *skb)
{
	return ub_sock_tcp_chargerecv(sk, skb, UB_FORCE);
}

/* Charge size */
static inline unsigned long skb_charge_datalen(unsigned long chargesize)
{
#ifdef CONFIG_BEANCOUNTERS
	unsigned long slabsize;

	chargesize -= sizeof(struct sk_buff);
	slabsize = 64;
	do { 
		slabsize <<= 1; 
	} while (slabsize <= chargesize);

	slabsize >>= 1;
	return (slabsize - sizeof(struct skb_shared_info)) &
		~(SMP_CACHE_BYTES-1);
#else
	return 0;
#endif
}

static inline unsigned long skb_charge_size_gen(unsigned long size)
{ 
#ifdef CONFIG_BEANCOUNTERS
	unsigned long slabsize;

	size = SKB_DATA_ALIGN(size) + sizeof(struct skb_shared_info);
	slabsize = roundup_pow_of_two(size);

	return slabsize + sizeof(struct sk_buff);
#else
	return 0;
#endif

}
	
static inline unsigned long skb_charge_size_const(unsigned long size)
{
#ifdef CONFIG_BEANCOUNTERS
	unsigned int ret;
	if (SKB_DATA_ALIGN(size) + sizeof(struct skb_shared_info) <= 64)
		ret = 64 + sizeof(struct sk_buff);
	else if (SKB_DATA_ALIGN(size) + sizeof(struct skb_shared_info) <= 128)
		ret = 128 + sizeof(struct sk_buff);
	else if (SKB_DATA_ALIGN(size) + sizeof(struct skb_shared_info) <= 256)
		ret = 256 + sizeof(struct sk_buff);
	else if (SKB_DATA_ALIGN(size) + sizeof(struct skb_shared_info) <= 512)
		ret = 512 + sizeof(struct sk_buff);
	else if (SKB_DATA_ALIGN(size) + sizeof(struct skb_shared_info) <= 1024)
		ret = 1024 + sizeof(struct sk_buff);
	else if (SKB_DATA_ALIGN(size) + sizeof(struct skb_shared_info) <= 2048)
		ret = 2048 + sizeof(struct sk_buff);
	else if (SKB_DATA_ALIGN(size) + sizeof(struct skb_shared_info) <= 4096)
		ret = 4096 + sizeof(struct sk_buff);
	else
		ret = skb_charge_size_gen(size);
	return ret;
#else
	return 0;
#endif
}


#define skb_charge_size(__size)			\
	(__builtin_constant_p(__size)	?	\
	 skb_charge_size_const(__size)	:	\
	 skb_charge_size_gen(__size))

UB_DECLARE_FUNC(int, skb_charge_fullsize(struct sk_buff *skb))
UB_DECLARE_VOID_FUNC(ub_skb_set_charge(struct sk_buff *skb, 
			struct sock *sk, unsigned long size, int res))
UB_DECLARE_FUNC(int, __ub_too_many_orphans(struct sock *sk, int count))

#ifdef CONFIG_BEANCOUNTERS_WILL_BE_BACK
#define CONFIG_BEANCOUNTERS 1
#undef CONFIG_BEANCOUNTERS_WILL_BE_BACK
#endif
#undef __BC_DECL_H_
#undef UB_DECLARE_FUNC
#undef UB_DECLARE_VOID_FUNC

#endif
