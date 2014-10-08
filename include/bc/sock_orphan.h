/*
 *  include/bc/sock_orphan.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __BC_SOCK_ORPHAN_H_
#define __BC_SOCK_ORPHAN_H_

#include <net/tcp.h>

#include "bc/beancounter.h"
#include "bc/net.h"


static inline struct percpu_counter *__ub_get_orphan_count_ptr(struct sock *sk)
{
	if (sock_has_ubc(sk))
		return &sock_bc(sk)->ub->ub_orphan_count;
	return sk->sk_prot->orphan_count;
}

static inline void ub_inc_orphan_count(struct sock *sk)
{
	percpu_counter_inc(__ub_get_orphan_count_ptr(sk));
}

static inline void ub_dec_orphan_count(struct sock *sk)
{
	percpu_counter_dec(__ub_get_orphan_count_ptr(sk));
}

static inline int ub_get_orphan_count(struct sock *sk)
{
	return percpu_counter_sum_positive(__ub_get_orphan_count_ptr(sk));
}

static inline int ub_too_many_orphans(struct sock *sk, int count)
{
#ifdef CONFIG_BEANCOUNTERS
	if (__ub_too_many_orphans(sk, count))
		return 1;
#endif
	return (ub_get_orphan_count(sk) > sysctl_tcp_max_orphans ||
		(sk->sk_wmem_queued > SOCK_MIN_SNDBUF &&
		 atomic_long_read(&tcp_memory_allocated) > sysctl_tcp_mem[2]));
}

struct inet_timewait_sock;

static inline void ub_timewait_mod(struct inet_timewait_sock *tw, int incdec)
{
#ifdef CONFIG_BEANCOUNTERS
	tw->tw_ub->ub_tw_count += incdec;
#endif
}

static inline int __ub_timewait_check(struct sock *sk)
{
#ifdef CONFIG_BEANCOUNTERS
	struct user_beancounter *ub;
	unsigned long mem_max, mem;
	int tw_count;

	ub = sock_bc(sk)->ub;
	if (ub == NULL)
		return 1;

	tw_count = ub->ub_tw_count;
	mem_max = sysctl_tcp_max_tw_kmem_fraction *
		((ub->ub_parms[UB_KMEMSIZE].limit >> 10) + 1);
	mem = sk->sk_prot_creator->twsk_prot->twsk_obj_size;
	mem *= tw_count;
	return tw_count < sysctl_tcp_max_tw_buckets_ub && mem < mem_max;
#else
	return 1;
#endif
}

#define ub_timewait_inc(tw, twdr) do {			\
		if ((twdr)->ub_managed)			\
			ub_timewait_mod(tw, 1);		\
	} while (0)

#define ub_timewait_dec(tw, twdr) do {			\
		if ((twdr)->ub_managed)			\
			ub_timewait_mod(tw, -1);	\
	} while (0)

#define ub_timewait_check(sk, twdr) ((!(twdr)->ub_managed) || \
					__ub_timewait_check(sk))

#endif
