/*
 *  include/bc/tcp.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __BC_TCP_H_
#define __BC_TCP_H_

/*
 * UB_NUMXXXSOCK, UB_XXXBUF accounting
 */

#include <bc/sock.h>
#include <bc/beancounter.h>

static inline void ub_tcp_update_maxadvmss(struct sock *sk)
{
#ifdef CONFIG_BEANCOUNTERS
	if (!sock_has_ubc(sk))
		return;
	if (sock_bc(sk)->ub->ub_maxadvmss >= tcp_sk(sk)->advmss)
		return;

	sock_bc(sk)->ub->ub_maxadvmss =
		skb_charge_size(MAX_HEADER + sizeof(struct iphdr)
				+ sizeof(struct tcphdr)	+ tcp_sk(sk)->advmss);
#endif
}

static inline int ub_tcp_rmem_allows_expand(struct sock *sk)
{
	if (tcp_memory_pressure)
		return 0;
#ifdef CONFIG_BEANCOUNTERS
	if (sock_has_ubc(sk)) {
		struct user_beancounter *ub;

		ub = sock_bc(sk)->ub;
		if (ub->ub_rmem_pressure == UB_RMEM_EXPAND)
			return 1;
		if (ub->ub_rmem_pressure == UB_RMEM_SHRINK)
			return 0;
		return sk->sk_rcvbuf <= ub->ub_rmem_thres;
	}
#endif
	return 1;
}

static inline int ub_tcp_memory_pressure(struct sock *sk)
{
	if (tcp_memory_pressure)
		return 1;
#ifdef CONFIG_BEANCOUNTERS
	if (sock_has_ubc(sk))
		return sock_bc(sk)->ub->ub_rmem_pressure != UB_RMEM_EXPAND;
#endif
	return 0;
}

static inline int ub_tcp_shrink_rcvbuf(struct sock *sk)
{
	if (tcp_memory_pressure)
		return 1;
#ifdef CONFIG_BEANCOUNTERS
	if (sock_has_ubc(sk))
		return sock_bc(sk)->ub->ub_rmem_pressure == UB_RMEM_SHRINK;
#endif
	return 0;
}

#endif
