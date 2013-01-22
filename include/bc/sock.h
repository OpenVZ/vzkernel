/*
 *  include/bc/sock.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __BC_SOCK_H_
#define __BC_SOCK_H_

#include <bc/task.h>

struct sock;
struct sk_buff;

struct skb_beancounter {
	struct user_beancounter *ub;
	unsigned long charged:27, resource:5;
};

struct sock_beancounter {
	struct user_beancounter *ub;
	/*
	 * poll_reserv accounts space already charged for future sends.
	 * It is required to make poll agree with sendmsg.
	 * Additionally, it makes real charges (with taking bc spinlock)
	 * in the send path rarer, speeding networking up.
	 * For TCP (only): changes are protected by socket lock (not bc!)
	 * For all proto: may be read without serialization in poll.
	 */
	unsigned long           poll_reserv;
	unsigned long		forw_space;
	/* fields below are protected by bc spinlock */
	unsigned long           ub_waitspc;     /* space waiting for */
	unsigned long           ub_wcharged;
	struct list_head        ub_sock_list;
};

#define sock_bc(__sk)		(&(__sk)->sk_bc)
#define skb_bc(__skb)		(&(__skb)->skb_bc)
#define skbc_sock(__skbc)	(container_of(__skbc, struct sock, sk_bc))
#define sock_has_ubc(__sk)	(sock_bc(__sk)->ub != NULL)

#endif
