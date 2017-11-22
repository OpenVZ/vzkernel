/*
 *  include/linux/veip.h
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef __VE_IP_H_
#define __VE_IP_H_

#include <linux/list.h>

struct veip_struct
{
	struct list_head	src_lh;
	struct list_head	dst_lh;
	struct list_head	ip_lh;
	struct list_head	list;
	struct list_head	ext_lh;
	envid_t			veid;
	struct rcu_head		rcu;
};

struct ve_addr_struct {
	int family;
	__u32 key[4];
};

struct sockaddr;

extern void veaddr_print(char *, int, struct ve_addr_struct *);
extern int sockaddr_to_veaddr(struct sockaddr __user *uaddr, int addrlen,
		struct ve_addr_struct *veaddr);

#endif
