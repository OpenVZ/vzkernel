/*
 *  include/linux/venet.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef _VENET_H
#define _VENET_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <uapi/linux/vzcalluser.h>
#include <linux/veip.h>
#include <linux/netdevice.h>

#define VEIP_HASH_SZ 512

struct ve_struct;
struct venet_stat;
struct venet_stats {
	struct net_device_stats	stats;
	struct net_device_stats	*real_stats;
};

struct ip_entry_struct
{
	struct ve_addr_struct	addr;
	struct ve_struct	*active_env;
	struct hlist_node 	ip_hash;
	union {
		struct list_head 	ve_list;
		struct rcu_head		rcu;
	};
};

struct ext_entry_struct
{
	struct list_head	list;
	struct ve_addr_struct	addr;
	struct rcu_head		rcu;
};

struct veip_struct
{
	struct list_head	src_lh;
	struct list_head	dst_lh;
	struct list_head	ip_lh;
	struct list_head	list;
	struct list_head	ext_lh;
	envid_t			veid;
	struct venet_stat	*stat;
	struct rcu_head		rcu;
};

struct veip_pool_ops {
	int (*veip_create)(struct ve_struct *);
	void (*veip_release)(struct ve_struct *);
	void (*veip_free)(struct veip_struct *);
	struct ve_struct *(*veip_lookup)(struct ve_struct *, struct sk_buff *);
};

extern struct veip_pool_ops *veip_pool_ops;

static inline struct net_device_stats *
venet_stats(struct net_device *dev, int cpu)
{
	struct venet_stats *stats;
	stats = (struct venet_stats*)dev->ml_priv;
	return per_cpu_ptr(stats->real_stats, cpu);
}

void ip_entry_hash(struct ip_entry_struct *entry, struct veip_struct *veip);
void ip_entry_unhash(struct ip_entry_struct *entry);
void ip_entry_unhash(struct ip_entry_struct *entry);
struct ip_entry_struct *venet_entry_lookup(struct ve_addr_struct *);

struct veip_struct *veip_findcreate(envid_t veid);
int veip_put(struct veip_struct *veip);
void veip_cleanup(void);

int in4_to_veaddr(const char *addr, struct ve_addr_struct *veaddr);
int in6_to_veaddr(const char *addr, struct ve_addr_struct *veaddr);

extern struct list_head veip_lh;

struct ext_entry_struct *venet_ext_lookup(struct ve_struct *ve,
		struct ve_addr_struct *addr);

extern struct hlist_head ip_entry_hash_table[];
extern spinlock_t veip_lock;

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#endif
