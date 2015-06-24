/*
 * include/linux/vznetstat.h
 *
 * Copyright (c) 2015 Parallels IP Holdings GmbH
 *
 */

#ifndef _VZNETSTAT_H
#define _VZNETSTAT_H

#include <linux/list.h>
#include <linux/spinlock.h>

#define TC_CLASS_MAX	16

struct acct_counter {
	u64	bytes;
	u32	pkts;
	u32	__pad;
};

enum {
	ACCT_IN,
	ACCT_OUT,
	ACCT_MAX
};

struct acct_stat {
	struct acct_counter cnt[TC_CLASS_MAX][ACCT_MAX];
};

struct venet_stat {
	struct list_head list;
	envid_t  veid;
	u16 base;
	unsigned long flags;
	atomic_t users;

	struct acct_stat __percpu *ipv4_stat;
	struct acct_stat __percpu *ipv6_stat;
};

static inline int venet_acct_skb_size(struct sk_buff *skb)
{
	return skb->data_len + (skb->tail - skb->network_header);
}

struct ve_addr_struct;

#if IS_ENABLED(CONFIG_VE_NETDEV_ACCOUNTING)
struct venet_stat *venet_acct_find_stat(envid_t veid);
struct venet_stat *venet_acct_find_create_stat(envid_t veid);
static inline void venet_acct_get_stat(struct venet_stat *stat)
{
	atomic_inc(&stat->users);
}
void   venet_acct_put_stat(struct venet_stat *);

void venet_acct_classify_add_incoming(struct venet_stat *, struct sk_buff *skb);
void venet_acct_classify_add_outgoing(struct venet_stat *, struct sk_buff *skb);
void venet_acct_classify_sub_outgoing(struct venet_stat *, struct sk_buff *skb);

void venet_acct_classify_add_incoming_plain(struct venet_stat *stat,
		struct ve_addr_struct *src_addr, int data_size);
void venet_acct_classify_add_outgoing_plain(struct venet_stat *stat,
		struct ve_addr_struct *dst_addr, int data_size);

#else /* !CONFIG_VE_NETDEV_ACCOUNTING */
static inline void venet_acct_get_stat(struct venet_stat *stat) { }
static inline void venet_acct_put_stat(struct venet_stat *stat) { }

static inline void venet_acct_classify_add_incoming(struct venet_stat *stat,
						struct sk_buff *skb) {}
static inline void venet_acct_classify_add_outgoing(struct venet_stat *stat,
						struct sk_buff *skb) {}
static inline void venet_acct_classify_sub_outgoing(struct venet_stat *stat,
						struct sk_buff *skb) {}

static inline void venet_acct_classify_add_incoming_plain(struct venet_stat *stat,
		struct ve_addr_struct *src_addr, int data_size) {}
static inline void venet_acct_classify_add_outgoing_plain(struct venet_stat *stat,
		struct ve_addr_struct *dst_addr, int data_size) {}
#endif /* CONFIG_VE_NETDEV_ACCOUNTING */

#endif
