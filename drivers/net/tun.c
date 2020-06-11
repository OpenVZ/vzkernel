/*
 *  TUN - Universal TUN/TAP device driver.
 *  Copyright (C) 1999-2002 Maxim Krasnyansky <maxk@qualcomm.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  $Id: tun.c,v 1.15 2002/03/01 02:44:24 maxk Exp $
 */

/*
 *  Changes:
 *
 *  Mike Kershaw <dragorn@kismetwireless.net> 2005/08/14
 *    Add TUNSETLINK ioctl to set the link encapsulation
 *
 *  Mark Smith <markzzzsmith@yahoo.com.au>
 *    Use eth_random_addr() for tap MAC address.
 *
 *  Harald Roelle <harald.roelle@ifi.lmu.de>  2004/04/20
 *    Fixes in packet dropping, queue length setting and queue wakeup.
 *    Increased default tx queue length.
 *    Added ethtool API.
 *    Minor cleanups
 *
 *  Daniel Podlejski <underley@underley.eu.org>
 *    Modifications for 2.3.99-pre5 kernel.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#define DRV_NAME	"tun"
#define DRV_VERSION	"1.6"
#define DRV_DESCRIPTION	"Universal TUN/TAP device driver"
#define DRV_COPYRIGHT	"(C) 1999-2004 Max Krasnyansky <maxk@qualcomm.com>"

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/miscdevice.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/compat.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/if_vlan.h>
#include <linux/crc32.h>
#include <linux/nsproxy.h>
#include <linux/virtio_net.h>
#include <linux/rcupdate.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>
#include <net/sock.h>
#include <linux/skb_array.h>
#include <linux/seq_file.h>
#include <linux/socket.h>

#include <asm/uaccess.h>

#ifdef CONFIG_VE_TUNTAP_ACCOUNTING
#include <linux/vznetstat.h>
#endif /* CONFIG_VE_TUNTAP_ACCOUNTING */

/* Uncomment to enable debugging */
/* #define TUN_DEBUG 1 */

#ifdef TUN_DEBUG
static int debug;

#define tun_debug(level, tun, fmt, args...)			\
do {								\
	if (tun->debug)						\
		netdev_printk(level, tun->dev, fmt, ##args);	\
} while (0)
#define DBG1(level, fmt, args...)				\
do {								\
	if (debug == 2)						\
		printk(level fmt, ##args);			\
} while (0)
#else
#define tun_debug(level, tun, fmt, args...)			\
do {								\
	if (0)							\
		netdev_printk(level, tun->dev, fmt, ##args);	\
} while (0)
#define DBG1(level, fmt, args...)				\
do {								\
	if (0)							\
		printk(level fmt, ##args);			\
} while (0)
#endif

/* TUN device flags */

/* IFF_ATTACH_QUEUE is never stored in device flags,
 * overload it to mean fasync when stored there.
 */
#define TUN_FASYNC	IFF_ATTACH_QUEUE
/* High bits in flags field are unused. */
#define TUN_VNET_LE     0x80000000
#define TUN_VNET_BE     0x40000000

#define TUN_FEATURES (IFF_NO_PI | IFF_ONE_QUEUE | IFF_VNET_HDR | \
		      IFF_MULTI_QUEUE)
#define GOODCOPY_LEN 128

#define FLT_EXACT_COUNT 8
struct tap_filter {
	unsigned int    count;    /* Number of addrs. Zero means disabled */
	u32             mask[2];  /* Mask of the hashed addrs */
	unsigned char	addr[FLT_EXACT_COUNT][ETH_ALEN];
};

/* MAX_TAP_QUEUES 256 is chosen to allow rx/tx queues to be equal
 * to max number of VCPUs in guest. */
#define MAX_TAP_QUEUES 256
#define MAX_TAP_FLOWS  4096

#define TUN_FLOW_EXPIRE (3 * HZ)

struct tun_pcpu_stats {
	u64 rx_packets;
	u64 rx_bytes;
	u64 tx_packets;
	u64 tx_bytes;
	struct u64_stats_sync syncp;
	u32 rx_dropped;
	u32 tx_dropped;
	u32 rx_frame_errors;
};

/* A tun_file connects an open character device to a tuntap netdevice. It
 * also contains all socket related strctures (except sock_fprog and tap_filter)
 * to serve as one transmit queue for tuntap device. The sock_fprog and
 * tap_filter were kept in tun_struct since they were used for filtering for the
 * netdevice not for a specific queue (at least I didn't see the requirement for
 * this).
 *
 * RCU usage:
 * The tun_file and tun_struct are loosely coupled, the pointer from one to the
 * other can only be read while rcu_read_lock or rtnl_lock is held.
 */
struct tun_file {
	struct sock sk;
	struct socket socket;
	struct socket_wq wq;
	struct tun_struct __rcu *tun;
	struct net *net;
	struct fasync_struct *fasync;
	/* only used for fasnyc */
	unsigned int flags;
	union {
		u16 queue_index;
		unsigned int ifindex;
	};
	struct list_head next;
	struct tun_struct *detached;
	struct skb_array tx_array;
};

struct tun_flow_entry {
	struct hlist_node hash_link;
	struct rcu_head rcu;
	struct tun_struct *tun;

	u32 rxhash;
	int queue_index;
	unsigned long updated;
};

#define TUN_NUM_FLOW_ENTRIES 1024

/* Since the socket were moved to tun_file, to preserve the behavior of persist
 * device, socket filter, sndbuf and vnet header size were restore when the
 * file were attached to a persist device.
 */
struct tun_struct {
	struct tun_file __rcu	*tfiles[MAX_TAP_QUEUES];
	unsigned int            numqueues;
	unsigned int 		flags;
	kuid_t			owner;
	kgid_t			group;

	struct net_device	*dev;
	netdev_features_t	set_features;
#define TUN_USER_FEATURES (NETIF_F_HW_CSUM|NETIF_F_TSO_ECN|NETIF_F_TSO| \
			  NETIF_F_TSO6|NETIF_F_UFO)

	int			align;
	int			vnet_hdr_sz;
	int			sndbuf;
	struct tap_filter	txflt;
	struct sock_fprog	fprog;
	/* protected by rtnl lock */
	bool			filter_attached;
#ifdef TUN_DEBUG
	int debug;
#endif
	spinlock_t lock;
	struct hlist_head flows[TUN_NUM_FLOW_ENTRIES];
	struct timer_list flow_gc_timer;
	unsigned long ageing_time;
	unsigned int numdisabled;
	struct list_head disabled;
	void *security;
	u32 flow_count;
	u32 rx_batched;
	struct tun_pcpu_stats __percpu *pcpu_stats;
#ifdef CONFIG_VE_TUNTAP_ACCOUNTING
	struct venet_stat *vestat;
#endif /* CONFIG_VE_TUNTAP_ACCOUNTING */
};

#ifdef CONFIG_TUN_VNET_CROSS_LE
static inline bool tun_legacy_is_little_endian(struct tun_struct *tun)
{
	return tun->flags & TUN_VNET_BE ? false :
		virtio_legacy_is_little_endian();
}

static long tun_get_vnet_be(struct tun_struct *tun, int __user *argp)
{
	int be = !!(tun->flags & TUN_VNET_BE);

	if (put_user(be, argp))
		return -EFAULT;

	return 0;
}

static long tun_set_vnet_be(struct tun_struct *tun, int __user *argp)
{
	int be;

	if (get_user(be, argp))
		return -EFAULT;

	if (be)
		tun->flags |= TUN_VNET_BE;
	else
		tun->flags &= ~TUN_VNET_BE;

	return 0;
}
#else
static inline bool tun_legacy_is_little_endian(struct tun_struct *tun)
{
	return virtio_legacy_is_little_endian();
}

static long tun_get_vnet_be(struct tun_struct *tun, int __user *argp)
{
	return -EINVAL;
}

static long tun_set_vnet_be(struct tun_struct *tun, int __user *argp)
{
	return -EINVAL;
}
#endif /* CONFIG_TUN_VNET_CROSS_LE */

static inline bool tun_is_little_endian(struct tun_struct *tun)
{
	return tun->flags & TUN_VNET_LE ||
		tun_legacy_is_little_endian(tun);
}

static inline u16 tun16_to_cpu(struct tun_struct *tun, __virtio16 val)
{
	return __virtio16_to_cpu(tun_is_little_endian(tun), val);
}

static inline __virtio16 cpu_to_tun16(struct tun_struct *tun, u16 val)
{
	return __cpu_to_virtio16(tun_is_little_endian(tun), val);
}

static inline u32 tun_hashfn(u32 rxhash)
{
	return rxhash & 0x3ff;
}

static struct tun_flow_entry *tun_flow_find(struct hlist_head *head, u32 rxhash)
{
	struct tun_flow_entry *e;

	hlist_for_each_entry_rcu(e, head, hash_link) {
		if (e->rxhash == rxhash)
			return e;
	}
	return NULL;
}

static struct tun_flow_entry *tun_flow_create(struct tun_struct *tun,
					      struct hlist_head *head,
					      u32 rxhash, u16 queue_index)
{
	struct tun_flow_entry *e = kmalloc(sizeof(*e), GFP_ATOMIC);

	if (e) {
		tun_debug(KERN_INFO, tun, "create flow: hash %u index %u\n",
			  rxhash, queue_index);
		e->updated = jiffies;
		e->rxhash = rxhash;
		e->queue_index = queue_index;
		e->tun = tun;
		hlist_add_head_rcu(&e->hash_link, head);
		++tun->flow_count;
	}
	return e;
}

static void tun_flow_delete(struct tun_struct *tun, struct tun_flow_entry *e)
{
	tun_debug(KERN_INFO, tun, "delete flow: hash %u index %u\n",
		  e->rxhash, e->queue_index);
	hlist_del_rcu(&e->hash_link);
	kfree_rcu(e, rcu);
	--tun->flow_count;
}

static void tun_flow_flush(struct tun_struct *tun)
{
	int i;

	spin_lock_bh(&tun->lock);
	for (i = 0; i < TUN_NUM_FLOW_ENTRIES; i++) {
		struct tun_flow_entry *e;
		struct hlist_node *n;

		hlist_for_each_entry_safe(e, n, &tun->flows[i], hash_link)
			tun_flow_delete(tun, e);
	}
	spin_unlock_bh(&tun->lock);
}

static void tun_flow_delete_by_queue(struct tun_struct *tun, u16 queue_index)
{
	int i;

	spin_lock_bh(&tun->lock);
	for (i = 0; i < TUN_NUM_FLOW_ENTRIES; i++) {
		struct tun_flow_entry *e;
		struct hlist_node *n;

		hlist_for_each_entry_safe(e, n, &tun->flows[i], hash_link) {
			if (e->queue_index == queue_index)
				tun_flow_delete(tun, e);
		}
	}
	spin_unlock_bh(&tun->lock);
}

static void tun_flow_cleanup(unsigned long data)
{
	struct tun_struct *tun = (struct tun_struct *)data;
	unsigned long delay = tun->ageing_time;
	unsigned long next_timer = jiffies + delay;
	unsigned long count = 0;
	int i;

	tun_debug(KERN_INFO, tun, "tun_flow_cleanup\n");

	spin_lock(&tun->lock);
	for (i = 0; i < TUN_NUM_FLOW_ENTRIES; i++) {
		struct tun_flow_entry *e;
		struct hlist_node *n;

		hlist_for_each_entry_safe(e, n, &tun->flows[i], hash_link) {
			unsigned long this_timer;

			this_timer = e->updated + delay;
			if (time_before_eq(this_timer, jiffies)) {
				tun_flow_delete(tun, e);
				continue;
			}
			count++;
			if (time_before(this_timer, next_timer))
				next_timer = this_timer;
		}
	}

	if (count)
		mod_timer(&tun->flow_gc_timer, round_jiffies_up(next_timer));
	spin_unlock(&tun->lock);
}

static void tun_flow_update(struct tun_struct *tun, u32 rxhash,
			    struct tun_file *tfile)
{
	struct hlist_head *head;
	struct tun_flow_entry *e;
	unsigned long delay = tun->ageing_time;
	u16 queue_index = tfile->queue_index;

	if (!rxhash)
		return;
	else
		head = &tun->flows[tun_hashfn(rxhash)];

	rcu_read_lock();

	/* We may get a very small possibility of OOO during switching, not
	 * worth to optimize.*/
	if (tun->numqueues == 1 || tfile->detached)
		goto unlock;

	e = tun_flow_find(head, rxhash);
	if (likely(e)) {
		/* TODO: keep queueing to old queue until it's empty? */
		e->queue_index = queue_index;
		e->updated = jiffies;
	} else {
		spin_lock_bh(&tun->lock);
		if (!tun_flow_find(head, rxhash) &&
		    tun->flow_count < MAX_TAP_FLOWS)
			tun_flow_create(tun, head, rxhash, queue_index);

		if (!timer_pending(&tun->flow_gc_timer))
			mod_timer(&tun->flow_gc_timer,
				  round_jiffies_up(jiffies + delay));
		spin_unlock_bh(&tun->lock);
	}

unlock:
	rcu_read_unlock();
}

/* We try to identify a flow through its rxhash first. The reason that
 * we do not check rxq no. is becuase some cards(e.g 82599), chooses
 * the rxq based on the txq where the last packet of the flow comes. As
 * the userspace application move between processors, we may get a
 * different rxq no. here. If we could not get rxhash, then we would
 * hope the rxq no. may help here.
 */
static u16 tun_select_queue(struct net_device *dev, struct sk_buff *skb,
			    void *accel_priv, select_queue_fallback_t fallback)
{
	struct tun_struct *tun = netdev_priv(dev);
	struct tun_flow_entry *e;
	u32 txq = 0;
	u32 numqueues = 0;

	rcu_read_lock();
	numqueues = ACCESS_ONCE(tun->numqueues);

	txq = __skb_get_hash_symmetric(skb);
	if (txq) {
		e = tun_flow_find(&tun->flows[tun_hashfn(txq)], txq);
		if (e)
			txq = e->queue_index;
		else
			/* use multiply and shift instead of expensive divide */
			txq = ((u64)txq * numqueues) >> 32;
	} else if (likely(skb_rx_queue_recorded(skb))) {
		txq = skb_get_rx_queue(skb);
		while (unlikely(txq >= numqueues))
			txq -= numqueues;
	}

	rcu_read_unlock();
	return txq;
}

static inline bool tun_not_capable(struct tun_struct *tun)
{
	const struct cred *cred = current_cred();
	struct net *net = dev_net(tun->dev);

	return ((uid_valid(tun->owner) && !uid_eq(cred->euid, tun->owner)) ||
		  (gid_valid(tun->group) && !in_egroup_p(tun->group))) &&
		!ns_capable(net->user_ns, CAP_NET_ADMIN);
}

static void tun_set_real_num_queues(struct tun_struct *tun)
{
	netif_set_real_num_tx_queues(tun->dev, tun->numqueues);
	netif_set_real_num_rx_queues(tun->dev, tun->numqueues);
}

static void tun_disable_queue(struct tun_struct *tun, struct tun_file *tfile)
{
	tfile->detached = tun;
	list_add_tail(&tfile->next, &tun->disabled);
	++tun->numdisabled;
}

static struct tun_struct *tun_enable_queue(struct tun_file *tfile)
{
	struct tun_struct *tun = tfile->detached;

	tfile->detached = NULL;
	list_del_init(&tfile->next);
	--tun->numdisabled;
	return tun;
}

static void tun_queue_purge(struct tun_file *tfile)
{
	struct sk_buff *skb;

	while ((skb = skb_array_consume(&tfile->tx_array)) != NULL)
		kfree_skb(skb);

	skb_queue_purge(&tfile->sk.sk_write_queue);
}

static void __tun_detach(struct tun_file *tfile, bool clean)
{
	struct tun_file *ntfile;
	struct tun_struct *tun;

	tun = rtnl_dereference(tfile->tun);

	if (tun && !tfile->detached) {
		u16 index = tfile->queue_index;
		BUG_ON(index >= tun->numqueues);

		rcu_assign_pointer(tun->tfiles[index],
				   tun->tfiles[tun->numqueues - 1]);
		ntfile = rtnl_dereference(tun->tfiles[index]);
		ntfile->queue_index = index;
		rcu_assign_pointer(tun->tfiles[tun->numqueues - 1],
				   NULL);

		--tun->numqueues;
		if (clean) {
			rcu_assign_pointer(tfile->tun, NULL);
			sock_put(&tfile->sk);
		} else
			tun_disable_queue(tun, tfile);

		synchronize_net();
		tun_flow_delete_by_queue(tun, tun->numqueues + 1);
		/* Drop read queue */
		tun_queue_purge(tfile);
		tun_set_real_num_queues(tun);
	} else if (tfile->detached && clean) {
		tun = tun_enable_queue(tfile);
		sock_put(&tfile->sk);
	}

	if (clean) {
		if (tun && tun->numqueues == 0 && tun->numdisabled == 0) {
			netif_carrier_off(tun->dev);

			if (!(tun->flags & IFF_PERSIST) &&
			    tun->dev->reg_state == NETREG_REGISTERED)
				unregister_netdevice(tun->dev);
		}

		skb_array_cleanup(&tfile->tx_array);
		BUG_ON(!test_bit(SOCK_EXTERNALLY_ALLOCATED,
				 &tfile->socket.flags));
		sk_release_kernel(&tfile->sk);
	}
}

static void tun_detach(struct tun_file *tfile, bool clean)
{
	struct tun_struct *tun;
	struct net_device *dev;

	rtnl_lock();
	tun = rtnl_dereference(tfile->tun);
	dev = tun ? tun->dev : NULL;
	__tun_detach(tfile, clean);
	if (dev)
		netdev_state_change(dev);
	rtnl_unlock();
}

static void tun_detach_all(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);
	struct tun_file *tfile, *tmp;
	int i, n = tun->numqueues;

	for (i = 0; i < n; i++) {
		tfile = rtnl_dereference(tun->tfiles[i]);
		BUG_ON(!tfile);
		wake_up_all(&tfile->wq.wait);
		rcu_assign_pointer(tfile->tun, NULL);
		--tun->numqueues;
	}
	list_for_each_entry(tfile, &tun->disabled, next) {
		wake_up_all(&tfile->wq.wait);
		rcu_assign_pointer(tfile->tun, NULL);
	}
	BUG_ON(tun->numqueues != 0);

	synchronize_net();
	for (i = 0; i < n; i++) {
		tfile = rtnl_dereference(tun->tfiles[i]);
		/* Drop read queue */
		tun_queue_purge(tfile);
		sock_put(&tfile->sk);
	}
	list_for_each_entry_safe(tfile, tmp, &tun->disabled, next) {
		tun_enable_queue(tfile);
		tun_queue_purge(tfile);
		sock_put(&tfile->sk);
	}
	BUG_ON(tun->numdisabled != 0);

	if (tun->flags & IFF_PERSIST)
		module_put(THIS_MODULE);
}

static int tun_attach(struct tun_struct *tun, struct file *file, bool skip_filter)
{
	struct tun_file *tfile = file->private_data;
	struct net_device *dev = tun->dev;
	int err;

	err = security_tun_dev_attach(tfile->socket.sk, tun->security);
	if (err < 0)
		goto out;

	err = -EINVAL;
	if (rtnl_dereference(tfile->tun) && !tfile->detached)
		goto out;

	err = -EBUSY;
	if (!(tun->flags & IFF_MULTI_QUEUE) && tun->numqueues == 1)
		goto out;

	err = -E2BIG;
	if (!tfile->detached &&
	    tun->numqueues + tun->numdisabled == MAX_TAP_QUEUES)
		goto out;

	err = 0;

	/* Re-attach the filter to presist device */
	if (!skip_filter && (tun->filter_attached == true)) {
		lock_sock(tfile->socket.sk);
		err = sk_attach_filter(&tun->fprog, tfile->socket.sk);
		release_sock(tfile->socket.sk);
		if (!err)
			goto out;
	}

	if (!tfile->detached &&
	    skb_array_resize(&tfile->tx_array, dev->tx_queue_len, GFP_KERNEL)) {
		err = -ENOMEM;
		goto out;
	}

	tfile->queue_index = tun->numqueues;
	rcu_assign_pointer(tfile->tun, tun);
	rcu_assign_pointer(tun->tfiles[tun->numqueues], tfile);
	tun->numqueues++;

	if (tfile->detached)
		tun_enable_queue(tfile);
	else
		sock_hold(&tfile->sk);

	tun_set_real_num_queues(tun);

	/* device is allowed to go away first, so no need to hold extra
	 * refcnt.
	 */

out:
	return err;
}

static struct tun_struct *__tun_get(struct tun_file *tfile)
{
	struct tun_struct *tun;

	rcu_read_lock();
	tun = rcu_dereference(tfile->tun);
	if (tun)
		dev_hold(tun->dev);
	rcu_read_unlock();

	return tun;
}

static struct tun_struct *tun_get(struct file *file)
{
	return __tun_get(file->private_data);
}

static void tun_put(struct tun_struct *tun)
{
	dev_put(tun->dev);
}

/* TAP filtering */
static void addr_hash_set(u32 *mask, const u8 *addr)
{
	int n = ether_crc(ETH_ALEN, addr) >> 26;
	mask[n >> 5] |= (1 << (n & 31));
}

static unsigned int addr_hash_test(const u32 *mask, const u8 *addr)
{
	int n = ether_crc(ETH_ALEN, addr) >> 26;
	return mask[n >> 5] & (1 << (n & 31));
}

static int update_filter(struct tap_filter *filter, void __user *arg)
{
	struct { u8 u[ETH_ALEN]; } *addr;
	struct tun_filter uf;
	int err, alen, n, nexact;

	if (copy_from_user(&uf, arg, sizeof(uf)))
		return -EFAULT;

	if (!uf.count) {
		/* Disabled */
		filter->count = 0;
		return 0;
	}

	alen = ETH_ALEN * uf.count;
	addr = kmalloc(alen, GFP_KERNEL);
	if (!addr)
		return -ENOMEM;

	if (copy_from_user(addr, arg + sizeof(uf), alen)) {
		err = -EFAULT;
		goto done;
	}

	/* The filter is updated without holding any locks. Which is
	 * perfectly safe. We disable it first and in the worst
	 * case we'll accept a few undesired packets. */
	filter->count = 0;
	wmb();

	/* Use first set of addresses as an exact filter */
	for (n = 0; n < uf.count && n < FLT_EXACT_COUNT; n++)
		memcpy(filter->addr[n], addr[n].u, ETH_ALEN);

	nexact = n;

	/* Remaining multicast addresses are hashed,
	 * unicast will leave the filter disabled. */
	memset(filter->mask, 0, sizeof(filter->mask));
	for (; n < uf.count; n++) {
		if (!is_multicast_ether_addr(addr[n].u)) {
			err = 0; /* no filter */
			goto done;
		}
		addr_hash_set(filter->mask, addr[n].u);
	}

	/* For ALLMULTI just set the mask to all ones.
	 * This overrides the mask populated above. */
	if ((uf.flags & TUN_FLT_ALLMULTI))
		memset(filter->mask, ~0, sizeof(filter->mask));

	/* Now enable the filter */
	wmb();
	filter->count = nexact;

	/* Return the number of exact filters */
	err = nexact;

done:
	kfree(addr);
	return err;
}

/* Returns: 0 - drop, !=0 - accept */
static int run_filter(struct tap_filter *filter, const struct sk_buff *skb)
{
	/* Cannot use eth_hdr(skb) here because skb_mac_hdr() is incorrect
	 * at this point. */
	struct ethhdr *eh = (struct ethhdr *) skb->data;
	int i;

	/* Exact match */
	for (i = 0; i < filter->count; i++)
		if (ether_addr_equal(eh->h_dest, filter->addr[i]))
			return 1;

	/* Inexact match (multicast only) */
	if (is_multicast_ether_addr(eh->h_dest))
		return addr_hash_test(filter->mask, eh->h_dest);

	return 0;
}

/*
 * Checks whether the packet is accepted or not.
 * Returns: 0 - drop, !=0 - accept
 */
static int check_filter(struct tap_filter *filter, const struct sk_buff *skb)
{
	if (!filter->count)
		return 1;

	return run_filter(filter, skb);
}

/* Network device part of the driver */

static const struct ethtool_ops tun_ethtool_ops;

/* Net device detach from fd. */
static void tun_net_uninit(struct net_device *dev)
{
	tun_detach_all(dev);
}

/* Net device open. */
static int tun_net_open(struct net_device *dev)
{
	netif_tx_start_all_queues(dev);
	return 0;
}

/* Net device close. */
static int tun_net_close(struct net_device *dev)
{
	netif_tx_stop_all_queues(dev);
	return 0;
}

/* Net device start xmit */
static netdev_tx_t tun_net_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);
	int txq = skb->queue_mapping;
	struct tun_file *tfile;
	u32 numqueues = 0;

	rcu_read_lock();
	tfile = rcu_dereference(tun->tfiles[txq]);
	numqueues = ACCESS_ONCE(tun->numqueues);

	/* Drop packet if interface is not attached */
	if (!tfile)
		goto drop;

	tun_debug(KERN_INFO, tun, "tun_net_xmit %d\n", skb->len);

	BUG_ON(!tfile);

	/* Drop if the filter does not like it.
	 * This is a noop if the filter is disabled.
	 * Filter can be enabled only for the TAP devices. */
	if (!check_filter(&tun->txflt, skb))
		goto drop;

	if (tfile->socket.sk->sk_filter &&
	    sk_filter(tfile->socket.sk, skb))
		goto drop;

	/* Orphan the skb - required as we might hang on to it
	 * for indefinite time. */
	if (unlikely(skb_orphan_frags(skb, GFP_ATOMIC)))
		goto drop;
	skb_orphan(skb);

	nf_reset(skb);

	if (skb_array_produce(&tfile->tx_array, skb))
		goto drop;

	/* Notify and wake up reader process */
	if (tfile->flags & TUN_FASYNC)
		kill_fasync(&tfile->fasync, SIGIO, POLL_IN);
	wake_up_interruptible_poll(&tfile->wq.wait, POLLIN |
				   POLLRDNORM | POLLRDBAND);

	rcu_read_unlock();
	return NETDEV_TX_OK;

drop:
	this_cpu_inc(tun->pcpu_stats->tx_dropped);
	skb_tx_error(skb);
	kfree_skb(skb);
	rcu_read_unlock();
	return NETDEV_TX_OK;
}

static void tun_net_mclist(struct net_device *dev)
{
	/*
	 * This callback is supposed to deal with mc filter in
	 * _rx_ path and has nothing to do with the _tx_ path.
	 * In rx path we always accept everything userspace gives us.
	 */
}

#define MIN_MTU 68
#define MAX_MTU 65535

static int
tun_net_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < MIN_MTU || new_mtu + dev->hard_header_len > MAX_MTU)
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

static netdev_features_t tun_net_fix_features(struct net_device *dev,
	netdev_features_t features)
{
	struct tun_struct *tun = netdev_priv(dev);

	return (features & tun->set_features) | (features & ~TUN_USER_FEATURES);
}

static void
tun_net_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	u32 rx_dropped = 0, tx_dropped = 0, rx_frame_errors = 0;
	struct tun_struct *tun = netdev_priv(dev);
	struct tun_pcpu_stats *p;
	int i;

	for_each_possible_cpu(i) {
		u64 rxpackets, rxbytes, txpackets, txbytes;
		unsigned int start;

		p = per_cpu_ptr(tun->pcpu_stats, i);
		do {
			start = u64_stats_fetch_begin(&p->syncp);
			rxpackets	= p->rx_packets;
			rxbytes		= p->rx_bytes;
			txpackets	= p->tx_packets;
			txbytes		= p->tx_bytes;
		} while (u64_stats_fetch_retry(&p->syncp, start));

		stats->rx_packets	+= rxpackets;
		stats->rx_bytes		+= rxbytes;
		stats->tx_packets	+= txpackets;
		stats->tx_bytes		+= txbytes;

		/* u32 counters */
		rx_dropped	+= p->rx_dropped;
		rx_frame_errors	+= p->rx_frame_errors;
		tx_dropped	+= p->tx_dropped;
	}
	stats->rx_dropped  = rx_dropped;
	stats->rx_frame_errors = rx_frame_errors;
	stats->tx_dropped = tx_dropped;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void tun_poll_controller(struct net_device *dev)
{
	/*
	 * Tun only receives frames when:
	 * 1) the char device endpoint gets data from user space
	 * 2) the tun socket gets a sendmsg call from user space
	 * Since both of those are syncronous operations, we are guaranteed
	 * never to have pending data when we poll for it
	 * so theres nothing to do here but return.
	 * We need this though so netpoll recognizes us as an interface that
	 * supports polling, which enables bridge devices in virt setups to
	 * still use netconsole
	 */
	return;
}
#endif

static void tun_set_headroom(struct net_device *dev, int new_hr)
{
	struct tun_struct *tun = netdev_priv(dev);

	if (new_hr < NET_SKB_PAD)
		new_hr = NET_SKB_PAD;

	tun->align = new_hr;
}

static int tun_net_change_carrier(struct net_device *dev, bool new_carrier)
{
	if (new_carrier) {
		struct tun_struct *tun = netdev_priv(dev);

		if (!tun->numqueues)
			return -EPERM;

		netif_carrier_on(dev);
	} else {
		netif_carrier_off(dev);
	}
	return 0;
}

static const struct net_device_ops tun_netdev_ops = {
	.ndo_uninit		= tun_net_uninit,
	.ndo_open		= tun_net_open,
	.ndo_stop		= tun_net_close,
	.ndo_start_xmit		= tun_net_xmit,
	.ndo_change_mtu_rh74	= tun_net_change_mtu,
	.ndo_fix_features	= tun_net_fix_features,
	.ndo_select_queue	= tun_select_queue,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= tun_poll_controller,
#endif
	.ndo_size		= sizeof(struct net_device_ops),
	.extended.ndo_set_rx_headroom	= tun_set_headroom,
	.ndo_get_stats64	= tun_net_get_stats64,
	.ndo_change_carrier	= tun_net_change_carrier,
};

static const struct net_device_ops tap_netdev_ops = {
	.ndo_uninit		= tun_net_uninit,
	.ndo_open		= tun_net_open,
	.ndo_stop		= tun_net_close,
	.ndo_start_xmit		= tun_net_xmit,
	.ndo_change_mtu_rh74	= tun_net_change_mtu,
	.ndo_fix_features	= tun_net_fix_features,
	.ndo_set_rx_mode	= tun_net_mclist,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_select_queue	= tun_select_queue,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= tun_poll_controller,
#endif
	.ndo_size		= sizeof(struct net_device_ops),
	.extended.ndo_set_rx_headroom	= tun_set_headroom,
	.ndo_get_stats64	= tun_net_get_stats64,
	.ndo_change_carrier	= tun_net_change_carrier,
};

static void tun_flow_init(struct tun_struct *tun)
{
	int i;

	for (i = 0; i < TUN_NUM_FLOW_ENTRIES; i++)
		INIT_HLIST_HEAD(&tun->flows[i]);

	tun->ageing_time = TUN_FLOW_EXPIRE;
	setup_timer(&tun->flow_gc_timer, tun_flow_cleanup, (unsigned long)tun);
}

static void tun_flow_uninit(struct tun_struct *tun)
{
	del_timer_sync(&tun->flow_gc_timer);
	tun_flow_flush(tun);
}

/* Initialize net device. */
static void tun_net_init(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);

	switch (tun->flags & TUN_TYPE_MASK) {
	case IFF_TUN:
		dev->netdev_ops = &tun_netdev_ops;

		/* Point-to-Point TUN Device */
		dev->hard_header_len = 0;
		dev->addr_len = 0;
		dev->mtu = 1500;

		/* Zero header length */
		dev->type = ARPHRD_NONE;
		dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
		break;

	case IFF_TAP:
		dev->netdev_ops = &tap_netdev_ops;
		/* Ethernet TAP Device */
		ether_setup(dev);
		dev->priv_flags &= ~IFF_TX_SKB_SHARING;
		dev->priv_flags |= IFF_LIVE_ADDR_CHANGE;

		eth_hw_addr_random(dev);

		break;
	}
}

/* Character device part */

/* Poll */
static unsigned int tun_chr_poll(struct file *file, poll_table *wait)
{
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun = __tun_get(tfile);
	struct sock *sk;
	unsigned int mask = 0;

	if (!tun)
		return POLLERR;

	sk = tfile->socket.sk;

	tun_debug(KERN_INFO, tun, "tun_chr_poll\n");

	poll_wait(file, &tfile->wq.wait, wait);

	if (!skb_array_empty(&tfile->tx_array))
		mask |= POLLIN | POLLRDNORM;

	if (sock_writeable(sk) ||
	    (!test_and_set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags) &&
	     sock_writeable(sk)))
		mask |= POLLOUT | POLLWRNORM;

	if (tun->dev->reg_state != NETREG_REGISTERED)
		mask = POLLERR;

	tun_put(tun);
	return mask;
}

/* prepad is the amount to reserve at front.  len is length after that.
 * linear is a hint as to how much to copy (usually headers). */
static struct sk_buff *tun_alloc_skb(struct tun_file *tfile,
				     size_t prepad, size_t len,
				     size_t linear, int noblock)
{
	struct sock *sk = tfile->socket.sk;
	struct sk_buff *skb;
	int err;

	/* Under a page?  Don't bother with paged skb. */
	if (prepad + len < PAGE_SIZE || !linear)
		linear = len;

	skb = sock_alloc_send_pskb(sk, prepad + linear, len - linear, noblock,
				   &err, 0);
	if (!skb)
		return ERR_PTR(err);

	skb_reserve(skb, prepad);
	skb_put(skb, linear);
	skb->data_len = len - linear;
	skb->len += len - linear;

	return skb;
}

/* set skb frags from iovec, this can move to core network code for reuse */
static int zerocopy_sg_from_iovec(struct sk_buff *skb, const struct iovec *from,
				  int offset, size_t count)
{
	int len = iov_length(from, count) - offset;
	int copy = skb_headlen(skb);
	int size, offset1 = 0;
	int i = 0;

	/* Skip over from offset */
	while (count && (offset >= from->iov_len)) {
		offset -= from->iov_len;
		++from;
		--count;
	}

	/* copy up to skb headlen */
	while (count && (copy > 0)) {
		size = min_t(unsigned int, copy, from->iov_len - offset);
		if (copy_from_user(skb->data + offset1, from->iov_base + offset,
				   size))
			return -EFAULT;
		if (copy > size) {
			++from;
			--count;
			offset = 0;
		} else
			offset += size;
		copy -= size;
		offset1 += size;
	}

	if (len == offset1)
		return 0;

	while (count--) {
		struct page *page[MAX_SKB_FRAGS];
		int num_pages;
		unsigned long base;
		unsigned long truesize;

		len = from->iov_len - offset;
		if (!len) {
			offset = 0;
			++from;
			continue;
		}
		base = (unsigned long)from->iov_base + offset;
		size = ((base & ~PAGE_MASK) + len + ~PAGE_MASK) >> PAGE_SHIFT;
		if (i + size > MAX_SKB_FRAGS)
			return -EMSGSIZE;
		num_pages = get_user_pages_fast(base, size, 0, &page[i]);
		if (num_pages != size) {
			int j;

			for (j = 0; j < num_pages; j++)
				put_page(page[i + j]);
			return -EFAULT;
		}
		truesize = size * PAGE_SIZE;
		skb->data_len += len;
		skb->len += len;
		skb->truesize += truesize;
		atomic_add(truesize, &skb->sk->sk_wmem_alloc);
		while (len) {
			int off = base & ~PAGE_MASK;
			int size = min_t(int, len, PAGE_SIZE - off);
			__skb_fill_page_desc(skb, i, page[i], off, size);
			skb_shinfo(skb)->nr_frags++;
			/* increase sk_wmem_alloc */
			base += size;
			len -= size;
			i++;
		}
		offset = 0;
		++from;
	}
	return 0;
}

static unsigned long iov_pages(const struct iovec *iv, int offset,
			       unsigned long nr_segs)
{
	unsigned long seg, base;
	int pages = 0, len, size;

	while (nr_segs && (offset >= iv->iov_len)) {
		offset -= iv->iov_len;
		++iv;
		--nr_segs;
	}

	for (seg = 0; seg < nr_segs; seg++) {
		base = (unsigned long)iv[seg].iov_base + offset;
		len = iv[seg].iov_len - offset;
		size = ((base & ~PAGE_MASK) + len + ~PAGE_MASK) >> PAGE_SHIFT;
		pages += size;
		offset = 0;
	}

	return pages;
}

static void tun_rx_batched(struct tun_struct *tun, struct tun_file *tfile,
			   struct sk_buff *skb, int more)
{
	struct sk_buff_head *queue = &tfile->sk.sk_write_queue;
	struct sk_buff_head process_queue;
	u32 rx_batched = tun->rx_batched;
	bool rcv = false;

	if (!rx_batched || (!more && skb_queue_empty(queue))) {
		local_bh_disable();
		skb_record_rx_queue(skb, tfile->queue_index);
		netif_receive_skb(skb);
		local_bh_enable();
		return;
	}

	spin_lock(&queue->lock);
	if (!more || skb_queue_len(queue) == rx_batched) {
		__skb_queue_head_init(&process_queue);
		skb_queue_splice_tail_init(queue, &process_queue);
		rcv = true;
	} else {
		__skb_queue_tail(queue, skb);
	}
	spin_unlock(&queue->lock);

	if (rcv) {
		struct sk_buff *nskb;

		local_bh_disable();
		while ((nskb = __skb_dequeue(&process_queue))) {
			skb_record_rx_queue(nskb, tfile->queue_index);
			netif_receive_skb(nskb);
		}
		skb_record_rx_queue(skb, tfile->queue_index);
		netif_receive_skb(skb);
		local_bh_enable();
	}
}

/* Get packet from user space buffer */
static ssize_t tun_get_user(struct tun_struct *tun, struct tun_file *tfile,
			    void *msg_control, const struct iovec *iv,
			    size_t total_len, size_t count, int noblock, bool more)
{
	struct tun_pi pi = { 0, cpu_to_be16(ETH_P_IP) };
	struct sk_buff *skb;
	size_t len = total_len, align = tun->align, linear;
	struct virtio_net_hdr gso = { 0 };
	struct tun_pcpu_stats *stats;
	int good_linear;
	int offset = 0;
	int copylen;
	bool zerocopy = false;
	int err;
	u32 rxhash;

	if (!(tun->flags & IFF_NO_PI)) {
		if (len < sizeof(pi))
			return -EINVAL;
		len -= sizeof(pi);

		if (memcpy_fromiovecend((void *)&pi, iv, 0, sizeof(pi)))
			return -EFAULT;
		offset += sizeof(pi);
	}

	if (tun->flags & IFF_VNET_HDR) {
		if (len < tun->vnet_hdr_sz)
			return -EINVAL;
		len -= tun->vnet_hdr_sz;

		if (memcpy_fromiovecend((void *)&gso, iv, offset, sizeof(gso)))
			return -EFAULT;

		if ((gso.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) &&
		    tun16_to_cpu(tun, gso.csum_start) + tun16_to_cpu(tun, gso.csum_offset) + 2 > tun16_to_cpu(tun, gso.hdr_len))
			gso.hdr_len = cpu_to_tun16(tun, tun16_to_cpu(tun, gso.csum_start) + tun16_to_cpu(tun, gso.csum_offset) + 2);

		if (tun16_to_cpu(tun, gso.hdr_len) > len)
			return -EINVAL;
		offset += tun->vnet_hdr_sz;
	}

	if ((tun->flags & TUN_TYPE_MASK) == IFF_TAP) {
		align += NET_IP_ALIGN;
		if (unlikely(len < ETH_HLEN ||
			     (gso.hdr_len && tun16_to_cpu(tun, gso.hdr_len) < ETH_HLEN)))
			return -EINVAL;
	}

	good_linear = SKB_MAX_HEAD(align);

	if (msg_control) {
		/* There are 256 bytes to be copied in skb, so there is
		 * enough room for skb expand head in case it is used.
		 * The rest of the buffer is mapped from userspace.
		 */
		copylen = gso.hdr_len ? tun16_to_cpu(tun, gso.hdr_len) : GOODCOPY_LEN;
		if (copylen > good_linear)
			copylen = good_linear;
		linear = copylen;
		if (iov_pages(iv, offset + copylen, count) <= MAX_SKB_FRAGS)
			zerocopy = true;
	}

	if (!zerocopy) {
		copylen = len;
		if (tun16_to_cpu(tun, gso.hdr_len) > good_linear)
			linear = good_linear;
		else
			linear = tun16_to_cpu(tun, gso.hdr_len);
	}

	skb = tun_alloc_skb(tfile, align, copylen, linear, noblock);
	if (IS_ERR(skb)) {
		if (PTR_ERR(skb) != -EAGAIN)
			this_cpu_inc(tun->pcpu_stats->rx_dropped);
		return PTR_ERR(skb);
	}

	if (zerocopy)
		err = zerocopy_sg_from_iovec(skb, iv, offset, count);
	else {
		err = skb_copy_datagram_from_iovec(skb, 0, iv, offset, len);
		if (!err && msg_control) {
			struct ubuf_info *uarg = msg_control;
			uarg->callback(uarg, false);
		}
	}

	if (err) {
		this_cpu_inc(tun->pcpu_stats->rx_dropped);
		kfree_skb(skb);
		return -EFAULT;
	}

	if (gso.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
		if (!skb_partial_csum_set(skb, tun16_to_cpu(tun, gso.csum_start),
					  tun16_to_cpu(tun, gso.csum_offset))) {
			this_cpu_inc(tun->pcpu_stats->rx_frame_errors);
			kfree_skb(skb);
			return -EINVAL;
		}
	}

	switch (tun->flags & TUN_TYPE_MASK) {
	case IFF_TUN:
		if (tun->flags & IFF_NO_PI) {
			switch (skb->data[0] & 0xf0) {
			case 0x40:
				pi.proto = htons(ETH_P_IP);
				break;
			case 0x60:
				pi.proto = htons(ETH_P_IPV6);
				break;
			default:
				this_cpu_inc(tun->pcpu_stats->rx_dropped);
				kfree_skb(skb);
				return -EINVAL;
			}
		}

		skb_reset_mac_header(skb);
		skb->protocol = pi.proto;
		skb->dev = tun->dev;
		break;
	case IFF_TAP:
		skb->protocol = eth_type_trans(skb, tun->dev);
		break;
	}

	if (gso.gso_type != VIRTIO_NET_HDR_GSO_NONE) {
		pr_debug("GSO!\n");
		switch (gso.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
		case VIRTIO_NET_HDR_GSO_TCPV4:
			skb_shinfo(skb)->gso_type = SKB_GSO_TCPV4;
			break;
		case VIRTIO_NET_HDR_GSO_TCPV6:
			skb_shinfo(skb)->gso_type = SKB_GSO_TCPV6;
			break;
		case VIRTIO_NET_HDR_GSO_UDP:
			skb_shinfo(skb)->gso_type = SKB_GSO_UDP;
			break;
		default:
			this_cpu_inc(tun->pcpu_stats->rx_frame_errors);
			kfree_skb(skb);
			return -EINVAL;
		}

		if (gso.gso_type & VIRTIO_NET_HDR_GSO_ECN)
			skb_shinfo(skb)->gso_type |= SKB_GSO_TCP_ECN;

		skb_shinfo(skb)->gso_size = tun16_to_cpu(tun, gso.gso_size);
		if (skb_shinfo(skb)->gso_size == 0) {
			this_cpu_inc(tun->pcpu_stats->rx_frame_errors);
			kfree_skb(skb);
			return -EINVAL;
		}

		/* Header must be checked, and gso_segs computed. */
		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_segs = 0;
	}

	/* copy skb_ubuf_info for callback when skb has no error */
	if (zerocopy) {
		skb_shinfo(skb)->destructor_arg = msg_control;
		skb_shinfo(skb)->tx_flags |= SKBTX_DEV_ZEROCOPY;
		skb_shinfo(skb)->tx_flags |= SKBTX_SHARED_FRAG;
	}

	skb_reset_network_header(skb);
	skb_probe_transport_header(skb, 0);

#ifdef CONFIG_VE_TUNTAP_ACCOUNTING
	if (tun->vestat) {
		venet_acct_classify_add_outgoing(tun->vestat, skb);
	}
#endif /* CONFIG_VE_TUNTAP_ACCOUNTING */

	rxhash = __skb_get_hash_symmetric(skb);
#ifndef CONFIG_4KSTACKS
	tun_rx_batched(tun, tfile, skb, more);
#else
	netif_rx_ni(skb);
#endif

	stats = get_cpu_ptr(tun->pcpu_stats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += len;
	u64_stats_update_end(&stats->syncp);
	put_cpu_ptr(stats);

	tun_flow_update(tun, rxhash, tfile);
	return total_len;
}

static ssize_t tun_chr_aio_write(struct kiocb *iocb, const struct iovec *iv,
			      unsigned long count, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct tun_struct *tun = tun_get(file);
	struct tun_file *tfile = file->private_data;
	ssize_t result;

	if (!tun)
		return -EBADFD;

	tun_debug(KERN_INFO, tun, "tun_chr_write %ld\n", count);

	result = tun_get_user(tun, tfile, NULL, iv, iov_length(iv, count),
			      count, file->f_flags & O_NONBLOCK, false);

	tun_put(tun);
	return result;
}

/* Put packet to the user space buffer */
static ssize_t tun_put_user(struct tun_struct *tun,
			    struct tun_file *tfile,
			    struct sk_buff *skb,
			    const struct iovec *iv, int len)
{
	struct tun_pi pi = { 0, skb->protocol };
	struct tun_pcpu_stats *stats;
	ssize_t total = 0;
	int vlan_offset = 0, copied;
	int vlan_hlen = 0;
	int vnet_hdr_sz = 0;

	if (skb_vlan_tag_present(skb))
		vlan_hlen = VLAN_HLEN;

	if (tun->flags & IFF_VNET_HDR)
		vnet_hdr_sz = tun->vnet_hdr_sz;

	if (!(tun->flags & IFF_NO_PI)) {
		if ((len -= sizeof(pi)) < 0)
			return -EINVAL;

		if (len < skb->len + vlan_hlen + vnet_hdr_sz) {
			/* Packet will be striped */
			pi.flags |= TUN_PKT_STRIP;
		}

		if (memcpy_toiovecend(iv, (void *) &pi, 0, sizeof(pi)))
			return -EFAULT;
		total += sizeof(pi);
	}

	if (vnet_hdr_sz) {
		struct virtio_net_hdr gso = { 0 }; /* no info leak */
		if ((len -= vnet_hdr_sz) < 0)
			return -EINVAL;

		if (skb_is_gso(skb)) {
			struct skb_shared_info *sinfo = skb_shinfo(skb);

			/* This is a hint as to how much should be linear. */
			gso.hdr_len = cpu_to_tun16(tun, skb_headlen(skb));
			gso.gso_size = cpu_to_tun16(tun, sinfo->gso_size);
			if (sinfo->gso_type & SKB_GSO_TCPV4)
				gso.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
			else if (sinfo->gso_type & SKB_GSO_TCPV6)
				gso.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
			else if (sinfo->gso_type & SKB_GSO_UDP)
				gso.gso_type = VIRTIO_NET_HDR_GSO_UDP;
			else {
				pr_err("unexpected GSO type: "
				       "0x%x, gso_size %d, hdr_len %d\n",
				       sinfo->gso_type, tun16_to_cpu(tun, gso.gso_size),
				       tun16_to_cpu(tun, gso.hdr_len));
				print_hex_dump(KERN_ERR, "tun: ",
					       DUMP_PREFIX_NONE,
					       16, 1, skb->head,
					       min((int)tun16_to_cpu(tun, gso.hdr_len), 64), true);
				WARN_ON_ONCE(1);
				return -EINVAL;
			}
			if (sinfo->gso_type & SKB_GSO_TCP_ECN)
				gso.gso_type |= VIRTIO_NET_HDR_GSO_ECN;
		} else
			gso.gso_type = VIRTIO_NET_HDR_GSO_NONE;

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			gso.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
			gso.csum_start = cpu_to_tun16(tun, skb_checksum_start_offset(skb) +
						      vlan_hlen);
			gso.csum_offset = cpu_to_tun16(tun, skb->csum_offset);
		} else if (skb->ip_summed == CHECKSUM_UNNECESSARY) {
			gso.flags = VIRTIO_NET_HDR_F_DATA_VALID;
		} /* else everything is zero */

		if (unlikely(memcpy_toiovecend(iv, (void *)&gso, total,
					       sizeof(gso))))
			return -EFAULT;
		total += vnet_hdr_sz;
	}

	copied = total;
	len = min_t(int, skb->len + vlan_hlen, len);
	total += skb->len + vlan_hlen;
	if (vlan_hlen) {
		int copy, ret;
		struct {
			__be16 h_vlan_proto;
			__be16 h_vlan_TCI;
		} veth;

		veth.h_vlan_proto = skb->vlan_proto;
		veth.h_vlan_TCI = htons(skb_vlan_tag_get(skb));

		vlan_offset = offsetof(struct vlan_ethhdr, h_vlan_proto);

		copy = min_t(int, vlan_offset, len);
		ret = skb_copy_datagram_const_iovec(skb, 0, iv, copied, copy);
		len -= copy;
		copied += copy;
		if (ret || !len)
			goto done;

		copy = min_t(int, sizeof(veth), len);
		ret = memcpy_toiovecend(iv, (void *)&veth, copied, copy);
		len -= copy;
		copied += copy;
		if (ret || !len)
			goto done;
	}

	skb_copy_datagram_const_iovec(skb, vlan_offset, iv, copied, len);

done:
	/* caller is in process context, */
	stats = get_cpu_ptr(tun->pcpu_stats);
	u64_stats_update_begin(&stats->syncp);
	stats->tx_packets++;
	stats->tx_bytes += skb->len + vlan_hlen;
	u64_stats_update_end(&stats->syncp);
	put_cpu_ptr(tun->pcpu_stats);

#ifdef CONFIG_VE_TUNTAP_ACCOUNTING
	if (tun->vestat) {
		venet_acct_classify_add_incoming(tun->vestat, skb);
	}
#endif /* CONFIG_VE_TUNTAP_ACCOUNTING */

	return total;
}

static struct sk_buff *tun_ring_recv(struct tun_struct *tun, 
			struct tun_file *tfile, int noblock, int *err)
{
	DECLARE_WAITQUEUE(wait, current);
	struct sk_buff *skb = NULL;
	int error = 0;

	skb = skb_array_consume(&tfile->tx_array);
	if (skb)
		goto out;
	if (noblock) {
		error = -EAGAIN;
		goto out;
	}

	add_wait_queue(&tfile->wq.wait, &wait);
	current->state = TASK_INTERRUPTIBLE;

	while (1) {
		skb = skb_array_consume(&tfile->tx_array);
		if (skb)
			break;
		if (signal_pending(current)) {
			error = -ERESTARTSYS;
			break;
		}

		if (tun->dev->reg_state != NETREG_REGISTERED) {
			error = -EFAULT;
			break;
		}

		schedule();
	}

	current->state = TASK_RUNNING;
	remove_wait_queue(&tfile->wq.wait, &wait);

out:
	*err = error;
	return skb;
}

static ssize_t tun_do_read(struct tun_struct *tun, struct tun_file *tfile,
			   struct kiocb *iocb, const struct iovec *iv,
			   ssize_t len, int noblock, struct sk_buff *skb)
{
	ssize_t ret;
	int err;

	tun_debug(KERN_INFO, tun, "tun_do_read\n");

	if (!len) {
		if (skb)
			kfree_skb(skb);
		return 0;
	}

	if (!skb) {
		/* Read frames from ring */
		skb = tun_ring_recv(tun, tfile, noblock, &err);
		if (!skb)
			return err;
	}

	ret = tun_put_user(tun, tfile, skb, iv, len);
	if (unlikely(ret < 0))
		kfree_skb(skb);
	else
		consume_skb(skb);

	return ret;
}

static ssize_t tun_chr_aio_read(struct kiocb *iocb, const struct iovec *iv,
			    unsigned long count, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun = __tun_get(tfile);
	ssize_t len, ret;

	if (!tun)
		return -EBADFD;
	len = iov_length(iv, count);
	if (len < 0) {
		ret = -EINVAL;
		goto out;
	}

	ret = tun_do_read(tun, tfile, iocb, iv, len,
			  file->f_flags & O_NONBLOCK, NULL);
	ret = min_t(ssize_t, ret, len);
out:
	tun_put(tun);
	return ret;
}

static void tun_free_netdev(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);

	BUG_ON(!(list_empty(&tun->disabled)));
	free_percpu(tun->pcpu_stats);
	tun_flow_uninit(tun);
	security_tun_dev_free_security(tun->security);

#ifdef CONFIG_VE_TUNTAP_ACCOUNTING
	if (tun->vestat) {
		venet_acct_put_stat(tun->vestat);
		tun->vestat = NULL;
	}
#endif /* CONFIG_VE_TUNTAP_ACCOUNTING */
}

static void tun_setup(struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);

	tun->owner = INVALID_UID;
	tun->group = INVALID_GID;

	dev->ethtool_ops = &tun_ethtool_ops;
	dev->extended->needs_free_netdev = true;
	dev->extended->priv_destructor = tun_free_netdev;
	/* We prefer our own queue length */
	dev->tx_queue_len = TUN_READQ_SIZE;
}

/* Trivial set of netlink ops to allow deleting tun or tap
 * device with netlink.
 */
static int tun_validate(struct nlattr *tb[], struct nlattr *data[])
{
	return -EINVAL;
}

static size_t tun_get_size(const struct net_device *dev)
{
	BUILD_BUG_ON(sizeof(u32) != sizeof(uid_t));
	BUILD_BUG_ON(sizeof(u32) != sizeof(gid_t));

	return nla_total_size(sizeof(uid_t)) + /* OWNER */
	       nla_total_size(sizeof(gid_t)) + /* GROUP */
	       nla_total_size(sizeof(u8)) + /* TYPE */
	       nla_total_size(sizeof(u8)) + /* PI */
	       nla_total_size(sizeof(u8)) + /* VNET_HDR */
	       nla_total_size(sizeof(u8)) + /* PERSIST */
	       nla_total_size(sizeof(u8)) + /* MULTI_QUEUE */
	       nla_total_size(sizeof(u32)) + /* NUM_QUEUES */
	       nla_total_size(sizeof(u32)) + /* NUM_DISABLED_QUEUES */
	       0;
}

static int tun_fill_info(struct sk_buff *skb, const struct net_device *dev)
{
	struct tun_struct *tun = netdev_priv(dev);

	if (nla_put_u8(skb, IFLA_TUN_TYPE, tun->flags & TUN_TYPE_MASK))
		goto nla_put_failure;
	if (uid_valid(tun->owner) &&
	    nla_put_u32(skb, IFLA_TUN_OWNER,
			from_kuid_munged(current_user_ns(), tun->owner)))
		goto nla_put_failure;
	if (gid_valid(tun->group) &&
	    nla_put_u32(skb, IFLA_TUN_GROUP,
			from_kgid_munged(current_user_ns(), tun->group)))
		goto nla_put_failure;
	if (nla_put_u8(skb, IFLA_TUN_PI, !(tun->flags & IFF_NO_PI)))
		goto nla_put_failure;
	if (nla_put_u8(skb, IFLA_TUN_VNET_HDR, !!(tun->flags & IFF_VNET_HDR)))
		goto nla_put_failure;
	if (nla_put_u8(skb, IFLA_TUN_PERSIST, !!(tun->flags & IFF_PERSIST)))
		goto nla_put_failure;
	if (nla_put_u8(skb, IFLA_TUN_MULTI_QUEUE,
		       !!(tun->flags & IFF_MULTI_QUEUE)))
		goto nla_put_failure;
	if (tun->flags & IFF_MULTI_QUEUE) {
		if (nla_put_u32(skb, IFLA_TUN_NUM_QUEUES, tun->numqueues))
			goto nla_put_failure;
		if (nla_put_u32(skb, IFLA_TUN_NUM_DISABLED_QUEUES,
				tun->numdisabled))
			goto nla_put_failure;
	}

	return 0;

nla_put_failure:
	return -EMSGSIZE;
}

static struct rtnl_link_ops tun_link_ops __read_mostly = {
	.kind		= DRV_NAME,
	.priv_size	= sizeof(struct tun_struct),
	.setup		= tun_setup,
	.validate	= tun_validate,
	.get_size       = tun_get_size,
	.fill_info      = tun_fill_info,
};

static void tun_sock_write_space(struct sock *sk)
{
	struct tun_file *tfile;
	wait_queue_head_t *wqueue;

	if (!sock_writeable(sk))
		return;

	if (!test_and_clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags))
		return;

	wqueue = sk_sleep(sk);
	if (wqueue && waitqueue_active(wqueue))
		wake_up_interruptible_sync_poll(wqueue, POLLOUT |
						POLLWRNORM | POLLWRBAND);

	tfile = container_of(sk, struct tun_file, sk);
	kill_fasync(&tfile->fasync, SIGIO, POLL_OUT);
}

static int tun_sendmsg(struct kiocb *iocb, struct socket *sock,
		       struct msghdr *m, size_t total_len)
{
	int ret;
	struct tun_file *tfile = container_of(sock, struct tun_file, socket);
	struct tun_struct *tun = __tun_get(tfile);

	if (!tun)
		return -EBADFD;
	ret = tun_get_user(tun, tfile, m->msg_control, m->msg_iov, total_len,
			   m->msg_iovlen, m->msg_flags & MSG_DONTWAIT,
			   m->msg_flags & MSG_MORE);
	tun_put(tun);
	return ret;
}


static int tun_recvmsg(struct kiocb *iocb, struct socket *sock,
		       struct msghdr *m, size_t total_len,
		       int flags)
{
	struct tun_file *tfile = container_of(sock, struct tun_file, socket);
	struct tun_struct *tun = __tun_get(tfile);
	struct sk_buff *skb = m->msg_control;
	int ret;

	if (!tun) {
		ret = -EBADFD;
		goto out_free_skb;
	}

	if (flags & ~(MSG_DONTWAIT|MSG_TRUNC)) {
		ret = -EINVAL;
		goto out_put_tun;
	}
	ret = tun_do_read(tun, tfile, iocb, m->msg_iov, total_len,
			  flags & MSG_DONTWAIT, skb);
	if (ret > total_len) {
		m->msg_flags |= MSG_TRUNC;
		ret = flags & MSG_TRUNC ? ret : total_len;
	}

	tun_put(tun);
	return ret;

out_put_tun:
	tun_put(tun);
out_free_skb:
	if (skb)
		kfree_skb(skb);
	return ret;
}

static int tun_release(struct socket *sock)
{
	if (sock->sk)
		sock_put(sock->sk);
	return 0;
}

static int tun_peek_len(struct socket *sock)
{
	struct tun_file *tfile = container_of(sock, struct tun_file, socket);
	struct tun_struct *tun;
	int ret = 0;

	tun = __tun_get(tfile);
	if (!tun)
		return 0;

	ret = skb_array_peek_len(&tfile->tx_array);
	tun_put(tun);

	return ret;
}

/* Ops structure to mimic raw sockets with tun */
static const struct proto_ops tun_socket_ops = {
	.peek_len = tun_peek_len,
	.sendmsg = tun_sendmsg,
	.recvmsg = tun_recvmsg,
	.release = tun_release,
};

static struct proto tun_proto = {
	.name		= "tun",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tun_file),
};

static int tun_flags(struct tun_struct *tun)
{
	return tun->flags & (TUN_FEATURES | IFF_PERSIST | IFF_TUN | IFF_TAP);
}

static ssize_t tun_show_flags(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct tun_struct *tun = netdev_priv(to_net_dev(dev));
	return sprintf(buf, "0x%x\n", tun_flags(tun));
}

static ssize_t tun_show_owner(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct tun_struct *tun = netdev_priv(to_net_dev(dev));
	return uid_valid(tun->owner)?
		sprintf(buf, "%u\n",
			from_kuid_munged(current_user_ns(), tun->owner)):
		sprintf(buf, "-1\n");
}

static ssize_t tun_show_group(struct device *dev, struct device_attribute *attr,
			      char *buf)
{
	struct tun_struct *tun = netdev_priv(to_net_dev(dev));
	return gid_valid(tun->group) ?
		sprintf(buf, "%u\n",
			from_kgid_munged(current_user_ns(), tun->group)):
		sprintf(buf, "-1\n");
}

static DEVICE_ATTR(tun_flags, 0444, tun_show_flags, NULL);
static DEVICE_ATTR(owner, 0444, tun_show_owner, NULL);
static DEVICE_ATTR(group, 0444, tun_show_group, NULL);

static int tun_set_iff(struct net *net, struct file *file, struct ifreq *ifr)
{
	struct tun_struct *tun;
	struct tun_file *tfile = file->private_data;
	struct net_device *dev;
	int err;

	if (tfile->detached)
		return -EINVAL;

	dev = __dev_get_by_name(net, ifr->ifr_name);
	if (dev) {
		if (ifr->ifr_flags & IFF_TUN_EXCL)
			return -EBUSY;
		if ((ifr->ifr_flags & IFF_TUN) && dev->netdev_ops == &tun_netdev_ops)
			tun = netdev_priv(dev);
		else if ((ifr->ifr_flags & IFF_TAP) && dev->netdev_ops == &tap_netdev_ops)
			tun = netdev_priv(dev);
		else
			return -EINVAL;

		if (!!(ifr->ifr_flags & IFF_MULTI_QUEUE) !=
		    !!(tun->flags & IFF_MULTI_QUEUE))
			return -EINVAL;

		if (tun_not_capable(tun))
			return -EPERM;
		err = security_tun_dev_open(tun->security);
		if (err < 0)
			return err;

		err = tun_attach(tun, file, ifr->ifr_flags & IFF_NOFILTER);
		if (err < 0)
			return err;

		if (tun->flags & IFF_MULTI_QUEUE &&
		    (tun->numqueues + tun->numdisabled > 1)) {
			/* One or more queue has already been attached, no need
			 * to initialize the device again.
			 */
			netdev_state_change(dev);
			return 0;
		}

		tun->flags = (tun->flags & ~TUN_FEATURES) |
			      (ifr->ifr_flags & TUN_FEATURES);

		netdev_state_change(dev);
	} else {
		char *name;
		unsigned long flags = 0;
		int queues = ifr->ifr_flags & IFF_MULTI_QUEUE ?
			     MAX_TAP_QUEUES : 1;

		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			return -EPERM;
		err = security_tun_dev_create();
		if (err < 0)
			return err;

		/* Set dev type */
		if (ifr->ifr_flags & IFF_TUN) {
			/* TUN device */
			flags |= IFF_TUN;
			name = "tun%d";
		} else if (ifr->ifr_flags & IFF_TAP) {
			/* TAP device */
			flags |= IFF_TAP;
			name = "tap%d";
		} else
			return -EINVAL;

		if (*ifr->ifr_name)
			name = ifr->ifr_name;

		dev = alloc_netdev_mqs(sizeof(struct tun_struct), name,
				       tun_setup, queues, queues);

		if (!dev)
			return -ENOMEM;
		err = dev_get_valid_name(net, dev, name);
		if (err < 0)
			goto err_free_dev;

		dev_net_set(dev, net);
		dev->rtnl_link_ops = &tun_link_ops;
		dev->ifindex = tfile->ifindex;

		tun = netdev_priv(dev);
		tun->dev = dev;
		tun->flags = flags;
		tun->txflt.count = 0;
		tun->vnet_hdr_sz = sizeof(struct virtio_net_hdr);

		tun->align = NET_SKB_PAD;
		tun->filter_attached = false;
		tun->sndbuf = tfile->socket.sk->sk_sndbuf;
		tun->rx_batched = 0;

		tun->pcpu_stats = netdev_alloc_pcpu_stats(struct tun_pcpu_stats);
		if (!tun->pcpu_stats) {
			err = -ENOMEM;
			goto err_free_dev;
		}

		spin_lock_init(&tun->lock);

		err = security_tun_dev_alloc_security(&tun->security);
		if (err < 0)
			goto err_free_stat;

		tun_net_init(dev);
		tun_flow_init(tun);

		dev->hw_features = NETIF_F_SG | NETIF_F_FRAGLIST |
				   TUN_USER_FEATURES | NETIF_F_HW_VLAN_CTAG_TX |
				   NETIF_F_HW_VLAN_STAG_TX;
		dev->features = dev->hw_features | NETIF_F_LLTX |
				   NETIF_F_VIRTUAL;
		dev->vlan_features = dev->features &
				     ~(NETIF_F_HW_VLAN_CTAG_TX |
				       NETIF_F_HW_VLAN_STAG_TX);

		tun->flags = (tun->flags & ~TUN_FEATURES) |
			      (ifr->ifr_flags & TUN_FEATURES);

		INIT_LIST_HEAD(&tun->disabled);
		err = tun_attach(tun, file, false);
		if (err < 0)
			goto err_free_flow;

		err = register_netdevice(tun->dev);
		if (err < 0)
			goto err_detach;

		if (device_create_file(&tun->dev->dev, &dev_attr_tun_flags) ||
		    device_create_file(&tun->dev->dev, &dev_attr_owner) ||
		    device_create_file(&tun->dev->dev, &dev_attr_group))
			pr_err("Failed to create tun sysfs files\n");
	}

	netif_carrier_on(tun->dev);

	tun_debug(KERN_INFO, tun, "tun_set_iff\n");

	/* Make sure persistent devices do not get stuck in
	 * xoff state.
	 */
	if (netif_running(tun->dev))
		netif_tx_wake_all_queues(tun->dev);

	strcpy(ifr->ifr_name, tun->dev->name);
	return 0;

err_detach:
	tun_detach_all(dev);
	/* register_netdevice() already called tun_free_netdev() */
	goto err_free_dev;

err_free_flow:
	tun_flow_uninit(tun);
	security_tun_dev_free_security(tun->security);
err_free_stat:
	free_percpu(tun->pcpu_stats);
err_free_dev:
	free_netdev(dev);
	return err;
}

static void tun_get_iff(struct net *net, struct tun_struct *tun,
		       struct ifreq *ifr)
{
	tun_debug(KERN_INFO, tun, "tun_get_iff\n");

	strcpy(ifr->ifr_name, tun->dev->name);

	ifr->ifr_flags = tun_flags(tun);

}

/* This is like a cut-down ethtool ops, except done via tun fd so no
 * privs required. */
static int set_offload(struct tun_struct *tun, unsigned long arg)
{
	netdev_features_t features = 0;

	if (arg & TUN_F_CSUM) {
		features |= NETIF_F_HW_CSUM;
		arg &= ~TUN_F_CSUM;

		if (arg & (TUN_F_TSO4|TUN_F_TSO6)) {
			if (arg & TUN_F_TSO_ECN) {
				features |= NETIF_F_TSO_ECN;
				arg &= ~TUN_F_TSO_ECN;
			}
			if (arg & TUN_F_TSO4)
				features |= NETIF_F_TSO;
			if (arg & TUN_F_TSO6)
				features |= NETIF_F_TSO6;
			arg &= ~(TUN_F_TSO4|TUN_F_TSO6);
		}

		if (arg & TUN_F_UFO) {
			features |= NETIF_F_UFO;
			arg &= ~TUN_F_UFO;
		}
	}

	/* This gives the user a way to test for new features in future by
	 * trying to set them. */
	if (arg)
		return -EINVAL;

	tun->set_features = features;
	netdev_update_features(tun->dev);

	return 0;
}

static void tun_detach_filter(struct tun_struct *tun, int n)
{
	int i;
	struct tun_file *tfile;

	for (i = 0; i < n; i++) {
		tfile = rtnl_dereference(tun->tfiles[i]);
		lock_sock(tfile->socket.sk);
		sk_detach_filter(tfile->socket.sk);
		release_sock(tfile->socket.sk);
	}

	tun->filter_attached = false;
}

static int tun_attach_filter(struct tun_struct *tun)
{
	int i, ret = 0;
	struct tun_file *tfile;

	for (i = 0; i < tun->numqueues; i++) {
		tfile = rtnl_dereference(tun->tfiles[i]);
		lock_sock(tfile->socket.sk);
		ret = sk_attach_filter(&tun->fprog, tfile->socket.sk);
		release_sock(tfile->socket.sk);
		if (ret) {
			tun_detach_filter(tun, i);
			return ret;
		}
	}

	tun->filter_attached = true;
	return ret;
}

static void tun_set_sndbuf(struct tun_struct *tun)
{
	struct tun_file *tfile;
	int i;

	for (i = 0; i < tun->numqueues; i++) {
		tfile = rtnl_dereference(tun->tfiles[i]);
		tfile->socket.sk->sk_sndbuf = tun->sndbuf;
	}
}

static int tun_set_queue(struct file *file, struct ifreq *ifr)
{
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun;
	int ret = 0;

	rtnl_lock();

	if (ifr->ifr_flags & IFF_ATTACH_QUEUE) {
		tun = tfile->detached;
		if (!tun) {
			ret = -EINVAL;
			goto unlock;
		}
		ret = security_tun_dev_attach_queue(tun->security);
		if (ret < 0)
			goto unlock;
		ret = tun_attach(tun, file, false);
	} else if (ifr->ifr_flags & IFF_DETACH_QUEUE) {
		tun = rtnl_dereference(tfile->tun);
		if (!tun || !(tun->flags & IFF_MULTI_QUEUE) || tfile->detached)
			ret = -EINVAL;
		else
			__tun_detach(tfile, false);
	} else
		ret = -EINVAL;

	if (ret >= 0)
		netdev_state_change(tun->dev);

unlock:
	rtnl_unlock();
	return ret;
}

#ifdef CONFIG_VE_TUNTAP_ACCOUNTING
/* setacctid_ioctl should be called under rtnl_lock */
static int tun_set_acctid(struct net *net, struct ifreq *ifr)
{
	struct net_device *dev;
	struct tun_struct *tun;

	dev = __dev_get_by_name(net, ifr->ifr_name);
	if (dev == NULL)
		return -ENOENT;

	/* This check may be dropped to allow tun devices */
	if (dev->netdev_ops != &tap_netdev_ops)
		return -EINVAL;

	tun = netdev_priv(dev);
	if (tun->vestat) {
		venet_acct_put_stat(tun->vestat);
	}
	tun->vestat = venet_acct_find_create_stat(ifr->ifr_acctid);
	if (tun->vestat == NULL)
		return -ENOMEM;

	return 0;
}
#endif /* CONFIG_VE_TUNTAP_ACCOUNTING */

static long __tun_chr_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg, int ifreq_len)
{
	struct tun_file *tfile = file->private_data;
	struct tun_struct *tun = NULL;
	void __user* argp = (void __user*)arg;
	unsigned int ifindex, carrier;
	struct ifreq ifr;
	struct net *net;
	kuid_t owner;
	kgid_t group;
	int sndbuf;
	int vnet_hdr_sz;
	int le;
	int ret;
	bool do_notify = false;

	if (cmd == TUNSETIFF || cmd == TUNSETQUEUE || cmd == TUNSETACCTID ||
	    (_IOC_TYPE(cmd) == 0x89 && cmd != SIOCGSKNS)) {
		if (copy_from_user(&ifr, argp, ifreq_len))
			return -EFAULT;
	} else {
		memset(&ifr, 0, sizeof(ifr));
	}
	if (cmd == TUNGETFEATURES) {
		/* Currently this just means: "what IFF flags are valid?".
		 * This is needed because we never checked for invalid flags on
		 * TUNSETIFF.
		 */
		return put_user(IFF_TUN | IFF_TAP | TUN_FEATURES,
				(unsigned int __user*)argp);
	} else if (cmd == TUNSETQUEUE)
		return tun_set_queue(file, &ifr);

	ret = 0;
	rtnl_lock();

#ifdef CONFIG_VE_TUNTAP_ACCOUNTING
	if (cmd == TUNSETACCTID) {
		ret = tun_set_acctid(tfile->net, &ifr);
		goto unlock;
	}
#endif /* CONFIG_VE_TUNTAP_ACCOUNTING */

	tun = __tun_get(tfile);
	net = sock_net(&tfile->sk);
	if (cmd == TUNSETIFF) {
		ret = -EEXIST;
		if (tun)
			goto unlock;
		ifr.ifr_name[IFNAMSIZ-1] = '\0';

		ret = tun_set_iff(tfile->net, file, &ifr);

		if (ret)
			goto unlock;

		if (copy_to_user(argp, &ifr, ifreq_len))
			ret = -EFAULT;
		goto unlock;
	}
	if (cmd == TUNSETIFINDEX) {
		ret = -EPERM;
		if (tun)
			goto unlock;

		ret = -EFAULT;
		if (copy_from_user(&ifindex, argp, sizeof(ifindex)))
			goto unlock;

		ret = 0;
		tfile->ifindex = ifindex;
		goto unlock;
	}
	if (cmd == SIOCGSKNS) {
		ret = -EPERM;
		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			goto unlock;

		ret = open_related_ns(&net->ns, get_net_ns);
		goto unlock;
	}

	ret = -EBADFD;
	if (!tun)
		goto unlock;

	tun_debug(KERN_INFO, tun, "tun_chr_ioctl cmd %u\n", cmd);

	net = dev_net(tun->dev);
	ret = 0;
	switch (cmd) {
	case TUNGETIFF:
		tun_get_iff(current->nsproxy->net_ns, tun, &ifr);

		if (tfile->detached)
			ifr.ifr_flags |= IFF_DETACH_QUEUE;
		if (!tfile->socket.sk->sk_filter)
			ifr.ifr_flags |= IFF_NOFILTER;

		if (copy_to_user(argp, &ifr, ifreq_len))
			ret = -EFAULT;
		break;

	case TUNSETNOCSUM:
		/* Disable/Enable checksum */

		/* [unimplemented] */
		tun_debug(KERN_INFO, tun, "ignored: set checksum %s\n",
			  arg ? "disabled" : "enabled");
		break;

	case TUNSETPERSIST:
		/* Disable/Enable persist mode. Keep an extra reference to the
		 * module to prevent the module being unprobed.
		 */
		if (arg && !(tun->flags & IFF_PERSIST)) {
			tun->flags |= IFF_PERSIST;
			__module_get(THIS_MODULE);
			do_notify = true;
		}
		if (!arg && (tun->flags & IFF_PERSIST)) {
			tun->flags &= ~IFF_PERSIST;
			module_put(THIS_MODULE);
			do_notify = true;
		}

		tun_debug(KERN_INFO, tun, "persist %s\n",
			  arg ? "enabled" : "disabled");
		break;

	case TUNSETOWNER:
		/* Set owner of the device */
		owner = make_kuid(current_user_ns(), arg);
		if (!uid_valid(owner)) {
			ret = -EINVAL;
			break;
		}
		tun->owner = owner;
		do_notify = true;
		tun_debug(KERN_INFO, tun, "owner set to %u\n",
			  from_kuid(&init_user_ns, tun->owner));
		break;

	case TUNSETGROUP:
		/* Set group of the device */
		group = make_kgid(current_user_ns(), arg);
		if (!gid_valid(group)) {
			ret = -EINVAL;
			break;
		}
		tun->group = group;
		do_notify = true;
		tun_debug(KERN_INFO, tun, "group set to %u\n",
			  from_kgid(&init_user_ns, tun->group));
		break;

	case TUNSETLINK:
		/* Only allow setting the type when the interface is down */
		if (tun->dev->flags & IFF_UP) {
			tun_debug(KERN_INFO, tun,
				  "Linktype set failed because interface is up\n");
			ret = -EBUSY;
		} else {
			tun->dev->type = (int) arg;
			tun_debug(KERN_INFO, tun, "linktype set to %d\n",
				  tun->dev->type);
			ret = 0;
		}
		break;

#ifdef TUN_DEBUG
	case TUNSETDEBUG:
		tun->debug = arg;
		break;
#endif
	case TUNSETOFFLOAD:
		ret = set_offload(tun, arg);
		break;

	case TUNSETTXFILTER:
		/* Can be set only for TAPs */
		ret = -EINVAL;
		if ((tun->flags & TUN_TYPE_MASK) != IFF_TAP)
			break;
		ret = update_filter(&tun->txflt, (void __user *)arg);
		break;

	case SIOCGIFHWADDR:
		/* Get hw address */
		memcpy(ifr.ifr_hwaddr.sa_data, tun->dev->dev_addr, ETH_ALEN);
		ifr.ifr_hwaddr.sa_family = tun->dev->type;
		if (copy_to_user(argp, &ifr, ifreq_len))
			ret = -EFAULT;
		break;

	case SIOCSIFHWADDR:
		/* Set hw address */
		tun_debug(KERN_DEBUG, tun, "set hw address: %pM\n",
			  ifr.ifr_hwaddr.sa_data);

		ret = dev_set_mac_address(tun->dev, &ifr.ifr_hwaddr);
		break;

	case TUNGETSNDBUF:
		sndbuf = tfile->socket.sk->sk_sndbuf;
		if (copy_to_user(argp, &sndbuf, sizeof(sndbuf)))
			ret = -EFAULT;
		break;

	case TUNSETSNDBUF:
		if (copy_from_user(&sndbuf, argp, sizeof(sndbuf))) {
			ret = -EFAULT;
			break;
		}
		if (sndbuf <= 0) {
			ret = -EINVAL;
			break;
		}

		tun->sndbuf = sndbuf;
		tun_set_sndbuf(tun);
		break;

	case TUNGETVNETHDRSZ:
		vnet_hdr_sz = tun->vnet_hdr_sz;
		if (copy_to_user(argp, &vnet_hdr_sz, sizeof(vnet_hdr_sz)))
			ret = -EFAULT;
		break;

	case TUNSETVNETHDRSZ:
		if (copy_from_user(&vnet_hdr_sz, argp, sizeof(vnet_hdr_sz))) {
			ret = -EFAULT;
			break;
		}
		if (vnet_hdr_sz < (int)sizeof(struct virtio_net_hdr)) {
			ret = -EINVAL;
			break;
		}

		tun->vnet_hdr_sz = vnet_hdr_sz;
		break;

	case TUNGETVNETLE:
		le = !!(tun->flags & TUN_VNET_LE);
		if (put_user(le, (int __user *)argp))
			ret = -EFAULT;
		break;

	case TUNSETVNETLE:
		if (get_user(le, (int __user *)argp)) {
			ret = -EFAULT;
			break;
		}
		if (le)
			tun->flags |= TUN_VNET_LE;
		else
			tun->flags &= ~TUN_VNET_LE;
		break;

	case TUNGETVNETBE:
		ret = tun_get_vnet_be(tun, argp);
		break;

	case TUNSETVNETBE:
		ret = tun_set_vnet_be(tun, argp);
		break;

	case TUNATTACHFILTER:
		/* Can be set only for TAPs */
		ret = -EINVAL;
		if ((tun->flags & TUN_TYPE_MASK) != IFF_TAP)
			break;
		ret = -EFAULT;
		if (copy_from_user(&tun->fprog, argp, sizeof(tun->fprog)))
			break;

		ret = tun_attach_filter(tun);
		break;

	case TUNDETACHFILTER:
		/* Can be set only for TAPs */
		ret = -EINVAL;
		if ((tun->flags & TUN_TYPE_MASK) != IFF_TAP)
			break;
		ret = 0;
		tun_detach_filter(tun, tun->numqueues);
		break;

	case TUNGETFILTER:
		ret = -EINVAL;
		if ((tun->flags & TUN_TYPE_MASK) != TUN_TAP_DEV)
			break;
		ret = -EFAULT;
		if (copy_to_user(argp, &tun->fprog, sizeof(tun->fprog)))
			break;
		ret = 0;
		break;

	case TUNSETCARRIER:
		ret = -EFAULT;
		if (copy_from_user(&carrier, argp, sizeof(carrier)))
			goto unlock;

		ret = tun_net_change_carrier(tun->dev, (bool)carrier);
		break;

	case TUNGETDEVNETNS:
		ret = -EPERM;
		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			goto unlock;
		ret = open_related_ns(&net->ns, get_net_ns);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	if (do_notify)
		netdev_state_change(tun->dev);

unlock:
	rtnl_unlock();
	if (tun)
		tun_put(tun);
	return ret;
}

static long tun_chr_ioctl(struct file *file,
			  unsigned int cmd, unsigned long arg)
{
	return __tun_chr_ioctl(file, cmd, arg, sizeof (struct ifreq));
}

#ifdef CONFIG_COMPAT
static long tun_chr_compat_ioctl(struct file *file,
			 unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case TUNSETIFF:
	case TUNGETIFF:
	case TUNSETTXFILTER:
	case TUNGETSNDBUF:
	case TUNSETSNDBUF:
	case SIOCGIFHWADDR:
	case SIOCSIFHWADDR:
		arg = (unsigned long)compat_ptr(arg);
		break;
	default:
		arg = (compat_ulong_t)arg;
		break;
	}

	/*
	 * compat_ifreq is shorter than ifreq, so we must not access beyond
	 * the end of that structure. All fields that are used in this
	 * driver are compatible though, we don't need to convert the
	 * contents.
	 */
	return __tun_chr_ioctl(file, cmd, arg, sizeof(struct compat_ifreq));
}
#endif /* CONFIG_COMPAT */

static int tun_chr_fasync(int fd, struct file *file, int on)
{
	struct tun_file *tfile = file->private_data;
	int ret;

	if ((ret = fasync_helper(fd, file, on, &tfile->fasync)) < 0)
		goto out;

	if (on) {
		ret = __f_setown(file, task_pid(current), PIDTYPE_PID, 0);
		if (ret)
			goto out;
		tfile->flags |= TUN_FASYNC;
	} else
		tfile->flags &= ~TUN_FASYNC;
	ret = 0;
out:
	return ret;
}

static int tun_chr_open(struct inode *inode, struct file * file)
{
	struct tun_file *tfile;

	DBG1(KERN_INFO, "tunX: tun_chr_open\n");

	tfile = (struct tun_file *)sk_alloc(&init_net, AF_UNSPEC, GFP_KERNEL,
					    &tun_proto);
	if (!tfile)
		return -ENOMEM;
	if (skb_array_init(&tfile->tx_array, 0, GFP_KERNEL)) {
		sk_free(&tfile->sk);
		return -ENOMEM;
	}
	rcu_assign_pointer(tfile->tun, NULL);
	tfile->net = get_net(current->nsproxy->net_ns);
	tfile->flags = 0;
	tfile->ifindex = 0;

	rcu_assign_pointer(tfile->socket.wq, &tfile->wq);
	init_waitqueue_head(&tfile->wq.wait);

	tfile->socket.file = file;
	tfile->socket.ops = &tun_socket_ops;

	sock_init_data(&tfile->socket, &tfile->sk);
	sk_change_net(&tfile->sk, tfile->net);

	tfile->sk.sk_write_space = tun_sock_write_space;
	tfile->sk.sk_sndbuf = INT_MAX;

	file->private_data = tfile;
	set_bit(SOCK_EXTERNALLY_ALLOCATED, &tfile->socket.flags);
	INIT_LIST_HEAD(&tfile->next);

	sock_set_flag(&tfile->sk, SOCK_ZEROCOPY);

	return 0;
}

static int tun_chr_close(struct inode *inode, struct file *file)
{
	struct tun_file *tfile = file->private_data;
	struct net *net = tfile->net;

	tun_detach(tfile, true);
	put_net(net);

	return 0;
}

#ifdef CONFIG_PROC_FS
static int tun_chr_show_fdinfo(struct seq_file *m, struct file *f)
{
	struct tun_struct *tun;
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));

	rtnl_lock();
	tun = tun_get(f);
	if (tun)
		tun_get_iff(current->nsproxy->net_ns, tun, &ifr);
	rtnl_unlock();

	if (tun)
		tun_put(tun);

	return seq_printf(m, "iff:\t%s\n", ifr.ifr_name);
}
#endif

static const struct file_operations tun_fops = {
	.owner	= THIS_MODULE,
	.llseek = no_llseek,
	.read  = do_sync_read,
	.aio_read  = tun_chr_aio_read,
	.write = do_sync_write,
	.aio_write = tun_chr_aio_write,
	.poll	= tun_chr_poll,
	.unlocked_ioctl	= tun_chr_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = tun_chr_compat_ioctl,
#endif
	.open	= tun_chr_open,
	.release = tun_chr_close,
	.fasync = tun_chr_fasync,
#ifdef CONFIG_PROC_FS
	.show_fdinfo = tun_chr_show_fdinfo,
#endif
};

static struct miscdevice tun_miscdev = {
	.minor = TUN_MINOR,
	.name = "tun",
	.nodename = "net/tun",
	.fops = &tun_fops,
};

/* ethtool interface */

static int tun_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	cmd->supported		= 0;
	cmd->advertising	= 0;
	ethtool_cmd_speed_set(cmd, SPEED_10);
	cmd->duplex		= DUPLEX_FULL;
	cmd->port		= PORT_TP;
	cmd->phy_address	= 0;
	cmd->transceiver	= XCVR_INTERNAL;
	cmd->autoneg		= AUTONEG_DISABLE;
	cmd->maxtxpkt		= 0;
	cmd->maxrxpkt		= 0;
	return 0;
}

static void tun_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	struct tun_struct *tun = netdev_priv(dev);

	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));

	switch (tun->flags & TUN_TYPE_MASK) {
	case IFF_TUN:
		strlcpy(info->bus_info, "tun", sizeof(info->bus_info));
		break;
	case IFF_TAP:
		strlcpy(info->bus_info, "tap", sizeof(info->bus_info));
		break;
	}
}

static u32 tun_get_msglevel(struct net_device *dev)
{
#ifdef TUN_DEBUG
	struct tun_struct *tun = netdev_priv(dev);
	return tun->debug;
#else
	return -EOPNOTSUPP;
#endif
}

static void tun_set_msglevel(struct net_device *dev, u32 value)
{
#ifdef TUN_DEBUG
	struct tun_struct *tun = netdev_priv(dev);
	tun->debug = value;
#endif
}

static int tun_get_coalesce(struct net_device *dev,
			    struct ethtool_coalesce *ec)
{
	struct tun_struct *tun = netdev_priv(dev);

	ec->rx_max_coalesced_frames = tun->rx_batched;

	return 0;
}

static int tun_set_coalesce(struct net_device *dev,
			    struct ethtool_coalesce *ec)
{
	struct tun_struct *tun = netdev_priv(dev);

	if (ec->rx_max_coalesced_frames > NAPI_POLL_WEIGHT)
		tun->rx_batched = NAPI_POLL_WEIGHT;
	else
		tun->rx_batched = ec->rx_max_coalesced_frames;

	return 0;
}

static const struct ethtool_ops tun_ethtool_ops = {
	.get_settings	= tun_get_settings,
	.get_drvinfo	= tun_get_drvinfo,
	.get_msglevel	= tun_get_msglevel,
	.set_msglevel	= tun_set_msglevel,
	.get_link	= ethtool_op_get_link,
	.get_coalesce   = tun_get_coalesce,
	.set_coalesce   = tun_set_coalesce,
};

static int tun_queue_resize(struct tun_struct *tun)
{
	struct net_device *dev = tun->dev;
	struct tun_file *tfile;
	struct skb_array **arrays;
	int n = tun->numqueues + tun->numdisabled;
	int ret, i;

	arrays = kmalloc(sizeof *arrays * n, GFP_KERNEL);
	if (!arrays)
		return -ENOMEM;

	for (i = 0; i < tun->numqueues; i++) {
		tfile = rtnl_dereference(tun->tfiles[i]);
		arrays[i] = &tfile->tx_array;
	}
	list_for_each_entry(tfile, &tun->disabled, next)
		arrays[i++] = &tfile->tx_array;

	ret = skb_array_resize_multiple(arrays, n,
					dev->tx_queue_len, GFP_KERNEL);

	kfree(arrays);
	return ret;
}

static int tun_device_event(struct notifier_block *unused,
			    unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct tun_struct *tun = netdev_priv(dev);

	if (dev->rtnl_link_ops != &tun_link_ops)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_CHANGE_TX_QUEUE_LEN:
		if (tun_queue_resize(tun))
			return NOTIFY_BAD;
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block tun_notifier_block __read_mostly = {
	.notifier_call	= tun_device_event,
};

static int __init tun_init(void)
{
	int ret = 0;

	pr_info("%s, %s\n", DRV_DESCRIPTION, DRV_VERSION);
	pr_info("%s\n", DRV_COPYRIGHT);

	ret = rtnl_link_register(&tun_link_ops);
	if (ret) {
		pr_err("Can't register link_ops\n");
		goto err_linkops;
	}

	ret = misc_register(&tun_miscdev);
	if (ret) {
		pr_err("Can't register misc device %d\n", TUN_MINOR);
		goto err_misc;
	}

	register_netdevice_notifier_rh(&tun_notifier_block);
	return  0;
err_misc:
	rtnl_link_unregister(&tun_link_ops);
err_linkops:
	return ret;
}

static void tun_cleanup(void)
{
	misc_deregister(&tun_miscdev);
	rtnl_link_unregister(&tun_link_ops);
	unregister_netdevice_notifier_rh(&tun_notifier_block);
}

/* Get an underlying socket object from tun file.  Returns error unless file is
 * attached to a device.  The returned object works like a packet socket, it
 * can be used for sock_sendmsg/sock_recvmsg.  The caller is responsible for
 * holding a reference to the file for as long as the socket is in use. */
struct socket *tun_get_socket(struct file *file)
{
	struct tun_file *tfile;
	if (file->f_op != &tun_fops)
		return ERR_PTR(-EINVAL);
	tfile = file->private_data;
	if (!tfile)
		return ERR_PTR(-EBADFD);
	return &tfile->socket;
}
EXPORT_SYMBOL_GPL(tun_get_socket);

struct skb_array *tun_get_skb_array(struct file *file)
{
	struct tun_file *tfile;

	if (file->f_op != &tun_fops)
		return ERR_PTR(-EINVAL);
	tfile = file->private_data;
	if (!tfile)
		return ERR_PTR(-EBADFD);
	return &tfile->tx_array;
}
EXPORT_SYMBOL_GPL(tun_get_skb_array);

module_init(tun_init);
module_exit(tun_cleanup);
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
MODULE_ALIAS_MISCDEV(TUN_MINOR);
MODULE_ALIAS("devname:net/tun");
