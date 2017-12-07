/*
 *  venet_core.c
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

/*
 * Common part for Virtuozzo virtual network devices
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/in.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/tcp.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/addrconf.h>

#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/unistd.h>

#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/ip.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/if_ether.h>	/* For the statistics structure. */
#include <linux/if_arp.h>	/* For ARPHRD_ETHER */
#include <linux/ethtool.h>
#include <linux/venet.h>
#include <linux/ve_proto.h>
#include <linux/vzctl.h>
#include <uapi/linux/vzctl_venet.h>
#include <linux/ve.h>
#include <linux/venet-netlink.h>

struct hlist_head ip_entry_hash_table[VEIP_HASH_SZ];
DEFINE_SPINLOCK(veip_lock);
LIST_HEAD(veip_lh);
static struct rtnl_link_ops venet_link_ops;

#define ip_entry_hash_function(ip)  (ntohl(ip) & (VEIP_HASH_SZ - 1))

void ip_entry_hash(struct ip_entry_struct *entry, struct veip_struct *veip)
{
	hlist_add_head_rcu(&entry->ip_hash,
			ip_entry_hash_table +
			ip_entry_hash_function(entry->addr.key[3]));
	list_add(&entry->ve_list, &veip->ip_lh);
}

static void ip_entry_free(struct rcu_head *rcu)
{
	struct ip_entry_struct *e;

	e = container_of(rcu, struct ip_entry_struct, rcu);
	kfree(e);
}

void ip_entry_unhash(struct ip_entry_struct *entry)
{
	list_del(&entry->ve_list);
	hlist_del_rcu(&entry->ip_hash);
	call_rcu(&entry->rcu, ip_entry_free);
}

static void veip_free(struct rcu_head *rcu)
{
	struct veip_struct *veip;

	veip = container_of(rcu, struct veip_struct, rcu);
	veip_pool_ops->veip_free(veip);
}

int veip_put(struct veip_struct *veip)
{
	if (!list_empty(&veip->ip_lh))
		return 0;
	if (!list_empty(&veip->src_lh))
		return 0;
	if (!list_empty(&veip->dst_lh))
		return 0;

	list_del(&veip->list);
	call_rcu(&veip->rcu, veip_free);
	return 1;
}

struct ip_entry_struct *venet_entry_lookup(struct ve_addr_struct *addr)
{
	struct ip_entry_struct *entry;

	hlist_for_each_entry_rcu(entry, ip_entry_hash_table +
			ip_entry_hash_function(addr->key[3]), ip_hash)
		if (memcmp(&entry->addr, addr, sizeof(*addr)) == 0)
			return entry;
	return NULL;
}

struct ext_entry_struct *venet_ext_lookup(struct ve_struct *ve,
		struct ve_addr_struct *addr)
{
	struct ext_entry_struct *entry;
	struct veip_struct *veip;

	veip = ACCESS_ONCE(ve->veip);
	if (veip == NULL)
		return NULL;

	list_for_each_entry_rcu (entry, &veip->ext_lh, list)
		if (memcmp(&entry->addr, addr, sizeof(*addr)) == 0)
			return entry;
	return NULL;
}

static int venet_ext_add(struct ve_struct *ve, struct ve_addr_struct *addr)
{
	struct ext_entry_struct *entry, *found;
	int err;

	if (ve->veip == NULL)
		return -ENONET;

	entry = kzalloc(sizeof(struct ext_entry_struct), GFP_KERNEL);
	if (entry == NULL)
		return -ENOMEM;

	spin_lock(&veip_lock);
	err = -EADDRINUSE;
	found = venet_ext_lookup(ve, addr);
	if (found != NULL)
		goto out_unlock;

	entry->addr = *addr;
	list_add_rcu(&entry->list, &ve->veip->ext_lh);
	err = 0;
	entry = NULL;
out_unlock:
	spin_unlock(&veip_lock);
	if (entry != NULL)
		kfree(entry);
	return err;
}

static void venet_ext_free(struct rcu_head *rcu)
{
	struct ext_entry_struct *e;

	e = container_of(rcu, struct ext_entry_struct, rcu);
	kfree(e);
}

static void venet_ext_release(struct ext_entry_struct *e)
{
	list_del_rcu(&e->list);
	call_rcu(&e->rcu, venet_ext_free);
}

static int venet_ext_del(struct ve_struct *ve, struct ve_addr_struct *addr)
{
	struct ext_entry_struct *found;
	int err;

	if (ve->veip == NULL)
		return -ENONET;

	err = -EADDRNOTAVAIL;
	spin_lock(&veip_lock);
	found = venet_ext_lookup(ve, addr);
	if (found == NULL)
		goto out;

	venet_ext_release(found);
	err = 0;
out:
	spin_unlock(&veip_lock);
	return err;
}

static void __venet_ext_clean(struct ve_struct *ve)
{
	struct ext_entry_struct *entry, *tmp;

	list_for_each_entry_safe (entry, tmp, &ve->veip->ext_lh, list)
		venet_ext_release(entry);
}

static struct veip_struct *veip_find(envid_t veid)
{
	struct veip_struct *ptr;

	list_for_each_entry(ptr, &veip_lh, list) {
		if (ptr->veid != veid)
			continue;
		return ptr;
	}
	return NULL;
}

struct veip_struct *veip_findcreate(envid_t veid)
{
	struct veip_struct *ptr;

	ptr = veip_find(veid);
	if (ptr != NULL)
		return ERR_PTR(-EEXIST);

	ptr = kmalloc(sizeof(struct veip_struct), GFP_ATOMIC);
	if (ptr == NULL)
		return NULL;
	memset(ptr, 0, sizeof(struct veip_struct));
	INIT_LIST_HEAD(&ptr->ip_lh);
	INIT_LIST_HEAD(&ptr->src_lh);
	INIT_LIST_HEAD(&ptr->dst_lh);
	INIT_LIST_HEAD(&ptr->ext_lh);
	ptr->veid = veid;
	list_add(&ptr->list, &veip_lh);
	return ptr;
}

static int veip_start(struct ve_struct *ve)
{
	int err, get;

	spin_lock(&veip_lock);

	get = ve->veip == NULL;
	err = veip_pool_ops->veip_create(ve);
	if (!err && get && !ve_is_super(ve))
		__module_get(THIS_MODULE);

	spin_unlock(&veip_lock);

	return err;
}

static void __veip_stop(struct ve_struct *ve)
{
	struct list_head *p, *tmp;

	list_for_each_safe(p, tmp, &ve->veip->ip_lh) {
		struct ip_entry_struct *ptr;
		ptr = list_entry(p, struct ip_entry_struct, ve_list);
		ptr->active_env = NULL;
		ip_entry_unhash(ptr);
	}

	veip_pool_ops->veip_release(ve);
	if (!ve_is_super(ve))
		module_put(THIS_MODULE);
}

static void veip_stop(struct ve_struct *ve)
{
	spin_lock(&veip_lock);
	if (ve->veip)
		__veip_stop(ve);
	spin_unlock(&veip_lock);
}

static int veip_entry_conflict(struct ip_entry_struct *entry, struct ve_struct *ve)
{
	if (entry->active_env != NULL)
		return -EADDRINUSE;

	entry->active_env = ve;
	return 0;
}

static int veip_entry_add(struct ve_struct *ve, struct ve_addr_struct *addr)
{
	struct ip_entry_struct *entry, *found;
	int err;

	entry = kzalloc(sizeof(struct ip_entry_struct), GFP_KERNEL);
	if (entry == NULL)
		return -ENOMEM;

	if (ve->veip == NULL) {
		/* This can happen if we load venet AFTER ve was started */
	       	err = veip_start(ve);
		if (err < 0)
			goto out;
	}

	spin_lock(&veip_lock);
	found = venet_entry_lookup(addr);
	if (found != NULL) {
		err = veip_entry_conflict(found, ve);
		goto out_unlock;
	}

	entry->active_env = ve;
	entry->addr = *addr;
	ip_entry_hash(entry, ve->veip);

	err = 0;
	entry = NULL;
out_unlock:
	spin_unlock(&veip_lock);
out:
	if (entry != NULL)
		kfree(entry);

	return err;
}

static int veip_entry_del(struct ve_struct *ve, struct ve_addr_struct *addr)
{
	struct ip_entry_struct *found;
	int err;

	err = -EADDRNOTAVAIL;
	spin_lock(&veip_lock);
	found = venet_entry_lookup(addr);
	if (found == NULL)
		goto out;
	if (found->active_env == NULL)
		goto out;
	if (found->active_env->veid != ve->veid)
		goto out;

	err = 0;
	found->active_env = NULL;

	ip_entry_unhash(found);
out:
	spin_unlock(&veip_lock);
	return err;
}

static int convert_sockaddr(struct sockaddr *addr, int addrlen,
		struct ve_addr_struct *veaddr)
{
	int err;

	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin;

		err = -EINVAL;
		if (addrlen != sizeof(struct sockaddr_in))
			break;

		err = 0;
		sin = (struct sockaddr_in *)addr;
		veaddr->family = AF_INET;
		veaddr->key[0] = 0;
		veaddr->key[1] = 0;
		veaddr->key[2] = 0;
		veaddr->key[3] = sin->sin_addr.s_addr;
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin;

		err = -EINVAL;
		if (addrlen != sizeof(struct sockaddr_in6))
			break;

		err = 0;
		sin = (struct sockaddr_in6 *)addr;
		veaddr->family = AF_INET6;
		memcpy(veaddr->key, &sin->sin6_addr, sizeof(veaddr->key));
		break;
	}
	default:
		err = -EAFNOSUPPORT;
	}
	return err;
}

int sockaddr_to_veaddr(struct sockaddr __user *uaddr, int addrlen,
		struct ve_addr_struct *veaddr)
{
	int err;
	char addr[MAX_SOCK_ADDR];

	err = move_addr_to_kernel(uaddr, addrlen, (struct sockaddr_storage *)&addr);
	if (err < 0)
		goto out;

	err = convert_sockaddr((struct sockaddr *)&addr, addrlen, veaddr);
out:
	return err;
}

int in4_to_veaddr(const char *addr, struct ve_addr_struct *veaddr)
{
	veaddr->family = AF_INET;
	if (!in4_pton(addr, -1, (u8 *)(&veaddr->key[3]), -1, NULL))
		return -EINVAL;
	return 0;
}
EXPORT_SYMBOL(in4_to_veaddr);

int in6_to_veaddr(const char *addr, struct ve_addr_struct *veaddr)
{
	veaddr->family = AF_INET6;
	if (!in6_pton(addr, -1, (u8 *)(veaddr->key), -1, NULL))
		return -EINVAL;
	return 0;
}
EXPORT_SYMBOL(in6_to_veaddr);

void veaddr_print(char *str, int len, struct ve_addr_struct *a)
{
	if (a->family == AF_INET)
		snprintf(str, len, "%u.%u.%u.%u", NIPQUAD(a->key[3]));
	else
		snprintf(str, len, "%x:%x:%x:%x:%x:%x:%x:%x",
				ntohl(a->key[0])>>16, ntohl(a->key[0])&0xFFFF,
				ntohl(a->key[1])>>16, ntohl(a->key[1])&0xFFFF,
				ntohl(a->key[2])>>16, ntohl(a->key[2])&0xFFFF,
				ntohl(a->key[3])>>16, ntohl(a->key[3])&0xFFFF
			);
}

/*
 * Device functions
 */

static int venet_open(struct net_device *dev)
{
	if (!ve_is_super(get_exec_env()) && !try_module_get(THIS_MODULE))
		return -EBUSY;
	return 0;
}

static int venet_close(struct net_device *master)
{
	if (!ve_is_super(get_exec_env()))
		module_put(THIS_MODULE);
	return 0;
}

void (*venet_free_stat)(struct ve_struct *) = NULL;
EXPORT_SYMBOL(venet_free_stat);

static void venet_destructor(struct net_device *dev)
{
	struct venet_stats *stats = (struct venet_stats *)dev->ml_priv;

	if (venet_free_stat)
		venet_free_stat(dev->nd_net->owner_ve);

	free_percpu(stats->real_stats);
	kfree(stats);
	free_netdev(dev);
}

/*
 * The higher levels take care of making this non-reentrant (it's
 * called with bh's disabled).
 */
static int venet_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct net_device_stats *stats;
	struct net_device *rcv = NULL;
	struct ve_struct *ve;
	int length;

	stats = venet_stats(dev, smp_processor_id());
	ve = dev_net(dev)->owner_ve;

	if (skb->protocol == __constant_htons(ETH_P_IP)) {
		struct iphdr *iph;
		iph = ip_hdr(skb);
		if (ipv4_is_multicast(iph->daddr))
			goto outf;
	} else if (skb->protocol == __constant_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;
		ip6h = ipv6_hdr(skb);
		if (ipv6_addr_is_multicast(&ip6h->daddr))
			goto outf;
		skb_orphan(skb);
	} else {
		goto outf;
	}

	ve = veip_pool_ops->veip_lookup(ve, skb);
	if (IS_ERR(ve))
		goto outf;

	rcv = ve->_venet_dev;
	if (!rcv)
		/* VE going down */
		goto outf;

	dev_hold(rcv);

	if (!(rcv->flags & IFF_UP))
		/* Target VE does not want to receive packets */
		goto outf;

	skb->pkt_type = PACKET_HOST;
	skb->dev = rcv;

	/*
	 * If there is not enough space for header we allocate one.
	 * Remember the traffic can reach VE from outside world and
	 * as result we have to cleanup mac address of such packet.
	 * The same applies to traffic which comes from inside of VE
	 * but if TUN is used and traffic get fragmented we might reach
	 * the point where is no L2 header at all and hard_header_len
	 * is simply ingnored (because this parameter is kind of a hint
	 * for upper net layers and never a guarantee that header will be
	 * provided). To unify the way how packets are seen after venet
	 * we always produce L2 header with zero'ified MAC.
	 */
	if (unlikely(skb_headroom(skb) < dev->hard_header_len)) {
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (!skb2)
			goto outf;

		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		kfree_skb(skb);
		skb = skb2;
	}

	skb_reset_mac_header(skb);
	memset(skb->data - dev->hard_header_len, 0, dev->hard_header_len);

	nf_reset(skb);
	length = skb->len;

	if (unlikely(netif_rx(skb) != NET_RX_SUCCESS))
		goto dropped;

	stats->tx_bytes += length;
	stats->tx_packets++;
	if (rcv) {
		struct net_device_stats *rcv_stats;

		rcv_stats = venet_stats(rcv, smp_processor_id());
		rcv_stats->rx_bytes += length;
		rcv_stats->rx_packets++;
		dev_put(rcv);
	}

	return 0;

outf:
	kfree_skb(skb);
dropped:
	if (rcv)
		dev_put(rcv);
	++stats->tx_dropped;
	return 0;
}

static struct net_device_stats *get_stats(struct net_device *dev)
{
	int i;
	struct venet_stats *stats;

	stats = (struct venet_stats *)dev->ml_priv;
	memset(&stats->stats, 0, sizeof(struct net_device_stats));
	for_each_possible_cpu(i) {
		struct net_device_stats *dev_stats;

		dev_stats = venet_stats(dev, i);
		stats->stats.rx_bytes   += dev_stats->rx_bytes;
		stats->stats.tx_bytes   += dev_stats->tx_bytes;
		stats->stats.rx_packets += dev_stats->rx_packets;
		stats->stats.tx_packets += dev_stats->tx_packets;
		stats->stats.tx_dropped += dev_stats->tx_dropped;
	}

	return &stats->stats;
}

/* Initialize the rest of the LOOPBACK device. */
static int venet_init_dev(struct net_device *dev)
{
	struct venet_stats *stats;

	stats = kzalloc(sizeof(struct venet_stats), GFP_KERNEL);
	if (stats == NULL)
		goto fail;
	stats->real_stats = alloc_percpu(struct net_device_stats);
	if (stats->real_stats == NULL)
		goto fail_free;
	dev->ml_priv = stats;

	/*
	 *	Fill in the generic fields of the device structure.
	 */
	dev->type		= ARPHRD_VOID;
	dev->hard_header_len 	= ETH_HLEN;
	dev->mtu		= 1500; /* eth_mtu */
	dev->tx_queue_len	= 0;

	memset(dev->broadcast, 0xFF, ETH_ALEN);

	/* New-style flags. */
	dev->flags		= IFF_BROADCAST|IFF_NOARP|IFF_POINTOPOINT;
	return 0;

fail_free:
	kfree(stats);
fail:
	return -ENOMEM;
}

static netdev_features_t common_features;
static const struct net_device_ops venet_netdev_ops;

static int venet_set_features(struct net_device *dev,
			      netdev_features_t features)
{
	struct net *net;

	common_features = features;
	for_each_net(net) {
		for_each_netdev(net, dev) {
			if (dev->netdev_ops == &venet_netdev_ops)
				dev->features = features;
		}
	}
	return 0;
}
#define DRV_NAME	"vz-venet"
#define DRV_VERSION	"1.0"

/*
 * ethtool interface
 */

static struct {
	const char string[ETH_GSTRING_LEN];
} ethtool_stats_keys[] = {
	{ "ifindex" },
};

static int venet_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	cmd->supported		= 0;
	cmd->advertising	= 0;
	ethtool_cmd_speed_set(cmd, SPEED_10000);
	cmd->duplex		= DUPLEX_FULL;
	cmd->port		= PORT_TP;
	cmd->phy_address	= 0;
	cmd->transceiver	= XCVR_INTERNAL;
	cmd->autoneg		= AUTONEG_DISABLE;
	cmd->maxtxpkt		= 0;
	cmd->maxrxpkt		= 0;
	return 0;
}

static void venet_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	strlcpy(info->driver, DRV_NAME, sizeof(info->driver));
	strlcpy(info->version, DRV_VERSION, sizeof(info->version));
}

static void venet_get_strings(struct net_device *dev, u32 stringset, u8 *buf)
{
	switch(stringset) {
	case ETH_SS_STATS:
		memcpy(buf, &ethtool_stats_keys, sizeof(ethtool_stats_keys));
		break;
	}
}

static int venet_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(ethtool_stats_keys);
	default:
		return -EOPNOTSUPP;
	}
}

static void venet_get_ethtool_stats(struct net_device *dev,
		struct ethtool_stats *stats, u64 *data)
{
	/*
	 * TODO: copy proper statistics here.
	 */
	data[0] = dev->ifindex;
}

static const struct ethtool_ops venet_ethtool_ops = {
	.get_settings		= venet_get_settings,
	.get_drvinfo		= venet_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_strings		= venet_get_strings,
	.get_sset_count		= venet_get_sset_count,
	.get_ethtool_stats	= venet_get_ethtool_stats,
};

static const struct net_device_ops venet_netdev_ops = {
	.ndo_start_xmit = venet_xmit,
	.ndo_get_stats = get_stats,
	.ndo_open = venet_open,
	.ndo_stop = venet_close,
	.ndo_init = venet_init_dev,
	.ndo_set_features = venet_set_features,
};

static void venet_setup(struct net_device *dev)
{
	/*
	 * No other features, as they are:
	 *  - checksumming is required, and nobody else will done our job
	 */
	dev->features |= NETIF_F_VENET | NETIF_F_VIRTUAL | NETIF_F_LLTX |
	       NETIF_F_HIGHDMA | NETIF_F_VLAN_CHALLENGED;

	dev->netdev_ops = &venet_netdev_ops;
	dev->destructor = venet_destructor;

	dev->hw_features = NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_TSO;

	dev->features |= common_features;

	SET_ETHTOOL_OPS(dev, &venet_ethtool_ops);
}

static void veip_shutdown(void *data)
{
	struct ve_struct *ve = (struct ve_struct *)data;

	spin_lock(&veip_lock);
	if (ve->veip) {
		__venet_ext_clean(ve);
		__veip_stop(ve);
	}
	spin_unlock(&veip_lock);
}

static void venet_dellink(struct net_device *dev, struct list_head *head)
{
	struct ve_struct *env = dev->nd_net->owner_ve;

	/* We check ve_netns to avoid races with veip SHUTDOWN hook, called from
	 * ve_exit_ns().
	 * Also, in veip SHUTDOWN hook we skip veip destruction, if container
	 * has VE_FEATURE_NFS enabled. Thus here we have to destroy veip in
	 * this case.
	 */
	if (env->ve_netns)
		veip_shutdown(env);

	env->_venet_dev = NULL;
	unregister_netdevice_queue(dev, head);
}

static int venet_newlink(struct net *src_net, struct net_device *dev,
		  struct nlattr *tb[], struct nlattr *data[])
{
	struct ve_struct *env = src_net->owner_ve;
	int err;

	if (!env->ve_netns)
		return -EBUSY;

	if (src_net != env->ve_netns)
		/* Don't create venet-s in sub net namespaces */
		return -ENOSYS;

	if (env->veip)
		return -EEXIST;

	err = veip_start(env);
	if (err)
		return err;

	dev->features |= NETIF_F_NETNS_LOCAL;

	err = register_netdevice(dev);
	if (err)
		goto err_stop;

	env->_venet_dev = dev;
	return 0;

err_stop:
	veip_stop(env);
	return err;
}

#ifdef CONFIG_PROC_FS
static void veaddr_seq_print(struct seq_file *m, struct ve_struct *ve)
{
	struct ip_entry_struct *entry;
	struct veip_struct *veip;

	spin_lock(&veip_lock);
	veip = ACCESS_ONCE(ve->veip);
	if (veip == NULL)
		goto unlock;
	list_for_each_entry (entry, &veip->ip_lh, ve_list) {
		char addr[40];

		if (entry->active_env == NULL)
			continue;

		veaddr_print(addr, sizeof(addr), &entry->addr);
		if (entry->addr.family == AF_INET)
			seq_printf(m, " %15s", addr);
		else
			seq_printf(m, " %39s", addr);
	}
unlock:
	spin_unlock(&veip_lock);
}

static void *veip_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t l;
	struct ip_entry_struct *s;
	int i;

	l = *pos;
	rcu_read_lock();
	if (l == 0) {
		m->private = (void *)0;
		return SEQ_START_TOKEN;
	}

	for (i = 0; i < VEIP_HASH_SZ; i++) {
		hlist_for_each_entry_rcu(s, ip_entry_hash_table + i, ip_hash) {
			if (--l == 0) {
				m->private = (void *)(long)(i + 1);
				return &s->ip_hash;
			}
		}
	}
	return NULL;
}

static void *veip_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct hlist_node *p;
	int i;

	if (v == SEQ_START_TOKEN)
		goto find;

	p = rcu_dereference(((struct hlist_node *)v)->next);
	if (p != NULL)
		goto found;

find:
	for (i = (int)(long)m->private; i < VEIP_HASH_SZ; i++) {
		p = rcu_dereference(ip_entry_hash_table[i].first);
		if (p != NULL) {
			m->private = (void *)(long)(i + 1);
found:
			(*pos)++;
			return p;
		}
	}

	return NULL;
}

static void veip_seq_stop(struct seq_file *m, void *v)
{
	rcu_read_unlock();
}

static int veip_seq_show(struct seq_file *m, void *v)
{
	struct hlist_node *p;
	struct ip_entry_struct *entry;
	char s[40];

	if (v == SEQ_START_TOKEN) {
		seq_puts(m, "Version: 2.5\n");
		return 0;
	}

	p = (struct hlist_node *)v;
	entry = hlist_entry(p, struct ip_entry_struct, ip_hash);
	veaddr_print(s, sizeof(s), &entry->addr);
	seq_printf(m, "%39s 0\n", s);
	return 0;
}

static struct seq_operations veip_seq_op = {
	.start	= veip_seq_start,
	.next	= veip_seq_next,
	.stop	= veip_seq_stop,
	.show	= veip_seq_show,
};

static int veip_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &veip_seq_op);
}

static struct file_operations proc_veip_operations = {
	.open		= veip_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};
#endif

static int do_ve_ip_map(struct ve_struct *ve, int op, struct ve_addr_struct *addr)
{
	int err;

	if (!capable_setveid())
		return -EPERM;

	down_read(&ve->op_sem);
	switch (op)
	{
		case VE_IP_ADD:
			/*
			 * FIXME We should check if VE
			 * is either running or in restore
			 * state instead of allowing adding
			 * address arbitrary.
			 */
			err = veip_entry_add(ve, addr);
			break;

		case VE_IP_DEL:
			err = veip_entry_del(ve, addr);
			break;
		case VE_IP_EXT_ADD:
			err = venet_ext_add(ve, addr);
			break;
		case VE_IP_EXT_DEL:
			err = venet_ext_del(ve, addr);
			break;
		default:
			err = -EINVAL;
	}
	up_read(&ve->op_sem);
	return err;
}

static int real_ve_ip_map(envid_t veid, int op,
			  struct sockaddr __user *uaddr, int addrlen)
{
	int err;
	struct ve_addr_struct addr;
	struct ve_struct *ve;

	err = sockaddr_to_veaddr(uaddr, addrlen, &addr);
	if (err < 0)
		return err;

	ve = get_ve_by_id(veid);
	if (!ve)
		return -ESRCH;

	err = do_ve_ip_map(ve, op, &addr);
	put_ve(ve);
	return err;
}

int venet_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;

	err = -ENOTTY;
	switch(cmd) {
	case VENETCTL_VE_IP_MAP: {
		struct vzctl_ve_ip_map s;
		err = -EFAULT;
		if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
			break;
		err = real_ve_ip_map(s.veid, s.op, s.addr, s.addrlen);
		break;
	}
	}
	return err;
}

#ifdef CONFIG_COMPAT
int compat_venet_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;

	switch(cmd) {
	case VENETCTL_COMPAT_VE_IP_MAP: {
		struct compat_vzctl_ve_ip_map cs;

		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;

		err = real_ve_ip_map(cs.veid, cs.op, compat_ptr(cs.addr),
				cs.addrlen);
		break;
	}
	default:
		err = venet_ioctl(file, cmd, arg);
		break;
	}
	return err;
}
#endif

static struct vzioctlinfo venetcalls = {
	.type		= VENETCTLTYPE,
	.ioctl		= venet_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_venet_ioctl,
#endif
	.owner		= THIS_MODULE,
};

static int ve_ip_access_write(struct cgroup *cgrp, struct cftype *cft,
			      const char *buffer)
{
	struct ve_struct *ve = cgroup_ve(cgrp);
	struct ve_addr_struct addr;
	int ret;

	if (!ve->veid)
		return -ENOENT;

	memset(&addr, 0, sizeof(addr));
	if (strncmp(cft->name, "ip6", 3)) {
		if ((ret = in4_to_veaddr(buffer, &addr)) != 0)
			return ret;
	} else {
		if ((ret = in6_to_veaddr(buffer, &addr)) != 0)
			return ret;
	}

	return do_ve_ip_map(ve, cft->private, &addr);
}

static int ve_ip_access_seq_read(struct cgroup *cgrp, struct cftype *cft,
				 struct seq_file *m)
{
	struct ve_struct *ve = cgroup_ve(cgrp);
	struct ip_entry_struct *s;
	char buf[40];
	int family = strncmp(cft->name, "ip6", 3) ? AF_INET : AF_INET6;
	int i;

	if (!ve->veid)
		return -ENOENT;

	rcu_read_lock();
	for (i = 0; i < VEIP_HASH_SZ; i++) {
		hlist_for_each_entry_rcu(s, ip_entry_hash_table + i,
					 ip_hash) {
			if (s->addr.family == family &&
			    s->active_env && s->active_env->veid == ve->veid) {
				veaddr_print(buf, sizeof(buf), &s->addr);
				seq_printf(m, "%s\n", buf);
			}
		}
	}
	rcu_read_unlock();

	return 0;
}

static struct cftype venet_cftypes[] = {
	{
		.name = "ip_allow",
		.write_string = ve_ip_access_write,
		.private = VE_IP_ADD,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "ip_deny",
		.write_string = ve_ip_access_write,
		.private = VE_IP_DEL,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "ip_list",
		.read_seq_string = ve_ip_access_seq_read,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "ip6_allow",
		.write_string = ve_ip_access_write,
		.private = VE_IP_ADD,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "ip6_deny",
		.write_string = ve_ip_access_write,
		.private = VE_IP_DEL,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "ip6_list",
		.read_seq_string = ve_ip_access_seq_read,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{ }
};

static int venet_changelink(struct net_device *dev, struct nlattr *tb[],
			    struct nlattr *data[])
{
	struct venetaddrmsg *vamp;
	struct nlattr *nla_addr;
	struct ve_struct *ve;
	struct ve_addr_struct addr;
	int cmd;

	ve = dev_net(dev)->owner_ve;
	if (ve_is_super(ve))
		return -EINVAL;

	if (!ve_is_super(get_exec_env()))
		return -EPERM;

	if (!data[VENET_INFO_CMD])
		return -EINVAL;

	nla_addr = data[VENET_INFO_CMD];
	vamp = nla_data(nla_addr);

	memset(&addr, 0, sizeof(addr));
	addr.family = vamp->va_family;

	if (addr.family == AF_INET)
		memcpy(&addr.key[3], &vamp->va_addr[0], 4);
	else if (addr.family == AF_INET6)
		memcpy(&addr.key[0], &vamp->va_addr[0], sizeof(addr.key));
	else
		return -EINVAL;

	if (vamp->va_cmd == VENET_IP_ADD)
		cmd = VE_IP_ADD;
	else if (vamp->va_cmd == VENET_IP_DEL)
		cmd = VE_IP_DEL;
	else
		return -EINVAL;

	return do_ve_ip_map(ve, cmd, &addr);
}

static const struct nla_policy venet_policy[VENET_INFO_MAX + 1] = {
	[VENET_INFO_CMD]	= { .len = sizeof(struct venetaddrmsg) },
};

static struct rtnl_link_ops venet_link_ops = {
	.kind		= "venet",
	.priv_size	= sizeof(struct veip_struct),
	.newlink	= venet_newlink,
	.dellink	= venet_dellink,
	.setup		= venet_setup,
	.changelink	= venet_changelink,
	.policy		= venet_policy,
	.maxtype	= VENET_INFO_MAX,
};

/*
 * veip is already removed from userspace by vzctl
 * since libvzctl-7.0.449: PSBM-77750.
 * Remove this hook couple releases after the vzctl
 * version begins used in official Virtuozzo 7.
 */
static struct ve_hook veip_shutdown_hook = {
	.fini		= veip_shutdown,
	.priority	= HOOK_PRIO_FINISHING,
	.owner		= THIS_MODULE,
};

__init int venet_init(void)
{
	struct proc_dir_entry *de;
	int i, err;

	if (get_ve0()->_venet_dev != NULL)
		return -EEXIST;

	for (i = 0; i < VEIP_HASH_SZ; i++)
		INIT_HLIST_HEAD(ip_entry_hash_table + i);

	de = proc_create("veip", S_IFREG | S_IRUSR, proc_vz_dir,
			&proc_veip_operations);
	if (!de)
		return -EINVAL;

	err = cgroup_add_cftypes(&ve_subsys, venet_cftypes);
	if (err)
		goto err_proc;

	vzioctl_register(&venetcalls);
	vzmon_register_veaddr_print_cb(veaddr_seq_print);
	ve_hook_register(VE_SHUTDOWN_CHAIN, &veip_shutdown_hook);

	return rtnl_link_register(&venet_link_ops);

err_proc:
	remove_proc_entry("veip", proc_vz_dir);
	return err;
}

__exit void venet_exit(void)
{
	cgroup_rm_cftypes(&ve_subsys, venet_cftypes);
	vzmon_unregister_veaddr_print_cb(veaddr_seq_print);
	vzioctl_unregister(&venetcalls);
	remove_proc_entry("veip", proc_vz_dir);
	veip_cleanup();

	/* Ensure there are no outstanding rcu callbacks */
	rcu_barrier();

	BUG_ON(!list_empty(&veip_lh));
	rtnl_link_unregister(&venet_link_ops);
}

module_init(venet_init);
module_exit(venet_exit);

MODULE_AUTHOR("Parallels <info@parallels.com>");
MODULE_DESCRIPTION("Virtuozzo Virtual Network Device");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("vznet");

EXPORT_SYMBOL(veip_lock);
EXPORT_SYMBOL(ip_entry_hash);
EXPORT_SYMBOL(ip_entry_unhash);
EXPORT_SYMBOL(sockaddr_to_veaddr);
EXPORT_SYMBOL(veaddr_print);
EXPORT_SYMBOL(venet_entry_lookup);
EXPORT_SYMBOL(veip_findcreate);
EXPORT_SYMBOL(veip_put);
EXPORT_SYMBOL(venet_ext_lookup);
EXPORT_SYMBOL(veip_lh);
EXPORT_SYMBOL(ip_entry_hash_table);
