/*
 *  include/linux/veth.h
 *
 *  Copyright (C) 2007  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */
#ifndef __NET_VETH_H_
#define __NET_VETH_H_

enum {
	VETH_INFO_UNSPEC,
	VETH_INFO_PEER,

	__VETH_INFO_MAX
#define VETH_INFO_MAX	(__VETH_INFO_MAX - 1)
};

#ifdef __KERNEL__
struct veth_struct
{
	struct net_device_stats stats;
	struct net_device	*me;
	struct net_device	*pair;
	struct list_head	hwaddr_list;
	struct net_device_stats	*real_stats;
	int			allow_mac_change;
};

#define veth_from_netdev(dev) \
	((struct veth_struct *)(netdev_priv(dev)))
static inline struct net_device * veth_to_netdev(struct veth_struct *veth)
{
	return veth->me;
}
#endif

static inline struct net_device_stats *
veth_stats(struct net_device *dev, int cpuid)
{
	return per_cpu_ptr(veth_from_netdev(dev)->real_stats, cpuid);
}

#endif
