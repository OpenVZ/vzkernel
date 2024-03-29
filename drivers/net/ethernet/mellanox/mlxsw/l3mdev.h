#ifndef __MLXSW_L3MDEV_H__
#define __MLXSW_L3MDEV_H__

/* VRF is missing in RHEL */

static inline u32 l3mdev_fib_table(const struct net_device *dev)
{
	return 0;
}

static inline bool netif_is_l3_slave(const struct net_device *dev)
{
	return false;
}

static inline bool netif_is_l3_master(const struct net_device *dev)
{
	return false;
}

#endif
