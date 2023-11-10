#ifndef _LINUX_IF_LINK_H
#define _LINUX_IF_LINK_H

#include <uapi/linux/if_link.h>


/* We don't want this structure exposed to user space */
struct ifla_vf_stats {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 broadcast;
	__u64 multicast;
	__u64 rx_dropped;
	__u64 tx_dropped;
};

struct ifla_vf_info {
	__u32 vf;
	__u8 mac[32];
	__u32 vlan;
	__u32 qos;
	RH_KABI_REPLACE(__u32 tx_rate, __u32 max_tx_rate)
	__u32 spoofchk;
	__u32 linkstate;
	RH_KABI_EXTEND(__u32 min_tx_rate)
	RH_KABI_EXTEND(__u32 rss_query_en)
	RH_KABI_EXTEND(__u32 trusted)
	RH_KABI_EXTEND(__be16 vlan_proto)
};
#endif /* _LINUX_IF_LINK_H */
