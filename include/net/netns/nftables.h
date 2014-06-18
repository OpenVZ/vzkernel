#ifndef _NETNS_NFTABLES_H_
#define _NETNS_NFTABLES_H_

#include <linux/list.h>

struct nft_af_info;

struct netns_nftables {
	struct list_head	af_info;
	struct list_head	commit_list;
	struct nft_af_info	*ipv4;
	struct nft_af_info	*ipv6;
	struct nft_af_info	*inet;
	struct nft_af_info	*arp;
	struct nft_af_info	*bridge;
	u8			gencursor;
	u8			genctr;

	/* Reserved for use in the future RHEL versions. */
	unsigned long		__rht_reserved1;
	unsigned long		__rht_reserved2;
	unsigned long		__rht_reserved3;
	unsigned long		__rht_reserved4;
	unsigned long		__rht_reserved5;
};

#endif
