/*
 *  include/net/netns/br_netfilter.h
 *
 *  Copyright (c) 2020-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef __NETNS_BR_NETFILTER_H
#define __NETNS_BR_NETFILTER_H

struct netns_brnf {
#ifdef CONFIG_SYSCTL
	struct ctl_table_header *brnf_sysctl_header;
#endif
};
#endif
