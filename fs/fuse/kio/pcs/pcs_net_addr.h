/*
 *  fs/fuse/kio/pcs/pcs_net_addr.h
 *
 *  Copyright (c) 2023 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef __PCS_NET_ADDR_H__
#define __PCS_NET_ADDR_H__ 1

int pcs_netaddr2sockaddr(PCS_NET_ADDR_T const *addr, struct sockaddr *sa, int *salen);
int pcs_netaddr_cmp(PCS_NET_ADDR_T const *addr1, PCS_NET_ADDR_T const *addr2);
int pcs_netaddr_cmp_ignore_port(PCS_NET_ADDR_T const *addr1, PCS_NET_ADDR_T const *addr2);
int pcs_format_netaddr_ignore_port(char *str, int len, PCS_NET_ADDR_T const *addr);

#endif /* __PCS_NET_ADDR_H__ */
