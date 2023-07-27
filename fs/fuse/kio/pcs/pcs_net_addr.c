/*
 *  fs/fuse/kio/pcs/pcs_net_addr.c
 *
 *  Copyright (c) 2023 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <net/sock.h>

#include "pcs_types.h"

int pcs_netaddr2sockaddr(PCS_NET_ADDR_T const *addr, struct sockaddr *sa, int *salen)
{
	BUG_ON(!sa);
	if (addr->type == PCS_ADDRTYPE_IP || addr->type == PCS_ADDRTYPE_RDMA) {
		struct sockaddr_in *saddr4 = (struct sockaddr_in *)sa;
		*saddr4 = (struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_port = (u16)addr->port,
		};
		memcpy(&saddr4->sin_addr, addr->address, sizeof(saddr4->sin_addr));
		*salen = sizeof(*saddr4);
	} else if (addr->type == PCS_ADDRTYPE_IP6) {
		struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)sa;
		*saddr6 = (struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_port = (u16)addr->port,
		};
		memcpy(&saddr6->sin6_addr, addr->address, sizeof(saddr6->sin6_addr));
		*salen = sizeof(*saddr6);
	} else
		return -EINVAL;

	return 0;
}

static inline int netaddr_cmp(PCS_NET_ADDR_T const *addr1,
		PCS_NET_ADDR_T const *addr2, int ignore_port)
{
	unsigned int d;
	size_t sz = 0;

	d = addr1->type - addr2->type;
	if (d)
		return d;
	d = addr1->port - addr2->port;
	if (!ignore_port && d)
		return d;

	switch (addr1->type) {
	case PCS_ADDRTYPE_IP:
	case PCS_ADDRTYPE_RDMA:
		sz = sizeof(struct in_addr);
		break;
	case PCS_ADDRTYPE_IP6:
		sz = sizeof(struct in6_addr);
		break;
	default:
		BUG();
	}

	return memcmp(addr1->address, addr2->address, sz);
}

int pcs_netaddr_cmp(PCS_NET_ADDR_T const *addr1, PCS_NET_ADDR_T const *addr2)
{
	return netaddr_cmp(addr1, addr2, 0);
}

int pcs_netaddr_cmp_ignore_port(PCS_NET_ADDR_T const *addr1, PCS_NET_ADDR_T const *addr2)
{
	return netaddr_cmp(addr1, addr2, 1);
}

int pcs_format_netaddr_ignore_port(char *str, int len, PCS_NET_ADDR_T const *addr)
{
	int ret;

	switch (addr->type) {
	case PCS_ADDRTYPE_IP:
	case PCS_ADDRTYPE_RDMA:
		ret = snprintf(str, len, "%pI4", addr->address);
		break;
	case PCS_ADDRTYPE_IP6:
		ret = snprintf(str, len, "%pI6", addr->address);
		break;
	default:
		ret = snprintf(str, len, "unknown");
		break;
	}

	return ret;
}
