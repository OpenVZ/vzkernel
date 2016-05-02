#ifndef __NET_NS_HASH_H__
#define __NET_NS_HASH_H__

#include <net/net_namespace.h>

static inline unsigned int net_hash_mix(const struct net *net)
{
	return net->hash_mix;
}
#endif
