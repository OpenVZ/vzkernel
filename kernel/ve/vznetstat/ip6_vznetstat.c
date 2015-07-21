/*
 * kernel/ve/vznetstat/ip6_vznetstat.c
 *
 * Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *
 */

/*
 * Networking statistics for IPv6
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>

#include <linux/ve.h>
#include <linux/ve_proto.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <linux/vznetstat.h>

static unsigned int
venet_acct_in_hook_v6(const struct nf_hook_ops *hook,
		      struct sk_buff *skb,
		      const struct net_device *in,
		      const struct net_device *out,
		      const struct nf_hook_state *state)
{
	int res = NF_ACCEPT;

	if (in->flags & IFF_LOOPBACK)
		goto out;

	venet_acct_classify_add_incoming(in->nd_net->owner_ve->stat, skb);
out:
	return res;
}

static unsigned int
venet_acct_out_hook_v6(const struct nf_hook_ops *hook,
		    struct sk_buff *skb,
		    const struct net_device *in,
		    const struct net_device *out,
		    const struct nf_hook_state *state)
{
	int res = NF_ACCEPT;

	if (out->flags & IFF_LOOPBACK)
		goto out;

	skb->protocol = __constant_htons(ETH_P_IPV6);
	venet_acct_classify_add_outgoing(out->nd_net->owner_ve->stat, skb);
out:
	return res;
}

static struct nf_hook_ops venet_acct_in_ops = {
	.hook		= venet_acct_in_hook_v6,
	.owner		= THIS_MODULE,
	.pf		= PF_INET6,
	.hooknum	= NF_INET_LOCAL_IN,
	.priority	= NF_IP6_PRI_FIRST,
};

static struct nf_hook_ops venet_acct_out_ops = {
	.hook		= venet_acct_out_hook_v6,
	.owner		= THIS_MODULE,
	.pf		= PF_INET6,
	.hooknum	= NF_INET_LOCAL_OUT,
	.priority	= NF_IP6_PRI_LAST,
};

int __init ip6_venetstat_init(void)
{
	int ret;

	ret = nf_register_hook(&venet_acct_in_ops);
	if (ret < 0)
		return ret;

	ret = nf_register_hook(&venet_acct_out_ops);
	if (ret < 0) {
		nf_unregister_hook(&venet_acct_in_ops);
		return ret;
	}

	return 0;
}

void __exit ip6_venetstat_exit(void)
{
	nf_unregister_hook(&venet_acct_out_ops);
	nf_unregister_hook(&venet_acct_in_ops);
}

module_init(ip6_venetstat_init);
module_exit(ip6_venetstat_exit);

MODULE_LICENSE("GPL v2");
