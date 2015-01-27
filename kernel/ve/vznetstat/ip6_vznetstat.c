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

static int init_venet_acct_ip6_stat(void *data)
{
	struct ve_struct *ve = (struct ve_struct *)data;

	if (!ve->stat)
		return -ENODEV;

	__module_get(THIS_MODULE);
	venet_acct_get_stat(ve->stat);
	set_bit(VE_NET_ACCT_V6, &ve->stat->flags);

	return 0;
}

static void fini_venet_acct_ip6_stat(void *data)
{
	struct ve_struct *ve = (struct ve_struct *)data;

	/* module was load after VE ? */
	if (!ve->stat || !test_bit(VE_NET_ACCT_V6, &ve->stat->flags))
		return;

	clear_bit(VE_NET_ACCT_V6, &ve->stat->flags);
	venet_acct_put_stat(ve->stat);
	module_put(THIS_MODULE);
}


static int venet_acct_register_ip6_hooks(void *data)
{
	struct ve_struct *ve = (struct ve_struct *)data;
	int ret;

	if (!ve->stat)
		return -ENODEV;

	venet_acct_get_stat(ve->stat);

	 /* Register hooks */
	ret = nf_register_hook(&venet_acct_in_ops);
	if (ret < 0)
		goto out_free_stat;

	ret = nf_register_hook(&venet_acct_out_ops);
	if (ret < 0)
		goto out_hook_in;

	set_bit(VE_NET_ACCT_V6, &ve->stat->flags);

	return 0;

out_hook_in:
	nf_unregister_hook(&venet_acct_in_ops);
out_free_stat:
	venet_acct_put_stat(ve->stat);
	return ret;
}

static void venet_acct_unregister_ip6_hooks(void *data)
{
	struct ve_struct *ve = (struct ve_struct *)data;

	clear_bit(VE_NET_ACCT_V6, &ve->stat->flags);

	nf_unregister_hook(&venet_acct_out_ops);
	nf_unregister_hook(&venet_acct_in_ops);

	venet_acct_put_stat(ve->stat);
}

static struct ve_hook venet_acct_hook_v6 = {
	.init		= init_venet_acct_ip6_stat,
	.fini		= fini_venet_acct_ip6_stat,
	.priority	= HOOK_PRIO_NET_ACCT_V6,
	.owner		= THIS_MODULE,
};

int __init ip6_venetstat_init(void)
{
	int ret;

	ret = venet_acct_register_ip6_hooks(get_ve0());
	if (ret < 0)
		return ret;

	ve_hook_register(VE_SS_CHAIN, &venet_acct_hook_v6);
	ip_vznetstat_touch();
	return 0;
}

void __exit ip6_venetstat_exit(void)
{
	venet_acct_unregister_ip6_hooks(get_ve0());
	ve_hook_unregister(&venet_acct_hook_v6);
}

module_init(ip6_venetstat_init);
module_exit(ip6_venetstat_exit);

MODULE_LICENSE("GPL v2");
