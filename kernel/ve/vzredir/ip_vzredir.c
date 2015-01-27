/*
 * kernel/ve/vzredir/ip_vzredir.c
 *
 * Copyright (c) 2005-2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/sched.h>
#include <linux/smp_lock.h>

#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>
#include <net/ip.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inetdevice.h>
#include <net/route.h>

#include <linux/ve.h>
#include <linux/ve_proto.h>
#include <linux/venet.h>
#include <linux/vzredir.h>

static unsigned int venet_redir2_prerouting(unsigned int hook,
					    struct sk_buff *skb,
					    const struct net_device *in,
					    const struct net_device *out,
					    int (*okfn)(struct sk_buff *))
{
	int res;
	struct iphdr *iph;
	struct net_device *dev;
	struct in_device *in_dev;
	struct in_ifaddr *ifa;
	u32 addr;

	res = NF_ACCEPT;

	if (likely(!skb_redirected(skb)))
		goto out;

	if (skb->owner_env == get_ve0())
		goto out;

	/*
	 * Basically, pskb_may_pull() isn't necessary here, because it's done
	 * in ip_rcv() before calling NF_IP_PRE_ROUTING NF_HOOK, but let's
	 * have some insurance for the future.
	 */
	if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
		goto out_hdr_error;

	iph = ip_hdr(skb);
	dev = skb->dev;
#if 0
	printk("%s: in=%s, out=%s, skb->owner_env=%p (%d), "
		"skb->dev=%s\n", __FUNCTION__, in ? in->name : NULL,
		out ? out->name : NULL, skb->owner_env,
		skb->owner_env->veid, skb->dev->name);
#endif
	addr = iph->daddr;
	if (ipv4_is_zeronet(addr) || IN_BADCLASS(ntohl(addr)) ||
	    ipv4_is_multicast(addr) || ipv4_is_loopback(addr))
		goto out_drop;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (in_dev == NULL)
		goto out_unlock;
	for (ifa = in_dev->ifa_list; ifa != NULL; ifa = ifa->ifa_next) {
		if (!ipv4_is_loopback(ifa->ifa_local))
			break;
	}
	if (ifa == NULL)
		goto out_unlock;
	addr = ifa->ifa_local;
	rcu_read_unlock();

	skb_dst_drop(skb);
	if (ip_route_input(skb, addr, iph->saddr, iph->tos, dev))
		goto out_drop;

out:
	return res;

out_hdr_error:
	if (net_ratelimit())
		printk("%s: IP header error\n", in->name);

out_drop:
	res = NF_DROP;
	goto out;

out_unlock:
	rcu_read_unlock();
	goto out_drop;
}

static struct nf_hook_ops venet_redir2_ops = {
	.hook = venet_redir2_prerouting,
	.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_MANGLE-1
};

static int __init iptable_redirect2_init(void)
{
	return nf_register_hook(&venet_redir2_ops);
}

static void __exit iptable_redirect2_exit(void)
{
	nf_unregister_hook(&venet_redir2_ops);
}

#if defined(MODULE) && defined(VZ_AUDIT)
VZ_AUDIT;
#endif
module_init(iptable_redirect2_init)
module_exit(iptable_redirect2_exit)

MODULE_LICENSE("GPL v2");
