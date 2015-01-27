/*
 * kernel/ve/vzredir/ip6_vzredir.c
 *
 * Copyright (c) 2004-2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ipv6.h>
#include <linux/ve.h>
#include <linux/ve_proto.h>
#include <linux/if.h>
#include <linux/netdevice.h>
#include <net/ipv6.h>
#include <net/addrconf.h>
#include <net/ip6_route.h>

#include <linux/vzredir.h>

static int ipv6_get_laddr(struct net_device *dev, struct in6_addr *addr)
{
	struct inet6_dev *idev;
	int err = -EADDRNOTAVAIL;

	rcu_read_lock();
	if ((idev = __in6_dev_get(dev)) != NULL) {
		struct inet6_ifaddr *ifp;

		read_lock_bh(&idev->lock);
		list_for_each_entry(ifp, &idev->addr_list, if_list) {
			if (ifp->flags & IFA_F_TENTATIVE)
				continue;
			if (ifp->scope & (IFA_LINK | IFA_HOST))
				continue;

			*addr = ifp->addr;
			err = 0;
			break;
		}
		read_unlock_bh(&idev->lock);
	}
	rcu_read_unlock();
	return err;
}

static unsigned int venet_redir6_prerouting(const struct nf_hook_ops *hook,
					    struct sk_buff *skb,
					    const struct net_device *in,
					    const struct net_device *out,
					    int (*okfn)(struct sk_buff *))
{
	int res;
	struct ipv6hdr *hdr;
	struct net_device *dev;
	struct in6_addr lladdr;

	res = NF_ACCEPT;

	if (likely(!skb_redirected(skb)))
		goto out;

	if (skb->dev && skb->dev->nd_net->owner_ve == get_ve0())
		goto out;

	if (unlikely(!pskb_may_pull(skb, sizeof(*hdr))))
		goto out_hdr_error;

	hdr = ipv6_hdr(skb);
	dev = skb->dev;

	if (ipv6_addr_type(&hdr->daddr) & (IPV6_ADDR_MULTICAST | IPV6_ADDR_LOOPBACK))
		goto out_drop;

	if (ipv6_get_laddr(dev, &lladdr))
		goto out;

	skb_dst_drop(skb);
	__ip6_route_input(skb, &lladdr);
	if (skb_dst(skb) == NULL)
		goto out_drop;

out:
	return res;

out_hdr_error:
	if (net_ratelimit())
		printk("%s: IP6 header error\n", in->name);
out_drop:
	res = NF_DROP;
	goto out;
}

static struct nf_hook_ops venet_redir6_ops = {
	.hook = venet_redir6_prerouting,
	.owner = THIS_MODULE,
	.pf = PF_INET6,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP6_PRI_MANGLE-1
};

static __init int ip6_vzredir_init(void)
{
	return nf_register_hook(&venet_redir6_ops);
}

static __exit void ip6_vzredir_exit(void)
{
	nf_unregister_hook(&venet_redir6_ops);
}

module_init(ip6_vzredir_init);
module_exit(ip6_vzredir_exit);

MODULE_LICENSE("GPL v2");
