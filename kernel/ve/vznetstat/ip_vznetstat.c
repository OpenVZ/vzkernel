/*
 * kernel/ve/vznetstat/ip_vznetstat.c
 *
 * Copyright (c) 2004-2015 Parallels IP Holdings GmbH
 *
 */

/*
 * Networking statistics for IPv4.
 */

#include <linux/sched.h>
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

#include <linux/ve.h>
#include <linux/ve_proto.h>
#include <linux/venet.h>
#include <linux/vznetstat.h>

#define VZNS_DEBUG 0

static unsigned int venet_acct_in_hook(const struct nf_hook_ops *hook,
				       struct sk_buff *skb,
				       const struct net_device *in,
				       const struct net_device *out,
				       const struct nf_hook_state *state)
{
	int res;

	res = NF_ACCEPT;

	/* Skip loopback dev */
	if (in == dev_net(in)->loopback_dev)
		goto out;

#if VZNS_DEBUG
	printk("%s: in %s, out %s, size %d, in->owner_env=%s\n",
		 __FUNCTION__, in ? in->name : NULL, out ? out->name : NULL,
		 venet_acct_skb_size(skb),
		 in ? in->nd_net->owner_ve->ve_name : -1);
#endif

	/*
	 * Basically, pskb_may_pull() isn't necessary here, because it's done
	 * in ip_rcv() before calling NF_IP_PRE_ROUTING NF_HOOK, but let's
	 * have some insurance for the future.
	 */
	if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
		goto out_hdr_error;

	venet_acct_classify_add_incoming(in->nd_net->owner_ve->stat, skb);

out:
	return res;

out_hdr_error:
	if (net_ratelimit())
		printk("%s: IN accounting: IP header error\n", in->name);
	res = NF_DROP;
	goto out;
}

static unsigned int venet_acct_out_hook(const struct nf_hook_ops *hook,
				        struct sk_buff *skb,
				        const struct net_device *in,
				        const struct net_device *out,
				        const struct nf_hook_state *state)
{
	int res;

	res = NF_ACCEPT;

	/* Skip loopback dev */
	if (out == dev_net(out)->loopback_dev)
		goto out;

	/* Paranoia */
	if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
		goto out_hdr_error;

#if VZNS_DEBUG
	printk("%s: in %s, out %s, size %d, out->owner_env=%s\n",
		 __FUNCTION__, in ? in->name : NULL, out ? out->name : NULL,
		 venet_acct_skb_size(skb), out ? out->nd_net->owner_ve->ve_name : -1);
#endif

	/*
	 * Basically, kproxy uses for accounting kp_account_check_in()
	 * for incoming in it packets and kp_account_check_out() for
	 * outgoing from it ones for both directions, from VE and to VE.
	 *
	 * So, for outgoing from VE packets on kproxy entrance
	 * kp_account_check_in() substracts packet from accounting, then
	 * kp_account_check_out() adds it back. Thus, we can don't worry
	 * abount double accounting here.
	 *
	 * All kproxy's accounting can't be moved in this module,
	 * since traffic amount between kproxy and outside world is a bit
	 * different from traffic amount between VE and kproxy.
	 */
	skb->protocol = __constant_htons(ETH_P_IP);
	venet_acct_classify_add_outgoing(out->nd_net->owner_ve->stat, skb);

out:
	return res;

out_hdr_error:
	if (net_ratelimit())
		printk("%s: OUT accounting: IP header error\n", out->name);
	res = NF_DROP;
	goto out;
}

static struct nf_hook_ops venet_acct_in_ops = {
	.hook		= venet_acct_in_hook,
	.owner		= THIS_MODULE,
	.pf		= PF_INET,
	.hooknum	= NF_INET_LOCAL_IN,
	.priority	= NF_IP_PRI_FIRST,
};

static struct nf_hook_ops venet_acct_out_ops = {
	.hook		= venet_acct_out_hook,
	.owner		= THIS_MODULE,
	.pf		= PF_INET,
	.hooknum	= NF_INET_LOCAL_OUT,
	.priority	= NF_IP_PRI_LAST,
};

int init_venet_acct_ip_stat(struct ve_struct *env, struct venet_stat *stat)
{
	if (env->stat) {
		WARN(1, "ve_struct->stat is not NULL, but should be.\n");
		return -EEXIST;
	}

	env->stat = stat;
	venet_acct_get_stat(stat);

	return 0;
}
EXPORT_SYMBOL(init_venet_acct_ip_stat);

void fini_venet_acct_ip_stat(struct ve_struct *env)
{
	if (env->stat) {
		venet_acct_put_stat(env->stat);
		env->stat = NULL;
	}
}
EXPORT_SYMBOL(fini_venet_acct_ip_stat);

static int venet_acct_register_ip_hooks(void)
{
	int ret;

	 /* Register hooks */
	ret = nf_register_hook(&venet_acct_in_ops);
	if (ret < 0)
		goto out_free_stat;

	ret = nf_register_hook(&venet_acct_out_ops);
	if (ret < 0)
		goto out_err_out_hook;

	return 0;

out_err_out_hook:
	nf_unregister_hook(&venet_acct_in_ops);
out_free_stat:
	return ret;
}

static void venet_acct_unregister_ip_hooks(void)
{
	nf_unregister_hook(&venet_acct_out_ops);
	nf_unregister_hook(&venet_acct_in_ops);
}

/* For ip6_vznetstat dependency */
void ip_vznetstat_touch(void)
{
}
EXPORT_SYMBOL(ip_vznetstat_touch);

/*
 * ---------------------------------------------------------------------------
 * Initialization
 * ---------------------------------------------------------------------------
 */

int __init ip_venetstat_init(void)
{
	struct ve_struct *ve;
	int ret = -ENOMEM;

	mutex_lock(&ve_list_lock);
	for_each_ve(ve) {
		BUG_ON(ve->stat);
		ve->stat = venet_acct_find_create_stat(ve->veid);
		if (!ve->stat)
			goto err_locked;
	}
	mutex_unlock(&ve_list_lock);

	ret = venet_acct_register_ip_hooks();
	if (ret < 0)
		goto err;

	return 0;
err:
	mutex_lock(&ve_list_lock);
err_locked:
	for_each_ve(ve) {
		venet_acct_put_stat(ve->stat);
		ve->stat = NULL;
	}
	mutex_unlock(&ve_list_lock);
	return ret;
}

void __exit ip_venetstat_exit(void)
{
	struct ve_struct *ve;

	venet_acct_unregister_ip_hooks();

	mutex_lock(&ve_list_lock);
	for_each_ve(ve) {
		venet_acct_put_stat(ve->stat);
		ve->stat = NULL;
	}
	mutex_unlock(&ve_list_lock);
}

#if defined(MODULE) && defined(VZ_AUDIT)
VZ_AUDIT;
#endif
module_init(ip_venetstat_init);
module_exit(ip_venetstat_exit);

MODULE_LICENSE("GPL v2");
