/*
 *  drivers/net/veip_mgmt.c
 *
 *  Copyright (c) 2005-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

/*
 * Virtual Networking device used to change VE ownership on packets
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/seq_file.h>

#include <linux/inet.h>
#include <net/ip.h>
#include <linux/skbuff.h>
#include <linux/venet.h>
#include <linux/ve.h>

static void veip_free(struct veip_struct *veip)
{
	kfree(veip);
}

static void veip_release(struct ve_struct *ve)
{
	struct veip_struct *veip;

	veip = ve->veip;
	ve->veip = NULL;
	barrier();
	veip_put(veip);
}

static int veip_create(struct ve_struct *ve)
{
	struct veip_struct *veip;

	veip = veip_findcreate(ve->veid);
	if (veip == NULL)
		return -ENOMEM;
	if (IS_ERR(veip))
		return PTR_ERR(veip);

	ve->veip = veip;
	return 0;
}

static int skb_extract_addr(struct sk_buff *skb,
		struct ve_addr_struct *addr, int dir)
{
	switch (skb->protocol) {
	case __constant_htons(ETH_P_IP):
		addr->family = AF_INET;
		addr->key[0] = 0;
		addr->key[1] = 0;
		addr->key[2] = 0;
		addr->key[3] = (dir ? ip_hdr(skb)->daddr : ip_hdr(skb)->saddr);
		return 0;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	case __constant_htons(ETH_P_IPV6):
		addr->family = AF_INET6;
		memcpy(&addr->key, dir ?
				ipv6_hdr(skb)->daddr.s6_addr32 :
				ipv6_hdr(skb)->saddr.s6_addr32,
				sizeof(addr->key));
		return 0;
#endif
	}

	return -EAFNOSUPPORT;
}

static struct ve_struct *venet_find_ve(struct ve_addr_struct *addr, int dir)
{
	struct ip_entry_struct *entry;
	struct ve_struct *ve = NULL;

	entry = venet_entry_lookup(addr);
	if (entry != NULL)
		ve = ACCESS_ONCE(entry->active_env);

	return ve;
}

static struct ve_struct *
veip_lookup(struct ve_struct *ve_old, struct sk_buff *skb)
{
	struct ve_struct *ve;
	int dir;
	struct ve_addr_struct addr;

	dir = ve_is_super(ve_old);
	if (skb_extract_addr(skb, &addr, dir) < 0)
		goto out_drop_nolock;

	rcu_read_lock();
	if (!dir) {
		/* from VE to host */
		ve = venet_find_ve(&addr, 0);
		if (ve == NULL) {
			if (!venet_ext_lookup(ve_old, &addr))
				goto out_drop;
		} else {
			if (ve != ve_old)
				goto out_source;
		}

		ve = get_ve0();
	} else {
		/* from host to VE */
		ve = venet_find_ve(&addr, 1);
		if (ve == NULL)
			goto out_drop;
	}
	rcu_read_unlock();

	return ve;

out_drop:
	rcu_read_unlock();
out_drop_nolock:
	return ERR_PTR(-ESRCH);

out_source:
	rcu_read_unlock();
	if (net_ratelimit() && skb->protocol == __constant_htons(ETH_P_IP)) {
		printk(KERN_WARNING "Dropped packet, source wrong "
		       "veid=%s src-IP=%u.%u.%u.%u "
		       "dst-IP=%u.%u.%u.%u\n",
		       ve_name(ve_old),
		       NIPQUAD(ip_hdr(skb)->saddr),
		       NIPQUAD(ip_hdr(skb)->daddr));
	}
	return ERR_PTR(-EACCES);
}

void veip_cleanup(void)
{
	int i;
	struct veip_struct *veip;

	spin_lock(&veip_lock);
	for (i = 0; i < VEIP_HASH_SZ; i++)
		while (!hlist_empty(ip_entry_hash_table + i)) {
			struct ip_entry_struct *entry;

			entry = hlist_entry(ip_entry_hash_table[i].first,
					struct ip_entry_struct, ip_hash);
			hlist_del(&entry->ip_hash);
			list_del(&entry->ve_list);
			kfree(entry);
		}

	/*vzredir may remain some veip-s*/
	while (!list_empty(&veip_lh)) {
		veip = list_first_entry(&veip_lh, struct veip_struct, list);
		veip_put(veip);
	}
	spin_unlock(&veip_lock);
}

static struct veip_pool_ops open_pool_ops = {
	.veip_create = veip_create,
	.veip_release = veip_release,
	.veip_free = veip_free,
	.veip_lookup = veip_lookup,
};

struct veip_pool_ops *veip_pool_ops = &open_pool_ops;
EXPORT_SYMBOL(veip_pool_ops);
