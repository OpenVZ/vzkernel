// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/mutex.h>
#include <net/sock.h>

#ifdef CONFIG_VE
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter_arp/arp_tables.h>
#include <linux/netfilter_bridge/ebtables.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/ip_vs.h>
#endif /* CONFIG_VE */

#include "nf_internals.h"

/* Sockopts only registered and called from user context, so
   net locking would be overkill.  Also, [gs]etsockopt calls may
   sleep. */
static DEFINE_MUTEX(nf_sockopt_mutex);
static LIST_HEAD(nf_sockopts);

/* Do exclusive ranges overlap? */
static inline int overlap(int min1, int max1, int min2, int max2)
{
	return max1 > min2 && min1 < max2;
}

/* Functions to register sockopt ranges (exclusive). */
int nf_register_sockopt(struct nf_sockopt_ops *reg)
{
	struct nf_sockopt_ops *ops;
	int ret = 0;

	mutex_lock(&nf_sockopt_mutex);
	list_for_each_entry(ops, &nf_sockopts, list) {
		if (ops->pf == reg->pf
		    && (overlap(ops->set_optmin, ops->set_optmax,
				reg->set_optmin, reg->set_optmax)
			|| overlap(ops->get_optmin, ops->get_optmax,
				   reg->get_optmin, reg->get_optmax))) {
			pr_debug("nf_sock overlap: %u-%u/%u-%u v %u-%u/%u-%u\n",
				ops->set_optmin, ops->set_optmax,
				ops->get_optmin, ops->get_optmax,
				reg->set_optmin, reg->set_optmax,
				reg->get_optmin, reg->get_optmax);
			ret = -EBUSY;
			goto out;
		}
	}

	list_add(&reg->list, &nf_sockopts);
out:
	mutex_unlock(&nf_sockopt_mutex);
	return ret;
}
EXPORT_SYMBOL(nf_register_sockopt);

void nf_unregister_sockopt(struct nf_sockopt_ops *reg)
{
	mutex_lock(&nf_sockopt_mutex);
	list_del(&reg->list);
	mutex_unlock(&nf_sockopt_mutex);
}
EXPORT_SYMBOL(nf_unregister_sockopt);

static struct nf_sockopt_ops *nf_sockopt_find(struct sock *sk, u_int8_t pf,
		int val, int get)
{
	struct nf_sockopt_ops *ops;

	mutex_lock(&nf_sockopt_mutex);
	list_for_each_entry(ops, &nf_sockopts, list) {
		if (ops->pf == pf) {
			if (!try_module_get(ops->owner))
				goto out_nosup;

			if (get) {
				if (val >= ops->get_optmin &&
						val < ops->get_optmax)
					goto out;
			} else {
				if (val >= ops->set_optmin &&
						val < ops->set_optmax)
					goto out;
			}
			module_put(ops->owner);
		}
	}
out_nosup:
	ops = ERR_PTR(-ENOPROTOOPT);
out:
	mutex_unlock(&nf_sockopt_mutex);
	return ops;
}

#ifdef CONFIG_VE
static int nf_sockopt_request_module(u8 pf, int val, int get)
{
	/* Normally, information of sockopt range provided by a module is owned
	 * by that module, and registered via nf_register_sockopt().
	 *
	 * But now need to find not-yet-loaded module by a sockopt number.
	 *
	 * TODO: evaluate if module aliases or device tables or whatever
	 * similar could be used to avoid duplication of that information
	 * in the below lookup table.
	 */
	struct table_entry {
		const char *name;
		u8 pf;
		int get_min;
		int get_max;
		int set_min;
		int set_max;
	};

#define TABLE_ENTRY(_name, _pf, _prefix) {		\
	.name = _name,					\
	.pf = _pf,					\
	.get_min = _prefix ## _BASE_CTL,		\
	.get_max = _prefix ## _SO_GET_MAX,		\
	.set_min = _prefix ## _BASE_CTL,		\
	.set_max = _prefix ## _SO_SET_MAX,		\
}
#define TABLE_ENTRY_SINGLE_GET(_name, _pf, _val) {	\
	.name = _name,					\
	.pf = _pf,					\
	.get_min = _val,				\
	.get_max = _val,				\
	.set_min = 0,					\
	.set_max = -1,					\
}

	static struct table_entry table[] = {
#ifdef CONFIG_IP_NF_IPTABLES_MODULE
		TABLE_ENTRY("ip_tables", PF_INET, IPT),
#endif
#ifdef CONFIG_IP6_NF_IPTABLES_MODULE
		TABLE_ENTRY("ip6_tables", PF_INET6, IP6T),
#endif
#ifdef CONFIG_IP_NF_ARPTABLES_MODULE
		TABLE_ENTRY("arp_tables", PF_INET, ARPT),
#endif
#ifdef CONFIG_BRIDGE_NF_EBTABLES_MODULE
		TABLE_ENTRY("ebtables", PF_INET, EBT),
#endif
#ifdef CONFIG_NF_CONNTRACK_MODULE
		TABLE_ENTRY_SINGLE_GET("nf_conntrack", PF_INET,
				       SO_ORIGINAL_DST),
		TABLE_ENTRY_SINGLE_GET("nf_conntrack", PF_INET6,
				       IP6T_SO_ORIGINAL_DST),
#endif
#ifdef CONFIG_IP_SET_MODULE
		TABLE_ENTRY_SINGLE_GET("ip_set", PF_INET, SO_IP_SET),
#endif
#ifdef CONFIG_IP_VS_MODULE
		TABLE_ENTRY("ip_vs", PF_INET, IP_VS),
#endif
	};
#undef TABLE_ENTRY
#undef TABLE_ENTRY_SINGLE_GET

	int i;

	for (i = 0; i < ARRAY_SIZE(table); i++) {
		if (pf != table[i].pf)
			continue;
		if (get && val >= table[i].get_min && val <= table[i].get_max)
			break;
		if (!get && val >= table[i].set_min && val <= table[i].set_max)
			break;
	}

	if (i == ARRAY_SIZE(table))
		return -EOPNOTSUPP;

	return request_module(table[i].name);
}

static struct nf_sockopt_ops *nf_sockopt_find_ve(struct sock *sk, u_int8_t pf,
						 int val, int get)
{
	struct nf_sockopt_ops *ops = nf_sockopt_find(sk, pf, val, get);

	if (!IS_ERR(ops) || ve_is_super(get_exec_env()))
		return ops;

	/* Containers are not able to load appropriate modules
	 * from userspace. We tricky help them here. For containers
	 * this looks like module is already loaded or driver
	 * is built in kernel.
	 */
	if (nf_sockopt_request_module(pf, val, get) == 0)
		ops = nf_sockopt_find(sk, pf, val, get);

	return ops;
}
#else /* !CONFIG_VE */
#define nf_sockopt_find_ve(sk, pf, val, get)	nf_sockopt_find(sk, pf, val, get)
#endif /* !CONFIG_VE */

int nf_setsockopt(struct sock *sk, u_int8_t pf, int val, sockptr_t opt,
		  unsigned int len)
{
	struct nf_sockopt_ops *ops;
	int ret;

	ops = nf_sockopt_find_ve(sk, pf, val, 0);
	if (IS_ERR(ops))
		return PTR_ERR(ops);
	ret = ops->set(sk, val, opt, len);
	module_put(ops->owner);
	return ret;
}
EXPORT_SYMBOL(nf_setsockopt);

int nf_getsockopt(struct sock *sk, u_int8_t pf, int val, char __user *opt,
		  int *len)
{
	struct nf_sockopt_ops *ops;
	int ret;

	ops = nf_sockopt_find_ve(sk, pf, val, 1);
	if (IS_ERR(ops))
		return PTR_ERR(ops);
	ret = ops->get(sk, val, opt, len);
	module_put(ops->owner);
	return ret;
}
EXPORT_SYMBOL(nf_getsockopt);
