#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/mutex.h>
#include <net/sock.h>

#ifdef CONFIG_VE_IPTABLES
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#endif /* CONFIG_VE_IPTABLES */

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

	if (mutex_lock_interruptible(&nf_sockopt_mutex) != 0)
		return -EINTR;

	list_for_each_entry(ops, &nf_sockopts, list) {
		if (ops->pf == reg->pf
		    && (overlap(ops->set_optmin, ops->set_optmax,
				reg->set_optmin, reg->set_optmax)
			|| overlap(ops->get_optmin, ops->get_optmax,
				   reg->get_optmin, reg->get_optmax))) {
			NFDEBUG("nf_sock overlap: %u-%u/%u-%u v %u-%u/%u-%u\n",
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

	if (mutex_lock_interruptible(&nf_sockopt_mutex) != 0)
		return ERR_PTR(-EINTR);

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
#ifdef CONFIG_VE_IPTABLES
static int sockopt_module_fits(u_int8_t pf, int val, int get,
			       u_int8_t mod_pf,
			       int set_optmin, int set_optmax,
			       int get_optmin, int get_optmax)
{
	if (pf != mod_pf)
		return 0;
	if (get)
		return val >= get_optmin && val < get_optmax;
	else
		return val >= set_optmin && val < set_optmax;
}

static int ve0_load_sockopt_module(struct net *net, u8 pf, int val, int get)
{
	const char *name;
	int ret = -EPERM;

	if (!ve_capable(CAP_NET_ADMIN))
		goto out;

	if (sockopt_module_fits(pf, val, get, PF_INET,
				     IPT_BASE_CTL, IPT_SO_SET_MAX + 1,
				     IPT_BASE_CTL, IPT_SO_GET_MAX + 1)) {
		name = "ip_tables";
	} else if (sockopt_module_fits(pf, val, get, PF_INET6,
				     IP6T_BASE_CTL, IP6T_SO_SET_MAX + 1,
				     IP6T_BASE_CTL, IP6T_SO_GET_MAX + 1)) {
		name = "ip6_tables";
	} else {
		ret = -EINVAL;
		goto out;
	}
	/*
	 * Currently loaded modules are free of locks used during
	 * their initialization. So, if you add one more module
	 * here research it before. Maybe you will have to use
	 * nowait module request in the function below.
	 */
	ret = request_module(name);
out:
	return ret;
}

static struct nf_sockopt_ops *nf_sockopt_find_ve(struct sock *sk, u_int8_t pf,
		int val, int get)
{
	struct nf_sockopt_ops *ops = nf_sockopt_find(sk, pf, val, get);

	if (!IS_ERR(ops) || ve_is_super(get_exec_env()))
		return ops;

	/*
	 * Containers are not able to load appropriate modules
	 * from userspace. We tricky help them here. For containers
	 * this looks like module is already loaded or driver
	 * is built in kernel.
	 */
	if (ve0_load_sockopt_module(sock_net(sk), pf, val, get) != 0)
		return ops;

	return nf_sockopt_find(sk, pf, val, get);
}
#else /* !CONFIG_VE_IPTABLES */
#define nf_sockopt_find_ve(sk, pf, val, get)	nf_sockopt_find(sk, pf, val, get)
#endif /* !CONFIG_VE_IPTABLES */

/* Call get/setsockopt() */
static int nf_sockopt(struct sock *sk, u_int8_t pf, int val,
		      char __user *opt, int *len, int get)
{
	struct nf_sockopt_ops *ops;
	int ret;

	ops = nf_sockopt_find_ve(sk, pf, val, get);
	if (IS_ERR(ops))
		return PTR_ERR(ops);

	if (get)
		ret = ops->get(sk, val, opt, len);
	else
		ret = ops->set(sk, val, opt, *len);

	module_put(ops->owner);
	return ret;
}

int nf_setsockopt(struct sock *sk, u_int8_t pf, int val, char __user *opt,
		  unsigned int len)
{
	return nf_sockopt(sk, pf, val, opt, &len, 0);
}
EXPORT_SYMBOL(nf_setsockopt);

int nf_getsockopt(struct sock *sk, u_int8_t pf, int val, char __user *opt,
		  int *len)
{
	return nf_sockopt(sk, pf, val, opt, len, 1);
}
EXPORT_SYMBOL(nf_getsockopt);

#ifdef CONFIG_COMPAT
static int compat_nf_sockopt(struct sock *sk, u_int8_t pf, int val,
			     char __user *opt, int *len, int get)
{
	struct nf_sockopt_ops *ops;
	int ret;

	ops = nf_sockopt_find_ve(sk, pf, val, get);
	if (IS_ERR(ops))
		return PTR_ERR(ops);

	if (get) {
		if (ops->compat_get)
			ret = ops->compat_get(sk, val, opt, len);
		else
			ret = ops->get(sk, val, opt, len);
	} else {
		if (ops->compat_set)
			ret = ops->compat_set(sk, val, opt, *len);
		else
			ret = ops->set(sk, val, opt, *len);
	}

	module_put(ops->owner);
	return ret;
}

int compat_nf_setsockopt(struct sock *sk, u_int8_t pf,
		int val, char __user *opt, unsigned int len)
{
	return compat_nf_sockopt(sk, pf, val, opt, &len, 0);
}
EXPORT_SYMBOL(compat_nf_setsockopt);

int compat_nf_getsockopt(struct sock *sk, u_int8_t pf,
		int val, char __user *opt, int *len)
{
	return compat_nf_sockopt(sk, pf, val, opt, len, 1);
}
EXPORT_SYMBOL(compat_nf_getsockopt);
#endif
