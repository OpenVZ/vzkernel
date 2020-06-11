/*
 * Operations on the network namespace
 */
#ifndef __NET_NET_NAMESPACE_H
#define __NET_NET_NAMESPACE_H

#include <linux/atomic.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <linux/sysctl.h>
#include <linux/idr.h>

#include <net/netns/core.h>
#include <net/netns/mib.h>
#include <net/netns/unix.h>
#include <net/netns/packet.h>
#include <net/netns/ipv4.h>
#include <net/netns/ipv6.h>
#include <net/netns/ieee802154_6lowpan.h>
#include <net/netns/sctp.h>
#include <net/netns/dccp.h>
#include <net/netns/netfilter.h>
#include <net/netns/br_netfilter.h>
#include <net/netns/x_tables.h>
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
#include <net/netns/conntrack.h>
#endif
#include <net/netns/nftables.h>
#include <net/netns/xfrm.h>
#include <linux/ns_common.h>
#include <linux/idr.h>
#include <linux/skbuff.h>

#include <linux/rh_kabi.h>

struct user_namespace;
struct proc_dir_entry;
struct net_device;
struct sock;
struct ctl_table_header;
struct net_generic;
struct sock;
struct netns_ipvs;


#define NETDEV_HASHBITS    8
#define NETDEV_HASHENTRIES (1 << NETDEV_HASHBITS)

struct net {
	atomic_t		passive;	/* To decided when the network
						 * namespace should be freed.
						 */
	atomic_t		count;		/* To decided when the network
						 *  namespace should be shut down.
						 */
	spinlock_t		rules_mod_lock;

	struct list_head	list;		/* list of network namespaces */
	struct list_head	cleanup_list;	/* namespaces on death row */
	struct list_head	exit_list;	/* Use only net_mutex */

	struct user_namespace   *user_ns;	/* Owning user namespace */

	struct ns_common	ns;

	struct proc_dir_entry 	*proc_net;
	struct proc_dir_entry 	*proc_net_stat;

#ifdef CONFIG_SYSCTL
	struct ctl_table_set	sysctls;
#endif

	struct sock 		*rtnl;			/* rtnetlink socket */
	struct sock		*genl_sock;

	struct list_head 	dev_base_head;
	struct hlist_head 	*dev_name_head;
	struct hlist_head	*dev_index_head;
	unsigned int		dev_base_seq;	/* protected by rtnl_mutex */
	int			ifindex;

#ifdef CONFIG_VE
	struct ve_struct	*owner_ve;
#ifdef CONFIG_VE_IPTABLES
	__u64			_iptables_modules;
#endif
#endif

	/* core fib_rules */
	struct list_head	rules_ops;


	struct net_device       *loopback_dev;          /* The loopback */
	struct netns_core	core;
	struct netns_mib	mib;
	struct netns_packet	packet;
	struct netns_unix	unx;
	struct netns_ipv4	ipv4;
#if IS_ENABLED(CONFIG_IPV6)
	struct netns_ipv6	ipv6;
#endif
#if defined(CONFIG_IP_SCTP) || defined(CONFIG_IP_SCTP_MODULE)
	struct netns_sctp	sctp;
#endif
#if defined(CONFIG_IP_DCCP) || defined(CONFIG_IP_DCCP_MODULE)
	struct netns_dccp	dccp;
#endif
#ifdef CONFIG_NETFILTER
	struct netns_nf		nf;
	struct netns_xt		xt;
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
	struct netns_ct		ct;
#endif
#if defined(CONFIG_BRIDGE_NETFILTER) || defined(CONFIG_BRIDGE_NETFILTER_MODULE)
	struct netns_brnf	brnf;
#endif
#if defined(CONFIG_NF_TABLES) || defined(CONFIG_NF_TABLES_MODULE)
	struct netns_nftables	nft;
#endif
#if IS_ENABLED(CONFIG_NF_DEFRAG_IPV6)
	struct netns_nf_frag	nf_frag;
#endif
	struct sock		*nfnl;
	struct sock		*nfnl_stash;
#endif
#ifdef CONFIG_WEXT_CORE
	struct sk_buff_head	wext_nlevents;
#endif
	struct net_generic __rcu	*gen;

	/* Note : following structs are cache line aligned */
#ifdef CONFIG_XFRM
	struct netns_xfrm	xfrm;
#endif
	struct netns_ipvs	*ipvs;
	struct sock		*diag_nlsk;
	atomic_t		rt_genid;

	RH_KABI_EXTEND(unsigned int	dev_unreg_count)
	RH_KABI_EXTEND(atomic_t		fnhe_genid)
	RH_KABI_EXTEND(int		sysctl_ip_no_pmtu_disc)
	RH_KABI_EXTEND(int		sysctl_ip_fwd_use_pmtu)
	/* upstream has this as part of netns_ipv4 */
	RH_KABI_EXTEND(struct local_ports ipv4_sysctl_local_ports)
	RH_KABI_EXTEND(struct idr	netns_ids)
	RH_KABI_EXTEND(spinlock_t	nsid_lock)
	/* upstream has this as part of netns_ipv4 */
	RH_KABI_EXTEND(struct sock  * __percpu *ipv4_tcp_sk)
#ifdef CONFIG_XFRM
	/* upstream has this as part of netns_xfrm */
	RH_KABI_EXTEND(spinlock_t xfrm_state_lock)
	RH_KABI_EXTEND(rwlock_t xfrm_policy_lock)
	RH_KABI_EXTEND(struct mutex xfrm_cfg_mutex)
	/* flow cache part */
	RH_KABI_EXTEND(struct flow_cache flow_cache_global)
	RH_KABI_EXTEND(atomic_t flow_cache_genid)
	RH_KABI_EXTEND(struct list_head flow_cache_gc_list)
	RH_KABI_EXTEND(spinlock_t flow_cache_gc_lock)
	RH_KABI_EXTEND(struct work_struct flow_cache_gc_work)
	RH_KABI_EXTEND(struct work_struct flow_cache_flush_work)
	RH_KABI_EXTEND(struct mutex flow_flush_sem)
	/* netns_xfrm */
	RH_KABI_EXTEND(struct xfrm_policy_hash_ext policy_bydst[XFRM_POLICY_MAX * 2])
	RH_KABI_EXTEND(struct xfrm_policy_hthresh policy_hthresh)
#endif
	RH_KABI_EXTEND(bool ip_local_ports_warned)
	RH_KABI_EXTEND(int ipv4_sysctl_ip_nonlocal_bind)
	RH_KABI_EXTEND(int ipv6_sysctl_ip_nonlocal_bind)
	RH_KABI_EXTEND(int ipv6_anycast_src_echo_reply)
	RH_KABI_EXTEND(struct sock *ipv4_mc_autojoin_sk)
	RH_KABI_EXTEND(struct sock *ipv6_mc_autojoin_sk)
	RH_KABI_EXTEND(struct netns_ieee802154_lowpan ieee802154_lowpan)
	/*
	 * Disable Potentially-Failed feature, the feature is enabled by default
	 * pf_enable    -  0  : disable pf
	 *		- >0  : enable pf
	 */
	RH_KABI_EXTEND(int sctp_pf_enable)
	RH_KABI_EXTEND(struct list_head	nfct_timeout_list)
#if IS_ENABLED(CONFIG_NF_CONNTRACK) && defined(CONFIG_NF_CT_PROTO_DCCP)
	RH_KABI_EXTEND(struct nf_dccp_net ct_dccp)
#endif
#if IS_ENABLED(CONFIG_NF_CONNTRACK) && defined(CONFIG_NF_CT_PROTO_SCTP)
	RH_KABI_EXTEND(struct nf_sctp_net ct_sctp)
#endif
#if IS_ENABLED(CONFIG_NF_CONNTRACK) && defined(CONFIG_NF_CT_PROTO_UDPLITE)
	RH_KABI_EXTEND(struct nf_udplite_net rh_reserved_ct_udplite)
#endif

	RH_KABI_EXTEND(int idgen_retries)
	RH_KABI_EXTEND(int idgen_delay)
	RH_KABI_EXTEND(struct ucounts *ucounts)
	RH_KABI_EXTEND(int ipv4_sysctl_fwmark_reflect)
	RH_KABI_EXTEND(int ipv6_sysctl_fwmark_reflect)
	RH_KABI_EXTEND(int ipv4_sysctl_tcp_keepalive_time)
	RH_KABI_EXTEND(int ipv4_sysctl_tcp_keepalive_probes)
	RH_KABI_EXTEND(int ipv4_sysctl_tcp_keepalive_intvl)
	RH_KABI_EXTEND(struct list_head	fib_notifier_ops)  /* protected by net_mutex */
	/* upstream has this as part of netns_ipv4 */
	RH_KABI_EXTEND(struct fib_notifier_ops *ipv4_notifier_ops)
	/* upstream has this as part of netns_ipv6 */
	RH_KABI_EXTEND(struct fib_notifier_ops *ipv6_notifier_ops)
#ifdef CONFIG_IP_ROUTE_MULTIPATH
	RH_KABI_EXTEND(int ipv4_sysctl_fib_multipath_hash_policy)
#endif
	RH_KABI_EXTEND(int ipv4_sysctl_ip_default_ttl)
	/* upstream has this as part of netns_ipv4 */
	RH_KABI_EXTEND(struct fib_notifier_ops	*ipv4_ipmr_notifier_ops)
	RH_KABI_EXTEND(unsigned int ipv4_ipmr_seq)	/* protected by rtnl_mutex */
	RH_KABI_EXTEND(int ipv4_sysctl_tcp_min_snd_mss)
	RH_KABI_EXTEND(u32 hash_mix)
	RH_KABI_EXTEND(siphash_key_t ip_id_key)
};

/*
 * ifindex generation is per-net namespace, and loopback is
 * always the 1st device in ns (see net_dev_init), thus any
 * loopback device should get ifindex 1
 */

#define LOOPBACK_IFINDEX	1

#include <linux/seq_file_net.h>

/* Init's network namespace */
extern struct net init_net;

#ifdef CONFIG_NET_NS
extern struct net *copy_net_ns(unsigned long flags,
	struct user_namespace *user_ns, struct net *old_net);

#else /* CONFIG_NET_NS */
#include <linux/sched.h>
#include <linux/nsproxy.h>
static inline struct net *copy_net_ns(unsigned long flags,
	struct user_namespace *user_ns, struct net *old_net)
{
	if (flags & CLONE_NEWNET)
		return ERR_PTR(-EINVAL);
	return old_net;
}
#endif /* CONFIG_NET_NS */


extern struct list_head net_namespace_list;

extern struct net *get_net_ns_by_pid(pid_t pid);
extern struct net *get_net_ns_by_fd(int pid);

#ifdef CONFIG_NET_NS
extern void __put_net(struct net *net);

static inline struct net *get_net(struct net *net)
{
	atomic_inc(&net->count);
	return net;
}

static inline struct net *maybe_get_net(struct net *net)
{
	/* Used when we know struct net exists but we
	 * aren't guaranteed a previous reference count
	 * exists.  If the reference count is zero this
	 * function fails and returns NULL.
	 */
	if (!atomic_inc_not_zero(&net->count))
		net = NULL;
	return net;
}

static inline void put_net(struct net *net)
{
	if (atomic_dec_and_test(&net->count))
		__put_net(net);
}

static inline
int net_eq(const struct net *net1, const struct net *net2)
{
	return net1 == net2;
}

extern void net_drop_ns(void *);

#else

static inline struct net *get_net(struct net *net)
{
	return net;
}

static inline void put_net(struct net *net)
{
}

static inline struct net *maybe_get_net(struct net *net)
{
	return net;
}

static inline
int net_eq(const struct net *net1, const struct net *net2)
{
	return 1;
}

#define net_drop_ns NULL
#endif


#define possible_net_t	struct net *

static inline void write_pnet(possible_net_t *pnet, struct net *net)
{
#ifdef CONFIG_NET_NS
	*pnet = net;
#endif
}

static inline struct net *read_pnet(possible_net_t const *pnet)
{
#ifdef CONFIG_NET_NS
	return *pnet;
#else
	return &init_net;
#endif
}

#define for_each_net(VAR)				\
	list_for_each_entry(VAR, &net_namespace_list, list)

#define for_each_net_rcu(VAR)				\
	list_for_each_entry_rcu(VAR, &net_namespace_list, list)

#ifdef CONFIG_NET_NS
#define __net_init
#define __net_exit
#define __net_initdata
#define __net_initconst
#else
#define __net_init	__init
#define __net_exit	__exit_refok
#define __net_initdata	__initdata
#define __net_initconst	__initconst
#endif

#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
static inline void allow_conntrack_allocation(struct net *net)
{
	net->ct.can_alloc = true;
	smp_wmb(); /* Pairs with rmb in resolve_normal_ct() */
}
#else
static inline void allow_conntrack_allocation(struct net *net) { }
#endif

int peernet2id_alloc(struct net *net, struct net *peer);
int peernet2id(struct net *net, struct net *peer);
bool peernet_has_id(struct net *net, struct net *peer);
struct net *get_net_ns_by_id(struct net *net, int id);

struct pernet_operations {
	struct list_head list;
	int (*init)(struct net *net);
	void (*exit)(struct net *net);
	void (*exit_batch)(struct list_head *net_exit_list);
	int *id;
	size_t size;
};

/*
 * Use these carefully.  If you implement a network device and it
 * needs per network namespace operations use device pernet operations,
 * otherwise use pernet subsys operations.
 *
 * Network interfaces need to be removed from a dying netns _before_
 * subsys notifiers can be called, as most of the network code cleanup
 * (which is done from subsys notifiers) runs with the assumption that
 * dev_remove_pack has been called so no new packets will arrive during
 * and after the cleanup functions have been called.  dev_remove_pack
 * is not per namespace so instead the guarantee of no more packets
 * arriving in a network namespace is provided by ensuring that all
 * network devices and all sockets have left the network namespace
 * before the cleanup methods are called.
 *
 * For the longest time the ipv4 icmp code was registered as a pernet
 * device which caused kernel oops, and panics during network
 * namespace cleanup.   So please don't get this wrong.
 */
extern int register_pernet_subsys(struct pernet_operations *);
extern void unregister_pernet_subsys(struct pernet_operations *);
extern int register_pernet_device(struct pernet_operations *);
extern void unregister_pernet_device(struct pernet_operations *);

struct ctl_table;
struct ctl_table_header;

#ifdef CONFIG_SYSCTL
extern int net_sysctl_init(void);
extern struct ctl_table_header *register_net_sysctl(struct net *net,
	const char *path, struct ctl_table *table);
extern void unregister_net_sysctl_table(struct ctl_table_header *header);
#else
static inline int net_sysctl_init(void) { return 0; }
static inline struct ctl_table_header *register_net_sysctl(struct net *net,
	const char *path, struct ctl_table *table)
{
	return NULL;
}
static inline void unregister_net_sysctl_table(struct ctl_table_header *header)
{
}
#endif

static inline int rt_genid_ipv4(struct net *net)
{
	return atomic_read(&net->rt_genid);
}

static inline void rt_genid_bump_ipv4(struct net *net)
{
	atomic_inc(&net->rt_genid);
}

extern void (*__fib6_flush_trees)(struct net *net);
static inline void rt_genid_bump_ipv6(struct net *net)
{
	if (__fib6_flush_trees)
		__fib6_flush_trees(net);
}

#if IS_ENABLED(CONFIG_IEEE802154_6LOWPAN)
static inline struct netns_ieee802154_lowpan *
net_ieee802154_lowpan(struct net *net)
{
	return &net->ieee802154_lowpan;
}
#endif

/* For callers who don't really care about whether it's IPv4 or IPv6 */
static inline void rt_genid_bump_all(struct net *net)
{
	rt_genid_bump_ipv4(net);
	rt_genid_bump_ipv6(net);
}

static inline int fnhe_genid(struct net *net)
{
	return atomic_read(&net->fnhe_genid);
}

static inline void fnhe_genid_bump(struct net *net)
{
	atomic_inc(&net->fnhe_genid);
}

#endif /* __NET_NET_NAMESPACE_H */
