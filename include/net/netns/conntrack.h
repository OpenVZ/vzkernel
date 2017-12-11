#ifndef __NETNS_CONNTRACK_H
#define __NETNS_CONNTRACK_H

#include <linux/list.h>
#include <linux/list_nulls.h>
#include <linux/atomic.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#ifdef CONFIG_NF_CT_PROTO_DCCP
#include <linux/netfilter/nf_conntrack_dccp.h>
#endif
#ifdef CONFIG_NF_CT_PROTO_SCTP
#include <linux/netfilter/nf_conntrack_sctp.h>
#endif
#include <linux/seqlock.h>
#include <linux/rh_kabi.h>

struct ctl_table_header;
struct nf_conntrack_ecache;

struct nf_proto_net {
#ifdef CONFIG_SYSCTL
	struct ctl_table_header *ctl_table_header;
	struct ctl_table        *ctl_table;
#ifdef CONFIG_NF_CONNTRACK_PROC_COMPAT
	struct ctl_table_header *ctl_compat_header;
	struct ctl_table        *ctl_compat_table;
#endif
#endif
	unsigned int		users;
};

struct nf_generic_net {
	struct nf_proto_net pn;
	unsigned int timeout;
};

struct nf_tcp_net {
	struct nf_proto_net pn;
	unsigned int timeouts[TCP_CONNTRACK_TIMEOUT_MAX];
	unsigned int tcp_loose;
	unsigned int tcp_be_liberal;
	unsigned int tcp_max_retrans;
};

enum udp_conntrack {
	UDP_CT_UNREPLIED,
	UDP_CT_REPLIED,
	UDP_CT_MAX
};

struct nf_udp_net {
	struct nf_proto_net pn;
	unsigned int timeouts[UDP_CT_MAX];
};

struct nf_icmp_net {
	struct nf_proto_net pn;
	unsigned int timeout;
};

#ifdef CONFIG_NF_CT_PROTO_DCCP
struct nf_dccp_net {
	struct nf_proto_net pn;
	int dccp_loose;
	unsigned int dccp_timeout[CT_DCCP_MAX + 1];
};
#endif

#ifdef CONFIG_NF_CT_PROTO_SCTP
struct nf_sctp_net {
	struct nf_proto_net pn;
	unsigned int timeouts[SCTP_CONNTRACK_MAX];
};
#endif

#ifdef CONFIG_NF_CT_PROTO_UDPLITE
enum udplite_conntrack {
	UDPLITE_CT_UNREPLIED,
	UDPLITE_CT_REPLIED,
	UDPLITE_CT_MAX
};

struct nf_udplite_net {
	struct nf_proto_net pn;
	unsigned int timeouts[UDPLITE_CT_MAX];
};
#endif

struct nf_ip_net {
	struct nf_generic_net   generic;
	struct nf_tcp_net	tcp;
	struct nf_udp_net	udp;
	struct nf_icmp_net	icmp;
	struct nf_icmp_net	icmpv6;
#if defined(CONFIG_SYSCTL) && defined(CONFIG_NF_CONNTRACK_PROC_COMPAT)
	struct ctl_table_header *ctl_table_header;
	struct ctl_table	*ctl_table;
#endif
};

#ifndef __GENKSYMS__
struct ct_pcpu {
	spinlock_t		lock;
	struct hlist_nulls_head unconfirmed;
	struct hlist_nulls_head dying;
};
#endif

struct netns_ct {
	atomic_t		count;
	unsigned int		max;
	unsigned int		expect_count;
	unsigned int		expect_max;
#ifdef CONFIG_SYSCTL
	struct ctl_table_header	*sysctl_header;
	struct ctl_table_header	*acct_sysctl_header;
	struct ctl_table_header	*tstamp_sysctl_header;
	struct ctl_table_header	*event_sysctl_header;
	struct ctl_table_header	*helper_sysctl_header;
#endif
	char			*slabname;
	unsigned int		sysctl_log_invalid; /* Log invalid packets */
	unsigned int		sysctl_events_retry_timeout;
	int			sysctl_events;
	int			sysctl_acct;
	int			sysctl_auto_assign_helper;
	bool			__rh_reserved;
	int			sysctl_tstamp;
	int			sysctl_checksum;

	unsigned int		htable_size;
	RH_KABI_DEPRECATE(seqcount_t, generation)
	struct kmem_cache	*nf_conntrack_cachep;
	struct hlist_nulls_head	*hash;
	struct hlist_head	*expect_hash;

	/* next three hlist heads are unused in RHEL,
	 * only kept for ABI compatibility. */
	struct hlist_nulls_head	unconfirmed;
	struct hlist_nulls_head	dying;
	struct hlist_nulls_head tmpl;

	struct ct_pcpu __percpu *pcpu_lists;
	struct ip_conntrack_stat __percpu *stat;
	struct nf_ct_event_notifier __rcu *nf_conntrack_event_cb;
	struct nf_exp_event_notifier __rcu *nf_expect_event_cb;
	struct nf_ip_net	nf_ct_proto;
#if defined(CONFIG_NF_CONNTRACK_LABELS)
	unsigned int		labels_used;
	RH_KABI_DEPRECATE(u8,	label_words)
#endif
#ifdef CONFIG_NF_NAT_NEEDED
	struct hlist_head	*nat_bysource;
	unsigned int		nat_htable_size;
#endif
};
#endif
