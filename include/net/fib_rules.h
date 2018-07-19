#ifndef __NET_FIB_RULES_H
#define __NET_FIB_RULES_H

#include <linux/types.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/fib_rules.h>
#include <net/flow.h>
#include <net/rtnetlink.h>
#include <net/fib_notifier.h>

struct fib_rule {
	struct list_head	list;
	atomic_t		refcnt;
	int			iifindex;
	int			oifindex;
	u32			mark;
	u32			mark_mask;
	u32			pref;
	u32			flags;
	u32			table;
	u8			action;
	u32			target;
	struct fib_rule __rcu	*ctarget;
	char			iifname[IFNAMSIZ];
	char			oifname[IFNAMSIZ];
	struct rcu_head		rcu;
	struct net *		fr_net;
	RH_KABI_EXTEND(__be64	tun_id)
	/* kABI: use these reserved fields to add new items; the structure
	 * can't be further extended after we whitelist fib_rules_register.
	 */
	RH_KABI_EXTEND(u32	rh_reserved[4])
};

struct fib_lookup_arg {
	void			*lookup_ptr;
	void			*result;
	struct fib_rule		*rule;
	int			flags;
#define FIB_LOOKUP_NOREF	1
};

struct fib_rules_ops {
	int			family;
	struct list_head	list;
	int			rule_size;
	int			addr_size;
	int			unresolved_rules;
	int			nr_goto_rules;

	int			(*action)(struct fib_rule *,
					  struct flowi *, int,
					  struct fib_lookup_arg *);
	int			(*match)(struct fib_rule *,
					 struct flowi *, int);
	int			(*configure)(struct fib_rule *,
					     struct sk_buff *,
					     struct fib_rule_hdr *,
					     struct nlattr **);
	RH_KABI_REPLACE(void	(*delete)(struct fib_rule *),
			int	(*delete)(struct fib_rule *))
	int			(*compare)(struct fib_rule *,
					   struct fib_rule_hdr *,
					   struct nlattr **);
	int			(*fill)(struct fib_rule *, struct sk_buff *,
					struct fib_rule_hdr *);
	RH_KABI_REPLACE(u32     (*default_pref)(struct fib_rules_ops *ops),
	                void    *rh_reserved_default_pref)
	size_t			(*nlmsg_payload)(struct fib_rule *);

	/* Called after modifications to the rules set, must flush
	 * the route cache if one exists. */
	void			(*flush_cache)(struct fib_rules_ops *ops);

	int			nlgroup;
	const struct nla_policy	*policy;
	struct list_head	rules_list;
	struct module		*owner;
	struct net		*fro_net;
	struct rcu_head		rcu;
	RH_KABI_EXTEND(unsigned int	fib_rules_seq)
};

struct fib_rule_notifier_info {
	struct fib_notifier_info info; /* must be first */
	struct fib_rule *rule;
};

#define FRA_GENERIC_POLICY \
	[FRA_IIFNAME]	= { .type = NLA_STRING, .len = IFNAMSIZ - 1 }, \
	[FRA_OIFNAME]	= { .type = NLA_STRING, .len = IFNAMSIZ - 1 }, \
	[FRA_PRIORITY]	= { .type = NLA_U32 }, \
	[FRA_FWMARK]	= { .type = NLA_U32 }, \
	[FRA_FWMASK]	= { .type = NLA_U32 }, \
	[FRA_TABLE]     = { .type = NLA_U32 }, \
	[FRA_GOTO]	= { .type = NLA_U32 }

static inline void fib_rule_get(struct fib_rule *rule)
{
	atomic_inc(&rule->refcnt);
}

static inline void fib_rule_put(struct fib_rule *rule)
{
	if (atomic_dec_and_test(&rule->refcnt))
		kfree_rcu(rule, rcu);
}

static inline u32 frh_get_table(struct fib_rule_hdr *frh, struct nlattr **nla)
{
	if (nla[FRA_TABLE])
		return nla_get_u32(nla[FRA_TABLE]);
	return frh->table;
}

extern struct fib_rules_ops *fib_rules_register(const struct fib_rules_ops *, struct net *);
extern void fib_rules_unregister(struct fib_rules_ops *);

extern int			fib_rules_lookup(struct fib_rules_ops *,
						 struct flowi *, int flags,
						 struct fib_lookup_arg *);
extern int			fib_default_rule_add(struct fib_rules_ops *,
						     u32 pref, u32 table,
						     u32 flags);
bool fib_rule_matchall(const struct fib_rule *rule);
int fib_rules_dump(struct net *net, struct notifier_block *nb, int family);
unsigned int fib_rules_seq_read(struct net *net, int family);
#endif
