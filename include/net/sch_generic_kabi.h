#ifndef __NET_SCHED_GENERIC_KABI_H
#define __NET_SCHED_GENERIC_KABI_H

#ifndef __GENKSYMS__
#error Do not include this file. It is used for generating correct checksums.
#endif

#include <linux/netdevice.h>
#include <net/gen_stats.h>

struct Qdisc_ops;
struct qdisc_walker;
struct tcf_walker;
struct module;

enum qdisc___state_t {
	__QDISC___STATE_RUNNING = 1,
};

struct qdisc_size_table {
	struct rcu_head		rcu;
	struct list_head	list;
	struct tc_sizespec	szopts;
	int			refcnt;
	u16			data[];
};

struct Qdisc {
	int 			(*enqueue)(struct sk_buff *skb, struct Qdisc *dev);
	struct sk_buff *	(*dequeue)(struct Qdisc *dev);
	unsigned int		flags;
	u32			limit;
	const struct Qdisc_ops	*ops;
	struct qdisc_size_table	__rcu *stab;
	struct list_head	list;
	u32			handle;
	u32			parent;
	int			(*reshape_fail)(struct sk_buff *skb,
					struct Qdisc *q);

	void			*u32_node;

	/* This field is deprecated, but it is still used by CBQ
	 * and it will live until better solution will be invented.
	 */
	struct Qdisc		*__parent;
	struct netdev_queue	*dev_queue;

	struct gnet_stats_rate_est64	rate_est;
	struct Qdisc		*next_sched;
	struct sk_buff		*gso_skb;
	/*
	 * For performance sake on SMP, we put highly modified fields at the end
	 */
	unsigned long		state;
	struct sk_buff_head	q;
	struct gnet_stats_basic_packed bstats;
	unsigned int		__state;
	struct gnet_stats_queue	qstats;
	struct rcu_head		rcu_head;
	int			padded;
	atomic_t		refcnt;

	spinlock_t		busylock ____cacheline_aligned_in_smp;
};

struct Qdisc_class_ops {
	/* Child qdisc manipulation */
	struct netdev_queue *	(*select_queue)(struct Qdisc *, struct tcmsg *);
	int			(*graft)(struct Qdisc *, unsigned long cl,
					struct Qdisc *, struct Qdisc **);
	struct Qdisc *		(*leaf)(struct Qdisc *, unsigned long cl);
	void			(*qlen_notify)(struct Qdisc *, unsigned long);

	/* Class manipulation routines */
	unsigned long		(*get)(struct Qdisc *, u32 classid);
	void			(*put)(struct Qdisc *, unsigned long);
	int			(*change)(struct Qdisc *, u32, u32,
					struct nlattr **, unsigned long *);
	int			(*delete)(struct Qdisc *, unsigned long);
	void			(*walk)(struct Qdisc *, struct qdisc_walker * arg);

	/* Filter manipulation */
	struct tcf_proto __rcu ** (*tcf_chain)(struct Qdisc *, unsigned long);
	unsigned long		(*bind_tcf)(struct Qdisc *, unsigned long,
					u32 classid);
	void			(*unbind_tcf)(struct Qdisc *, unsigned long);

	/* rtnetlink specific */
	int			(*dump)(struct Qdisc *, unsigned long,
					struct sk_buff *skb, struct tcmsg*);
	int			(*dump_stats)(struct Qdisc *, unsigned long,
					struct gnet_dump *);
};

struct Qdisc_ops {
	struct Qdisc_ops	*next;
	const struct Qdisc_class_ops	*cl_ops;
	char			id[IFNAMSIZ];
	int			priv_size;

	int 			(*enqueue)(struct sk_buff *, struct Qdisc *);
	struct sk_buff *	(*dequeue)(struct Qdisc *);
	struct sk_buff *	(*peek)(struct Qdisc *);
	unsigned int		(*drop)(struct Qdisc *);

	int			(*init)(struct Qdisc *, struct nlattr *arg);
	void			(*reset)(struct Qdisc *);
	void			(*destroy)(struct Qdisc *);
	int			(*change)(struct Qdisc *, struct nlattr *arg);
	void			(*attach)(struct Qdisc *);

	int			(*dump)(struct Qdisc *, struct sk_buff *);
	int			(*dump_stats)(struct Qdisc *, struct gnet_dump *);

	struct module		*owner;
};


struct tcf_result {
	unsigned long	class;
	u32		classid;
};

struct tcf_proto_ops {
	struct tcf_proto_ops	*next;
	char			kind[IFNAMSIZ];

	int			(*classify)(struct sk_buff *,
					    const struct tcf_proto *,
					    struct tcf_result *);
	int			(*init)(struct tcf_proto*);
	void			(*destroy)(struct tcf_proto*);

	unsigned long		(*get)(struct tcf_proto*, u32 handle);
	void			(*put)(struct tcf_proto*, unsigned long);
	int			(*change)(struct net *net, struct sk_buff *,
					  struct tcf_proto*, unsigned long,
					  u32 handle, struct nlattr **,
					  unsigned long *);
	int			(*delete)(struct tcf_proto*, unsigned long);
	void			(*walk)(struct tcf_proto*, struct tcf_walker *arg);

	/* rtnetlink specific */
	int			(*dump)(struct tcf_proto*, unsigned long,
					struct sk_buff *skb, struct tcmsg*);

	struct module		*owner;
};

struct tcf_proto {
	/* Fast access part */
	struct tcf_proto __rcu	*next;
	void __rcu		*root;
	int			(*classify)(struct sk_buff *,
					    const struct tcf_proto *,
					    struct tcf_result *);
	__be16			protocol;

	/* All the rest */
	u32			prio;
	u32			classid;
	struct Qdisc		*q;
	void			*data;
	const struct tcf_proto_ops	*ops;
};

#endif
