#ifndef __NET_FRAG_H__
#define __NET_FRAG_H__

#include <linux/percpu_counter.h> /* Only needed for RH KABI */

struct netns_frags {
	int			nqueues;
	struct list_head	lru_list;
	spinlock_t		lru_lock;

	/* RHEL notes: this struct is frozen by KABI as it is embedded
	 * into other netns structs.  Fortunately the cacheline
	 * alignment contains enough padding.
	 */
	RH_KABI_DEPRECATE(struct percpu_counter, mem ____cacheline_aligned_in_smp)

	/* sysctls */
	int			timeout;
	int			high_thresh;
	int			low_thresh;

	RH_KABI_EXTEND(atomic_t	mem)
};

struct inet_frag_queue {
	spinlock_t		lock;
	struct timer_list	timer;      /* when will this queue expire? */
	struct list_head	lru_list;   /* lru list member */
	struct hlist_node	list;
	atomic_t		refcnt;
	struct sk_buff		*fragments;  /* Used in IPv6. */
	struct rb_root		rb_fragments; /* Used in IPv4. */
	struct sk_buff		*fragments_tail;
	struct sk_buff		*last_run_head; /* the head of the last "run". see ip_fragment.c */
	ktime_t			stamp;
	int			len;        /* total length of orig datagram */
	int			meat;
	__u8			last_in;    /* first/last segment arrived? */

#define INET_FRAG_COMPLETE	4
#define INET_FRAG_FIRST_IN	2
#define INET_FRAG_LAST_IN	1

	u16			max_size;

	struct netns_frags	*net;
};

#define INETFRAGS_HASHSZ	1024

/* averaged:
 * max_depth = default ipfrag_high_thresh / INETFRAGS_HASHSZ /
 *	       rounded up (SKB_TRUELEN(0) + sizeof(struct ipq or
 *	       struct frag_queue))
 */
#define INETFRAGS_MAXDEPTH		128

struct inet_frag_bucket {
	struct hlist_head	chain;
	spinlock_t		chain_lock;
};

struct inet_frags {
	struct inet_frag_bucket	hash[INETFRAGS_HASHSZ];
	/* This rwlock is a global lock (seperate per IPv4, IPv6 and
	 * netfilter). Important to keep this on a seperate cacheline.
	 * Its primarily a rebuild protection rwlock.
	 */
	rwlock_t		lock ____cacheline_aligned_in_smp;
	int			secret_interval;
	struct timer_list	secret_timer;

	/* The first call to hashfn is responsible to initialize
	 * rnd. This is best done with net_get_random_once.
	 */
	u32			rnd;
	int			qsize;

	unsigned int		(*hashfn)(struct inet_frag_queue *);
	bool			(*match)(struct inet_frag_queue *q, void *arg);
	void			(*constructor)(struct inet_frag_queue *q,
						void *arg);
	void			(*destructor)(struct inet_frag_queue *);
	void			(*skb_free)(struct sk_buff *);
	void			(*frag_expire)(unsigned long data);
};

void inet_frags_init(struct inet_frags *);
void inet_frags_fini(struct inet_frags *);

void inet_frags_init_net(struct netns_frags *nf);
void inet_frags_exit_net(struct netns_frags *nf, struct inet_frags *f);

void inet_frag_kill(struct inet_frag_queue *q, struct inet_frags *f);
void inet_frag_destroy(struct inet_frag_queue *q,
				struct inet_frags *f, int *work);
int inet_frag_evictor(struct netns_frags *nf, struct inet_frags *f, bool force);
struct inet_frag_queue *inet_frag_find(struct netns_frags *nf,
		struct inet_frags *f, void *key, unsigned int hash)
	__releases(&f->lock);
void inet_frag_maybe_warn_overflow(struct inet_frag_queue *q,
				   const char *prefix);

static inline void inet_frag_put(struct inet_frag_queue *q, struct inet_frags *f)
{
	if (atomic_dec_and_test(&q->refcnt))
		inet_frag_destroy(q, f, NULL);
}

/* Free all skbs in the queue; return the sum of their truesizes. */
unsigned int inet_frag_rbtree_purge(struct rb_root *root);

/* Memory Tracking Functions. */

static inline int frag_mem_limit(struct netns_frags *nf)
{
	return atomic_read(&nf->mem);
}

static inline void sub_frag_mem_limit(struct inet_frag_queue *q, int i)
{
	atomic_sub(i, &q->net->mem);
}

static inline void add_frag_mem_limit(struct inet_frag_queue *q, int i)
{
	atomic_add(i, &q->net->mem);
}

static inline void init_frag_mem_limit(struct netns_frags *nf)
{
	atomic_set(&nf->mem, 0);
}

static inline int sum_frag_mem_limit(struct netns_frags *nf)
{
	return atomic_read(&nf->mem);
}

static inline void inet_frag_lru_move(struct inet_frag_queue *q)
{
	spin_lock(&q->net->lru_lock);
	if (!list_empty(&q->lru_list))
		list_move_tail(&q->lru_list, &q->net->lru_list);
	spin_unlock(&q->net->lru_lock);
}

static inline void inet_frag_lru_del(struct inet_frag_queue *q)
{
	spin_lock(&q->net->lru_lock);
	list_del_init(&q->lru_list);
	q->net->nqueues--;
	spin_unlock(&q->net->lru_lock);
}

static inline void inet_frag_lru_add(struct netns_frags *nf,
				     struct inet_frag_queue *q)
{
	spin_lock(&nf->lru_lock);
	list_add_tail(&q->lru_list, &nf->lru_list);
	q->net->nqueues++;
	spin_unlock(&nf->lru_lock);
}

/* RFC 3168 support :
 * We want to check ECN values of all fragments, do detect invalid combinations.
 * In ipq->ecn, we store the OR value of each ip4_frag_ecn() fragment value.
 */
#define	IPFRAG_ECN_NOT_ECT	0x01 /* one frag had ECN_NOT_ECT */
#define	IPFRAG_ECN_ECT_1	0x02 /* one frag had ECN_ECT_1 */
#define	IPFRAG_ECN_ECT_0	0x04 /* one frag had ECN_ECT_0 */
#define	IPFRAG_ECN_CE		0x08 /* one frag had ECN_CE */

extern const u8 ip_frag_ecn_table[16];

#endif
