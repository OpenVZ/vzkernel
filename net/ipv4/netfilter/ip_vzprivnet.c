/*
 *
 *  Copyright (C) 2010  Parallels
 *
 */

/*
 * This is implementation of the private network filtering.
 * How does it work:
 *   _______      _______       _______
 *  |  VE1  |    |  VE2  |     | VE-N  |
 *  |_______|    |_______|     |_______|
 *      | venet      | venet       | venet
 *      |            |             |
 *      |_______ip_forward__ ... __| VE0
 *             vzfilter_hook
 *
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/log2.h>
#include <linux/ctype.h>
#include <asm/page.h>

#define VZPRIV_PROCNAME "ip_vzprivnet"

enum {
	VZPRIV_MARK_UNKNOWN,
	VZPRIV_MARK_ACCEPT,
	VZPRIV_MARK_DROP,
	VZPRIV_MARK_MAX
};

static inline unsigned int dst_pmark_get(struct dst_entry *dst)
{
	return dst->privnet_mark;
}

static inline void dst_pmark_set(struct dst_entry *dst, unsigned int mark)
{
	dst->privnet_mark = mark;
}

struct vzprivnet {
	u32 nmask;
	int weak;
};

struct vzprivnet_range {
	struct vzprivnet *pn;

	/* In big-endian */
	u32 netip;
	u32 rmask;
	struct rb_node node;
};

static DEFINE_RWLOCK(vzprivlock);

/*
 * Tree helpers
 */

static struct rb_root rbroot = RB_ROOT;
/* ip: big-endian IP address */
static struct vzprivnet_range *tree_search(u32 ip)
{
	struct rb_node *node = rbroot.rb_node;

	ip = ntohl(ip);
	while (node) {
		struct vzprivnet_range *p = rb_entry(node, struct vzprivnet_range, node);
		u32 start, end;

		start = ntohl(p->netip);
		end = start | ~ntohl(p->rmask);

		if (ip <= end) {
			if (start <= ip)
				return p;

			node = node->rb_left;
		} else
			node = node->rb_right;
	}
	return NULL;
}

static int tree_insert(struct vzprivnet_range *data)
{
	struct rb_node **link = &(rbroot.rb_node), *parent = NULL;
	u32 ip = ntohl(data->netip);

	while (*link) {
		struct vzprivnet_range *p = rb_entry(*link, struct vzprivnet_range, node);
		u32 start, end;

		start = ntohl(p->netip);
		end = start | ~ntohl(p->rmask);

		if (start <= ip && ip <= end)
			return -EEXIST;

		parent = *link;
		if (ip < end)
			link = &((*link)->rb_left);
		else
			link = &((*link)->rb_right);
	}

	/* Add link node and rebalance tree. */
	rb_link_node(&data->node, parent, link);
	rb_insert_color(&data->node, &rbroot);

	return 0;
}

static void tree_delete(struct vzprivnet_range *p)
{
	rb_erase(&p->node, &rbroot);
}

static struct vzprivnet_range *tree_first(void)
{
	struct rb_node *node;

	node = rb_first(&rbroot);
	if (!node)
		return NULL;

	return rb_entry(node, struct vzprivnet_range, node);
}

static struct vzprivnet_range *tree_next(struct vzprivnet_range *p)
{
	struct rb_node *node;

	node = rb_next(&p->node);
	if (!node)
		return NULL;

	return rb_entry(node, struct vzprivnet_range, node);
}

/*
 * Generic code
 */

static struct vzprivnet vzpriv_internet = {
	.nmask = 0,
	.weak = 1
};

static struct vzprivnet *vzpriv_search(u32 ip)
{
	struct vzprivnet_range *pnr;

	pnr = tree_search(ip);
	if (pnr != NULL)
		return pnr->pn;
	else
		return &vzpriv_internet;
}

static noinline unsigned int vzprivnet_classify(struct sk_buff *skb)
{
	int res;
	u32 saddr, daddr;
	struct vzprivnet *p1, *p2;

	saddr = ip_hdr(skb)->saddr;
	daddr = ip_hdr(skb)->daddr;

	read_lock(&vzprivlock);
	p1 = vzpriv_search(saddr);
	p2 = vzpriv_search(daddr);

	if (p1 == p2) {
		if ((saddr & p1->nmask) == (daddr & p1->nmask))
			res = VZPRIV_MARK_ACCEPT;
		else
			res = VZPRIV_MARK_DROP;
	} else {
		if (p1->weak && p2->weak)
			res = VZPRIV_MARK_ACCEPT;
		else
			res = VZPRIV_MARK_DROP;
	}

	read_unlock(&vzprivlock);
	return res;
}

static unsigned int vzprivnet_hook(const struct nf_hook_ops *ops,
				  struct sk_buff *skb,
				  const struct net_device *in,
				  const struct net_device *out,
				  const struct nf_hook_state *state)
{
	struct dst_entry *dst;
	unsigned int pmark = VZPRIV_MARK_UNKNOWN;

	dst = skb_dst(skb);
	if (dst != NULL)
		pmark = dst_pmark_get(dst);

	if (unlikely(pmark == VZPRIV_MARK_UNKNOWN)) {
		pmark = vzprivnet_classify(skb);
		if (dst != NULL)
			dst_pmark_set(dst, pmark);
	}

	return pmark == VZPRIV_MARK_ACCEPT ? NF_ACCEPT : NF_DROP;
}

static struct nf_hook_ops vzprivnet_ops = {
	.hook = vzprivnet_hook,
	.owner = THIS_MODULE,
	.pf = PF_INET,
	.hooknum = NF_INET_FORWARD,
	.priority = NF_IP_PRI_FIRST
};

static inline u32 to_netmask(int prefix)
{
	return ((~0 << (32 - prefix)));
}

static inline unsigned int to_prefix(u32 netmask)
{
	return 32 - ilog2(~netmask + 1);
}

static char *nextline(char *s)
{
	while(*s && *s != '\n') s++;
	while(*s && *s == '\n') s++;
	return s;
}

static int vzprivnet_add(u32 net, u32 m1, u32 m2, int weak)
{
	struct vzprivnet_range *p;
	struct vzprivnet *pn;
	int err;

	p = kmalloc(sizeof(struct vzprivnet_range), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	pn = kmalloc(sizeof(struct vzprivnet), GFP_KERNEL);
	if (!pn) {
		kfree(p);
		return -ENOMEM;
	}

	p->pn = pn;
	p->netip = net;
	p->rmask = m1;
	pn->nmask = m2;
	pn->weak = weak;

	write_lock_bh(&vzprivlock);
	err = tree_insert(p);
	write_unlock_bh(&vzprivlock);
	if (err) {
		kfree(pn);
		kfree(p);
	}

	return err;
}

static int vzprivnet_del(u32 net)
{
	struct vzprivnet_range *p;

	write_lock_bh(&vzprivlock);
	p = tree_search(net);
	if (p == NULL) {
		write_unlock_bh(&vzprivlock);
		return -ENOENT;
	}

	tree_delete(p);
	write_unlock_bh(&vzprivlock);
	kfree(p->pn);
	kfree(p);
	return 0;
}

static void vzprivnet_cleanup(void)
{
	struct vzprivnet_range *p;

	write_lock_bh(&vzprivlock);
	while (1) {
		p = tree_first();
		if (!p)
			break;
		tree_delete(p);
		kfree(p->pn);
		kfree(p);
	}
	write_unlock_bh(&vzprivlock);
}

/*     +a.b.c.d/M1/M2
 * or
 *     -a.b.c.d/M1/M2
 *
 * add: 0 - delete, 1 - add
 * if delete, netmasks don't matter
 */
static int parse_param(const char *param, int *add, u32 *net,
			u32 *netmask1, u32 *netmask2, int *weak)
{
	int err;
	unsigned char ch, e;
	unsigned int a,b,c,d;
	unsigned int m1, m2;

	if (!*param)
		return -EINVAL;

	ch = *param;
	if (ch != '+' && ch != '-')
		return -EINVAL;

	param++;
	err = sscanf(param, "%u.%u.%u.%u/%u/%u%c\n",
				&a, &b, &c, &d, &m1, &m2, &e);
	if (err < 4 || (a == 0 || a > 255 || b > 255 || c > 255 || d > 255))
		return -EINVAL;

	*weak = 0;
	if (err == 7) {
		if (e == '*')
			*weak = 1;
		else if (e != '\n' || !isspace(e))
			return -EINVAL;
	}

	*net = htonl((a << 24) + (b << 16) + (c << 8) + d);
	if (ch == '+') {
		if (err < 6 || m1 == 0 || m1 > 32 || m2 == 0 || m2 > 32)
			return -EINVAL;

		*netmask1 = htonl(to_netmask(m1));
		*netmask2 = htonl(to_netmask(m2));
		*net &= *netmask1;
	} else
		*netmask1 = *netmask2 = 0;

	*add = (ch == '+') ? 1 : 0;
	return 0;
}

static ssize_t vzpriv_write(struct file * file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	char *s, *page;
	int err;
	int offset;

	page = (unsigned char *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	if (count > (PAGE_SIZE - 1))
		count = (PAGE_SIZE - 1);

	err = copy_from_user(page, buf, count);
	if (err)
		goto err;

	s = page;
	s[count] = 0;

	err = -EINVAL;
	while (*s) {
		u32 net, m1, m2;
		int add, weak;

		err = parse_param(s, &add, &net, &m1, &m2, &weak);
		if (err)
			goto out;

		if (add)
			err = vzprivnet_add(net, m1, m2, weak);
		else
			err = vzprivnet_del(net);

		if (err)
			goto out;

		s = nextline(s);
	}
out:
	offset = s - page;
	if (offset > 0)
		err = offset;
err:
	free_page((unsigned long)page);
	return err;
}

static void *vzprivnet_seq_start(struct seq_file *seq, loff_t *pos)
{
	unsigned int n = *pos;

	read_lock_bh(&vzprivlock);
	if (n > 0) {
		struct vzprivnet_range *p;

		p = tree_first();
		while (n-- && p)
			p = tree_next(p);

		return p;
	}

	return tree_first();
}

static void *vzprivnet_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	(*pos)++;

	return tree_next(v);
}

static void vzprivnet_seq_stop(struct seq_file *s, void *v)
{
	read_unlock_bh(&vzprivlock);
}

static int vzprivnet_seq_show(struct seq_file *s, void *v)
{
	struct vzprivnet_range *p = v;

	seq_printf(s, "%pI4/%u/%u", &p->netip,
		   to_prefix(ntohl(p->rmask)), to_prefix(ntohl(p->pn->nmask)));
	if (p->pn->weak)
		seq_printf(s, "*\n");
	else
		seq_printf(s, "\n");
	return 0;
}

static struct seq_operations vzprivnet_seq_ops = {
	.start = vzprivnet_seq_start,
	.next  = vzprivnet_seq_next,
	.stop  = vzprivnet_seq_stop,
	.show  = vzprivnet_seq_show,
};

static int vzprivnet_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &vzprivnet_seq_ops);
}

static struct file_operations proc_vzprivnet_ops = {
	.owner   = THIS_MODULE,
	.open    = vzprivnet_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
	.write   = vzpriv_write,
};

static int __init iptable_vzprivnet_init(void)
{
	int err;
	struct proc_dir_entry *proc;

	proc = proc_net_fops_create(&init_net, VZPRIV_PROCNAME, 0640, &proc_vzprivnet_ops);
	if (!proc)
		return -ENOMEM;

	err = nf_register_hook(&vzprivnet_ops);
	if (err)
		proc_net_remove(&init_net, VZPRIV_PROCNAME);

	return err;
}

static void __exit iptable_vzprivnet_exit(void)
{
	nf_unregister_hook(&vzprivnet_ops);
	proc_net_remove(&init_net, VZPRIV_PROCNAME);
	vzprivnet_cleanup();
}

module_init(iptable_vzprivnet_init)
module_exit(iptable_vzprivnet_exit)
