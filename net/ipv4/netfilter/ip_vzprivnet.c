/*
 *  net/ipv4/netfilter/ip_vzprivnet.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
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
#include <linux/sysctl.h>
#include <linux/inet.h>
#include <asm/page.h>

#include <linux/vzprivnet.h>
#define VZPRIV_PROCNAME "ip_vzprivnet"

static DEFINE_PER_CPU(unsigned long, lookup_stat[2]);

struct vzprivnet {
	u32 nmask;
	int weak;
};

struct vzprivnet_sparse {
	struct vzprivnet pn;

	unsigned int netid;
	struct list_head list;
	struct list_head entries;
};

struct vzprivnet_range {
	struct vzprivnet *pn;

	/* In big-endian */
	u32 netip;
	u32 rmask;
	struct rb_node node;
};

struct vzprivnet_entry {
	struct vzprivnet_range range;
	struct list_head list;
};

static DEFINE_RWLOCK(vzprivlock);
static LIST_HEAD(vzpriv_sparse);
static struct rb_root entries_root = RB_ROOT;

/*
 * Tree helpers
 */

static struct rb_root rbroot = RB_ROOT;
/* ip: big-endian IP address */
static struct vzprivnet_range *tree_search(struct rb_root *root, u32 ip)
{
	struct rb_node *node = root->rb_node;

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

static struct vzprivnet_range *legacy_search(u32 ip)
{
	return tree_search(&rbroot, ip);
}

static int tree_insert(struct rb_root *root, struct vzprivnet_range *data)
{
	struct rb_node **link = &(root->rb_node), *parent = NULL;
	u32 ip;
	u32 end_ip;

	ip = ntohl(data->netip);
	end_ip = ip | ~ntohl(data->rmask);


	while (*link) {
		struct vzprivnet_range *p = rb_entry(*link, struct vzprivnet_range, node);
		u32 start, end;

		start = ntohl(p->netip);
		end = start | ~ntohl(p->rmask);

		if (!(ip > end || start > end_ip))
			return -EEXIST;

		parent = *link;
		if (ip < end)
			link = &((*link)->rb_left);
		else
			link = &((*link)->rb_right);
	}

	/* Add link node and rebalance tree. */
	rb_link_node(&data->node, parent, link);
	rb_insert_color(&data->node, root);

	return 0;
}

static int legacy_insert(struct vzprivnet_range *data)
{
	return tree_insert(&rbroot, data);
}

static void legacy_delete(struct vzprivnet_range *p)
{
	rb_erase(&p->node, &rbroot);
}

static struct vzprivnet_range *legacy_first(void)
{
	struct rb_node *node;

	node = rb_first(&rbroot);
	if (!node)
		return NULL;

	return rb_entry(node, struct vzprivnet_range, node);
}

static struct vzprivnet_range *legacy_next(struct vzprivnet_range *p)
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
	.weak = VZPRIVNET_INET
};

static struct vzprivnet *vzpriv_search(u32 ip)
{
	struct vzprivnet_range *pnr;

	pnr = tree_search(&entries_root, ip);
	if (pnr == NULL)
		pnr = legacy_search(ip);

	if (pnr != NULL)
		return pnr->pn;
	else
		return &vzpriv_internet;
}

static noinline unsigned int vzprivnet_classify(struct sk_buff *skb, int type)
{
	int res;
	u32 saddr, daddr;
	struct vzprivnet *p1, *p2;

	per_cpu(lookup_stat[type], smp_processor_id())++;

	saddr = ip_hdr(skb)->saddr;
	daddr = ip_hdr(skb)->daddr;

	read_lock(&vzprivlock);
	p1 = vzpriv_search(saddr);
	p2 = vzpriv_search(daddr);

	if (p1 == p2) {
		if ((saddr & p1->nmask) == (daddr & p1->nmask))
			res = NF_ACCEPT;
		else
			res = NF_DROP;
	} else {
		if (p1->weak + p2->weak >= 3)
			res = NF_ACCEPT;
		else
			res = NF_DROP;
	}

	read_unlock(&vzprivlock);
	return res;
}

int vzpn_handle_bridged = 0;
EXPORT_SYMBOL(vzpn_handle_bridged);

int vzpn_filter_host = 0;
EXPORT_SYMBOL(vzpn_filter_host);

static unsigned int vzprivnet_hook(struct sk_buff *skb, int can_be_bridge)
{
	struct dst_entry *dst;
	struct net *src_net;

	if (WARN_ON_ONCE(!skb->dev && !skb->sk))
		return NF_ACCEPT;

	src_net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);
	if (!ve_is_super(src_net->owner_ve))
		return NF_ACCEPT;

	dst = skb_dst(skb);
	if (dst != NULL && can_be_bridge && dst->output != ip_output) { /* bridge */
		if (vzpn_handle_bridged)
			return vzprivnet_classify(skb, 1);
		else
			return NF_ACCEPT;
	}

	return vzprivnet_classify(skb, 0);
}

static unsigned int vzprivnet_fwd_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb, const struct net_device *in,
		const struct net_device *out, const struct nf_hook_state *state)
{
	return vzprivnet_hook(skb, 1);
}

static unsigned int vzprivnet_host_hook(struct sk_buff *skb,
		const struct net_device *dev, int can_be_bridge)
{
	if (!vzpn_filter_host)
		return NF_ACCEPT;

	/*
	 * Only packets coming from venet or going to one matter
	 */
	if (!(dev->features & NETIF_F_VENET))
		return NF_ACCEPT;

	return vzprivnet_hook(skb, can_be_bridge);
}

static unsigned int vzprivnet_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb, const struct net_device *in,
		const struct net_device *out, const struct nf_hook_state *state)
{
	return vzprivnet_host_hook(skb, in, 0); /* bridge doesn't call it */
}

static unsigned int vzprivnet_out_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb, const struct net_device *in,
		const struct net_device *out, const struct nf_hook_state *state)
{
	return vzprivnet_host_hook(skb, out, 1);
}

static struct nf_hook_ops vzprivnet_ops[] = {
	{
		.hook = vzprivnet_fwd_hook,
		.owner = THIS_MODULE,
		.pf = PF_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FIRST
	},
	{
		.hook = vzprivnet_in_hook,
		.owner = THIS_MODULE,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FIRST
	},
	{
		.hook = vzprivnet_out_hook,
		.owner = THIS_MODULE,
		.pf = PF_INET,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FIRST
	},
};

static inline u32 to_netmask(int prefix)
{
	return htonl((~0 << (32 - prefix)));
}

static inline unsigned int to_prefix(u32 netmask)
{
	netmask = ntohl(netmask);
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
	err = legacy_insert(p);
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
	p = legacy_search(net);
	if (p == NULL) {
		write_unlock_bh(&vzprivlock);
		return -ENOENT;
	}

	legacy_delete(p);
	write_unlock_bh(&vzprivlock);
	kfree(p->pn);
	kfree(p);
	return 0;
}

static void sparse_free_one(struct vzprivnet_sparse *pns);
static void vzprivnet_cleanup(void)
{
	struct vzprivnet_range *p;
	struct vzprivnet_sparse *pns;

	write_lock_bh(&vzprivlock);
	while (1) {
		p = legacy_first();
		if (!p)
			break;
		legacy_delete(p);
		kfree(p->pn);
		kfree(p);
	}

	while (!list_empty(&vzpriv_sparse)) {
		pns = list_first_entry(&vzpriv_sparse,
				struct vzprivnet_sparse, list);
		sparse_free_one(pns);
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

	*weak = VZPRIVNET_STRONG;
	if (err == 7) {
		if (e == '*')
			*weak = VZPRIVNET_WEAK;
		else if (e != '\n' || !isspace(e))
			return -EINVAL;
	}

	*net = htonl((a << 24) + (b << 16) + (c << 8) + d);
	if (ch == '+') {
		if (err < 6 || m1 == 0 || m1 > 32 || m2 == 0 || m2 > 32)
			return -EINVAL;

		*netmask1 = to_netmask(m1);
		*netmask2 = to_netmask(m2);
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

		p = legacy_first();
		while (n-- && p)
			p = legacy_next(p);

		return p;
	}

	return legacy_first();
}

static void *vzprivnet_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	(*pos)++;

	return legacy_next(v);
}

static void vzprivnet_seq_stop(struct seq_file *s, void *v)
{
	read_unlock_bh(&vzprivlock);
}

static int vzprivnet_seq_show(struct seq_file *s, void *v)
{
	struct vzprivnet_range *p = v;

	seq_printf(s, "%pI4/%u/%u", &p->netip,
		   to_prefix(p->rmask), to_prefix(p->pn->nmask));
	if (p->pn->weak == VZPRIVNET_WEAK)
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

static int sparse_add(unsigned int netid, u32 ip, u32 mask, int weak)
{
	int err;
	struct vzprivnet_sparse *pns, *epns = NULL;
	struct vzprivnet_entry *pne = NULL;

	err = -ENOMEM;

	pns = kmalloc(sizeof(struct vzprivnet_sparse), GFP_KERNEL);
	if (pns == NULL)
		goto out;

	pne = kmalloc(sizeof(struct vzprivnet_entry), GFP_KERNEL);
	if (pne == NULL)
		goto out;

	write_lock_bh(&vzprivlock);
	list_for_each_entry(epns, &vzpriv_sparse, list)
		if (epns->netid == netid) {
			kfree(pns);
			pns = epns;
			goto found_net;
		}

	pns->netid = netid;
	pns->pn.nmask = 0;
	pns->pn.weak =  VZPRIVNET_STRONG;
	INIT_LIST_HEAD(&pns->entries);

found_net:
	if (ip != 0) {
		pne->range.netip = ip & mask;
		pne->range.rmask = mask;
		pne->range.pn = &pns->pn;
		err = tree_insert(&entries_root, &pne->range);
		if (err)
			goto out_unlock;

		list_add_tail(&pne->list, &pns->entries);
		pne = NULL;
	} else if (weak == VZPRIVNET_WEAK) {
		pns->pn.weak = VZPRIVNET_WEAK;
	} else if (pns == epns) {
		err = -EEXIST;
		goto out_unlock;
	}

	if (pns != epns) {
		list_add_tail(&pns->list, &vzpriv_sparse);
		pns = NULL;
	}

	err = 0;

out_unlock:
	write_unlock_bh(&vzprivlock);
out:
	if (pns != epns)
		kfree(pns);
	kfree(pne);

	return err;
}

static void sparse_free_entry(struct vzprivnet_entry *pne)
{
	list_del(&pne->list);
	rb_erase(&pne->range.node, &entries_root);
	kfree(pne);
}

static void sparse_free_one(struct vzprivnet_sparse *pns)
{
	struct vzprivnet_entry *pne;

	list_del(&pns->list);

	while (!list_empty(&pns->entries)) {
		pne = list_first_entry(&pns->entries,
				struct vzprivnet_entry, list);
		sparse_free_entry(pne);
	}

	kfree(pns);
}

static int sparse_del_net(unsigned int netid, int weak)
{
	struct vzprivnet_sparse *pns;

	list_for_each_entry(pns, &vzpriv_sparse, list)
		if (pns->netid == netid) {
			if (weak == VZPRIVNET_WEAK)
				pns->pn.weak = VZPRIVNET_STRONG;
			else
				sparse_free_one(pns);
			return 0;
		}

	return -ENOENT;
}

static int sparse_del_ip(u32 ip)
{
	struct vzprivnet_range *rng;
	struct vzprivnet_entry *pne;

	rng = tree_search(&entries_root, ip);
	if (rng == NULL)
		return -ENOENT;

	pne = container_of(rng, struct vzprivnet_entry, range);
	sparse_free_entry(pne);

	return 0;
}

static int sparse_del(unsigned int netid, u32 ip, int weak)
{
	int err;

	write_lock_bh(&vzprivlock);
	if (ip != 0)
		err = sparse_del_ip(ip);
	else
		err = sparse_del_net(netid, weak);
	write_unlock_bh(&vzprivlock);

	return err;
}

/*
 * +ID			to add a network
 * +ID:a.b.c.d		to add an IP to network
 * +ID:a.b.c.d/m	to add a subnet to network
 * +ID:*		to make a network weak
 * -ID			to remove the whole network
 * -a.b.c.d		to remove an IP or bounding subnet (from its network)
 * -ID:*		to make a network "strong" ;)
 *
 *  No weak networks here!
 */

static int parse_sparse_add(const char *str, unsigned int *netid, u32 *ip, u32 *mask, int *weak)
{
	unsigned int m;
	char *end;

	*netid = simple_strtol(str, &end, 10);
	if (is_eol(*end)) {
		*ip = 0;
		return 0;
	}

	if (*end != ':')
		return -EINVAL;

	str = end + 1;
	if (*str == '*') {
		if (!is_eol(*(str + 1)))
			return -EINVAL;

		*weak = VZPRIVNET_WEAK;
		return 0;
	}

	if (!in4_pton(str, -1, (u8 *)ip, -1, (const char **)&end))
		return -EINVAL;

	if (is_eol(*end)) {
		*mask = -1; /* match only one IP */
		return 0;
	}

	if (*end != '/')
		return -EINVAL;

	str = end + 1;
	m = simple_strtol(str, &end, 10);
	if (!is_eol(*end))
		return -EINVAL;

	*mask = to_netmask(m);
	return 0;
}

static int parse_sparse_remove(const char *str, unsigned int *netid, u32 *ip, int *weak)
{
	char *end;

	if (strchr(str, '.')) {
		if (!in4_pton(str, -1, (u8 *)ip, -1, (const char **)&end))
			return -EINVAL;
	} else {
		*netid = simple_strtol(str, &end, 10);
		if (end[0] == ':' && end[1] == '*') {
			end += 2;
			*weak = VZPRIVNET_WEAK;
		}
	}

	return (is_eol(*end) ? 0 : -EINVAL);
}

static int parse_sparse(const char *param, int *add,
		unsigned int *netid, u32 *ip, u32 *mask, int *weak)
{
	if (param[0] == '+') {
		*add = 1;
		return parse_sparse_add(param + 1, netid, ip, mask, weak);
	}

	if (param[0] == '-') {
		*add = 0;
		return parse_sparse_remove(param + 1, netid, ip, weak);
	}

	return -EINVAL;
}

static ssize_t sparse_write(struct file * file, const char __user *buf,
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
		int add, weak = VZPRIVNET_STRONG;
		unsigned int netid = 0;
		u32 ip = 0, mask = 0;

		err = parse_sparse(s, &add, &netid, &ip, &mask, &weak);
		if (err)
			goto out;

		if (add)
			err = sparse_add(netid, ip, mask, weak);
		else
			err = sparse_del(netid, ip, weak);

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

static void *sparse_seq_start(struct seq_file *seq, loff_t *pos)
{
	read_lock_bh(&vzprivlock);
	return seq_list_start(&vzpriv_sparse, *pos);
}

static void *sparse_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return seq_list_next(v, &vzpriv_sparse, pos);
}

static void sparse_seq_stop(struct seq_file *s, void *v)
{
	read_unlock_bh(&vzprivlock);
}

static int sparse_seq_show(struct seq_file *s, void *v)
{
	struct list_head *lh = v;
	struct vzprivnet_sparse *pns;
	struct vzprivnet_entry *pne;

	pns = list_entry(lh, struct vzprivnet_sparse, list);
	seq_printf(s, "%u: ", pns->netid);

	if (pns->pn.weak == VZPRIVNET_WEAK)
		seq_puts(s, "* ");

	list_for_each_entry(pne, &pns->entries, list) {
		seq_printf(s, "%pI4", &pne->range.netip);
		if (~pne->range.rmask != 0) /* subnet */
			seq_printf(s, "/%u", to_prefix(pne->range.rmask));
		seq_putc(s, ' ');
	}

	seq_putc(s, '\n');

	return 0;
}

static struct seq_operations sparse_seq_ops = {
	.start = sparse_seq_start,
	.next  = sparse_seq_next,
	.stop  = sparse_seq_stop,
	.show  = sparse_seq_show,
};

static int sparse_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &sparse_seq_ops);
}

static struct file_operations proc_sparse_ops = {
	.owner   = THIS_MODULE,
	.open    = sparse_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
	.write   = sparse_write,
};

static void (*show_more)(struct seq_file *s);
static DEFINE_MUTEX(show_lock);

static void vzprivnet_reg_swap(vzprivnet_show_fn old, vzprivnet_show_fn new)
{
	mutex_lock(&show_lock);
	if (show_more == old)
		show_more = new;
	mutex_unlock(&show_lock);
}

static void vzprivnet_show_more(struct seq_file *f)
{
	mutex_lock(&show_lock);
	if (show_more != NULL)
		show_more(f);
	mutex_unlock(&show_lock);
}

void vzprivnet_reg_show(vzprivnet_show_fn fn)
{
	vzprivnet_reg_swap(NULL, fn);
}
EXPORT_SYMBOL(vzprivnet_reg_show);

void vzprivnet_unreg_show(vzprivnet_show_fn fn)
{
	vzprivnet_reg_swap(fn, NULL);
}
EXPORT_SYMBOL(vzprivnet_unreg_show);

static int stat_seq_show(struct seq_file *s, void *v)
{
	unsigned long sum[2];
	int cpu;

	sum[0] = sum[1] = 0;
	for_each_possible_cpu(cpu) {
		sum[0] += per_cpu(lookup_stat[0], cpu);
		sum[1] += per_cpu(lookup_stat[1], cpu);
	}

	seq_printf(s, "Lookups: %lu\n", sum[0]);
	seq_printf(s, "Br-lookups: %lu\n", sum[1]);
	vzprivnet_show_more(s);

	return 0;
}

static int stat_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, &stat_seq_show, NULL);
}

static struct file_operations proc_stat_ops = {
	.owner   = THIS_MODULE,
	.open    = stat_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static char sample_ip[16];

static ssize_t classify_write(struct file * file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	size_t len;
	char *tmp;

	len = count;
	if (len >= sizeof(sample_ip))
		len = sizeof(sample_ip) - 1;

	if (copy_from_user(sample_ip, buf, len))
		return -EFAULT;

	sample_ip[len] = '\0';
	tmp = strchr(sample_ip, '\n');
	if (tmp)
		*tmp = '\0';

	return count;
}

static int classify_seq_show(struct seq_file *s, void *v)
{
	u32 ip;
	struct vzprivnet_range *pnr;

	seq_printf(s, "%s: ", sample_ip);

	if (!in4_pton(sample_ip, sizeof(sample_ip), (u8 *)&ip, -1, NULL)) {
		seq_puts(s, "invalid IP\n");
		return 0;
	}

	read_lock(&vzprivlock);
	pnr = tree_search(&entries_root, ip);
	if (pnr != NULL) {
		struct vzprivnet_sparse *pns;

		pns = container_of(pnr->pn, struct vzprivnet_sparse, pn);
		seq_printf(s, "net %u, ", pns->netid);
		seq_printf(s, "rule %pI4", &pnr->netip);
		if (~pnr->rmask != 0)
			seq_printf(s, "/%u", to_prefix(pnr->rmask));
		seq_putc(s, '\n');

		goto out;
	}

	pnr = legacy_search(ip);
	if (pnr != NULL) {
		seq_printf(s, "legacy %pI4/%u/%u\n",
				&pnr->netip,
				to_prefix(pnr->rmask),
				to_prefix(pnr->pn->nmask));

		goto out;
	}

	seq_printf(s, "internet\n");
out:
	read_unlock(&vzprivlock);
	return 0;
}

static int classify_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, &classify_seq_show, NULL);
}

static struct file_operations proc_classify_ops = {
	.owner   = THIS_MODULE,
	.open    = classify_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write	 = classify_write,
};

struct proc_dir_entry *vzpriv_proc_dir;
EXPORT_SYMBOL(vzpriv_proc_dir);

static struct ctl_table vzprivnet_table[] = {
	{
		.procname = "net",
		.child = vzprivnet_table + 2,
	},
	{ },
	{
		.procname = "vzpriv_handle_bridge",
		.data = &vzpn_handle_bridged,
		.maxlen = sizeof(vzpn_handle_bridged),
		.mode = 0600,
		.proc_handler = proc_dointvec,
	},
	{
		.procname = "vzpriv_filter_host",
		.data = &vzpn_filter_host,
		.maxlen = sizeof(vzpn_filter_host),
		.mode = 0600,
		.proc_handler = proc_dointvec,
	},
	{ },
};

static struct ctl_table_header *ctl;

static int __init iptable_vzprivnet_init(void)
{
	int err = -ENOMEM;
	struct proc_dir_entry *proc;

	vzpriv_proc_dir = proc_mkdir("privnet", proc_vz_dir);
	if (vzpriv_proc_dir == NULL)
		goto err_mkdir;

	proc = proc_create("legacy", 0644,
			vzpriv_proc_dir, &proc_vzprivnet_ops);
	if (proc == NULL)
		goto err_legacy;

	proc = proc_create("sparse", 0644,
			vzpriv_proc_dir, &proc_sparse_ops);
	if (proc == NULL)
		goto err_net;

	proc = proc_create("stat", 0644,
			vzpriv_proc_dir, &proc_stat_ops);
	if (proc == NULL)
		goto err_stat;

	proc = proc_create("classify", 0644,
			vzpriv_proc_dir, &proc_classify_ops);
	if (proc == NULL)
		goto err_classify;

	proc = proc_symlink(VZPRIV_PROCNAME, init_net.proc_net, "/proc/vz/privnet/legacy");
	if (proc == NULL)
		goto err_link;

	err = -ENOMEM;
	ctl = register_sysctl_table(vzprivnet_table);
	if (ctl == NULL)
		goto err_ctl;

	err = nf_register_hooks(vzprivnet_ops, 3);
	if (err)
		goto err_reg;

	return 0;

err_reg:
	unregister_sysctl_table(ctl);
err_ctl:
	remove_proc_entry(VZPRIV_PROCNAME, init_net.proc_net);
err_link:
	remove_proc_entry("classify", vzpriv_proc_dir);
err_classify:
	remove_proc_entry("stat", vzpriv_proc_dir);
err_stat:
	remove_proc_entry("sparse", vzpriv_proc_dir);
err_net:
	remove_proc_entry("legacy", vzpriv_proc_dir);
err_legacy:
	remove_proc_entry("privnet", proc_vz_dir);
err_mkdir:
	return err;
}

static void __exit iptable_vzprivnet_exit(void)
{
	nf_unregister_hooks(vzprivnet_ops, 3);
	unregister_sysctl_table(ctl);
	remove_proc_entry(VZPRIV_PROCNAME, init_net.proc_net);
	remove_proc_entry("classify", vzpriv_proc_dir);
	remove_proc_entry("stat", vzpriv_proc_dir);
	remove_proc_entry("sparse", vzpriv_proc_dir);
	remove_proc_entry("legacy", vzpriv_proc_dir);
	remove_proc_entry("privnet", proc_vz_dir);
	vzprivnet_cleanup();
}

module_init(iptable_vzprivnet_init)
module_exit(iptable_vzprivnet_exit)

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Virtuozzo <devel@openvz.org>");
