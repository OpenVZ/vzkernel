/*
 *  net/ipv6/netfilter/ip6_vzprivnet.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/vzprivnet.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/inet.h>
#include <net/ipv6.h>

static DEFINE_RWLOCK(vzpriv6lock);

struct vzprivnet {
	unsigned int netid;
	int weak;
	unsigned int subnet_preflen;
	struct list_head list;
	struct list_head entries;
};

static LIST_HEAD(sparse6_vzprivnets);

struct vzprivnet_entry {
	__u32 ip[4];
	unsigned preflen;
	struct vzprivnet *pn;
	struct vzprivnet6_node *n;
	struct list_head list;
};

struct vzprivnet6_node
{
	struct vzprivnet6_node	*parent;
	struct vzprivnet6_node	*left;
	struct vzprivnet6_node	*right;

	struct vzprivnet_entry	*entry;

	__u16			fn_bit;		/* bit key */
	__u16			fn_flags;
};

struct vzprivnet internet = {
	.weak = VZPRIVNET_INET,
};

#define RTN_RTINFO		1

static struct vzprivnet_entry sparse6_null_entry = {
	.preflen = 128,
	.pn = &internet,
};

static struct vzprivnet6_node sparse6_root_node = {
	.entry		= &sparse6_null_entry,
	.fn_flags	= RTN_RTINFO,
};

static struct vzprivnet_entry legacy6_null_entry = {
	.preflen = 128,
	.pn = &internet,
};

static struct vzprivnet6_node legacy6_root_node = {
	.entry		= &legacy6_null_entry,
	.fn_flags	= RTN_RTINFO,
};

static LIST_HEAD(legacy6_vzprivnets);

static inline int ip6_match(u32 *net, unsigned plen, u32 *ip)
{
	return ipv6_prefix_equal((const struct in6_addr *)net, (const struct in6_addr *)ip, plen);
}

static inline int ip6_intersect(u32 *ip1, unsigned len1, u32 *ip2, unsigned len2)
{
	return ip6_match(ip1, len1, ip2) || ip6_match(ip2, len2, ip1);
}

static __inline__ int addr_bit_set(void *ip, int fn_bit)
{
	__u32 *addr = ip;

	return htonl(1 << ((~fn_bit)&0x1F)) & addr[fn_bit>>5];
}

static __inline__ void vzprivnet6_node_free(struct vzprivnet6_node * fn)
{
	kfree(fn);
}

static __inline__ struct vzprivnet6_node * vzprivnet6_node_alloc(void)
{
	return kzalloc(sizeof(struct vzprivnet6_node), GFP_ATOMIC);
}

static struct vzprivnet6_node * radix_tree_search(struct vzprivnet6_node *root,
					struct in6_addr *addr)
{
	struct vzprivnet6_node *fn;
	int dir;

	fn = root;

	for (;;) {
		struct vzprivnet6_node *next;

		dir = addr_bit_set(addr, fn->fn_bit);

		next = dir ? fn->right : fn->left;
		if (next) {
			fn = next;
			continue;
		}

		break;
	}

	if (ip6_match(fn->entry->ip, fn->entry->preflen, (u32 *)addr))
		return fn;

	return NULL;
}

static struct vzprivnet_entry *vzprivnet6_lookup(struct vzprivnet6_node *root,
						u32 *ip)
{
	struct vzprivnet6_node *n;

	n = radix_tree_search(root, (struct in6_addr *)ip);
	return (n) ? n->entry : NULL;
}

static inline struct vzprivnet *vzprivnet6_lookup_net(u32 *ip)
{
	struct vzprivnet_entry *pne;

	pne = vzprivnet6_lookup(&sparse6_root_node, ip);
	if (pne == NULL)
		pne = vzprivnet6_lookup(&legacy6_root_node, ip);

	if (pne != NULL)
		return pne->pn;
	else
		return &internet;
}

static inline int noip(u32 *ip)
{
	return (ip[0] | ip[1] | ip[2] | ip[3]) == 0;
}

static struct vzprivnet6_node * radix_tree_add(void *addr, unsigned plen,
						struct vzprivnet6_node *root)
{
	struct vzprivnet6_node *fn, *in, *ln;
	struct vzprivnet6_node *pn = NULL;
	struct vzprivnet_entry *pne = NULL;
	int	bit;
	int	dir = 0;

	/* insert node in tree */

	fn = root;

	do {
		pne = fn->entry;
		if (ip6_intersect(pne->ip, pne->preflen, (u32 *)addr, plen))
			return ERR_PTR(-EEXIST);

		/*
		 *	Prefix match
		 */
		if (plen < fn->fn_bit ||
		    !ipv6_prefix_equal((struct in6_addr *)pne->ip, addr, fn->fn_bit))
			goto insert_intermediate_node;

		dir = addr_bit_set(addr, fn->fn_bit);
		pn = fn;
		fn = dir ? fn->right : fn->left;
	} while (fn);

	/*
	 *	We walked to the bottom of tree.
	 *	Create new leaf node without children.
	 */

	ln = vzprivnet6_node_alloc();
	if (ln == NULL)
		return ERR_PTR(-ENOMEM);

	ln->fn_bit = plen;
	ln->parent = pn;

	if (dir)
		pn->right = ln;
	else
		pn->left  = ln;

	return ln;

insert_intermediate_node:

	pn = fn->parent;

	bit = ipv6_addr_diff(addr, (struct in6_addr *)pne->ip);

	BUG_ON(plen <= bit);

	/*
	 *		(intermediate)[in]
	 *	          /	   \
	 *	(new leaf node)[ln] (old node)[fn]
	 */
	in = vzprivnet6_node_alloc();
	ln = vzprivnet6_node_alloc();

	if (in == NULL || ln == NULL) {
		if (in)
			vzprivnet6_node_free(in);
		if (ln)
			vzprivnet6_node_free(ln);
		return ERR_PTR(-ENOMEM);
	}

	/*
	 * new intermediate node.
	 * RTN_RTINFO will be off
	 */

	in->fn_bit = bit;

	in->parent = pn;
	in->entry = fn->entry;

	/* update parent pointer */
	if (dir)
		pn->right = in;
	else
		pn->left  = in;

	ln->fn_bit = plen;

	ln->parent = in;
	fn->parent = in;

	if (addr_bit_set(addr, bit)) {
		in->right = ln;
		in->left  = fn;
	} else {
		in->left  = ln;
		in->right = fn;
	}

	return ln;
}

static struct vzprivnet6_node * sparse6_add_subnet(void *addr, unsigned plen)
{
	return radix_tree_add(addr, plen, &sparse6_root_node);
}

static int sparse6_add(unsigned netid, u32 *ip, unsigned preflen, int weak)
{
	int err;
	struct vzprivnet *pn = NULL, *epn = NULL;
	struct vzprivnet_entry *pne = NULL;

	err = -ENOMEM;
	pn = kzalloc(sizeof(*pn), GFP_KERNEL);
	if (pn == NULL)
		goto out;

	pne = kzalloc(sizeof(*pne), GFP_KERNEL);
	if (pne == NULL)
		goto out;

	write_lock_bh(&vzpriv6lock);
	list_for_each_entry(epn, &sparse6_vzprivnets, list)
		if (epn->netid == netid) {
			kfree(pn);
			pn = epn;
			goto found_net;
		}

	pn->netid = netid;
	pn->weak = weak;
	INIT_LIST_HEAD(&pn->entries);

found_net:
	if (!noip(ip)) {
		struct vzprivnet6_node *n;

		n = sparse6_add_subnet(ip, preflen);
		if (IS_ERR(n)) {
			err = PTR_ERR(n);
			goto out_unlock;
		}

		n->entry = pne;
		n->fn_flags |= RTN_RTINFO;

		memcpy(pne->ip, ip, sizeof(pne->ip));
		pne->preflen = preflen;
		pne->pn = pn;
		list_add_tail(&pne->list, &pn->entries);
		pne->n = n;
		pne = NULL;
	} else if (weak == VZPRIVNET_WEAK) {
		pn->weak =  VZPRIVNET_WEAK;
	} else if (pn == epn) {
		err = -EEXIST;
		goto out_unlock;
	}

	if (pn != epn) {
		list_add_tail(&pn->list, &sparse6_vzprivnets);
		pn = NULL;
	}

	err = 0;

out_unlock:
	write_unlock_bh(&vzpriv6lock);
out:
	if (pn != epn)
		kfree(pn);
	kfree(pne);

	return err;
}

static void radix_tree_del(struct vzprivnet6_node *fn)
{
	int children;
	struct vzprivnet6_node *child, *pn;

	BUG_ON(fn->parent == NULL);

	for (;;) {
		children = 0;
		child = NULL;

		if (fn->right) {
			child = fn->right;
			children |= 1;
		}
		if (fn->left) {
			child = fn->left;
			children |= 2;
		}

		if (children == 3)
			return;

		pn = fn->parent;
		if (pn->right == fn)
			pn->right = child;
		else if (pn->left == fn)
			pn->left = child;

		if (child)
			child->parent = pn;

		vzprivnet6_node_free(fn);
		if (pn->fn_flags & RTN_RTINFO)
			return;

		fn = pn;
	}
}


static void vzprivnet6_del_entry(struct vzprivnet_entry *pne)
{
	radix_tree_del(pne->n);
}


static void sparse6_free_entry(struct vzprivnet_entry *pne)
{
	list_del(&pne->list);
	vzprivnet6_del_entry(pne);
	kfree(pne);
}

static void vzprivnet6_del_one(struct vzprivnet *pn)
{
	struct vzprivnet_entry *pne;

	list_del(&pn->list);

	while (!list_empty(&pn->entries)) {
		pne = list_first_entry(&pn->entries,
				struct vzprivnet_entry, list);
		sparse6_free_entry(pne);
	}

	kfree(pn);
}

static void vzprivnet6_cleanup(void)
{
	struct vzprivnet *pn;

	write_lock_bh(&vzpriv6lock);
	while (!list_empty(&sparse6_vzprivnets)) {
		pn = list_first_entry(&sparse6_vzprivnets,
				struct vzprivnet, list);
		vzprivnet6_del_one(pn);
	}
	while (!list_empty(&legacy6_vzprivnets)) {
		pn = list_first_entry(&legacy6_vzprivnets,
				struct vzprivnet, list);
		vzprivnet6_del_one(pn);
	}
	write_unlock_bh(&vzpriv6lock);
}

static int sparse6_del_net(unsigned netid, int weak)
{
	struct vzprivnet *pn;

	list_for_each_entry(pn, &sparse6_vzprivnets, list) {
		if (pn->netid != netid)
			continue;

		if (weak == VZPRIVNET_WEAK)
			pn->weak = VZPRIVNET_STRONG;
		else
			vzprivnet6_del_one(pn);

		return 0;
	}

	return -ENOENT;
}

static int sparse6_del_ip(u32 *ip)
{
	struct vzprivnet_entry *pne;

	pne = vzprivnet6_lookup(&sparse6_root_node, ip);
	if (pne == NULL)
		return -ENOENT;

	sparse6_free_entry(pne);
	return 0;
}

static int sparse6_del(unsigned netid, u32 *ip, int weak)
{
	int err;

	write_lock_bh(&vzpriv6lock);
	if (!noip(ip))
		err = sparse6_del_ip(ip);
	else
		err = sparse6_del_net(netid, weak);
	write_unlock_bh(&vzpriv6lock);

	return err;
}

static inline int is_ipv6_neighbour_solicit(const struct in6_addr *addr)
{
	/* see addrconf_addr_solict_mult */
	return (addr->s6_addr32[0] == __constant_htonl(0xFF020000) &&
		addr->s6_addr32[1] == 0 &&
		addr->s6_addr32[2] == __constant_htonl(1) &&
		(addr->s6_addr32[3] & __constant_htonl(0xFF000000)) == __constant_htonl(0xFF000000));
}

static unsigned int vzprivnet6_hook(struct sk_buff *skb, int can_be_bridge)
{
	int verdict = NF_DROP;
	struct vzprivnet *dst, *src;
	struct ipv6hdr *hdr;
	struct net *src_net;

	if (WARN_ON_ONCE(!skb->dev && !skb->sk))
		return NF_ACCEPT;

	src_net = skb->dev ? dev_net(skb->dev) : sock_net(skb->sk);
	if (!ve_is_super(src_net->owner_ve))
		return NF_ACCEPT;

	hdr = ipv6_hdr(skb);

	if (can_be_bridge) {
		if (!vzpn_handle_bridged &&
				skb_dst(skb) != NULL &&
				skb_dst(skb)->output != ip6_output)
			return NF_ACCEPT;
		if (is_ipv6_neighbour_solicit(&hdr->daddr))
			return NF_ACCEPT;
	}

	read_lock(&vzpriv6lock);

	src = vzprivnet6_lookup_net(hdr->saddr.in6_u.u6_addr32);
	dst = vzprivnet6_lookup_net(hdr->daddr.in6_u.u6_addr32);

	if (src == dst) {
		if (ipv6_prefix_equal(&hdr->saddr, &hdr->daddr,
				      src->subnet_preflen))
			verdict = NF_ACCEPT;
	} else if (src->weak + dst->weak >= 3)
		verdict = NF_ACCEPT;

	read_unlock(&vzpriv6lock);

	return verdict;
}

static unsigned int vzprivnet6_fwd_hook(const struct nf_hook_ops *ops,
				  struct sk_buff *skb,
				  const struct net_device *in,
				  const struct net_device *out,
				  const struct nf_hook_state *state)
{
	return vzprivnet6_hook(skb, 1);
}

static unsigned int vzprivnet6_host_hook(struct sk_buff *skb,
		const struct net_device *dev, int can_be_bridge)
{
	if (!vzpn_filter_host)
		return NF_ACCEPT;
	if (!(dev->features & NETIF_F_VENET))
		return NF_ACCEPT;

	return vzprivnet6_hook(skb, can_be_bridge);
}

static unsigned int vzprivnet6_in_hook(const struct nf_hook_ops *ops,
				  struct sk_buff *skb,
				  const struct net_device *in,
				  const struct net_device *out,
				  const struct nf_hook_state *state)
{
	return vzprivnet6_host_hook(skb, in, 0);
}

static unsigned int vzprivnet6_out_hook(const struct nf_hook_ops *ops,
				  struct sk_buff *skb,
				  const struct net_device *in,
				  const struct net_device *out,
				  const struct nf_hook_state *state)
{
	return vzprivnet6_host_hook(skb, out, 1);
}

static struct nf_hook_ops vzprivnet6_ops[] = {
	{
		.hook = vzprivnet6_fwd_hook,
		.owner = THIS_MODULE,
		.pf = PF_INET6,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP6_PRI_FIRST
	},
	{
		.hook = vzprivnet6_in_hook,
		.owner = THIS_MODULE,
		.pf = PF_INET6,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP6_PRI_FIRST
	},
	{
		.hook = vzprivnet6_out_hook,
		.owner = THIS_MODULE,
		.pf = PF_INET6,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP6_PRI_FIRST
	},
};

static char *nextline(char *s)
{
	while(*s && *s != '\n') s++;
	while(*s && *s == '\n') s++;
	return s;
}

static int parse_sparse6_add(const char *str, unsigned int *netid, u32 *ip, unsigned *preflen, int *weak)
{
	char *end;

	*netid = simple_strtol(str, &end, 10);
	if (is_eol(*end))
		return 0;

	if (*end != ':')
		return -EINVAL;

	str = end + 1;
	if (*str == '*') {
		if (!is_eol(*(str + 1)))
			return -EINVAL;

		*weak = VZPRIVNET_WEAK;
		return 0;
	}

	if (!in6_pton(str, -1, (u8 *)ip, -1, (const char **)&end))
		return -EINVAL;

	if (*end != '/')
		return -EINVAL;

	str = end + 1;
	*preflen = simple_strtol(str, &end, 10);
	if (!is_eol(*end))
		return -EINVAL;

	return 0;
}

static int parse_sparse6_remove(const char *str, unsigned int *netid, u32 *ip, int *weak)
{
	char *end;

	if (strchr(str, ':') && !strchr(str, '*')) {
		if (!in6_pton(str, -1, (u8 *)ip, -1, (const char **)&end)) {
			printk("Bad ip in %s\n", str);
			return -EINVAL;
		}

		if (!is_eol(*end))
			printk("No EOL in %s\n", str);
	} else {
		*netid = simple_strtol(str, &end, 10);
		if (end[0] == ':' && end[1] == '*') {
			end += 2;
			*weak = VZPRIVNET_WEAK;
		}
	}

	return (is_eol(*end) ? 0 : -EINVAL);
}

static int parse_sparse6(const char *param, int *add,
		unsigned int *netid, u32 *ip, unsigned *preflen, int *weak)
{
	if (param[0] == '+') {
		*add = 1;
		return parse_sparse6_add(param + 1, netid, ip, preflen, weak);
	}

	if (param[0] == '-') {
		*add = 0;
		return parse_sparse6_remove(param + 1, netid, ip, weak);
	}

	return -EINVAL;
}

/*
 * +ID			to add a network
 * +ID:<addr>/m		to add a subnet to network
 * +ID:*		to make a network weak
 * -ID			to remove the whole network
 * -<addr>		to remove an IP or bounding subnet (from its network)
 * -ID:*		to make a network "strong" ;)
 *
 *  No weak networks here!
 */

static ssize_t sparse6_write(struct file * file, const char __user *buf,
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
		unsigned int netid = 0, preflen = 0;
		u32 ip[4] = { 0, 0, 0, 0 };

		err = parse_sparse6(s, &add, &netid, ip, &preflen, &weak);
		if (err)
			goto out;

		if (add)
			err = sparse6_add(netid, ip, preflen, weak);
		else
			err = sparse6_del(netid, ip, weak);

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

static void *sparse6_seq_start(struct seq_file *seq, loff_t *ppos)
{
	struct list_head *lh;
	loff_t pos = *ppos;

	read_lock(&vzpriv6lock);
	list_for_each(lh, &sparse6_vzprivnets)
		if (pos-- == 0)
			return lh;

	return NULL;
}

static void *sparse6_seq_next(struct seq_file *seq, void *v, loff_t *ppos)
{
	struct list_head *lh;

	lh = ((struct list_head *)v)->next;
	++*ppos;
	return lh == &sparse6_vzprivnets ? NULL : lh;
}

static void sparse6_seq_stop(struct seq_file *s, void *v)
{
	read_unlock(&vzpriv6lock);
}

static int sparse6_seq_show(struct seq_file *s, void *v)
{
	struct vzprivnet *pn;
	struct vzprivnet_entry *pne;

	pn = list_entry(v, struct vzprivnet, list);
	seq_printf(s, "%u: ", pn->netid);
	if (pn->weak == VZPRIVNET_WEAK)
		seq_puts(s, "* ");

	list_for_each_entry(pne, &pn->entries, list)
		seq_printf(s, "%pI6/%u ", pne->ip, pne->preflen);

	seq_putc(s, '\n');

	return 0;
}

static struct seq_operations sparse6_seq_ops = {
	.start = sparse6_seq_start,
	.next  = sparse6_seq_next,
	.stop  = sparse6_seq_stop,
	.show  = sparse6_seq_show,
};

static int sparse6_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &sparse6_seq_ops);
}

static struct file_operations proc_sparse6_ops = {
	.owner   = THIS_MODULE,
	.open    = sparse6_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
	.write   = sparse6_write,
};

static char sample_ipv6[42];

static ssize_t classify6_write(struct file * file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	size_t len;
	char *tmp;

	len = count;
	if (len >= sizeof(sample_ipv6))
		len = sizeof(sample_ipv6) - 1;

	if (copy_from_user(sample_ipv6, buf, len))
		return -EFAULT;

	sample_ipv6[len] = '\0';
	tmp = strchr(sample_ipv6, '\n');
	if (tmp)
		*tmp = '\0';

	return count;
}

static int classify6_seq_show(struct seq_file *s, void *v)
{
	u32 ip[4];
	struct vzprivnet_entry *pne;

	seq_printf(s, "%s: ", sample_ipv6);

	if (!in6_pton(sample_ipv6, sizeof(sample_ipv6), (u8 *)ip, -1, NULL)) {
		seq_puts(s, "invalid IP\n");
		return 0;
	}

	read_lock(&vzpriv6lock);
	pne = vzprivnet6_lookup(&sparse6_root_node, ip);
	if (pne != NULL) {
		seq_printf(s, "net %u, ", pne->pn->netid);
		seq_printf(s, "rule %pI6/%u\n", pne->ip, pne->preflen);
		goto out;
	}

	pne = vzprivnet6_lookup(&legacy6_root_node, ip);
	if (pne != NULL) {
		seq_printf(s, "legacy %pI6/%u/%u\n",
				pne->ip, pne->preflen, pne->pn->subnet_preflen);

	} else
		seq_printf(s, "internet\n");
out:
	read_unlock(&vzpriv6lock);
	return 0;
}

static int classify6_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, &classify6_seq_show, NULL);
}

static struct file_operations proc_classify6_ops = {
	.owner   = THIS_MODULE,
	.open    = classify6_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write	 = classify6_write,
};

static int legacy6_del(u32 *ip)
{
	struct vzprivnet_entry *pne;

	write_lock_bh(&vzpriv6lock);
	pne = vzprivnet6_lookup(&legacy6_root_node, ip);
	if (pne == NULL) {
		write_unlock_bh(&vzpriv6lock);
		return -ENOENT;
	}
	vzprivnet6_del_one(pne->pn);
	write_unlock_bh(&vzpriv6lock);

	return 0;
}

static struct vzprivnet6_node * legacy6_add_subnet(void *addr, unsigned plen)
{
	return radix_tree_add(addr, plen, &legacy6_root_node);
}

static int legacy6_add(u32 *ip, u32 preflen, u32 subnet_preflen)
{
	int err;
	struct vzprivnet *pn = NULL;
	struct vzprivnet_entry *pne = NULL;
	struct vzprivnet6_node *n;

	err = -ENOMEM;
	pn = kzalloc(sizeof(*pn), GFP_KERNEL);
	if (pn == NULL)
		goto out;

	pn->subnet_preflen = subnet_preflen;
	INIT_LIST_HEAD(&pn->entries);

	pne = kzalloc(sizeof(*pne), GFP_KERNEL);
	if (pne == NULL)
		goto out;

	write_lock_bh(&vzpriv6lock);
	n = legacy6_add_subnet(ip, preflen);
	if (IS_ERR(n)) {
		err = PTR_ERR(n);
		write_unlock_bh(&vzpriv6lock);
		goto out;
	}

	n->entry = pne;
	n->fn_flags |= RTN_RTINFO;

	memcpy(pne->ip, ip, sizeof(struct in6_addr));
	pne->preflen = preflen;
	pne->pn = pn;
	list_add_tail(&pne->list, &pn->entries);
	pne->n = n;

	list_add_tail(&pn->list, &legacy6_vzprivnets);
	write_unlock_bh(&vzpriv6lock);

	return 0;
out:
	kfree(pn);
	kfree(pne);

	return err;
}

static int parse_legacy6(char *param, int *add, u32 *ip,
				unsigned *preflen, unsigned *subnet_preflen)
{
	char *str, *end;

	if (param[0] == '+')
		*add = 1;
	else if (param[0] == '-')
		*add = 0;
	else
		return -EINVAL;

	str = param + 1;

	if (!in6_pton(str, -1, (u8 *)ip, -1, (const char **)&end))
		return -EINVAL;

	if (*end != '/')
		return -EINVAL;

	str = end + 1;
	*preflen = simple_strtol(str, &end, 10);

	if (*end != '/')
		return -EINVAL;

	str = end + 1;
	*subnet_preflen = simple_strtol(str, &end, 10);
	if (!is_eol(*end))
		return -EINVAL;

	if ((*preflen == 0) || (*preflen > 128) ||
		(*subnet_preflen == 0) || (*subnet_preflen > 128))
		return -EINVAL;

	if (*subnet_preflen < *preflen)
		return -EINVAL;

	return 0;
}

static ssize_t legacy6_write(struct file * file, const char __user *buf,
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
		int add;
		unsigned int preflen = 0, subnet_preflen = 0;
		u32 ip[4] = { 0, 0, 0, 0 };

		err = parse_legacy6(s, &add, ip, &preflen, &subnet_preflen);
		if (err)
			goto out;

		if (add)
			err = legacy6_add(ip, preflen, subnet_preflen);
		else
			err = legacy6_del(ip);

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

static void *legacy6_seq_start(struct seq_file *seq, loff_t *ppos)
{
	struct list_head *lh;
	loff_t pos = *ppos;

	read_lock(&vzpriv6lock);
	list_for_each(lh, &legacy6_vzprivnets)
		if (pos-- == 0)
			return lh;

	return NULL;
}

static void *legacy6_seq_next(struct seq_file *seq, void *v, loff_t *ppos)
{
	struct list_head *lh;

	lh = ((struct list_head *)v)->next;
	++*ppos;
	return lh == &legacy6_vzprivnets ? NULL : lh;
}

static void legacy6_seq_stop(struct seq_file *s, void *v)
{
	read_unlock(&vzpriv6lock);
}

static int legacy6_seq_show(struct seq_file *s, void *v)
{
	struct vzprivnet *pn;
	struct vzprivnet_entry *pne;

	pn = list_entry(v, struct vzprivnet, list);
	list_for_each_entry(pne, &pn->entries, list)
		seq_printf(s, "%pI6/%u/%u", pne->ip, pne->preflen,
							pne->pn->subnet_preflen);

	seq_putc(s, '\n');

	return 0;
}

static struct seq_operations legacy6_seq_ops = {
	.start = legacy6_seq_start,
	.next  = legacy6_seq_next,
	.stop  = legacy6_seq_stop,
	.show  = legacy6_seq_show,
};

static int legacy6_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &legacy6_seq_ops);
}

static struct file_operations proc_legacy6_ops = {
	.owner   = THIS_MODULE,
	.open    = legacy6_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
	.write   = legacy6_write,
};

static int __init ip6_vzprivnet_init(void)
{
	int err = -ENOMEM;
	struct proc_dir_entry *proc;

	proc = proc_create("sparse6", 0644,
			vzpriv_proc_dir, &proc_sparse6_ops);
	if (proc == NULL)
		goto err_sparse6;

	proc = proc_create("classify6", 0644,
			vzpriv_proc_dir, &proc_classify6_ops);
	if (proc == NULL)
		goto err_classify6;

	proc = proc_create("legacy6", 0644,
			vzpriv_proc_dir, &proc_legacy6_ops);
	if (proc == NULL)
		goto err_legacy6;

	err = nf_register_hooks(vzprivnet6_ops, 3);
	if (err)
		goto err_reg;

	return 0;

err_reg:
	remove_proc_entry("legacy6", vzpriv_proc_dir);
err_legacy6:
	remove_proc_entry("classify6", vzpriv_proc_dir);
err_classify6:
	remove_proc_entry("sparse6", vzpriv_proc_dir);
err_sparse6:
	return err;
}

static void __exit ip6_vzprivnet_exit(void)
{
	nf_unregister_hooks(vzprivnet6_ops, 3);
	remove_proc_entry("legacy6", vzpriv_proc_dir);
	remove_proc_entry("classify6", vzpriv_proc_dir);
	remove_proc_entry("sparse6", vzpriv_proc_dir);
	vzprivnet6_cleanup();
}

module_init(ip6_vzprivnet_init)
module_exit(ip6_vzprivnet_exit)

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Virtuozzo <devel@openvz.org>");
