#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/vzprivnet.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/inet.h>
#include <net/ipv6.h>

static DEFINE_RWLOCK(vzpriv6lock);

struct vzprivnet {
	unsigned int netid;
	int weak;
	struct list_head list;
	struct list_head entries;
};

static LIST_HEAD(vzprivnets);

struct vzprivnet_entry {
	__u32 ip[4];
	unsigned preflen;
	struct vzprivnet *pn;
	struct list_head list;
	struct hlist_node hash;
};

struct vzprivnet_hash {
	unsigned preflen;
	struct hlist_head *hash;
};

#define MAX_PREFLEN	128

static struct vzprivnet_hash hashes[MAX_PREFLEN];
static unsigned hash_rnd;

#define HASH_MASK	((PAGE_SIZE / sizeof(struct hlist_head)) - 1)

static noinline unsigned hash_ip_and_prefix(u32 *ip, unsigned preflen)
{
	u32 key[4];

	ipv6_addr_prefix((struct in6_addr *)key, (struct in6_addr *)ip, preflen);
	return jhash2(key, 4, hash_rnd) & HASH_MASK;
}

static inline int ip6_match(u32 *net, unsigned plen, u32 *ip)
{
	return ipv6_prefix_equal((const struct in6_addr *)net, (const struct in6_addr *)ip, plen);
}

static inline int ip6_intersect(u32 *ip1, unsigned len1, u32 *ip2, unsigned len2)
{
	return ip6_match(ip1, len1, ip2) || ip6_match(ip2, len2, ip1);
}

static struct vzprivnet_hash *vzprivnet6_get_hash(unsigned preflen)
{
	int i;
	struct hlist_head *hash = NULL;

	if (preflen == MAX_PREFLEN)
		return NULL;

again:
	write_lock_bh(&vzpriv6lock);
	for (i = 0; hashes[i].hash != NULL; i++)
		if (hashes[i].preflen == preflen) {
			write_unlock_bh(&vzpriv6lock);
			if (hash != NULL)
				free_page((unsigned long)hash);
			return hashes + i;
		}

	if (i == MAX_PREFLEN) {
		write_unlock_bh(&vzpriv6lock);
		if (hash != NULL)
			free_page((unsigned long)hash);

		WARN_ON_ONCE(1);
		return NULL;
	}

	if (hash != NULL) {
		hashes[i].preflen = preflen;
		hashes[i].hash = hash;
		write_unlock_bh(&vzpriv6lock);
		return hashes + i;
	}

	write_unlock_bh(&vzpriv6lock);

	hash = (struct hlist_head *)get_zeroed_page(GFP_KERNEL);
	if (hash == NULL)
		return NULL;

	goto again;
}

static struct vzprivnet_entry *vzprivnet6_lookup(u32 *ip)
{
	int i;

	for (i = 0; hashes[i].hash != NULL; i++) {
		struct vzprivnet_entry *pne;
		unsigned chain;

		chain = hash_ip_and_prefix(ip, hashes[i].preflen);
		hlist_for_each_entry(pne, &hashes[i].hash[chain], hash)
			/* hashes[i].preflen == pne->preflen here */
			if (ip6_match(pne->ip, pne->preflen, ip))
				return pne;
	}

	return NULL;
}

struct vzprivnet internet = {
	.weak = VZPRIVNET_INET,
};

static inline struct vzprivnet *vzprivnet6_lookup_net(u32 *ip)
{
	struct vzprivnet_entry *pne;

	pne = vzprivnet6_lookup(ip);
	if (pne != NULL)
		return pne->pn;
	else
		return &internet;
}

static void vzprivnet6_hash_entry(struct vzprivnet_entry *e, struct vzprivnet_hash *h)
{
	unsigned chain;

	chain = hash_ip_and_prefix(e->ip, e->preflen);
	hlist_add_head(&e->hash, &h->hash[chain]);
}

static void vzprivnet6_unhash_entry(struct vzprivnet_entry *e)
{
	hlist_del(&e->hash);
}

static inline int noip(u32 *ip)
{
	return (ip[0] | ip[1] | ip[2] | ip[3]) == 0;
}

static int sparse6_add(unsigned netid, u32 *ip, unsigned preflen, int weak)
{
	int err;
	struct vzprivnet *pn = NULL, *epn = NULL;
	struct vzprivnet_entry *pne = NULL, *tmp;
	struct vzprivnet_hash *hash;

	err = -ENOMEM;
	hash = vzprivnet6_get_hash(preflen);
	if (hash == NULL)
		goto out;

	pn = kzalloc(sizeof(*pn), GFP_KERNEL);
	if (pn == NULL)
		goto out;

	pne = kzalloc(sizeof(*pne), GFP_KERNEL);
	if (pne == NULL)
		goto out;

	write_lock_bh(&vzpriv6lock);
	list_for_each_entry(epn, &vzprivnets, list)
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
		err = -EEXIST;
		list_for_each_entry(tmp, &pn->entries, list)
			if (ip6_intersect(ip, preflen, tmp->ip, tmp->preflen))
				goto out_unlock;

		memcpy(pne->ip, ip, sizeof(pne->ip));
		pne->preflen = preflen;
		pne->pn = pn;
		list_add_tail(&pne->list, &pn->entries);
		vzprivnet6_hash_entry(pne, hash);
		pne = NULL;
	} else if (weak == VZPRIVNET_WEAK) {
		pn->weak =  VZPRIVNET_WEAK;
	} else if (pn == epn) {
		err = -EEXIST;
		goto out_unlock;
	}

	if (pn != epn) {
		list_add_tail(&pn->list, &vzprivnets);
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

static void sparse6_free_entry(struct vzprivnet_entry *pne)
{
	list_del(&pne->list);
	vzprivnet6_unhash_entry(pne);
	kfree(pne);
}

static void sparse6_del_one(struct vzprivnet *pn)
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
	while (!list_empty(&vzprivnets)) {
		pn = list_first_entry(&vzprivnets,
				struct vzprivnet, list);
		sparse6_del_one(pn);
	}
	write_unlock_bh(&vzpriv6lock);
}

static int sparse6_del_net(unsigned netid, int weak)
{
	struct vzprivnet *pn;

	list_for_each_entry(pn, &vzprivnets, list) {
		if (pn->netid != netid)
			continue;

		if (weak == VZPRIVNET_WEAK)
			pn->weak = VZPRIVNET_STRONG;
		else
			sparse6_del_one(pn);

		return 0;
	}

	return -ENOENT;
}

static int sparse6_del_ip(u32 *ip)
{
	struct vzprivnet_entry *pne;

	pne = vzprivnet6_lookup(ip);
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

	if (src == dst)
		verdict = NF_ACCEPT;
	else if (src->weak + dst->weak >= 3)
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
	list_for_each(lh, &vzprivnets)
		if (pos-- == 0)
			return lh;

	return NULL;
}

static void *sparse6_seq_next(struct seq_file *seq, void *v, loff_t *ppos)
{
	struct list_head *lh;

	lh = ((struct list_head *)v)->next;
	++*ppos;
	return lh == &vzprivnets ? NULL : lh;
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
	int len;
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
	pne = vzprivnet6_lookup(ip);
	if (pne == NULL) {
		seq_printf(s, "internet\n");
		goto out;
	}

	seq_printf(s, "net %u, ", pne->pn->netid);
	seq_printf(s, "rule %pI6/%u\n", pne->ip, pne->preflen);
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
	.release = seq_release,
	.write	 = classify6_write,
};

static void vzprivnet6_show_stat(struct seq_file *f)
{
	int i;

	for (i = 0; i < MAX_PREFLEN; i++)
		if (hashes[i].hash == NULL)
			break;

	seq_printf(f, "Hashes6: %d\n", i);
}

static int __init ip6_vzprivnet_init(void)
{
	int err = -ENOMEM;
	struct proc_dir_entry *proc;

	get_random_bytes(&hash_rnd, 4);

	proc = proc_create("sparse6", 0644,
			vzpriv_proc_dir, &proc_sparse6_ops);
	if (proc == NULL)
		goto err_sparse6;

	proc = proc_create("classify6", 0644,
			vzpriv_proc_dir, &proc_classify6_ops);
	if (proc == NULL)
		goto err_classify6;

	err = nf_register_hooks(vzprivnet6_ops, 3);
	if (err)
		goto err_reg;

	vzprivnet_reg_show(vzprivnet6_show_stat);
	return 0;

err_reg:
	remove_proc_entry("classify6", vzpriv_proc_dir);
err_classify6:
	remove_proc_entry("sparse6", vzpriv_proc_dir);
err_sparse6:
	return err;
}

static void __exit ip6_vzprivnet_exit(void)
{
	vzprivnet_unreg_show(vzprivnet6_show_stat);
	nf_unregister_hooks(vzprivnet6_ops, 3);
	remove_proc_entry("classify6", vzpriv_proc_dir);
	remove_proc_entry("sparse6", vzpriv_proc_dir);
	vzprivnet6_cleanup();
}

module_init(ip6_vzprivnet_init)
module_exit(ip6_vzprivnet_exit)
