/*
 * kernel/ve/vzredir/vzredir.c
 *
 * Copyright (c) 2004-2015 Parallels IP Holdings GmbH
 *
 */

/*
 * Traffic redirects support.
 * Persistent (independent from VE struct storage)
 */

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/veip.h>
#include <linux/inet.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/list.h>

#include <linux/sched.h>
#include <linux/ve.h>
#include <linux/ve_proto.h>
#include <linux/venet.h>
#include <linux/vzctl.h>
#include <linux/vznetstat.h>

#include <uapi/linux/vzctl_redir.h>
#include <linux/vzredir.h>

/*
 * 1. Each ve_struct keeps a reference to one veip_struct.
 *    veip_struct may exist without a ve_struct, specifying
 *    redirects for a stopped VE.
 *
 *    veip_struct exists iff
 *     - it has a reference from a VE, or
 *     - its src_lh, dst_lh or ip_lh not empty.
 *
 *    veip_struct contains a list of ip_entry_struct's.
 *
 * 2. ip_entry_struct is an entry to the data structures describing what
 *    to do with packets destined to a particular IP address (and for source
 *    IP address verification) in venet device.
 *
 *    ip_entry_struct's are stored in a hash by IP addresses.
 *
 *    If the IP address belongs to a stopped VE, active_env field of
 *    ip_entry_struct is NULL.
 *
 *
 * Locking scheme:
 *
 * 1. All lists above are protected by veip_hash_lock.
 * 2. All veip_XXX should be called with veip_hash_lock held (see comments
 *    below for the version of lock required (read or write).
 * 3. ve_list_guard should be taken before veip_hash_lock
 */

static void veip_free(struct veip_struct *veip)
{
	venet_acct_put_stat(veip->stat);
	kfree(veip);
}

static void veip_release(struct ve_struct *ve)
{
	struct veip_redir_port *port;
	struct veip_struct *veip;

	veip = ve->veip;
	ve->veip = NULL;
	barrier();

	list_for_each_entry(port, &veip->dst_lh, dst_list)
		port->target = NULL;

	veip_put(veip);
}

static struct veip_struct *vzredir_veip_findcreate(envid_t veid)
{
	struct veip_struct *veip;

	veip = veip_findcreate(veid);
	if (veip == NULL)
		return NULL;

	if (veip->stat)
		return veip;

	spin_unlock(&veip_lock);
	veip->stat = venet_acct_find_create_stat(veid);
	spin_lock(&veip_lock);
	if (veip->stat == NULL) {
		veip_put(veip);
		return NULL;
	}

	return veip;
}

static int veip_create(struct ve_struct *ve)
{
	struct veip_struct *veip;
	struct veip_redir_port *redir;
	int err;

	veip = vzredir_veip_findcreate(ve->veid);
	if (veip == NULL)
		return -ENOMEM;

	ve->veip = veip;
	list_for_each_entry(redir, &veip->dst_lh, dst_list)
		redir->target = ve;


	err = init_venet_acct_ip_stat(ve, veip->stat);
	if (err < 0) {
		veip_free(veip);
		return err;
	}

	return 0;
}

#define VENET_PORT_UNDEFINED (0xffff)

static inline int redir_match_port(struct veip_redir_port *r, __u16 port)
{
	int i;

	for (i = 0; i < r->numports; ) {
		if (port < r->ports[i++])
			break;
		if (port <= r->ports[i++])
			return 1;
	}
	return 0;
}

struct ve_struct *venet_find_redirect_ve(struct ve_addr_struct *addr,
		__u16 port, struct list_head *search_lh)
{
	struct veip_redir_port *redir;

	list_for_each_entry_rcu (redir, search_lh, src_list) {
		if (!(redir_match_any(redir) || memcmp(&redir->addr, addr,
					sizeof(*addr)) == 0))
			continue;
		if (!redir_match_port(redir, port))
			continue;

		return redir->target;
	}
	return NULL;
}
EXPORT_SYMBOL(venet_find_redirect_ve);

static struct ve_struct *venet_find_ve(struct ve_addr_struct *addr, __u16 port,
		struct veip_struct **orig_veip)
{
	struct ip_entry_struct *entry;
	struct veip_struct *veip;
	struct ve_struct *ve = NULL;

	entry = venet_entry_lookup(addr);
	if (entry == NULL)
		return NULL;

	if (port == VENET_PORT_UNDEFINED)
		goto out_no_redir;

	veip = ACCESS_ONCE(entry->tgt_veip);
	if (veip == NULL)
		goto out_no_redir;

	ve = venet_find_redirect_ve(addr, port, &veip->src_lh);
	if (ve != NULL) {
		*orig_veip = veip;
		return ve;
	}

out_no_redir:
	return ACCESS_ONCE(entry->active_env);
}

static inline int skb_extract_v4(struct sk_buff *skb, struct ve_addr_struct *a,
		__u16 *port, int dir)
{
	struct iphdr *iph;

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP &&
			!(iph->frag_off & htons(IP_MF|IP_OFFSET))) {
		int length;
		struct tcphdr th, *tp;

		length = ntohs(iph->tot_len);
		if (length < (iph->ihl << 2) + sizeof(struct tcphdr))
			return -EINVAL;

		tp = skb_header_pointer(skb, iph->ihl << 2, sizeof(th), &th);
		if (tp == NULL)
			return -EFAULT;

		*port = ntohs(dir ? tp->dest : tp->source);
	}

	a->family = AF_INET;
	a->key[0] = 0;
	a->key[1] = 0;
	a->key[2] = 0;
	a->key[3] = (dir ? iph->daddr : iph->saddr);
	return 0;
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static inline int skb_extract_v6(struct sk_buff *skb, struct ve_addr_struct *a,
		__u16 *port, int dir)
{
	struct ipv6hdr *hdr;
	int ptr, len;
	__u8 nexthdr;
	__be16 frag_off;

	hdr = ipv6_hdr(skb);
	ptr = (u8*)(ipv6_hdr(skb) + 1) - skb->data;
	len = skb->len - ptr;
	nexthdr = ipv6_hdr(skb)->nexthdr;

	if (len < 0)
		goto out;

	ptr = ipv6_skip_exthdr(skb, ptr, &nexthdr, &frag_off);
	if (ptr < 0)
		goto out;

	if (nexthdr == IPPROTO_TCP) {
		struct tcphdr th, *tp;

		tp = skb_header_pointer(skb, ptr, sizeof(th), &th);
		if (tp == NULL)
			return -EFAULT;

		*port = ntohs(dir ? tp->dest : tp->source);
	}
out:
	a->family = AF_INET6;
	memcpy(&a->key, dir ? hdr->daddr.s6_addr32 : hdr->saddr.s6_addr32,
			sizeof(a->key));
	return 0;
}
#endif

int skb_extract_addr_port(struct sk_buff *skb,
		struct ve_addr_struct *addr, __u16 *port, int dir)
{
	switch (skb->protocol) {
	case __constant_htons(ETH_P_IP):
		return skb_extract_v4(skb, addr, port, dir);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	case __constant_htons(ETH_P_IPV6):
		return skb_extract_v6(skb, addr, port, dir);
#endif
	}

	return 0;
}
EXPORT_SYMBOL(skb_extract_addr_port);

static struct ve_struct *
veip_lookup_redirect(struct ve_struct *ve_old, struct sk_buff *skb)
{
	struct ve_struct *ve;
	struct ve_addr_struct addr;
	__u16 port;
	struct veip_struct *orig_veip = NULL;
	int dir, err;

	port = VENET_PORT_UNDEFINED;
	dir = ve_is_super(ve_old);

	err = skb_extract_addr_port(skb, &addr, &port, dir);
	if (err < 0)
		return ERR_PTR(err);

	rcu_read_lock();
	ve = venet_find_ve(&addr, port, &orig_veip);
	if (ve == NULL) {
		if (!dir && venet_ext_lookup(ve_old, &addr))
			goto out_pass;
		goto out_drop;
	}

	if (!dir) {
		/* from VE to host */
		if (ve != ve_old)
			goto out_source;
		if (orig_veip != NULL) {
			/* Redirect */
			skb_set_redirect(skb);
			venet_acct_classify_sub_outgoing(ve->stat, skb);
			venet_acct_classify_add_outgoing(orig_veip->stat, skb);
		}
out_pass:
		ve = get_ve0();
	} else {
		/* from host to VE */
		if (orig_veip != NULL) {
			/* Redirect */
			skb_set_redirect(skb);
			venet_acct_classify_add_incoming(orig_veip->stat, skb);
		}
	}
	rcu_read_unlock();

	return ve;

out_drop:
	rcu_read_unlock();
	return ERR_PTR(-ESRCH);

out_source:
	rcu_read_unlock();
	if (net_ratelimit()) {
		printk(KERN_WARNING "Dropped packet, source wrong "
		       "veid=%u src-IP=%u.%u.%u.%u "
		       "dst-IP=%u.%u.%u.%u\n",
		       ve->veid,
		       NIPQUAD(ip_hdr(skb)->saddr),
		       NIPQUAD(ip_hdr(skb)->daddr));
	}
	return ERR_PTR(-EACCES);
}

static struct veip_pool_ops vznet_pool_ops = {
	.veip_create = veip_create,
	.veip_release = veip_release,
	.veip_free = veip_free,
	.veip_lookup = veip_lookup_redirect,
};

static struct veip_pool_ops *old_veip_pool_ops;

static __exit void ip_entry_cleanup(void)
{
	int i;
	struct ip_entry_struct *entry;
	struct hlist_node *node;

	for (i = 0; i < VEIP_HASH_SZ; i++)
		hlist_for_each_entry_safe(entry, node,
				ip_entry_hash_table + i, ip_hash) {
			entry->tgt_veip = NULL;
			if (entry->active_env == NULL)
				ip_entry_unhash(entry);
		}
}

static __exit void veip_cleanup_redirects(struct list_head *to_release)
{
	struct veip_struct *veip, *tmp;

	list_for_each_entry_safe(veip, tmp, &veip_lh, list) {
		while (!list_empty(&veip->dst_lh)) {
			struct veip_redir_port *port;
			port = list_first_entry(&veip->dst_lh,
					struct veip_redir_port, dst_list);
			list_move(&port->dst_list, to_release);
			list_del_rcu(&port->src_list);
		}
		while (!list_empty(&veip->src_lh)) {
			struct veip_redir_port *port;
			port = list_first_entry(&veip->src_lh,
					struct veip_redir_port, src_list);
			list_move(&port->dst_list, to_release);
			list_del_rcu(&port->src_list);
		}

		venet_acct_put_stat(veip->stat);
		veip->stat = NULL;
		/* veip can't be released here, because it may belong to CT.
		 * They will be relesed in venet_exit. */
	}
}

static void release_redirects(struct list_head *list)
{
	struct veip_redir_port *port;

	if (list_empty(list))
		return;

	synchronize_net();
	do {
		port = list_first_entry(list, struct veip_redir_port, dst_list);
		list_del(&port->dst_list);
		kfree(port);
	} while (!list_empty(list));
}

/* Configuring redirects */

static int real_ve_redir_ip_map(envid_t veid, int op,
		struct sockaddr __user *uservaddr, int addrlen)
{
	int err;
	struct ip_entry_struct *entry;
	struct ip_entry_struct *found;
	struct ve_addr_struct veaddr;

	err = -EPERM;
	if (!capable_setveid())
		goto out;

	err = sockaddr_to_veaddr(uservaddr, addrlen, &veaddr);
	if (err < 0)
		goto out;

	switch (op)
	{
		case VE_IPPOOL_ADD:
			err = -ENOMEM;

			entry = kzalloc(sizeof(struct ip_entry_struct), GFP_KERNEL);
			if (entry == NULL)
				goto out;

			spin_lock(&veip_lock);
			found = venet_entry_lookup(&veaddr);
			if (found != NULL) {
				kfree(entry);
				err = -EADDRINUSE;
				if (found->tgt_veip != NULL)
					goto out_unlock;
				err = -EADDRNOTAVAIL;
				if (found->active_env != NULL &&
				    found->active_env->veid != veid)
					goto out_unlock;
				found->tgt_veip = found->active_env->veip;
			} else {
				struct veip_struct *veip;

				veip = vzredir_veip_findcreate(veid);
				err = -ESRCH;
				if (veip == NULL)
					goto out_unlock;
				entry->tgt_veip = veip;
				entry->addr = veaddr;
				ip_entry_hash(entry, veip);
			}
			spin_unlock(&veip_lock);
			err = 0;
			/* Above code is NOT raced with VE stop in any way.
			 * If ip_entry lookup was negative, it should simple
			 * survive in any case. If not, it WAS hashed and
			 * remains hashed without changes. Appropriate
			 * cleanup procedures will be called in time. Den */
			break;

		case VE_IPPOOL_DEL:
			spin_lock(&veip_lock);
			err = -EADDRNOTAVAIL;
			found = venet_entry_lookup(&veaddr);
			if (found == NULL)
				goto out_unlock;
			if (found->tgt_veip == NULL)
				goto out_unlock;
			if (found->tgt_veip->veid != veid)
				goto out_unlock;
			found->tgt_veip = NULL;
			if (found->active_env == NULL)
				ip_entry_unhash(found);
			spin_unlock(&veip_lock);
			err = 0;
			break;

		case VE_IPPOOL_GET:
			spin_lock(&veip_lock);
			err = -EADDRNOTAVAIL;
			found = venet_entry_lookup(&veaddr);
			if (found == NULL)
				goto out_unlock;
			err = found->tgt_veip != NULL ?  found->tgt_veip->veid : 0;

			spin_unlock(&veip_lock);
			break;

		default:
			err = -EINVAL;
	}

out:
	return err;

out_unlock:
	spin_unlock(&veip_lock);
	goto out;
}

/* ve_list_lock is held by caller */
static int redirect_insert(envid_t source, struct veip_redir_port *redir,
		struct list_head *to_release)
{
	struct list_head *tmp;
	struct veip_struct *veip;
	struct veip_struct *veip_target;
	int err;

	veip = NULL;
	veip_target = NULL;

	spin_lock(&veip_lock);

	if (redir->target != NULL && (!redir->target->is_running ||
				redir->target->veip == NULL))
		/* VE is in transition state or run without venet.
		 * Add redirect like in the situation that there is no VE */
		redir->target = NULL;

	err = -ENOMEM;
	if (redir->target == NULL) {
		veip_target = vzredir_veip_findcreate(redir->target_veid);
		if (veip_target == NULL)
			goto out_unlock;
	}

	veip = vzredir_veip_findcreate(source);
	err = -ENOENT;
	if (veip == NULL)
		goto out_free;

	if (veip_target == NULL)
		veip_target = redir->target->veip;

	err = 0;
	list_for_each(tmp, &veip->src_lh) {
		struct veip_redir_port *ve;
		ve = list_entry(tmp, struct veip_redir_port, src_list);
		if (ve->target_veid != redir->target_veid)
			continue;
		if (memcmp(&ve->addr, &redir->addr,
					sizeof(struct ve_addr_struct)) != 0)
			continue;

		list_move(&ve->dst_list, to_release);
		list_replace_rcu(&ve->src_list, &redir->src_list);
		list_add_tail(&redir->dst_list, &veip_target->dst_lh);
		goto out_unlock;

	}
	list_add_tail_rcu(&redir->src_list, &veip->src_lh);
	list_add_tail(&redir->dst_list, &veip_target->dst_lh);

out_unlock:
	spin_unlock(&veip_lock);

	return err;

out_free:
	if (veip_target != NULL)
		veip_put(veip_target);
	spin_unlock(&veip_lock);

	return err;
}

static void veip_redir_port_free(struct veip_redir_port *port, struct list_head *to_release)
{
	struct veip_struct *tgt;

	list_move(&port->dst_list, to_release);

	if (port->target == NULL) {
		/* target VE is stopped and this redirect can be last */
		tgt = veip_find(port->target_veid);
		if (tgt == NULL)
			BUG();
		veip_put(tgt);
	}

	/* keek the reference till here if redirect is set to self */
	list_del_rcu(&port->src_list);
}

static int do_ve_redir_port(struct vzctl_ve_redir_port *lredir,
		unsigned long uports, struct ve_addr_struct *addr)
{
	struct veip_redir_port *kredir;
	LIST_HEAD(to_release);
	int err;

	err = -EPERM;
	if (!capable_setveid())
		goto out;

	err = -EDOM;
	if (lredir->numports <= 0 || lredir->numports > 65536 ||
			(lredir->numports & 1))
		goto out;

	err = -ENOMEM;
	kredir = kmalloc(sizeof(*kredir) + lredir->numports * sizeof(u16),
			GFP_KERNEL);
	if (kredir == NULL)
		goto out;

	kredir->numports = lredir->numports;
	err = -EFAULT;
	if (copy_from_user(kredir->ports, (void *)uports,
				kredir->numports * sizeof(u16)))
		goto out_free;

	/* veip_stop is called after ve_list_del under the same lock */
	mutex_lock(&ve_list_lock);
	err = -ENOENT;
	kredir->target = __find_ve_by_id(lredir->target);
	kredir->target_veid = lredir->target;
	kredir->addr = *addr;

	err = redirect_insert(lredir->source, kredir, &to_release);
	mutex_unlock(&ve_list_lock);
	if (err != 0) {
		BUG_ON(!list_empty(&to_release));
		goto out_free;
	}

	release_redirects(&to_release);

	return 0;

out_free:
	kfree(kredir);
out:
	return err;
}

static int real_ve_redir_port(struct vzctl_ve_redir_port *lredir,
		unsigned long uports,
		struct sockaddr __user *uaddr, int addrlen)
{
	int err;
	struct ve_addr_struct addr;

	err = sockaddr_to_veaddr(uaddr, addrlen, &addr);
	if (err == 0)
		err = do_ve_redir_port(lredir, uports, &addr);
	return err;
}

static int compat_ve_redir_port(struct vzctl_ve_redir_port_compat *credir,
		unsigned long uports)
{
	int err;
	struct vzctl_ve_redir_port lredir;
	struct sockaddr_in in_addr;
	struct ve_addr_struct veaddr;
	mm_segment_t old_fs;

	memset(&in_addr, 0, sizeof(in_addr));

	in_addr.sin_family = AF_INET;
	in_addr.sin_port = 0;
	in_addr.sin_addr.s_addr = credir->ip;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = sockaddr_to_veaddr((struct sockaddr *)&in_addr, sizeof(in_addr),
			&veaddr);
	set_fs(old_fs);
	if (err < 0)
		return err;

	lredir.target = credir->target;
	lredir.source = credir->source;
	lredir.numports = credir->numports;

	return do_ve_redir_port(&lredir, uports, &veaddr);
}

static int real_ve_redir_port_del(struct vzctl_ve_redir_port_del *todel)
{
	int err;
	struct veip_struct *veip;
	struct ve_struct *ve;
	LIST_HEAD(to_release);

	mutex_lock(&ve_list_lock);
	veip = NULL;
	ve = __find_ve_by_id(todel->veid);
	if (ve != NULL)
		veip = ve->veip;

	spin_lock(&veip_lock);
	if (veip == NULL)
		veip = veip_find(todel->veid);
	err = -ESRCH;
	if (veip == NULL)
		goto out_unlock;

	while (!list_empty(&veip->src_lh)) {
		struct veip_redir_port *port;
		port = list_entry(veip->src_lh.next,
				  struct veip_redir_port, src_list);
		veip_redir_port_free(port, &to_release);
	}

	if (ve == NULL)
		veip_put(veip);

out_unlock:
	spin_unlock(&veip_lock);
	mutex_unlock(&ve_list_lock);
	release_redirects(&to_release);
	return err;
}

static int venet_redir_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	int err;

	err = -ENOTTY;
	switch(cmd) {
	case VZTRCTL_VE_IP_MAP: {
			struct vzctl_ve_redir_ip_map s;
			err = -EFAULT;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = real_ve_redir_ip_map(s.veid, s.op,
					s.addr, s.addrlen);
		}
		break;
	case VZTRCTL_VE_REDIR_PORT_COMPAT: {
			struct vzctl_ve_redir_port_compat s;
			err = -EFAULT;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = compat_ve_redir_port(&s, arg + sizeof(s));
		}
		break;
	case VZTRCTL_VE_REDIR_PORT_DEL: {
			struct vzctl_ve_redir_port_del s;
			err = -EFAULT;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = real_ve_redir_port_del(&s);
		}
		break;
	case VZTRCTL_VE_REDIR_PORT: {
			struct vzctl_ve_redir_port s;
			err = -EFAULT;
			if (copy_from_user(&s, (void *)arg, sizeof(s)))
				break;
			err = real_ve_redir_port(&s, arg + sizeof(s),
					s.addr, s.addrlen);
		}
		break;
	}
	return err;
}

#ifdef CONFIG_COMPAT
static int venet_redir_ioctl_compat(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	/* do we need this? */
	return -ENOTTY;
}
#endif

static struct vzioctlinfo tr_ioctl_info = {
	.type 		= VZTRCTLTYPE,
	.ioctl		= venet_redir_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= venet_redir_ioctl_compat,
#endif
	.owner		= THIS_MODULE,
};

/*
 * ------------------------------------------------------------------
 * VE redirects information via /proc
 * ------------------------------------------------------------------
 */
#ifdef CONFIG_PROC_FS
static int veinfo_redir_seq_show(struct seq_file *m, void *v)
{
	struct ve_struct *ve;
	struct veip_struct *veip;
	struct ip_entry_struct *entry;

	ve = list_entry((struct list_head *)v, struct ve_struct, ve_list);

	seq_printf(m, "%10u ", ve->veid);
	spin_lock(&veip_lock);
	veip = ACCESS_ONCE(ve->veip);
	if (veip == NULL)
		goto done;
	list_for_each_entry(entry, &veip->ip_lh, ve_list) {
		char addr[40];

		if (entry->tgt_veip == NULL)
			continue;

		veaddr_print(addr, sizeof(addr), &entry->addr);
		seq_printf(m, " %15s", addr);
	}
done:
	spin_unlock(&veip_lock);
	seq_putc(m, '\n');
	return 0;
}

static struct seq_operations veinfo_redir_seq_op = {
	.start	= ve_seq_start,
	.next	= ve_seq_next,
	.stop	= ve_seq_stop,
	.show	= veinfo_redir_seq_show,
};

static int veinfo_redir_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &veinfo_redir_seq_op);
}

static struct file_operations proc_veinfo_redir_operations = {
	.open		= veinfo_redir_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};
static int veredir_seq_show(struct seq_file *m, void *v)
{
	struct list_head *p;
	struct veip_redir_port *entry;
	int i;

	p = (struct list_head *)v;
	if (p == &get_exec_env()->veip->src_lh) {
		seq_puts(m, "Version: 2.5\n");
		return 0;
	}
	entry = list_entry(p, struct veip_redir_port, src_list);
	seq_printf(m, "%10u", entry->target_veid);
	for (i = 0; i < entry->numports; i += 2) {
		if (entry->ports[i] == entry->ports[i + 1])
			seq_printf(m, " %u", entry->ports[i]);
		else
			seq_printf(m, " %u-%u",
					entry->ports[i],
					entry->ports[i + 1]);
	}
	seq_printf(m, "\n");
	return 0;
}

/* veip_hash_lock is already taken */
static inline int ve_has_redirects(struct ve_struct *ve)
{
	struct list_head *tmp;

	list_for_each(tmp, &ve->veip->ip_lh) {
		struct ip_entry_struct *entry;
		entry = list_entry(tmp, struct ip_entry_struct, ve_list);
		if (entry->tgt_veip == NULL)
			continue;
		return 1;
	}
	return 0;
}

static void *veredir_seq_start(struct seq_file *m, loff_t *pos)
{
	loff_t l;
	struct list_head *p;

	l = *pos;
	spin_lock(&veip_lock);
	if (l == 0)
		return &get_exec_env()->veip->src_lh;
	if (!ve_has_redirects(get_exec_env()))
		return NULL;
	list_for_each(p, &get_exec_env()->veip->src_lh) {
		if (--l == 0)
			return p;
	}
	return NULL;
}

static void *veredir_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct list_head *p;

	if (!ve_has_redirects(get_exec_env()))
		return NULL;

	p = (struct list_head *)v;
	p = p->next;
	if (p != &get_exec_env()->veip->src_lh) {
		(*pos)++;
		return p;
	}
	return NULL;
}

static void veredir_seq_stop(struct seq_file *m, void *v)
{
	spin_unlock(&veip_lock);
}

static struct seq_operations veredir_seq_op = {
	.start	= veredir_seq_start,
	.next	= veredir_seq_next,
	.stop	= veredir_seq_stop,
	.show	= veredir_seq_show,
};

static int veredir_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &veredir_seq_op);
}

static struct file_operations proc_veredir_operations = {
	.open		= veredir_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init init_vzredir_proc(void)
{
	struct proc_dir_entry *de;

	de = proc_create("veinfo_redir", S_IFREG|S_IRUSR|S_ISVTX, proc_vz_dir,
			&proc_veinfo_redir_operations);
	if (de == NULL)
		printk(KERN_WARNING
			"VZREDIR: can't make veinfo_redir proc entry\n");

	de = proc_create("veredir", S_IFREG|S_IRUSR|S_ISVTX, proc_vz_dir,
			&proc_veredir_operations);
	if (de == NULL)
		printk(KERN_WARNING
			"VZREDIR: can't make veredir proc entry\n");
	return 0;
}

static void __exit fini_vzredir_proc(void)
{
	remove_proc_entry("veinfo_redir", proc_vz_dir);
	remove_proc_entry("veredir", proc_vz_dir);
}
#else
#define init_vzredir_proc()	(0)
#define fini_vzredir_proc()	do { } while (0)
#endif /* CONFIG_PROC_FS */

/*
 * ---------------------------------------------------------------------------
 * Initialization
 * ---------------------------------------------------------------------------
 */
static int venet_alloc_one_stat(unsigned id)
{
	struct venet_stat *stat;
	struct veip_struct *veip;

	spin_unlock(&veip_lock);
	stat = venet_acct_find_create_stat(id);
	spin_lock(&veip_lock);

	if (stat == NULL)
		return -ENOMEM;

	list_for_each_entry(veip, &veip_lh, list)
		if (veip->veid == id) {
			if (veip->stat == NULL) {
				veip->stat = stat;
				stat = NULL;
			}

			break;
		}

	venet_acct_put_stat(stat);
	return 0;
}

static int venet_alloc_all_stats(void)
{
	struct veip_struct *veip;

again:
	list_for_each_entry(veip, &veip_lh, list) {
		if (veip->stat != NULL)
			continue;

		if (venet_alloc_one_stat(veip->veid))
			goto err_clean_all;

		goto again;
	}

	return 0;

err_clean_all:
	list_for_each_entry(veip, &veip_lh, list)
		venet_acct_put_stat(veip->stat);
	return -ENOMEM;
}

void (*old_venet_free_stat)(struct ve_struct *) = NULL;

int __init venetredir_init(void)
{
	spin_lock(&veip_lock);

	if (venet_alloc_all_stats())
		goto err;

	old_veip_pool_ops = veip_pool_ops;
	veip_pool_ops = &vznet_pool_ops;

	old_venet_free_stat = venet_free_stat;
	venet_free_stat = fini_venet_acct_ip_stat;

	spin_unlock(&veip_lock);

	vzioctl_register(&tr_ioctl_info);
	init_vzredir_proc();
	return 0;
err:
	spin_unlock(&veip_lock);
	return -ENOMEM;
}

void __exit venetredir_exit(void)
{
	LIST_HEAD(to_release);

	fini_vzredir_proc();
	vzioctl_unregister(&tr_ioctl_info);

	spin_lock(&veip_lock);
	venet_free_stat = old_venet_free_stat;
	veip_pool_ops = old_veip_pool_ops;
	ip_entry_cleanup();
	veip_cleanup_redirects(&to_release);
	spin_unlock(&veip_lock);
	release_redirects(&to_release);
}

module_init(venetredir_init);
module_exit(venetredir_exit);

MODULE_LICENSE("GPL v2");
