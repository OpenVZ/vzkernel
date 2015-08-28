/*
 * kernel/ve/vznetstat/vznetstat.c
 *
 * Copyright (c) 2004-2015 Parallels IP Holdings GmbH
 *
 */

/*
 * Networking statistics.
 * Traffic classes support.
 * Persistent (independent from VE struct storage)
 */

#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>
#include <net/ip.h>
#include <linux/in6.h>
#include <linux/module.h>

#include <linux/ve.h>
#include <linux/venet.h>
#include <linux/vznetstat.h>
#include <linux/vzctl.h>
#include <uapi/linux/vzctl_netstat.h>
#include <uapi/linux/vzcalluser.h>

/*
 * ---------------------------------------------------------------------------
 * Traffic classes storage
 * ---------------------------------------------------------------------------
 */

static int stat_num = 0;
static DEFINE_RWLOCK(tc_lock);

struct class_info_set {
	unsigned int len;
	union {
		struct vz_tc_class_info info_v4[0];
		struct vz_tc_class_info_v6 info_v6[0];
		char data[0];
	};
};

static struct class_info_set *info_v4 = NULL;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static struct class_info_set *info_v6 = NULL;
#endif

/* v6: flag IPv6 classes or IPv4 */
static int venet_acct_set_classes(const void __user *user_info, int length, int v6)
{
	struct class_info_set *info, *old;
	int size;
	int err, i;

	if (v6)
		size = sizeof(struct vz_tc_class_info_v6);
	else
		size = sizeof(struct vz_tc_class_info);

	info = kmalloc(sizeof(struct class_info_set) + size * length, GFP_KERNEL);
	if (info == NULL)
		return -ENOMEM;

	err = -EFAULT;
	info->len = length;
	if (copy_from_user(info->data, user_info, size * length))
		goto out_free;

	/* Verify incoming data */
	err = -EINVAL;
	for (i = 0; i < length; i++) {
		unsigned int cid;

		if (v6)
			cid = info->info_v6[i].cid;
		else
			cid = info->info_v4[i].cid;

		if (cid < 0 || cid >= TC_CLASS_MAX)
			goto out_free;
	}

	write_lock_irq(&tc_lock);
	if (v6) {
		old = rcu_dereference(info_v6);
		rcu_assign_pointer(info_v6, info);
	} else {
		old = rcu_dereference(info_v4);
		rcu_assign_pointer(info_v4, info);
	}
	write_unlock_irq(&tc_lock);

	synchronize_net();
	/* IMPORTANT. I think reset of statistics collected should not be
	 * done here. */
	kfree(old);
	return 0;

out_free:
	kfree(info);
	return err;
}

/* all records */
static int venet_acct_get_classes(void __user *ret, int length, int v6)
{
	void *info;
	struct class_info_set *rinfo;
	int len, err;
	unsigned int size;

	if (v6)
		size = sizeof(struct vz_tc_class_info_v6);
	else
		size = sizeof(struct vz_tc_class_info);

	/* due to spinlock locking, see below */
	info = kmalloc(size * length, GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	rcu_read_lock();
	if (v6)
		rinfo = rcu_dereference(info_v6);
	else
		rinfo = rcu_dereference(info_v4);

	len = min(length, (int)rinfo->len);
	memcpy(info, rinfo->data, size * length);
	rcu_read_unlock();

	err = -EFAULT;
	if (!copy_to_user(ret, info, size * len))
		err = len;
	kfree(info);
	return err;
}

static inline int class_info_len(int v6)
{
	int ret = 0;
	struct class_info_set *info;

	rcu_read_lock();
	if (v6)
		info = rcu_dereference(info_v6);
	else
		info = rcu_dereference(info_v4);

	if (info)
		ret = info->len;
	rcu_read_unlock();

	return ret;
}

/*
 * ---------------------------------------------------------------------------
 * Persistent statistics storage
 * ---------------------------------------------------------------------------
 */

/* The cache should not be good right now. It used only for user-space */
#define STAT_HASH_LEN	128

static struct list_head stat_hash_list[STAT_HASH_LEN];
static int stat_hash(envid_t veid)
{
	return veid & (STAT_HASH_LEN - 1);
}

/* tc_lock is taken by the caller! */
static inline struct venet_stat *__find(envid_t veid)
{
	int hash;
	struct venet_stat *ptr;

	hash = stat_hash(veid);
	list_for_each_entry(ptr, stat_hash_list + hash, list) {
		if (ptr->veid == veid)
			return ptr;
	}
	return NULL;
}

static struct venet_stat *next_stat(int *hash, struct venet_stat *item)
{
	struct list_head *ptr;

	ptr = item != NULL ? &item->list : (stat_hash_list + *hash);
	while (*hash < STAT_HASH_LEN) {
		if (ptr->next != stat_hash_list + *hash)
			return list_entry(ptr->next, struct venet_stat, list);
		(*hash)++;
		ptr = stat_hash_list + *hash;
	}
	return NULL;
}

struct venet_stat *venet_acct_find_create_stat(envid_t veid)
{
	struct venet_stat *ptr;
	unsigned long flags;
	struct venet_stat *stat;

	read_lock(&tc_lock);
	ptr = __find(veid);
	if (ptr != NULL) {
		venet_acct_get_stat(ptr);
		read_unlock(&tc_lock);
		return ptr;
	}
	read_unlock(&tc_lock);

	ptr = kzalloc(sizeof(struct venet_stat), GFP_KERNEL);
	if (ptr == NULL)
		goto out;
	ptr->veid = veid;

	ptr->ipv4_stat = alloc_percpu(struct acct_stat);
	if (ptr->ipv4_stat == NULL)
		goto out_free;

	ptr->ipv6_stat = alloc_percpu(struct acct_stat);
	if (ptr->ipv6_stat == NULL)
		goto out_free_v4;

	write_lock_irqsave(&tc_lock, flags);
	stat = __find(veid);
	if (stat != NULL) {
		free_percpu(ptr->ipv6_stat);
		free_percpu(ptr->ipv4_stat);
		kfree(ptr);
		ptr = stat;
	} else {
		list_add(&ptr->list, stat_hash_list + stat_hash(veid));
		stat_num++;
	}
	venet_acct_get_stat(ptr);
	write_unlock_irqrestore(&tc_lock, flags);
	return ptr;

out_free_v4:
	free_percpu(ptr->ipv4_stat);
out_free:
	kfree(ptr);
out:
	return NULL;
}

struct venet_stat *venet_acct_find_stat(envid_t veid)
{
	struct venet_stat *ptr;

	read_lock(&tc_lock);
	ptr = __find(veid);
	if (ptr != NULL)
		venet_acct_get_stat(ptr);
	read_unlock(&tc_lock);
	return ptr;
}

void venet_acct_put_stat(struct venet_stat *stat)
{
	if (stat == NULL)
		return;
	atomic_dec(&stat->users);
}

static inline struct acct_stat *
__choose_acct(struct venet_stat *stat, int v6)
{
	if (v6)
		return stat->ipv6_stat;
	else
		return stat->ipv4_stat;
}

/*
 * v6: flag - IPv6 or IPv4 statistic are interested in
 * returns array of counters, indexed by tc
 */
static int venet_acct_get_ve_stat(struct vzctl_tc_get_stat *data, int v6)
{
	struct venet_stat *stat;
	void *buf;
	u64 *incoming, *outgoing;
	u32 *incoming_pkt, *outgoing_pkt;
	int err, size, cpu;
	struct acct_stat *acct;

	if (data->length < 0 || data->length > TC_CLASS_MAX)
		return -EINVAL;

	buf = kzalloc(2 * TC_CLASS_MAX * (sizeof(u64) + sizeof(u32)), GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;

	incoming = buf;
	outgoing = incoming + TC_CLASS_MAX;
	incoming_pkt = (u32 *)(outgoing + TC_CLASS_MAX);
	outgoing_pkt = incoming_pkt + TC_CLASS_MAX;

	read_lock(&tc_lock);
	err = -ESRCH;
	stat = __find(data->veid);
	if (stat == NULL)
		goto out_unlock;

	acct = __choose_acct(stat, v6);

	for_each_possible_cpu(cpu) {
		struct acct_stat *stat;
		int i;

		stat = per_cpu_ptr(acct, cpu);
		for (i = 0; i < data->length; i++) {
			incoming[i] += stat->cnt[i][ACCT_IN].bytes;
			outgoing[i] += stat->cnt[i][ACCT_OUT].bytes;
			incoming_pkt[i] += stat->cnt[i][ACCT_IN].pkts;
			outgoing_pkt[i] += stat->cnt[i][ACCT_OUT].pkts;
		}
	}

	read_unlock(&tc_lock);

	err = -EFAULT;
	size = data->length * sizeof(u64);
	if (copy_to_user(data->incoming, incoming, size))
		goto out_free;
	if (copy_to_user(data->outgoing, outgoing, size))
		goto out_free;
	size = data->length * sizeof(u32);
	if (copy_to_user(data->incoming_pkt, incoming_pkt, size))
		goto out_free;
	if (copy_to_user(data->outgoing_pkt, outgoing_pkt, size))
		goto out_free;

	err = data->length;

out_free:
	kfree(buf);
	return err;

out_unlock:
	read_unlock(&tc_lock);
	goto out_free;
}

static int __tc_destroy_stat(struct venet_stat *stat)
{
	if (atomic_read(&stat->users))
		return -EBUSY;
	stat_num--;
	list_del(&stat->list);
	free_percpu(stat->ipv6_stat);
	free_percpu(stat->ipv4_stat);
	kfree(stat);
	return 0;
}

/* cleans up counter and removes it from memory if VE not exists */
static int venet_acct_destroy_stat(envid_t veid)
{
	struct venet_stat *stat;
	int err;

	err = -ESRCH;
	write_lock_irq(&tc_lock);
	stat = __find(veid);
	if (stat != NULL)
		err = __tc_destroy_stat(stat);
	write_unlock_irq(&tc_lock);
	return err;
}

static void venet_acct_destroy_all_stat(void)
{
	int hash;
	struct list_head *ptr, *tmp;

	write_lock_irq(&tc_lock);
	for (hash = 0; hash < STAT_HASH_LEN; hash++) {
		list_for_each_safe(ptr, tmp, stat_hash_list + hash)
			__tc_destroy_stat(list_entry(ptr,
						struct venet_stat, list));
	}
	write_unlock_irq(&tc_lock);
}

static DEFINE_MUTEX(req_mutex);
static struct venet_stat *req_stat;

static void zero_venet_stat(struct venet_stat *stat, unsigned cpu)
{
	struct acct_stat *acct;

	acct = per_cpu_ptr(stat->ipv4_stat, cpu);
	memset(acct, 0, sizeof(*acct));
	acct = per_cpu_ptr(stat->ipv6_stat, cpu);
	memset(acct, 0, sizeof(*acct));
}

static void clear_one_percpu_statistics(struct work_struct *dummy)
{
	unsigned cpu, this_cpu = get_cpu();

	zero_venet_stat(req_stat, this_cpu);

	if (cpumask_first(cpu_online_mask) != this_cpu)
		goto out;

	/* First cpu clears statistics on all offline cpus */
	for_each_possible_cpu(cpu)
		if (!cpu_online(cpu))
			zero_venet_stat(req_stat, cpu);
out:
	put_cpu();
}

/* Clear VE's statistics */
static int venet_acct_clear_stat(envid_t veid)
{
	int ret = -EINTR;

	if (mutex_lock_interruptible(&req_mutex))
		goto out;

	req_stat = venet_acct_find_stat(veid);
	if (!req_stat) {
		ret = -ESRCH;
		goto unlock;
	}

	ret = schedule_on_each_cpu(clear_one_percpu_statistics);

	venet_acct_put_stat(req_stat);
unlock:
	mutex_unlock(&req_mutex);
out:
	return ret;
}

static void clear_all_percpu_statistics(struct work_struct *dummy)
{
	unsigned cpu, this_cpu = smp_processor_id();
	struct venet_stat *stat = NULL;
	int other = 0, hash = 0;

	/*
	 * Some cpus may be offline, and schedule_on_each_cpu()
	 * does not create a work on them.
	 * Work on the first online CPU clears their statistics.
	 * Hotplug is disabled by schedule_on_each_cpu().
	 */
	if (cpumask_first(cpu_online_mask) == this_cpu)
		other = 1;

	read_lock(&tc_lock);

	while ((stat = next_stat(&hash, stat)) != NULL) {
		zero_venet_stat(stat, this_cpu);

		if (!other)
			continue;

		/* Clear statistics on not active cpus */
		for_each_possible_cpu(cpu)
			if (!cpu_online(cpu))
				zero_venet_stat(stat, cpu);
	}

	read_unlock(&tc_lock);
}

/* Clear all present statistics */
static int venet_acct_clear_all_stat(void)
{
	int ret = -EINTR;

	if (mutex_lock_interruptible(&req_mutex))
		goto out;

	ret = schedule_on_each_cpu(clear_all_percpu_statistics);

	mutex_unlock(&req_mutex);
out:
	return ret;
}

static int venet_acct_get_stat_list(envid_t *__list, int length)
{
	int hash;
	struct venet_stat *ptr;
	int i, err;
	envid_t *list;

	if (length <= 0)
		return -EINVAL;

	list = kmalloc(sizeof(envid_t) * length, GFP_KERNEL);
	if (list == NULL)
		return -ENOMEM;

	i = 0;
	read_lock(&tc_lock);
	for (hash = 0; hash < STAT_HASH_LEN; hash++) {
		list_for_each_entry(ptr, stat_hash_list + hash, list) {
			list[i++] = ptr->veid;
			if (i == length)
				break;
		}
	}
	read_unlock(&tc_lock);

	err = -EFAULT;
	if (!copy_to_user(__list, list, sizeof(envid_t) * i))
		err = i;
	kfree(list);
	return err;
}

static int venet_acct_get_base(envid_t veid)
{
	int err = -ESRCH;
	struct venet_stat *ptr;

	read_lock(&tc_lock);
	ptr = __find(veid);
	if (ptr != NULL)
		err = ptr->base;
	read_unlock(&tc_lock);
	return err;
}

static int __check_base(__u16 base)
{
	int hash;
	struct venet_stat *stat;

	hash = 0;
	stat = NULL;
	while ((stat = next_stat(&hash, stat)) != NULL) {
		if (stat->base == 0 || stat->base != base)
			continue;
		return 1;
	}
	return 0;
}

static int venet_acct_set_base(envid_t veid, __u16 base)
{
	static __u16 rover = 1;
	int err, pos;
	struct venet_stat *stat;

	stat = venet_acct_find_create_stat(veid);
	if (stat == NULL)
		return -ENOMEM;

	write_lock_irq(&tc_lock);
	if (base != 0)
		goto done;

	err = -ERANGE;
	pos = rover;
	do {
		rover++;
		if (rover == 0)
			rover = 1;
		if (__check_base(rover))
			continue;
		base = rover;
done:
		err = base;
		stat->base = base;
		break;
	} while (pos != rover);

	write_unlock_irq(&tc_lock);
	venet_acct_put_stat(stat);
	return err;
}

/*
 * ---------------------------------------------------------------------------
 * Accounting engine
 * ---------------------------------------------------------------------------
 */
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static int match_v6_class(const __u32 *addr, struct vz_tc_class_info_v6 *class)
{
	return !(
			((addr[0] & class->mask[0]) ^ class->addr[0]) |
			((addr[1] & class->mask[1]) ^ class->addr[1]) |
			((addr[2] & class->mask[2]) ^ class->addr[2]) |
			((addr[3] & class->mask[3]) ^ class->addr[3])
		);
}

static noinline int venet_acct_classify_v6(struct sk_buff *skb, int dir)
{
	int i, ret = 0;
	struct class_info_set *info;
	const __u32 *addr;

	if (dir == ACCT_IN)
		addr = ipv6_hdr(skb)->saddr.s6_addr32;
	else
		addr = ipv6_hdr(skb)->daddr.s6_addr32;

	rcu_read_lock();
	info = rcu_dereference(info_v6);
	if (info == NULL)
		goto out_unlock;

	for (i = info->len - 1; i >= 0; i--) {
		if (match_v6_class(addr, &info->info_v6[i])) {
			ret = info->info_v6[i].cid;
			break;
		}
	}
out_unlock:
	rcu_read_unlock();
	return ret;
}
#else
#define venet_acct_classify_v6(skb, dir)	(0)
#endif

static int __venet_acct_classify(__u32 daddr)
{
	int ret, i;
	struct class_info_set *info;

	ret = 0;
	rcu_read_lock();
	info = rcu_dereference(info_v4);
	if (info == NULL)
		goto out_unlock;
	for (i = info->len - 1; i >= 0; i--) {
		if ((daddr & info->info_v4[i].mask) == info->info_v4[i].addr) {
			ret = info->info_v4[i].cid;
			break;
		}
	}
out_unlock:
	rcu_read_unlock();
	return ret;
}

static int venet_acct_classify(struct sk_buff *skb, int dir)
{
	__u32 addr;

	if (dir == ACCT_IN)
		addr = ip_hdr(skb)->saddr;
	else
		addr = ip_hdr(skb)->daddr;

	return __venet_acct_classify(addr);
}

static void __do_acct_one(struct acct_stat *acct, int class, int dir, int size)
{
	int cpu;
	struct acct_counter *cnt;

	cpu = get_cpu();

	acct = per_cpu_ptr(acct, cpu);
	cnt = &acct->cnt[class][dir];

	cnt->bytes += size;
	if (size > 0)
		cnt->pkts++;
	else
		cnt->pkts--;

	put_cpu();
}

static int acct_one_skb(struct venet_stat *stat, struct sk_buff *skb, int dir, int size)
{
	int class;
	struct acct_stat *acct;

	switch (skb->protocol) {
	case __constant_htons(ETH_P_IP):
		class = venet_acct_classify(skb, dir);
		acct = stat->ipv4_stat;
		break;
	case __constant_htons(ETH_P_IPV6):
		class = venet_acct_classify_v6(skb, dir);
		acct = stat->ipv6_stat;
		break;
	default:
		return 0;
	}

	__do_acct_one(acct, class, dir, size);

	return class;
}

void venet_acct_classify_add_incoming(struct venet_stat *stat, struct sk_buff *skb)
{
	acct_one_skb(stat, skb, ACCT_IN, venet_acct_skb_size(skb));
}

static inline void venet_acct_mark(struct venet_stat *stat,
	       struct sk_buff *skb, int class)
{
#ifdef CONFIG_NETFILTER
	if (stat->base == 0)	/* compatibility mode */
		skb->mark = class + stat->veid*2*TC_CLASS_MAX;
	else
		skb->mark = class + stat->base*TC_CLASS_MAX;
#endif
}

/* FIX ME: hardheader accouting */
void venet_acct_classify_add_outgoing(struct venet_stat *stat, struct sk_buff *skb)
{
	int class;

	class = acct_one_skb(stat, skb, ACCT_OUT, venet_acct_skb_size(skb));
	/* Do not forget to mark skb for traffic shaper */
	venet_acct_mark(stat, skb, class);
}

void venet_acct_classify_sub_outgoing(struct venet_stat *stat, struct sk_buff *skb)
{
	int class;

	class = acct_one_skb(stat, skb, ACCT_OUT, -venet_acct_skb_size(skb));
	/* Do not forget to mark skb for traffic shaper */
	venet_acct_mark(stat, skb, class);
}

void venet_acct_classify_add_incoming_plain(struct venet_stat *stat,
		struct ve_addr_struct *src_addr, int data_size)
{
	int class;

	class = __venet_acct_classify(src_addr->key[3]);
	__do_acct_one(stat->ipv4_stat, class, ACCT_IN, data_size);
}

void venet_acct_classify_add_outgoing_plain(struct venet_stat *stat,
		struct ve_addr_struct *dst_addr, int data_size)
{
	int class;

	class = __venet_acct_classify(dst_addr->key[3]);
	__do_acct_one(stat->ipv4_stat, class, ACCT_OUT, data_size);
}

/*
 * ---------------------------------------------------------------------------
 * IOCTL interface for user
 * ---------------------------------------------------------------------------
 */

static int venet_acct_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	int err;
	struct vzctl_tc_classes		tcl;
	struct vzctl_tc_classes_v6	tcl_v6;
	struct vzctl_tc_get_stat 	tcnt;
	struct vzctl_tc_get_stat_list	tcsl;


	if (!capable_setveid())
		return -EPERM;

	err = -ENOTTY;
	switch(cmd) {
		case VZCTL_TC_MAX_CLASS:
			err = TC_CLASS_MAX;
			break;
		case VZCTL_TC_CLASS_NUM:
			err = class_info_len(0);
			break;
		case VZCTL_TC_SET_CLASS_TABLE:
			err = -EFAULT;
			if (copy_from_user(&tcl, (void *)arg, sizeof(tcl)))
				break;
			err = venet_acct_set_classes(tcl.info, tcl.length, 0);
			break;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		case VZCTL_TC_CLASS_NUM_V6:
			err = class_info_len(1);
			break;
		case VZCTL_TC_SET_CLASS_TABLE_V6:
			err = -EFAULT;
			if (copy_from_user(&tcl_v6, (void *)arg, sizeof(tcl_v6)))
				break;
			err = venet_acct_set_classes(tcl_v6.info, tcl_v6.length, 1);
			break;
#endif
		case VZCTL_TC_GET_CLASS_TABLE:
			err = -EFAULT;
			if (copy_from_user(&tcl, (void *)arg, sizeof(tcl)))
				break;
			err = venet_acct_get_classes(tcl.info, tcl.length, 0);
			break;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		case VZCTL_TC_GET_CLASS_TABLE_V6:
			err = -EFAULT;
			if (copy_from_user(&tcl_v6, (void *)arg, sizeof(tcl_v6)))
				break;
			err = venet_acct_get_classes(tcl_v6.info, tcl_v6.length, 1);
			break;
#endif

		case VZCTL_TC_STAT_NUM:
			err = stat_num;
			break;
		case VZCTL_TC_GET_STAT_LIST:
			err = -EFAULT;
			if (copy_from_user(&tcsl, (void *)arg, sizeof(tcsl)))
				break;
			err = venet_acct_get_stat_list(tcsl.list, tcsl.length);
			break;
		case VZCTL_TC_GET_STAT:
		case VZCTL_TC_GET_STAT_V6:
			err = -EFAULT;
			if (copy_from_user(&tcnt, (void *)arg, sizeof(tcnt)))
				break;
			err = venet_acct_get_ve_stat(&tcnt, cmd == VZCTL_TC_GET_STAT_V6);
			break;
		case VZCTL_TC_DESTROY_STAT:
			err = venet_acct_destroy_stat(arg);
			break;
		case VZCTL_TC_DESTROY_ALL_STAT:
			err = 0;
			venet_acct_destroy_all_stat();
			break;
		case VZCTL_TC_CLEAR_STAT:
			err = venet_acct_clear_stat(arg);
			break;
		case VZCTL_TC_CLEAR_ALL_STAT:
			err = venet_acct_clear_all_stat();
			break;

		case VZCTL_TC_GET_BASE:
			err = venet_acct_get_base(arg);
			break;
		case VZCTL_TC_SET_BASE:
		{
			struct vzctl_tc_set_base tcb;
			err = -EFAULT;
			if (copy_from_user(&tcb, (void *)arg, sizeof(tcb)))
				break;
			err = venet_acct_set_base(tcb.veid, tcb.base);
			break;
		}
	}
	return err;
}

#ifdef CONFIG_COMPAT
static int compat_venet_acct_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	int err;

	if (!capable_setveid())
		return -EPERM;

	switch (cmd) {
	case COMPAT_VZCTL_TC_GET_STAT: {
		struct compat_vzctl_tc_get_stat cs;
		struct vzctl_tc_get_stat __user *s;

		s = compat_alloc_user_space(sizeof(*s));

		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;
		if (put_user(cs.veid, &s->veid) ||
		    put_user(compat_ptr(cs.incoming), &s->incoming) ||
		    put_user(compat_ptr(cs.outgoing), &s->outgoing) ||
		    put_user(compat_ptr(cs.incoming_pkt), &s->incoming_pkt) ||
		    put_user(compat_ptr(cs.outgoing_pkt), &s->outgoing_pkt) ||
		    put_user(cs.length, &s->length))
			break;

		err = venet_acct_ioctl(file, VZCTL_TC_GET_STAT,
				(unsigned long)s);
		break;
	}
	case COMPAT_VZCTL_TC_GET_STAT_LIST: {
		struct compat_vzctl_tc_get_stat_list cs;
		struct vzctl_tc_get_stat_list __user *s;

		s = compat_alloc_user_space(sizeof(*s));

		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;
		if (put_user(compat_ptr(cs.list), &s->list) ||
		    put_user(cs.length, &s->length))
			break;

		err = venet_acct_ioctl(file, VZCTL_TC_GET_STAT_LIST,
				(unsigned long)s);
		break;
	}
	case COMPAT_VZCTL_TC_SET_CLASS_TABLE:
	case COMPAT_VZCTL_TC_GET_CLASS_TABLE: {
		struct compat_vzctl_tc_classes cs;
		struct vzctl_tc_classes __user *s;

		s = compat_alloc_user_space(sizeof(*s));

		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;
		if (put_user(compat_ptr(cs.info), &s->info) ||
		    put_user(cs.length, &s->length))
			break;

		err = venet_acct_ioctl(file,
				cmd == COMPAT_VZCTL_TC_GET_CLASS_TABLE ?
					VZCTL_TC_GET_CLASS_TABLE :
					VZCTL_TC_SET_CLASS_TABLE,
				(unsigned long)s);
		break;
	}
	default:
		/* should be OK */
		err = venet_acct_ioctl(file, cmd, arg);
		break;
	}
	return err;
}
#endif

static struct vzioctlinfo tc_ioctl_info = {
	.type 		= VZTCCTLTYPE,
	.ioctl		= venet_acct_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_venet_acct_ioctl,
#endif
	.owner		= THIS_MODULE,
};


/*
 * ---------------------------------------------------------------------------
 * /proc interface for user
 * ---------------------------------------------------------------------------
 */

static char seq_buffer[1024];
static DEFINE_SPINLOCK(seq_buffer_lock);

static int stat_seq_show_common(struct seq_file *m, void *v, int v6)
{
	struct venet_stat *ptr = (struct venet_stat *)v;
	struct acct_stat *acct = __choose_acct(ptr, v6);
	int i;

	spin_lock(&seq_buffer_lock);
	*seq_buffer = 0;
	for (i = 0; i < TC_CLASS_MAX; i++) {
		u64 incoming = 0;
		u64 outgoing = 0;
		int cpu;

		for_each_possible_cpu(cpu) {
			struct acct_stat *stat;

			stat = per_cpu_ptr(acct, cpu);
			incoming += stat->cnt[i][ACCT_IN].bytes;
			outgoing += stat->cnt[i][ACCT_OUT].bytes;
		}

		sprintf(seq_buffer + strlen(seq_buffer), " %20Lu/%20Lu",
				incoming, outgoing);
	}

	seq_printf(m, "%u %s\n", ptr->veid, seq_buffer);
	spin_unlock(&seq_buffer_lock);
	return 0;
}

static int stat_seq_show_v4(struct seq_file *m, void *v)
{
	return stat_seq_show_common(m, v, 0);
}

static int stat_seq_show_v6(struct seq_file *m, void *v)
{
	return stat_seq_show_common(m, v, 1);
}

static void *stat_seq_start(struct seq_file *m, loff_t *pos)
{
	struct venet_stat *stat;
	int hash;
	loff_t l;

	if (!ve_is_super(get_exec_env()))
		return NULL;

	read_lock(&tc_lock);
	hash = 0;
	stat = NULL;
	stat = next_stat(&hash, stat);
	for (l = *pos; stat && l > 0; l--)
		stat = next_stat(&hash, stat);
	return stat;
}

static void *stat_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct venet_stat *ptr = (struct venet_stat *)v;
	int hash;

	if (!ve_is_super(get_exec_env()))
		return NULL;
	hash = stat_hash(ptr->veid);
	(*pos)++;
	return next_stat(&hash, ptr);
}

static void stat_seq_stop(struct seq_file *m, void *v)
{
	read_unlock(&tc_lock);
}

static struct seq_operations stat_seq_op = {
        .start = stat_seq_start,
        .next  = stat_seq_next,
        .stop  = stat_seq_stop,
        .show  = stat_seq_show_v4,
};

static struct seq_operations stat_v6_seq_op = {
        .start = stat_seq_start,
        .next  = stat_seq_next,
        .stop  = stat_seq_stop,
        .show  = stat_seq_show_v6,
};

static int stat_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &stat_seq_op);
}

static int stat_v6_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &stat_v6_seq_op);
}

static struct file_operations proc_venetstat_operations = {
        .open		= stat_open,
        .read		= seq_read,
        .llseek		= seq_lseek,
        .release	= seq_release,
};

static struct file_operations proc_venetstat_v6_operations = {
        .open		= stat_v6_open,
        .read		= seq_read,
        .llseek		= seq_lseek,
        .release	= seq_release,
};

static int __net_init net_init_acct(struct net *net)
{
	struct ve_struct *ve = net->owner_ve;

	if (!ve->stat) {
		ve->stat = venet_acct_find_create_stat(ve->veid);
		if (!ve->stat)
			return -ENOMEM;
	} else
		venet_acct_get_stat(ve->stat);

	return 0;
}

static void __net_exit net_exit_acct(struct net *net)
{
	struct ve_struct *ve = net->owner_ve;

	if (ve->stat) {
		venet_acct_put_stat(ve->stat);
		if (ve->ve_netns == net)
			ve->stat = NULL;
	}
}

static struct pernet_operations __net_initdata net_acct_ops = {
	.init	= net_init_acct,
	.exit	= net_exit_acct,
};

int __init venetstat_init(void)
{
	int i, ret;
#if CONFIG_PROC_FS
	struct proc_dir_entry *de;
#endif

	for (i = 0; i < STAT_HASH_LEN; i++)
		INIT_LIST_HEAD(stat_hash_list + i);

	ret = register_pernet_subsys(&net_acct_ops);
	if (ret)
		return ret;

#if CONFIG_PROC_FS
	de = proc_create("venetstat", S_IFREG|S_IRUSR, proc_vz_dir,
			&proc_venetstat_operations);
	if (de == NULL)
		printk(KERN_WARNING "VENET: can't make venetstat proc entry\n");

	de = proc_create("venetstat_v6", S_IFREG|S_IRUSR, proc_vz_dir,
			&proc_venetstat_v6_operations);
	if (de == NULL)
		printk(KERN_WARNING "VENET: can't make venetstat_v6 proc entry\n");

#endif
	vzioctl_register(&tc_ioctl_info);
	return 0;
}

void __exit venetstat_exit(void)
{
	unregister_pernet_subsys(&net_acct_ops);
	vzioctl_unregister(&tc_ioctl_info);
	venet_acct_destroy_all_stat();

#if CONFIG_PROC_FS
	remove_proc_entry("venetstat_v6", proc_vz_dir);
	remove_proc_entry("venetstat", proc_vz_dir);
#endif
	kfree(info_v4);
	kfree(info_v6);
}

module_init(venetstat_init);
module_exit(venetstat_exit);

MODULE_LICENSE("GPL v2");

EXPORT_SYMBOL(venet_acct_find_create_stat);
EXPORT_SYMBOL(venet_acct_find_stat);
EXPORT_SYMBOL(venet_acct_put_stat);
EXPORT_SYMBOL(venet_acct_classify);
EXPORT_SYMBOL(venet_acct_classify_add_outgoing);
EXPORT_SYMBOL(venet_acct_classify_sub_outgoing);
EXPORT_SYMBOL(venet_acct_classify_add_incoming);
EXPORT_SYMBOL(venet_acct_classify_add_incoming_plain);
EXPORT_SYMBOL(venet_acct_classify_add_outgoing_plain);
