/*
 *  linux/kernel/ve/vecalls.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 */

/*
 * 'vecalls.c' is file with basic VE support. It provides basic primities
 * along with initialization script
 */

#include <linux/delay.h>
#include <linux/capability.h>
#include <linux/ve.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sys.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/mnt_namespace.h>
#include <linux/termios.h>
#include <linux/tty_driver.h>
#include <linux/netdevice.h>
#include <linux/wait.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/utsname.h>
#include <linux/proc_fs.h>
#include <linux/devpts_fs.h>
#include <linux/shmem_fs.h>
#include <linux/user_namespace.h>
#include <linux/sysfs.h>
#include <linux/seq_file.h>
#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/rcupdate.h>
#include <linux/in.h>
#include <linux/idr.h>
#include <linux/inetdevice.h>
#include <linux/pid.h>
#include <net/pkt_sched.h>
#include <bc/beancounter.h>
#include <linux/nsproxy.h>
#include <linux/kobject.h>
#include <linux/freezer.h>
#include <linux/pid_namespace.h>
#include <linux/tty.h>
#include <linux/mount.h>
#include <linux/kthread.h>
#include <linux/oom.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <generated/utsrelease.h>

#include <net/route.h>
#include <net/ip_fib.h>
#include <net/ip6_route.h>
#include <net/arp.h>
#include <net/ipv6.h>

#include <linux/ve_proto.h>
#include <linux/venet.h>
#include <linux/vzctl.h>
#include <uapi/linux/vzcalluser.h>
#include <linux/fairsched.h>
#include <linux/device_cgroup.h>

#include <linux/virtinfo.h>
#include <linux/major.h>

static struct cgroup *devices_root;

static int	do_env_enter(struct ve_struct *ve, unsigned int flags);

static void vecalls_exit(void);

static int alone_in_pgrp(struct task_struct *tsk);

static s64 ve_get_uptime(struct ve_struct *ve)
{
	struct timespec uptime;
	do_posix_clock_monotonic_gettime(&uptime);
	monotonic_to_bootbased(&uptime);
	uptime = timespec_sub(uptime, ve->real_start_timespec);
	return timespec_to_ns(&uptime);
}

static int ve_get_cpu_stat(envid_t veid, struct vz_cpu_stat __user *buf)
{
	struct ve_struct *ve;
	struct vz_cpu_stat *vstat;
	int retval;
	int i;
	unsigned long tmp;
	unsigned long avenrun[3];
	struct kernel_cpustat kstat;

	if (!ve_is_super(get_exec_env()) && (veid != get_exec_env()->veid))
		return -EPERM;
	ve = get_ve_by_id(veid);
	if (!ve)
		return -ESRCH;

	retval = -ENOMEM;
	vstat = kzalloc(sizeof(*vstat), GFP_KERNEL);
	if (!vstat)
		goto out_put_ve;

	retval = fairsched_get_cpu_stat(ve->ve_name, &kstat);
	if (retval)
		goto out_free;

	retval = fairsched_get_cpu_avenrun(ve->ve_name, avenrun);
	if (retval)
		goto out_free;

	vstat->user_jif += (unsigned long)cputime64_to_clock_t(kstat.cpustat[CPUTIME_USER]);
	vstat->nice_jif += (unsigned long)cputime64_to_clock_t(kstat.cpustat[CPUTIME_NICE]);
	vstat->system_jif += (unsigned long)cputime64_to_clock_t(kstat.cpustat[CPUTIME_SYSTEM]);
	vstat->idle_clk += cputime_to_usecs(kstat.cpustat[CPUTIME_IDLE]) * NSEC_PER_USEC;

	vstat->uptime_clk = ve_get_uptime(ve);

	vstat->uptime_jif = (unsigned long)cputime64_to_clock_t(
				get_jiffies_64() - ve->start_jiffies);
	for (i = 0; i < 3; i++) {
		tmp = avenrun[i] + (FIXED_1/200);
		vstat->avenrun[i].val_int = LOAD_INT(tmp);
		vstat->avenrun[i].val_frac = LOAD_FRAC(tmp);
	}

	retval = 0;
	if (copy_to_user(buf, vstat, sizeof(*vstat)))
		retval = -EFAULT;
out_free:
	kfree(vstat);
out_put_ve:
	put_ve(ve);
	return retval;
}

static int real_setdevperms(envid_t veid, unsigned type,
		dev_t dev, unsigned mask)
{
	struct ve_struct *ve;
	struct cgroup *cgroup;
	int err;

	if (!capable_setveid() || veid == 0)
		return -EPERM;

	if ((ve = get_ve_by_id(veid)) == NULL)
		return -ESRCH;

	down_read(&ve->op_sem);
	err = -ESRCH;

	cgroup = ve_cgroup_open(devices_root, 0, ve->veid);
	err = PTR_ERR(cgroup);
	if (IS_ERR(cgroup))
		goto out;

	if (ve->is_running)
		err = devcgroup_set_perms_ve(cgroup, type, dev, mask);

	cgroup_kernel_close(cgroup);
out:
	up_read(&ve->op_sem);
	put_ve(ve);
	return err;
}

/**********************************************************************
 **********************************************************************
 *
 * VE start: subsystems
 *
 **********************************************************************
 **********************************************************************/

/*
 * Namespaces
 */

static inline int init_ve_namespaces(void)
{
	int err;

	err = copy_namespaces(CLONE_NEWUTS | CLONE_NEWIPC |
			      CLONE_NEWPID | CLONE_NEWNET,
			      current, 1);
	if (err < 0)
		return err;

	memcpy(utsname()->release, virt_utsname.release,
			sizeof(virt_utsname.release));

	return 0;
}

static __u64 get_ve_features(env_create_param_t *data, int datalen)
{
	__u64 known_features;

	if (datalen < sizeof(struct env_create_param3))
		/* this version of vzctl is aware of VE_FEATURES_OLD only */
		known_features = VE_FEATURES_OLD;
	else
		known_features = data->known_features;

	/*
	 * known features are set as required
	 * yet unknown features are set as in VE_FEATURES_DEF
	 */
	return (data->feature_mask & known_features) |
		(VE_FEATURES_DEF & ~known_features);
}

#ifdef CONFIG_VE_IPTABLES

static __u64 setup_iptables_mask(__u64 init_mask)
{
	/* Remove when userspace will start supplying IPv6-related bits. */
	init_mask &= ~VE_IP_IPTABLES6;
	init_mask &= ~VE_IP_FILTER6;
	init_mask &= ~VE_IP_MANGLE6;
	init_mask &= ~VE_IP_IPTABLE_NAT_MOD;
	init_mask &= ~VE_NF_CONNTRACK_MOD;

	if (mask_ipt_allow(init_mask, VE_IP_IPTABLES))
		init_mask |= VE_IP_IPTABLES6;
	if (mask_ipt_allow(init_mask, VE_IP_FILTER))
		init_mask |= VE_IP_FILTER6;
	if (mask_ipt_allow(init_mask, VE_IP_MANGLE))
		init_mask |= VE_IP_MANGLE6;
	if (mask_ipt_allow(init_mask, VE_IP_NAT))
		init_mask |= VE_IP_IPTABLE_NAT;
	if (mask_ipt_allow(init_mask, VE_IP_CONNTRACK))
		init_mask |= VE_NF_CONNTRACK;

	return init_mask;
}

#endif

static int init_ve_struct(struct ve_struct *ve,
		u32 class_id, env_create_param_t *data, int datalen)
{
	ve->class_id = class_id;
	ve->features = get_ve_features(data, datalen);

	ve->_randomize_va_space = ve0._randomize_va_space;

	ve->odirect_enable = 2;

#ifdef CONFIG_VE_IPTABLES
	/* Set up ipt_mask as it will be used during
	 * net namespace initialization
	 */
	ve->ipt_mask = setup_iptables_mask(data ? data->iptables_mask
						: VE_IP_DEFAULT);
#endif

	return 0;
}

/**********************************************************************
 **********************************************************************
 *
 * /proc/meminfo virtualization
 *
 **********************************************************************
 **********************************************************************/
static int ve_set_meminfo(envid_t veid, unsigned long val)
{
#ifdef CONFIG_BEANCOUNTERS
	struct ve_struct *ve;

	ve = get_ve_by_id(veid);
	if (!ve)
		return -EINVAL;

	if (val == 0)
		val = VE_MEMINFO_SYSTEM;
	else if (val == 1)
		val = VE_MEMINFO_DEFAULT;

	ve->meminfo_val = val;
	put_ve(ve);
	return 0;
#else
	return -ENOTTY;
#endif
}

static void init_ve_cred(struct cred *new)
{
	struct user_namespace *user_ns = new->user_ns;
	kernel_cap_t bset;

	bset = current_cred()->cap_effective;

	/*
	 * Task capabilities checks now user-ns aware. This deprecates old
	 * CAP_VE_ADMIN. CAP_SYS/NET_ADMIN in container now completely safe.
	 */
	if (cap_raised(bset, CAP_VE_ADMIN)) {
		cap_raise(bset, CAP_SYS_ADMIN);
		cap_raise(bset, CAP_NET_ADMIN);
	}

	/*
	 * Full set of capabilites in nested user-ns is safe. But vzctl can
	 * drop some capabilites to create restricted container.
	 */
	new->cap_inheritable = CAP_EMPTY_SET;
	new->cap_effective = bset;
	new->cap_permitted = bset;
	new->cap_bset = bset;

	/*
	 * Setup equal uid/gid mapping.
	 * proc_uid_map_write() forbids further changings.
	 */
	user_ns->uid_map = user_ns->parent->uid_map;
	user_ns->gid_map = user_ns->parent->gid_map;
}

static int alone_in_pgrp(struct task_struct *tsk)
{
	struct task_struct *p;
	int alone = 0;

	read_lock(&tasklist_lock);
	do_each_pid_task(task_pid(tsk), PIDTYPE_PGID, p) {
		if (p != tsk)
			goto out;
	} while_each_pid_task(task_pid(tsk), PIDTYPE_PGID, p);
	do_each_pid_task(task_pid(tsk), PIDTYPE_SID, p) {
		if (p != tsk)
			goto out;
	} while_each_pid_task(task_pid(tsk), PIDTYPE_SID, p);
	alone = 1;
out:
	read_unlock(&tasklist_lock);
	return alone;
}

static struct vfsmount *ve_cgroup_mnt, *devices_cgroup_mnt;

static int __init init_vecalls_cgroups(void)
{
	struct cgroup_sb_opts devices_opts = {
		.name		= vz_compat ? "container" : NULL,
		.subsys_mask	=
			(1ul << devices_subsys_id),
	};

	struct cgroup_sb_opts ve_opts = {
		.subsys_mask	=
			(1ul << ve_subsys_id),
	};

	devices_cgroup_mnt = cgroup_kernel_mount(&devices_opts);
	if (IS_ERR(devices_cgroup_mnt))
		return PTR_ERR(devices_cgroup_mnt);
	devices_root = cgroup_get_root(devices_cgroup_mnt);

	ve_cgroup_mnt = cgroup_kernel_mount(&ve_opts);
	if (IS_ERR(ve_cgroup_mnt)) {
		kern_unmount(devices_cgroup_mnt);
		return PTR_ERR(ve_cgroup_mnt);
	}

	return 0;
}

static void fini_vecalls_cgroups(void)
{
	kern_unmount(ve_cgroup_mnt);
	kern_unmount(devices_cgroup_mnt);
}

static int do_env_create(envid_t veid, unsigned int flags, u32 class_id,
			 env_create_param_t *data, int datalen)
{
	struct task_struct *tsk = current;
	struct ve_struct *ve;
	struct cred *new_creds, *old_creds;
	int err;
	struct nsproxy *old_ns;
	char ve_name[VE_LEGACY_NAME_MAXLEN];
	struct cgroup *ve_cgroup;
	struct cgroup *dev_cgroup;

	if (tsk->signal->tty) {
		printk("ERR: CT init has controlling terminal\n");
		return -EINVAL;
	}
	if (task_pgrp(tsk) != task_pid(tsk) ||
			task_session(tsk) != task_pid(tsk)) {
		int may_setsid;

		read_lock(&tasklist_lock);
		may_setsid = !tsk->signal->leader &&
			!pid_task(find_pid_ns(task_pid_nr(tsk), &init_pid_ns), PIDTYPE_PGID);
		read_unlock(&tasklist_lock);

		if (!may_setsid) {
			printk("ERR: CT init is process group leader\n");
			return -EINVAL;
		}
	}
	/* Check that the process is not a leader of non-empty group/session.
	 * If it is, we cannot virtualize its PID and must fail. */
	if (!alone_in_pgrp(tsk)) {
		printk("ERR: CT init is not alone in process group\n");
		return -EINVAL;
	}

	/* create new cpu-cgroup and move current task into it */
	err = fairsched_new_node(veid, data->total_vcpus);
	if (err)
		goto err_sched;

	legacy_veid_to_name(veid, ve_name);

	ve_cgroup = ve_cgroup_open(ve0.css.cgroup, CGRP_CREAT|CGRP_EXCL, veid);
	err = PTR_ERR(ve_cgroup);
	if (IS_ERR(ve_cgroup))
		goto err_ve_cgroup;

	dev_cgroup = ve_cgroup_open(devices_root, CGRP_CREAT, veid);
	err = PTR_ERR(dev_cgroup);
	if (IS_ERR(dev_cgroup))
		goto err_dev_cgroup;

	err = devcgroup_default_perms_ve(dev_cgroup);
	if (err)
		goto err_devperms;

	ve = cgroup_ve(ve_cgroup);
	ve->legacy = true;

	init_ve_struct(ve, class_id, data, datalen);

	down_write(&ve->op_sem);

	err = cgroup_kernel_attach(ve->css.cgroup, tsk);
	if (err)
		goto err_ve_attach;

	err = cgroup_kernel_attach(dev_cgroup, tsk);
	if (err)
		goto err_dev_attach;

	err = -ENOMEM;
	new_creds = prepare_creds();
	if (new_creds == NULL)
		goto err_creds;

	err = create_user_ns(new_creds);
	if (err) {
		put_cred(new_creds);
		goto err_creds;
	}

	init_ve_cred(new_creds);

	old_creds = (struct cred *)get_current_cred();

	commit_creds(new_creds);

	old_ns = tsk->nsproxy;

	if ((err = init_ve_namespaces()))
		goto err_ns;

	/* for compatibility only */
	if ((err = change_active_pid_ns(tsk, tsk->nsproxy->pid_ns)) < 0)
		goto err_vpid;

	if (flags & VE_LOCK)
		ve->is_locked = 1;

	err = ve_start_container(ve);
	if (err)
		goto err_ve_start;

	up_write(&ve->op_sem);

	cgroup_kernel_close(ve_cgroup);
	cgroup_kernel_close(dev_cgroup);

	put_nsproxy(old_ns);
	put_cred(old_creds);

	return veid;

err_ve_start:
	up_write(&ve->op_sem);
err_vpid:
	switch_task_namespaces(tsk, old_ns);
err_ns:
	commit_creds(old_creds);
err_creds:
	cgroup_kernel_attach(&dev_cgroup->root->top_cgroup, tsk);
err_dev_attach:
	cgroup_kernel_attach(ve0.css.cgroup, tsk);
err_ve_attach:
err_devperms:
	cgroup_kernel_close(dev_cgroup);
err_dev_cgroup:
	cgroup_kernel_close(ve_cgroup);
err_ve_cgroup:
	fairsched_drop_node(veid, 1);
err_sched:
	printk(KERN_INFO "CT: %d: failed to start with err=%d\n", veid, err);
	return err;
}


/**********************************************************************
 **********************************************************************
 *
 * VE start/stop callbacks
 *
 **********************************************************************
 **********************************************************************/

int real_env_create(envid_t veid, unsigned flags, u32 class_id,
			env_create_param_t *data, int datalen)
{
	int status;
	struct ve_struct *ve;

	if (!flags) {
		status = get_exec_env()->veid;
		goto out;
	}

	status = -EPERM;
	if (!capable_setveid())
		goto out;

	status = -EINVAL;
	if ((flags & VE_TEST) && (flags & (VE_ENTER|VE_CREATE)))
		goto out;

	status = -EINVAL;
	ve = get_ve_by_id(veid);
	if (ve) {
		if (flags & VE_TEST) {
			status = 0;
			goto out_put;
		}
		if (flags & VE_EXCLUSIVE) {
			status = -EACCES;
			goto out_put;
		}
		if (flags & VE_CREATE) {
			flags &= ~VE_CREATE;
			flags |= VE_ENTER;
		}
	} else {
		if (flags & (VE_TEST|VE_ENTER)) {
			status = -ESRCH;
			goto out;
		}
	}

	if (flags & VE_CREATE) {
		status = do_env_create(veid, flags, class_id, data, datalen);
		goto out;
	} else if (flags & VE_ENTER)
		status = do_env_enter(ve, flags);

	/* else: returning EINVAL */

out_put:
	put_ve(ve);
out:
	return status;
}
EXPORT_SYMBOL(real_env_create);

static int do_env_enter(struct ve_struct *ve, unsigned int flags)
{
	struct task_struct *tsk = current;
	int err;

	err = fairsched_move_task(ve->veid, current);
	if (err)
		return err;

	err = -EBUSY;
	down_read(&ve->op_sem);
	if (!ve->is_running)
		goto out_up;
	if (ve->is_locked && !(flags & VE_SKIPLOCK))
		goto out_up;

	switch_task_namespaces(tsk, get_nsproxy(ve->ve_ns));

	commit_creds(get_new_cred(ve->init_cred));

	err = cgroup_kernel_attach(ve->css.cgroup, current);
	if (err)
		goto out_up;

	if (alone_in_pgrp(tsk) && !(flags & VE_SKIPLOCK))
		change_active_pid_ns(tsk, ve->ve_ns->pid_ns);

	/* Unlike VE_CREATE, we do not setsid() in VE_ENTER.
	 * Process is allowed to be in an external group/session.
	 * If user space callers wants, it will do setsid() after
	 * VE_ENTER.
	 */
	err = ve->veid;
	tsk->did_ve_enter = 1;

out_up:
	up_read(&ve->op_sem);

	if (err < 0)
		fairsched_move_task(0, current);

	return err;
}

static void vzmon_stop_notifier(void *data)
{
	struct ve_struct *ve = data;

	if (ve->legacy)
		fairsched_drop_node(ve->veid, 0);
}

static struct ve_hook vzmon_stop_hook = {
	.fini		= vzmon_stop_notifier,
	.priority	= HOOK_PRIO_FINISHING,
	.owner		= THIS_MODULE,
};

/**********************************************************************
 **********************************************************************
 *
 * Pieces of VE network
 *
 **********************************************************************
 **********************************************************************/

#ifdef CONFIG_NET
#include <asm/uaccess.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/route.h>
#include <net/ip_fib.h>
#endif

static int ve_dev_add(envid_t veid, char *dev_name)
{
	struct net_device *dev;
	struct ve_struct *dst_ve;
	struct net *dst_net;
	int err = -ESRCH;

	dst_ve = get_ve_by_id(veid);
	if (dst_ve == NULL)
		goto out;

	dst_net = dst_ve->ve_netns;

	rtnl_lock();
	read_lock(&dev_base_lock);
	dev = __dev_get_by_name(&init_net, dev_name);
	read_unlock(&dev_base_lock);
	if (dev == NULL)
		goto out_unlock;

	err = dev_change_net_namespace(dev, dst_net, dev_name);
out_unlock:
	rtnl_unlock();
	put_ve(dst_ve);

	if (dev == NULL)
		printk(KERN_WARNING "%s: device %s not found\n",
			__func__, dev_name);
out:
	return err;
}

static int ve_dev_del(envid_t veid, char *dev_name)
{
	struct net_device *dev;
	struct ve_struct *src_ve;
	struct net *src_net;
	int err = -ESRCH;

	src_ve = get_ve_by_id(veid);
	if (src_ve == NULL)
		goto out;

	src_net = src_ve->ve_netns;

	rtnl_lock();

	read_lock(&dev_base_lock);
	dev = __dev_get_by_name(src_net, dev_name);
	read_unlock(&dev_base_lock);
	if (dev == NULL)
		goto out_unlock;

	err = dev_change_net_namespace(dev, &init_net, dev_name);
out_unlock:
	rtnl_unlock();
	put_ve(src_ve);

	if (dev == NULL)
		printk(KERN_WARNING "%s: device %s not found\n",
			__func__, dev_name);
out:
	return err;
}

int real_ve_dev_map(envid_t veid, int op, char *dev_name)
{
	if (!capable_setveid())
		return -EPERM;
	switch (op) {
	case VE_NETDEV_ADD:
		return ve_dev_add(veid, dev_name);
	case VE_NETDEV_DEL:
		return ve_dev_del(veid, dev_name);
	default:
		return -EINVAL;
	}
}

/**********************************************************************
 **********************************************************************
 *
 * VE information via /proc
 *
 **********************************************************************
 **********************************************************************/
#ifdef CONFIG_PROC_FS
#if BITS_PER_LONG == 32
#define VESTAT_LINE_WIDTH (6 * 11 + 6 * 21)
#define VESTAT_LINE_FMT "%10s %10lu %10lu %10lu %10Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %10lu\n"
#define VESTAT_HEAD_FMT "%10s %10s %10s %10s %10s %20s %20s %20s %20s %20s %20s %10s\n"
#else
#define VESTAT_LINE_WIDTH (12 * 21)
#define VESTAT_LINE_FMT "%20s %20lu %20lu %20lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20lu\n"
#define VESTAT_HEAD_FMT "%20s %20s %20s %20s %20s %20s %20s %20s %20s %20s %20s %20s\n"
#endif

static int vestat_seq_show(struct seq_file *m, void *v)
{
	struct list_head *entry;
	struct ve_struct *ve;
	struct ve_struct *curve;
	int ret;
	unsigned long user_ve, nice_ve, system_ve;
	unsigned long long uptime;
	u64 uptime_cycles, idle_time, strv_time, used;
	struct kernel_cpustat kstat;

	entry = (struct list_head *)v;
	ve = list_entry(entry, struct ve_struct, ve_list);

	curve = get_exec_env();
	if (entry == ve_list_head.next ||
	    (!ve_is_super(curve) && ve == curve)) {
		/* print header */
		seq_printf(m, "%-*s\n",
			VESTAT_LINE_WIDTH - 1,
			"Version: 2.2");
		seq_printf(m, VESTAT_HEAD_FMT, "VEID",
					"user", "nice", "system",
					"uptime", "idle",
					"strv", "uptime", "used",
					"maxlat", "totlat", "numsched");
	}

	if (ve == get_ve0())
		return 0;

	ret = fairsched_get_cpu_stat(ve->ve_name, &kstat);
	if (ret)
		return ret;

	strv_time = 0;
	user_ve = cputime_to_jiffies(kstat.cpustat[CPUTIME_USER]);
	nice_ve = cputime_to_jiffies(kstat.cpustat[CPUTIME_NICE]);
	system_ve = cputime_to_jiffies(kstat.cpustat[CPUTIME_SYSTEM]);
	used = cputime_to_usecs(kstat.cpustat[CPUTIME_USED]) * NSEC_PER_USEC;
	idle_time = cputime_to_usecs(kstat.cpustat[CPUTIME_IDLE]) *
							NSEC_PER_USEC;

	uptime_cycles = ve_get_uptime(ve);
	uptime = get_jiffies_64() - ve->start_jiffies;

	seq_printf(m, VESTAT_LINE_FMT, ve_name(ve),
				user_ve, nice_ve, system_ve,
				(unsigned long long)uptime,
				(unsigned long long)idle_time, 
				(unsigned long long)strv_time,
				(unsigned long long)uptime_cycles,
				(unsigned long long)used,
				(unsigned long long)ve->sched_lat_ve.last.maxlat,
				(unsigned long long)ve->sched_lat_ve.last.totlat,
				ve->sched_lat_ve.last.count);
	return 0;
}

void *ve_seq_start(struct seq_file *m, loff_t *pos)
{
	struct ve_struct *curve;

	curve = get_exec_env();
	mutex_lock(&ve_list_lock);
	if (!ve_is_super(curve)) {
		if (*pos != 0)
			return NULL;
		return &curve->ve_list;
	}

	return seq_list_start(&ve_list_head, *pos);
}
EXPORT_SYMBOL(ve_seq_start);

void *ve_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	if (!ve_is_super(get_exec_env()))
		return NULL;
	else
		return seq_list_next(v, &ve_list_head, pos);
}
EXPORT_SYMBOL(ve_seq_next);

void ve_seq_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&ve_list_lock);
}
EXPORT_SYMBOL(ve_seq_stop);

static struct seq_operations vestat_seq_op = {
        .start	= ve_seq_start,
        .next	= ve_seq_next,
        .stop	= ve_seq_stop,
        .show	= vestat_seq_show
};

static int vestat_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &vestat_seq_op);
}

static struct file_operations proc_vestat_operations = {
        .open	 = vestat_open,
        .read	 = seq_read,
        .llseek	 = seq_lseek,
        .release = seq_release
};

static int devperms_seq_show(struct seq_file *m, void *v)
{
	struct ve_struct *ve = list_entry(v, struct ve_struct, ve_list);

	if (m->private == (void *)0) {
		seq_printf(m, "Version: 2.7\n");
		m->private = (void *)-1;
	}

	if (ve_is_super(ve))
		seq_printf(m, "%10u b 016 *:*\n%10u c 006 *:*\n", 0, 0);
	else
		devcgroup_seq_show_ve(devices_root, ve, m);

	return 0;
}

static struct seq_operations devperms_seq_op = {
	.start  = ve_seq_start,
	.next   = ve_seq_next,
	.stop   = ve_seq_stop,
	.show   = devperms_seq_show,
};

static int devperms_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &devperms_seq_op);
}

static struct file_operations proc_devperms_ops = {
	.open           = devperms_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

static int vz_version_show(struct seq_file *file, void* v)
{
	static const char ver[] = VZVERSION "\n";

	return seq_puts(file, ver);
}

static int vz_version_open(struct inode *inode, struct file *file)
{
	return single_open(file, vz_version_show, NULL);
}

static struct file_operations proc_vz_version_oparations = {
	.open    = vz_version_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

/* /proc/vz/veinfo */

static ve_seq_print_t veaddr_seq_print_cb;

void vzmon_register_veaddr_print_cb(ve_seq_print_t cb)
{
	rcu_assign_pointer(veaddr_seq_print_cb, cb);
}
EXPORT_SYMBOL(vzmon_register_veaddr_print_cb);

void vzmon_unregister_veaddr_print_cb(ve_seq_print_t cb)
{
	rcu_assign_pointer(veaddr_seq_print_cb, NULL);
	synchronize_rcu();
}
EXPORT_SYMBOL(vzmon_unregister_veaddr_print_cb);

static int veinfo_seq_show(struct seq_file *m, void *v)
{
	struct ve_struct *ve;
	ve_seq_print_t veaddr_seq_print;

	ve = list_entry((struct list_head *)v, struct ve_struct, ve_list);

	seq_printf(m, "%10s %5u %5u", ve_name(ve), ve->class_id, nr_threads_ve(ve));

	rcu_read_lock();
	veaddr_seq_print = rcu_dereference(veaddr_seq_print_cb);
	if (veaddr_seq_print)
		veaddr_seq_print(m, ve);
	rcu_read_unlock();

	seq_putc(m, '\n');
	return 0;
}

static struct seq_operations veinfo_seq_op = {
	.start	= ve_seq_start,
	.next	=  ve_seq_next,
	.stop	=  ve_seq_stop,
	.show	=  veinfo_seq_show,
};

static int veinfo_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &veinfo_seq_op);
}

static struct file_operations proc_veinfo_operations = {
	.open		= veinfo_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init init_vecalls_proc(void)
{
	struct proc_dir_entry *de;

	de = proc_create("vestat", S_IFREG | S_IRUSR | S_ISVTX, proc_vz_dir,
			&proc_vestat_operations);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make vestat proc entry\n");

	de = proc_create("devperms", S_IFREG | S_IRUSR, proc_vz_dir,
			&proc_devperms_ops);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make devperms proc entry\n");

	de = proc_create("version", S_IFREG | S_IRUGO, proc_vz_dir,
			&proc_vz_version_oparations);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make version proc entry\n");

	de = proc_create("veinfo", S_IFREG | S_IRUSR | S_ISVTX, proc_vz_dir,
			&proc_veinfo_operations);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make veinfo proc entry\n");

	return 0;
}

static void fini_vecalls_proc(void)
{
	remove_proc_entry("version", proc_vz_dir);
	remove_proc_entry("devperms", proc_vz_dir);
	remove_proc_entry("vestat", proc_vz_dir);
	remove_proc_entry("veinfo", proc_vz_dir);
}
#else
#define init_vecalls_proc()	(0)
#define fini_vecalls_proc()	do { } while (0)
#endif /* CONFIG_PROC_FS */

static int init_ve_osrelease(struct ve_struct *ve, char *release)
{
	if (!release)
		return -ENODATA;

	if (strlen(release) >= sizeof(ve->ve_ns->uts_ns->name.release))
		return -EMSGSIZE;

	down_write(&uts_sem);
	strcpy(ve->ve_ns->uts_ns->name.release, release);
	up_write(&uts_sem);

	return 0;
}

static int ve_configure(envid_t veid, unsigned int key,
			unsigned int val, unsigned int size, char *data)
{
	struct ve_struct *ve;
	int err = -ENOKEY;

	ve = get_ve_by_id(veid);
	if (!ve)
		return -EINVAL;

	switch(key) {
	case VE_CONFIGURE_OS_RELEASE:
		err = init_ve_osrelease(ve, data);
		break;
	}

	put_ve(ve);
 	return err;
}

static int ve_configure_ioctl(struct vzctl_ve_configure *arg)
{
	int err;
	struct vzctl_ve_configure s;
	char *data = NULL;

	err = -EFAULT;
	if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
		goto out;
	if (s.size) {
		if (s.size > PAGE_SIZE)
			return -EMSGSIZE;

		data = kzalloc(s.size + 1, GFP_KERNEL);
		if (unlikely(!data))
			return -ENOMEM;

		if (copy_from_user(data, (void __user *) &arg->data, s.size))
			goto out;
	}
	err = ve_configure(s.veid, s.key, s.val, s.size, data);
out:
	kfree(data);
	return err;
}

/**********************************************************************
 **********************************************************************
 *
 * User ctl
 *
 **********************************************************************
 **********************************************************************/

int vzcalls_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;

	err = -ENOTTY;
	switch(cmd) {
	    case VZCTL_MARK_ENV_TO_DOWN: {
		        /* Compatibility issue */
		        err = 0;
		}
		break;
	    case VZCTL_SETDEVPERMS: {
			/* Device type was mistakenly declared as dev_t
			 * in the old user-kernel interface.
			 * That's wrong, dev_t is a kernel internal type.
			 * I use `unsigned' not having anything better in mind.
			 * 2001/08/11  SAW  */
			struct vzctl_setdevperms s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = real_setdevperms(s.veid, s.type,
					new_decode_dev(s.dev), s.mask);
		}
		break;
#ifdef CONFIG_INET
	    case VZCTL_VE_NETDEV: {
			struct vzctl_ve_netdev d;
			char *s;
			err = -EFAULT;
			if (copy_from_user(&d, (void __user *)arg, sizeof(d)))
				break;
			err = -ENOMEM;
			s = kmalloc(IFNAMSIZ+1, GFP_KERNEL);
			if (s == NULL)
				break;
			err = -EFAULT;
			if (strncpy_from_user(s, d.dev_name, IFNAMSIZ) > 0) {
				s[IFNAMSIZ] = 0;
				err = real_ve_dev_map(d.veid, d.op, s);
			}
			kfree(s);
		}
		break;
#endif
	    case VZCTL_ENV_CREATE: {
			struct vzctl_env_create s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = real_env_create(s.veid, s.flags, s.class_id,
				NULL, 0);
		}
		break;
	    case VZCTL_ENV_CREATE_DATA: {
			struct vzctl_env_create_data s;
			env_create_param_t *data;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err=-EINVAL;
			if (s.datalen < VZCTL_ENV_CREATE_DATA_MINLEN ||
			    s.datalen > VZCTL_ENV_CREATE_DATA_MAXLEN ||
			    s.data == 0)
				break;
			err = -ENOMEM;
			data = kzalloc(sizeof(*data), GFP_KERNEL);
			if (!data)
				break;

			err = -EFAULT;
			if (copy_from_user(data, (void __user *)s.data,
						s.datalen))
				goto free_data;
			err = real_env_create(s.veid, s.flags, s.class_id,
				data, s.datalen);
free_data:
			kfree(data);
		}
		break;
	    case VZCTL_GET_CPU_STAT: {
			struct vzctl_cpustatctl s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = ve_get_cpu_stat(s.veid, s.cpustat);
		}
		break;
	    case VZCTL_VE_MEMINFO: {
			struct vzctl_ve_meminfo s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = ve_set_meminfo(s.veid, s.val);
		}
		break;
	    case VZCTL_VE_CONFIGURE:
		err = ve_configure_ioctl((struct vzctl_ve_configure *)arg);
		break;
	}
	return err;
}

#ifdef CONFIG_COMPAT
int compat_vzcalls_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	int err;

	switch(cmd) {
	case VZCTL_GET_CPU_STAT: {
		/* FIXME */
	}
	case VZCTL_COMPAT_ENV_CREATE_DATA: {
		struct compat_vzctl_env_create_data cs;
		struct vzctl_env_create_data __user *s;

		s = compat_alloc_user_space(sizeof(*s));
		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;

		if (put_user(cs.veid, &s->veid) ||
		    put_user(cs.flags, &s->flags) ||
		    put_user(cs.class_id, &s->class_id) ||
		    put_user(compat_ptr(cs.data), &s->data) ||
		    put_user(cs.datalen, &s->datalen))
			break;
		err = vzcalls_ioctl(file, VZCTL_ENV_CREATE_DATA,
						(unsigned long)s);
		break;
	}
#ifdef CONFIG_NET
	case VZCTL_COMPAT_VE_NETDEV: {
		struct compat_vzctl_ve_netdev cs;
		struct vzctl_ve_netdev __user *s;

		s = compat_alloc_user_space(sizeof(*s));
		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;

		if (put_user(cs.veid, &s->veid) ||
		    put_user(cs.op, &s->op) ||
		    put_user(compat_ptr(cs.dev_name), &s->dev_name))
			break;
		err = vzcalls_ioctl(file, VZCTL_VE_NETDEV, (unsigned long)s);
		break;
	}
#endif
	case VZCTL_COMPAT_VE_MEMINFO: {
		struct compat_vzctl_ve_meminfo cs;
		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;
		err = ve_set_meminfo(cs.veid, cs.val);
		break;
	}
	default:
		err = vzcalls_ioctl(file, cmd, arg);
		break;
	}
	return err;
}
#endif

static struct vzioctlinfo vzcalls = {
	.type		= VZCTLTYPE,
	.ioctl		= vzcalls_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_vzcalls_ioctl,
#endif
	.owner		= THIS_MODULE,
};


/**********************************************************************
 **********************************************************************
 *
 * Init/exit stuff
 *
 **********************************************************************
 **********************************************************************/

static inline __init int init_vecalls_ioctls(void)
{
	vzioctl_register(&vzcalls);
	return 0;
}

static inline void fini_vecalls_ioctls(void)
{
	vzioctl_unregister(&vzcalls);
}

static int __init vecalls_init(void)
{
	int err;

	ve_hook_register(VE_SS_CHAIN, &vzmon_stop_hook);

	err = init_vecalls_cgroups();
	if (err)
		goto out_cgroups;

	err = init_vecalls_proc();
	if (err < 0)
		goto out_proc;

	err = init_vecalls_ioctls();
	if (err < 0)
		goto out_ioctls;

	/*
	 * This one can also be dereferenced since not freed
	 * VE holds reference on module
	 */

	return 0;

out_ioctls:
	fini_vecalls_proc();
out_proc:
	fini_vecalls_cgroups();
out_cgroups:
	ve_hook_unregister(&vzmon_stop_hook);

	return err;
}

static void __exit vecalls_exit(void)
{
	fini_vecalls_ioctls();
	fini_vecalls_proc();
	fini_vecalls_cgroups();
	ve_hook_unregister(&vzmon_stop_hook);
}

MODULE_AUTHOR("SWsoft <info@sw-soft.com>");
MODULE_DESCRIPTION("Virtuozzo Control");
MODULE_LICENSE("GPL v2");

module_init(vecalls_init)
module_exit(vecalls_exit)
