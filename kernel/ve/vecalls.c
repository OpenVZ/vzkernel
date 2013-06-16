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

#include <linux/sched.h>
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
#include <linux/sysctl.h>
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
#include <linux/vzcalluser.h>
#include <linux/fairsched.h>

#include <linux/virtinfo.h>
#include <linux/major.h>

#include <bc/dcache.h>

int nr_ve = 1;	/* One VE always exists. Compatibility with vestat */
EXPORT_SYMBOL(nr_ve);

static int	do_env_enter(struct ve_struct *ve, unsigned int flags);

static void vecalls_exit(void);

static int alone_in_pgrp(struct task_struct *tsk);

/*
 * real_put_ve() MUST be used instead of put_ve() inside vecalls.
 */
static void real_do_env_free(struct ve_struct *ve);
static inline void real_put_ve(struct ve_struct *ve)
{
	if (ve && atomic_dec_and_test(&ve->counter)) {
		BUG_ON(ve->is_running);
		real_do_env_free(ve);
	}
}
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
	if (veid == 0)
		return -ESRCH;

	vstat = kzalloc(sizeof(*vstat), GFP_KERNEL);
	if (!vstat)
		return -ENOMEM;

	retval = fairsched_get_cpu_stat(veid, &kstat);
	if (retval)
		goto out_free;

	retval = fairsched_get_cpu_avenrun(veid, avenrun);
	if (retval)
		goto out_free;

	retval = -ESRCH;
	mutex_lock(&ve_list_lock);
	ve = __find_ve_by_id(veid);
	if (ve == NULL)
		goto out_unlock;

	vstat->user_jif += (unsigned long)cputime64_to_clock_t(kstat.cpustat[CPUTIME_USER]);
	vstat->nice_jif += (unsigned long)cputime64_to_clock_t(kstat.cpustat[CPUTIME_NICE]);
	vstat->system_jif += (unsigned long)cputime64_to_clock_t(kstat.cpustat[CPUTIME_SYSTEM]);
	vstat->idle_clk += kstat.cpustat[CPUTIME_IDLE];

	vstat->uptime_clk = ve_get_uptime(ve);

	vstat->uptime_jif = (unsigned long)cputime64_to_clock_t(
				get_jiffies_64() - ve->start_jiffies);
	for (i = 0; i < 3; i++) {
		tmp = avenrun[i] + (FIXED_1/200);
		vstat->avenrun[i].val_int = LOAD_INT(tmp);
		vstat->avenrun[i].val_frac = LOAD_FRAC(tmp);
	}
	mutex_unlock(&ve_list_lock);

	retval = 0;
	if (copy_to_user(buf, vstat, sizeof(*vstat)))
		retval = -EFAULT;
out_free:
	kfree(vstat);
	return retval;

out_unlock:
	mutex_unlock(&ve_list_lock);
	goto out_free;
}

static int real_setdevperms(envid_t veid, unsigned type,
		dev_t dev, unsigned mask)
{
	struct ve_struct *ve;
	int err;

	if (!capable_setveid() || veid == 0)
		return -EPERM;

	if ((ve = get_ve_by_id(veid)) == NULL)
		return -ESRCH;

	down_read(&ve->op_sem);
	err = -ESRCH;
	if (ve->is_running)
		err = set_device_perms_ve(ve, type, dev, mask);
	up_read(&ve->op_sem);
	real_put_ve(ve);
	return err;
}

/**********************************************************************
 **********************************************************************
 *
 * VE start: subsystems
 *
 **********************************************************************
 **********************************************************************/

static void free_ve_filesystems(struct ve_struct *ve)
{
#if defined(CONFIG_FUSE_FS) || defined(CONFIG_FUSE_FS_MODULE)
	BUG_ON(ve->fuse_fs_type && !list_empty(&ve->_fuse_conn_list));
	kfree(ve->fuse_fs_type);
	ve->fuse_fs_type = NULL;

	kfree(ve->fuse_ctl_fs_type);
	ve->fuse_ctl_fs_type = NULL;
#endif

#if defined(CONFIG_BINFMT_MISC) || defined(CONFIG_BINFMT_MISC_MODULE)
	kfree(ve->bm_fs_type);
	ve->bm_fs_type = NULL;
#endif
}

static int init_printk(struct ve_struct *ve)
{
	int err;

	err = -ENOMEM;
	ve->log_wait = kmalloc(sizeof(*ve->log_wait), GFP_KERNEL);
	if (!ve->log_wait)
		return -ENOMEM;

	init_waitqueue_head(ve->log_wait);
	err = init_ve_log_state(ve);
	if (err) {
		kfree(ve->log_wait);
		return err;
	}

	/* ve->log_buf will be initialized later by ve_log_init() */
	return 0;
}

static void fini_printk(struct ve_struct *ve)
{
	/* 
	 * there is no spinlock protection here because nobody can use
	 * log_buf at the moments when this code is called. 
	 */
	kfree(ve->log_buf);
	kfree(ve->log_state);
	kfree(ve->log_wait);
}

static void fini_venet(struct ve_struct *ve)
{
#ifdef CONFIG_INET
	tcp_v4_kill_ve_sockets(ve);
	synchronize_net();
#endif
}

static int init_ve_sched(struct ve_struct *ve, unsigned int vcpus)
{
	int err;

	err = fairsched_new_node(ve->veid, vcpus);

	return err;
}

static void fini_ve_sched(struct ve_struct *ve, int leave)
{
	fairsched_drop_node(ve->veid, leave);
}

/*
 * Namespaces
 */

static inline int init_ve_namespaces(struct ve_struct *ve,
		struct nsproxy **old)
{
	int err;
	struct task_struct *tsk;
	struct nsproxy *cur;

	tsk = current;
	cur = tsk->nsproxy;

	err = copy_namespaces(CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID,
			tsk, 1);
	if (err < 0)
		return err;

	ve->ve_ns = get_nsproxy(tsk->nsproxy);
	memcpy(ve->ve_ns->uts_ns->name.release, virt_utsname.release,
			sizeof(virt_utsname.release));

	*old = cur;
	return 0;
}

static inline void fini_ve_namespaces(struct ve_struct *ve,
		struct nsproxy *old)
{
	struct task_struct *tsk = current;
	struct nsproxy *tmp;

	if (old) {
		tmp = tsk->nsproxy;
		tsk->nsproxy = get_nsproxy(old);
		put_nsproxy(tmp);
		tmp = ve->ve_ns;
		ve->ve_ns = get_nsproxy(old);
		put_nsproxy(tmp);
	} else {
		put_cred(ve->init_cred);
		put_nsproxy(ve->ve_ns);
		ve->ve_ns = NULL;
	}
}

static int init_ve_netns(struct ve_struct *ve, struct nsproxy **old)
{
	int err;
	struct task_struct *tsk;
	struct nsproxy *cur;

	tsk = current;
	cur = tsk->nsproxy;

	err = copy_namespaces(CLONE_NEWNET, tsk, 1);
	if (err < 0)
		return err;

	put_nsproxy(ve->ve_ns);
	ve->ve_ns = get_nsproxy(tsk->nsproxy);
	ve->ve_netns = get_net(ve->ve_ns->net_ns);
	*old = cur;
	return 0;
}

static void fini_ve_netns(struct ve_struct *ve)
{
	put_net(ve->ve_netns);
}

static inline void switch_ve_namespaces(struct ve_struct *ve,
		struct task_struct *tsk)
{
	struct nsproxy *old_ns;
	struct nsproxy *new_ns;

	BUG_ON(tsk != current);
	old_ns = tsk->nsproxy;
	new_ns = ve->ve_ns;

	if (old_ns != new_ns) {
		tsk->nsproxy = get_nsproxy(new_ns);
		put_nsproxy(old_ns);
	}
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

static int init_ve_struct(struct ve_struct *ve, envid_t veid,
		u32 class_id, env_create_param_t *data, int datalen)
{
	(void)get_ve(ve);
	ve->veid = veid;
	ve->class_id = class_id;
	ve->features = get_ve_features(data, datalen);
	init_rwsem(&ve->op_sem);

	ve->start_timespec = current->start_time;
	ve->real_start_timespec = current->real_start_time;
	/* The value is wrong, but it is never compared to process
	 * start times */
	ve->start_jiffies = get_jiffies_64();

	ve->_randomize_va_space = ve0._randomize_va_space;
	INIT_LIST_HEAD(&ve->devices);

	ve->odirect_enable = 2;

	mutex_init(&ve->sync_mutex);

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
	real_put_ve(ve);
	return 0;
#else
	return -ENOTTY;
#endif
}

static int init_ve_meminfo(struct ve_struct *ve)
{
	ve->meminfo_val = VE_MEMINFO_DEFAULT;
	return 0;
}

static inline void fini_ve_meminfo(struct ve_struct *ve)
{
}

static void set_ve_root(struct ve_struct *ve, struct task_struct *tsk)
{
	get_fs_root(tsk->fs, &ve->root_path);
	/* mark_tree_virtual(&ve->root_path); */
	//ub_dcache_set_owner(ve->root_path.dentry, get_exec_ub());
}

static void put_ve_root(struct ve_struct *ve)
{
	path_put(&ve->root_path);
}

static void set_ve_caps(struct ve_struct *ve, struct task_struct *tsk)
{
	/* required for real_setdevperms from register_ve_<fs> above */
	memcpy(&ve->ve_cap_bset, &tsk->cred->cap_effective, sizeof(kernel_cap_t));
}

static int ve_list_add(struct ve_struct *ve)
{
	mutex_lock(&ve_list_lock);
	if (__find_ve_by_id(ve->veid) != NULL)
		goto err_exists;

	list_add(&ve->ve_list, &ve_list_head);
	nr_ve++;
	mutex_unlock(&ve_list_lock);
	return 0;

err_exists:
	mutex_unlock(&ve_list_lock);
	return -EEXIST;
}

static void ve_list_del(struct ve_struct *ve)
{
	mutex_lock(&ve_list_lock);
	list_del(&ve->ve_list);
	nr_ve--;
	mutex_unlock(&ve_list_lock);
}

static void fixup_ve_admin_cap(kernel_cap_t *cap_set)
{
	if (cap_raised(*cap_set, CAP_VE_SYS_ADMIN))
		cap_raise(*cap_set, CAP_SYS_ADMIN);
	if (cap_raised(*cap_set, CAP_VE_NET_ADMIN))
		cap_raise(*cap_set, CAP_NET_ADMIN);
}

static void init_ve_cred(struct ve_struct *ve, struct cred *new)
{
	const struct cred *cur;
	kernel_cap_t bset;
	struct uid_gid_extent extent = {
		.first = 0,
		.lower_first = 0,
		.count = UINT_MAX,
	};

	bset = ve->ve_cap_bset;
	cur = current_cred();
	new->cap_effective = cap_intersect(cur->cap_effective, bset);
	new->cap_inheritable = cap_intersect(cur->cap_inheritable, bset);
	new->cap_permitted = cap_intersect(cur->cap_permitted, bset);
	new->cap_bset = cap_intersect(cur->cap_bset, bset);

	fixup_ve_admin_cap(&new->cap_effective);
	fixup_ve_admin_cap(&new->cap_inheritable);
	fixup_ve_admin_cap(&new->cap_permitted);
	fixup_ve_admin_cap(&new->cap_bset);

	new->user_ns->uid_map.nr_extents = 1;
	new->user_ns->uid_map.extent[0] = extent;
	new->user_ns->gid_map.nr_extents = 1;
	new->user_ns->gid_map.extent[0] = extent;

	ve->init_cred = new;
	ve->user_ns = new->user_ns;
}

static void ve_move_task(struct ve_struct *new)
{
	struct task_struct *tsk = current;

	might_sleep();
	BUG_ON(!(thread_group_leader(tsk) && thread_group_empty(tsk)));

	/* this probihibts ptracing of task entered to VE from host system */
	if (tsk->mm)
		tsk->mm->vps_dumpable = 0;

	/* setup capabilities before enter */
	if (commit_creds(get_new_cred(new->init_cred)))
		BUG();

	/* Drop OOM protection. */
	if (tsk->signal->oom_adj == OOM_DISABLE)
		tsk->signal->oom_adj = 0;

	/* Leave parent exec domain */
	tsk->parent_exec_id--;

	cgroup_kernel_attach(new->ve_cgroup, tsk);
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

static inline int init_ve_cpustats(struct ve_struct *ve)
{
	ve->sched_lat_ve.cur = alloc_percpu(struct kstat_lat_pcpu_snap_struct);
	if (ve->sched_lat_ve.cur == NULL)
		return -ENOMEM;
	return 0;
}

static inline void free_ve_cpustats(struct ve_struct *ve)
{
	free_percpu(ve->sched_lat_ve.cur);
	ve->sched_lat_ve.cur = NULL;
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

#ifdef CONFIG_CGROUP_DEVICE

static struct vfsmount *ve_cgroup_mnt;
static struct cgroup *ve_cgroup_root;

static int init_ve_cgroups(struct ve_struct *ve)
{
	char name[16];

	snprintf(name, sizeof(name), "%u", ve->veid);
	ve->ve_cgroup = cgroup_kernel_open(ve_cgroup_root,
			CGRP_CREAT|CGRP_WEAK, name);
	if (IS_ERR(ve->ve_cgroup))
		return PTR_ERR(ve->ve_cgroup);
	return 0;
}

static void fini_ve_cgroups(struct ve_struct *ve)
{
	cgroup_kernel_close(ve->ve_cgroup);
	ve->ve_cgroup = NULL;
}

static int __init init_vecalls_cgroups(void)
{
	struct cgroup_sb_opts opts = {
		.name		= "container",
		.subsys_bits	=
			(1ul << devices_subsys_id) |
			(1ul << freezer_subsys_id),
	};

	ve_cgroup_mnt = cgroup_kernel_mount(&opts);
	if (IS_ERR(ve_cgroup_mnt))
		return PTR_ERR(ve_cgroup_mnt);
	ve_cgroup_root = cgroup_get_root(ve_cgroup_mnt);
	get_ve0()->ve_cgroup = ve_cgroup_root;
	return 0;
}

static void fini_vecalls_cgroups(void)
{
	kern_unmount(ve_cgroup_mnt);
}
#else
static int init_ve_cgroups(struct ve_struct *ve) { }
static int fini_ve_cgroups(struct ve_struct *ve) { }
static int init_vecalls_cgroups(void) { return 0; }
static void fini_vecalls_cgroups(void) { ; }
#endif /* CONFIG_CGROUP_DEVICE */

static int do_env_create(envid_t veid, unsigned int flags, u32 class_id,
			 env_create_param_t *data, int datalen)
{
	struct task_struct *tsk = current;
	struct ve_struct *old_ve, *ve;
	struct cred *new_creds;
	__u64 init_mask;
	int err;
	struct nsproxy *old_ns, *old_ns_net;

	if (!thread_group_leader(tsk) || !thread_group_empty(tsk))
		return -EINVAL;

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


	VZTRACE("%s: veid=%d classid=%d pid=%d\n",
		__FUNCTION__, veid, class_id, current->pid);

	err = -ENOMEM;
	ve = kzalloc(sizeof(struct ve_struct), GFP_KERNEL);
	if (ve == NULL)
		goto err_struct;

	init_ve_struct(ve, veid, class_id, data, datalen);
	__module_get(THIS_MODULE);
	down_write(&ve->op_sem);
	if (flags & VE_LOCK)
		ve->is_locked = 1;

	/*
	 * this should be done before adding to list
	 * because if calc_load_ve finds this ve in
	 * list it will be very surprised
	 */
	if ((err = init_ve_cpustats(ve)) < 0)
		goto err_cpu_stats;

	if ((err = init_ve_cgroups(ve)))
		goto err_cgroup;

	if ((err = ve_list_add(ve)) < 0)
		goto err_exist;

	/* this should be done before context switching */
	if ((err = init_printk(ve)) < 0)
		goto err_log_wait;

	old_ve = tsk->task_ve;
	tsk->task_ve = ve;

	if ((err = init_ve_sched(ve, data->total_vcpus)) < 0)
		goto err_sched;

	set_ve_root(ve, tsk);

	if ((err = init_ve_namespaces(ve, &old_ns)))
		goto err_ns;

	init_mask = data ? data->iptables_mask : VE_IP_DEFAULT;

#ifdef CONFIG_VE_IPTABLES
	/* Set up ipt_mask as it will be used during
	 * net namespace initialization
	 */
	init_mask = setup_iptables_mask(init_mask);
	ve->ipt_mask = init_mask;
#endif

	if ((err = init_ve_netns(ve, &old_ns_net)))
		goto err_netns;

	if((err = init_ve_meminfo(ve)))
		goto err_meminf;

	set_ve_caps(ve, tsk);

	if ((err = change_active_pid_ns(tsk, ve->ve_ns->pid_ns)) < 0)
		goto err_vpid;

	err = -ENOMEM;
	new_creds = prepare_creds();
	if (new_creds == NULL)
		goto err_creds;

	if ((err = create_user_ns(new_creds)) < 0)
		goto err_uns;

	init_ve_cred(ve, new_creds);

	ve_move_task(ve);

	if ((err = ve_hook_iterate_init(VE_SS_CHAIN, ve)) < 0)
		goto err_ve_hook;

	put_nsproxy(old_ns);
	put_nsproxy(old_ns_net);

	ve->ve_init_task = tsk;
	tsk->nsproxy->pid_ns->notify_ve = ve;

	ve->is_running = 1;
	up_write(&ve->op_sem);

	printk(KERN_INFO "CT: %d: started\n", veid);
	return veid;

err_ve_hook:
	ve_move_task(old_ve);
	/* creds will put user and user ns */
err_uns:
	put_cred(new_creds);
err_creds:
err_vpid:
	fini_venet(ve);
	fini_ve_meminfo(ve);
err_meminf:
	fini_ve_namespaces(ve, old_ns_net);
	put_nsproxy(old_ns_net);
	fini_ve_netns(ve);
err_netns:
	/*
	 * If process hasn't become VE's init, proc_mnt won't be put during
	 * pidns death, so this mntput by hand is needed. If it has, we
	 * compensate with mntget above.
	 */
	/* free_ve_utsname() is called inside real_put_ve() */
	fini_ve_namespaces(ve, old_ns);
	put_nsproxy(old_ns);
	/*
	 * We need to compensate, because fini_ve_namespaces() assumes
	 * ve->ve_ns will continue to be used after, but VE will be freed soon
	 * (in kfree() sense).
	 */
	put_nsproxy(ve->ve_ns);
err_ns:
	put_ve_root(ve);

	fini_ve_sched(ve, 1);
err_sched:
	tsk->task_ve = old_ve;

	/* we can jump here having incorrect envid */
	fini_printk(ve);
err_log_wait:
	/* cpustats will be freed in do_env_free */
	ve_list_del(ve);
	up_write(&ve->op_sem);

	real_put_ve(ve);
err_struct:
	printk(KERN_INFO "CT: %d: failed to start with err=%d\n", veid, err);
	return err;

err_exist:
	fini_ve_cgroups(ve);
err_cgroup:
	free_ve_cpustats(ve);
err_cpu_stats:
	kfree(ve);
	module_put(THIS_MODULE);
	goto err_struct;
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
	real_put_ve(ve);
out:
	return status;
}
EXPORT_SYMBOL(real_env_create);

static int do_env_enter(struct ve_struct *ve, unsigned int flags)
{
	struct task_struct *tsk = current;
	int err;

	VZTRACE("%s: veid=%d\n", __FUNCTION__, ve->veid);

	err = -EBUSY;
	down_read(&ve->op_sem);
	if (!ve->is_running)
		goto out_up;
	if (ve->is_locked && !(flags & VE_SKIPLOCK))
		goto out_up;
	err = -EINVAL;
	if (!thread_group_leader(tsk) || !thread_group_empty(tsk))
		goto out_up;

#ifdef CONFIG_VZ_FAIRSCHED
	err = fairsched_move_task(ve->veid, current);
	if (err)
		goto out_up;
#endif
	switch_ve_namespaces(ve, tsk);
	tsk->task_ve = ve;
	ve_move_task(ve);

	if (alone_in_pgrp(tsk) && !(flags & VE_SKIPLOCK))
		change_active_pid_ns(tsk, ve->ve_ns->pid_ns);

	/* Unlike VE_CREATE, we do not setsid() in VE_ENTER.
	 * Process is allowed to be in an external group/session.
	 * If user space callers wants, it will do setsid() after
	 * VE_ENTER.
	 */
	err = task_veid(tsk);
	tsk->did_ve_enter = 1;

out_up:
	up_read(&ve->op_sem);
	return err;
}

static void env_cleanup(struct ve_struct *ve)
{
	VZTRACE("real_do_env_cleanup\n");

	down_read(&ve->op_sem);

	fini_venet(ve);

	/* no new packets in flight beyond this point */

	fini_ve_sched(ve, 0);

	if (ve->devpts_sb)
		deactivate_super(ve->devpts_sb);

	fini_ve_meminfo(ve);

	fini_ve_namespaces(ve, NULL);
	fini_ve_netns(ve);

	put_ve_root(ve);

	fini_printk(ve);	/* no printk can happen in ve context anymore */

	ve_list_del(ve);
	up_read(&ve->op_sem);

	real_put_ve(ve);
}

static LIST_HEAD(ve_cleanup_list);
static DEFINE_SPINLOCK(ve_cleanup_lock);
static struct task_struct *ve_cleanup_thread;
static DECLARE_COMPLETION(vzmond_complete);
static int vzmond_helper(void *arg)
{
	char name[18];
	struct ve_struct *ve;

	ve = (struct ve_struct *)arg;
	snprintf(name, sizeof(name), "vzmond/%d", ve->veid);
	daemonize(name);
	env_cleanup(ve);
	module_put_and_exit(0);
}

static void do_pending_env_cleanups(void)
{
	int err;
	struct ve_struct *ve;

	spin_lock(&ve_cleanup_lock);
	while (1) {
		if (list_empty(&ve_cleanup_list) || need_resched())
			break;

		ve = list_first_entry(&ve_cleanup_list,
				struct ve_struct, cleanup_list);
		list_del(&ve->cleanup_list);
		spin_unlock(&ve_cleanup_lock);

		__module_get(THIS_MODULE);
		err = kernel_thread(vzmond_helper, (void *)ve, 0);
		if (err < 0) {
			env_cleanup(ve);
			module_put(THIS_MODULE);
		}

		spin_lock(&ve_cleanup_lock);
	}
	spin_unlock(&ve_cleanup_lock);
}

static inline int have_pending_cleanups(void)
{
	return !list_empty(&ve_cleanup_list);
}

static int vzmond(void *arg)
{
	set_current_state(TASK_INTERRUPTIBLE);

	while (!kthread_should_stop() || have_pending_cleanups()) {
		schedule();
		try_to_freeze();
		if (signal_pending(current))
			flush_signals(current);

		do_pending_env_cleanups();
		set_current_state(TASK_INTERRUPTIBLE);
		if (have_pending_cleanups())
			__set_current_state(TASK_RUNNING);
	}

	__set_task_state(current, TASK_RUNNING);
	complete_and_exit(&vzmond_complete, 0);
}

static int __init init_vzmond(void)
{
	ve_cleanup_thread = kthread_run(vzmond, NULL, "vzmond");
	if (IS_ERR(ve_cleanup_thread))
		return PTR_ERR(ve_cleanup_thread);
	else
		return 0;
}

static void fini_vzmond(void)
{
	kthread_stop(ve_cleanup_thread);
	WARN_ON(!list_empty(&ve_cleanup_list));
}

static void real_do_env_free(struct ve_struct *ve)
{
	VZTRACE("real_do_env_free\n");

	fini_ve_cgroups(ve);
	free_ve_filesystems(ve);
	free_ve_cpustats(ve);
	printk(KERN_INFO "CT: %d: stopped\n", VEID(ve));
	kfree(ve);

	module_put(THIS_MODULE);
}

static void vzmon_kill_notifier(void *data)
{
	struct ve_struct *ve = data;

	/*
	 * Here the VE changes its state into "not running".
	 * op_sem taken for write is a barrier to all VE manipulations from
	 * ioctl: it waits for operations currently in progress and blocks all
	 * subsequent operations until is_running is set to 0 and op_sem is
	 * released.
	 */

	ve->is_running = 0;
	ve->ve_init_task = NULL;
}

static void vzmon_stop_notifier(void *data)
{
	struct ve_struct *ve = data;

	spin_lock(&ve_cleanup_lock);
	list_add_tail(&ve->cleanup_list, &ve_cleanup_list);
	spin_unlock(&ve_cleanup_lock);
	wake_up_process(ve_cleanup_thread);
}

static struct ve_hook vzmon_kill_hook = {
	.fini		= vzmon_kill_notifier,
	.priority	= HOOK_PRIO_FINISHING,
	.owner		= THIS_MODULE,
};

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
	real_put_ve(dst_ve);

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
	real_put_ve(src_ve);

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
#define VESTAT_LINE_FMT "%10u %10lu %10lu %10lu %10Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %10lu\n"
#define VESTAT_HEAD_FMT "%10s %10s %10s %10s %10s %20s %20s %20s %20s %20s %20s %10s\n"
#else
#define VESTAT_LINE_WIDTH (12 * 21)
#define VESTAT_LINE_FMT "%20u %20lu %20lu %20lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20lu\n"
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

	ret = fairsched_get_cpu_stat(ve->veid, &kstat);
	if (ret)
		return ret;

	strv_time = 0;
	user_ve = kstat.cpustat[CPUTIME_USER];
	nice_ve = kstat.cpustat[CPUTIME_NICE];
	system_ve = kstat.cpustat[CPUTIME_SYSTEM];
	used = kstat.cpustat[CPUTIME_USED];
	idle_time = kstat.cpustat[CPUTIME_IDLE];

	uptime_cycles = ve_get_uptime(ve);
	uptime = get_jiffies_64() - ve->start_jiffies;

	seq_printf(m, VESTAT_LINE_FMT, ve->veid,
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
		return curve;
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

	seq_printf(m, "%10u %5u %5u", ve->veid, ve->class_id, nr_threads_ve(ve));

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

	real_put_ve(ve);
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

#ifdef CONFIG_SYSCTL
static struct ctl_table_header *table_header;

static ctl_table kernel_table[] = {
	{
		.procname	= "ve_allow_kthreads",
		.data		= &ve_allow_kthreads,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{ 0 }
};

static ctl_table root_table[] =  {
	{"kernel",  NULL, 0, 0555, kernel_table},
	{ 0 }
};

static int init_vecalls_sysctl(void)
{
	table_header = register_sysctl_table(root_table);
	if (!table_header)
		return -ENOMEM ;
	return 0;
}

static void fini_vecalls_sysctl(void)
{
	unregister_sysctl_table(table_header);
} 
#else
static int init_vecalls_sysctl(void) { return 0; }
static void fini_vecalls_sysctl(void) { ; }
#endif

static int __init vecalls_init(void)
{
	int err;

	ve_hook_register(VE_KILL_CHAIN, &vzmon_kill_hook);
	ve_hook_register(VE_SS_CHAIN, &vzmon_stop_hook);

	err = init_vecalls_cgroups();
	if (err)
		goto out_cgroups;

	err = init_vecalls_sysctl();
	if (err)
		goto out_vzmond;

	err = init_vzmond();
	if (err < 0)
		goto out_sysctl;

	err = init_vecalls_proc();
	if (err < 0)
		goto out_proc;

	err = init_vecalls_ioctls();
	if (err < 0)
		goto out_ioctls;

	/* We can easy dereference this hook if VE is running
	 * because in this case vzmon refcount > 0
	 */
	do_ve_enter_hook = do_env_enter;
	/*
	 * This one can also be dereferenced since not freed
	 * VE holds reference on module
	 */
	do_env_free_hook = real_do_env_free;

	return 0;

out_ioctls:
	fini_vecalls_proc();
out_proc:
	fini_vzmond();
out_sysctl:
	fini_vecalls_sysctl();
out_vzmond:
	fini_vecalls_cgroups();
out_cgroups:
	ve_hook_unregister(&vzmon_kill_hook);
	ve_hook_unregister(&vzmon_stop_hook);

	return err;
}

static void __exit vecalls_exit(void)
{
	do_env_free_hook = NULL;
	do_ve_enter_hook = NULL;
	fini_vecalls_ioctls();
	fini_vecalls_proc();
	fini_vzmond();
	fini_vecalls_sysctl();
	fini_vecalls_cgroups();
	ve_hook_unregister(&vzmon_kill_hook);
	ve_hook_unregister(&vzmon_stop_hook);
}

MODULE_AUTHOR("SWsoft <info@sw-soft.com>");
MODULE_DESCRIPTION("Virtuozzo Control");
MODULE_LICENSE("GPL v2");

module_init(vecalls_init)
module_exit(vecalls_exit)
