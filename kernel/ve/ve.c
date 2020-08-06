/*
 *  kernel/ve/ve.c
 *
 *  Copyright (c) 2000-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

/*
 * 've.c' helper file performing VE sub-system initialization
 */

#include <linux/delay.h>
#include <linux/capability.h>
#include <linux/ve.h>
#include <linux/init.h>

#include <linux/aio.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/sys.h>
#include <linux/kdev_t.h>
#include <linux/termios.h>
#include <linux/netdevice.h>
#include <linux/utsname.h>
#include <linux/proc_fs.h>
#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/ve_proto.h>
#include <linux/devpts_fs.h>
#include <linux/user_namespace.h>
#include <linux/init_task.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/fs_struct.h>
#include <linux/task_work.h>
#include <linux/ctype.h>
#include <linux/tty.h>
#include <linux/kmapset.h>

#include <uapi/linux/vzcalluser.h>
#include <linux/vziptable_defs.h>
#include <net/rtnetlink.h>

extern struct kmapset_set sysfs_ve_perms_set;

static struct kmem_cache *ve_cachep;

unsigned long vz_rstamp = 0x37e0f59d;
EXPORT_SYMBOL(vz_rstamp);

#ifdef CONFIG_MODULES
struct module no_module = { .state = MODULE_STATE_GOING };
EXPORT_SYMBOL(no_module);
#endif

static DEFINE_PER_CPU(struct kstat_lat_pcpu_snap_struct, ve0_lat_stats);

struct ve_struct ve0 = {
	.ve_name		= "0",
	.start_jiffies		= INITIAL_JIFFIES,
	RCU_POINTER_INITIALIZER(ve_ns, &init_nsproxy),
	.ve_netns		= &init_net,
	.is_running		= 1,
	.is_pseudosuper		= 1,
#ifdef CONFIG_VE_IPTABLES
	.ipt_mask		= VE_IP_ALL,	/* everything is allowed */
#endif
	.features		= -1,
	.fsync_enable		= FSYNC_FILTERED,
	.meminfo_val		= VE_MEMINFO_SYSTEM,
	._randomize_va_space	=
#ifdef CONFIG_COMPAT_BRK
					1,
#else
					2,
#endif
	.sched_lat_ve.cur	= &ve0_lat_stats,
	.init_cred		= &init_cred,
	.mnt_nr			= ATOMIC_INIT(0),
	.netns_avail_nr		= ATOMIC_INIT(INT_MAX),
	.netns_max_nr		= INT_MAX,
	.netif_avail_nr		= ATOMIC_INIT(INT_MAX),
	.netif_max_nr		= INT_MAX,
	.arp_neigh_nr		= ATOMIC_INIT(0),
	.nd_neigh_nr		= ATOMIC_INIT(0),
};
EXPORT_SYMBOL(ve0);

LIST_HEAD(ve_list_head);
DEFINE_MUTEX(ve_list_lock);

int nr_ve = 1;	/* One VE always exists. Compatibility with vestat */
EXPORT_SYMBOL(nr_ve);

static DEFINE_IDR(ve_idr);

struct ve_struct *get_ve(struct ve_struct *ve)
{
	if (ve)
		css_get(&ve->css);
	return ve;
}
EXPORT_SYMBOL(get_ve);

void put_ve(struct ve_struct *ve)
{
	if (ve)
		css_put(&ve->css);
}
EXPORT_SYMBOL(put_ve);

struct cgroup_subsys_state *ve_get_init_css(struct ve_struct *ve, int subsys_id)
{
	struct cgroup_subsys_state *css, *tmp;
	struct task_struct *task;
	struct cgroup *cgroup;

	rcu_read_lock();
	task = ve->ve_ns ? ve->init_task : &init_task;
	while (true) {
		css = task_subsys_state(task, subsys_id);
		if (likely(css_tryget(css)))
			break;
		cpu_relax();
	}

	cgroup = css->cgroup;
	while (!test_bit(CGRP_VE_ROOT, &cgroup->flags) && cgroup->parent)
		cgroup = cgroup->parent;

	if (cgroup != css->cgroup) {
		tmp = cgroup->subsys[subsys_id];
		css_get(tmp);
		css_put(css);
		css = tmp;
	}

	rcu_read_unlock();
	return css;
}

static int ve_list_add(struct ve_struct *ve)
{
	int err;

	mutex_lock(&ve_list_lock);
	err = idr_alloc(&ve_idr, ve, ve->veid, ve->veid + 1, GFP_KERNEL);
	if (err < 0) {
		if (err == -ENOSPC)
			err = -EEXIST;
		goto out;
	}
	list_add(&ve->ve_list, &ve_list_head);
	nr_ve++;
	err = 0;
out:
	mutex_unlock(&ve_list_lock);
	return err;
}

static void ve_list_del(struct ve_struct *ve)
{
	mutex_lock(&ve_list_lock);
	idr_remove(&ve_idr, ve->veid);
	list_del_init(&ve->ve_list);
	nr_ve--;
	mutex_unlock(&ve_list_lock);
}

/* caller provides refrence to ve-struct */
const char *ve_name(struct ve_struct *ve)
{
	return ve->ve_name;
}
EXPORT_SYMBOL(ve_name);

/* under rcu_read_lock if task != current */
const char *task_ve_name(struct task_struct *task)
{
	return rcu_dereference_check(task->task_ve, task == current)->ve_name;
}
EXPORT_SYMBOL(task_ve_name);

struct ve_struct *get_ve_by_id(envid_t veid)
{
	struct ve_struct *ve;
	rcu_read_lock();
	ve = idr_find(&ve_idr, veid);
	if (ve && !css_tryget(&ve->css))
		ve = NULL;
	rcu_read_unlock();
	return ve;
}
EXPORT_SYMBOL(get_ve_by_id);

EXPORT_SYMBOL(ve_list_lock);
EXPORT_SYMBOL(ve_list_head);

int vz_security_family_check(struct net *net, int family, int type)
{
	if (ve_is_super(net->owner_ve))
		return 0;

	switch (family) {
	case PF_UNSPEC:
	case PF_PACKET:
	case PF_NETLINK:
	case PF_UNIX:
	case PF_INET:
	case PF_INET6:
	case PF_PPPOX:
	case PF_KEY:
		return 0;
	case PF_BRIDGE:
		if (type)
			switch (type) {
				case RTM_NEWNEIGH:
				case RTM_DELNEIGH:
				case RTM_GETNEIGH:
				case RTM_GETLINK:
				case RTM_DELLINK:
				case RTM_SETLINK:
					return 0;
			}
	default:
		return -EAFNOSUPPORT;
	}
}
EXPORT_SYMBOL_GPL(vz_security_family_check);

int vz_security_protocol_check(struct net *net, int protocol)
{
	if (ve_is_super(net->owner_ve))
		return 0;

	switch (protocol) {
	case  IPPROTO_IP:
	case  IPPROTO_ICMP:
	case  IPPROTO_TCP:
	case  IPPROTO_UDP:
	case  IPPROTO_RAW:
	case  IPPROTO_DCCP:
	case  IPPROTO_GRE:
	case  IPPROTO_ESP:
	case  IPPROTO_AH:
	case  IPPROTO_SCTP:
		return 0;
	default:
		return -EAFNOSUPPORT;
	}
}
EXPORT_SYMBOL_GPL(vz_security_protocol_check);

/* Check if current user_ns is initial for current ve */
bool current_user_ns_initial(void)
{
	struct ve_struct *ve = get_exec_env();
	bool ret = false;

	if (current_user_ns() == &init_user_ns)
		return true;

	rcu_read_lock();
	if (ve->ve_ns && ve->init_cred->user_ns == current_user_ns())
		ret = true;
	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL(current_user_ns_initial);

struct user_namespace *ve_init_user_ns(void)
{
	struct cred *init_cred;

	init_cred = get_exec_env()->init_cred;
	return init_cred ? init_cred->user_ns : &init_user_ns;
}
EXPORT_SYMBOL(ve_init_user_ns);

int ve_net_hide_sysctl(struct net *net)
{
	/*
	 * This can happen only on VE creation, when process created VE cgroup,
	 * and clones a child with new network namespace.
	 */
	if (net->owner_ve->init_cred == NULL)
		return 0;

	/*
	 * Expose sysctl only for container's init user namespace
	 */
	return net->user_ns != net->owner_ve->init_cred->user_ns;
}
EXPORT_SYMBOL(ve_net_hide_sysctl);

int nr_threads_ve(struct ve_struct *ve)
{
	return cgroup_task_count(ve->css.cgroup);
}
EXPORT_SYMBOL(nr_threads_ve);

struct kthread_attach_work {
	struct kthread_work work;
	struct completion done;
	struct task_struct *target;
	int result;
};

static void kthread_attach_fn(struct kthread_work *w)
{
	struct kthread_attach_work *work = container_of(w,
			struct kthread_attach_work, work);
	struct task_struct *target = work->target;
	struct cred *cred;
	int err;

	switch_task_namespaces(current, get_nsproxy(target->nsproxy));

	err = unshare_fs_struct();
	if (err)
		goto out;
	set_fs_root(current->fs, &target->fs->root);
	set_fs_pwd(current->fs, &target->fs->root);

	err = -ENOMEM;
	cred = prepare_kernel_cred(target);
	if (!cred)
		goto out;
	err = commit_creds(cred);
	if (err)
		goto out;

	err = change_active_pid_ns(current, task_active_pid_ns(target));
	if (err)
		goto out;

	err = cgroup_attach_task_all(target, current);
	if (err)
		goto out;
out:
	work->result = err;
	complete(&work->done);
}

struct kthread_create_work {
	struct kthread_work work;
	struct kthread_create_info *info;
};

extern void create_kthread(struct kthread_create_info *create);

static void kthread_create_fn(struct kthread_work *w)
{
	struct kthread_create_work *work = container_of(w,
			struct kthread_create_work, work);

	create_kthread(work->info);
}

static void kthread_create_queue(void *data, struct kthread_create_info *info)
{
	struct ve_struct *ve = data;
	struct kthread_create_work create = {
		KTHREAD_WORK_INIT(create.work, kthread_create_fn),
		.info = info,
	};
	queue_kthread_work(&ve->ve_kthread_worker, &create.work);
	wait_for_completion(&info->done);
}

struct task_struct *kthread_create_on_node_ve(struct ve_struct *ve,
					int (*threadfn)(void *data),
					void *data, int node,
					const char namefmt[], ...)
{
	va_list args;
	struct task_struct *task;
	void (*queue)(void *data, struct kthread_create_info *info) = NULL;

	if (!ve_is_super(ve))
		queue = kthread_create_queue;

	va_start(args, namefmt);
	task = __kthread_create_on_node(queue, ve, threadfn, data,
					node, namefmt, args);
	va_end(args);
	return task;
}
EXPORT_SYMBOL(kthread_create_on_node_ve);

static int ve_start_umh(struct ve_struct *ve)
{
	struct task_struct *t;

	init_kthread_worker(&ve->ve_umh_worker);
	t = kthread_run_ve(ve, kthread_worker_fn, &ve->ve_umh_worker,
			"khelper");
	if (IS_ERR(t))
		return PTR_ERR(t);

	ve->ve_umh_task = t;
	return 0;
}

static void ve_stop_umh(struct ve_struct *ve)
{
	flush_kthread_worker(&ve->ve_umh_worker);
	kthread_stop(ve->ve_umh_task);
	ve->ve_umh_task = NULL;
}

static int ve_start_kthread(struct ve_struct *ve)
{
	struct task_struct *t;
	struct kthread_attach_work attach = {
		KTHREAD_WORK_INIT(attach.work, kthread_attach_fn),
		COMPLETION_INITIALIZER_ONSTACK(attach.done),
		.target = current,
	};

	init_kthread_worker(&ve->ve_kthread_worker);
	t = kthread_run(kthread_worker_fn, &ve->ve_kthread_worker,
			"kthreadd/%s", ve_name(ve));
	if (IS_ERR(t))
		return PTR_ERR(t);

	queue_kthread_work(&ve->ve_kthread_worker, &attach.work);
	wait_for_completion(&attach.done);
	if (attach.result) {
		kthread_stop(t);
		return attach.result;
	}

	ve->ve_kthread_task = t;
	return 0;
}

static void ve_stop_kthread(struct ve_struct *ve)
{
	flush_kthread_worker(&ve->ve_kthread_worker);
	kthread_stop(ve->ve_kthread_task);
	ve->ve_kthread_task = NULL;
}

static void ve_grab_context(struct ve_struct *ve)
{
	struct task_struct *tsk = current;

	get_task_struct(tsk);
	ve->init_task = tsk;
	ve->root_css_set = tsk->cgroups;
	get_css_set(ve->root_css_set);
	ve->init_cred = (struct cred *)get_current_cred();
	rcu_assign_pointer(ve->ve_ns, get_nsproxy(tsk->nsproxy));
	ve->ve_netns =  get_net(ve->ve_ns->net_ns);
	synchronize_rcu();
}

static void ve_drop_context(struct ve_struct *ve)
{
	struct nsproxy *ve_ns = ve->ve_ns;
	struct net *net = ve->ve_netns;

	put_css_set_taskexit(ve->root_css_set);
	ve->root_css_set = NULL;

	ve->ve_netns = NULL;
	put_net(net);

	/* Allows to dereference init_cred and init_task if ve_ns is set */
	rcu_assign_pointer(ve->ve_ns, NULL);
	synchronize_rcu();
	put_nsproxy(ve_ns);

	ve_hook_iterate_fini(VE_SHUTDOWN_CHAIN, ve);

	put_cred(ve->init_cred);
	ve->init_cred = NULL;

	put_task_struct(ve->init_task);
	ve->init_task = NULL;
}

static const struct timespec zero_time = { };

static int ve_workqueue_start(struct ve_struct *ve)
{
	ve->wq = alloc_workqueue("ve_wq_%s",
		WQ_SYSFS|WQ_FREEZABLE|WQ_UNBOUND, 8, ve->ve_name);

	if (!ve->wq)
		return -ENOMEM;
	return 0;
}

static void ve_workqueue_stop(struct ve_struct *ve)
{
	destroy_workqueue(ve->wq);
}

/* under ve->op_sem write-lock */
static int ve_start_container(struct ve_struct *ve)
{
	struct task_struct *tsk = current;
	int err;

	if (!ve->veid)
		return -ENOENT;

	if (ve->is_running || ve->ve_ns)
		return -EBUSY;

	if (tsk->task_ve != ve || !is_child_reaper(task_pid(tsk)))
		return -ECHILD;

	/*
	 * Setup uptime for new containers only, if restored
	 * the velue won't be zero here already but setup from
	 * cgroup write while resuming the container.
	 */
	if (timespec_equal(&ve->start_timespec, &zero_time)) {
		ve->start_timespec = tsk->start_time;
		ve->real_start_timespec = tsk->real_start_time;
	}

	/* The value is wrong, but it is never compared to process
	 * start times */
	ve->start_jiffies = get_jiffies_64();

	ve_grab_context(ve);

	err = ve_list_add(ve);
	if (err)
		goto err_list;

	err = ve_start_kthread(ve);
	if (err)
		goto err_kthread;

	err = ve_start_umh(ve);
	if (err)
		goto err_umh;

	err = ve_workqueue_start(ve);
	if (err)
		goto err_workqueue;

	err = ve_hook_iterate_init(VE_SS_CHAIN, ve);
	if (err < 0)
		goto err_iterate;

	cgroup_mark_ve_roots(ve);

	ve->is_running = 1;

	printk(KERN_INFO "CT: %s: started\n", ve_name(ve));

	get_ve(ve); /* for ve_exit_ns() */

	return 0;

err_iterate:
	ve_workqueue_stop(ve);
err_workqueue:
	ve_stop_umh(ve);
err_umh:
	ve_stop_kthread(ve);
err_kthread:
	ve_list_del(ve);
err_list:
	ve_drop_context(ve);
	return err;
}

void ve_stop_ns(struct pid_namespace *pid_ns)
{
	struct ve_struct *ve = current->task_ve;

	/*
	 * current->cgroups already switched to init_css_set in cgroup_exit(),
	 * but current->task_ve still points to our exec ve.
	 */
	if (!ve->ve_ns || ve->ve_ns->pid_ns != pid_ns)
		return;

	wait_khelpers();

	down_write(&ve->op_sem);
	/*
	 * Here the VE changes its state into "not running".
	 * op_sem works as barrier for vzctl ioctls.
	 * ve_mutex works as barrier for ve_can_attach().
	 */
	ve->is_running = 0;

	/*
	 * Neither it can be in pseudosuper state
	 * anymore, setup it again if needed.
	 */
	ve->is_pseudosuper = 0;

	ve_stop_umh(ve);
	/*
	 * Stop kernel thread, or zap_pid_ns_processes() would wait it forever.
	 */
	ve_stop_kthread(ve);
	up_write(&ve->op_sem);
}

void ve_exit_ns(struct pid_namespace *pid_ns)
{
	struct ve_struct *ve = current->task_ve;

	/*
	 * current->cgroups already switched to init_css_set in cgroup_exit(),
	 * but current->task_ve still points to our exec ve.
	 */
	if (!ve->ve_ns || ve->ve_ns->pid_ns != pid_ns)
		return;

	cgroup_unmark_ve_roots(ve);

	ve_workqueue_stop(ve);

	/*
	 * At this point all userspace tasks in container are dead.
	 */

	if (ve->dev_sb) {
		deactivate_super(ve->dev_sb);
		ve->dev_sb = NULL;
	}
	if (ve->devpts_sb) {
		deactivate_super(ve->devpts_sb);
		ve->devpts_sb = NULL;
	}

	down_write(&ve->op_sem);
	ve_hook_iterate_fini(VE_SS_CHAIN, ve);

	ve_list_del(ve);
	ve_drop_context(ve);
	up_write(&ve->op_sem);

	printk(KERN_INFO "CT: %s: stopped\n", ve_name(ve));

	put_ve(ve); /* from ve_start_container() */
}

#ifdef CONFIG_VE_IPTABLES
static __u64 ve_setup_iptables_mask(__u64 init_mask)
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

static struct cgroup_subsys_state *ve_create(struct cgroup *cg)
{
	struct ve_struct *ve = &ve0;
	int err;

	if (!cg->parent)
		goto do_init;

	/* forbid nested containers */
	if (cgroup_ve(cg->parent) != ve)
		return ERR_PTR(-ENOTDIR);

	err = -ENOMEM;
	ve = kmem_cache_zalloc(ve_cachep, GFP_KERNEL);
	if (!ve)
		goto err_ve;

	ve->ve_name = kstrdup(cg->dentry->d_name.name, GFP_KERNEL);
	if (!ve->ve_name)
		goto err_name;

	ve->_randomize_va_space = ve0._randomize_va_space;

	ve->features = VE_FEATURES_DEF;

	ve->odirect_enable = 2;
	ve->fsync_enable = 2;

#ifdef CONFIG_VE_IPTABLES
	ve->ipt_mask = ve_setup_iptables_mask(VE_IP_DEFAULT);
#endif

	ve->sched_lat_ve.cur = alloc_percpu(struct kstat_lat_pcpu_snap_struct);
	if (!ve->sched_lat_ve.cur)
		goto err_lat;

	err = ve_log_init(ve);
	if (err)
		goto err_log;

	ve->meminfo_val = VE_MEMINFO_DEFAULT;

	atomic_set(&ve->netns_avail_nr, NETNS_MAX_NR_DEFAULT);
	ve->netns_max_nr = NETNS_MAX_NR_DEFAULT;

	atomic_set(&ve->netif_avail_nr, NETIF_MAX_NR_DEFAULT);
	ve->netif_max_nr = NETIF_MAX_NR_DEFAULT;

	atomic_set(&ve->arp_neigh_nr, 0);
	atomic_set(&ve->nd_neigh_nr, 0);
do_init:
	init_rwsem(&ve->op_sem);
	INIT_LIST_HEAD(&ve->devices);
	INIT_LIST_HEAD(&ve->ve_list);
	INIT_LIST_HEAD(&ve->devmnt_list);
	mutex_init(&ve->devmnt_mutex);

#ifdef CONFIG_AIO
	spin_lock_init(&ve->aio_nr_lock);
	ve->aio_nr = 0;
	ve->aio_max_nr = AIO_MAX_NR_DEFAULT;
#endif
	atomic_set(&ve->mnt_nr, 0);

#ifdef CONFIG_COREDUMP
	strcpy(ve->core_pattern, "core");
#endif
	kmapset_init_key(&ve->sysfs_perms_key);
	return &ve->css;

err_log:
	free_percpu(ve->sched_lat_ve.cur);
err_lat:
	kfree(ve->ve_name);
err_name:
	kmem_cache_free(ve_cachep, ve);
err_ve:
	return ERR_PTR(err);
}

static void ve_devmnt_free(struct ve_devmnt *devmnt)
{
	if (!devmnt)
		return;

	kfree(devmnt->allowed_options);
	kfree(devmnt->hidden_options);
	kfree(devmnt);
}

static void free_ve_devmnts(struct ve_struct *ve)
{
	while (!list_empty(&ve->devmnt_list)) {
		struct ve_devmnt *devmnt;

		devmnt = list_first_entry(&ve->devmnt_list, struct ve_devmnt, link);
		list_del(&devmnt->link);
		ve_devmnt_free(devmnt);
	}
}

static bool ve_task_can_attach(struct cgroup *cg, struct cgroup_taskset *tset)
{
	struct task_struct *task = cgroup_taskset_first(tset);

	if (cgroup_taskset_size(tset) > 1) {
		pr_err_ratelimited("ve_cgroup#%s: attach of a thread group is not supported\n",
				cg->name->name);
		return false;
	}
	if (!thread_group_leader(task)) {
		pr_err_ratelimited("ve_cgroup#%s: only thread group leader is allowed to attach\n",
				cg->name->name);
		return false;
	}
	if (!thread_group_empty(task)) {
		pr_err_ratelimited("ve_cgroup#%s: only single-threaded process is allowed to attach\n",
				cg->name->name);
		return false;
	}
	return true;
}

static int ve_is_attachable(struct cgroup *cg, struct cgroup_taskset *tset)
{
	struct task_struct *task = cgroup_taskset_first(tset);
	struct ve_struct *ve = cgroup_ve(cg);

	if (ve->is_running)
		return 0;

	if (!ve->veid) {
		pr_err_ratelimited("ve_cgroup#%s: container's veid is not set\n",
				cg->name->name);
		return -EINVAL;
	}

	if (task->flags & PF_KTHREAD) {
		/* Paranoia check: allow to attach kthread only, if cgroup is
		 * not empty.
		 * This check is required for kthreadd, which is created on CT
		 * start.
		 */
		if (nr_threads_ve(ve))
			return 0;
		pr_err_ratelimited("ve_cgroup#%s: can't attach kthread - empty group\n",
				cg->name->name);
	} else {
		/* In case of generic task only one is allowed to enter to
		 * non-running container: init.
		 */
		if (nr_threads_ve(ve) == 0)
			return 0;
		pr_err_ratelimited("ve_cgroup#%s: can't attach more than 1 task to "
				"non-running container\n",
				cg->name->name);
	}
	return -EINVAL;
}

static void ve_destroy(struct cgroup *cg)
{
	struct ve_struct *ve = cgroup_ve(cg);

	kmapset_unlink(&ve->sysfs_perms_key, &sysfs_ve_perms_set);
	free_ve_devmnts(ve);
	ve_log_destroy(ve);
#if IS_ENABLED(CONFIG_BINFMT_MISC)
	kfree(ve->binfmt_misc);
#endif
	free_percpu(ve->sched_lat_ve.cur);
	kfree(ve->ve_name);
	kmem_cache_free(ve_cachep, ve);
}

static int ve_can_attach(struct cgroup *cg, struct cgroup_taskset *tset)
{
	if (!ve_task_can_attach(cg, tset))
		return -EINVAL;

	return ve_is_attachable(cg, tset);
}

static void ve_update_cpuid_faulting(void *dummy)
{
	set_cpuid_faulting(!ve_is_super(get_exec_env()));
}

static void ve_attach(struct cgroup *cg, struct cgroup_taskset *tset)
{
	struct ve_struct *ve = cgroup_ve(cg);
	struct task_struct *task;

	cgroup_taskset_for_each(task, cg, tset) {
		/* this probihibts ptracing of task entered to VE from host system */
		if (ve->is_running && task->mm)
			task->mm->vps_dumpable = VD_VE_ENTER_TASK;

		/* Drop OOM protection. */
		task->signal->oom_score_adj = 0;
		task->signal->oom_score_adj_min = 0;

		/* Leave parent exec domain */
		task->parent_exec_id--;

		ve_try_set_task_start_time(ve, task);

		task->task_ve = ve;
	}

	/* Adjust cpuid faulting */
	on_each_cpu(ve_update_cpuid_faulting, NULL, 1);
}

static int ve_state_read(struct cgroup *cg, struct cftype *cft,
			 struct seq_file *m)
{
	struct ve_struct *ve = cgroup_ve(cg);

	down_read(&ve->op_sem);
	if (ve->is_running)
		seq_puts(m, "RUNNING");
	else if (!nr_threads_ve(ve) && !ve->ve_ns)
		seq_puts(m, "STOPPED");
	else if (ve->ve_ns)
		seq_puts(m, "STOPPING");
	else
		seq_puts(m, "STARTING");
	seq_putc(m, '\n');
	up_read(&ve->op_sem);

	return 0;
}

struct ve_start_callback {
		struct callback_head head;
		struct ve_struct *ve;
};

static void ve_start_work(struct callback_head *head)
{
	struct ve_start_callback *work;
	struct ve_struct *ve;
	int ret;

	work = container_of(head, struct ve_start_callback, head);
	ve = work->ve;

	down_write(&ve->op_sem);
	ret = ve_start_container(ve);
	up_write(&ve->op_sem);
	put_ve(ve);
	if (ret)
		force_sig(SIGKILL, current);

	kfree(work);
}

static int ve_state_write(struct cgroup *cg, struct cftype *cft,
			  const char *buffer)
{
	struct ve_struct *ve = cgroup_ve(cg);
	struct ve_start_callback *work = NULL;
	struct task_struct *tsk;
	int ret = -EINVAL;
	pid_t pid;

	if (!strcmp(buffer, "START")) {
		down_write(&ve->op_sem);
		ret = ve_start_container(ve);
		up_write(&ve->op_sem);

		return ret;
	}

	ret = sscanf(buffer, "START %d", &pid);
	if (ret != 1)
		return -EINVAL;

	work = kmalloc(sizeof(struct ve_start_callback), GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	rcu_read_lock();
	tsk = find_task_by_vpid(pid);
	if (!tsk) {
		ret = -ESRCH;
		goto out_unlock;
	}

	init_task_work(&work->head, ve_start_work);

	work->ve = get_ve(ve);
	ret = task_work_add(tsk, &work->head, 1);
	if (ret)
		put_ve(ve);

out_unlock:
	rcu_read_unlock();
	if (ret)
		kfree(work);

	return ret;
}

static u64 ve_id_read(struct cgroup *cg, struct cftype *cft)
{
	return cgroup_ve(cg)->veid;
}

static int ve_id_write(struct cgroup *cg, struct cftype *cft, u64 value)
{
	struct ve_struct *ve = cgroup_ve(cg);
	int err = 0;

	if (value <= 0 || value > INT_MAX)
		return -EINVAL;

	down_write(&ve->op_sem);
	if (ve->is_running || ve->ve_ns) {
		if (ve->veid != value)
			err = -EBUSY;
	} else
		ve->veid = value;
	up_write(&ve->op_sem);
	return err;
}

static void *ve_mount_opts_start(struct seq_file *m, loff_t *ppos)
{
	struct ve_struct *ve = m->private;
	struct ve_devmnt *devmnt;
	loff_t pos = *ppos;

	mutex_lock(&ve->devmnt_mutex);
	list_for_each_entry(devmnt, &ve->devmnt_list, link) {
		if (!pos--)
			return devmnt;
	}
	return NULL;
}

static void *ve_mount_opts_next(struct seq_file *m, void *v, loff_t *ppos)
{
	struct ve_struct *ve = m->private;
	struct ve_devmnt *devmnt = v;

	(*ppos)++;
	if (list_is_last(&devmnt->link, &ve->devmnt_list))
		return NULL;
	return list_entry(devmnt->link.next, struct ve_devmnt, link);
}

static void ve_mount_opts_stop(struct seq_file *m, void *v)
{
	struct ve_struct *ve = m->private;

	mutex_unlock(&ve->devmnt_mutex);
}

static int ve_mount_opts_show(struct seq_file *m, void *v)
{
	struct ve_devmnt *devmnt = v;
	dev_t dev = devmnt->dev;

	seq_printf(m, "0 %u:%u;", MAJOR(dev), MINOR(dev));
	if (devmnt->hidden_options)
		seq_printf(m, "1 %s;", devmnt->hidden_options);
	if (devmnt->allowed_options)
		seq_printf(m, "2 %s;", devmnt->allowed_options);
	seq_putc(m, '\n');
	return 0;
}

struct seq_operations ve_mount_opts_sops = {
	.start = ve_mount_opts_start,
	.stop = ve_mount_opts_stop,
	.next = ve_mount_opts_next,
	.show = ve_mount_opts_show,
};

static int ve_mount_opts_open(struct inode *inode, struct file *file)
{
	struct ve_struct *ve = cgroup_ve(file->f_dentry->d_parent->d_fsdata);
	struct seq_file *m;
	int ret;

	if (ve_is_super(ve))
		return -ENODEV;

	ret = seq_open(file, &ve_mount_opts_sops);
	if (!ret) {
		m = file->private_data;
		m->private = ve;
	}
	return ret;
}

static ssize_t ve_mount_opts_read(struct cgroup *cgrp, struct cftype *cft,
				  struct file *file, char __user *buf,
				  size_t nbytes, loff_t *ppos)
{
	return seq_read(file, buf, nbytes, ppos);
}

static int ve_mount_opts_release(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

/*
 * 'data' for VE_CONFIGURE_MOUNT_OPTIONS is a zero-terminated string
 * consisting of substrings separated by MNTOPT_DELIM.
 */
#define MNTOPT_DELIM ';'
#define MNTOPT_MAXLEN 256

/*
 * Each substring has the form of "<type> <comma-separated-list-of-options>"
 * where types are:
 */
enum {
	MNTOPT_DEVICE = 0,
	MNTOPT_HIDDEN = 1,
	MNTOPT_ALLOWED = 2,
};

/*
 * 'ptr' points to the first character of buffer to parse
 * 'endp' points to the last character of buffer to parse
 */
static int ve_parse_mount_options(const char *ptr, const char *endp,
				  struct ve_devmnt *devmnt)
{
	while (*ptr) {
		const char *delim = strchr(ptr, MNTOPT_DELIM) ? : endp;
		char *space = strchr(ptr, ' ');
		int type;
		char *options, c, s;
		int options_size = delim - space;
		char **opts_pp = NULL; /* where to store 'options' */

		if (delim == ptr || !space || options_size <= 1 ||
		    !isdigit(*ptr) || space > delim)
			return -EINVAL;

		if (sscanf(ptr, "%d%c", &type, &c) != 2 || c != ' ')
			return -EINVAL;

		if (type == MNTOPT_DEVICE) {
			unsigned major, minor;
			if (devmnt->dev)
				return -EINVAL; /* Already set */
			if (sscanf(space + 1, "%u%c%u%c", &major, &c,
							  &minor, &s) != 4 ||
			    c != ':' || s != MNTOPT_DELIM)
				return -EINVAL;
			devmnt->dev = MKDEV(major, minor);
			goto next;
		}

	        options = kmalloc(options_size, GFP_KERNEL);
		if (!options)
			return -ENOMEM;

		strncpy(options, space + 1, options_size - 1);
		options[options_size - 1] = 0;

		switch (type) {
		case MNTOPT_ALLOWED:
			opts_pp = &devmnt->allowed_options;
			break;
		case MNTOPT_HIDDEN:
			opts_pp = &devmnt->hidden_options;
			break;
		};

		/* wrong type or already set */
		if (!opts_pp || *opts_pp) {
			kfree(options);
			return -EINVAL;
		}

		*opts_pp = options;
next:
		if (!*delim)
			break;

		ptr = delim + 1;
	}

	if (!devmnt->dev)
		return -EINVAL;
	return 0;
}

static int ve_mount_opts_write(struct cgroup *cg, struct cftype *cft,
			       const char *buffer)
{
	struct ve_struct *ve = cgroup_ve(cg);
	struct ve_devmnt *devmnt, *old;
	int size, err;

	size = strlen(buffer);
	if (size <= 1)
		return -EINVAL;

	devmnt = kzalloc(sizeof(*devmnt), GFP_KERNEL);
	if (!devmnt)
		return -ENOMEM;

	err = ve_parse_mount_options(buffer, buffer + size, devmnt);
	if (err) {
		ve_devmnt_free(devmnt);
		return err;
	}

	mutex_lock(&ve->devmnt_mutex);
	list_for_each_entry(old, &ve->devmnt_list, link) {
		/* Delete old devmnt */
		if (old->dev == devmnt->dev) {
			list_del(&old->link);
			ve_devmnt_free(old);
			break;
		}
	}
	list_add(&devmnt->link, &ve->devmnt_list);
	mutex_unlock(&ve->devmnt_mutex);

	return 0;
}

static int ve_os_release_read(struct cgroup *cg, struct cftype *cft,
			      struct seq_file *m)
{
	struct ve_struct *ve = cgroup_ve(cg);
	int ret = 0;

	down_read(&ve->op_sem);

	if (!ve->ve_ns) {
		ret = -ENOENT;
		goto up_opsem;
	}

	down_read(&uts_sem);
	seq_puts(m, ve->ve_ns->uts_ns->name.release);
	seq_putc(m, '\n');
	up_read(&uts_sem);
up_opsem:
	up_read(&ve->op_sem);

	return ret;
}

static int ve_os_release_write(struct cgroup *cg, struct cftype *cft,
			       const char *buffer)
{
	struct ve_struct *ve = cgroup_ve(cg);
	char *release;
	int ret = 0;

	down_read(&ve->op_sem);

	if (!ve->ve_ns) {
		ret = -ENOENT;
		goto up_opsem;
	}

	down_write(&uts_sem);
	release = ve->ve_ns->uts_ns->name.release;
	strncpy(release, buffer, __NEW_UTS_LEN);
	release[__NEW_UTS_LEN] = '\0';
	up_write(&uts_sem);
up_opsem:
	up_read(&ve->op_sem);

	return ret;
}

enum {
	VE_CF_STATE,
	VE_CF_FEATURES,
	VE_CF_IPTABLES_MASK,
	VE_CF_PSEUDOSUPER,
	VE_CF_CLOCK_MONOTONIC,
	VE_CF_CLOCK_BOOTBASED,
	VE_CF_AIO_MAX_NR,
	VE_CF_PID_MAX,
	VE_CF_NETNS_MAX_NR,
	VE_CF_NETNS_NR,
	VE_CF_NETIF_MAX_NR,
	VE_CF_NETIF_NR,
	VE_CF_CTTY,
};

static int ve_ts_read(struct cgroup *cg, struct cftype *cft, struct seq_file *m)
{
	struct ve_struct *ve = cgroup_ve(cg);
	struct timespec ts, *delta;

	do_posix_clock_monotonic_gettime(&ts);
	if (cft->private == VE_CF_CLOCK_MONOTONIC) {
		delta = &ve->start_timespec;
	} else if (cft->private == VE_CF_CLOCK_BOOTBASED) {
		delta = &ve->real_start_timespec;
		monotonic_to_bootbased(&ts);
	} else {
		delta = &ts;
		memset(&ts, 0, sizeof(ts));
		WARN_ON_ONCE(1);
	}

	set_normalized_timespec(&ts, ts.tv_sec - delta->tv_sec,
				ts.tv_nsec - delta->tv_nsec);
	seq_printf(m, "%ld %ld", ts.tv_sec, ts.tv_nsec);
	return 0;
}

static int ve_ts_write(struct cgroup *cg, struct cftype *cft, const char *buffer)
{
	struct ve_struct *ve = cgroup_ve(cg);
	struct timespec ts, delta, *target;

	if (sscanf(buffer, "%ld %ld", &delta.tv_sec, &delta.tv_nsec) != 2)
		return -EINVAL;

	do_posix_clock_monotonic_gettime(&ts);
	if (cft->private == VE_CF_CLOCK_MONOTONIC) {
		target = &ve->start_timespec;
	} else if (cft->private == VE_CF_CLOCK_BOOTBASED) {
		target = &ve->real_start_timespec;
		monotonic_to_bootbased(&ts);
	} else {
		WARN_ON_ONCE(1);
		return -EINVAL;
	}

	set_normalized_timespec(target, ts.tv_sec - delta.tv_sec,
				ts.tv_nsec - delta.tv_nsec);
	return 0;
}

static u64 ve_read_u64(struct cgroup *cg, struct cftype *cft)
{
	if (cft->private == VE_CF_FEATURES)
		return cgroup_ve(cg)->features;
#ifdef CONFIG_VE_IPTABLES
	else if (cft->private == VE_CF_IPTABLES_MASK)
		return cgroup_ve(cg)->ipt_mask;
#endif
	else if (cft->private == VE_CF_PSEUDOSUPER)
		return cgroup_ve(cg)->is_pseudosuper;
	else if (cft->private == VE_CF_AIO_MAX_NR)
		return cgroup_ve(cg)->aio_max_nr;
	else if (cft->private == VE_CF_PID_MAX) {
		struct ve_struct *ve = cgroup_ve(cg);
		if (ve->ve_ns && ve->ve_ns->pid_ns)
			return ve->ve_ns->pid_ns->pid_max;
	} else if (cft->private == VE_CF_NETNS_MAX_NR)
		return cgroup_ve(cg)->netns_max_nr;
	else if (cft->private == VE_CF_NETNS_NR)
		return atomic_read(&cgroup_ve(cg)->netns_avail_nr);
	else if (cft->private == VE_CF_NETIF_MAX_NR)
		return cgroup_ve(cg)->netif_max_nr;
	return 0;
}

static s64 ve_read_s64(struct cgroup *cg, struct cftype *cft)
{
	if (cft->private == VE_CF_NETIF_NR)
		return atomic_read(&cgroup_ve(cg)->netif_avail_nr);
	return 0;
}

/*
 * Move VE into pseudosuper state where some of privilegued
 * operations such as mounting cgroups from inside of VE context
 * is allowed in a sake of container restore for example.
 *
 * While dropping pseudosuper privilegues is allowed from
 * any context to set this value up one have to be a real
 * node's owner.
 */
static int ve_write_pseudosuper(struct cgroup *cg,
				struct cftype *cft,
				u64 value)
{
	struct ve_struct *ve = cgroup_ve(cg);

	if (!ve_capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!ve_is_super(get_exec_env()) && value)
		return -EPERM;

	down_write(&ve->op_sem);
	if (value && (ve->is_running || ve->ve_ns)) {
		up_write(&ve->op_sem);
		return -EBUSY;
	}
	ve->is_pseudosuper = value;
	/*
	 * In criu we do unset pseudosuper on ve cgroup just before doing
	 * ptrace(PTRACE_DETACH) to release restored process, what if one of
	 * them will see pseudosuper flag still set to 1?
	 *
	 * To be 100% sure that these will never happen we need to call
	 * synchronize_sched_expedited(); here to make cross cpu memory
	 * barrier.
	 *
	 * For now we rely on userspace that ptrace from criu will do wake-up
	 * on CT tasks which should imply memory barrier.
	 */
	up_write(&ve->op_sem);

	return 0;
}

extern int pid_max_min, pid_max_max;

static int ve_write_pid_max(struct cgroup *cg,
			    struct cftype *cft,
			    u64 value)
{
	struct ve_struct *ve = cgroup_ve(cg);
	if (!ve->ve_ns || !ve->ve_ns->pid_ns)
		return -EBUSY;

	if (pid_max_min > value ||
	     pid_max_max < value)
		return -EINVAL;

	ve->ve_ns->pid_ns->pid_max = value;
	return 0;
}

static int _ve_write_u64(struct cgroup *cg, struct cftype *cft,
                         u64 value, int running)
{
	struct ve_struct *ve = cgroup_ve(cg);

	if (!ve_is_super(get_exec_env()) &&
	    !ve->is_pseudosuper)
		return -EPERM;

	down_write(&ve->op_sem);
	if (!running && (ve->is_running || ve->ve_ns)) {
		up_write(&ve->op_sem);
		return -EBUSY;
	}

	if (cft->private == VE_CF_FEATURES)
		ve->features = value;
#ifdef CONFIG_VE_IPTABLES
	else if (cft->private == VE_CF_IPTABLES_MASK)
		ve->ipt_mask = ve_setup_iptables_mask(value);
#endif
	else if (cft->private == VE_CF_AIO_MAX_NR)
		ve->aio_max_nr = value;
	else if (cft->private == VE_CF_PID_MAX) {
		int ret;
		ret = ve_write_pid_max(cg, cft, value);
		up_write(&ve->op_sem);
		return ret;
	} else if (cft->private == VE_CF_NETNS_MAX_NR) {
		int delta = value - ve->netns_max_nr;

		ve->netns_max_nr = value;
		atomic_add(delta, &ve->netns_avail_nr);
	} else if (cft->private == VE_CF_NETIF_MAX_NR) {
		int delta = value - ve->netif_max_nr;

		ve->netif_max_nr = value;
		atomic_add(delta, &ve->netif_avail_nr);
	}
	up_write(&ve->op_sem);
	return 0;
}

static int ve_write_u64(struct cgroup *cg, struct cftype *cft, u64 value)
{
	return _ve_write_u64(cg, cft, value, 0);
}

static int ve_write_running_u64(struct cgroup *cg, struct cftype *cft, u64 value)
{
	return _ve_write_u64(cg, cft, value, 1);
}

static int ve_write_ctty(struct cgroup *cg, struct cftype *cft, const char *buffer)
{
	struct task_struct *tsk_from, *tsk_to;
	struct tty_struct *tty_from, *tty_to;
	pid_t pid_from, pid_to;
	unsigned long flags;
	char *pids;
	int ret;

	/*
	 * Buffer format is the following
	 *
	 * 	pid_from pid_to pid_to ...
	 *
	 * where pid_to are pids to propagate
	 * current terminal into.
	 */

	pids = skip_spaces(buffer);
	if (sscanf(pids, "%d", &pid_from) != 1)
		return -EINVAL;
	pids = strchr(pids, ' ');
	if (!pids)
		return -EINVAL;
	pids = skip_spaces(pids);

	rcu_read_lock();
	tsk_from = find_task_by_vpid(pid_from);
	if (tsk_from)
		get_task_struct(tsk_from);
	rcu_read_unlock();

	if (!tsk_from)
		return -ESRCH;

	spin_lock_irqsave(&tsk_from->sighand->siglock, flags);
	tty_from = tty_kref_get(tsk_from->signal->tty);
	spin_unlock_irqrestore(&tsk_from->sighand->siglock, flags);

	if (!tty_from) {
		ret = -ENOTTY;
		goto out;
	}

	ret = 0;
	while (pids && *pids) {
		if (sscanf(pids, "%d", &pid_to) != 1) {
			ret = -EINVAL;
			goto out;
		}
		pids = strchr(pids, ' ');
		if (pids)
			pids = skip_spaces(pids);

		rcu_read_lock();
		tsk_to = find_task_by_vpid(pid_to);
		if (tsk_to)
			get_task_struct(tsk_to);
		rcu_read_unlock();

		if (!tsk_to) {
			ret = -ESRCH;
			goto out;
		}

		if (tsk_from->task_ve == tsk_to->task_ve) {
			spin_lock_irqsave(&tsk_to->sighand->siglock, flags);
			tty_to = tsk_to->signal->tty;
			if (!tty_to)
				tsk_to->signal->tty = tty_kref_get(tty_from);
			else
				ret = -EBUSY;
			spin_unlock_irqrestore(&tsk_to->sighand->siglock, flags);
		} else
			ret = -EINVAL;

		put_task_struct(tsk_to);

		if (ret)
			goto out;
	}

out:
	tty_kref_put(tty_from);
	put_task_struct(tsk_from);
	return ret;
}

static struct cftype ve_cftypes[] = {
	{
		.name			= "state",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_seq_string	= ve_state_read,
		.write_string		= ve_state_write,
		.private		= VE_CF_STATE,
	},
	{
		.name			= "veid",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_id_read,
		.write_u64		= ve_id_write,
	},
	{
		.name			= "features",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_read_u64,
		.write_u64		= ve_write_u64,
		.private		= VE_CF_FEATURES,
	},
	{
		.name			= "mount_opts",
		.max_write_len		= MNTOPT_MAXLEN,
		.flags			= CFTYPE_NOT_ON_ROOT,
		.open			= ve_mount_opts_open,
		.read			= ve_mount_opts_read,
		.release		= ve_mount_opts_release,
		.write_string		= ve_mount_opts_write,
	},
	{
		.name			= "os_release",
		.max_write_len		= __NEW_UTS_LEN + 1,
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_seq_string	= ve_os_release_read,
		.write_string		= ve_os_release_write,
	},
	{
		.name			= "iptables_mask",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_read_u64,
		.write_u64		= ve_write_u64,
		.private		= VE_CF_IPTABLES_MASK,
	},
	{
		.name			= "pseudosuper",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_read_u64,
		.write_u64		= ve_write_pseudosuper,
		.private		= VE_CF_PSEUDOSUPER,
	},
	{
		.name			= "clock_monotonic",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_seq_string	= ve_ts_read,
		.write_string		= ve_ts_write,
		.private		= VE_CF_CLOCK_MONOTONIC,
	},
	{
		.name			= "clock_bootbased",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_seq_string	= ve_ts_read,
		.write_string		= ve_ts_write,
		.private		= VE_CF_CLOCK_BOOTBASED,
	},
	{
		.name			= "aio_max_nr",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_read_u64,
		.write_u64		= ve_write_u64,
		.private		= VE_CF_AIO_MAX_NR,
	},
	{
		.name			= "pid_max",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_read_u64,
		.write_u64		= ve_write_running_u64,
		.private		= VE_CF_PID_MAX,
	},
	{
		.name			= "netns_max_nr",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_read_u64,
		.write_u64		= ve_write_u64,
		.private		= VE_CF_NETNS_MAX_NR,
	},
	{
		.name			= "netns_avail_nr",
		.read_u64		= ve_read_u64,
		.private		= VE_CF_NETNS_NR,
	},
	{
		.name			= "netif_max_nr",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_read_u64,
		.write_u64		= ve_write_running_u64,
		.private		= VE_CF_NETIF_MAX_NR,
	},
	{
		.name			= "netif_avail_nr",
		.read_s64		= ve_read_s64,
		.private		= VE_CF_NETIF_NR,
	},
	{
		.name			= "ctty",
		.flags			= CFTYPE_ONLY_ON_ROOT,
		.write_string		= ve_write_ctty,
		.private		= VE_CF_CTTY,
	},
	{ }
};

struct cgroup_subsys ve_subsys = {
	.name		= "ve",
	.subsys_id	= ve_subsys_id,
	.css_alloc	= ve_create,
	.css_free	= ve_destroy,
	.can_attach	= ve_can_attach,
	.attach		= ve_attach,
	.base_cftypes	= ve_cftypes,
};
EXPORT_SYMBOL(ve_subsys);

static int __init ve_subsys_init(void)
{
	ve_cachep = KMEM_CACHE(ve_struct, SLAB_PANIC);
	list_add(&ve0.ve_list, &ve_list_head);
	ve0.wq = alloc_workqueue("ve0_wq", WQ_FREEZABLE|WQ_UNBOUND, 8);
	BUG_ON(!ve0.wq);
	return 0;
}
late_initcall(ve_subsys_init);

#ifdef CONFIG_CGROUP_SCHED
int cpu_cgroup_proc_stat(struct cgroup *cgrp, struct cftype *cft,
			 struct seq_file *p);

int ve_show_cpu_stat(struct ve_struct *ve, struct seq_file *p)
{
	struct cgroup_subsys_state *css;
	int err;

	css = ve_get_init_css(ve, cpu_cgroup_subsys_id);
	err = cpu_cgroup_proc_stat(css->cgroup, NULL, p);
	css_put(css);
	return err;
}

int cpu_cgroup_proc_loadavg(struct cgroup *cgrp, struct cftype *cft,
			    struct seq_file *p);

int ve_show_loadavg(struct ve_struct *ve, struct seq_file *p)
{
	struct cgroup_subsys_state *css;
	int err;

	css = ve_get_init_css(ve, cpu_cgroup_subsys_id);
	err = cpu_cgroup_proc_loadavg(css->cgroup, NULL, p);
	css_put(css);
	return err;
}

int cpu_cgroup_get_avenrun(struct cgroup *cgrp, unsigned long *avnrun);

int ve_get_cpu_avenrun(struct ve_struct *ve, unsigned long *avnrun)
{
	struct cgroup_subsys_state *css;
	int err;

	css = ve_get_init_css(ve, cpu_cgroup_subsys_id);
	err = cpu_cgroup_get_avenrun(css->cgroup, avnrun);
	css_put(css);
	return err;
}
EXPORT_SYMBOL(ve_get_cpu_avenrun);

int cpu_cgroup_get_stat(struct cgroup *cgrp, struct kernel_cpustat *kstat);

int ve_get_cpu_stat(struct ve_struct *ve, struct kernel_cpustat *kstat)
{
	struct cgroup_subsys_state *css;
	int err;

	css = ve_get_init_css(ve, cpu_cgroup_subsys_id);
	err = cpu_cgroup_get_stat(css->cgroup, kstat);
	css_put(css);
	return err;
}
EXPORT_SYMBOL(ve_get_cpu_stat);
#endif /* CONFIG_CGROUP_SCHED */
