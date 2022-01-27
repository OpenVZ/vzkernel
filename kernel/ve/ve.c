/*
 *  kernel/ve/ve.c
 *
 *  Copyright (c) 2000-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

/*
 * 've.c' helper file performing VE sub-system initialization
 */

#include <linux/cpuid_override.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ve.h>
#include <linux/aio.h>
#include <linux/errno.h>
#include <linux/rcupdate.h>
#include <linux/init_task.h>
#include <linux/mutex.h>
#include <linux/kmapset.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/nsproxy.h>
#include <linux/fs_struct.h>
#include <linux/time_namespace.h>
#include <linux/blkdev.h>
#include <linux/task_work.h>
#include <linux/ctype.h>
#include <linux/tty.h>
#include <linux/device.h>
#include <net/net_namespace.h>

#include <uapi/linux/vzcalluser.h>
#include <net/rtnetlink.h>

#include "../fs/mount.h"
#include "../cgroup/cgroup-internal.h" /* For cgroup_task_count() */

struct ve_ra_data {
	struct list_head list;
	struct rcu_head rcu;
	/*
	 * data is related to this cgroup
	 */
	struct cgroup_root *cgroot;
	char *release_agent_path;
};

extern struct kmapset_set sysfs_ve_perms_set;

static struct kmem_cache *ve_cachep;

static DEFINE_PER_CPU(struct kstat_lat_pcpu_snap_struct, ve0_lat_stats);

struct ve_struct ve0 = {
	.ve_name		= "0",
	.start_jiffies		= INITIAL_JIFFIES,

	RCU_POINTER_INITIALIZER(ve_ns, &init_nsproxy),

	.is_running		= 1,
	.is_pseudosuper		= 1,

	.init_cred		= &init_cred,
	.features		= -1,
	.sched_lat_ve.cur	= &ve0_lat_stats,
	.netns_avail_nr		= ATOMIC_INIT(INT_MAX),
	.netns_max_nr		= INT_MAX,
	.netif_avail_nr		= ATOMIC_INIT(INT_MAX),
	.netif_max_nr		= INT_MAX,
	.fsync_enable		= FSYNC_FILTERED,
	._randomize_va_space	=
#ifdef CONFIG_COMPAT_BRK
					1,
#else
					2,
#endif

	.arp_neigh_nr		= ATOMIC_INIT(0),
	.nd_neigh_nr		= ATOMIC_INIT(0),
	.mnt_nr			= ATOMIC_INIT(0),
	.meminfo_val		= VE_MEMINFO_SYSTEM,
	.vdso_64		= (struct vdso_image*)&vdso_image_64,
	.vdso_32		= (struct vdso_image*)&vdso_image_32,
	.release_list_lock	= __SPIN_LOCK_UNLOCKED(
					ve0.release_list_lock),
	.release_list		= LIST_HEAD_INIT(ve0.release_list),
	.release_agent_work	= __WORK_INITIALIZER(ve0.release_agent_work,
					cgroup1_release_agent),
	.ra_data_list	= LIST_HEAD_INIT(ve0.ra_data_list),
	.ra_data_lock	= __SPIN_LOCK_UNLOCKED(ve0.ra_data_lock),
};
EXPORT_SYMBOL(ve0);

LIST_HEAD(ve_list_head);
EXPORT_SYMBOL(ve_list_head);

DEFINE_MUTEX(ve_list_lock);
EXPORT_SYMBOL(ve_list_lock);

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
		switch (type) {
			case RTM_NEWNEIGH:
			case RTM_DELNEIGH:
			case RTM_GETNEIGH:
			case RTM_GETLINK:
			case RTM_DELLINK:
			case RTM_SETLINK:
				return 0;
		}
		fallthrough;
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
	case  IPPROTO_ICMPV6:
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
		return -EPROTONOSUPPORT;
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

struct net *ve_get_net_ns(struct ve_struct* ve)
{
	struct nsproxy *ve_ns;
	struct net *net_ns;

	rcu_read_lock();
	ve_ns = rcu_dereference(ve->ve_ns);
	net_ns = ve_ns ? get_net(ve_ns->net_ns) : NULL;
	rcu_read_unlock();

	return net_ns;
}
EXPORT_SYMBOL(ve_get_net_ns);

int nr_threads_ve(struct ve_struct *ve)
{
        return cgroup_task_count(ve->css.cgroup);
}
EXPORT_SYMBOL(nr_threads_ve);

static struct ve_ra_data *alloc_ve_ra_data(struct cgroup_root *cgroot,
					   const char *str)
{
	struct ve_ra_data *data;
	size_t buflen;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return ERR_PTR(-ENOMEM);

	/* Don't allow more than page */
	buflen = min(strlen(str) + 1, PAGE_SIZE);

	data->release_agent_path = kmalloc(buflen, GFP_KERNEL);
	if (!data->release_agent_path) {
		kfree(data);
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&data->list);
	data->cgroot = cgroot;

	if (strlcpy(data->release_agent_path, str, buflen) >= buflen) {
		kfree(data->release_agent_path);
		kfree(data);
		return ERR_PTR(-EINVAL);
	}

	return data;
}

static void free_ve_ra_data(struct rcu_head *head)
{
	struct ve_ra_data *data = container_of(head, struct ve_ra_data, rcu);

	kfree(data->release_agent_path);
	kfree(data);
}

/*
 * Either rcu_read_lock or ve->ra_data_lock
 * should be held so that data is not freed under us.
 */
static struct ve_ra_data *ve_ra_data_find_locked(struct ve_struct *ve,
						 struct cgroup_root *cgroot)
{
	struct list_head *ve_ra_data_list = &ve->ra_data_list;
	struct ve_ra_data *data;

	list_for_each_entry_rcu(data, ve_ra_data_list, list) {
		if (data->cgroot == cgroot)
			return data;
	}

	return NULL;
}

const char *ve_ra_data_get_path_locked(struct ve_struct *ve,
				       struct cgroup_root *cgroot)
{
	struct ve_ra_data *data;

	data = ve_ra_data_find_locked(ve, cgroot);

	return data ? data->release_agent_path : NULL;
}

int ve_ra_data_set(struct ve_struct *ve, struct cgroup_root *cgroot,
		   const char *release_agent)
{
	struct ve_ra_data *data, *other_data;
	unsigned long flags;

	data = alloc_ve_ra_data(cgroot, release_agent);
	if (IS_ERR(data))
		return PTR_ERR(data);

	spin_lock_irqsave(&ve->ra_data_lock, flags);
	other_data =  ve_ra_data_find_locked(ve, cgroot);
	if (other_data) {
		list_del_rcu(&other_data->list);
		call_rcu(&other_data->rcu, free_ve_ra_data);
	}

	list_add_rcu(&data->list, &ve->ra_data_list);
	spin_unlock_irqrestore(&ve->ra_data_lock, flags);

	return 0;
}

static void ve_cleanup_ra_data(struct ve_struct *ve, struct cgroup_root *cgroot)
{
	struct ve_ra_data *data;
	unsigned long flags;

	spin_lock_irqsave(&ve->ra_data_lock, flags);
	list_for_each_entry_rcu(data, &ve->ra_data_list, list) {
		if (cgroot && data->cgroot != cgroot)
			continue;

		list_del_rcu(&data->list);
		call_rcu(&data->rcu, free_ve_ra_data);
	}
	spin_unlock_irqrestore(&ve->ra_data_lock, flags);
}

void cgroot_ve_cleanup_ra_data(struct cgroup_root *cgroot)
{
	struct cgroup_subsys_state *css;
	struct ve_struct *ve;

	rcu_read_lock();
	css_for_each_descendant_pre(css, &ve0.css) {
		ve = css_to_ve(css);
		ve_cleanup_ra_data(ve, cgroot);
	}
	rcu_read_unlock();
}

struct cgroup_subsys_state *ve_get_init_css(struct ve_struct *ve, int subsys_id)
{
	struct cgroup_subsys_state *css;
	struct css_set *root_cset;
	struct nsproxy *nsproxy;

	rcu_read_lock();

	nsproxy = rcu_dereference(ve->ve_ns);
	if (!nsproxy)
		nsproxy = &init_nsproxy;

	root_cset = nsproxy->cgroup_ns->root_cset;
	css = root_cset->subsys[subsys_id];
	/* nsproxy->cgroup_ns must hold root_cset refcnt */
	BUG_ON(!css_tryget(css));

	rcu_read_unlock();
	return css;
}

static void ve_grab_context(struct ve_struct *ve)
{
	struct task_struct *tsk = current;

	ve->init_cred = (struct cred *)get_current_cred();
	get_nsproxy(tsk->nsproxy);
	rcu_assign_pointer(ve->ve_ns, tsk->nsproxy);
}

static void ve_drop_context(struct ve_struct *ve)
{
	struct nsproxy *ve_ns;

	ve_ns = rcu_dereference_protected(ve->ve_ns, lockdep_is_held(&ve->op_sem));

	/* Allows to dereference init_cred and init_task if ve_ns is set */
        rcu_assign_pointer(ve->ve_ns, NULL);
        synchronize_rcu();
	put_nsproxy(ve_ns);

	put_cred(ve->init_cred);
	ve->init_cred = NULL;
}

static void ve_stop_umh(struct ve_struct *ve)
{
	kthread_flush_worker(&ve->umh_worker);
	kthread_stop(ve->umh_task);
	ve->umh_task = NULL;
}

static int ve_start_umh(struct ve_struct *ve)
{
	struct task_struct *task;

	kthread_init_worker(&ve->umh_worker);

	task = kthread_create_on_node_ve_flags(ve, 0, kthread_worker_fn,
				      &ve->umh_worker, NUMA_NO_NODE,
				      "khelper");
	if (IS_ERR(task))
		return PTR_ERR(task);

	wake_up_process(task);

	ve->umh_task = task;
	return 0;
}

static void ve_stop_kthreadd(struct ve_struct *ve)
{
	kthread_flush_worker(ve->kthreadd_worker);
	kthread_stop(ve->kthreadd_task);
	kfree(ve->kthreadd_worker);
	ve->kthreadd_worker = NULL;
}

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

	get_nsproxy(target->nsproxy);
	switch_task_namespaces(current, target->nsproxy);

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

	err = cgroup_attach_task_all(target, current);
	if (err)
		goto out;
out:
	work->result = err;
	complete(&work->done);
}

static struct kthread_worker *ve_create_kworker(struct ve_struct *ve)
{
	struct kthread_worker *w;
	struct kthread_attach_work attach = {
		KTHREAD_WORK_INIT(attach.work, kthread_attach_fn),
		COMPLETION_INITIALIZER_ONSTACK(attach.done),
		.target = current,
	};

	w = kthread_create_worker(0, "worker/%s", ve_name(ve));
	if (IS_ERR(w))
		return w;

	kthread_queue_work(w, &attach.work);
	wait_for_completion(&attach.done);
	if (attach.result) {
		kthread_destroy_worker(w);
		return ERR_PTR(attach.result);
	}

	return w;
}

static int ve_create_kthreadd(struct ve_struct *ve,
			      struct kthread_worker *gastarbeiter)
{
	struct kthread_worker *w;
	struct task_struct *task;

	w = kmalloc(sizeof(struct kthread_worker), GFP_KERNEL);
	if (!w)
		return -ENOMEM;
	kthread_init_worker(w);

	/* This is a trick to fork kthread in a container */
	ve->kthreadd_worker = gastarbeiter;

	/* We create kthread with CLONE_PARENT flags, because otherwise when
	 * gastarbeiter will be stopped, kthreadd will be reparented to idle,
	 * while we want to keep all the threads in kthreadd pool */
	task = kthread_create_on_node_ve_flags(ve, CLONE_PARENT, kthread_worker_fn,
					       w, NUMA_NO_NODE, "kthreadd");
	if (IS_ERR(task)) {
		kfree(w);
		return PTR_ERR(task);
	}
	wake_up_process(task);

	ve->kthreadd_task = task;
	ve->kthreadd_worker = w;
	return 0;
}

static int ve_start_kthreadd(struct ve_struct *ve)
{
	struct kthread_worker *w;
	int err;

	w = ve_create_kworker(ve);
	if (IS_ERR(w))
		return PTR_ERR(w);

	err = ve_create_kthreadd(ve, w);

	kthread_destroy_worker(w);
	return err;
}

static int ve_workqueue_start(struct ve_struct *ve)
{
	ve->wq = alloc_workqueue("ve_wq_%s", WQ_SYSFS|WQ_FREEZABLE|WQ_UNBOUND,
				 8, ve->ve_name);

	if (!ve->wq)
		return -ENOMEM;
	return 0;
}

static void ve_workqueue_stop(struct ve_struct *ve)
{
	destroy_workqueue(ve->wq);
	ve->wq = NULL;
}

/*
 * ve_add_to_release_list - called from cgroup1_check_for_release to put a
 * cgroup into a release workqueue. There are two codepaths that lead to this
 * function. One starts from cgroup_exit() which holds css_set_lock, another
 * one from cgroup_destroy_locked which does not hold css_set_lock. So we
 * should not use any reschedulable
 *
 */
void ve_add_to_release_list(struct cgroup *cgrp)
{
	struct ve_struct *ve;
	unsigned long flags;
	int need_schedule_work = 0;

	rcu_read_lock();
	ve = cgroup_ve_owner(cgrp);
	if (!ve)
		ve = &ve0;

	if (!ve->is_running) {
		rcu_read_unlock();
		return;
	}

	spin_lock_irqsave(&ve->release_list_lock, flags);
	if (!cgroup_is_dead(cgrp) &&
	    list_empty(&cgrp->release_list)) {
		list_add(&cgrp->release_list, &ve->release_list);
		need_schedule_work = 1;
	}
	spin_unlock_irqrestore(&ve->release_list_lock, flags);

	if (need_schedule_work)
		queue_work(ve->wq, &ve->release_agent_work);

	rcu_read_unlock();
}

/*
 * As workqueue destroy happens before we unset CGRP_VE_ROOT and
 * cgroup->ve_owner and also as destroy waits for all current works
 * to finish, we can rely that if cgroup is in release_list of some ve
 * then cgroup_ve_owner would return exactly the same ve, and we
 * would take the right ve->release_list_lock for operating on
 * our cgroup->release_list.
 */
void ve_rm_from_release_list(struct cgroup *cgrp)
{
	struct ve_struct *ve;
	unsigned long flags;

	rcu_read_lock();
	ve = cgroup_ve_owner(cgrp);
	if (!ve)
		ve = &ve0;

	spin_lock_irqsave(&ve->release_list_lock, flags);
	if (!list_empty(&cgrp->release_list))
		list_del_init(&cgrp->release_list);
	spin_unlock_irqrestore(&ve->release_list_lock, flags);
	rcu_read_unlock();
}

/* under ve->op_sem write-lock */
static int ve_start_container(struct ve_struct *ve)
{
	struct task_struct *tsk = current;
	struct nsproxy *ve_ns;
	int err;

	if (!ve->veid)
		return -ENOENT;

	ve_ns = rcu_dereference_protected(ve->ve_ns, lockdep_is_held(&ve->op_sem));

	if (ve->is_running || ve_ns)
		return -EBUSY;

	if (tsk->task_ve != ve || !is_child_reaper(task_pid(tsk)))
		return -ECHILD;

	/*
	 * It's comfortable to use ve_struct::ve_ns::pid_ns_for_children
	 * as a pointer to ve's root pid namespace. Here we sanity check
	 * the task namespaces are so.
	 */
	if (task_active_pid_ns(tsk) != tsk->nsproxy->pid_ns_for_children)
		return -ECHILD;

	/* The value is wrong, but it is never compared to process
	 * start times */
	ve->start_jiffies = get_jiffies_64();

	ve_grab_context(ve);

	err = ve_list_add(ve);
	if (err)
		goto err_list;

	err = ve_start_kthreadd(ve);
	if (err)
		goto err_kthreadd;

	err = ve_start_umh(ve);
	if (err)
		goto err_umh;

	err = ve_workqueue_start(ve);
	if (err)
		goto err_workqueue;

	err = ve_hook_iterate_init(VE_SS_CHAIN, ve);
	if (err < 0)
		goto err_iterate;

	err = cgroup_mark_ve_roots(ve);
	if (err)
		goto err_mark_ve;

	ve->is_running = 1;

	printk(KERN_INFO "CT: %s: started\n", ve_name(ve));

	get_ve(ve); /* for ve_exit_ns() */

	return 0;

err_mark_ve:
	ve_hook_iterate_fini(VE_SS_CHAIN, ve);
err_iterate:
	ve_workqueue_stop(ve);
err_workqueue:
	ve_stop_umh(ve);
err_umh:
	ve_stop_kthreadd(ve);
err_kthreadd:
	ve_list_del(ve);
err_list:
	ve_drop_context(ve);
	return err;
}

void ve_stop_ns(struct pid_namespace *pid_ns)
{
	struct ve_struct *ve = current->task_ve;
	struct nsproxy *ve_ns;

	down_write(&ve->op_sem);
	ve_ns = rcu_dereference_protected(ve->ve_ns, lockdep_is_held(&ve->op_sem));
	/*
	 * current->cgroups already switched to init_css_set in cgroup_exit(),
	 * but current->task_ve still points to our exec ve.
	 */
	if (!ve_ns || ve_ns->pid_ns_for_children != pid_ns)
		goto unlock;
	/*
	 * Here the VE changes its state into "not running".
	 * op_sem works as barrier for vzctl ioctls.
	 * ve_mutex works as barrier for ve_can_attach().
	 */
	ve->is_running = 0;
	synchronize_rcu();

	/*
	 * release_agent works on top of umh_worker, so we must make sure, that
	 * ve workqueue is stopped first.
	 */
	ve_workqueue_stop(ve);

	/*
	 * Neither it can be in pseudosuper state
	 * anymore, setup it again if needed.
	 */
	ve->is_pseudosuper = 0;
	/*
	 * Stop kthreads, or zap_pid_ns_processes() will wait them forever.
	 */
	ve_stop_umh(ve);
	ve_stop_kthreadd(ve);
unlock:
	up_write(&ve->op_sem);
}

void ve_exit_ns(struct pid_namespace *pid_ns)
{
	struct ve_struct *ve = current->task_ve;
	struct nsproxy *ve_ns;

	down_write(&ve->op_sem);
	ve_ns = rcu_dereference_protected(ve->ve_ns, lockdep_is_held(&ve->op_sem));
	/*
	 * current->cgroups already switched to init_css_set in cgroup_exit(),
	 * but current->task_ve still points to our exec ve.
	 */
	if (!ve_ns || ve_ns->pid_ns_for_children != pid_ns)
		goto unlock;

	cgroup_unmark_ve_roots(ve);

	/*
	 * At this point all userspace tasks in container are dead.
	 */
	ve_hook_iterate_fini(VE_SS_CHAIN, ve);
	ve_list_del(ve);
	ve_drop_context(ve);
	printk(KERN_INFO "CT: %s: stopped\n", ve_name(ve));
	put_ve(ve); /* from ve_start_container() */
unlock:
	up_write(&ve->op_sem);
}

u64 ve_get_monotonic(struct ve_struct *ve)
{
	struct time_namespace *time_ns = ve_get_time_ns(ve);
	struct timespec64 tp;

	if (unlikely(!time_ns)) {
		/* container not yet started */
		return 0;
	}

	ktime_get_ts64(&tp);
	tp = timespec64_add(tp, time_ns->offsets.monotonic);
	put_time_ns(time_ns);
	return timespec64_to_ns(&tp);
}
EXPORT_SYMBOL(ve_get_monotonic);

u64 ve_get_uptime(struct ve_struct *ve)
{
	struct time_namespace *time_ns = ve_get_time_ns(ve);
	struct timespec64 tp;

	if (unlikely(!time_ns)) {
		/* container not yet started */
		return 0;
	}

	ktime_get_boottime_ts64(&tp);
	tp = timespec64_add(tp, time_ns->offsets.boottime);
	put_time_ns(time_ns);
	return timespec64_to_ns(&tp);
}
EXPORT_SYMBOL(ve_get_uptime);

static int copy_vdso(struct vdso_image **vdso_dst, const struct vdso_image *vdso_src)
{
	struct vdso_image *vdso;
	void *vdso_data;

	if (*vdso_dst)
		return 0;

	vdso = kmemdup(vdso_src, sizeof(*vdso), GFP_KERNEL);
	if (!vdso)
		return -ENOMEM;

	vdso_data = alloc_pages_exact(vdso_src->size, GFP_KERNEL);
	if (!vdso_data) {
		kfree(vdso);
		return -ENOMEM;
	}

	memcpy(vdso_data, vdso_src->data, vdso_src->size);

	vdso->data = vdso_data;

	*vdso_dst = vdso;
	return 0;
}

static void ve_free_vdso(struct ve_struct *ve)
{
	if (ve->vdso_64 && ve->vdso_64 != &vdso_image_64) {
		free_pages_exact(ve->vdso_64->data, ve->vdso_64->size);
		kfree(ve->vdso_64);
	}
	if (ve->vdso_32 && ve->vdso_32 != &vdso_image_32) {
		free_pages_exact(ve->vdso_32->data, ve->vdso_32->size);
		kfree(ve->vdso_32);
	}
}

static struct cgroup_subsys_state *ve_create(struct cgroup_subsys_state *parent_css)
{
	struct ve_struct *ve = &ve0;
	int err;

	if (!parent_css)
		goto do_init;

	/* forbid nested containers */
	if (css_to_ve(parent_css) != &ve0)
		return ERR_PTR(-ENOTDIR);

	err = -ENOMEM;
	ve = kmem_cache_zalloc(ve_cachep, GFP_KERNEL);
	if (!ve)
		goto err_ve;

	ve->sched_lat_ve.cur = alloc_percpu(struct kstat_lat_pcpu_snap_struct);
	if (!ve->sched_lat_ve.cur)
		goto err_lat;

	ve->features = VE_FEATURES_DEF;

	INIT_WORK(&ve->release_agent_work, cgroup1_release_agent);
	spin_lock_init(&ve->release_list_lock);
	INIT_LIST_HEAD(&ve->release_list);
	spin_lock_init(&ve->ra_data_lock);
	INIT_LIST_HEAD(&ve->ra_data_list);

	ve->_randomize_va_space = ve0._randomize_va_space;

	ve->meminfo_val = VE_MEMINFO_DEFAULT;

	ve->odirect_enable = 2;
	/* for veX FSYNC_FILTERED means "get value from ve0 */
	ve->fsync_enable = FSYNC_FILTERED;

	atomic_set(&ve->netns_avail_nr, NETNS_MAX_NR_DEFAULT);
	ve->netns_max_nr = NETNS_MAX_NR_DEFAULT;

	atomic_set(&ve->netif_avail_nr, NETIF_MAX_NR_DEFAULT);
	ve->netif_max_nr = NETIF_MAX_NR_DEFAULT;

	err = ve_log_init(ve);
	if (err)
		goto err_log;

	err = copy_vdso(&ve->vdso_64, &vdso_image_64);
	if (err)
		goto err_vdso;

	err = copy_vdso(&ve->vdso_32, &vdso_image_32);
	if (err)
		goto err_vdso;

	err = ve_mount_devtmpfs(ve);
	if (err)
		goto err_vdso; /* The same as above, correct */

do_init:
	init_rwsem(&ve->op_sem);
	INIT_LIST_HEAD(&ve->ve_list);
	kmapset_init_key(&ve->sysfs_perms_key);

	atomic_set(&ve->arp_neigh_nr, 0);
	atomic_set(&ve->nd_neigh_nr, 0);
	atomic_set(&ve->mnt_nr, 0);

#ifdef CONFIG_COREDUMP
	strcpy(ve->core_pattern, "core");
#endif
	INIT_LIST_HEAD(&ve->devmnt_list);
	mutex_init(&ve->devmnt_mutex);

#ifdef CONFIG_AIO
	spin_lock_init(&ve->aio_nr_lock);
	ve->aio_nr = 0;
	ve->aio_max_nr = AIO_MAX_NR_DEFAULT;
#endif

	return &ve->css;

err_vdso:
	ve_free_vdso(ve);
	ve_log_destroy(ve);
err_log:
	free_percpu(ve->sched_lat_ve.cur);
err_lat:
	kmem_cache_free(ve_cachep, ve);
err_ve:
	return ERR_PTR(err);
}

static int ve_online(struct cgroup_subsys_state *css)
{
	static char ve_name_buf[NAME_MAX + 1]; /* protected by ve_name_mutex */
	static DEFINE_MUTEX(ve_name_mutex);
	struct ve_struct *ve = css_to_ve(css);

	mutex_lock(&ve_name_mutex);
	/*
	 * Cache ve_name to have it directly accessed. But keep in mind,
	 * that ve directory may be removed, and we don't handle that.
	 * For exact cgroup name you may allocate temporary buffers
	 * and use cgroup_name().
	 */
	cgroup_name(css->cgroup, ve_name_buf, sizeof(ve_name_buf));
	ve->ve_name = kasprintf(GFP_KERNEL, "%s", ve_name_buf);
	mutex_unlock(&ve_name_mutex);

	if (!ve->ve_name)
		return -ENOMEM;
	return 0;
}

static void ve_offline(struct cgroup_subsys_state *css)
{
	struct ve_struct *ve = css_to_ve(css);

	kfree(ve->ve_name);
	ve->ve_name = NULL;

	ve_cleanup_ra_data(ve, NULL);
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

static void ve_destroy(struct cgroup_subsys_state *css)
{
	struct ve_struct *ve = css_to_ve(css);

	free_ve_devmnts(ve);

	kmapset_unlink(&ve->sysfs_perms_key, &sysfs_ve_perms_set);
	ve_log_destroy(ve);
	ve_free_vdso(ve);
	mntput(ve->devtmpfs_mnt);
#if IS_ENABLED(CONFIG_BINFMT_MISC)
	kfree(ve->binfmt_misc);
#endif
	free_percpu(ve->sched_lat_ve.cur);
	kmem_cache_free(ve_cachep, ve);
}

static bool ve_task_can_attach(struct cgroup_taskset *tset)
{
	struct cgroup_subsys_state *css;
	struct task_struct *task;

	task = cgroup_taskset_first(tset, &css);
	if (task != current)
		pr_err_ratelimited("ve_cgroup: Add task_work-based interface for attaching!!!\n");

	if (cgroup_taskset_next(tset, &css) != NULL) {
		pr_err_ratelimited("ve_cgroup: attach of a thread group is not supported\n");
		return false;
	}
	if (!thread_group_leader(task)) {
		pr_err_ratelimited("ve_cgroup: only thread group leader is allowed to attach\n");
		return false;
	}
	if (!thread_group_empty(task)) {
		pr_err_ratelimited("ve_cgroup: only single-threaded process is allowed to attach\n");
		return false;
	}
	return true;
}

static int ve_is_attachable(struct cgroup_taskset *tset)
{
	struct cgroup_subsys_state *css;
	struct task_struct *task;
	struct ve_struct *ve;

	task = cgroup_taskset_first(tset, &css);
	ve = css_to_ve(css);

	if (ve->is_running)
		return 0;

	if (!ve->veid) {
		pr_err_ratelimited("ve_cgroup: container's veid is not set\n");
		return -EINVAL;
	}

	if (task->flags & PF_KTHREAD) {
		/* Paranoia check: allow to attach kthread only, if cgroup is
		 * not empty.
		 * This check is required for kthreadd, which is created on CT
		 * start.
		 */
		if (cgroup_is_populated(css->cgroup))
			return 0;
		pr_err_ratelimited("ve_cgroup: can't attach kthread - empty group\n");
	} else {
		/* In case of generic task only one is allowed to enter to
		 * non-running container: init.
		 */
		if (!cgroup_is_populated(css->cgroup))
			return 0;
		pr_err_ratelimited("ve_cgroup: can't attach more than 1 task to "
				"non-running container\n");
	}
	return -EINVAL;
}

static int ve_can_attach(struct cgroup_taskset *tset)
{
	if (!ve_task_can_attach(tset))
		return -EINVAL;

	return ve_is_attachable(tset);
}

static void ve_attach(struct cgroup_taskset *tset)
{
	struct cgroup_subsys_state *css;
	struct task_struct *task;
	extern struct cpuid_override_table __rcu *cpuid_override;

	cgroup_taskset_for_each(task, css, tset) {
		struct ve_struct *ve = css_to_ve(css);

		/* this probihibts ptracing of task entered to VE from host system */
		if (ve->is_running && task->mm)
			task->mm->vps_dumpable = VD_VE_ENTER_TASK;

		/* Drop OOM protection. */
		task->signal->oom_score_adj = 0;
		task->signal->oom_score_adj_min = 0;

		/* Leave parent exec domain */
		task->parent_exec_id--;

		ve_set_task_start_time(ve, task);

		if (cpuid_override_on())
			set_tsk_thread_flag(task, TIF_CPUID_OVERRIDE);

		rcu_assign_pointer(task->task_ve, ve);
	}
}

static int ve_state_show(struct seq_file *sf, void *v)
{
	struct cgroup_subsys_state *css = seq_css(sf);
	struct ve_struct *ve = css_to_ve(css);

	down_read(&ve->op_sem);
	if (ve->is_running)
		seq_puts(sf, "RUNNING");
	else if (!cgroup_is_populated(css->cgroup) && !ve->ve_ns)
		seq_puts(sf, "STOPPED");
	else if (ve->ve_ns)
		seq_puts(sf, "STOPPING");
	else
		seq_puts(sf, "STARTING");
	seq_putc(sf, '\n');
	up_read(&ve->op_sem);

	return 0;
}

static ssize_t ve_state_write(struct kernfs_open_file *of, char *buf,
			      size_t nbytes, loff_t off)

{
	struct cgroup_subsys_state *css = of_css(of);
        struct ve_struct *ve = css_to_ve(css);
	int ret = -EINVAL;

	if (!strcmp(buf, "START")) {
		down_write(&ve->op_sem);
		ret = ve_start_container(ve);
		up_write(&ve->op_sem);
	}
	return ret ? ret : nbytes;
}

static u64 ve_id_read(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct ve_struct *ve = css_to_ve(css);

	return ve->veid;
}

static int ve_id_write(struct cgroup_subsys_state *css, struct cftype *cft, u64 val)
{
	struct ve_struct *ve = css_to_ve(css);
	struct nsproxy *ve_ns;
	int err = 0;

	if (val <= 0 || val > INT_MAX)
		return -EINVAL;

	down_write(&ve->op_sem);
	ve_ns = rcu_dereference_protected(ve->ve_ns, lockdep_is_held(&ve->op_sem));

	/* FIXME: check veid is uniqul */
	if (ve->is_running || ve_ns) {
		if (ve->veid != val)
			err = -EBUSY;
	} else
		ve->veid = val;
	up_write(&ve->op_sem);
	return err;
}

static u64 ve_pseudosuper_read(struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct ve_struct *ve = css_to_ve(css);
	return ve->is_pseudosuper;
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
static int ve_pseudosuper_write(struct cgroup_subsys_state *css, struct cftype *cft, u64 val)
{
	struct ve_struct *ve = css_to_ve(css);

	if (!ve_capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!ve_is_super(get_exec_env()) && val)
		return -EPERM;

	down_write(&ve->op_sem);
	if (val && (ve->is_running || ve->ve_ns)) {
		up_write(&ve->op_sem);
		return -EBUSY;
	}
	ve->is_pseudosuper = val;
	/*
	 * In CRIU we do unset pseudosuper on ve cgroup just before doing
	 * ptrace(PTRACE_DETACH) to release restored process, what if one of
	 * them will see pseudosuper flag still set to 1?
	 *
	 * To be 100% sure that these will never happen we need to call
	 * synchronize_sched_expedited(); here to make cross cpu memory
	 * barrier.
	 *
	 * For now we rely on userspace that ptrace from CRIU will do wake-up
	 * on CT tasks which should imply memory barrier.
	 */
	up_write(&ve->op_sem);

	return 0;
}

static u64 ve_reatures_read(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_to_ve(css)->features;
}

static int ve_features_write(struct cgroup_subsys_state *css, struct cftype *cft, u64 val)
{
	struct ve_struct *ve = css_to_ve(css);

	if (!ve_is_super(get_exec_env()) &&
	    !ve->is_pseudosuper)
		return -EPERM;

	down_write(&ve->op_sem);
	if (ve->is_running || ve->ve_ns) {
		up_write(&ve->op_sem);
		return -EBUSY;
	}
	ve->features = val;
	up_write(&ve->op_sem);
	return 0;
}

static u64 ve_netns_max_nr_read(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_to_ve(css)->netns_max_nr;
}

static int ve_netns_max_nr_write(struct cgroup_subsys_state *css, struct cftype *cft, u64 val)
{
	struct ve_struct *ve = css_to_ve(css);
	int delta;

	if (!ve_is_super(get_exec_env()))
		return -EPERM;

	down_write(&ve->op_sem);
	if (ve->is_running || ve->ve_ns) {
		up_write(&ve->op_sem);
		return -EBUSY;
	}
	delta = val - ve->netns_max_nr;
	ve->netns_max_nr = val;
	atomic_add(delta, &ve->netns_avail_nr);
	up_write(&ve->op_sem);
	return 0;
}
static u64 ve_netns_avail_nr_read(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return atomic_read(&css_to_ve(css)->netns_avail_nr);
}

static u64 ve_netif_max_nr_read(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return css_to_ve(css)->netif_max_nr;
}

static int ve_netif_max_nr_write(struct cgroup_subsys_state *css, struct cftype *cft, u64 val)
{
	struct ve_struct *ve = css_to_ve(css);
	int delta;

	if (!ve_is_super(get_exec_env()))
		return -EPERM;

	if (val > INT_MAX)
		return -EOVERFLOW;

	down_write(&ve->op_sem);
	delta = val - ve->netif_max_nr;
	ve->netif_max_nr = val;
	atomic_add(delta, &ve->netif_avail_nr);
	up_write(&ve->op_sem);
	return 0;
}

static s64 ve_netif_avail_nr_read(struct cgroup_subsys_state *css, struct cftype *cft)
{
	return atomic_read(&css_to_ve(css)->netif_avail_nr);
}

static int ve_os_release_read(struct seq_file *sf, void *v)
{
	struct cgroup_subsys_state *css = seq_css(sf);
	struct ve_struct *ve = css_to_ve(css);
	int ret = 0;

	down_read(&ve->op_sem);

	if (!ve->ve_ns) {
		ret = -ENOENT;
		goto up_opsem;
	}

	down_read(&uts_sem);
	seq_puts(sf, ve->ve_ns->uts_ns->name.release);
	seq_putc(sf, '\n');
	up_read(&uts_sem);
up_opsem:
	up_read(&ve->op_sem);

	return ret;
}

static ssize_t ve_os_release_write(struct kernfs_open_file *of, char *buf,
				   size_t nbytes, loff_t off)
{
	struct cgroup_subsys_state *css = of_css(of);
	struct ve_struct *ve = css_to_ve(css);
	int n1, n2, n3, new_version;
	char *release;
	int ret = 0;

	down_read(&ve->op_sem);

	if (!ve->ve_ns) {
		ret = -ENOENT;
		goto up_opsem;
	}

	if (sscanf(buf, "%d.%d.%d", &n1, &n2, &n3) == 3) {
		new_version = ((n1 << 16) + (n2 << 8)) + n3;
		*((int *)(ve->vdso_64->data + ve->vdso_64->sym_linux_version_code)) = new_version;
		*((int *)(ve->vdso_32->data + ve->vdso_32->sym_linux_version_code)) = new_version;
	}

	down_write(&uts_sem);
	release = ve->ve_ns->uts_ns->name.release;
	strncpy(release, buf, __NEW_UTS_LEN);
	release[__NEW_UTS_LEN] = '\0';
	up_write(&uts_sem);
up_opsem:
	up_read(&ve->op_sem);

	return ret ? ret : nbytes;
}

enum {
	VE_CF_CLOCK_MONOTONIC,
	VE_CF_CLOCK_BOOTBASED,
};

static u64 ve_pid_max_read_u64(struct cgroup_subsys_state *css,
			       struct cftype *cft)
{
	struct ve_struct *ve = css_to_ve(css);
	struct nsproxy *ve_ns;
	u64 pid_max = 0;

	rcu_read_lock();
	ve_ns = rcu_dereference(ve->ve_ns);
	if (ve_ns && ve_ns->pid_ns_for_children)
		pid_max = ve_ns->pid_ns_for_children->pid_max;

	rcu_read_unlock();

	return pid_max;
}

extern int pid_max_min, pid_max_max;

static int ve_pid_max_write_running_u64(struct cgroup_subsys_state *css,
					struct cftype *cft, u64 val)
{
	struct ve_struct *ve = css_to_ve(css);
	struct nsproxy *ve_ns;

	if (!ve_is_super(get_exec_env()) &&
	    !ve->is_pseudosuper)
		return -EPERM;

	rcu_read_lock();
	ve_ns = rcu_dereference(ve->ve_ns);
	if (!ve_ns || !ve_ns->pid_ns_for_children) {
		return -EBUSY;
	}
	if (pid_max_min > val || pid_max_max < val) {
		return -EINVAL;
	}

	ve->ve_ns->pid_ns_for_children->pid_max = val;
	rcu_read_unlock();

	return 0;
}

static int ve_ts_read(struct seq_file *sf, void *v)
{
	struct ve_struct *ve = css_to_ve(seq_css(sf));
	struct nsproxy *ve_ns;
	struct time_namespace *time_ns;
	struct timespec64 tp = ns_to_timespec64(0);
	struct timespec64 *offset = NULL;

	rcu_read_lock();
	ve_ns = rcu_dereference(ve->ve_ns);
	if (!ve_ns) {
		rcu_read_unlock();
		goto out;
	}

	time_ns = get_time_ns(ve_ns->time_ns);
	rcu_read_unlock();

	switch (seq_cft(sf)->private) {
		case VE_CF_CLOCK_MONOTONIC:
			ktime_get_ts64(&tp);
			offset = &time_ns->offsets.monotonic;
			break;
		case VE_CF_CLOCK_BOOTBASED:
			ktime_get_boottime_ts64(&tp);
			offset = &time_ns->offsets.boottime;
			break;
		default:
			WARN_ON_ONCE(1);
			goto out_ns;
	}

	/*
	 * Note: ve.clock_* fields should report ve-relative time, but timens
	 * offsets instead report the offset between ns-relative time and host
	 * time, so we need to print offset+now to show ve-relative time.
	 */
	tp = timespec64_add(tp, *offset);
out_ns:
	put_time_ns(time_ns);
out:
	seq_printf(sf, "%lld %ld", tp.tv_sec, tp.tv_nsec);
	return 0;
}

static int ve_mount_opts_read(struct seq_file *sf, void *v)
{
	struct ve_struct *ve = css_to_ve(seq_css(sf));
	struct ve_devmnt *devmnt;

	if (ve_is_super(ve))
		return -ENODEV;

	mutex_lock(&ve->devmnt_mutex);
	list_for_each_entry(devmnt, &ve->devmnt_list, link) {
		dev_t dev = devmnt->dev;

		seq_printf(sf, "0 %u:%u;", MAJOR(dev), MINOR(dev));
		if (devmnt->hidden_options)
			seq_printf(sf, "1 %s;", devmnt->hidden_options);
		if (devmnt->allowed_options)
			seq_printf(sf, "2 %s;", devmnt->allowed_options);
		seq_putc(sf, '\n');
	}
	mutex_unlock(&ve->devmnt_mutex);
	return 0;
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

static ssize_t ve_mount_opts_write(struct kernfs_open_file *of, char *buf,
			   size_t nbytes, loff_t off)
{
	struct ve_struct *ve = css_to_ve(of_css(of));
	struct ve_devmnt *devmnt, *old;
	int err;

	devmnt = kzalloc(sizeof(*devmnt), GFP_KERNEL);
	if (!devmnt)
		return -ENOMEM;

	err = ve_parse_mount_options(buf, buf + nbytes, devmnt);
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

	return nbytes;
}

#ifdef CONFIG_AIO
static u64 ve_aio_max_nr_read(struct cgroup_subsys_state *css,
			      struct cftype *cft)
{
	return css_to_ve(css)->aio_max_nr;
}

static int ve_aio_max_nr_write(struct cgroup_subsys_state *css,
			       struct cftype *cft, u64 val)
{
	struct ve_struct *ve = css_to_ve(css);

	if (!ve_is_super(get_exec_env()) && !ve->is_pseudosuper)
		return -EPERM;

	down_write(&ve->op_sem);
	if (ve->is_running || ve->ve_ns) {
		up_write(&ve->op_sem);
		return -EBUSY;
	}

	ve->aio_max_nr = val;

	up_write(&ve->op_sem);

	return 0;
}
#endif

static ssize_t ve_write_ctty(struct kernfs_open_file *of, char *buf,
			 size_t nbytes, loff_t off)
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

	pids = skip_spaces(buf);
	if (sscanf(pids, "%d", &pid_from) != 1)
		return -EINVAL;
	pids = strchr(pids, ' ');
	if (!pids)
		return -EINVAL;
	pids = skip_spaces(pids);

	tsk_from = find_get_task_by_vpid(pid_from);
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

		tsk_to = find_get_task_by_vpid(pid_to);
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

	if (!ret)
		ret = nbytes;

	return ret;
}

static struct cftype ve_cftypes[] = {

	{
		.name			= "state",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.seq_show		= ve_state_show,
		.write			= ve_state_write,
	},
	{
		.name			= "veid",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_id_read,
		.write_u64		= ve_id_write,
	},
	{
		.name			= "pseudosuper",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_pseudosuper_read,
		.write_u64		= ve_pseudosuper_write,
	},
	{
		.name			= "features",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_reatures_read,
		.write_u64		= ve_features_write,
	},
	{
		.name			= "clock_monotonic",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.seq_show		= ve_ts_read,
		.private		= VE_CF_CLOCK_MONOTONIC,
	},
	{
		.name			= "clock_bootbased",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.seq_show		= ve_ts_read,
		.private		= VE_CF_CLOCK_BOOTBASED,
	},
	{
		.name			= "pid_max",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_pid_max_read_u64,
		.write_u64		= ve_pid_max_write_running_u64,
	},
	{
		.name			= "netns_max_nr",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_netns_max_nr_read,
		.write_u64		= ve_netns_max_nr_write,
	},
	{
		.name			= "netns_avail_nr",
		.read_u64		= ve_netns_avail_nr_read,
	},
	{
		.name			= "netif_max_nr",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_netif_max_nr_read,
		.write_u64		= ve_netif_max_nr_write,
	},
	{
		.name			= "netif_avail_nr",
		.read_s64		= ve_netif_avail_nr_read,
	},
	{
		.name			= "os_release",
		.max_write_len		= __NEW_UTS_LEN + 1,
		.flags			= CFTYPE_NOT_ON_ROOT,
		.seq_show		= ve_os_release_read,
		.write			= ve_os_release_write,
	},
	{
		.name			= "mount_opts",
		.max_write_len		= MNTOPT_MAXLEN,
		.flags			= CFTYPE_NOT_ON_ROOT,
		.seq_show		= ve_mount_opts_read,
		.write			= ve_mount_opts_write,
	},
#ifdef CONFIG_AIO
	{
		.name			= "aio_max_nr",
		.flags			= CFTYPE_NOT_ON_ROOT,
		.read_u64		= ve_aio_max_nr_read,
		.write_u64		= ve_aio_max_nr_write,
	},
#endif
	{
		.name			= "ctty",
		.flags			= CFTYPE_ONLY_ON_ROOT,
		.write			= ve_write_ctty,
	},
	{ }
};

struct cgroup_subsys ve_cgrp_subsys = {
	.css_alloc	= ve_create,
	.css_online	= ve_online,
	.css_offline	= ve_offline,
	.css_free	= ve_destroy,
	.can_attach	= ve_can_attach,
	.attach		= ve_attach,
	.legacy_cftypes	= ve_cftypes,
};

static int __init ve_subsys_init(void)
{
	ve_cachep = KMEM_CACHE_USERCOPY(ve_struct, SLAB_PANIC, core_pattern);
	list_add(&ve0.ve_list, &ve_list_head);
	ve0.wq = alloc_workqueue("ve0_wq", WQ_FREEZABLE|WQ_UNBOUND, 8);
	BUG_ON(!ve0.wq);
	return 0;
}
late_initcall(ve_subsys_init);

static bool ve_check_trusted_file(struct file *file)
{
	struct block_device *bdev;
	bool exec_from_ct;
	bool file_on_host_mount;

	/* The trusted exec defense is globally off. */
	if (trusted_exec)
		return true;

	/* The current process does not belong to ve0. */
	exec_from_ct = !ve_is_super(get_exec_env());
	if (exec_from_ct)
		return true;

	/* The current process belongs to ve0. */
	bdev = file->f_inode->i_sb->s_bdev;
	if (bdev) {
		/* The file to execute is stored on trusted block device. */
		if (bdev->bd_disk->vz_trusted_exec)
			return true;
	} else {
		/*
		 * bdev can be NULL if the file is on tmpfs, for example.
		 * If this is a host's tmpfs - execution is allowed.
		 */
		file_on_host_mount = ve_is_super(
				     real_mount(file->f_path.mnt)->ve_owner);
		if (file_on_host_mount)
			return true;
	}

	return false;
}

/* Send signal only 3 times a day so that coredumps don't overflow the disk */
#define SIGSEGV_RATELIMIT_INTERVAL	(24 * 60 * 60 * HZ)
#define SIGSEGV_RATELIMIT_BURST		3

bool ve_check_trusted_mmap(struct file *file)
{
	const char *filename = "";

	static DEFINE_RATELIMIT_STATE(sigsegv_rs, SIGSEGV_RATELIMIT_INTERVAL,
						  SIGSEGV_RATELIMIT_BURST);
	if (ve_check_trusted_file(file))
		return true;

	if (!__ratelimit(&sigsegv_rs))
		return false;

	if (file->f_path.dentry)
		filename = file->f_path.dentry->d_name.name;

	WARN(1, "VE0 %s tried to map code from file '%s' from VEX\n",
			current->comm, filename);
	force_sigsegv(SIGSEGV);
	return false;
}

/*
 * We don't want a VE0-privileged user intentionally or by mistake
 * to execute files of container, these files are untrusted.
 */
bool ve_check_trusted_exec(struct file *file, struct filename *name)
{
	static DEFINE_RATELIMIT_STATE(sigsegv_rs, SIGSEGV_RATELIMIT_INTERVAL,
						  SIGSEGV_RATELIMIT_BURST);
	if (ve_check_trusted_file(file))
		return true;

	if (!__ratelimit(&sigsegv_rs))
		return false;

	WARN(1, "VE0's %s tried to execute untrusted file %s from VEX\n",
		current->comm, name->name);
	force_sigsegv(SIGSEGV);
	return false;
}

#ifdef CONFIG_CGROUP_SCHED
int cpu_cgroup_proc_stat(struct cgroup_subsys_state *cpu_css,
			 struct cgroup_subsys_state *cpuacct_css,
			 struct seq_file *p);

int ve_show_cpu_stat(struct ve_struct *ve, struct seq_file *p)
{
	struct cgroup_subsys_state *cpu_css, *cpuacct_css;
	int err;

	cpu_css = ve_get_init_css(ve, cpu_cgrp_id);
	cpuacct_css = ve_get_init_css(ve, cpuacct_cgrp_id);
	err = cpu_cgroup_proc_stat(cpu_css, cpuacct_css, p);
	css_put(cpuacct_css);
	css_put(cpu_css);
	return err;
}

int cpu_cgroup_proc_loadavg(struct cgroup_subsys_state *css,
			    struct seq_file *p);

int ve_show_loadavg(struct ve_struct *ve, struct seq_file *p)
{
	struct cgroup_subsys_state *css;
	int err;

	css = ve_get_init_css(ve, cpu_cgrp_id);
	err = cpu_cgroup_proc_loadavg(css, p);
	css_put(css);
	return err;
}

struct task_group *css_tg(struct cgroup_subsys_state *css);
int get_avenrun_tg(struct task_group *tg, unsigned long *loads,
		   unsigned long offset, int shift);

int ve_get_cpu_avenrun(struct ve_struct *ve, unsigned long *avnrun)
{
	struct cgroup_subsys_state *css;
	struct task_group *tg;
	int err;

	css = ve_get_init_css(ve, cpu_cgrp_id);
	tg = css_tg(css);
	err = get_avenrun_tg(tg, avnrun, 0, 0);
	css_put(css);
	return err;
}
EXPORT_SYMBOL(ve_get_cpu_avenrun);

int cpu_cgroup_get_stat(struct cgroup_subsys_state *cpu_css,
			struct cgroup_subsys_state *cpuacct_css,
			struct kernel_cpustat *kstat);

int ve_get_cpu_stat(struct ve_struct *ve, struct kernel_cpustat *kstat)
{
	struct cgroup_subsys_state *cpu_css, *cpuacct_css;
	int err;

	cpu_css = ve_get_init_css(ve, cpu_cgrp_id);
	cpuacct_css = ve_get_init_css(ve, cpuacct_cgrp_id);
	err = cpu_cgroup_get_stat(cpu_css, cpuacct_css, kstat);
	css_put(cpuacct_css);
	css_put(cpu_css);
	return err;
}
EXPORT_SYMBOL(ve_get_cpu_stat);
#endif /* CONFIG_CGROUP_SCHED */
