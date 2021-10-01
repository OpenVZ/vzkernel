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

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ve.h>
#include <linux/errno.h>
#include <linux/rcupdate.h>
#include <linux/init_task.h>
#include <linux/mutex.h>
#include <linux/kmapset.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/nsproxy.h>
#include <linux/fs_struct.h>
#include <uapi/linux/vzcalluser.h>
#include <net/rtnetlink.h>

#include "../cgroup/cgroup-internal.h" /* For cgroup_task_count() */

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
	._randomize_va_space	=
#ifdef CONFIG_COMPAT_BRK
					1,
#else
					2,
#endif
	.meminfo_val		= VE_MEMINFO_SYSTEM,
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

int nr_threads_ve(struct ve_struct *ve)
{
        return cgroup_task_count(ve->css.cgroup);
}
EXPORT_SYMBOL(nr_threads_ve);

struct cgroup_subsys_state *ve_get_init_css(struct ve_struct *ve, int subsys_id)
{
	struct cgroup_subsys_state *css;
	struct css_set *root_cset;
	struct nsproxy *nsproxy;

	rcu_read_lock();

	nsproxy = ve->ve_ns ? : &init_nsproxy;
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

	/*
	 * Setup uptime for new containers only, if restored
	 * the value won't be zero here already but setup from
	 * cgroup write while resuming the container.
	 */
	if (ve->start_time == 0) {
		ve->start_time = tsk->start_time;
		ve->start_boottime = tsk->start_boottime;
	}
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

	err = ve_hook_iterate_init(VE_SS_CHAIN, ve);
	if (err < 0)
		goto err_iterate;

	cgroup_mark_ve_roots(ve);

	ve->is_running = 1;

	printk(KERN_INFO "CT: %s: started\n", ve_name(ve));

	get_ve(ve); /* for ve_exit_ns() */

	return 0;

err_iterate:
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
	ve->_randomize_va_space = ve0._randomize_va_space;

	ve->meminfo_val = VE_MEMINFO_DEFAULT;

	atomic_set(&ve->netns_avail_nr, NETNS_MAX_NR_DEFAULT);
	ve->netns_max_nr = NETNS_MAX_NR_DEFAULT;

	err = ve_log_init(ve);
	if (err)
		goto err_log;

do_init:
	init_rwsem(&ve->op_sem);
	INIT_LIST_HEAD(&ve->ve_list);
	kmapset_init_key(&ve->sysfs_perms_key);
	return &ve->css;

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
}

static void ve_destroy(struct cgroup_subsys_state *css)
{
	struct ve_struct *ve = css_to_ve(css);

	kmapset_unlink(&ve->sysfs_perms_key, &sysfs_ve_perms_set);
	ve_log_destroy(ve);
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

		task->task_ve = ve;
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

static int ve_reatures_write(struct cgroup_subsys_state *css, struct cftype *cft, u64 val)
{
	struct ve_struct *ve = css_to_ve(css);

	if (!ve_is_super(get_exec_env()))
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
	char *release;
	int ret = 0;

	down_read(&ve->op_sem);

	if (!ve->ve_ns) {
		ret = -ENOENT;
		goto up_opsem;
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
		.write_u64		= ve_reatures_write,
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
		.name			= "os_release",
		.max_write_len		= __NEW_UTS_LEN + 1,
		.flags			= CFTYPE_NOT_ON_ROOT,
		.seq_show		= ve_os_release_read,
		.write			= ve_os_release_write,
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
	ve_cachep = KMEM_CACHE(ve_struct, SLAB_PANIC);
	list_add(&ve0.ve_list, &ve_list_head);
	return 0;
}
late_initcall(ve_subsys_init);

#ifdef CONFIG_CGROUP_SCHED
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
#endif /* CONFIG_CGROUP_SCHED */
