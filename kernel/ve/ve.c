/*
 *  linux/kernel/ve/ve.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

/*
 * 've.c' helper file performing VE sub-system initialization
 */

#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/capability.h>
#include <linux/ve.h>
#include <linux/init.h>

#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/sys.h>
#include <linux/kdev_t.h>
#include <linux/termios.h>
#include <linux/tty_driver.h>
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

#include <linux/vzcalluser.h>
#include <linux/venet.h>

static struct kmem_cache *ve_cachep;

unsigned long vz_rstamp = 0x37e0f59d;
EXPORT_SYMBOL(vz_rstamp);

#ifdef CONFIG_MODULES
struct module no_module = { .state = MODULE_STATE_GOING };
EXPORT_SYMBOL(no_module);
#endif

int glob_ve_meminfo = 0;
int ve_allow_kthreads = 1;

struct kmapset_set ve_sysfs_perms;

static DEFINE_PER_CPU(struct kstat_lat_pcpu_snap_struct, ve0_lat_stats);

struct ve_struct ve0 = {
	.ve_name		= "0",
	.start_jiffies		= INITIAL_JIFFIES,
	.ve_ns			= &init_nsproxy,
	.ve_netns		= &init_net,
	.is_running		= 1,
#ifdef CONFIG_VE_IPTABLES
	.ipt_mask		= VE_IP_ALL,	/* everything is allowed */
	._iptables_modules	= VE_IP_NONE,	/* but nothing yet loaded */
#endif
	.features		= -1,
	.meminfo_val		= VE_MEMINFO_SYSTEM,
	._randomize_va_space	=
#ifdef CONFIG_COMPAT_BRK
					1,
#else
					2,
#endif
	.sched_lat_ve.cur	= &ve0_lat_stats,
	.init_cred		= &init_cred,
};

EXPORT_SYMBOL(ve0);

LIST_HEAD(ve_list_head);
DEFINE_MUTEX(ve_list_lock);

int nr_ve = 1;	/* One VE always exists. Compatibility with vestat */
EXPORT_SYMBOL(nr_ve);

static void ve_list_add(struct ve_struct *ve)
{
	mutex_lock(&ve_list_lock);
	/* FIXME temporary hack */
	while (__find_ve_by_id(ve->veid))
		ve->veid--;
	list_add(&ve->ve_list, &ve_list_head);
	nr_ve++;
	mutex_unlock(&ve_list_lock);
}

static void ve_list_del(struct ve_struct *ve)
{
	mutex_lock(&ve_list_lock);
	list_del(&ve->ve_list);
	nr_ve--;
	mutex_unlock(&ve_list_lock);
}

const char *__ve_name(struct ve_struct *ve)
{
	if (unlikely(!ve->ve_name))
		return ve->css.cgroup->dentry->d_name.name;

	return ve->ve_name;
}
EXPORT_SYMBOL(__ve_name);

/* caller provides refrence to ve-struct */
const char *ve_name(struct ve_struct *ve)
{
	return ve->ve_name;
}
EXPORT_SYMBOL(ve_name);

void legacy_veid_to_name(envid_t veid, char *name)
{
	snprintf(name, VE_LEGACY_NAME_MAXLEN, "%u", veid);
}
EXPORT_SYMBOL(legacy_veid_to_name);

/* under rcu_read_lock if task != current */
const char *task_ve_name(struct task_struct *task)
{
	return rcu_dereference_check(task->task_ve, task == current)->ve_name;
}
EXPORT_SYMBOL(task_ve_name);

struct ve_struct *__find_ve_by_id(envid_t veid)
{
	struct ve_struct *ve;

	for_each_ve(ve) {
		if (ve->veid == veid)
			return ve;
	}
	return NULL;
}
EXPORT_SYMBOL(__find_ve_by_id);

struct ve_struct *get_ve_by_id(envid_t veid)
{
	struct ve_struct *ve;
	mutex_lock(&ve_list_lock);
	ve = __find_ve_by_id(veid);
	get_ve(ve);
	mutex_unlock(&ve_list_lock);
	return ve;
}
EXPORT_SYMBOL(get_ve_by_id);

struct ve_struct *get_ve_by_name(const char *name)
{
	struct ve_struct *ve;

	mutex_lock(&ve_list_lock);
	list_for_each_entry(ve, &ve_list_head, ve_list) {
		if (!ve->ve_name || strcmp(ve->ve_name, name))
			continue;
		get_ve(ve);
		mutex_unlock(&ve_list_lock);
		return ve;
	}
	mutex_unlock(&ve_list_lock);
	return NULL;
}
EXPORT_SYMBOL(get_ve_by_name);

EXPORT_SYMBOL(ve_list_lock);
EXPORT_SYMBOL(ve_list_head);

int vz_security_family_check(struct net *net, int family)
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
	case  IPPROTO_TCP:
	case  IPPROTO_UDP:
	case  IPPROTO_RAW:
	case  IPPROTO_DCCP:
	case  IPPROTO_GRE:
	case  IPPROTO_ESP:
	case  IPPROTO_AH:
		return 0;
	default:
		return -EAFNOSUPPORT;
	}
}
EXPORT_SYMBOL_GPL(vz_security_protocol_check);

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

	ve->init_cred = (struct cred *)get_current_cred();
	ve->ve_ns = get_nsproxy(tsk->nsproxy);
	ve->ve_netns =  get_net(ve->ve_ns->net_ns);
	get_fs_root(tsk->fs, &ve->root_path);
}

static void ve_drop_context(struct ve_struct *ve)
{
	path_put(&ve->root_path);
	ve->root_path.mnt = NULL;
	ve->root_path.dentry = NULL;

	put_net(ve->ve_netns);
	ve->ve_netns = NULL;

	put_nsproxy(ve->ve_ns);
	ve->ve_ns = NULL;

	put_cred(ve->init_cred);
	ve->init_cred = NULL;
}

/* under ve->op_sem write-lock */
int ve_start_container(struct ve_struct *ve)
{
	struct task_struct *tsk = current;
	int err;

	if (ve->is_running || ve->ve_ns)
		return -EBUSY;

	if (tsk->task_ve != ve || !is_child_reaper(task_pid(tsk)))
		return -ECHILD;

	ve->start_timespec = tsk->start_time;
	ve->real_start_timespec = tsk->real_start_time;
	/* The value is wrong, but it is never compared to process
	 * start times */
	ve->start_jiffies = get_jiffies_64();

	ve_grab_context(ve);
	ve_list_add(ve);

	err = ve_start_kthread(ve);
	if (err)
		goto err_kthread;

	err = ve_hook_iterate_init(VE_SS_CHAIN, ve);
	if (err < 0)
		goto err_iterate;

	cgroup_lock();
	ve->is_running = 1;
	cgroup_unlock();

	printk(KERN_INFO "CT: %s: started\n", ve_name(ve));

	get_ve(ve); /* for ve_exit_ns() */

	return 0;

err_iterate:
	ve_stop_kthread(ve);
err_kthread:
	ve_list_del(ve);
	ve_drop_context(ve);
	return err;
}
EXPORT_SYMBOL_GPL(ve_start_container);

void ve_stop_ns(struct pid_namespace *pid_ns)
{
	struct ve_struct *ve = current->task_ve;

	/*
	 * current->cgroups already switched to init_css_set in cgroup_exit(),
	 * but current->task_ve still points to our exec ve.
	 */
	if (!ve->ve_ns || ve->ve_ns->pid_ns != pid_ns)
		return;

	down_write(&ve->op_sem);
	/*
	 * Here the VE changes its state into "not running".
	 * op_sem works as barrier for vzctl ioctls.
	 * cgroup_mutex works as barrier for ve_can_attach().
	 */
	cgroup_lock();
	ve->is_running = 0;
	cgroup_unlock();
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

	/*
	 * At this point all userspace tasks in container are dead.
	 */

	if (ve->devpts_sb) {
		deactivate_super(ve->devpts_sb);
		ve->devpts_sb = NULL;
	}

	down_write(&ve->op_sem);
	ve_hook_iterate_fini(VE_SS_CHAIN, ve);
#ifdef CONFIG_INET
	tcp_v4_kill_ve_sockets(ve);
	synchronize_net();
#endif
	ve_list_del(ve);
	ve_drop_context(ve);
	up_write(&ve->op_sem);

	printk(KERN_INFO "CT: %s: stopped\n", ve_name(ve));

	put_ve(ve); /* from ve_start_container() */
}

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

	ve->sched_lat_ve.cur = alloc_percpu(struct kstat_lat_pcpu_snap_struct);
	if (!ve->sched_lat_ve.cur)
		goto err_lat;

	err = ve_log_init(ve);
	if (err)
		goto err_log;

do_init:
	init_rwsem(&ve->op_sem);
	mutex_init(&ve->sync_mutex);
	INIT_LIST_HEAD(&ve->devices);
	ve->meminfo_val = VE_MEMINFO_DEFAULT;
	kmapset_init_key(&ve->ve_sysfs_perms);

	return &ve->css;

err_log:
	free_percpu(ve->sched_lat_ve.cur);
err_lat:
	kmem_cache_free(ve_cachep, ve);
err_ve:
	return ERR_PTR(err);
}

static void ve_destroy(struct cgroup *cg)
{
	struct ve_struct *ve = cgroup_ve(cg);

	ve_log_destroy(ve);
	kfree(ve->binfmt_misc);
	free_percpu(ve->sched_lat_ve.cur);
	kfree(ve->ve_name);
	kmem_cache_free(ve_cachep, ve);
}

static int ve_can_attach(struct cgroup *cg, struct cgroup_taskset *tset)
{
	struct ve_struct *ve = cgroup_ve(cg);
	struct task_struct *task = current;

	if (cgroup_taskset_size(tset) != 1 ||
	    cgroup_taskset_first(tset) != task ||
	    !thread_group_leader(task) ||
	    !thread_group_empty(task))
		return -EINVAL;

	if (ve->is_locked)
		return -EBUSY;

	/*
	 * Forbid userspace tasks to enter during starting or stopping.
	 * Permit attaching kernel threads and init task for this containers.
	 */
	if (!ve->is_running && (ve->ve_ns || nr_threads_ve(ve)) &&
			!(task->flags & PF_KTHREAD))
		return -EPIPE;

	if (!ve->ve_name) {
		ve->ve_name = kstrdup(cg->dentry->d_name.name, GFP_KERNEL);
		if (!ve->ve_name)
			return -ENOMEM;
	}

	return 0;
}

static void ve_attach(struct cgroup *cg, struct cgroup_taskset *tset)
{
	struct ve_struct *ve = cgroup_ve(cg);
	struct task_struct *tsk = current;

	/* this probihibts ptracing of task entered to VE from host system */
	if (tsk->mm)
		tsk->mm->vps_dumpable = 0;

	/* Drop OOM protection. */
	tsk->signal->oom_score_adj = 0;
	tsk->signal->oom_score_adj_min = 0;

	/* Leave parent exec domain */
	tsk->parent_exec_id--;

	tsk->task_ve = ve;
}

static int ve_state_read(struct cgroup *cg, struct cftype *cft,
			 struct seq_file *m)
{
	struct ve_struct *ve = cgroup_ve(cg);

	if (ve->is_running)
		seq_puts(m, "RUNNING");
	else if (!nr_threads_ve(ve))
		seq_puts(m, "STOPPED");
	else if (ve->ve_ns)
		seq_puts(m, "STOPPING");
	else
		seq_puts(m, "STARTING");
	seq_putc(m, '\n');

	return 0;
}

static int ve_state_write(struct cgroup *cg, struct cftype *cft,
			  const char *buffer)
{
	struct ve_struct *ve = cgroup_ve(cg);
	int ret = -EINVAL;

	if (!strcmp(buffer, "START")) {
		down_write(&ve->op_sem);
		ret = ve_start_container(ve);
		up_write(&ve->op_sem);
	}

	kmapset_unlink(&ve->ve_sysfs_perms, &ve_sysfs_perms);

	return ret;
}

static int ve_legacy_veid_read(struct cgroup *cg, struct cftype *cft,
		struct seq_file *m)
{
	struct ve_struct *ve = cgroup_ve(cg);

	if (!ve->is_running)
		return -EPIPE;

	return seq_printf(m, "%u\n", ve->veid);
}

static struct cftype ve_cftypes[] = {
	{
		.name = "state",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_seq_string = ve_state_read,
		.write_string = ve_state_write,
	},
	{
		.name = "legacy_veid",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_seq_string = ve_legacy_veid_read,
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
	kmapset_init_set(&ve_sysfs_perms);
	return 0;
}
late_initcall(ve_subsys_init);
