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

#include <uapi/linux/vzcalluser.h>
#include <linux/vziptable_defs.h>

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

EXPORT_SYMBOL(ve_list_lock);
EXPORT_SYMBOL(ve_list_head);

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
}

static void ve_drop_context(struct ve_struct *ve)
{
	put_net(ve->ve_netns);
	ve->ve_netns = NULL;

	/* Allows to dereference init_cred if ve_ns is set */
	put_nsproxy(ve->ve_ns);
	ve->ve_ns = NULL;

	put_cred(ve->init_cred);
	ve->init_cred = NULL;
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

	ve->start_timespec = tsk->start_time;
	ve->real_start_timespec = tsk->real_start_time;
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

	err = ve_hook_iterate_init(VE_SS_CHAIN, ve);
	if (err < 0)
		goto err_iterate;

	ve->is_running = 1;

	printk(KERN_INFO "CT: %s: started\n", ve_name(ve));

	get_ve(ve); /* for ve_exit_ns() */

	return 0;

err_iterate:
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

	down_write(&ve->op_sem);
	/*
	 * Here the VE changes its state into "not running".
	 * op_sem works as barrier for vzctl ioctls.
	 * ve_mutex works as barrier for ve_can_attach().
	 */
	ve->is_running = 0;

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

	/*
	 * At this point all userspace tasks in container are dead.
	 */

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

#ifdef CONFIG_VE_IPTABLES
	ve->ipt_mask = ve_setup_iptables_mask(VE_IP_DEFAULT);
#endif

	ve->sched_lat_ve.cur = alloc_percpu(struct kstat_lat_pcpu_snap_struct);
	if (!ve->sched_lat_ve.cur)
		goto err_lat;

	ve->meminfo_val = VE_MEMINFO_DEFAULT;

do_init:
	init_rwsem(&ve->op_sem);
	mutex_init(&ve->sync_mutex);
	INIT_LIST_HEAD(&ve->devices);
	INIT_LIST_HEAD(&ve->ve_list);
	INIT_LIST_HEAD(&ve->devmnt_list);
	mutex_init(&ve->devmnt_mutex);

	return &ve->css;

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

	free_ve_devmnts(ve);

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

		task->task_ve = ve;
	}
}

static int ve_state_read(struct cgroup *cg, struct cftype *cft,
			 struct seq_file *m)
{
	struct ve_struct *ve = cgroup_ve(cg);

	if (ve->is_running)
		seq_puts(m, "RUNNING");
	else if (!ve->init_task)
		seq_puts(m, "STOPPED");
	else if (ve->ve_ns)
		seq_puts(m, "STOPPING");
	else
		seq_puts(m, "STARTING");
	seq_putc(m, '\n');

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
};

static u64 ve_read_u64(struct cgroup *cg, struct cftype *cft)
{
	if (cft->private == VE_CF_FEATURES)
		return cgroup_ve(cg)->features;
#ifdef CONFIG_VE_IPTABLES
	else if (cft->private == VE_CF_IPTABLES_MASK)
		return cgroup_ve(cg)->ipt_mask;
#endif
	return 0;
}

static int ve_write_u64(struct cgroup *cg, struct cftype *cft, u64 value)
{
	struct ve_struct *ve = cgroup_ve(cg);

	if (!ve_is_super(get_exec_env()))
		return -EPERM;

	down_write(&ve->op_sem);
	if (ve->is_running || ve->ve_ns) {
		up_write(&ve->op_sem);
		return -EBUSY;
	}

	if (cft->private == VE_CF_FEATURES)
		ve->features = value;
#ifdef CONFIG_VE_IPTABLES
	else if (cft->private == VE_CF_IPTABLES_MASK)
		ve->ipt_mask = ve_setup_iptables_mask(value);
#endif
	up_write(&ve->op_sem);
	return 0;
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

static int __init ve_subsys_init(void)
{
	ve_cachep = KMEM_CACHE(ve_struct, SLAB_PANIC);
	list_add(&ve0.ve_list, &ve_list_head);
	return 0;
}
late_initcall(ve_subsys_init);
