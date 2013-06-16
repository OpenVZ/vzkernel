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

#include <linux/vzcalluser.h>

static struct kmem_cache *ve_cachep;

unsigned long vz_rstamp = 0x37e0f59d;
EXPORT_SYMBOL(vz_rstamp);

#ifdef CONFIG_MODULES
struct module no_module = { .state = MODULE_STATE_GOING };
EXPORT_SYMBOL(no_module);
#endif

static DEFINE_PER_CPU(struct kstat_lat_pcpu_snap_struct, ve0_lat_stats);

struct ve_struct ve0 = {
	.start_jiffies		= INITIAL_JIFFIES,
	.ve_ns			= &init_nsproxy,
	.ve_netns		= &init_net,
	.user_ns		= &init_user_ns,
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

unsigned task_veid(struct task_struct *task)
{
	return task->task_ve->veid;
}
EXPORT_SYMBOL(task_veid);

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

static struct cgroup_subsys_state *ve_create(struct cgroup *cg)
{
	struct ve_struct *ve = &ve0;

	if (!cg->parent)
		goto do_init;

	ve = kmem_cache_zalloc(ve_cachep, GFP_KERNEL);
	if (!ve)
		return ERR_PTR(-ENOMEM);
	ve->sched_lat_ve.cur = alloc_percpu(struct kstat_lat_pcpu_snap_struct);
	if (!ve->sched_lat_ve.cur) {
		kmem_cache_free(ve_cachep, ve);
		return ERR_PTR(-ENOMEM);
	}

do_init:
	init_rwsem(&ve->op_sem);
	mutex_init(&ve->sync_mutex);
	INIT_LIST_HEAD(&ve->devices);
	ve->meminfo_val = VE_MEMINFO_DEFAULT;

	return &ve->css;
}

static void ve_destroy(struct cgroup *cg)
{
	struct ve_struct *ve = cgroup_ve(cg);

	kfree(ve->binfmt_misc);
	free_percpu(ve->sched_lat_ve.cur);
	kmem_cache_free(ve_cachep, ve);
}

static int ve_can_attach(struct cgroup *cg, struct cgroup_taskset *tset)
{
	if (cgroup_taskset_size(tset) != 1 ||
	    cgroup_taskset_first(tset) != current)
		return -EBUSY;

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
	tsk->signal->oom_adj = 0;
	tsk->signal->oom_score_adj = 0;
	tsk->signal->oom_score_adj_min = 0;

	/* Leave parent exec domain */
	tsk->parent_exec_id--;

	tsk->task_ve = ve;
}

struct cgroup_subsys ve_subsys = {
	.name		= "ve",
	.subsys_id	= ve_subsys_id,
	.create		= ve_create,
	.destroy	= ve_destroy,
	.can_attach	= ve_can_attach,
	.attach		= ve_attach,
};

static int __init ve_subsys_init(void)
{
	ve_cachep = KMEM_CACHE(ve_struct, SLAB_PANIC);
	list_add(&ve0.ve_list, &ve_list_head);
	return 0;
}
late_initcall(ve_subsys_init);
