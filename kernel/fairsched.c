/*
 * Fair Scheduler
 *
 * Copyright (C) 2000-2008  SWsoft
 * All rights reserved.
 *
 * Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/module.h>
#include <linux/err.h>
#include <linux/mount.h>
#include <linux/cgroup.h>
#include <linux/cpumask.h>
#include <linux/cpuset.h>
#include <linux/pid_namespace.h>
#include <linux/syscalls.h>
#include <linux/fairsched.h>
#include <linux/ve.h>
#include <linux/uaccess.h>

struct fairsched_node {
	struct cgroup *cpu;
	struct cgroup *cpuset;
};

static struct fairsched_node root_node = {NULL, NULL};

/* fairsched use node id = INT_MAX for ve0 tasks */
#define FAIRSCHED_HOST_NODE 2147483647

#define fairsched_id(id) (id == FAIRSCHED_HOST_NODE ? 0 : id)

static int fairsched_open(struct fairsched_node *node, int id)
{
	envid_t veid = fairsched_id(id);

	node->cpu = ve_cgroup_open(root_node.cpu, 0, veid);
	if (IS_ERR(node->cpu))
		return PTR_ERR(node->cpu);

	node->cpuset = ve_cgroup_open(root_node.cpuset, 0, veid);
	if (IS_ERR(node->cpuset)) {
		cgroup_kernel_close(node->cpu);
		return PTR_ERR(node->cpuset);
	}
	return 0;
}

static int fairsched_create(struct fairsched_node *node, int id)
{
	envid_t veid = fairsched_id(id);
	int err;

	node->cpu = ve_cgroup_open(root_node.cpu, CGRP_CREAT|CGRP_EXCL, veid);
	if (IS_ERR(node->cpu))
		return PTR_ERR(node->cpu);

	node->cpuset = ve_cgroup_open(root_node.cpuset, CGRP_CREAT, veid);
	if (IS_ERR(node->cpuset)) {
		cgroup_kernel_close(node->cpu);
		err = ve_cgroup_remove(root_node.cpu, veid);
		if (err)
			printk(KERN_ERR "Cleanup error, fairsched id=%d, err=%d\n", id, err);
		return PTR_ERR(node->cpuset);
	}
	return 0;
}

static int fairsched_remove(int id)
{
	envid_t veid = fairsched_id(id);
	int ret;

	ret = ve_cgroup_remove(root_node.cpuset, veid);
	if (ret < 0)
		return ret;

	return ve_cgroup_remove(root_node.cpu, veid);
}

static int fairsched_move(struct fairsched_node *node, struct task_struct *tsk)
{
	int ret, err;

	ret = cgroup_kernel_attach(node->cpu, tsk);
	if (ret)
		return ret;

	ret = cgroup_kernel_attach(node->cpuset, tsk);
	if (ret) {
		err = cgroup_kernel_attach(root_node.cpu, tsk);
		if (err)
			printk(KERN_ERR "Cleanup error, fairsched id=, err=%d\n", err);
	}
	return ret;
}

static void fairsched_close(struct fairsched_node *node)
{
	cgroup_kernel_close(node->cpu);
	cgroup_kernel_close(node->cpuset);
}

SYSCALL_DEFINE3(fairsched_mknod, unsigned int, parent, unsigned int, weight,
				 unsigned int, newid)
{
	int retval;
	struct fairsched_node node;

	if (!capable_setveid())
		return -EPERM;

	retval = -EINVAL;
	if (weight < 1 || weight > FSCHWEIGHT_MAX)
		goto out;
	if (newid < 0 || newid > INT_MAX)
		goto out;

	retval = fairsched_create(&node, newid);
	if (retval)
		return retval;

	fairsched_close(&node);
	retval = newid;
out:
	return retval;
}

SYSCALL_DEFINE1(fairsched_rmnod, unsigned int, id)
{
	if (!capable_setveid())
		return -EPERM;

	return fairsched_remove(id);
}

SYSCALL_DEFINE2(fairsched_chwt, unsigned int, id, unsigned, weight)
{
	struct cgroup *cgrp;
	int retval;

	if (!capable_setveid())
		return -EPERM;

	if (id == 0)
		return -EINVAL;
	if (weight < 1 || weight > FSCHWEIGHT_MAX)
		return -EINVAL;

	cgrp = ve_cgroup_open(root_node.cpu, 0, fairsched_id(id));
	if (IS_ERR(cgrp))
		return PTR_ERR(cgrp);

	retval = sched_cgroup_set_shares(cgrp, FSCHWEIGHT_BASE / weight);
	cgroup_kernel_close(cgrp);

	return retval;
}

SYSCALL_DEFINE2(fairsched_vcpus, unsigned int, id, unsigned int, vcpus)
{
	struct cgroup *cgrp;
	int retval = 0;

	if (!capable_setveid())
		return -EPERM;

	if (id == 0)
		return -EINVAL;

	cgrp = ve_cgroup_open(root_node.cpu, 0, fairsched_id(id));
	if (IS_ERR(cgrp))
		return PTR_ERR(cgrp);

	retval = sched_cgroup_set_nr_cpus(cgrp, vcpus);
	cgroup_kernel_close(cgrp);

	return retval;
}

SYSCALL_DEFINE3(fairsched_rate, unsigned int, id, int, op, unsigned, rate)
{
	struct cgroup *cgrp;
	long ret;

	if (!capable_setveid())
		return -EPERM;

	if (id == 0)
		return -EINVAL;
	if (op == FAIRSCHED_SET_RATE && (rate < 1 || rate >= (1UL << 31)))
		return -EINVAL;

	cgrp = ve_cgroup_open(root_node.cpu, 0, fairsched_id(id));
	if (IS_ERR(cgrp))
		return PTR_ERR(cgrp);

	switch (op) {
		case FAIRSCHED_SET_RATE:
			ret = sched_cgroup_set_rate(cgrp, rate);
			if (!ret)
				ret = sched_cgroup_get_rate(cgrp);
			break;
		case FAIRSCHED_DROP_RATE:
			ret = sched_cgroup_set_rate(cgrp, 0);
			break;
		case FAIRSCHED_GET_RATE:
			ret = sched_cgroup_get_rate(cgrp);
			if (!ret)
				ret = -ENODATA;
			break;
		default:
			ret = -EINVAL;
			break;
	}
	cgroup_kernel_close(cgrp);

	return ret;
}

SYSCALL_DEFINE2(fairsched_mvpr, pid_t, pid, unsigned int, id)
{
	struct task_struct *tsk;
	struct fairsched_node node = {NULL, NULL};
	int retval;

	if (!capable_setveid())
		return -EPERM;

	retval = fairsched_open(&node, id);
	if (retval)
		return retval;

	write_lock_irq(&tasklist_lock);
	tsk = find_task_by_vpid(pid);
	if (tsk == NULL) {
		write_unlock_irq(&tasklist_lock);
		retval = -ESRCH;
		goto out;
	}
	get_task_struct(tsk);
	write_unlock_irq(&tasklist_lock);


	retval = fairsched_move(&node, tsk);

	put_task_struct(tsk);
out:
	fairsched_close(&node);
	return retval;
}

static int get_user_cpu_mask(unsigned long __user *user_mask_ptr, unsigned len,
			     struct cpumask *new_mask)
{
	if (len < cpumask_size())
		cpumask_clear(new_mask);
	else if (len > cpumask_size())
		len = cpumask_size();

	return copy_from_user(new_mask, user_mask_ptr, len) ? -EFAULT : 0;
}

SYSCALL_DEFINE3(fairsched_cpumask, unsigned int, id, unsigned int, len,
		unsigned long __user *, user_mask_ptr)
{
	struct cgroup *cgrp;
	int retval;
	cpumask_var_t new_mask, in_mask;

	if (!capable_setveid())
		return -EPERM;

	if (id == 0)
		return -EINVAL;

	cgrp = ve_cgroup_open(root_node.cpuset, 0, fairsched_id(id));
	if (IS_ERR(cgrp))
		return PTR_ERR(cgrp);

	if (!alloc_cpumask_var(&in_mask, GFP_KERNEL)) {
		retval = -ENOMEM;
		goto out;
	}
	if (!alloc_cpumask_var(&new_mask, GFP_KERNEL)) {
		retval = -ENOMEM;
		goto out_free_in_mask;
	}

	retval = get_user_cpu_mask(user_mask_ptr, len, in_mask);
	if (retval == 0) {
		cpumask_and(new_mask, in_mask, cpu_active_mask);
		retval = cgroup_set_cpumask(cgrp, new_mask);
	}

	free_cpumask_var(new_mask);

out_free_in_mask:
	free_cpumask_var(in_mask);
out:
	cgroup_kernel_close(cgrp);
	return retval;
}

static int get_user_node_mask(unsigned long __user *user_mask_ptr, unsigned len,
			      nodemask_t *new_mask)
{
	if (len < sizeof(nodemask_t))
		nodes_clear(*new_mask);
	else if (len > sizeof(nodemask_t))
		len = sizeof(nodemask_t);

	return copy_from_user(new_mask, user_mask_ptr, len) ? -EFAULT : 0;
}

SYSCALL_DEFINE3(fairsched_nodemask, unsigned int, id, unsigned int, len,
		unsigned long __user *, user_mask_ptr)
{
	struct cgroup *cgrp;
	int retval;
	nodemask_t new_mask, in_mask;

	if (!capable_setveid())
		return -EPERM;

	if (id == 0)
		return -EINVAL;

	cgrp = ve_cgroup_open(root_node.cpuset, 0, fairsched_id(id));
	if (IS_ERR(cgrp))
		return PTR_ERR(cgrp);
	if (cgrp == NULL)
		return -ENOENT;

	retval = get_user_node_mask(user_mask_ptr, len, &in_mask);
	if (retval == 0) {
		nodes_and(new_mask, in_mask, node_states[N_HIGH_MEMORY]);
		retval = cgroup_set_nodemask(cgrp, &new_mask);
	}

	cgroup_kernel_close(cgrp);
	return retval;
}

int fairsched_new_node(int id, unsigned int vcpus)
{
	struct fairsched_node node = {NULL, NULL};
	int err;

	err = fairsched_create(&node, id);
	if (err < 0)
		return err;

	err = sched_cgroup_set_nr_cpus(node.cpu, vcpus);
	if (err) {
		printk(KERN_ERR "Can't set sched vcpus on node %d err=%d\n", id, err);
		goto err_remove;
	}

	err = fairsched_move(&node, current);
	if (err)
		goto err_remove;

	fairsched_close(&node);
	return 0;

err_remove:
	fairsched_close(&node);
	fairsched_remove(id);
	return err;
}
EXPORT_SYMBOL(fairsched_new_node);

void fairsched_drop_node(int id, int leave)
{
	int err;

	if (leave) {
		err = fairsched_move(&root_node, current);
		if (err)
			printk(KERN_ERR "Can't leave fairsched node %d "
					"err=%d\n", id, err);
	}

	err = fairsched_remove(id);
	if (err)
		printk(KERN_ERR "Can't remove fairsched node %d err=%d\n", id, err);
}
EXPORT_SYMBOL(fairsched_drop_node);

int fairsched_move_task(int id, struct task_struct *tsk)
{
	struct fairsched_node node = {NULL, NULL};
	int err;

	err = fairsched_open(&node, id);
	if (err)
		return err;

	err = fairsched_move(&node, tsk);
	fairsched_close(&node);
	return err;
}

EXPORT_SYMBOL(fairsched_move_task);

#ifdef CONFIG_PROC_FS

/*********************************************************************/
/*
 * proc interface
 */
/*********************************************************************/

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>

struct fairsched_node_dump {
	int id;
	unsigned weight;
	unsigned rate;
	int nr_pcpu;
	int nr_tasks, nr_runtasks;
};

struct fairsched_dump {
	int len;
	struct fairsched_node_dump nodes[0];
};

static struct fairsched_dump *fairsched_do_dump(int compat)
{
	struct fairsched_dump *dump;
	struct fairsched_node_dump *p;
	int nr_nodes;
	struct dentry *root, *dentry;
	struct cgroup *cgrp;
	struct ve_struct *ve = get_exec_env();
	int id;

	root = root_node.cpu->dentry;
	mutex_lock(&root->d_inode->i_mutex);

	spin_lock(&root->d_lock);
	nr_nodes = 0;
	list_for_each_entry(dentry, &root->d_subdirs, d_u.d_child) {
		if (d_unhashed(dentry) || !dentry->d_inode ||
				!S_ISDIR(dentry->d_inode->i_mode))
			continue;
		nr_nodes++;
	}
	spin_unlock(&root->d_lock);

	nr_nodes = ve_is_super(get_exec_env()) ? nr_nodes + 16 : 1;

	dump = vmalloc(sizeof(*dump) + nr_nodes * sizeof(dump->nodes[0]));
	if (dump == NULL)
		goto out;

	spin_lock(&root->d_lock);

	p = dump->nodes;
	list_for_each_entry_reverse(dentry, &root->d_subdirs, d_u.d_child) {
		if (d_unhashed(dentry) || !dentry->d_inode ||
				!S_ISDIR(dentry->d_inode->i_mode))
			continue;
		if (legacy_name_to_veid(dentry->d_name.name, &id) < 0)
			continue;
		if (!ve_is_super(ve) &&
		    strcmp(ve_name(ve), dentry->d_name.name))
			continue;
		cgrp = dentry->d_fsdata; /* __d_cgrp */
		p->id = id;
		p->nr_tasks = cgroup_task_count(cgrp);
		p->nr_runtasks = sched_cgroup_get_nr_running(cgrp);
		p->weight = FSCHWEIGHT_BASE / sched_cgroup_get_shares(cgrp);
		p->nr_pcpu = num_online_cpus();
		p->rate = sched_cgroup_get_rate(cgrp);
		p++;
		if (!--nr_nodes)
			break;
	}
	dump->len = p - dump->nodes;

	spin_unlock(&root->d_lock);
out:
	mutex_unlock(&root->d_inode->i_mutex);
	return dump;
}

#define FAIRSCHED_PROC_HEADLINES 2

#define FAIRSHED_DEBUG          " debug"

#ifdef CONFIG_VE
/*
 * File format is dictated by compatibility reasons.
 */
static int fairsched_seq_show(struct seq_file *m, void *v)
{
	struct fairsched_dump *dump;
	struct fairsched_node_dump *p;
	unsigned vid, nid, pid, r;

	dump = m->private;
	p = (struct fairsched_node_dump *)((unsigned long)v & ~3UL);
	if (p - dump->nodes < FAIRSCHED_PROC_HEADLINES) {
		if (p == dump->nodes)
			seq_printf(m, "Version: 2.6 debug\n");
		else if (p == dump->nodes + 1)
			seq_printf(m,
				       "      veid "
				       "        id "
				       "    parent "
				       "weight "
				       " rate "
				       "tasks "
				       "  run "
				       "cpus"
				       " "
				       "flg "
				       "ready "
				       "           start_tag "
				       "               value "
				       "               delay"
				       "\n");
	} else {
		p -= FAIRSCHED_PROC_HEADLINES;
		vid = nid = pid = 0;
		r = (unsigned long)v & 3;
		if (p == dump->nodes) {
			if (r == 2)
				nid = p->id;
		} else {
			if (!r)
				nid = p->id;
			else if (r == 1)
				vid = pid = p->id;
			else
				vid = p->id, nid = 1;
		}
		seq_printf(m,
			       "%10u "
			       "%10u %10u %6u %5u %5u %5u %4u"
			       " "
			       " %c%c %5u %20Lu %20Lu %20Lu"
			       "\n",
			       vid,
			       nid,
			       pid,
			       p->weight,
			       p->rate,
			       p->nr_tasks,
			       p->nr_runtasks,
			       p->nr_pcpu,
			       p->rate ? 'L' : '.',
			       '.',
			       p->nr_runtasks,
			       0ll, 0ll, 0ll);
	}

	return 0;
}

static void *fairsched_seq_start(struct seq_file *m, loff_t *pos)
{
	struct fairsched_dump *dump;
	unsigned long l;

	dump = m->private;
	if (*pos >= dump->len * 3 - 1 + FAIRSCHED_PROC_HEADLINES)
		return NULL;
	if (*pos < FAIRSCHED_PROC_HEADLINES)
		return dump->nodes + *pos;
	/* guess why... */
	l = (unsigned long)(dump->nodes +
		((unsigned long)*pos + FAIRSCHED_PROC_HEADLINES * 2 + 1) / 3);
	l |= ((unsigned long)*pos + FAIRSCHED_PROC_HEADLINES * 2 + 1) % 3;
	return (void *)l;
}
static void *fairsched_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return fairsched_seq_start(m, pos);
}
#endif /* CONFIG_VE */

static int fairsched2_seq_show(struct seq_file *m, void *v)
{
	struct fairsched_dump *dump;
	struct fairsched_node_dump *p;

	dump = m->private;
	p = v;
	if (p - dump->nodes < FAIRSCHED_PROC_HEADLINES) {
		if (p == dump->nodes)
			seq_printf(m, "Version: 2.7" FAIRSHED_DEBUG "\n");
		else if (p == dump->nodes + 1)
			seq_printf(m,
				       "        id "
				       "weight "
				       " rate "
				       "  run "
				       "cpus"
#ifdef FAIRSHED_DEBUG
				       " "
				       "flg "
				       "ready "
				       "           start_tag "
				       "               value "
				       "               delay"
#endif
				       "\n");
	} else {
		p -= FAIRSCHED_PROC_HEADLINES;
		seq_printf(m,
			       "%10u %6u %5u %5u %4u"
#ifdef FAIRSHED_DEBUG
			       " "
			       " %c%c %5u %20Lu %20Lu %20Lu"
#endif
			       "\n",
			       p->id,
			       p->weight,
			       p->rate,
			       p->nr_runtasks,
			       p->nr_pcpu
#ifdef FAIRSHED_DEBUG
			       ,
			       p->rate ? 'L' : '.',
			       '.',
			       p->nr_runtasks,
			       0ll, 0ll, 0ll
#endif
			       );
	}

	return 0;
}

static void *fairsched2_seq_start(struct seq_file *m, loff_t *pos)
{
	struct fairsched_dump *dump;

	dump = m->private;
	if (*pos >= dump->len + FAIRSCHED_PROC_HEADLINES)
		return NULL;
	return dump->nodes + *pos;
}
static void *fairsched2_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return fairsched2_seq_start(m, pos);
}
static void fairsched2_seq_stop(struct seq_file *m, void *v)
{
}

#ifdef CONFIG_VE
static struct seq_operations fairsched_seq_op = {
	.start		= fairsched_seq_start,
	.next		= fairsched_seq_next,
	.stop		= fairsched2_seq_stop,
	.show		= fairsched_seq_show
};
#endif
static struct seq_operations fairsched2_seq_op = {
	.start		= fairsched2_seq_start,
	.next		= fairsched2_seq_next,
	.stop		= fairsched2_seq_stop,
	.show		= fairsched2_seq_show
};
static int fairsched_seq_open(struct inode *inode, struct file *file)
{
	int ret;
	struct seq_file *m;
	int compat;

#ifdef CONFIG_VE
	compat = (file->f_dentry->d_name.len == sizeof("fairsched") - 1);
	ret = seq_open(file, compat ? &fairsched_seq_op : &fairsched2_seq_op);
#else
	compat = 0;
	ret = seq_open(file, &fairsched2_seq_op);
#endif
	if (ret)
		return ret;
	m = file->private_data;
	m->private = fairsched_do_dump(compat);
	if (m->private == NULL) {
		seq_release(inode, file);
		ret = -ENOMEM;
	}
	return ret;
}
static int fairsched_seq_release(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	struct fairsched_dump *dump;

	m = file->private_data;
	dump = m->private;
	m->private = NULL;
	vfree(dump);
	seq_release(inode, file);
	return 0;
}
static struct file_operations proc_fairsched_operations = {
	.open		= fairsched_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= fairsched_seq_release
};

int fairsched_show_stat(const char *name, struct seq_file *p)
{
	struct cgroup *cgrp;
	int err;

	cgrp = cgroup_kernel_open(root_node.cpu, 0, name);
	if (IS_ERR_OR_NULL(cgrp))
		return cgrp ? PTR_ERR(cgrp) : -ENOENT;

	err = cpu_cgroup_proc_stat(cgrp, NULL, p);
	cgroup_kernel_close(cgrp);

	return err;
}

int fairsched_show_loadavg(const char *name, struct seq_file *p)
{
	struct cgroup *cgrp;
	int err;

	cgrp = cgroup_kernel_open(root_node.cpu, 0, name);
	if (IS_ERR_OR_NULL(cgrp))
		return cgrp ? PTR_ERR(cgrp) : -ENOENT;

	err = cpu_cgroup_proc_loadavg(cgrp, NULL, p);
	cgroup_kernel_close(cgrp);

	return err;
}

int fairsched_get_cpu_avenrun(const char *name, unsigned long *avenrun)
{
	struct cgroup *cgrp;
	int err;

	cgrp = cgroup_kernel_open(root_node.cpu, 0, name);
	if (IS_ERR_OR_NULL(cgrp))
		return cgrp ? PTR_ERR(cgrp) : -ENOENT;

	err = cpu_cgroup_get_avenrun(cgrp, avenrun);
	cgroup_kernel_close(cgrp);

	return 0;
}
EXPORT_SYMBOL(fairsched_get_cpu_avenrun);

int fairsched_get_cpu_stat(const char *name, struct kernel_cpustat *kstat)
{
	struct cgroup *cgrp;

	cgrp = cgroup_kernel_open(root_node.cpu, 0, name);
	if (IS_ERR_OR_NULL(cgrp))
		return cgrp ? PTR_ERR(cgrp) : -ENOENT;

	cpu_cgroup_get_stat(cgrp, kstat);
	cgroup_kernel_close(cgrp);

	return 0;
}
EXPORT_SYMBOL(fairsched_get_cpu_stat);

#endif /* CONFIG_PROC_FS */

extern int sysctl_sched_rt_runtime;

int __init fairsched_init(void)
{
	struct vfsmount *cpu_mnt, *cpuset_mnt;
	struct cgroup_sb_opts cpu_opts = {
		.name		= vz_compat ? "fairsched" : NULL,
		.subsys_mask	=
			(1ul << cpu_cgroup_subsys_id) |
			(1ul << cpuacct_subsys_id),
	};

	struct cgroup_sb_opts cpuset_opts = {
		.subsys_mask	=
			(1ul << cpuset_subsys_id),
	};

	cpu_mnt = cgroup_kernel_mount(&cpu_opts);
	if (IS_ERR(cpu_mnt))
		return PTR_ERR(cpu_mnt);
	root_node.cpu = cgroup_get_root(cpu_mnt);

	cpuset_mnt = cgroup_kernel_mount(&cpuset_opts);
	if (IS_ERR(cpuset_mnt)) {
		kern_unmount(cpu_mnt);
		return PTR_ERR(cpuset_mnt);
	}
	root_node.cpuset = cgroup_get_root(cpuset_mnt);

#ifdef CONFIG_PROC_FS
	proc_create("fairsched", S_ISVTX, NULL,	&proc_fairsched_operations);
	proc_create("fairsched2", S_ISVTX, NULL, &proc_fairsched_operations);
	proc_mkdir_mode("fairsched", 0, proc_vz_dir);
#endif /* CONFIG_PROC_FS */
	return 0;
}
late_initcall(fairsched_init);
