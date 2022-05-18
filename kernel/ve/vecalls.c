/*
 *  kernel/ve/vecalls.c
 *
 *  Copyright (c) 2000-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

/*
 * 'vecalls.c' is file with basic VE support. It provides basic primities
 * along with initialization script
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/utsname.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <linux/mount.h>
#include <generated/utsrelease.h>

#include <linux/ve.h>
#include <linux/vecalls.h>
#include <linux/vzctl.h>
#include <linux/veowner.h>
#include <linux/device_cgroup.h>

/**********************************************************************
 **********************************************************************
 *
 * VE information via /proc
 *
 **********************************************************************
 **********************************************************************/
#ifdef CONFIG_PROC_FS
static void *ve_seq_start(struct seq_file *m, loff_t *pos)
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

static void *ve_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	if (!ve_is_super(get_exec_env())) {
		(*pos)++;
		return NULL;
	} else
		return seq_list_next(v, &ve_list_head, pos);
}

static void ve_seq_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&ve_list_lock);
}

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
		devcgroup_seq_show_ve(ve, m);

	return 0;
}

static struct seq_operations devperms_seq_op = {
	.start	= ve_seq_start,
	.next	= ve_seq_next,
	.stop	= ve_seq_stop,
	.show	= devperms_seq_show,
};

static int devperms_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &devperms_seq_op);
}

static struct proc_ops proc_devperms_ops = {
	.proc_open		= devperms_open,
	.proc_read		= seq_read,
	.proc_lseek		= seq_lseek,
	.proc_release		= seq_release,
};

static int vz_version_show(struct seq_file *file, void* v)
{
	static const char ver[] = VZVERSION "\n";

	seq_puts(file, ver);
	return 0;
}

static int vz_version_open(struct inode *inode, struct file *file)
{
	return single_open(file, vz_version_show, NULL);
}

static struct proc_ops proc_vz_version_operations = {
	.proc_open	= vz_version_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
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

	/* second 0 is deprecated ve->class_id */
	seq_printf(m, "%10s 0 %5u", ve_name(ve), nr_threads_ve(ve));

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

static struct proc_ops proc_veinfo_operations = {
	.proc_open	= veinfo_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release,
};

static int __init init_vecalls_proc(void)
{
	struct proc_dir_entry *de;

	de = proc_create("devperms", S_IFREG | S_IRUSR, proc_vz_dir,
			&proc_devperms_ops);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make devperms proc entry\n");

	de = proc_create("version", S_IFREG | S_IRUGO, proc_vz_dir,
			&proc_vz_version_operations);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make version proc entry\n");

	de = proc_create("veinfo", S_IFREG | S_IRUSR | S_ISVTX, proc_vz_dir,
			&proc_veinfo_operations);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make veinfo proc entry\n");

	return 0;
}

static void __exit fini_vecalls_proc(void)
{
	remove_proc_entry("devperms", proc_vz_dir);
	remove_proc_entry("version", proc_vz_dir);
	remove_proc_entry("veinfo", proc_vz_dir);
}
#else
#define init_vecalls_proc()	(0)
#define fini_vecalls_proc()	do { } while (0)
#endif /* CONFIG_PROC_FS */

static int ve_configure(envid_t veid, unsigned int key,
			unsigned int val, unsigned int size, char *data)
{
	struct ve_struct *ve;
	int err = -ENOKEY;

	ve = get_ve_by_id(veid);
	if (!ve)
		return -EINVAL;

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
	    case VZCTL_VE_CONFIGURE:
		err = ve_configure_ioctl((struct vzctl_ve_configure *)arg);
		break;
	}
	return err;
}

static struct vzioctlinfo vzcalls = {
	.type		= VZCTLTYPE,
	.ioctl		= vzcalls_ioctl,
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
	return err;
}

static void __exit vecalls_exit(void)
{
	fini_vecalls_ioctls();
	fini_vecalls_proc();
}

MODULE_AUTHOR("Virtuozzo <devel@openvz.org>");
MODULE_DESCRIPTION("Virtuozzo Control");
MODULE_LICENSE("GPL v2");

module_init(vecalls_init)
module_exit(vecalls_exit)
