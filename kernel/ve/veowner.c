/*
 *  kernel/ve/veowner.c
 *
 *  Copyright (c) 2000-2017 Virtuozzo International GmbH.  All rights reserved.
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

/*
 * ------------------------------------------------------------------------
 * proc entries
 * ------------------------------------------------------------------------
 */

#ifdef CONFIG_PROC_FS
struct proc_dir_entry *proc_vz_dir;
EXPORT_SYMBOL(proc_vz_dir);
struct proc_dir_entry *bc_proc_root;
EXPORT_SYMBOL(bc_proc_root);

static int proc_fairsched_open(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t proc_fairsched_read(struct file *file, char __user *buf,
				   size_t size, loff_t *ppos)
{
	return 0;
}

static struct file_operations proc_fairsched_operations = {
	.open		= proc_fairsched_open,
	.read		= proc_fairsched_read,
	.llseek		= noop_llseek,
};

static void prepare_proc(void)
{
	proc_vz_dir = proc_mkdir_mode("vz", S_ISVTX | S_IRUGO | S_IXUGO, NULL);
	if (!proc_vz_dir)
		panic("Can't create /proc/vz dir");

	bc_proc_root = proc_mkdir_mode("bc", 0, NULL);
        if (!bc_proc_root)
                panic("Can't create /proc/bc entry");


	/* Legacy files. They are not really needed and should be removed
	 * sooner or later, but leave the stubs for now as they may be required
	 * by userspace: https://jira.sw.ru/browse/PSBM-79882 */

	proc_create("fairsched", S_ISVTX, NULL,	&proc_fairsched_operations);
	proc_create("fairsched2", S_ISVTX, NULL, &proc_fairsched_operations);
}
#endif

/*
 * ------------------------------------------------------------------------
 * OpenVZ sysctl
 * ------------------------------------------------------------------------
 */

static struct ctl_table vz_fs_table[] = {
	{ }
};

static struct ctl_path fs_path[] = {
	{ .procname = "fs", },
	{ }
};

static void prepare_sysctl(void)
{
	register_sysctl_paths(fs_path, vz_fs_table);
}

/*
 * ------------------------------------------------------------------------
 * XXX init_ve_system
 * ------------------------------------------------------------------------
 */

void __init init_ve_system(void)
{
#ifdef CONFIG_PROC_FS
	prepare_proc();
#endif
	prepare_sysctl();
}
