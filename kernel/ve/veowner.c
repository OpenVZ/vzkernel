/*
 *  kernel/ve/veowner.c
 *
 *  Copyright (c) 2000-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/ve.h>
#include <linux/ve_proto.h>
#include <linux/ipc.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/inetdevice.h>
#include <linux/pid_namespace.h>
#include <linux/xattr.h>
#include <asm/io.h>

#include <net/tcp.h>

/*
 * ------------------------------------------------------------------------
 * proc entries
 * ------------------------------------------------------------------------
 */

#ifdef CONFIG_PROC_FS
struct proc_dir_entry *proc_vz_dir;
EXPORT_SYMBOL(proc_vz_dir);

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
		panic("Can't create /proc/vz dir\n");

	/* Legacy files. They are not really needed and should be removed
	 * sooner or later, but leave the stubs for now as they may be required
	 * by userspace */

	proc_mkdir_mode("fairsched", 0, proc_vz_dir);

	proc_create("fairsched", S_ISVTX, NULL,	&proc_fairsched_operations);
	proc_create("fairsched2", S_ISVTX, NULL, &proc_fairsched_operations);
}
#endif

/*
 * ------------------------------------------------------------------------
 * OpenVZ sysctl
 * ------------------------------------------------------------------------
 */

/*
 * Operations with a big amount of mount points can require a lot of time.
 * These operations take the global lock namespace_sem, so they can affect
 * other containers. Let us allow no more than sysctl_ve_mount_nr mount
 * points for a VE.
 */
unsigned int sysctl_ve_mount_nr = 4096;
static int ve_mount_nr_min = 0;
static int ve_mount_nr_max = INT_MAX;

static struct ctl_table vz_fs_table[] = {
	{
		.procname	= "fsync-enable",
		.data		= &ve0.fsync_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644 | S_ISVTX,
		.proc_handler	= &proc_dointvec_virtual,
	},
	{
		.procname       = "ve-mount-nr",
		.data           = &sysctl_ve_mount_nr,
		.maxlen         = sizeof(sysctl_ve_mount_nr),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1		= &ve_mount_nr_min,
		.extra2		= &ve_mount_nr_max,
	},
	{ 0 }
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

void init_ve_system(void)
{
#ifdef CONFIG_PROC_FS
	prepare_proc();
#endif
	prepare_sysctl();
}
