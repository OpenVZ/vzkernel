/*
 *  kernel/ve/veowner.c
 *
 *  Copyright (c) 2000-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2021 Virtuozzo International GmbH. All rights reserved.
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

static void prepare_proc(void)
{
	proc_vz_dir = proc_mkdir_mode("vz", S_ISVTX | S_IRUGO | S_IXUGO, NULL);
	if (!proc_vz_dir)
		panic("Can't create /proc/vz dir");

	/*
	 * Can't easily drop this: without dropping /proc/vz dir
	 * systemd considers it's in a Container and Node does not boot.
	 * https://jira.sw.ru/browse/PSBM-127913
	 */
	bc_proc_root = proc_mkdir_mode("bc", 0, NULL);
        if (!bc_proc_root)
                panic("Can't create /proc/bc entry");
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
		.procname	= "ve-mount-nr",
		.data		= &sysctl_ve_mount_nr,
		.maxlen		= sizeof(sysctl_ve_mount_nr),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &ve_mount_nr_min,
		.extra2		= &ve_mount_nr_max,
	},
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
