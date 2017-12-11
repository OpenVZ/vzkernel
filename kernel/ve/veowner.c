/*
 *  kernel/ve/veowner.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/sched.h>
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

struct proc_dir_entry *glob_proc_vz_dir;
EXPORT_SYMBOL(glob_proc_vz_dir);

static void prepare_proc(void)
{
	proc_vz_dir = proc_mkdir("vz", NULL);
	if (!proc_vz_dir)
		panic("Can't create /proc/vz dir\n");

	glob_proc_vz_dir = proc_mkdir("vz", &glob_proc_root);
	if (!proc_vz_dir)
		panic("Can't create /proc/vz dir\n");
	proc_create("container", S_IFDIR|S_IRUSR|S_IXUSR, proc_vz_dir, NULL);
}
#endif

/*
 * ------------------------------------------------------------------------
 * OpenVZ sysctl
 * ------------------------------------------------------------------------
 */

#ifdef CONFIG_INET
static struct ctl_table vz_ipv4_route_table[] = {
	{
		.procname	= "src_check",
		.data		= &ip_rt_src_check,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ 0 }
};

static struct ctl_path net_ipv4_route_path[] = {
	{ .procname = "net", },
	{ .procname = "ipv4", },
	{ .procname = "route", },
	{ }
};
#endif

static struct ctl_table vz_fs_table[] = {
	{
		.procname	= "fsync-enable",
		.data		= &sysctl_fsync_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{ 0 }
};

static struct ctl_path fs_path[] = {
	{ .procname = "fs", },
	{ }
};

static void prepare_sysctl(void)
{
#ifdef CONFIG_INET
	register_sysctl_paths(net_ipv4_route_path, vz_ipv4_route_table);
#endif
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
