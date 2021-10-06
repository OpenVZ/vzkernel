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
#include <linux/jiffies.h>
#include <linux/sched/loadavg.h>
#include <generated/utsrelease.h>

#include <linux/ve.h>
#include <linux/vzctl.h>
#include <linux/veowner.h>
#include <linux/device_cgroup.h>
#include <uapi/linux/vzcalluser.h>

static int fill_cpu_stat(envid_t veid, struct vz_cpu_stat __user *buf)
{
	struct ve_struct *ve;
	struct vz_cpu_stat *vstat;
	int retval;
	int i;
	unsigned long tmp;
	unsigned long avnrun[3];
	struct kernel_cpustat kstat;

	if (!ve_is_super(get_exec_env()) && (veid != get_exec_env()->veid))
		return -EPERM;
	ve = get_ve_by_id(veid);
	if (!ve)
		return -ESRCH;

	retval = -ENOMEM;
	vstat = kzalloc(sizeof(*vstat), GFP_KERNEL);
	if (!vstat)
		goto out_put_ve;

	retval = ve_get_cpu_stat(ve, &kstat);
	if (retval)
		goto out_free;

	retval = ve_get_cpu_avenrun(ve, avnrun);
	if (retval)
		goto out_free;

	vstat->user_jif	  = (unsigned long)nsec_to_clock_t(
					   kstat.cpustat[CPUTIME_USER]);
	vstat->nice_jif   = (unsigned long)nsec_to_clock_t(
					   kstat.cpustat[CPUTIME_NICE]);
	vstat->system_jif = (unsigned long)nsec_to_clock_t(
					   kstat.cpustat[CPUTIME_SYSTEM]);
	vstat->idle_clk   = kstat.cpustat[CPUTIME_IDLE];
	vstat->uptime_clk = ve_get_uptime(ve);

	vstat->uptime_jif = (unsigned long)jiffies_64_to_clock_t(
			    get_jiffies_64() - ve->start_jiffies);
	for (i = 0; i < 3; i++) {
		tmp = avnrun[i] + (FIXED_1/200);
		vstat->avenrun[i].val_int = LOAD_INT(tmp);
		vstat->avenrun[i].val_frac = LOAD_FRAC(tmp);
	}

	retval = 0;
	if (copy_to_user(buf, vstat, sizeof(*vstat)))
		retval = -EFAULT;
out_free:
	kfree(vstat);
out_put_ve:
	put_ve(ve);
	return retval;
}

/**********************************************************************
 **********************************************************************
 *
 * VE information via /proc
 *
 **********************************************************************
 **********************************************************************/
#ifdef CONFIG_PROC_FS
#if BITS_PER_LONG == 32
#define VESTAT_LINE_WIDTH (6 * 11 + 6 * 21)
#define VESTAT_LINE_FMT "%10s %10lu %10lu %10lu %10Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %10lu\n"
#define VESTAT_HEAD_FMT "%10s %10s %10s %10s %10s %20s %20s %20s %20s %20s %20s %10s\n"
#else
#define VESTAT_LINE_WIDTH (12 * 21)
#define VESTAT_LINE_FMT "%20s %20lu %20lu %20lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20lu\n"
#define VESTAT_HEAD_FMT "%20s %20s %20s %20s %20s %20s %20s %20s %20s %20s %20s %20s\n"
#endif

static int vestat_seq_show(struct seq_file *m, void *v)
{
	struct list_head *entry;
	struct ve_struct *ve;
	struct ve_struct *curve;
	int ret;
	unsigned long user_ve, nice_ve, system_ve;
	unsigned long long uptime;
	u64 uptime_cycles, idle_time, strv_time, used;
	struct kernel_cpustat kstat;

	entry = (struct list_head *)v;
	ve = list_entry(entry, struct ve_struct, ve_list);

	curve = get_exec_env();
	if (entry == ve_list_head.next ||
	    (!ve_is_super(curve) && ve == curve)) {
		/* print header */
		seq_printf(m, "%-*s\n",
			   VESTAT_LINE_WIDTH - 1,
			   "Version: 2.2");
		seq_printf(m, VESTAT_HEAD_FMT, "VEID",
			   "user", "nice", "system",
			   "uptime", "idle",
			   "strv", "uptime", "used",
			   "maxlat", "totlat", "numsched");
	}

	if (ve == get_ve0())
		return 0;

	ret = ve_get_cpu_stat(ve, &kstat);
	if (ret)
		return ret;

	strv_time	= 0;
	user_ve		= nsecs_to_jiffies(kstat.cpustat[CPUTIME_USER]);
	nice_ve		= nsecs_to_jiffies(kstat.cpustat[CPUTIME_NICE]);
	system_ve	= nsecs_to_jiffies(kstat.cpustat[CPUTIME_SYSTEM]);
	used		= kstat.cpustat[CPUTIME_USED];
	idle_time	= kstat.cpustat[CPUTIME_IDLE];

	uptime_cycles = ve_get_uptime(ve);
	uptime = get_jiffies_64() - ve->start_jiffies;

	seq_printf(m, VESTAT_LINE_FMT, ve_name(ve),
		   user_ve, nice_ve, system_ve,
		   (unsigned long long)uptime,
		   (unsigned long long)idle_time,
		   (unsigned long long)strv_time,
		   (unsigned long long)uptime_cycles,
		   (unsigned long long)used,
		   (unsigned long long)ve->sched_lat_ve.last.maxlat,
		   (unsigned long long)ve->sched_lat_ve.last.totlat,
		   ve->sched_lat_ve.last.count);
	return 0;
}

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

static struct seq_operations vestat_seq_op = {
	.start	= ve_seq_start,
	.next	= ve_seq_next,
	.stop	= ve_seq_stop,
	.show	= vestat_seq_show
};

static int vestat_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &vestat_seq_op);
}

static struct proc_ops proc_vestat_operations = {
	.proc_open	= vestat_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release
};

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
static int veinfo_seq_show(struct seq_file *m, void *v)
{
	struct ve_struct *ve;

	ve = list_entry((struct list_head *)v, struct ve_struct, ve_list);

	/* second 0 is deprecated ve->class_id */
	seq_printf(m, "%10s 0 %5u\n", ve_name(ve), nr_threads_ve(ve));
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

	de = proc_create("vestat", S_IFREG | S_IRUSR | S_ISVTX, proc_vz_dir,
			&proc_vestat_operations);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make vestat proc entry\n");

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
	remove_proc_entry("vestat", proc_vz_dir);
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
	    case VZCTL_GET_CPU_STAT: {
			struct vzctl_cpustatctl s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = fill_cpu_stat(s.veid, s.cpustat);
		}
		break;
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
