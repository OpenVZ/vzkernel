/*
 *  linux/kernel/ve/vecalls.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 */

/*
 * 'vecalls.c' is file with basic VE support. It provides basic primities
 * along with initialization script
 */

#include <linux/sched.h>
#include <linux/ve.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/sys.h>
#include <linux/fs.h>
#include <linux/netdevice.h>
#include <linux/utsname.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/mount.h>
#include <generated/utsrelease.h>

#include <linux/venet.h>
#include <linux/vzctl.h>
#include <uapi/linux/vzcalluser.h>
#include <linux/fairsched.h>
#include <linux/device_cgroup.h>

#include <bc/dcache.h>

static struct cgroup *devices_root;

static s64 ve_get_uptime(struct ve_struct *ve)
{
	struct timespec uptime;
	do_posix_clock_monotonic_gettime(&uptime);
	monotonic_to_bootbased(&uptime);
	uptime = timespec_sub(uptime, ve->real_start_timespec);
	return timespec_to_ns(&uptime);
}

static int ve_get_cpu_stat(envid_t veid, struct vz_cpu_stat __user *buf)
{
	struct ve_struct *ve;
	struct vz_cpu_stat *vstat;
	int retval;
	int i;
	unsigned long tmp;
	unsigned long avenrun[3];
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

	retval = fairsched_get_cpu_stat(ve->ve_name, &kstat);
	if (retval)
		goto out_free;

	retval = fairsched_get_cpu_avenrun(ve->ve_name, avenrun);
	if (retval)
		goto out_free;

	vstat->user_jif += (unsigned long)cputime64_to_clock_t(kstat.cpustat[CPUTIME_USER]);
	vstat->nice_jif += (unsigned long)cputime64_to_clock_t(kstat.cpustat[CPUTIME_NICE]);
	vstat->system_jif += (unsigned long)cputime64_to_clock_t(kstat.cpustat[CPUTIME_SYSTEM]);
	vstat->idle_clk += kstat.cpustat[CPUTIME_IDLE];

	vstat->uptime_clk = ve_get_uptime(ve);

	vstat->uptime_jif = (unsigned long)jiffies_64_to_clock_t(
				get_jiffies_64() - ve->start_jiffies);
	for (i = 0; i < 3; i++) {
		tmp = avenrun[i] + (FIXED_1/200);
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
 * /proc/meminfo virtualization
 *
 **********************************************************************
 **********************************************************************/
static int ve_set_meminfo(envid_t veid, unsigned long val)
{
#ifdef CONFIG_BEANCOUNTERS
	struct ve_struct *ve;

	ve = get_ve_by_id(veid);
	if (!ve)
		return -EINVAL;

	if (val == 0)
		val = VE_MEMINFO_SYSTEM;
	else if (val == 1)
		val = VE_MEMINFO_DEFAULT;

	ve->meminfo_val = val;
	put_ve(ve);
	return 0;
#else
	return -ENOTTY;
#endif
}

static struct vfsmount *ve_cgroup_mnt, *devices_cgroup_mnt;

static int __init init_vecalls_cgroups(void)
{
	struct cgroup_sb_opts devices_opts = {
		.subsys_mask	=
			(1ul << devices_subsys_id),
	};

	struct cgroup_sb_opts ve_opts = {
		.subsys_mask	=
			(1ul << ve_subsys_id),
	};

	devices_cgroup_mnt = cgroup_kernel_mount(&devices_opts);
	if (IS_ERR(devices_cgroup_mnt))
		return PTR_ERR(devices_cgroup_mnt);
	devices_root = cgroup_get_root(devices_cgroup_mnt);

	ve_cgroup_mnt = cgroup_kernel_mount(&ve_opts);
	if (IS_ERR(ve_cgroup_mnt)) {
		kern_unmount(devices_cgroup_mnt);
		return PTR_ERR(ve_cgroup_mnt);
	}

	return 0;
}

static void fini_vecalls_cgroups(void)
{
	kern_unmount(ve_cgroup_mnt);
	kern_unmount(devices_cgroup_mnt);
}

/**********************************************************************
 **********************************************************************
 *
 * Pieces of VE network
 *
 **********************************************************************
 **********************************************************************/

#ifdef CONFIG_NET
#include <asm/uaccess.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/route.h>
#include <net/ip_fib.h>
#endif

static int ve_dev_add(envid_t veid, char *dev_name)
{
	struct net_device *dev;
	struct ve_struct *dst_ve;
	struct net *dst_net;
	int err = -ESRCH;

	dst_ve = get_ve_by_id(veid);
	if (dst_ve == NULL)
		goto out;

	dst_net = dst_ve->ve_netns;

	rtnl_lock();
	read_lock(&dev_base_lock);
	dev = __dev_get_by_name(&init_net, dev_name);
	read_unlock(&dev_base_lock);
	if (dev == NULL)
		goto out_unlock;

	err = dev_change_net_namespace(dev, dst_net, dev_name);
out_unlock:
	rtnl_unlock();
	put_ve(dst_ve);

	if (dev == NULL)
		printk(KERN_WARNING "%s: device %s not found\n",
			__func__, dev_name);
out:
	return err;
}

static int ve_dev_del(envid_t veid, char *dev_name)
{
	struct net_device *dev;
	struct ve_struct *src_ve;
	struct net *src_net;
	int err = -ESRCH;

	src_ve = get_ve_by_id(veid);
	if (src_ve == NULL)
		goto out;

	src_net = src_ve->ve_netns;

	rtnl_lock();

	read_lock(&dev_base_lock);
	dev = __dev_get_by_name(src_net, dev_name);
	read_unlock(&dev_base_lock);
	if (dev == NULL)
		goto out_unlock;

	err = dev_change_net_namespace(dev, &init_net, dev_name);
out_unlock:
	rtnl_unlock();
	put_ve(src_ve);

	if (dev == NULL)
		printk(KERN_WARNING "%s: device %s not found\n",
			__func__, dev_name);
out:
	return err;
}

int real_ve_dev_map(envid_t veid, int op, char *dev_name)
{
	if (!capable_setveid())
		return -EPERM;
	switch (op) {
	case VE_NETDEV_ADD:
		return ve_dev_add(veid, dev_name);
	case VE_NETDEV_DEL:
		return ve_dev_del(veid, dev_name);
	default:
		return -EINVAL;
	}
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

	ret = fairsched_get_cpu_stat(ve->ve_name, &kstat);
	if (ret)
		return ret;

	strv_time = 0;
	user_ve = kstat.cpustat[CPUTIME_USER];
	nice_ve = kstat.cpustat[CPUTIME_NICE];
	system_ve = kstat.cpustat[CPUTIME_SYSTEM];
	used = kstat.cpustat[CPUTIME_USED];
	idle_time = kstat.cpustat[CPUTIME_IDLE];

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

void *ve_seq_start(struct seq_file *m, loff_t *pos)
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
EXPORT_SYMBOL(ve_seq_start);

void *ve_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	if (!ve_is_super(get_exec_env()))
		return NULL;
	else
		return seq_list_next(v, &ve_list_head, pos);
}
EXPORT_SYMBOL(ve_seq_next);

void ve_seq_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&ve_list_lock);
}
EXPORT_SYMBOL(ve_seq_stop);

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

static struct file_operations proc_vestat_operations = {
        .open	 = vestat_open,
        .read	 = seq_read,
        .llseek	 = seq_lseek,
        .release = seq_release
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
		devcgroup_seq_show_ve(devices_root, ve, m);

	return 0;
}

static struct seq_operations devperms_seq_op = {
	.start  = ve_seq_start,
	.next   = ve_seq_next,
	.stop   = ve_seq_stop,
	.show   = devperms_seq_show,
};

static int devperms_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &devperms_seq_op);
}

static struct file_operations proc_devperms_ops = {
	.open           = devperms_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

static int vz_version_show(struct seq_file *file, void* v)
{
	static const char ver[] = VZVERSION "\n";

	return seq_puts(file, ver);
}

static int vz_version_open(struct inode *inode, struct file *file)
{
	return single_open(file, vz_version_show, NULL);
}

static struct file_operations proc_vz_version_oparations = {
	.open    = vz_version_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
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

	seq_printf(m, "%10s %5u %5u", ve_name(ve), ve->class_id, nr_threads_ve(ve));

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

static struct file_operations proc_veinfo_operations = {
	.open		= veinfo_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
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
			&proc_vz_version_oparations);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make version proc entry\n");

	de = proc_create("veinfo", S_IFREG | S_IRUSR | S_ISVTX, proc_vz_dir,
			&proc_veinfo_operations);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make veinfo proc entry\n");

	return 0;
}

static void fini_vecalls_proc(void)
{
	remove_proc_entry("version", proc_vz_dir);
	remove_proc_entry("devperms", proc_vz_dir);
	remove_proc_entry("vestat", proc_vz_dir);
	remove_proc_entry("veinfo", proc_vz_dir);
}
#else
#define init_vecalls_proc()	(0)
#define fini_vecalls_proc()	do { } while (0)
#endif /* CONFIG_PROC_FS */

static int init_ve_osrelease(struct ve_struct *ve, char *release)
{
	if (!release)
		return -ENODATA;

	if (strlen(release) >= sizeof(ve->ve_ns->uts_ns->name.release))
		return -EMSGSIZE;

	down_write(&uts_sem);
	strcpy(ve->ve_ns->uts_ns->name.release, release);
	up_write(&uts_sem);

	return 0;
}

static int ve_configure(envid_t veid, unsigned int key,
			unsigned int val, unsigned int size, char *data)
{
	struct ve_struct *ve;
	int err = -ENOKEY;

	ve = get_ve_by_id(veid);
	if (!ve)
		return -EINVAL;

	switch(key) {
	case VE_CONFIGURE_OS_RELEASE:
		err = init_ve_osrelease(ve, data);
		break;
	}

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
	    case VZCTL_MARK_ENV_TO_DOWN: {
		        /* Compatibility issue */
		        err = 0;
		}
		break;
#ifdef CONFIG_INET
	    case VZCTL_VE_NETDEV: {
			struct vzctl_ve_netdev d;
			char *s;
			err = -EFAULT;
			if (copy_from_user(&d, (void __user *)arg, sizeof(d)))
				break;
			err = -ENOMEM;
			s = kmalloc(IFNAMSIZ+1, GFP_KERNEL);
			if (s == NULL)
				break;
			err = -EFAULT;
			if (strncpy_from_user(s, d.dev_name, IFNAMSIZ) > 0) {
				s[IFNAMSIZ] = 0;
				err = real_ve_dev_map(d.veid, d.op, s);
			}
			kfree(s);
		}
		break;
#endif
	    case VZCTL_ENV_CREATE: {
			err = -ENOTSUPP;
		}
		break;
	    case VZCTL_ENV_CREATE_DATA: {
			err = -ENOTSUPP;
		}
		break;
	    case VZCTL_GET_CPU_STAT: {
			struct vzctl_cpustatctl s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = ve_get_cpu_stat(s.veid, s.cpustat);
		}
		break;
	    case VZCTL_VE_MEMINFO: {
			struct vzctl_ve_meminfo s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = ve_set_meminfo(s.veid, s.val);
		}
		break;
	    case VZCTL_VE_CONFIGURE:
		err = ve_configure_ioctl((struct vzctl_ve_configure *)arg);
		break;
	}
	return err;
}

#ifdef CONFIG_COMPAT
int compat_vzcalls_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	int err;

	switch(cmd) {
	case VZCTL_GET_CPU_STAT: {
		/* FIXME */
	}
	case VZCTL_COMPAT_ENV_CREATE_DATA: {
		struct compat_vzctl_env_create_data cs;
		struct vzctl_env_create_data __user *s;

		s = compat_alloc_user_space(sizeof(*s));
		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;

		if (put_user(cs.veid, &s->veid) ||
		    put_user(cs.flags, &s->flags) ||
		    put_user(cs.class_id, &s->class_id) ||
		    put_user(compat_ptr(cs.data), &s->data) ||
		    put_user(cs.datalen, &s->datalen))
			break;
		err = vzcalls_ioctl(file, VZCTL_ENV_CREATE_DATA,
						(unsigned long)s);
		break;
	}
#ifdef CONFIG_NET
	case VZCTL_COMPAT_VE_NETDEV: {
		struct compat_vzctl_ve_netdev cs;
		struct vzctl_ve_netdev __user *s;

		s = compat_alloc_user_space(sizeof(*s));
		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;

		if (put_user(cs.veid, &s->veid) ||
		    put_user(cs.op, &s->op) ||
		    put_user(compat_ptr(cs.dev_name), &s->dev_name))
			break;
		err = vzcalls_ioctl(file, VZCTL_VE_NETDEV, (unsigned long)s);
		break;
	}
#endif
	case VZCTL_COMPAT_VE_MEMINFO: {
		struct compat_vzctl_ve_meminfo cs;
		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;
		err = ve_set_meminfo(cs.veid, cs.val);
		break;
	}
	default:
		err = vzcalls_ioctl(file, cmd, arg);
		break;
	}
	return err;
}
#endif

static struct vzioctlinfo vzcalls = {
	.type		= VZCTLTYPE,
	.ioctl		= vzcalls_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_vzcalls_ioctl,
#endif
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

	err = init_vecalls_cgroups();
	if (err)
		goto out_cgroups;

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
	fini_vecalls_cgroups();
out_cgroups:
	return err;
}

static void __exit vecalls_exit(void)
{
	fini_vecalls_ioctls();
	fini_vecalls_proc();
	fini_vecalls_cgroups();
}

MODULE_AUTHOR("SWsoft <info@sw-soft.com>");
MODULE_DESCRIPTION("Virtuozzo Control");
MODULE_LICENSE("GPL v2");

module_init(vecalls_init)
module_exit(vecalls_exit)
