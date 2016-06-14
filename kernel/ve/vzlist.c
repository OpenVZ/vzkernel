/*
 *  kernel/ve/vzlist.c
 *
 *  Copyright (c) 2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/ve.h>
#include <linux/venet.h>
#include <linux/vzctl.h>
#include <uapi/linux/vzlist.h>
#include <linux/vmalloc.h>
#include <linux/ve_proto.h>
#include <linux/veip.h>
#include <linux/uaccess.h>
#include <linux/pid_namespace.h>

static DEFINE_SEMAPHORE(vzlist_sem);

static int get_veids(struct vzlist_veidctl *s)
{
	int ret;
	int ves;
	unsigned long size;
	envid_t *buf;
	struct ve_struct *ve;

	ves = nr_ve + 1;
	if (!s->num || s->id == NULL)
		return ves;

	down(&vzlist_sem);
again:
	size = (ves + 20)*sizeof(envid_t);
	ret = -ENOMEM;
	buf = vmalloc(size);
	if (!buf)
		goto out_oom;

	ves = 0;
	mutex_lock(&ve_list_lock);
	for_each_ve(ve) {
		if (size >= (ves + 1)*sizeof(envid_t))
			buf[ves] = ve->veid;
		ves++;
	}
	mutex_unlock(&ve_list_lock);

	ret = ves;
	if (ves > s->num)
		goto out;
	if (size < ves*sizeof(envid_t)) {
		vfree(buf);
		goto again;
	}
	if (copy_to_user(s->id, buf, ves*sizeof(envid_t)))
		ret = -EFAULT;
	/* success */
out:
	vfree(buf);
out_oom:
	up(&vzlist_sem);
	return ret;
}

static int get_vepids(struct vzlist_vepidctl *s)
{
	int ret;
	int tasks = 0;
	unsigned long size;
	envid_t *buf;
	struct ve_struct *ve;
	struct task_struct *tsk;
	struct pid_namespace *ns;
	int nr;

	ret = -ESRCH;
	ve = get_ve_by_id(s->veid);
	if (!ve)
		goto out_no_ve;
	ns = ve->ve_ns->pid_ns;

	down(&vzlist_sem);
again:
	size = (tasks + 512)*(2*sizeof(pid_t));
	ret = -ENOMEM;
	buf = vmalloc(size);
	if (!buf)
		goto out_oom;

	tasks = 0;
	qread_lock(&tasklist_lock);
	nr = next_pidmap(ns, 0);
	while (nr > 0) {
		rcu_read_lock();

		tsk = pid_task(find_pid_ns(nr, ns), PIDTYPE_PID);
		if (tsk) {
			if (size >= (tasks + 1)*(2*sizeof(pid_t))) {
				buf[2*tasks] = tsk->pid;
				buf[2*tasks + 1] = task_pid_nr_ns(tsk, ns);
			}
			tasks++;
		}

		rcu_read_unlock();
		nr = next_pidmap(ns, nr);
	}
	qread_unlock(&tasklist_lock);

	ret = tasks;
	if ((tasks > s->num) | (!tasks))
		goto out;
	if (size < tasks*(2*sizeof(pid_t))) {
		vfree(buf);
		goto again;
	}
	if (copy_to_user(s->pid, buf, tasks*(2*sizeof(pid_t))))
		ret = -EFAULT;
	/* success */
out:
	vfree(buf);
out_oom:
	up(&vzlist_sem);
	put_ve(ve);
out_no_ve:
	return ret;
}

static int get_veips(struct vzlist_veipctl *s, unsigned int cmd)
{
	int ret;
	int ips;
	unsigned long size;
	u32 *buf, *pos;
	struct ve_struct *ve;
	struct veip_struct *veip;
	struct ip_entry_struct *entry;
	struct ve_addr_struct *addr;

	ret = -ESRCH;
	ve = get_ve_by_id(s->veid);
	if (!ve)
		goto out_no_ve;

	size = PAGE_SIZE;
	down(&vzlist_sem);
again:
	ret = -ENOMEM;
	buf = vmalloc(size);
	if (!buf)
		goto out_oom;

	ips = 0;
#if defined(CONFIG_VE_NETDEV) || defined(CONFIG_VE_NETDEV_MODULE)
	rcu_read_lock();
	veip = ACCESS_ONCE(ve->veip);
	if (veip == NULL)
		goto noip;

	pos = buf;
	list_for_each_entry_rcu(entry, &veip->ip_lh, ve_list) {
		if (entry->active_env == NULL)
			continue;

		addr = &entry->addr;

		if (cmd == VZCTL_GET_VEIPS && addr->family == AF_INET) {
			if (size >= (ips + 1) * sizeof(addr->key[3])) {
				pos[0] = addr->key[3];
				pos++;
			}
			ips++;
		}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		if (cmd == VZCTL_GET_VEIP6S && addr->family == AF_INET6) {
			if (size >= (ips + 1) * sizeof(addr->key)) {
				memcpy(pos, addr->key, sizeof(addr->key));
				pos += 4;
			}
			ips++;
		}
#endif
	}
noip:
	rcu_read_unlock();
#endif

	ret = ips;
	if (ips > s->num)
		goto out;

	if (cmd == VZCTL_GET_VEIPS) {
		if (size < ips * sizeof(u32)) {
			size = ips * sizeof(u32);
			vfree(buf);
			goto again;
		}
		if (copy_to_user(s->ip, buf, ips * sizeof(u32)))
			ret = -EFAULT;
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else {
		if (size < ips * sizeof(u32) * 4) {
			size = ips * sizeof(u32) * 4;
			vfree(buf);
			goto again;
		}
		if (copy_to_user(s->ip, buf, ips * sizeof(u32) * 4))
			ret = -EFAULT;
	}
#endif
	/* success */
out:
	vfree(buf);
out_oom:
	up(&vzlist_sem);
	put_ve(ve);
out_no_ve:
	return ret;
}

static int vzlist_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err = -ENOTTY;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case VZCTL_GET_VEIDS: {
			struct vzlist_veidctl s;

			if (arg) {
				err = -EFAULT;
				if (copy_from_user(&s, argp, sizeof(s)))
					break;
				err = get_veids(&s);
			} else
				err = nr_ve;
		}
		break;
	case VZCTL_GET_VEPIDS: {
			struct vzlist_vepidctl s;

			err = -EFAULT;
			if (copy_from_user(&s, argp, sizeof(s)))
				break;
			err = get_vepids(&s);
		}
		break;
	case VZCTL_GET_VEIP6S:
	case VZCTL_GET_VEIPS: {
			struct vzlist_veipctl s;

			err = -EFAULT;
			if (copy_from_user(&s, argp, sizeof(s)))
				break;
			err = get_veips(&s, cmd);
		}
		break;
	}
	return err;
}

#ifdef CONFIG_COMPAT
static int vzlist_ioctl_compat(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	/* do we need this? */
	return -ENOTTY;
}
#endif

static struct vzioctlinfo vzid_calls = {
	.type		= VZLISTTYPE,
	.ioctl		= vzlist_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= vzlist_ioctl_compat,
#endif
	.owner		= THIS_MODULE
};

static int __init init_vzlist(void)
{
	vzioctl_register(&vzid_calls);
	return 0;
}

static void __exit exit_vzlist(void)
{
	vzioctl_unregister(&vzid_calls);
}

module_init(init_vzlist);
module_exit(exit_vzlist);

MODULE_LICENSE("GPL v2");
