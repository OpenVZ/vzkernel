/*
 *  kernel/ve/vzdev.c
 *
 *  Copyright (c) 2000-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/vzctl.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <uapi/linux/vzcalluser.h>
#include <asm/uaccess.h>
#include <asm/pgalloc.h>
#include <linux/device.h>

#define VZCTL_MAJOR 126
#define VZCTL_NAME "vzctl"

MODULE_AUTHOR("SWsoft <info@sw-soft.com>");
MODULE_DESCRIPTION("Virtuozzo Interface");
MODULE_LICENSE("GPL v2");

static LIST_HEAD(ioctls);
static DEFINE_SPINLOCK(ioctl_lock);

static struct vzioctlinfo *vzctl_get_handler(unsigned int cmd)
{
	struct vzioctlinfo *h;

	spin_lock(&ioctl_lock);
	list_for_each_entry(h, &ioctls, list) {
		if (h->type == _IOC_TYPE(cmd))
			goto found;
	}
	h = NULL;
found:
	if (h && !try_module_get(h->owner))
		h = NULL;
	spin_unlock(&ioctl_lock);
	return h;
}

static void vzctl_put_handler(struct vzioctlinfo *h)
{
	if (!h)
		return;

	module_put(h->owner);
}

long vzctl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct vzioctlinfo *h;
	int err;

	err = -ENOTTY;
	h = vzctl_get_handler(cmd);
	if (h && h->ioctl)
		err = (*h->ioctl)(file, cmd, arg);
	vzctl_put_handler(h);

	return err;
}

long compat_vzctl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct vzioctlinfo *h;
	int err;

	err = -ENOIOCTLCMD;
	h = vzctl_get_handler(cmd);
	if (h && h->compat_ioctl)
		err = (*h->compat_ioctl)(file, cmd, arg);
	vzctl_put_handler(h);

	return err;
}

void vzioctl_register(struct vzioctlinfo *inf)
{
	spin_lock(&ioctl_lock);
	list_add(&inf->list, &ioctls);
	spin_unlock(&ioctl_lock);
}
EXPORT_SYMBOL(vzioctl_register);

void vzioctl_unregister(struct vzioctlinfo *inf)
{
	spin_lock(&ioctl_lock);
	list_del_init(&inf->list);
	spin_unlock(&ioctl_lock);
}
EXPORT_SYMBOL(vzioctl_unregister);

/*
 * Init/exit stuff.
 */
static struct file_operations vzctl_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= vzctl_ioctl,
	.compat_ioctl	= compat_vzctl_ioctl,
};

static struct class *vzctl_class;

static void __exit vzctl_exit(void)
{
	device_destroy(vzctl_class, MKDEV(VZCTL_MAJOR, 0));
	class_destroy(vzctl_class);
	unregister_chrdev(VZCTL_MAJOR, VZCTL_NAME);
}

static int __init vzctl_init(void)
{
	int ret;
	struct device *class_err;

	ret = register_chrdev(VZCTL_MAJOR, VZCTL_NAME, &vzctl_fops);
	if (ret < 0)
		goto out;

	vzctl_class = class_create(THIS_MODULE, "vzctl");
	if (IS_ERR(vzctl_class)) {
		ret = PTR_ERR(vzctl_class);
		goto out_cleandev;
	}

	class_err = device_create(vzctl_class, NULL,
			MKDEV(VZCTL_MAJOR, 0), NULL, VZCTL_NAME);
	if (IS_ERR(class_err)) {
		ret = PTR_ERR(class_err);
		goto out_rmclass;
	}

	goto out;

out_rmclass:
	class_destroy(vzctl_class);
out_cleandev:
	unregister_chrdev(VZCTL_MAJOR, VZCTL_NAME);
out:
	return ret;
}

module_init(vzctl_init)
module_exit(vzctl_exit);
