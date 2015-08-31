#define pr_fmt(fmt) "vz con: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/init.h>

#include <linux/tty.h>
#include <linux/tty_flip.h>

#include <linux/ve.h>

#define VZ_CON_INDEX		(0)
#define VZ_CON_SLAVE_NAME	"vzcons"

static struct tty_driver *vz_conm_driver;
static struct tty_driver *vz_cons_driver;

extern struct class *tty_class;

static char *vzcon_devnode(struct device *dev, umode_t *mode)
{
	if (mode)
		*mode = 0600;
	return NULL;
}

static struct class vz_con_class_base = {
	.name		= "vzcon",
	.devnode	= vzcon_devnode,
	.ns_type	= &ve_ns_type_operations,
	.namespace	= ve_namespace,
	.owner		= THIS_MODULE,
};

static struct class *vz_con_class = &vz_con_class_base;

static struct tty_struct *vz_tty_lookup(struct tty_driver *driver,
					struct inode *inode, int idx)
{
	struct ve_struct *ve = get_exec_env();

	BUG_ON(driver != vz_conm_driver &&
	       driver != vz_cons_driver);

	if (idx != VZ_CON_INDEX || driver == vz_cons_driver)
		return ERR_PTR(-EIO);

	return ve->vz_tty_vt[idx];
}

static int vz_tty_install(struct tty_driver *driver, struct tty_struct *tty)
{
	struct ve_struct *ve = get_exec_env();

	BUG_ON(driver != vz_conm_driver);

	tty->port = kzalloc(sizeof(*tty->port), GFP_KERNEL);
	if (!tty->port)
		return -ENOMEM;
	tty_port_init(tty->port);
	tty->termios = driver->init_termios;

	ve->vz_tty_vt[tty->index] = tty;

	tty_driver_kref_get(driver);
	tty->count++;
	return 0;
}

static void vz_tty_remove(struct tty_driver *driver, struct tty_struct *tty)
{
	struct ve_struct *ve = get_exec_env();

	BUG_ON(driver != vz_conm_driver);
	ve->vz_tty_vt[tty->index] = NULL;
}

static int vz_tty_open(struct tty_struct *tty, struct file *filp)
{
	set_bit(TTY_THROTTLED, &tty->flags);
	return 0;
}

static void vz_tty_close(struct tty_struct *tty, struct file *filp)
{
}

static void vz_tty_shutdown(struct tty_struct *tty)
{
}

static void vz_tty_cleanup(struct tty_struct *tty)
{
	tty_port_put(tty->port);
}

static int vz_tty_write(struct tty_struct *tty, const unsigned char *buf, int count)
{
	return count;
}

static int vz_tty_write_room(struct tty_struct *tty)
{
	return 4096;
}

static void vz_tty_unthrottle(struct tty_struct *tty)
{
	set_bit(TTY_THROTTLED, &tty->flags);
}

static const struct tty_operations vz_tty_fops = {
	.lookup		= vz_tty_lookup,
	.install	= vz_tty_install,
	.remove		= vz_tty_remove,
	.open		= vz_tty_open,
	.close		= vz_tty_close,
	.shutdown	= vz_tty_shutdown,
	.cleanup	= vz_tty_cleanup,
	.write		= vz_tty_write,
	.write_room	= vz_tty_write_room,
	.unthrottle	= vz_tty_unthrottle,
};

static struct tty_struct *vz_vt_lookup(struct tty_driver *driver,
				       struct inode *inode, int idx)
{
	return driver->ttys[idx];
}

static int vz_vt_install(struct tty_driver *driver, struct tty_struct *tty)
{
	tty->port = kzalloc(sizeof(*tty->port), GFP_KERNEL);
	if (!tty->port)
		return -ENOMEM;
	tty_standard_install(driver, tty);
	tty_port_init(tty->port);
	return 0;
}

static void vz_vt_cleanup(struct tty_struct *tty)
{
	kfree(tty->port);
	tty->port = NULL;
}

const static struct tty_operations vt_tty_fops = {
	.lookup		= vz_vt_lookup,
	.install	= vz_vt_install,
	.open		= vz_tty_open,
	.cleanup	= vz_vt_cleanup,
	.write		= vz_tty_write,
	.write_room	= vz_tty_write_room,
	.unthrottle	= vz_tty_unthrottle,
};

static int __vz_vt_ve_init(struct ve_struct *ve)
{
#define TTY_DRIVER_ALLOC_FLAGS			\
	(TTY_DRIVER_REAL_RAW		|	\
	 TTY_DRIVER_RESET_TERMIOS	|	\
	 TTY_DRIVER_DYNAMIC_DEV		|	\
	 TTY_DRIVER_CONTAINERIZED)

	struct tty_driver *driver;
	int ret = 0;
	int i;

	driver = tty_alloc_driver(VZ_VT_MAX_DEVS, TTY_DRIVER_ALLOC_FLAGS);
	if (IS_ERR(driver)) {
		ret = PTR_ERR(driver);
		pr_err("Can't allocate VT master driver\n");
		return ret;
	}

	driver->driver_name	= "vt_master";
	driver->name		= "tty";
	driver->name_base	= 1;
	driver->major		= 0;
	driver->minor_start	= 1;
	driver->type		= TTY_DRIVER_TYPE_CONSOLE;
	driver->init_termios	= tty_std_termios;
	driver->ve		= ve;
	tty_set_operations(driver, &vt_tty_fops);

	ret = tty_register_driver(driver);
	if (ret) {
		pr_err("Can't register vt master driver\n");
		put_tty_driver(driver);
		return ret;
	}

	for (i = 0; i < VZ_VT_MAX_DEVS; i++) {
		dev_t dev = MKDEV(TTY_MAJOR, i);
		struct device *d;

		d = device_create(tty_class, NULL, dev, ve, "tty%i", i);
		if (IS_ERR(d)) {
			for (i--; i >= 0; i--)
				device_destroy_namespace(tty_class, dev, ve);
			tty_unregister_driver(driver);
			put_tty_driver(driver);
			return PTR_ERR(d);
		}
	}
	ve->vz_vt_driver = driver;

	return 0;
#undef TTY_DRIVER_ALLOC_FLAGS
}

static void __vz_vt_ve_fini(struct ve_struct *ve)
{
	int i;

	if (!ve->vz_vt_driver)
		return;

	for (i = 0; i < VZ_VT_MAX_DEVS; i++) {
		dev_t dev = MKDEV(TTY_MAJOR, i);
		device_destroy_namespace(tty_class, dev, ve);
	}

	tty_unregister_driver(ve->vz_vt_driver);
	put_tty_driver(ve->vz_vt_driver);
}

static int __vz_con_ve_init(struct ve_struct *ve)
{
	struct device *d;
	dev_t dev;

	dev = MKDEV(vz_cons_driver->major, vz_cons_driver->minor_start);
	d = device_create(vz_con_class, NULL, dev, ve, VZ_CON_SLAVE_NAME);

	return IS_ERR(d) ? PTR_ERR(d) : 0;
}

int vz_con_ve_init(struct ve_struct *ve)
{
	int ret = 0;

	if (ve != get_ve0()) {
		ret = __vz_con_ve_init(ve);
		if (!ret)
			ret = __vz_vt_ve_init(ve);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(vz_con_ve_init);

static void __vz_con_ve_fini(struct ve_struct *ve)
{
	dev_t dev = MKDEV(vz_cons_driver->major, vz_cons_driver->minor_start);
	device_destroy_namespace(vz_con_class, dev, ve);
	__vz_vt_ve_fini(ve);
}

void vz_con_ve_fini(struct ve_struct *ve)
{
	if (ve != get_ve0())
		return __vz_con_ve_fini(ve);
}
EXPORT_SYMBOL_GPL(vz_con_ve_fini);

static int __init vz_con_init(void)
{
#define TTY_DRIVER_ALLOC_FLAGS			\
	(TTY_DRIVER_REAL_RAW		|	\
	 TTY_DRIVER_RESET_TERMIOS	|	\
	 TTY_DRIVER_UNNUMBERED_NODE	|	\
	 TTY_DRIVER_DEVPTS_MEM		|	\
	 TTY_DRIVER_DYNAMIC_ALLOC	|	\
	 TTY_DRIVER_DYNAMIC_DEV		|	\
	 TTY_DRIVER_CONTAINERIZED)

	int ret = 0;

	ret = class_register(&vz_con_class_base);
	if (ret) {
		pr_err("Can't register vzcon class\n");
		return ret;
	}

	vz_conm_driver = tty_alloc_driver(1, TTY_DRIVER_ALLOC_FLAGS);
	if (IS_ERR(vz_conm_driver)) {
		ret = PTR_ERR(vz_conm_driver);
		pr_err("Can't allocate vzcon master driver\n");
		goto err_class_unregister;
	}

	vz_cons_driver = tty_alloc_driver(1, TTY_DRIVER_ALLOC_FLAGS);
	if (IS_ERR(vz_cons_driver)) {
		ret = PTR_ERR(vz_cons_driver);
		pr_err("Can't allocate vzcon slave driver\n");
		goto err_put_master;
	}

	vz_conm_driver->driver_name	= "vzcon_master";
	vz_conm_driver->name		= "vzconm";
	vz_conm_driver->name_base	= 1;
	vz_conm_driver->major		= 0;
	vz_conm_driver->minor_start	= 1;
	vz_conm_driver->type		= TTY_DRIVER_TYPE_CONSOLE;
	vz_conm_driver->subtype		= PTY_TYPE_MASTER;
	vz_conm_driver->init_termios	= tty_std_termios;
	vz_conm_driver->ve		= get_ve0();
	tty_set_operations(vz_conm_driver, &vz_tty_fops);

	vz_cons_driver->driver_name	= "vzcon_slave";
	vz_cons_driver->name		= "vzcons";
	vz_cons_driver->name_base	= 1;
	vz_cons_driver->major		= 0;
	vz_cons_driver->minor_start	= 1;
	vz_cons_driver->type		= TTY_DRIVER_TYPE_CONSOLE;
	vz_conm_driver->subtype		= PTY_TYPE_SLAVE;
	vz_cons_driver->init_termios	= tty_std_termios;
	vz_cons_driver->ve		= get_ve0();
	tty_set_operations(vz_cons_driver, &vz_tty_fops);

	ret = tty_register_driver(vz_conm_driver);
	if (ret) {
		pr_err("Can't register vzcon master driver\n");
		goto err_put_slave;
	}
	ret = tty_register_driver(vz_cons_driver);
	if (ret) {
		pr_err("Can't register vzcon slave driver\n");
		goto err_unregister_master;
	}

	ret = __vz_con_ve_init(get_ve0());
	if (ret) {
		pr_err("Can't init for node\n");
		goto err_unregister_slave;
	}

	return 0;

err_unregister_slave:
	tty_unregister_driver(vz_cons_driver);
err_unregister_master:
	tty_unregister_driver(vz_conm_driver);
err_put_slave:
	put_tty_driver(vz_cons_driver);
err_put_master:
	put_tty_driver(vz_conm_driver);
err_class_unregister:
	class_unregister(&vz_con_class_base);
	return ret;
#undef TTY_DRIVER_ALLOC_FLAGS
}
module_init(vz_con_init);

static void __exit vz_con_exit(void)
{
	__vz_con_ve_fini(get_ve0());
	tty_unregister_driver(vz_conm_driver);
	tty_unregister_driver(vz_cons_driver);
	put_tty_driver(vz_conm_driver);
	put_tty_driver(vz_cons_driver);
	class_unregister(&vz_con_class_base);
}
module_exit(vz_con_exit)

struct tty_driver *vz_console_device(int *index)
{
	*index = VZ_CON_INDEX;
	return vz_conm_driver;
}
EXPORT_SYMBOL_GPL(vz_console_device);

struct tty_driver *vz_vt_device(struct ve_struct *ve, dev_t dev, int *index)
{
	BUG_ON(MINOR(dev) > VZ_VT_MAX_DEVS);

	*index = MINOR(dev) ? MINOR(dev) - 1 : 0;
	return ve->vz_vt_driver;
}
EXPORT_SYMBOL_GPL(vz_vt_device);
