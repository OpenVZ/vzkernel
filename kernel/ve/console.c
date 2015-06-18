#define pr_fmt(fmt) "vz con: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/console.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/tty.h>
#include <linux/ve.h>

static struct tty_driver *vz_con_driver;

struct vz_tty_priv {
	struct tty_port		port;
	struct ve_struct	*owner_ve;
};

static int vz_tty_install(struct tty_driver *driver, struct tty_struct *tty)
{
	static const struct tty_port_operations vz_tty_port_ops;
	struct vz_tty_priv *priv;
	int ret;

	BUG_ON(tty->index != 0);

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->owner_ve = get_exec_env();
	tty_port_init(&priv->port);
	priv->port.ops = &vz_tty_port_ops;
	tty->driver_data = priv;

	ret = tty_port_install(&priv->port, driver, tty);
	if (ret) {
		pr_err("Can't install tty port: %d\n", ret);
		goto err;
	}

	return 0;
err:
	tty_port_destroy(&priv->port);
	kfree(priv);
	return ret;
}

static int vz_tty_open(struct tty_struct *tty, struct file *filp)
{
	struct vz_tty_priv *priv = tty->driver_data;
	return tty_port_open(&priv->port, tty, filp);
}

static void vz_tty_close(struct tty_struct *tty, struct file *filp)
{
	struct vz_tty_priv *priv = tty->driver_data;
	tty_port_close(&priv->port, tty, filp);
}

static void vz_tty_cleanup(struct tty_struct *tty)
{
	struct vz_tty_priv *priv = tty->driver_data;

	tty->driver_data = NULL;
	priv->owner_ve = NULL;
	tty_port_destroy(&priv->port);
	kfree(priv);
}

static int vz_tty_write(struct tty_struct *tty, const unsigned char *buf, int count)
{
	return count;
}

static int vz_tty_write_room(struct tty_struct *tty)
{
	return 4096;
}

static void vz_tty_hangup(struct tty_struct *tty)
{
	struct vz_tty_priv *priv = tty->driver_data;
	tty_port_hangup(&priv->port);
}

static const struct tty_operations vz_tty_fops = {
	.install	= vz_tty_install,
	.open		= vz_tty_open,
	.close		= vz_tty_close,
	.cleanup	= vz_tty_cleanup,
	.write		= vz_tty_write,
	.write_room	= vz_tty_write_room,
	.hangup		= vz_tty_hangup,
};

static void __exit vz_exit(void)
{
	put_tty_driver(vz_con_driver);
}
module_exit(vz_exit)

static int __init init(void)
{
	int ret = 0;

	vz_con_driver = tty_alloc_driver(1,
					 TTY_DRIVER_REAL_RAW		|
					 TTY_DRIVER_RESET_TERMIOS	|
					 TTY_DRIVER_CONTAINERIZED);
	if (IS_ERR(vz_con_driver)) {
		pr_err("Couldn't allocate vzcon driver\n");
		return PTR_ERR(vz_con_driver);
	}

	vz_con_driver->driver_name	= "vzcon driver";
	vz_con_driver->name		= "vzcon";
	vz_con_driver->name_base	= 1;
	vz_con_driver->major		= 0;
	vz_con_driver->minor_start	= 1;
	vz_con_driver->type		= TTY_DRIVER_TYPE_CONSOLE;
	vz_con_driver->init_termios	= tty_std_termios;
	vz_con_driver->ve		= get_ve0();
	tty_set_operations(vz_con_driver, &vz_tty_fops);

	ret = tty_register_driver(vz_con_driver);
	if (ret) {
		pr_err("Couldn't register vzcon driver\n");
		put_tty_driver(vz_con_driver);
		return ret;
	}

	return 0;
}
module_init(init);

struct tty_driver *vz_console_device(int *index)
{
	*index = 0;
	return vz_con_driver;
}
EXPORT_SYMBOL(vz_console_device);

MODULE_DESCRIPTION("Virtuozzo Container console");
MODULE_LICENSE("GPL v2");
