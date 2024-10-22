// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Added support for a Unix98-style ptmx device.
 *    -- C. Scott Ananian <cananian@alumni.princeton.edu>, 14-Jan-1998
 *
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/fcntl.h>
#include <linux/sched/signal.h>
#include <linux/string.h>
#include <linux/major.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/bitops.h>
#include <linux/devpts_fs.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/ioctl.h>
#include <linux/compat.h>
#include "tty.h"

#undef TTY_DEBUG_HANGUP
#ifdef TTY_DEBUG_HANGUP
# define tty_debug_hangup(tty, f, args...)	tty_debug(tty, f, ##args)
#else
# define tty_debug_hangup(tty, f, args...)	do {} while (0)
#endif

#ifdef CONFIG_UNIX98_PTYS
static struct tty_driver *ptm_driver;
static struct tty_driver *pts_driver;
static DEFINE_MUTEX(devpts_mutex);
#endif

static void pty_close(struct tty_struct *tty, struct file *filp)
{
	if (tty->driver->subtype == PTY_TYPE_MASTER)
		WARN_ON(tty->count > 1);
	else {
		if (tty_io_error(tty))
			return;
		if (tty->count > 2)
			return;
	}
	set_bit(TTY_IO_ERROR, &tty->flags);
	wake_up_interruptible(&tty->read_wait);
	wake_up_interruptible(&tty->write_wait);
	spin_lock_irq(&tty->ctrl.lock);
	tty->ctrl.packet = false;
	spin_unlock_irq(&tty->ctrl.lock);
	/* Review - krefs on tty_link ?? */
	if (!tty->link)
		return;
	set_bit(TTY_OTHER_CLOSED, &tty->link->flags);
	wake_up_interruptible(&tty->link->read_wait);
	wake_up_interruptible(&tty->link->write_wait);
	if (tty->driver->subtype == PTY_TYPE_MASTER) {
		set_bit(TTY_OTHER_CLOSED, &tty->flags);
#ifdef CONFIG_UNIX98_PTYS
		if (tty->driver == ptm_driver) {
			mutex_lock(&devpts_mutex);
			if (tty->link->driver_data)
				devpts_pty_kill(tty->link->driver_data);
			mutex_unlock(&devpts_mutex);
		}
#endif
		tty_vhangup(tty->link);
	}
}

/*
 * The unthrottle routine is called by the line discipline to signal
 * that it can receive more characters.  For PTY's, the TTY_THROTTLED
 * flag is always set, to force the line discipline to always call the
 * unthrottle routine when there are fewer than TTY_THRESHOLD_UNTHROTTLE
 * characters in the queue.  This is necessary since each time this
 * happens, we need to wake up any sleeping processes that could be
 * (1) trying to send data to the pty, or (2) waiting in wait_until_sent()
 * for the pty buffer to be drained.
 */
static void pty_unthrottle(struct tty_struct *tty)
{
	tty_wakeup(tty->link);
	set_bit(TTY_THROTTLED, &tty->flags);
}

/**
 *	pty_write		-	write to a pty
 *	@tty: the tty we write from
 *	@buf: kernel buffer of data
 *	@c: bytes to write
 *
 *	Our "hardware" write method. Data is coming from the ldisc which
 *	may be in a non sleeping state. We simply throw this at the other
 *	end of the link as if we were an IRQ handler receiving stuff for
 *	the other side of the pty/tty pair.
 */

static int pty_write(struct tty_struct *tty, const unsigned char *buf, int c)
{
	struct tty_struct *to = tty->link;
	unsigned long flags;

	if (tty->flow.stopped)
		return 0;

	if (c > 0) {
		spin_lock_irqsave(&to->port->lock, flags);
		/* Stuff the data into the input queue of the other end */
		c = tty_insert_flip_string(to->port, buf, c);
		spin_unlock_irqrestore(&to->port->lock, flags);
		/* And shovel */
		if (c)
			tty_flip_buffer_push(to->port);
	}
	return c;
}

/**
 *	pty_write_room	-	write space
 *	@tty: tty we are writing from
 *
 *	Report how many bytes the ldisc can send into the queue for
 *	the other device.
 */

static unsigned int pty_write_room(struct tty_struct *tty)
{
	if (tty->flow.stopped)
		return 0;
	return tty_buffer_space_avail(tty->link->port);
}

/* Set the lock flag on a pty */
static int pty_set_lock(struct tty_struct *tty, int __user *arg)
{
	int val;

	if (get_user(val, arg))
		return -EFAULT;
	if (val)
		set_bit(TTY_PTY_LOCK, &tty->flags);
	else
		clear_bit(TTY_PTY_LOCK, &tty->flags);
	return 0;
}

static int pty_get_lock(struct tty_struct *tty, int __user *arg)
{
	int locked = test_bit(TTY_PTY_LOCK, &tty->flags);

	return put_user(locked, arg);
}

/* Set the packet mode on a pty */
static int pty_set_pktmode(struct tty_struct *tty, int __user *arg)
{
	int pktmode;

	if (get_user(pktmode, arg))
		return -EFAULT;

	spin_lock_irq(&tty->ctrl.lock);
	if (pktmode) {
		if (!tty->ctrl.packet) {
			tty->link->ctrl.pktstatus = 0;
			smp_mb();
			tty->ctrl.packet = true;
		}
	} else
		tty->ctrl.packet = false;
	spin_unlock_irq(&tty->ctrl.lock);

	return 0;
}

/* Get the packet mode of a pty */
static int pty_get_pktmode(struct tty_struct *tty, int __user *arg)
{
	int pktmode = tty->ctrl.packet;

	return put_user(pktmode, arg);
}

/* Send a signal to the slave */
static int pty_signal(struct tty_struct *tty, int sig)
{
	struct pid *pgrp;

	if (sig != SIGINT && sig != SIGQUIT && sig != SIGTSTP)
		return -EINVAL;

	if (tty->link) {
		pgrp = tty_get_pgrp(tty->link);
		if (pgrp)
			kill_pgrp(pgrp, sig, 1);
		put_pid(pgrp);
	}
	return 0;
}

static void pty_flush_buffer(struct tty_struct *tty)
{
	struct tty_struct *to = tty->link;

	if (!to)
		return;

	tty_buffer_flush(to, NULL);
	if (to->ctrl.packet) {
		spin_lock_irq(&tty->ctrl.lock);
		tty->ctrl.pktstatus |= TIOCPKT_FLUSHWRITE;
		wake_up_interruptible(&to->read_wait);
		spin_unlock_irq(&tty->ctrl.lock);
	}
}

static int pty_open(struct tty_struct *tty, struct file *filp)
{
	if (!tty || !tty->link)
		return -ENODEV;

	if (test_bit(TTY_OTHER_CLOSED, &tty->flags))
		goto out;
	if (test_bit(TTY_PTY_LOCK, &tty->link->flags))
		goto out;
	if (tty->driver->subtype == PTY_TYPE_SLAVE && tty->link->count != 1)
		goto out;

	clear_bit(TTY_IO_ERROR, &tty->flags);
	clear_bit(TTY_OTHER_CLOSED, &tty->link->flags);
	set_bit(TTY_THROTTLED, &tty->flags);
	return 0;

out:
	set_bit(TTY_IO_ERROR, &tty->flags);
	return -EIO;
}

static void pty_set_termios(struct tty_struct *tty,
					struct ktermios *old_termios)
{
	/* See if packet mode change of state. */
	if (tty->link && tty->link->ctrl.packet) {
		int extproc = (old_termios->c_lflag & EXTPROC) | L_EXTPROC(tty);
		int old_flow = ((old_termios->c_iflag & IXON) &&
				(old_termios->c_cc[VSTOP] == '\023') &&
				(old_termios->c_cc[VSTART] == '\021'));
		int new_flow = (I_IXON(tty) &&
				STOP_CHAR(tty) == '\023' &&
				START_CHAR(tty) == '\021');
		if ((old_flow != new_flow) || extproc) {
			spin_lock_irq(&tty->ctrl.lock);
			if (old_flow != new_flow) {
				tty->ctrl.pktstatus &= ~(TIOCPKT_DOSTOP | TIOCPKT_NOSTOP);
				if (new_flow)
					tty->ctrl.pktstatus |= TIOCPKT_DOSTOP;
				else
					tty->ctrl.pktstatus |= TIOCPKT_NOSTOP;
			}
			if (extproc)
				tty->ctrl.pktstatus |= TIOCPKT_IOCTL;
			spin_unlock_irq(&tty->ctrl.lock);
			wake_up_interruptible(&tty->link->read_wait);
		}
	}

	tty->termios.c_cflag &= ~(CSIZE | PARENB);
	tty->termios.c_cflag |= (CS8 | CREAD);
}

/**
 *	pty_resize		-	resize event
 *	@tty: tty being resized
 *	@ws: window size being set.
 *
 *	Update the termios variables and send the necessary signals to
 *	peform a terminal resize correctly
 */

static int pty_resize(struct tty_struct *tty,  struct winsize *ws)
{
	struct pid *pgrp, *rpgrp;
	struct tty_struct *pty = tty->link;

	/* For a PTY we need to lock the tty side */
	mutex_lock(&tty->winsize_mutex);
	if (!memcmp(ws, &tty->winsize, sizeof(*ws)))
		goto done;

	/* Signal the foreground process group of both ptys */
	pgrp = tty_get_pgrp(tty);
	rpgrp = tty_get_pgrp(pty);

	if (pgrp)
		kill_pgrp(pgrp, SIGWINCH, 1);
	if (rpgrp != pgrp && rpgrp)
		kill_pgrp(rpgrp, SIGWINCH, 1);

	put_pid(pgrp);
	put_pid(rpgrp);

	tty->winsize = *ws;
	pty->winsize = *ws;	/* Never used so will go away soon */
done:
	mutex_unlock(&tty->winsize_mutex);
	return 0;
}

/**
 *	pty_start - start() handler
 *	pty_stop  - stop() handler
 *	@tty: tty being flow-controlled
 *
 *	Propagates the TIOCPKT status to the master pty.
 *
 *	NB: only the master pty can be in packet mode so only the slave
 *	    needs start()/stop() handlers
 */
static void pty_start(struct tty_struct *tty)
{
	unsigned long flags;

	if (tty->link && tty->link->ctrl.packet) {
		spin_lock_irqsave(&tty->ctrl.lock, flags);
		tty->ctrl.pktstatus &= ~TIOCPKT_STOP;
		tty->ctrl.pktstatus |= TIOCPKT_START;
		spin_unlock_irqrestore(&tty->ctrl.lock, flags);
		wake_up_interruptible_poll(&tty->link->read_wait, EPOLLIN);
	}
}

static void pty_stop(struct tty_struct *tty)
{
	unsigned long flags;

	if (tty->link && tty->link->ctrl.packet) {
		spin_lock_irqsave(&tty->ctrl.lock, flags);
		tty->ctrl.pktstatus &= ~TIOCPKT_START;
		tty->ctrl.pktstatus |= TIOCPKT_STOP;
		spin_unlock_irqrestore(&tty->ctrl.lock, flags);
		wake_up_interruptible_poll(&tty->link->read_wait, EPOLLIN);
	}
}

/**
 *	pty_common_install		-	set up the pty pair
 *	@driver: the pty driver
 *	@tty: the tty being instantiated
 *	@legacy: true if this is BSD style
 *
 *	Perform the initial set up for the tty/pty pair. Called from the
 *	tty layer when the port is first opened.
 *
 *	Locking: the caller must hold the tty_mutex
 */
static int pty_common_install(struct tty_driver *driver, struct tty_struct *tty,
		bool legacy)
{
	struct tty_struct *o_tty;
	struct tty_port *ports[2];
	int idx = tty->index;
	int retval = -ENOMEM;

	/* Opening the slave first has always returned -EIO */
	if (driver->subtype != PTY_TYPE_MASTER)
		return -EIO;

	ports[0] = kmalloc(sizeof **ports, GFP_KERNEL);
	ports[1] = kmalloc(sizeof **ports, GFP_KERNEL);
	if (!ports[0] || !ports[1])
		goto err;
	if (!try_module_get(driver->other->owner)) {
		/* This cannot in fact currently happen */
		goto err;
	}
	o_tty = alloc_tty_struct(driver->other, idx);
	if (!o_tty)
		goto err_put_module;

	tty_set_lock_subclass(o_tty);
	lockdep_set_subclass(&o_tty->termios_rwsem, TTY_LOCK_SLAVE);

	if (legacy) {
		/* We always use new tty termios data so we can do this
		   the easy way .. */
		tty_init_termios(tty);
		tty_init_termios(o_tty);

		driver->other->ttys[idx] = o_tty;
		driver->ttys[idx] = tty;
	} else {
		memset(&tty->termios_locked, 0, sizeof(tty->termios_locked));
		tty->termios = driver->init_termios;
		memset(&o_tty->termios_locked, 0, sizeof(tty->termios_locked));
		o_tty->termios = driver->other->init_termios;
	}

	/*
	 * Everything allocated ... set up the o_tty structure.
	 */
	tty_driver_kref_get(driver->other);
	/* Establish the links in both directions */
	tty->link   = o_tty;
	o_tty->link = tty;
	tty_port_init(ports[0]);
	tty_port_init(ports[1]);
	tty_buffer_set_limit(ports[0], 8192);
	tty_buffer_set_limit(ports[1], 8192);
	o_tty->port = ports[0];
	tty->port = ports[1];
	o_tty->port->itty = o_tty;

	tty_buffer_set_lock_subclass(o_tty->port);

	tty_driver_kref_get(driver);
	tty->count++;
	o_tty->count++;
	return 0;

err_put_module:
	module_put(driver->other->owner);
err:
	kfree(ports[0]);
	kfree(ports[1]);
	return retval;
}

static void pty_cleanup(struct tty_struct *tty)
{
	tty_port_put(tty->port);
}

/* Traditional BSD devices */
#ifdef CONFIG_LEGACY_PTYS

static int pty_install(struct tty_driver *driver, struct tty_struct *tty)
{
	return pty_common_install(driver, tty, true);
}

static void pty_remove(struct tty_driver *driver, struct tty_struct *tty)
{
	struct tty_struct *pair = tty->link;

	driver->ttys[tty->index] = NULL;
	if (pair)
		pair->driver->ttys[pair->index] = NULL;
}

static int pty_bsd_ioctl(struct tty_struct *tty,
			 unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case TIOCSPTLCK: /* Set PT Lock (disallow slave open) */
		return pty_set_lock(tty, (int __user *) arg);
	case TIOCGPTLCK: /* Get PT Lock status */
		return pty_get_lock(tty, (int __user *)arg);
	case TIOCPKT: /* Set PT packet mode */
		return pty_set_pktmode(tty, (int __user *)arg);
	case TIOCGPKT: /* Get PT packet mode */
		return pty_get_pktmode(tty, (int __user *)arg);
	case TIOCSIG:    /* Send signal to other side of pty */
		return pty_signal(tty, (int) arg);
	case TIOCGPTN: /* TTY returns ENOTTY, but glibc expects EINVAL here */
		return -EINVAL;
	}
	return -ENOIOCTLCMD;
}

#ifdef CONFIG_COMPAT
static long pty_bsd_compat_ioctl(struct tty_struct *tty,
				 unsigned int cmd, unsigned long arg)
{
	/*
	 * PTY ioctls don't require any special translation between 32-bit and
	 * 64-bit userspace, they are already compatible.
	 */
	return pty_bsd_ioctl(tty, cmd, (unsigned long)compat_ptr(arg));
}
#else
#define pty_bsd_compat_ioctl NULL
#endif

static int legacy_count = CONFIG_LEGACY_PTY_COUNT;
/*
 * not really modular, but the easiest way to keep compat with existing
 * bootargs behaviour is to continue using module_param here.
 */
module_param(legacy_count, int, 0);

/*
 * The master side of a pty can do TIOCSPTLCK and thus
 * has pty_bsd_ioctl.
 */
static const struct tty_operations master_pty_ops_bsd = {
	.install = pty_install,
	.open = pty_open,
	.close = pty_close,
	.write = pty_write,
	.write_room = pty_write_room,
	.flush_buffer = pty_flush_buffer,
	.unthrottle = pty_unthrottle,
	.ioctl = pty_bsd_ioctl,
	.compat_ioctl = pty_bsd_compat_ioctl,
	.cleanup = pty_cleanup,
	.resize = pty_resize,
	.remove = pty_remove
};

static const struct tty_operations slave_pty_ops_bsd = {
	.install = pty_install,
	.open = pty_open,
	.close = pty_close,
	.write = pty_write,
	.write_room = pty_write_room,
	.flush_buffer = pty_flush_buffer,
	.unthrottle = pty_unthrottle,
	.set_termios = pty_set_termios,
	.cleanup = pty_cleanup,
	.resize = pty_resize,
	.start = pty_start,
	.stop = pty_stop,
	.remove = pty_remove
};

static void __init legacy_pty_init(void)
{
	struct tty_driver *pty_driver, *pty_slave_driver;

	if (legacy_count <= 0)
		return;

	pty_driver = tty_alloc_driver(legacy_count,
			TTY_DRIVER_RESET_TERMIOS |
			TTY_DRIVER_REAL_RAW |
			TTY_DRIVER_DYNAMIC_ALLOC);
	if (IS_ERR(pty_driver))
		panic("Couldn't allocate pty driver");

	pty_slave_driver = tty_alloc_driver(legacy_count,
			TTY_DRIVER_RESET_TERMIOS |
			TTY_DRIVER_REAL_RAW |
			TTY_DRIVER_DYNAMIC_ALLOC);
	if (IS_ERR(pty_slave_driver))
		panic("Couldn't allocate pty slave driver");

	pty_driver->driver_name = "pty_master";
	pty_driver->name = "pty";
	pty_driver->major = PTY_MASTER_MAJOR;
	pty_driver->minor_start = 0;
	pty_driver->type = TTY_DRIVER_TYPE_PTY;
	pty_driver->subtype = PTY_TYPE_MASTER;
	pty_driver->init_termios = tty_std_termios;
	pty_driver->init_termios.c_iflag = 0;
	pty_driver->init_termios.c_oflag = 0;
	pty_driver->init_termios.c_cflag = B38400 | CS8 | CREAD;
	pty_driver->init_termios.c_lflag = 0;
	pty_driver->init_termios.c_ispeed = 38400;
	pty_driver->init_termios.c_ospeed = 38400;
	pty_driver->other = pty_slave_driver;
	tty_set_operations(pty_driver, &master_pty_ops_bsd);

	pty_slave_driver->driver_name = "pty_slave";
	pty_slave_driver->name = "ttyp";
	pty_slave_driver->major = PTY_SLAVE_MAJOR;
	pty_slave_driver->minor_start = 0;
	pty_slave_driver->type = TTY_DRIVER_TYPE_PTY;
	pty_slave_driver->subtype = PTY_TYPE_SLAVE;
	pty_slave_driver->init_termios = tty_std_termios;
	pty_slave_driver->init_termios.c_cflag = B38400 | CS8 | CREAD;
	pty_slave_driver->init_termios.c_ispeed = 38400;
	pty_slave_driver->init_termios.c_ospeed = 38400;
	pty_slave_driver->other = pty_driver;
	tty_set_operations(pty_slave_driver, &slave_pty_ops_bsd);

	if (tty_register_driver(pty_driver))
		panic("Couldn't register pty driver");
	if (tty_register_driver(pty_slave_driver))
		panic("Couldn't register pty slave driver");
}
#else
static inline void legacy_pty_init(void) { }
#endif

#if defined(CONFIG_VE)

/*
 * VTTY architecture overview.
 *
 * With VTTY we make /dev/console and /dev/tty[X] virtualized
 * per container (note the real names may vary because the
 * kernel itself uses major:minor numbers to distinguish
 * devices and doesn't care how they are named inside /dev.
 * /dev/console stands for TTYAUX_MAJOR:1 while /dev/tty[X]
 * stands for TTY_MAJOR:[0:12]. That said from inside of
 * VTTY /dev/console is the same as /dev/tty0.
 *
 * For every container here is a tty map represented by
 * vtty_map_t. It carries @veid of VE and associated slave
 * tty peers.
 *
 * map
 *  veid -> CTID
 *    vttys -> [ 0 ]
 *               `- @slave -> link -> @master
 *             [ 1 ]
 *               `- @slave -> link -> @master
 */

#include <linux/ve.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>

static struct tty_driver *vttym_driver;
static struct tty_driver *vttys_driver;
static DEFINE_IDR(vtty_idr);

static struct file_operations vtty_fops;

#define MAX_NR_VTTY_CONSOLES	(12)
#define vtty_match_index(idx)	((idx) >= 0 && (idx) < MAX_NR_VTTY_CONSOLES)

bool vtty_is_master(struct tty_struct *tty)
{
	return tty->driver == vttym_driver;
}

typedef struct {
	envid_t			veid;
	struct tty_struct	*vttys[MAX_NR_VTTY_CONSOLES];
} vtty_map_t;

static vtty_map_t *vtty_map_lookup(envid_t veid)
{
	lockdep_assert_held(&tty_mutex);
	return idr_find(&vtty_idr, veid);
}

static void vtty_map_set(vtty_map_t *map, struct tty_struct *tty)
{
	lockdep_assert_held(&tty_mutex);
	WARN_ON(map->vttys[tty->index]);

	tty->driver_data = tty->link->driver_data = map;
	map->vttys[tty->index] = tty;
}

static void vtty_map_free(vtty_map_t *map)
{
	lockdep_assert_held(&tty_mutex);
	idr_remove(&vtty_idr, map->veid);
	kfree(map);
}

static void vtty_map_clear(struct tty_struct *tty)
{
	vtty_map_t *map = tty->driver_data;

	lockdep_assert_held(&tty_mutex);
	if (map) {
		struct tty_struct *p = map->vttys[tty->index];
		int i;

		WARN_ON(p != (tty->driver == vttys_driver ? tty : tty->link));
		map->vttys[tty->index] = NULL;
		tty->driver_data = tty->link->driver_data = NULL;

		for (i = 0; i < MAX_NR_VTTY_CONSOLES; i++) {
			if (map->vttys[i])
				break;
		}
		if (i >= MAX_NR_VTTY_CONSOLES)
			vtty_map_free(map);
	}
}

static vtty_map_t *vtty_map_alloc(envid_t veid)
{
	vtty_map_t *map = kzalloc(sizeof(*map), GFP_KERNEL);

	lockdep_assert_held(&tty_mutex);
	if (map) {
		int id;

		map->veid = veid;
		id = idr_alloc(&vtty_idr, map, veid, veid + 1, GFP_KERNEL);
		if (id < 0) {
			kfree(map);
			return ERR_PTR(id);
		}
	} else
		map = ERR_PTR(-ENOMEM);
	return map;
}

/*
 * vttys are never supposed to be opened from inside
 * of VE0 except special ioctl call, so treat zero as
 * "unused" sign.
 */
static envid_t vtty_context_veid;

static void vtty_set_context(envid_t veid)
{
	lockdep_assert_held(&tty_mutex);
	WARN_ON(!veid);
	vtty_context_veid = veid;
}

static void vtty_drop_context(void)
{
	lockdep_assert_held(&tty_mutex);
	vtty_context_veid = 0;
}

static envid_t vtty_get_context(void)
{
	lockdep_assert_held(&tty_mutex);
	return vtty_context_veid ?: get_exec_env()->veid;
}

static struct tty_struct *vtty_lookup(struct tty_driver *driver,
				      struct file *file, int idx)
{
	vtty_map_t *map = vtty_map_lookup(vtty_get_context());
	struct tty_struct *tty;

	if (!vtty_match_index(idx))
		return ERR_PTR(-EIO);

	/*
	 * Nothing ever been opened yet, allocate a new
	 * tty map together with both peers from the scratch
	 * in install procedure.
	 */
	if (!map)
		return NULL;

	tty = map->vttys[idx];
	if (tty) {
		if (driver == vttym_driver)
			tty = tty->link;
		WARN_ON(!tty);
	}
	return tty;
}

static void vtty_standard_install(struct tty_driver *driver,
				  struct tty_struct *tty)
{
	tty_init_termios(tty);

	tty_driver_kref_get(driver);
	tty_port_init(tty->port);
	tty_buffer_set_limit(tty->port, 8192);
	tty->port->itty = tty;
}

static struct tty_struct *vtty_install_peer(struct tty_driver *driver,
					    struct tty_port *port, int index)
{
	struct tty_struct *tty;

	tty = alloc_tty_struct(driver, index);
	if (!tty)
		return ERR_PTR(-ENOMEM);
	tty->port = port;
	vtty_standard_install(driver, tty);
	return tty;
}

static int vtty_install(struct tty_driver *driver, struct tty_struct *tty)
{
	envid_t veid = vtty_get_context();
	struct tty_port *peer_port;
	struct tty_struct *peer;
	vtty_map_t *map;
	int ret;

	WARN_ON_ONCE(driver != vttys_driver);

	map = vtty_map_lookup(veid);
	if (!map) {
		map = vtty_map_alloc(veid);
		if (IS_ERR(map))
			return PTR_ERR(map);
	}

	tty->port = kzalloc(sizeof(*tty->port), GFP_KERNEL);
	peer_port = kzalloc(sizeof(*peer_port), GFP_KERNEL);
	if (!tty->port || !peer_port) {
		ret = -ENOMEM;
		goto err_free;
	}

	peer = vtty_install_peer(vttym_driver, peer_port, tty->index);
	if (IS_ERR(peer)) {
		ret = PTR_ERR(peer);
		goto err_free;
	}

	vtty_standard_install(vttys_driver, tty);
	tty->count++;

	tty->link = peer;
	peer->link = tty;

	vtty_map_set(map, tty);
	return 0;

err_free:
	kfree(tty->port);
	kfree(peer_port);
	return ret;
}

static int vtty_open(struct tty_struct *tty, struct file *filp)
{
	set_bit(TTY_THROTTLED, &tty->flags);
	return 0;
}

static void vtty_close(struct tty_struct *tty, struct file *filp)
{
	int count = (tty->driver == vttys_driver) ? 2 : 1;
	if (tty->count <= count) {
		wake_up_interruptible(&tty->read_wait);
		wake_up_interruptible(&tty->write_wait);

		wake_up_interruptible(&tty->link->read_wait);
		wake_up_interruptible(&tty->link->write_wait);
	}
}

static void vtty_shutdown(struct tty_struct *tty)
{
	vtty_map_clear(tty);
}

static int vtty_write(struct tty_struct *tty,
		      const unsigned char *buf, int count)
{
	struct tty_struct *peer = tty->link;

	if (tty->flow.stopped)
		return 0;

	if (count > 0) {
		count = tty_insert_flip_string(peer->port, buf, count);
		if (count) {
			tty_flip_buffer_push(peer->port);
			tty_wakeup(tty);
		} else {
			int _count = (tty->driver == vttym_driver) ? 2 : 1;
			/*
			 * Flush the slave reader if noone
			 * is actually hooked on. Otherwise
			 * wait until reader fetch all data.
			 */
			if (peer->count < _count)
				tty_perform_flush(peer, TCIFLUSH);
		}
	}

	return count;
}

static unsigned int vtty_write_room(struct tty_struct *tty)
{
	struct tty_struct *peer = tty->link;

	if (tty->flow.stopped)
		return 0;

	return tty_buffer_space_avail(peer->port);
}

static void vtty_remove(struct tty_driver *driver, struct tty_struct *tty)
{
}

static int vtty_resize(struct tty_struct *tty, struct winsize *ws)
{
	if (tty->driver == vttym_driver)
		return pty_resize(tty, ws);
	return tty_do_resize(tty, ws);
}

static const struct tty_operations vtty_ops = {
	.lookup		= vtty_lookup,
	.install	= vtty_install,
	.open		= vtty_open,
	.close		= vtty_close,
	.shutdown	= vtty_shutdown,
	.cleanup	= pty_cleanup,
	.write		= vtty_write,
	.write_room	= vtty_write_room,
	.set_termios	= pty_set_termios,
	.unthrottle	= pty_unthrottle,
	.flush_buffer	= pty_flush_buffer,
	.remove		= vtty_remove,
	.resize		= vtty_resize,
};

struct tty_driver *vtty_console_driver(int *index)
{
	*index = 0;
	return vttys_driver;
}

struct tty_driver *vtty_driver(dev_t dev, int *index)
{
	if (MAJOR(dev) == TTY_MAJOR &&
	MINOR(dev) <= MAX_NR_VTTY_CONSOLES) {
		if (MINOR(dev))
			*index = MINOR(dev) - 1;
		else
			*index = 0;
		return vttys_driver;
	}
	return NULL;
}

void vtty_release(struct tty_struct *tty, struct tty_struct *o_tty,
		  int *tty_closing, int *o_tty_closing)
{
	int pty_master;
	lockdep_assert_held(&tty_mutex);

	if (tty->driver != vttym_driver &&
	    tty->driver != vttys_driver)
		return;

	pty_master = (tty->driver == vttym_driver);

	/*
	 * Do not close master while slave is active.
	 */
	if (!*o_tty_closing && pty_master)
		*tty_closing = 0;

	/*
	 * Do not close master if we've closing
	 * not the last slave even if there is no
	 * readers on the master.
	 */
	if (*o_tty_closing && !*tty_closing && !pty_master)
		*o_tty_closing = 0;
}

static int __init vtty_init(void)
{
#define VTTY_DRIVER_ALLOC_FLAGS			\
	(TTY_DRIVER_REAL_RAW		|	\
	 TTY_DRIVER_RESET_TERMIOS	|	\
	 TTY_DRIVER_DYNAMIC_DEV		|	\
	 TTY_DRIVER_INSTALLED		|	\
	 TTY_DRIVER_DEVPTS_MEM)

	vttym_driver = tty_alloc_driver(MAX_NR_VTTY_CONSOLES,
					VTTY_DRIVER_ALLOC_FLAGS);
	if (IS_ERR(vttym_driver))
		panic(pr_fmt("Can't allocate master vtty driver\n"));

	vttys_driver = tty_alloc_driver(MAX_NR_VTTY_CONSOLES,
					VTTY_DRIVER_ALLOC_FLAGS);
	if (IS_ERR(vttys_driver))
		panic(pr_fmt("Can't allocate slave vtty driver\n"));

	vttym_driver->driver_name		= "vtty_master";
	vttym_driver->name			= "vttym";
	vttym_driver->name_base			= 0;
	vttym_driver->major			= 0;
	vttym_driver->minor_start		= 0;
	vttym_driver->type			= TTY_DRIVER_TYPE_PTY;
	vttym_driver->subtype			= PTY_TYPE_MASTER;
	vttym_driver->init_termios		= tty_std_termios;
	vttym_driver->init_termios.c_iflag	= 0;
	vttym_driver->init_termios.c_oflag	= 0;

	/* 38400 boud rate, 8 bit char size, enable receiver */
	vttym_driver->init_termios.c_cflag	= B38400 | CS8 | CREAD;
	vttym_driver->init_termios.c_lflag	= 0;
	vttym_driver->init_termios.c_ispeed	= 38400;
	vttym_driver->init_termios.c_ospeed	= 38400;
	tty_set_operations(vttym_driver, &vtty_ops);

	vttys_driver->driver_name		= "vtty_slave";
	vttys_driver->name			= "vttys";
	vttys_driver->name_base			= 0;
	vttys_driver->major			= 0;
	vttys_driver->minor_start		= 0;
	vttys_driver->type			= TTY_DRIVER_TYPE_PTY;
	vttys_driver->subtype			= PTY_TYPE_SLAVE;
	vttys_driver->init_termios		= tty_std_termios;
	vttys_driver->init_termios.c_cflag	= B38400 | CS8 | CREAD;
	vttys_driver->init_termios.c_ispeed	= 38400;
	vttys_driver->init_termios.c_ospeed	= 38400;
	tty_set_operations(vttys_driver, &vtty_ops);

	if (tty_register_driver(vttym_driver))
		panic(pr_fmt("Can't register master vtty driver\n"));

	if (tty_register_driver(vttys_driver))
		panic(pr_fmt("Can't register slave vtty driver\n"));

	tty_default_fops(&vtty_fops);
	return 0;
}

void vtty_alloc_tty_struct(const struct tty_driver *driver,
			   struct tty_struct *o_tty)
{
	if (driver != vttys_driver)
		return;

	tty_set_lock_subclass(o_tty);
	lockdep_set_subclass(&o_tty->termios_rwsem, TTY_LOCK_SLAVE);
}

int vtty_open_master(envid_t veid, int idx)
{
	struct tty_struct *tty;
	struct file *file;
	char devname[64];
	int fd, ret;

	if (!vtty_match_index(idx))
		return -EIO;

	fd = get_unused_fd_flags(0);
	if (fd < 0)
		return fd;

	snprintf(devname, sizeof(devname), "v%utty%d", veid, idx);
	file = anon_inode_getfile(devname, &vtty_fops, NULL, O_RDWR);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		goto err_put_unused_fd;
	}
	nonseekable_open(NULL, file);

	ret = tty_alloc_file(file);
	if (ret)
		goto err_fput;

	/*
	 * Opening comes from ve0 context so
	 * setup VE's context until master fetched.
	 * This is done under @tty_mutex so noone
	 * else would access it while we're holding
	 * the lock.
	 */
	mutex_lock(&tty_mutex);
	vtty_set_context(veid);

	tty = vtty_lookup(vttym_driver, NULL, idx);
	if (IS_ERR(tty)) {
		ret = PTR_ERR(tty);
		goto err_install;
	}

	if (!tty) {
		tty = tty_init_dev(vttys_driver, idx);
		if (IS_ERR(tty)) {
			ret = PTR_ERR(tty);
			goto err_install;
		}
		tty->count--;
		tty_unlock(tty);
		tty = tty->link;
	}

	/* One master at a time */
	if (tty->count >= 1) {
		ret = -EBUSY;
		goto err_install;
	}

	vtty_drop_context();

	/*
	 * We're the master peer so increment
	 * slave counter as well.
	 */
	tty_add_file(tty, file);
	tty->count++;
	tty->link->count++;
	fd_install(fd, file);
	vtty_open(tty, file);

	mutex_unlock(&tty_mutex);
	ret = fd;
out:
	return ret;

err_install:
	vtty_drop_context();
	mutex_unlock(&tty_mutex);
	tty_free_file(file);
err_fput:
	/*
	 * __fput will try to call file->f_op->fasync and file->f_op->release
	 * We don't want that.
	 * fasync ( will not get called without FASYNC flag.
	 * release (tty_release in our case) has private_data == NULL checked
	 * for early return.
	 */
	file->f_flags &= ~FASYNC;
	fput(file);
err_put_unused_fd:
	put_unused_fd(fd);
	goto out;
}
EXPORT_SYMBOL(vtty_open_master);
#else
static void vtty_init(void) { };
#endif /* CONFIG_VE */


/* Unix98 devices */
#ifdef CONFIG_UNIX98_PTYS
static struct cdev ptmx_cdev;

/**
 *	ptm_open_peer - open the peer of a pty
 *	@master: the open struct file of the ptmx device node
 *	@tty: the master of the pty being opened
 *	@flags: the flags for open
 *
 *	Provide a race free way for userspace to open the slave end of a pty
 *	(where they have the master fd and cannot access or trust the mount
 *	namespace /dev/pts was mounted inside).
 */
int ptm_open_peer(struct file *master, struct tty_struct *tty, int flags)
{
	int fd;
	struct file *filp;
	int retval = -EINVAL;
	struct path path;

	if (tty->driver != ptm_driver)
		return -EIO;

	fd = get_unused_fd_flags(flags);
	if (fd < 0) {
		retval = fd;
		goto err;
	}

	/* Compute the slave's path */
	path.mnt = devpts_mntget(master, tty->driver_data);
	if (IS_ERR(path.mnt)) {
		retval = PTR_ERR(path.mnt);
		goto err_put;
	}
	path.dentry = tty->link->driver_data;

	filp = dentry_open(&path, flags, current_cred());
	mntput(path.mnt);
	if (IS_ERR(filp)) {
		retval = PTR_ERR(filp);
		goto err_put;
	}

	fd_install(fd, filp);
	return fd;

err_put:
	put_unused_fd(fd);
err:
	return retval;
}

static int pty_unix98_ioctl(struct tty_struct *tty,
			    unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case TIOCSPTLCK: /* Set PT Lock (disallow slave open) */
		return pty_set_lock(tty, (int __user *)arg);
	case TIOCGPTLCK: /* Get PT Lock status */
		return pty_get_lock(tty, (int __user *)arg);
	case TIOCPKT: /* Set PT packet mode */
		return pty_set_pktmode(tty, (int __user *)arg);
	case TIOCGPKT: /* Get PT packet mode */
		return pty_get_pktmode(tty, (int __user *)arg);
	case TIOCGPTN: /* Get PT Number */
		return put_user(tty->index, (unsigned int __user *)arg);
	case TIOCSIG:    /* Send signal to other side of pty */
		return pty_signal(tty, (int) arg);
	}

	return -ENOIOCTLCMD;
}

#ifdef CONFIG_COMPAT
static long pty_unix98_compat_ioctl(struct tty_struct *tty,
				 unsigned int cmd, unsigned long arg)
{
	/*
	 * PTY ioctls don't require any special translation between 32-bit and
	 * 64-bit userspace, they are already compatible.
	 */
	return pty_unix98_ioctl(tty, cmd,
		cmd == TIOCSIG ? arg : (unsigned long)compat_ptr(arg));
}
#else
#define pty_unix98_compat_ioctl NULL
#endif

/**
 *	ptm_unix98_lookup	-	find a pty master
 *	@driver: ptm driver
 *	@file: unused
 *	@idx: tty index
 *
 *	Look up a pty master device. Called under the tty_mutex for now.
 *	This provides our locking.
 */

static struct tty_struct *ptm_unix98_lookup(struct tty_driver *driver,
		struct file *file, int idx)
{
	/* Master must be open via /dev/ptmx */
	return ERR_PTR(-EIO);
}

/**
 *	pts_unix98_lookup	-	find a pty slave
 *	@driver: pts driver
 *	@file: file pointer to tty
 *	@idx: tty index
 *
 *	Look up a pty master device. Called under the tty_mutex for now.
 *	This provides our locking for the tty pointer.
 */

static struct tty_struct *pts_unix98_lookup(struct tty_driver *driver,
		struct file *file, int idx)
{
	struct tty_struct *tty;

	mutex_lock(&devpts_mutex);
	tty = devpts_get_priv(file->f_path.dentry);
	mutex_unlock(&devpts_mutex);
	/* Master must be open before slave */
	if (!tty)
		return ERR_PTR(-EIO);
	return tty;
}

static int pty_unix98_install(struct tty_driver *driver, struct tty_struct *tty)
{
	return pty_common_install(driver, tty, false);
}

/* this is called once with whichever end is closed last */
static void pty_unix98_remove(struct tty_driver *driver, struct tty_struct *tty)
{
	struct pts_fs_info *fsi;

	if (tty->driver->subtype == PTY_TYPE_MASTER)
		fsi = tty->driver_data;
	else
		fsi = tty->link->driver_data;

	if (fsi) {
		devpts_kill_index(fsi, tty->index);
		devpts_release(fsi);
	}
}

static void pty_show_fdinfo(struct tty_struct *tty, struct seq_file *m)
{
	seq_printf(m, "tty-index:\t%d\n", tty->index);
}

static const struct tty_operations ptm_unix98_ops = {
	.lookup = ptm_unix98_lookup,
	.install = pty_unix98_install,
	.remove = pty_unix98_remove,
	.open = pty_open,
	.close = pty_close,
	.write = pty_write,
	.write_room = pty_write_room,
	.flush_buffer = pty_flush_buffer,
	.unthrottle = pty_unthrottle,
	.ioctl = pty_unix98_ioctl,
	.compat_ioctl = pty_unix98_compat_ioctl,
	.resize = pty_resize,
	.cleanup = pty_cleanup,
	.show_fdinfo = pty_show_fdinfo,
};

static const struct tty_operations pty_unix98_ops = {
	.lookup = pts_unix98_lookup,
	.install = pty_unix98_install,
	.remove = pty_unix98_remove,
	.open = pty_open,
	.close = pty_close,
	.write = pty_write,
	.write_room = pty_write_room,
	.flush_buffer = pty_flush_buffer,
	.unthrottle = pty_unthrottle,
	.set_termios = pty_set_termios,
	.start = pty_start,
	.stop = pty_stop,
	.cleanup = pty_cleanup,
};

/**
 *	ptmx_open		-	open a unix 98 pty master
 *	@inode: inode of device file
 *	@filp: file pointer to tty
 *
 *	Allocate a unix98 pty master device from the ptmx driver.
 *
 *	Locking: tty_mutex protects the init_dev work. tty->count should
 *		protect the rest.
 *		allocated_ptys_lock handles the list of free pty numbers
 */

static int ptmx_open(struct inode *inode, struct file *filp)
{
	struct pts_fs_info *fsi;
	struct tty_struct *tty;
	struct dentry *dentry;
	int retval;
	int index;

	nonseekable_open(inode, filp);

	/* We refuse fsnotify events on ptmx, since it's a shared resource */
	filp->f_mode |= FMODE_NONOTIFY;

	retval = tty_alloc_file(filp);
	if (retval)
		return retval;

	fsi = devpts_acquire(filp);
	if (IS_ERR(fsi)) {
		retval = PTR_ERR(fsi);
		goto out_free_file;
	}

	/* find a device that is not in use. */
	mutex_lock(&devpts_mutex);
	index = devpts_new_index(fsi);
	mutex_unlock(&devpts_mutex);

	retval = index;
	if (index < 0)
		goto out_put_fsi;


	mutex_lock(&tty_mutex);
	tty = tty_init_dev(ptm_driver, index);
	/* The tty returned here is locked so we can safely
	   drop the mutex */
	mutex_unlock(&tty_mutex);

	retval = PTR_ERR(tty);
	if (IS_ERR(tty))
		goto out;

	/*
	 * From here on out, the tty is "live", and the index and
	 * fsi will be killed/put by the tty_release()
	 */
	set_bit(TTY_PTY_LOCK, &tty->flags); /* LOCK THE SLAVE */
	tty->driver_data = fsi;

	tty_add_file(tty, filp);

	dentry = devpts_pty_new(fsi, index, tty->link);
	if (IS_ERR(dentry)) {
		retval = PTR_ERR(dentry);
		goto err_release;
	}
	tty->link->driver_data = dentry;

	retval = ptm_driver->ops->open(tty, filp);
	if (retval)
		goto err_release;

	tty_debug_hangup(tty, "opening (count=%d)\n", tty->count);

	tty_unlock(tty);
	return 0;
err_release:
	tty_unlock(tty);
	// This will also put-ref the fsi
	tty_release(inode, filp);
	return retval;
out:
	devpts_kill_index(fsi, index);
out_put_fsi:
	devpts_release(fsi);
out_free_file:
	tty_free_file(filp);
	return retval;
}

static struct file_operations ptmx_fops __ro_after_init;

static void __init unix98_pty_init(void)
{
	ptm_driver = tty_alloc_driver(NR_UNIX98_PTY_MAX,
			TTY_DRIVER_RESET_TERMIOS |
			TTY_DRIVER_REAL_RAW |
			TTY_DRIVER_DYNAMIC_DEV |
			TTY_DRIVER_DEVPTS_MEM |
			TTY_DRIVER_DYNAMIC_ALLOC);
	if (IS_ERR(ptm_driver))
		panic("Couldn't allocate Unix98 ptm driver");
	pts_driver = tty_alloc_driver(NR_UNIX98_PTY_MAX,
			TTY_DRIVER_RESET_TERMIOS |
			TTY_DRIVER_REAL_RAW |
			TTY_DRIVER_DYNAMIC_DEV |
			TTY_DRIVER_DEVPTS_MEM |
			TTY_DRIVER_DYNAMIC_ALLOC);
	if (IS_ERR(pts_driver))
		panic("Couldn't allocate Unix98 pts driver");

	ptm_driver->driver_name = "pty_master";
	ptm_driver->name = "ptm";
	ptm_driver->major = UNIX98_PTY_MASTER_MAJOR;
	ptm_driver->minor_start = 0;
	ptm_driver->type = TTY_DRIVER_TYPE_PTY;
	ptm_driver->subtype = PTY_TYPE_MASTER;
	ptm_driver->init_termios = tty_std_termios;
	ptm_driver->init_termios.c_iflag = 0;
	ptm_driver->init_termios.c_oflag = 0;
	ptm_driver->init_termios.c_cflag = B38400 | CS8 | CREAD;
	ptm_driver->init_termios.c_lflag = 0;
	ptm_driver->init_termios.c_ispeed = 38400;
	ptm_driver->init_termios.c_ospeed = 38400;
	ptm_driver->other = pts_driver;
	tty_set_operations(ptm_driver, &ptm_unix98_ops);

	pts_driver->driver_name = "pty_slave";
	pts_driver->name = "pts";
	pts_driver->major = UNIX98_PTY_SLAVE_MAJOR;
	pts_driver->minor_start = 0;
	pts_driver->type = TTY_DRIVER_TYPE_PTY;
	pts_driver->subtype = PTY_TYPE_SLAVE;
	pts_driver->init_termios = tty_std_termios;
	pts_driver->init_termios.c_cflag = B38400 | CS8 | CREAD;
	pts_driver->init_termios.c_ispeed = 38400;
	pts_driver->init_termios.c_ospeed = 38400;
	pts_driver->other = ptm_driver;
	tty_set_operations(pts_driver, &pty_unix98_ops);

	if (tty_register_driver(ptm_driver))
		panic("Couldn't register Unix98 ptm driver");
	if (tty_register_driver(pts_driver))
		panic("Couldn't register Unix98 pts driver");

	/* Now create the /dev/ptmx special device */
	tty_default_fops(&ptmx_fops);
	ptmx_fops.open = ptmx_open;

	cdev_init(&ptmx_cdev, &ptmx_fops);
	if (cdev_add(&ptmx_cdev, MKDEV(TTYAUX_MAJOR, 2), 1) ||
	    register_chrdev_region(MKDEV(TTYAUX_MAJOR, 2), 1, "/dev/ptmx") < 0)
		panic("Couldn't register /dev/ptmx driver");
	device_create(tty_class, NULL, MKDEV(TTYAUX_MAJOR, 2), NULL, "ptmx");
}

#else
static inline void unix98_pty_init(void) { }
#endif

static int __init pty_init(void)
{
	legacy_pty_init();
	unix98_pty_init();
	vtty_init();
	return 0;
}
device_initcall(pty_init);
