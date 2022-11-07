/*
 * drivers/net/phy/mdio_bus.c
 *
 * MDIO Bus interface
 *
 * Author: Andy Fleming
 *
 * Copyright (c) 2004 Freescale Semiconductor, Inc.
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/of_device.h>
#include <linux/of_mdio.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/phy.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>

#define CREATE_TRACE_POINTS
#include <trace/events/mdio.h>

int mdiobus_register_device(struct phy_device *phydev)
{
	if (phydev->mdio_bus->phy_map[phydev->mdio_addr])
		return -EBUSY;

	phydev->mdio_bus->phy_map[phydev->mdio_addr] = phydev;

	return 0;
}
EXPORT_SYMBOL(mdiobus_register_device);

int mdiobus_unregister_device(struct phy_device *phydev)
{
	if (phydev->mdio_bus->phy_map[phydev->mdio_addr] != phydev)
		return -EINVAL;

	phydev->mdio_bus->phy_map[phydev->mdio_addr] = NULL;

	return 0;
}
EXPORT_SYMBOL(mdiobus_unregister_device);

struct phy_device *mdiobus_get_phy(struct mii_bus *bus, int addr)
{
	struct phy_device *phydev = bus->phy_map[addr];

	if (!phydev)
		return NULL;

	if (!(phydev->mdio_flags & MDIO_DEVICE_FLAG_PHY))
		return NULL;

	return phydev;
}
EXPORT_SYMBOL(mdiobus_get_phy);

bool mdiobus_is_registered_device(struct mii_bus *bus, int addr)
{
	return bus->phy_map[addr];
}
EXPORT_SYMBOL(mdiobus_is_registered_device);

/**
 * mdiobus_alloc_size - allocate a mii_bus structure
 * @size: extra amount of memory to allocate for private storage.
 * If non-zero, then bus->priv is points to that memory.
 *
 * Description: called by a bus driver to allocate an mii_bus
 * structure to fill in.
 */
struct mii_bus *mdiobus_alloc_size(size_t size)
{
	struct mii_bus *bus;
	size_t aligned_size = ALIGN(sizeof(*bus), NETDEV_ALIGN);
	size_t alloc_size;

	/* If we alloc extra space, it should be aligned */
	if (size)
		alloc_size = aligned_size + size;
	else
		alloc_size = sizeof(*bus);

	bus = kzalloc(alloc_size, GFP_KERNEL);
	if (bus) {
		bus->state = MDIOBUS_ALLOCATED;
		if (size)
			bus->priv = (void *)bus + aligned_size;
	}

	return bus;
}
EXPORT_SYMBOL(mdiobus_alloc_size);

static void _devm_mdiobus_free(struct device *dev, void *res)
{
	mdiobus_free(*(struct mii_bus **)res);
}

static int devm_mdiobus_match(struct device *dev, void *res, void *data)
{
	struct mii_bus **r = res;

	if (WARN_ON(!r || !*r))
		return 0;

	return *r == data;
}

/**
 * devm_mdiobus_alloc_size - Resource-managed mdiobus_alloc_size()
 * @dev:		Device to allocate mii_bus for
 * @sizeof_priv:	Space to allocate for private structure.
 *
 * Managed mdiobus_alloc_size. mii_bus allocated with this function is
 * automatically freed on driver detach.
 *
 * If an mii_bus allocated with this function needs to be freed separately,
 * devm_mdiobus_free() must be used.
 *
 * RETURNS:
 * Pointer to allocated mii_bus on success, NULL on failure.
 */
struct mii_bus *devm_mdiobus_alloc_size(struct device *dev, int sizeof_priv)
{
	struct mii_bus **ptr, *bus;

	ptr = devres_alloc(_devm_mdiobus_free, sizeof(*ptr), GFP_KERNEL);
	if (!ptr)
		return NULL;

	/* use raw alloc_dr for kmalloc caller tracing */
	bus = mdiobus_alloc_size(sizeof_priv);
	if (bus) {
		*ptr = bus;
		devres_add(dev, ptr);
	} else {
		devres_free(ptr);
	}

	return bus;
}
EXPORT_SYMBOL_GPL(devm_mdiobus_alloc_size);

/**
 * devm_mdiobus_free - Resource-managed mdiobus_free()
 * @dev:		Device this mii_bus belongs to
 * @bus:		the mii_bus associated with the device
 *
 * Free mii_bus allocated with devm_mdiobus_alloc_size().
 */
void devm_mdiobus_free(struct device *dev, struct mii_bus *bus)
{
	int rc;

	rc = devres_release(dev, _devm_mdiobus_free,
			    devm_mdiobus_match, bus);
	WARN_ON(rc);
}
EXPORT_SYMBOL_GPL(devm_mdiobus_free);

/**
 * mdiobus_release - mii_bus device release callback
 * @d: the target struct device that contains the mii_bus
 *
 * Description: called when the last reference to an mii_bus is
 * dropped, to free the underlying memory.
 */
static void mdiobus_release(struct device *d)
{
	struct mii_bus *bus = to_mii_bus(d);
	BUG_ON(bus->state != MDIOBUS_RELEASED &&
	       /* for compatibility with error handling in drivers */
	       bus->state != MDIOBUS_ALLOCATED);
	kfree(bus);
}

static struct class mdio_bus_class = {
	.name		= "mdio_bus",
	.dev_release	= mdiobus_release,
};

#if IS_ENABLED(CONFIG_OF_MDIO)
/* Helper function for of_mdio_find_bus */
static int of_mdio_bus_match(struct device *dev, const void *mdio_bus_np)
{
	return dev->of_node == mdio_bus_np;
}
/**
 * of_mdio_find_bus - Given an mii_bus node, find the mii_bus.
 * @mdio_bus_np: Pointer to the mii_bus.
 *
 * Returns a reference to the mii_bus, or NULL if none found.  The
 * embedded struct device will have its reference count incremented,
 * and this must be put once the bus is finished with.
 *
 * Because the association of a device_node and mii_bus is made via
 * of_mdiobus_register(), the mii_bus cannot be found before it is
 * registered with of_mdiobus_register().
 *
 */
struct mii_bus *of_mdio_find_bus(struct device_node *mdio_bus_np)
{
	struct device *d;

	if (!mdio_bus_np)
		return NULL;

	d = class_find_device(&mdio_bus_class, NULL,  mdio_bus_np,
			      of_mdio_bus_match);

	return d ? to_mii_bus(d) : NULL;
}
EXPORT_SYMBOL(of_mdio_find_bus);
#endif

/**
 * mdiobus_register - bring up all the PHYs on a given bus and attach them to bus
 * @bus: target mii_bus
 *
 * Description: Called by a bus driver to bring up all the PHYs
 *   on a given bus, and attach them to the bus.
 *
 * Returns 0 on success or < 0 on error.
 */
int __mdiobus_register(struct mii_bus *bus, struct module *owner)
{
	int i, err;

	if (NULL == bus || NULL == bus->name ||
			NULL == bus->read ||
			NULL == bus->write)
		return -EINVAL;

	BUG_ON(bus->state != MDIOBUS_ALLOCATED &&
	       bus->state != MDIOBUS_UNREGISTERED);

	bus->owner = owner;
	bus->dev.parent = bus->parent;
	bus->dev.class = &mdio_bus_class;
	bus->dev.groups = NULL;
	dev_set_name(&bus->dev, "%s", bus->id);

	err = device_register(&bus->dev);
	if (err) {
		pr_err("mii_bus %s failed to register\n", bus->id);
		return -EINVAL;
	}

	mutex_init(&bus->mdio_lock);

	if (bus->reset)
		bus->reset(bus);

	for (i = 0; i < PHY_MAX_ADDR; i++) {
		if ((bus->phy_mask & (1 << i)) == 0) {
			struct phy_device *phydev;

			phydev = mdiobus_scan(bus, i);
			if (IS_ERR(phydev) && (PTR_ERR(phydev) != -ENODEV)) {
				err = PTR_ERR(phydev);
				goto error;
			}
		}
	}

	bus->state = MDIOBUS_REGISTERED;
	pr_info("%s: probed\n", bus->name);
	return 0;

error:
	while (--i >= 0) {
		struct phy_device *phydev = mdiobus_get_phy(bus, i);
		if (phydev) {
			phy_device_remove(phydev);
			phy_device_free(phydev);
		}
	}
	device_del(&bus->dev);
	return err;
}
EXPORT_SYMBOL(__mdiobus_register);

void mdiobus_unregister(struct mii_bus *bus)
{
	int i;

	BUG_ON(bus->state != MDIOBUS_REGISTERED);
	bus->state = MDIOBUS_UNREGISTERED;

	device_del(&bus->dev);
	for (i = 0; i < PHY_MAX_ADDR; i++) {
		struct phy_device *phydev = mdiobus_get_phy(bus, i);
		if (phydev) {
			phy_device_remove(phydev);
			phy_device_free(phydev);
		}
	}
}
EXPORT_SYMBOL(mdiobus_unregister);

/**
 * mdiobus_free - free a struct mii_bus
 * @bus: mii_bus to free
 *
 * This function releases the reference to the underlying device
 * object in the mii_bus.  If this is the last reference, the mii_bus
 * will be freed.
 */
void mdiobus_free(struct mii_bus *bus)
{
	/*
	 * For compatibility with error handling in drivers.
	 */
	if (bus->state == MDIOBUS_ALLOCATED) {
		kfree(bus);
		return;
	}

	BUG_ON(bus->state != MDIOBUS_UNREGISTERED);
	bus->state = MDIOBUS_RELEASED;

	put_device(&bus->dev);
}
EXPORT_SYMBOL(mdiobus_free);

struct phy_device *mdiobus_scan(struct mii_bus *bus, int addr)
{
	struct phy_device *phydev;
	int err;

	phydev = get_phy_device(bus, addr, false);
	if (IS_ERR(phydev) || phydev == NULL)
		return phydev;

	err = phy_device_register(phydev);
	if (err) {
		phy_device_free(phydev);
		return NULL;
	}

	return phydev;
}
EXPORT_SYMBOL(mdiobus_scan);

/**
 * __mdiobus_read - Unlocked version of the mdiobus_read function
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to read
 *
 * Read a MDIO bus register. Caller must hold the mdio bus lock.
 *
 * NOTE: MUST NOT be called from interrupt context.
 */
int __mdiobus_read(struct mii_bus *bus, int addr, u32 regnum)
{
	int retval;

	WARN_ON_ONCE(!mutex_is_locked(&bus->mdio_lock));

	retval = bus->read(bus, addr, regnum);

	trace_mdio_access(bus, 1, addr, regnum, retval, retval);

	return retval;
}
EXPORT_SYMBOL(__mdiobus_read);

/**
 * __mdiobus_write - Unlocked version of the mdiobus_write function
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to write
 * @val: value to write to @regnum
 *
 * Write a MDIO bus register. Caller must hold the mdio bus lock.
 *
 * NOTE: MUST NOT be called from interrupt context.
 */
int __mdiobus_write(struct mii_bus *bus, int addr, u32 regnum, u16 val)
{
	int err;

	WARN_ON_ONCE(!mutex_is_locked(&bus->mdio_lock));

	err = bus->write(bus, addr, regnum, val);

	trace_mdio_access(bus, 0, addr, regnum, val, err);

	return err;
}
EXPORT_SYMBOL(__mdiobus_write);

/**
 * mdiobus_read_nested - Nested version of the mdiobus_read function
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to read
 *
 * In case of nested MDIO bus access avoid lockdep false positives by
 * using mutex_lock_nested().
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int mdiobus_read_nested(struct mii_bus *bus, int addr, u32 regnum)
{
	int retval;

	BUG_ON(in_interrupt());

	mutex_lock_nested(&bus->mdio_lock, SINGLE_DEPTH_NESTING);
	retval = __mdiobus_read(bus, addr, regnum);
	mutex_unlock(&bus->mdio_lock);

	return retval;
}
EXPORT_SYMBOL(mdiobus_read_nested);

/**
 * mdiobus_read - Convenience function for reading a given MII mgmt register
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to read
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int mdiobus_read(struct mii_bus *bus, int addr, u32 regnum)
{
	int retval;

	BUG_ON(in_interrupt());

	mutex_lock(&bus->mdio_lock);
	retval = __mdiobus_read(bus, addr, regnum);
	mutex_unlock(&bus->mdio_lock);

	return retval;
}
EXPORT_SYMBOL(mdiobus_read);

/**
 * mdiobus_write_nested - Nested version of the mdiobus_write function
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to write
 * @val: value to write to @regnum
 *
 * In case of nested MDIO bus access avoid lockdep false positives by
 * using mutex_lock_nested().
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int mdiobus_write_nested(struct mii_bus *bus, int addr, u32 regnum, u16 val)
{
	int err;

	BUG_ON(in_interrupt());

	mutex_lock_nested(&bus->mdio_lock, SINGLE_DEPTH_NESTING);
	err = __mdiobus_write(bus, addr, regnum, val);
	mutex_unlock(&bus->mdio_lock);

	return err;
}
EXPORT_SYMBOL(mdiobus_write_nested);

/**
 * mdiobus_write - Convenience function for writing a given MII mgmt register
 * @bus: the mii_bus struct
 * @addr: the phy address
 * @regnum: register number to write
 * @val: value to write to @regnum
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int mdiobus_write(struct mii_bus *bus, int addr, u32 regnum, u16 val)
{
	int err;

	BUG_ON(in_interrupt());

	mutex_lock(&bus->mdio_lock);
	err = __mdiobus_write(bus, addr, regnum, val);
	mutex_unlock(&bus->mdio_lock);

	return err;
}
EXPORT_SYMBOL(mdiobus_write);

/**
 * mdio_bus_match - determine if given PHY driver supports the given PHY device
 * @dev: target PHY device
 * @drv: given PHY driver
 *
 * Description: Given a PHY device, and a PHY driver, return 1 if
 *   the driver supports the device.  Otherwise, return 0.
 */
static int mdio_bus_match(struct device *dev, struct device_driver *drv)
{
	struct phy_device *phydev = to_phy_device(dev);
	struct phy_driver *phydrv = to_phy_driver(drv);

	if (of_driver_match_device(dev, drv))
		return 1;

	if (phydrv->match_phy_device)
		return phydrv->match_phy_device(phydev);

	return ((phydrv->phy_id & phydrv->phy_id_mask) ==
		(phydev->phy_id & phydrv->phy_id_mask));
}

#ifdef CONFIG_PM
static int mdio_bus_suspend(struct device *dev)
{
	struct phy_device *phy = to_phy_device(dev);

	if (phy->mdio_pm_ops && phy->mdio_pm_ops->suspend)
		return phy->mdio_pm_ops->suspend(dev);

	return 0;
}

static int mdio_bus_resume(struct device *dev)
{
	struct phy_device *phy = to_phy_device(dev);

	if (phy->mdio_pm_ops && phy->mdio_pm_ops->resume)
		return phy->mdio_pm_ops->resume(dev);

	return 0;
}

static int mdio_bus_restore(struct device *dev)
{
	struct phy_device *phy = to_phy_device(dev);

	if (phy->mdio_pm_ops && phy->mdio_pm_ops->restore)
		return phy->mdio_pm_ops->restore(dev);

	return 0;
}

static struct dev_pm_ops mdio_bus_pm_ops = {
	.suspend = mdio_bus_suspend,
	.resume = mdio_bus_resume,
	.freeze = mdio_bus_suspend,
	.thaw = mdio_bus_resume,
	.restore = mdio_bus_restore,
};

#define MDIO_BUS_PM_OPS (&mdio_bus_pm_ops)

#else

#define MDIO_BUS_PM_OPS NULL

#endif /* CONFIG_PM */

static ssize_t
phy_id_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct phy_device *phydev = to_phy_device(dev);

	return sprintf(buf, "0x%.8lx\n", (unsigned long)phydev->phy_id);
}

static struct device_attribute mdio_dev_attrs[] = {
	__ATTR_RO(phy_id),
	__ATTR_NULL
};

struct bus_type mdio_bus_type = {
	.name		= "mdio_bus",
	.match		= mdio_bus_match,
	.pm		= MDIO_BUS_PM_OPS,
	.dev_attrs	= mdio_dev_attrs,
};
EXPORT_SYMBOL(mdio_bus_type);

int __init mdio_bus_init(void)
{
	int ret;

	ret = class_register(&mdio_bus_class);
	if (!ret) {
		ret = bus_register(&mdio_bus_type);
		if (ret)
			class_unregister(&mdio_bus_class);
	}

	return ret;
}

void mdio_bus_exit(void)
{
	class_unregister(&mdio_bus_class);
	bus_unregister(&mdio_bus_type);
}
