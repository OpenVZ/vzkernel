/*
 * Core PHY library, taken from phy.c
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */
#include <linux/export.h>
#include <linux/phy.h>

static void mmd_phy_indirect(struct mii_bus *bus, int phy_addr, int devad,
			     u16 regnum)
{
	/* Write the desired MMD Devad */
	__mdiobus_write(bus, phy_addr, MII_MMD_CTRL, devad);

	/* Write the desired MMD register address */
	__mdiobus_write(bus, phy_addr, MII_MMD_DATA, regnum);

	/* Select the Function : DATA with no post increment */
	__mdiobus_write(bus, phy_addr, MII_MMD_CTRL,
			devad | MII_MMD_CTRL_NOINCR);
}

/**
 * __phy_read_mmd - Convenience function for reading a register
 * from an MMD on a given PHY.
 * @phydev: The phy_device struct
 * @devad: The MMD to read from (0..31)
 * @regnum: The register on the MMD to read (0..65535)
 *
 * Same rules as for __phy_read();
 */
int __phy_read_mmd(struct phy_device *phydev, int devad, u32 regnum)
{
	int val;

	if (regnum > (u16)~0 || devad > 32)
		return -EINVAL;

	if (phydev->drv->read_mmd) {
		val = phydev->drv->read_mmd(phydev, devad, regnum);
	} else if (phydev->is_c45) {
		u32 addr = MII_ADDR_C45 | (devad << 16) | (regnum & 0xffff);

		val = __mdiobus_read(phydev->mdio_bus, phydev->mdio_addr, addr);
	} else {
		struct mii_bus *bus = phydev->mdio_bus;
		int phy_addr = phydev->mdio_addr;

		mmd_phy_indirect(bus, phy_addr, devad, regnum);

		/* Read the content of the MMD's selected register */
		val = __mdiobus_read(bus, phy_addr, MII_MMD_DATA);
	}
	return val;
}
EXPORT_SYMBOL(__phy_read_mmd);

/**
 * phy_read_mmd - Convenience function for reading a register
 * from an MMD on a given PHY.
 * @phydev: The phy_device struct
 * @devad: The MMD to read from
 * @regnum: The register on the MMD to read
 *
 * Same rules as for phy_read();
 */
int phy_read_mmd(struct phy_device *phydev, int devad, u32 regnum)
{
	int ret;

	mutex_lock(&phydev->mdio_bus->mdio_lock);
	ret = __phy_read_mmd(phydev, devad, regnum);
	mutex_unlock(&phydev->mdio_bus->mdio_lock);

	return ret;
}
EXPORT_SYMBOL(phy_read_mmd);

/**
 * __phy_write_mmd - Convenience function for writing a register
 * on an MMD on a given PHY.
 * @phydev: The phy_device struct
 * @devad: The MMD to read from
 * @regnum: The register on the MMD to read
 * @val: value to write to @regnum
 *
 * Same rules as for __phy_write();
 */
int __phy_write_mmd(struct phy_device *phydev, int devad, u32 regnum, u16 val)
{
	int ret;

	if (regnum > (u16)~0 || devad > 32)
		return -EINVAL;

	if (phydev->drv->write_mmd) {
		ret = phydev->drv->write_mmd(phydev, devad, regnum, val);
	} else if (phydev->is_c45) {
		u32 addr = MII_ADDR_C45 | (devad << 16) | (regnum & 0xffff);

		ret = __mdiobus_write(phydev->mdio_bus, phydev->mdio_addr,
				      addr, val);
	} else {
		struct mii_bus *bus = phydev->mdio_bus;
		int phy_addr = phydev->mdio_addr;

		mmd_phy_indirect(bus, phy_addr, devad, regnum);

		/* Write the data into MMD's selected register */
		__mdiobus_write(bus, phy_addr, MII_MMD_DATA, val);

		ret = 0;
	}
	return ret;
}
EXPORT_SYMBOL(__phy_write_mmd);

/**
 * phy_write_mmd - Convenience function for writing a register
 * on an MMD on a given PHY.
 * @phydev: The phy_device struct
 * @devad: The MMD to read from
 * @regnum: The register on the MMD to read
 * @val: value to write to @regnum
 *
 * Same rules as for phy_write();
 */
int phy_write_mmd(struct phy_device *phydev, int devad, u32 regnum, u16 val)
{
	int ret;

	mutex_lock(&phydev->mdio_bus->mdio_lock);
	ret = __phy_write_mmd(phydev, devad, regnum, val);
	mutex_unlock(&phydev->mdio_bus->mdio_lock);

	return ret;
}
EXPORT_SYMBOL(phy_write_mmd);

/**
 * __phy_modify_changed() - Convenience function for modifying a PHY register
 * @phydev: a pointer to a &struct phy_device
 * @regnum: register number
 * @mask: bit mask of bits to clear
 * @set: bit mask of bits to set
 *
 * Unlocked helper function which allows a PHY register to be modified as
 * new register value = (old register value & ~mask) | set
 *
 * Returns negative errno, 0 if there was no change, and 1 in case of change
 */
int __phy_modify_changed(struct phy_device *phydev, u32 regnum, u16 mask,
			 u16 set)
{
	int new, ret;

	ret = __phy_read(phydev, regnum);
	if (ret < 0)
		return ret;

	new = (ret & ~mask) | set;
	if (new == ret)
		return 0;

	ret = __phy_write(phydev, regnum, new);

	return ret < 0 ? ret : 1;
}
EXPORT_SYMBOL_GPL(__phy_modify_changed);

/**
 * phy_modify_changed - Function for modifying a PHY register
 * @phydev: the phy_device struct
 * @regnum: register number to modify
 * @mask: bit mask of bits to clear
 * @set: new value of bits set in mask to write to @regnum
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 *
 * Returns negative errno, 0 if there was no change, and 1 in case of change
 */
int phy_modify_changed(struct phy_device *phydev, u32 regnum, u16 mask, u16 set)
{
	int ret;

	mutex_lock(&phydev->mdio_bus->mdio_lock);
	ret = __phy_modify_changed(phydev, regnum, mask, set);
	mutex_unlock(&phydev->mdio_bus->mdio_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(phy_modify_changed);

/**
 * __phy_modify - Convenience function for modifying a PHY register
 * @phydev: the phy_device struct
 * @regnum: register number to modify
 * @mask: bit mask of bits to clear
 * @set: new value of bits set in mask to write to @regnum
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int __phy_modify(struct phy_device *phydev, u32 regnum, u16 mask, u16 set)
{
	int ret;

	ret = __phy_modify_changed(phydev, regnum, mask, set);

	return ret < 0 ? ret : 0;
}
EXPORT_SYMBOL_GPL(__phy_modify);

/**
 * phy_modify - Convenience function for modifying a given PHY register
 * @phydev: the phy_device struct
 * @regnum: register number to write
 * @mask: bit mask of bits to clear
 * @set: new value of bits set in mask to write to @regnum
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int phy_modify(struct phy_device *phydev, u32 regnum, u16 mask, u16 set)
{
	int ret;

	mutex_lock(&phydev->mdio_bus->mdio_lock);
	ret = __phy_modify(phydev, regnum, mask, set);
	mutex_unlock(&phydev->mdio_bus->mdio_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(phy_modify);

/**
 * __phy_modify_mmd_changed - Function for modifying a register on MMD
 * @phydev: the phy_device struct
 * @devad: the MMD containing register to modify
 * @regnum: register number to modify
 * @mask: bit mask of bits to clear
 * @set: new value of bits set in mask to write to @regnum
 *
 * Unlocked helper function which allows a MMD register to be modified as
 * new register value = (old register value & ~mask) | set
 *
 * Returns negative errno, 0 if there was no change, and 1 in case of change
 */
int __phy_modify_mmd_changed(struct phy_device *phydev, int devad, u32 regnum,
			     u16 mask, u16 set)
{
	int new, ret;

	ret = __phy_read_mmd(phydev, devad, regnum);
	if (ret < 0)
		return ret;

	new = (ret & ~mask) | set;
	if (new == ret)
		return 0;

	ret = __phy_write_mmd(phydev, devad, regnum, new);

	return ret < 0 ? ret : 1;
}
EXPORT_SYMBOL_GPL(__phy_modify_mmd_changed);

/**
 * phy_modify_mmd_changed - Function for modifying a register on MMD
 * @phydev: the phy_device struct
 * @devad: the MMD containing register to modify
 * @regnum: register number to modify
 * @mask: bit mask of bits to clear
 * @set: new value of bits set in mask to write to @regnum
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 *
 * Returns negative errno, 0 if there was no change, and 1 in case of change
 */
int phy_modify_mmd_changed(struct phy_device *phydev, int devad, u32 regnum,
			   u16 mask, u16 set)
{
	int ret;

	mutex_lock(&phydev->mdio_bus->mdio_lock);
	ret = __phy_modify_mmd_changed(phydev, devad, regnum, mask, set);
	mutex_unlock(&phydev->mdio_bus->mdio_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(phy_modify_mmd_changed);

/**
 * __phy_modify_mmd - Convenience function for modifying a register on MMD
 * @phydev: the phy_device struct
 * @devad: the MMD containing register to modify
 * @regnum: register number to modify
 * @mask: bit mask of bits to clear
 * @set: new value of bits set in mask to write to @regnum
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int __phy_modify_mmd(struct phy_device *phydev, int devad, u32 regnum,
		     u16 mask, u16 set)
{
	int ret;

	ret = __phy_modify_mmd_changed(phydev, devad, regnum, mask, set);

	return ret < 0 ? ret : 0;
}
EXPORT_SYMBOL_GPL(__phy_modify_mmd);

/**
 * phy_modify_mmd - Convenience function for modifying a register on MMD
 * @phydev: the phy_device struct
 * @devad: the MMD containing register to modify
 * @regnum: register number to modify
 * @mask: bit mask of bits to clear
 * @set: new value of bits set in mask to write to @regnum
 *
 * NOTE: MUST NOT be called from interrupt context,
 * because the bus read/write functions may wait for an interrupt
 * to conclude the operation.
 */
int phy_modify_mmd(struct phy_device *phydev, int devad, u32 regnum,
		   u16 mask, u16 set)
{
	int ret;

	mutex_lock(&phydev->mdio_bus->mdio_lock);
	ret = __phy_modify_mmd(phydev, devad, regnum, mask, set);
	mutex_unlock(&phydev->mdio_bus->mdio_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(phy_modify_mmd);

static int __phy_read_page(struct phy_device *phydev)
{
	return phydev->drv->read_page(phydev);
}

static int __phy_write_page(struct phy_device *phydev, int page)
{
	return phydev->drv->write_page(phydev, page);
}

/**
 * phy_save_page() - take the bus lock and save the current page
 * @phydev: a pointer to a &struct phy_device
 *
 * Take the MDIO bus lock, and return the current page number. On error,
 * returns a negative errno. phy_restore_page() must always be called
 * after this, irrespective of success or failure of this call.
 */
int phy_save_page(struct phy_device *phydev)
{
	mutex_lock(&phydev->mdio_bus->mdio_lock);
	return __phy_read_page(phydev);
}
EXPORT_SYMBOL_GPL(phy_save_page);

/**
 * phy_select_page() - take the bus lock, save the current page, and set a page
 * @phydev: a pointer to a &struct phy_device
 * @page: desired page
 *
 * Take the MDIO bus lock to protect against concurrent access, save the
 * current PHY page, and set the current page.  On error, returns a
 * negative errno, otherwise returns the previous page number.
 * phy_restore_page() must always be called after this, irrespective
 * of success or failure of this call.
 */
int phy_select_page(struct phy_device *phydev, int page)
{
	int ret, oldpage;

	oldpage = ret = phy_save_page(phydev);
	if (ret < 0)
		return ret;

	if (oldpage != page) {
		ret = __phy_write_page(phydev, page);
		if (ret < 0)
			return ret;
	}

	return oldpage;
}
EXPORT_SYMBOL_GPL(phy_select_page);

/**
 * phy_restore_page() - restore the page register and release the bus lock
 * @phydev: a pointer to a &struct phy_device
 * @oldpage: the old page, return value from phy_save_page() or phy_select_page()
 * @ret: operation's return code
 *
 * Release the MDIO bus lock, restoring @oldpage if it is a valid page.
 * This function propagates the earliest error code from the group of
 * operations.
 *
 * Returns:
 *   @oldpage if it was a negative value, otherwise
 *   @ret if it was a negative errno value, otherwise
 *   phy_write_page()'s negative value if it were in error, otherwise
 *   @ret.
 */
int phy_restore_page(struct phy_device *phydev, int oldpage, int ret)
{
	int r;

	if (oldpage >= 0) {
		r = __phy_write_page(phydev, oldpage);

		/* Propagate the operation return code if the page write
		 * was successful.
		 */
		if (ret >= 0 && r < 0)
			ret = r;
	} else {
		/* Propagate the phy page selection error code */
		ret = oldpage;
	}

	mutex_unlock(&phydev->mdio_bus->mdio_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(phy_restore_page);

/**
 * phy_read_paged() - Convenience function for reading a paged register
 * @phydev: a pointer to a &struct phy_device
 * @page: the page for the phy
 * @regnum: register number
 *
 * Same rules as for phy_read().
 */
int phy_read_paged(struct phy_device *phydev, int page, u32 regnum)
{
	int ret = 0, oldpage;

	oldpage = phy_select_page(phydev, page);
	if (oldpage >= 0)
		ret = __phy_read(phydev, regnum);

	return phy_restore_page(phydev, oldpage, ret);
}
EXPORT_SYMBOL(phy_read_paged);

/**
 * phy_write_paged() - Convenience function for writing a paged register
 * @phydev: a pointer to a &struct phy_device
 * @page: the page for the phy
 * @regnum: register number
 * @val: value to write
 *
 * Same rules as for phy_write().
 */
int phy_write_paged(struct phy_device *phydev, int page, u32 regnum, u16 val)
{
	int ret = 0, oldpage;

	oldpage = phy_select_page(phydev, page);
	if (oldpage >= 0)
		ret = __phy_write(phydev, regnum, val);

	return phy_restore_page(phydev, oldpage, ret);
}
EXPORT_SYMBOL(phy_write_paged);

/**
 * phy_modify_paged() - Convenience function for modifying a paged register
 * @phydev: a pointer to a &struct phy_device
 * @page: the page for the phy
 * @regnum: register number
 * @mask: bit mask of bits to clear
 * @set: bit mask of bits to set
 *
 * Same rules as for phy_read() and phy_write().
 */
int phy_modify_paged(struct phy_device *phydev, int page, u32 regnum,
		     u16 mask, u16 set)
{
	int ret = 0, oldpage;

	oldpage = phy_select_page(phydev, page);
	if (oldpage >= 0)
		ret = __phy_modify(phydev, regnum, mask, set);

	return phy_restore_page(phydev, oldpage, ret);
}
EXPORT_SYMBOL(phy_modify_paged);
