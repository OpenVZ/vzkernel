/*
 * fwnode.h - Firmware device node object handle type definition.
 *
 * Copyright (C) 2015, Intel Corporation
 * Author: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _LINUX_FWNODE_H_
#define _LINUX_FWNODE_H_

#include <linux/device.h>

enum fwnode_type {
	FWNODE_INVALID = 0,
	FWNODE_OF,
	FWNODE_ACPI,
	FWNODE_ACPI_DATA,
	FWNODE_PDATA,
};

struct fwnode_handle {
	enum fwnode_type type;
	struct fwnode_handle *secondary;
};

/*
 * Prior to this code being introduced, device_rh was allocated in
 * device_add().  This seemed correct as there were no users of the elements of
 * device_rh prior to the device_add.  This is no longer true with the addition
 * of the fwnode code.  The functions below will check and WARN loudly on
 * uses of device_rh prior to it being initialized.  These warnings are
 * Red Hat bugs and should be filed against RHEL7.
 */
static inline struct fwnode_handle *get_rh_dev_fwnode(struct device *device)
{
	if (!device->device_rh) {
		WARN(1, "device_rh is not allocated on get ... fixing\n");
		device_rh_alloc(device);
	}
	return device->device_rh->fwnode;
}

static inline void set_rh_dev_fwnode(struct device *device,
				     struct fwnode_handle *fwnode)
{
	if (!device->device_rh) {
		WARN(1, "device_rh is not allocated on set ... fixing\n");
		device_rh_alloc(device);
	}
	device->device_rh->fwnode = fwnode;
}
#endif
