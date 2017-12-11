/*
 *  include/linux/vzctl.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef _LINUX_VZCTL_H
#define _LINUX_VZCTL_H

#include <linux/list.h>

struct module;
struct inode;
struct file;
struct vzioctlinfo {
	unsigned type;
	int (*ioctl)(struct file *, unsigned int, unsigned long);
	int (*compat_ioctl)(struct file *, unsigned int, unsigned long);
	struct module *owner;
	struct list_head list;
};

extern void vzioctl_register(struct vzioctlinfo *inf);
extern void vzioctl_unregister(struct vzioctlinfo *inf);

#endif
