/*
 *  include/linux/vzctl.h
 *
 *  Copyright (c) 2005-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
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
