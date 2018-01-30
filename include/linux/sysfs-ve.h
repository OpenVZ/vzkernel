/*
 *  include/linux/sysfs-ve.h
 *
 *  Copyright (c) 2000-2017 Virtuozzo International GmbH.
 *  All rights reserved.
 *
 */

#ifndef _SYSFS_VE_H_
#define _SYSFS_VE_H_

#ifdef CONFIG_VE
int sysfs_set_def_perms(char *path, int mask);
#else
static inline int sysfs_set_def_perms(char *path, int mask)
{
	return 0;
}
#endif

#endif
