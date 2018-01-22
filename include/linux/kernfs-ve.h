/*
 *  include/linux/kernfs-ve.h
 *
 *  Copyright (c) 2000-2017 Virtuozzo International GmbH.
 *  All rights reserved.
 *
 */

#ifndef __LINUX_KERNFS_VE_H
#define __LINUX_KERNFS_VE_H

#include <linux/kmapset.h>
#include <linux/mutex.h>

struct kernfs_root;
struct dentry;

#ifdef CONFIG_VE
int kernfs_init_ve_perms(struct kernfs_root *root,
			 struct kmapset_set *perms_set);
void kernfs_set_ve_perms(struct dentry *root, off_t key_off);
#else   /* CONFIG_VE */
static inline int kernfs_init_ve_perms(struct kernfs_root *root,
				       struct kmapset_set *perms_set)
{
	return 0;
}
static inline void kernfs_set_ve_perms(struct dentry *root,
				       off_t key_off) { }
#endif  /* CONFIG_VE */

#endif  /* __LINUX_KERNFS_VE_H */

