/*
 * fs/sysfs/sysfs.h - sysfs internal header file
 *
 * Copyright (c) 2001-3 Patrick Mochel
 * Copyright (c) 2007 SUSE Linux Products GmbH
 * Copyright (c) 2007 Tejun Heo <teheo@suse.de>
 *
 * This file is released under the GPLv2.
 */

#ifndef __SYSFS_INTERNAL_H
#define __SYSFS_INTERNAL_H

#include <linux/sysfs.h>

/*
 * mount.c
 */
extern struct kernfs_node *sysfs_root_kn;

/*
 * dir.c
 */
extern spinlock_t sysfs_symlink_target_lock;

void sysfs_warn_dup(struct kernfs_node *parent, const char *name);

/*
 * file.c
 */
int sysfs_add_file(struct kernfs_node *parent,
		   const struct attribute *attr, bool is_bin);
int sysfs_add_file_mode_ns(struct kernfs_node *parent,
			   const struct attribute *attr, bool is_bin,
			   umode_t amode, const void *ns);

/*
 * symlink.c
 */
int sysfs_create_link_sd(struct kernfs_node *kn, struct kobject *target,
			 const char *name);

#ifdef CONFIG_VE
void sysfs_set_ve_perms(struct dentry *root);
int sysfs_init_ve_perms(struct kernfs_root *root);
#else
static inline void sysfs_set_ve_perms(struct dentry *root) { }
static inline int sysfs_init_ve_perms(struct kernfs_root *root)
{
	return 0;
}
#endif

#endif	/* __SYSFS_INTERNAL_H */
