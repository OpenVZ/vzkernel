/*
 *  fs/kernfs/kernfs-ve.h
 *
 *  Copyright (c) 2000-2017 Virtuozzo International GmbH.
 *  All rights reserved.
 *
 */

#ifndef __KERNFS_VE_H
#define __KERNFS_VE_H

struct kernfs_root;
struct kernfs_super_info;
struct kernfs_node;
struct kmapset;

#ifdef CONFIG_VE

int kernfs_test_ve(struct kernfs_super_info *sb_info,
		   struct kernfs_super_info *info);

void kernfs_get_ve_perms(struct kernfs_node *kn);
void kernfs_put_ve_perms(struct kernfs_node *kn);

int kernfs_ve_permission(struct kernfs_node *kn,
			 struct kernfs_super_info *info, int mask);

int kernfs_ve_allowed(struct kernfs_node *kn);

bool kernfs_d_visible(struct kernfs_node *kn, struct kernfs_super_info *info);

#else // CONFIG_VE

static inline int kernfs_test_ve(struct kernfs_super_info *sb_info,
				 struct kernfs_super_info *info)
{
	return 0;
}

void kernfs_get_ve_perms(struct kernfs_node *kn) { }
void kernfs_put_ve_perms(struct kernfs_node *kn) { }

static inline int kernfs_ve_permission(struct kernfs_node *kn,
				 struct kernfs_super_info *info, int mask)
{
	return 0;
}

static inline int kernfs_ve_allowed(void)
{
	return 1;
}

bool kernfs_d_visible(struct kernfs_node *kn, struct kernfs_super_info *info)
{
	return true;
}

#endif

#endif
