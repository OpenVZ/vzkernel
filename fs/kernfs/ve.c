/*
 *  fs/kernfs/ve.c
 *
 *  Copyright (c) 2000-2017 Virtuozzo International GmbH.
 *  All rights reserved.
 *
 */

#include <linux/pagemap.h>
#include <linux/backing-dev.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/security.h>

#include <linux/ve.h>
#include <linux/kmapset.h>

#include "kernfs-internal.h"

#include "kernfs-ve.h"

void kernfs_set_ve_perms(struct dentry *root, off_t key_off)
{
	struct kernfs_super_info *info = kernfs_info(root->d_sb);

	info->ve_perms_off = key_off;
	info->ve = get_exec_env();
}

int kernfs_init_ve_perms(struct kernfs_root *root,
			 struct kmapset_set *perms_set)
{
	struct kernfs_node *kn = root->kn;

	kmapset_init_set(perms_set);
	kn->ve_perms_map = kmapset_new(perms_set);
	if (!kn->ve_perms_map)
		return -ENOMEM;
	kmapset_commit(kn->ve_perms_map);

	root->ve_perms_set = perms_set;
	return 0;
}

int kernfs_ve_allowed(struct kernfs_node *kn)
{
	return !kn->ve_perms_map || ve_is_super(get_exec_env());
}

int kernfs_test_ve(struct kernfs_super_info *sb_info,
		   struct kernfs_super_info *info)
{
	return sb_info->ve == info->ve;
}

static struct kmapset_key *kernfs_info_perms_key(struct kernfs_super_info *info)
{
	return (void *)get_exec_env() + info->ve_perms_off;
}

int kernfs_ve_permission(struct kernfs_node *kn,
			 struct kernfs_super_info *info, int mask)
{
	struct kernfs_node *tmp_kn = kn;
	int perm;

	if (kernfs_ve_allowed(kn))
		return 0;

	/* Entries with namespace tag and their sub-entries always visible */
	while (tmp_kn) {
		if (tmp_kn->ns)
			return 0;
		tmp_kn = tmp_kn->parent;
	}

	if (kernfs_type(kn) == KERNFS_LINK)
		kn = kn->symlink.target_kn;

	perm = kmapset_get_value(kn->ve_perms_map, kernfs_info_perms_key(info));
	if ((mask & ~perm & (MAY_READ | MAY_WRITE | MAY_EXEC)) == 0)
		return 0;

	return -EACCES;
}

void kernfs_get_ve_perms(struct kernfs_node *kn)
{
	struct kernfs_root *root = kernfs_root(kn);
	struct kmapset_map *kms;

	if (!root->ve_perms_set)
		return;

	kms = kmapset_new(root->ve_perms_set);
	if (kms)
		kn->ve_perms_map = kmapset_commit(kms);
}

void kernfs_put_ve_perms(struct kernfs_node *kn)
{
	if (kn->ve_perms_map)
		kmapset_put(kn->ve_perms_map);
}
