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
struct ve_struct;

#ifdef CONFIG_VE
int kernfs_init_ve_perms(struct kernfs_root *root,
			 struct kmapset_set *perms_set);
void kernfs_set_ve_perms(struct dentry *root, off_t key_off);

void *kernfs_perms_start(struct seq_file *m, loff_t *ppos,
			 struct kernfs_node *root, struct kmapset_key *key);
void *kernfs_perms_next(struct seq_file *m, void *v, loff_t *ppos,
			      struct kmapset_key *key);
void kernfs_perms_stop(struct seq_file *m, void *v);

int kernfs_perms_show(struct seq_file *m, void *v, struct kmapset_key *key);

ssize_t kernfs_perms_write(struct ve_struct *ve,
			   char *buf, size_t nbytes, loff_t off,
			   struct kernfs_node *root, struct kmapset_key *key);

int kernfs_perms_set(char *path, struct ve_struct *ve, int mask,
		     struct kernfs_node *root, struct kmapset_key *key);

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

