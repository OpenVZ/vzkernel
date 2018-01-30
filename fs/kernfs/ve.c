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
#include <linux/seq_file.h>
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

bool kernfs_d_visible(struct kernfs_node *kn, struct kernfs_super_info *info)
{
	struct ve_struct *ve = info->ve;
	struct kernfs_node *tmp_kn = kn;

	/* Non-containerized fs */
	if (!ve)
		return true;

	/* Host sees anything */
	if (ve_is_super(ve))
		return true;

	/* Entries with namespace tag and their sub-entries always visible */
	while (tmp_kn) {
		if (tmp_kn->ns)
			return true;
		tmp_kn = tmp_kn->parent;
	}

	/* Symlinks are visible if target kn is visible */
	if (kernfs_type(kn) == KERNFS_LINK)
		kn = kn->symlink.target_kn;

	return !!kmapset_get_value(kn->ve_perms_map,
				   kernfs_info_perms_key(info));
}

#define rb_to_kn(X) rb_entry((X), struct kernfs_node, rb)

static struct kernfs_node *kernfs_next_recursive(struct kernfs_node *kn)
{
	struct rb_node *node;

	if (kernfs_type(kn) == KERNFS_DIR &&
			!RB_EMPTY_ROOT(&kn->dir.children)) {
		return rb_to_kn(rb_first(&kn->dir.children));
	}

	do {
		node = rb_next(&kn->rb);
		if (node)
			return rb_to_kn(node);
		kn = kn->parent;
	} while (kn);

	return kn;
}

static bool kernfs_perms_shown(struct ve_struct *ve, struct kernfs_node *kn,
			       struct kmapset_key *key)
{
	if (ve_is_super(ve))
		return kn->ve_perms_map->default_value != 0;
	return kmapset_lookup(kn->ve_perms_map, key) != NULL;
}

void *kernfs_perms_start(struct seq_file *m, loff_t *ppos,
			 struct kernfs_node *root, struct kmapset_key *key)
{
	struct ve_struct *ve = m->private;
	struct kernfs_node *kn;
	loff_t pos = *ppos;

	mutex_lock(&kernfs_mutex);
	for (kn = root; kn; kn = kernfs_next_recursive(kn)) {
		if (kernfs_perms_shown(ve, kn, key) && !pos--)
			break;
	};
	return kn;
}

void *kernfs_perms_next(struct seq_file *m, void *v, loff_t *ppos,
			      struct kmapset_key *key)
{
	struct ve_struct *ve = m->private;
	struct kernfs_node *kn = v;

	(*ppos)++;
	while ((kn = kernfs_next_recursive(kn))) {
		if (kernfs_perms_shown(ve, kn, key))
			break;
	};
	return kn;
}

void kernfs_perms_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&kernfs_mutex);
}

int kernfs_perms_show(struct seq_file *m, void *v, struct kmapset_key *key)
{
	struct ve_struct *ve = m->private;
	struct kernfs_node *kn = v;
	char *buf;
	size_t size, len, off;
	int mask;

	if (ve_is_super(ve))
		mask = kn->ve_perms_map->default_value;
	else
		mask = kmapset_get_value(kn->ve_perms_map, key);

	size = seq_get_buf(m, &buf);
	if (size) {
		off = size;
		do {
			len = strlen(kn->name);
			if (len >= off) {
				seq_commit(m, -1);
				return 0;
			}
			if (kernfs_type(kn) == KERNFS_DIR)
				buf[--off] = '/';
			off -= len;
			memcpy(buf + off, kn->name, len);
			kn = kn->parent;
		} while (kn && kn != kernfs_root(kn)->kn);
		memmove(buf, buf + off, size - off);
		seq_commit(m, size - off);
	}

	seq_putc(m, ' ');

	if (!mask)
		seq_putc(m, '-');
	if (mask & MAY_READ)
		seq_putc(m, 'r');
	if (mask & MAY_WRITE)
		seq_putc(m, 'w');
	if (mask & MAY_EXEC)
		seq_putc(m, 'x');

	seq_putc(m, '\n');

	return 0;
}

int kernfs_perms_set(char *path, struct ve_struct *ve, int mask,
		     struct kernfs_node *root, struct kmapset_key *key)
{
	struct kernfs_node *kn = root, *nkn;
	struct kmapset_map *map = NULL;
	char *sep = path, *dname;
	int ret;

	kernfs_get(kn);
	do {
		dname = sep;

		sep = strchr(sep, '/');
		if (sep)
			*sep++ = 0;

		if (!*dname)
			break;

		nkn = kernfs_find_and_get(kn, dname);
		if (!nkn) {
			ret = -ENOENT;
			goto out;
		}

		kernfs_put(kn);
		kn = nkn;
	} while (sep);

	ret = -ENOMEM;
	map = kmapset_dup(kn->ve_perms_map);
	if (!map)
		goto out_put;

	ret = 0;
	if (ve_is_super(ve)) {
		kmapset_set_default(map, mask > 0 ? mask : 0);
	} else if (mask < 0) {
		kmapset_del_value(map, key);
	} else {
		ret = kmapset_set_value(map, key, mask);
	}

	if (!ret) {
		map = kmapset_commit(map);
		swap(map, kn->ve_perms_map);
	}

out_put:
	kmapset_put(map);
out:
	kernfs_put(kn);
	return ret;
}

static int kernfs_perms_line(struct ve_struct *ve, char *line,
			     struct kernfs_node *root, struct kmapset_key *key)
{
	int mask = 0;
	char *p;

	p = strpbrk(line, " \t");
	if (!p)
		return -EINVAL;
	*p++ = 0;
	p = skip_spaces(p);
	while (1) {
		switch (*p++) {
			case 'r':
				mask |= MAY_READ;
				break;
			case 'w':
				mask |= MAY_WRITE;
				break;
			case 'x':
				mask |= MAY_EXEC;
				break;
			case '-':
				mask = -1;
				break;
			case 0:
				return kernfs_perms_set(line, ve, mask,
							root, key);
			default:
				return -EINVAL;
		}
	}
}

ssize_t kernfs_perms_write(struct ve_struct *ve,
			   char *buf, size_t nbytes, loff_t off,
			   struct kernfs_node *root, struct kmapset_key *key)
{
	char *line, *next = buf;
	int ret = -EINVAL;

	do {
		line = skip_spaces(next);
		if (!*line)
			break;

		next = strchr(line, '\n');
		if (next)
			*next++ = '\0';

		if (*line != '#') {
			ret = kernfs_perms_line(ve, line, root, key);
			if (ret)
				break;
		}
	} while (next);
	return ret ? ret : nbytes;
}
