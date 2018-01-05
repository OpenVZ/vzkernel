/*
 *  fs/sysfs/ve.c
 *
 *  Copyright (c) 2000-2017 Virtuozzo International GmbH.
 *  All rights reserved.
 *
 */

#include <linux/seq_file.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/ve.h>
#include "sysfs.h"

#include "linux/kernfs-ve.h"

struct kmapset_set sysfs_ve_perms_set;

static DEFINE_MUTEX(sysfs_perms_mutex);

void sysfs_set_ve_perms(struct dentry *root)
{
	kernfs_set_ve_perms(root, offsetof(struct ve_struct,
					   sysfs_perms_key));
}

int sysfs_init_ve_perms(struct kernfs_root *root)
{
	return kernfs_init_ve_perms(root, &sysfs_ve_perms_set);
}

static void *sysfs_perms_start(struct seq_file *m, loff_t *ppos)
{
	struct ve_struct *ve = m->private;

	mutex_lock(&sysfs_perms_mutex);
	return kernfs_perms_start(m, ppos, sysfs_root_kn, &ve->sysfs_perms_key);
}

static void *sysfs_perms_next(struct seq_file *m, void *v, loff_t *ppos)
{
	struct ve_struct *ve = m->private;

	return kernfs_perms_next(m, v, ppos, &ve->sysfs_perms_key);
}

static void sysfs_perms_stop(struct seq_file *m, void *v)
{
	kernfs_perms_stop(m, v);
	mutex_unlock(&sysfs_perms_mutex);
}

static int sysfs_perms_show(struct seq_file *m, void *v)
{
	struct ve_struct *ve = m->private;

	return kernfs_perms_show(m, v, &ve->sysfs_perms_key);
}

static ssize_t sysfs_perms_write(struct cgroup *cgrp,
		struct cftype *cftype, struct file * file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	struct ve_struct *ve = cgroup_ve(file->f_dentry->d_parent->d_fsdata);
	char *page;
	ssize_t ret, len;

	page = (unsigned char *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	len = min(count, PAGE_SIZE - 1);
	ret = copy_from_user(page, buf, len);
	if (ret)
		goto err;

	page[len] = '\0';

	mutex_lock(&sysfs_perms_mutex);
	ret = kernfs_perms_write(ve, page, len, *ppos,
				 sysfs_root_kn, &ve->sysfs_perms_key);
	mutex_unlock(&sysfs_perms_mutex);
err:
	free_page((unsigned long)page);
	return ret;
}

struct seq_operations sysfs_perms_sops = {
	.start = sysfs_perms_start,
	.stop = sysfs_perms_stop,
	.next = sysfs_perms_next,
	.show = sysfs_perms_show,
};

static int sysfs_perms_open(struct inode *inode, struct file *file)
{
	struct ve_struct *ve = cgroup_ve(file->f_dentry->d_parent->d_fsdata);
	struct seq_file *m;
	int ret;

	ret = seq_open(file, &sysfs_perms_sops);
	if (!ret) {
		m = file->private_data;
		m->private = ve_is_super(ve) ? NULL : ve;
	}
	return ret;
}

static ssize_t sysfs_perms_read(struct cgroup *cgrp, struct cftype *cft,
	struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
	return seq_read(file, buf, nbytes, ppos);
}

static int sysfs_perms_release(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

static struct cftype sysfs_ve_cftypes[] = {
	{
		.name = "default_sysfs_permissions",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.open = sysfs_perms_open,
		.read = sysfs_perms_read,
		.write = sysfs_perms_write,
		.release = sysfs_perms_release,
		.mode = S_IRUGO | S_IWUSR,
	},
	{
		.name = "sysfs_permissions",
		.flags = CFTYPE_NOT_ON_ROOT,
		.open = sysfs_perms_open,
		.read = sysfs_perms_read,
		.write = sysfs_perms_write,
		.release = sysfs_perms_release,
		.mode = S_IRUGO | S_IWUSR,
	},
	{ },
};

static int init_sysfve_perms(void)
{
	return cgroup_add_cftypes(&ve_subsys, sysfs_ve_cftypes);
}
module_init(init_sysfve_perms);
