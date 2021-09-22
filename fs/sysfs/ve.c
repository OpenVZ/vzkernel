/*
 *  fs/sysfs/ve.c
 *
 *  Copyright (c) 2018-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/module.h>
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
	struct ve_struct *ve = css_to_ve(seq_css(m));

	mutex_lock(&sysfs_perms_mutex);
	return kernfs_perms_start(m, ppos, sysfs_root_kn, &ve->sysfs_perms_key);
}

static void *sysfs_perms_next(struct seq_file *m, void *v, loff_t *ppos)
{
	struct ve_struct *ve = css_to_ve(seq_css(m));

	return kernfs_perms_next(m, v, ppos, &ve->sysfs_perms_key);
}

static void sysfs_perms_stop(struct seq_file *m, void *v)
{
	kernfs_perms_stop(m, v);
	mutex_unlock(&sysfs_perms_mutex);
}

static int sysfs_perms_show(struct seq_file *m, void *v)
{
	struct ve_struct *ve = css_to_ve(seq_css(m));

	return kernfs_perms_show(m, v, &ve->sysfs_perms_key);
}

static ssize_t sysfs_perms_write(struct kernfs_open_file *of,
				 char *buf, size_t nbytes, loff_t off)
{
	struct ve_struct *ve = css_to_ve(of_css(of));
	ssize_t ret;

	mutex_lock(&sysfs_perms_mutex);
	ret = kernfs_perms_write(of, buf, nbytes, off,
				 sysfs_root_kn, &ve->sysfs_perms_key);
	mutex_unlock(&sysfs_perms_mutex);
	return ret;
}

static struct cftype sysfs_ve_cftypes[] = {
	{
		.name = "default_sysfs_permissions",
		.flags = CFTYPE_ONLY_ON_ROOT,
		.seq_start = sysfs_perms_start,
		.seq_next = sysfs_perms_next,
		.seq_stop = sysfs_perms_stop,
		.seq_show = sysfs_perms_show,
		.write = sysfs_perms_write,
	},
	{
		.name = "sysfs_permissions",
		.flags = CFTYPE_NOT_ON_ROOT,
		.seq_start = sysfs_perms_start,
		.seq_next = sysfs_perms_next,
		.seq_stop = sysfs_perms_stop,
		.seq_show = sysfs_perms_show,
		.write = sysfs_perms_write,
	},
	{ },
};

static int init_sysfve_perms(void)
{
	return cgroup_add_legacy_cftypes(&ve_cgrp_subsys, sysfs_ve_cftypes);
}
module_init(init_sysfve_perms);
