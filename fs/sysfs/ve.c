/*
 * fs/sysfs/ve.c - sysfs permissions for containers
 *
 * Copyright (C) 2013  Parallels, inc.
 * Licensing governed by "linux/COPYING.Parallels" file.
 */

#include <linux/seq_file.h>
#include <linux/kmapset.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/ve.h>
#include <net/sock.h>
#include "sysfs.h"

static void *ve_grab_current_ns(void)
{
	return get_ve(get_exec_env());
}

static const void *ve_initial_ns(void)
{
	return get_ve0();
}

static void ve_drop_ns(void *p)
{
	put_ve(p);
}

const void *ve_netlink_ns(struct sock *sk)
{
	return sock_net(sk)->owner_ve;
}

const void *ve_namespace(struct device *dev)
{
	/*
	 * Below is a hack. We use drvdata as a ve_struct pointer.
	 * But it can be a valid drvdata. We use dev->groups pointer to differ
	 * between them: if set, then drvdata is not a ve namespace.
	 */
	return (!dev->groups && dev_get_drvdata(dev)) ? dev_get_drvdata(dev) : get_ve0();
}

struct kobj_ns_type_operations ve_ns_type_operations = {
	.type = KOBJ_NS_TYPE_VE,
	.grab_current_ns = ve_grab_current_ns,
	.netlink_ns = ve_netlink_ns,
	.initial_ns = ve_initial_ns,
	.drop_ns = ve_drop_ns,
};

static bool sysfs_perms_shown(struct ve_struct *ve, struct sysfs_dirent *sd)
{
	if (!ve) /* default_sysfs_permissions */
		return sd->s_ve_perms->default_value != 0;
	return kmapset_lookup(sd->s_ve_perms, &ve->ve_sysfs_perms) != NULL;
}

static void * sysfs_perms_start(struct seq_file *m, loff_t *ppos)
{
	struct ve_struct *ve = m->private;
	struct sysfs_dirent *sd = &sysfs_root;
	loff_t pos = *ppos;

	mutex_lock(&sysfs_mutex);
	for (sd = &sysfs_root; sd; sd = sysfs_next_recursive(sd)) {
		if (sysfs_perms_shown(ve, sd) && !pos--)
			break;
	};
	return sd;
}

static void * sysfs_perms_next(struct seq_file *m, void *v, loff_t *ppos)
{
	struct ve_struct *ve = m->private;
	struct sysfs_dirent *sd = v;

	(*ppos)++;
	while ((sd = sysfs_next_recursive(sd))) {
		if (sysfs_perms_shown(ve, sd))
			break;
	};
	return sd;
}

static void sysfs_perms_stop(struct seq_file *m, void *v)
{
	mutex_unlock(&sysfs_mutex);
}

static int sysfs_perms_show(struct seq_file *m, void *v)
{
	struct ve_struct *ve = m->private;
	struct sysfs_dirent *sd = v;
	char *buf;
	size_t size, len, off;
	int mask;

	if (!ve)
		mask = sd->s_ve_perms->default_value;
	else
		mask = kmapset_get_value(sd->s_ve_perms, &ve->ve_sysfs_perms);

	size = seq_get_buf(m, &buf);
	if (size) {
		off = size;
		do {
			len = strlen(sd->s_name);
			if (len >= off) {
				seq_commit(m, -1);
				return 0;
			}
			if (sysfs_type(sd) == SYSFS_DIR)
				buf[--off] = '/';
			off -= len;
			memcpy(buf + off, sd->s_name, len);
			sd = sd->s_parent;
		} while (sd && sd != &sysfs_root);
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

static int sysfs_perms_set(char *path, struct ve_struct *ve, int mask)
{
	struct sysfs_dirent *sd = &sysfs_root;
	struct kmapset_map *map = NULL;
	char *name = path, *sep;
	int ret;

	mutex_lock(&sysfs_mutex);
	do {
		sep = strchr(name, '/');
		if (sep)
			*sep = 0;
		if (*name)
			sd = sysfs_find_dirent(sd, NULL, name);
		if (sep)
			*sep = '/';
		name = sep + 1;
	} while (sd && sep);

	ret = -ENOENT;
	if (!sd)
		goto out;

	ret = -ENOMEM;
	map = kmapset_dup(sd->s_ve_perms);
	if (!map)
		goto out;

	ret = 0;
	if (!ve) {
		kmapset_set_default(map, mask > 0 ? mask : 0);
	} else if (mask < 0) {
		kmapset_del_value(map, &ve->ve_sysfs_perms);
	} else {
		ret = kmapset_set_value(map, &ve->ve_sysfs_perms, mask);
	}

	if (!ret) {
		map = kmapset_commit(map);
		swap(map, sd->s_ve_perms);
	}
out:
	mutex_unlock(&sysfs_mutex);
	kmapset_put(map);
	return ret;
}

static int sysfs_perms_line(struct ve_struct *ve, char *line)
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
				return sysfs_perms_set(line, ve, mask);
			default:
				return -EINVAL;
		}
	}
}

static ssize_t sysfs_perms_write(struct cgroup *cgrp,
		struct cftype *cftype, struct file * file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	struct ve_struct *ve = cgroup_ve(file->f_dentry->d_parent->d_fsdata);
	char *line, *next, *page;
	int ret, len;

	ve = ve_is_super(ve) ? NULL : ve;

	page = (unsigned char *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	len = min(count, PAGE_SIZE - 1);
	ret = copy_from_user(page, buf, len);
	if (ret)
		goto err;

	page[len] = '\0';

	next = page;
	while (1) {
		line = skip_spaces(next);
		next = strchr(line, '\n');
		if (next) {
			*next++ = '\0';
		} else if (len < count) {
			ret = line != page ? line - page : -EINVAL;
			break;
		}
		if (*line && *line != '#') {
			ret = sysfs_perms_line(ve, line);
			if (ret)
				break;
		}
		if (!next) {
			ret = len;
			break;
		}
	}
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

static int init_sysfs_ve_perms(void)
{
	return cgroup_add_cftypes(&ve_subsys, sysfs_ve_cftypes);
}
module_init(init_sysfs_ve_perms);
