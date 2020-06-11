#include <linux/proc_fs.h>
#include <linux/nsproxy.h>
#include <linux/ptrace.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/utsname.h>
#include <net/net_namespace.h>
#include <linux/ipc_namespace.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include "internal.h"


static const struct proc_ns_operations *ns_entries[] = {
#ifdef CONFIG_NET_NS
	&netns_operations,
#endif
#ifdef CONFIG_UTS_NS
	&utsns_operations,
#endif
#ifdef CONFIG_IPC_NS
	&ipcns_operations,
#endif
#ifdef CONFIG_PID_NS
	&pidns_operations,
#endif
#ifdef CONFIG_USER_NS
	&userns_operations,
#endif
	&mntns_operations,
};

static void *proc_ns_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = dentry->d_inode;
	const struct proc_ns_operations *ns_ops = PROC_I(inode)->ns.ns_ops;
	struct task_struct *task;
	struct path ns_path;
	void *error = ERR_PTR(-EACCES);

	task = get_proc_task(inode);
	if (!task)
		return error;

	if (ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS)) {
		error = ns_get_path(&ns_path, task, ns_ops);
		if (!error)
			nd_jump_link(nd, &ns_path);
	}
	put_task_struct(task);
	return error;
}

static int proc_ns_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	struct inode *inode = dentry->d_inode;
	const struct proc_ns_operations *ns_ops = PROC_I(inode)->ns.ns_ops;
	struct task_struct *task;
	char name[50];
	int len = -EACCES;

	task = get_proc_task(inode);
	if (!task)
		return len;
	if (ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS)) {
		len = ns_get_name(name, sizeof(name), task, ns_ops);
		if (len >= 0) {
			len = strlen(name);

			if (len > buflen)
				len = buflen;
			if (copy_to_user(buffer, name, len))
				len = -EFAULT;
		}
	}
	put_task_struct(task);
	return len;
}

static const struct inode_operations proc_ns_link_inode_operations = {
	.readlink	= proc_ns_readlink,
	.follow_link	= proc_ns_follow_link,
	.setattr	= proc_setattr,
};

static struct dentry *proc_ns_instantiate(struct inode *dir,
	struct dentry *dentry, struct task_struct *task, const void *ptr)
{
	const struct proc_ns_operations *ns_ops = ptr;
	struct inode *inode;
	struct proc_inode *ei;
	struct dentry *error = ERR_PTR(-ENOENT);

	inode = proc_pid_make_inode(dir->i_sb, task, S_IFLNK|S_IRWXUGO);
	if (!inode)
		goto out;

	ei = PROC_I(inode);
	inode->i_op = &proc_ns_link_inode_operations;
	ei->ns.ns_ops = ns_ops;

	d_set_d_op(dentry, &pid_dentry_operations);
	d_add(dentry, inode);
	/* Close the race of the process dying before we return the dentry */
	if (pid_revalidate(dentry, 0))
		error = NULL;
out:
	return error;
}

static int proc_ns_fill_cache(struct file *filp, void *dirent,
	filldir_t filldir, struct task_struct *task,
	const struct proc_ns_operations *ops)
{
	return proc_fill_cache(filp, dirent, filldir,
				ops->name, strlen(ops->name),
				proc_ns_instantiate, task, ops);
}

static int proc_ns_dir_readdir(struct file *filp, void *dirent,
				filldir_t filldir)
{
	int i;
	struct dentry *dentry = filp->f_path.dentry;
	struct inode *inode = dentry->d_inode;
	struct task_struct *task = get_proc_task(inode);
	const struct proc_ns_operations **entry, **last;
	ino_t ino;
	int ret;

	ret = -ENOENT;
	if (!task)
		goto out_no_task;

	ret = 0;
	i = filp->f_pos;
	switch (i) {
	case 0:
		ino = inode->i_ino;
		if (filldir(dirent, ".", 1, i, ino, DT_DIR) < 0)
			goto out;
		i++;
		filp->f_pos++;
		/* fall through */
	case 1:
		ino = parent_ino(dentry);
		if (filldir(dirent, "..", 2, i, ino, DT_DIR) < 0)
			goto out;
		i++;
		filp->f_pos++;
		/* fall through */
	default:
		i -= 2;
		if (i >= ARRAY_SIZE(ns_entries)) {
			ret = 1;
			goto out;
		}
		entry = ns_entries + i;
		last = &ns_entries[ARRAY_SIZE(ns_entries) - 1];
		while (entry <= last) {
			if (proc_ns_fill_cache(filp, dirent, filldir,
						task, *entry) < 0)
				goto out;
			filp->f_pos++;
			entry++;
		}
	}

	ret = 1;
out:
	put_task_struct(task);
out_no_task:
	return ret;
}

const struct file_operations proc_ns_dir_operations = {
	.read		= generic_read_dir,
	.readdir	= proc_ns_dir_readdir,
};

static struct dentry *proc_ns_dir_lookup(struct inode *dir,
				struct dentry *dentry, unsigned int flags)
{
	struct dentry *error;
	struct task_struct *task = get_proc_task(dir);
	const struct proc_ns_operations **entry, **last;
	unsigned int len = dentry->d_name.len;

	error = ERR_PTR(-ENOENT);

	if (!task)
		goto out_no_task;

	last = &ns_entries[ARRAY_SIZE(ns_entries)];
	for (entry = ns_entries; entry < last; entry++) {
		if (strlen((*entry)->name) != len)
			continue;
		if (!memcmp(dentry->d_name.name, (*entry)->name, len))
			break;
	}
	if (entry == last)
		goto out;

	error = proc_ns_instantiate(dir, dentry, task, *entry);
out:
	put_task_struct(task);
out_no_task:
	return error;
}

const struct inode_operations proc_ns_dir_inode_operations = {
	.lookup		= proc_ns_dir_lookup,
	.getattr	= pid_getattr,
	.setattr	= proc_setattr,
};
