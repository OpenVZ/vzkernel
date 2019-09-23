/*
 *  linux/fs/filesystems.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  table of configured filesystems
 */

#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/hash.h>

/*
 * Handling of filesystem drivers list.
 * Rules:
 *	Inclusion to/removals from/scanning of list are protected by spinlock.
 *	During the unload module must call unregister_filesystem().
 *	We can access the fields of list element if:
 *		1) spinlock is held or
 *		2) we hold the reference to the module.
 *	The latter can be guaranteed by call of try_module_get(); if it
 *	returned 0 we must skip the element, otherwise we got the reference.
 *	Once the reference is obtained we can drop the spinlock.
 */

static struct file_system_type *file_systems;
static DEFINE_RWLOCK(file_systems_lock);
/*
 * KABI: keep a hash table of file systems that registered an extended
 * file operations struct.  There's a smallish number of registered
 * file systems by default (31 on my machine), so we don't need a large
 * hash table.  However, it's large enough that a linked list would likely
 * be too much overhead.
 */
#define FO_EXTEND_BITS 6
#define FO_EXTEND_SIZE (1 << FO_EXTEND_BITS)
struct hlist_head fo_extend_hash[FO_EXTEND_SIZE];
static DEFINE_SPINLOCK(fo_extend_lock);
struct fo_extend_ent {
	struct hlist_node node;
	struct rcu_head rcu;
	const struct file_operations_extend *foe;
};

/* WARNING: This can be used only if we _already_ own a reference */
void get_filesystem(struct file_system_type *fs)
{
	__module_get(fs->owner);
}

void put_filesystem(struct file_system_type *fs)
{
	module_put(fs->owner);
}

static struct file_system_type **find_filesystem(const char *name, unsigned len)
{
	struct file_system_type **p;
	for (p=&file_systems; *p; p=&(*p)->next)
		if (strlen((*p)->name) == len &&
		    strncmp((*p)->name, name, len) == 0)
			break;
	return p;
}

static struct fo_extend_ent *lookup_fo_extend_ent(
	const struct file_operations_extend *foe)
{
	unsigned long bucket = hash_ptr(foe, FO_EXTEND_BITS);
	struct hlist_head *head = &fo_extend_hash[bucket];
	struct fo_extend_ent *pos;

	hlist_for_each_entry_rcu(pos, head, node) {
		if (pos->foe == foe)
			return pos;
	}
	return NULL;
}

const struct file_operations_extend *lookup_fo_extend(
	const struct file_operations *fops)
{
	struct fo_extend_ent *foe_ent;
	const struct file_operations_extend *foe = NULL;

	rcu_read_lock();
	foe_ent = lookup_fo_extend_ent(
		(const struct file_operations_extend *)fops);
	if (foe_ent)
		foe = foe_ent->foe;
	rcu_read_unlock();

	return foe;
}

EXPORT_SYMBOL(lookup_fo_extend);

int register_fo_extend(const struct file_operations_extend *foe)
{
	unsigned long bucket = hash_ptr(foe, FO_EXTEND_BITS);
	struct hlist_head *head = &fo_extend_hash[bucket];
	struct fo_extend_ent *foe_ent;

	foe_ent = kzalloc(sizeof(*foe_ent), GFP_KERNEL);
	if (!foe_ent) {
		printk("%s: kmalloc failed!\n", __func__);
		return -1;
	}
	foe_ent->foe = foe;

	spin_lock(&fo_extend_lock);
	rcu_read_lock();
	if (lookup_fo_extend_ent(foe) != NULL) {
		WARN(1, "duplicate registration of file operations\n");
		kfree(foe_ent);
		goto out_unlock;
	}
	hlist_add_head_rcu(&foe_ent->node, head);

out_unlock:
	rcu_read_unlock();
	spin_unlock(&fo_extend_lock);

	return 0;
}

EXPORT_SYMBOL(register_fo_extend);

void unregister_fo_extend(const struct file_operations_extend *foe)
{
	struct fo_extend_ent *foe_ent;

	spin_lock(&fo_extend_lock);
	rcu_read_lock();
	foe_ent = lookup_fo_extend_ent(foe);
	if (foe_ent) {
		hlist_del_rcu(&foe_ent->node);
		kfree_rcu(foe_ent, rcu);
	}
	rcu_read_unlock();
	spin_unlock(&fo_extend_lock);
}

EXPORT_SYMBOL(unregister_fo_extend);

/**
 *	register_filesystem - register a new filesystem
 *	@fs: the file system structure
 *
 *	Adds the file system passed to the list of file systems the kernel
 *	is aware of for mount and other syscalls. Returns 0 on success,
 *	or a negative errno code on an error.
 *
 *	The &struct file_system_type that is passed is linked into the kernel 
 *	structures and must not be freed until the file system has been
 *	unregistered.
 */
 
int register_filesystem(struct file_system_type * fs)
{
	int res = 0;
	struct file_system_type ** p;

	BUG_ON(strchr(fs->name, '.'));
	if (fs->next)
		return -EBUSY;
	write_lock(&file_systems_lock);
	p = find_filesystem(fs->name, strlen(fs->name));
	if (*p)
		res = -EBUSY;
	else
		*p = fs;
	write_unlock(&file_systems_lock);
	return res;
}

EXPORT_SYMBOL(register_filesystem);

/**
 *	unregister_filesystem - unregister a file system
 *	@fs: filesystem to unregister
 *
 *	Remove a file system that was previously successfully registered
 *	with the kernel. An error is returned if the file system is not found.
 *	Zero is returned on a success.
 *	
 *	Once this function has returned the &struct file_system_type structure
 *	may be freed or reused.
 */
 
int unregister_filesystem(struct file_system_type * fs)
{
	struct file_system_type ** tmp;

	write_lock(&file_systems_lock);
	tmp = &file_systems;
	while (*tmp) {
		if (fs == *tmp) {
			*tmp = fs->next;
			fs->next = NULL;
			write_unlock(&file_systems_lock);
			synchronize_rcu();
			return 0;
		}
		tmp = &(*tmp)->next;
	}
	write_unlock(&file_systems_lock);

	return -EINVAL;
}

EXPORT_SYMBOL(unregister_filesystem);

static int fs_index(const char __user * __name)
{
	struct file_system_type * tmp;
	struct filename *name;
	int err, index;

	name = getname(__name);
	err = PTR_ERR(name);
	if (IS_ERR(name))
		return err;

	err = -EINVAL;
	read_lock(&file_systems_lock);
	for (tmp=file_systems, index=0 ; tmp ; tmp=tmp->next, index++) {
		if (strcmp(tmp->name, name->name) == 0) {
			err = index;
			break;
		}
	}
	read_unlock(&file_systems_lock);
	putname(name);
	return err;
}

static int fs_name(unsigned int index, char __user * buf)
{
	struct file_system_type * tmp;
	int len, res;

	read_lock(&file_systems_lock);
	for (tmp = file_systems; tmp; tmp = tmp->next, index--)
		if (index <= 0 && try_module_get(tmp->owner))
			break;
	read_unlock(&file_systems_lock);
	if (!tmp)
		return -EINVAL;

	/* OK, we got the reference, so we can safely block */
	len = strlen(tmp->name) + 1;
	res = copy_to_user(buf, tmp->name, len) ? -EFAULT : 0;
	put_filesystem(tmp);
	return res;
}

static int fs_maxindex(void)
{
	struct file_system_type * tmp;
	int index;

	read_lock(&file_systems_lock);
	for (tmp = file_systems, index = 0 ; tmp ; tmp = tmp->next, index++)
		;
	read_unlock(&file_systems_lock);
	return index;
}

/*
 * Whee.. Weird sysv syscall. 
 */
SYSCALL_DEFINE3(sysfs, int, option, unsigned long, arg1, unsigned long, arg2)
{
	int retval = -EINVAL;

	switch (option) {
		case 1:
			retval = fs_index((const char __user *) arg1);
			break;

		case 2:
			retval = fs_name(arg1, (char __user *) arg2);
			break;

		case 3:
			retval = fs_maxindex();
			break;
	}
	return retval;
}

int __init get_filesystem_list(char *buf)
{
	int len = 0;
	struct file_system_type * tmp;

	read_lock(&file_systems_lock);
	tmp = file_systems;
	while (tmp && len < PAGE_SIZE - 80) {
		len += sprintf(buf+len, "%s\t%s\n",
			(tmp->fs_flags & FS_REQUIRES_DEV) ? "" : "nodev",
			tmp->name);
		tmp = tmp->next;
	}
	read_unlock(&file_systems_lock);
	return len;
}

#ifdef CONFIG_PROC_FS
static int filesystems_proc_show(struct seq_file *m, void *v)
{
	struct file_system_type * tmp;

	read_lock(&file_systems_lock);
	tmp = file_systems;
	while (tmp) {
		seq_printf(m, "%s\t%s\n",
			(tmp->fs_flags & FS_REQUIRES_DEV) ? "" : "nodev",
			tmp->name);
		tmp = tmp->next;
	}
	read_unlock(&file_systems_lock);
	return 0;
}

static int filesystems_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, filesystems_proc_show, NULL);
}

static const struct file_operations filesystems_proc_fops = {
	.open		= filesystems_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init proc_filesystems_init(void)
{
	proc_create("filesystems", 0, NULL, &filesystems_proc_fops);
	return 0;
}
module_init(proc_filesystems_init);
#endif

static struct file_system_type *__get_fs_type(const char *name, int len)
{
	struct file_system_type *fs;

	read_lock(&file_systems_lock);
	fs = *(find_filesystem(name, len));
	if (fs && !try_module_get(fs->owner))
		fs = NULL;
	read_unlock(&file_systems_lock);
	return fs;
}

struct file_system_type *get_fs_type(const char *name)
{
	struct file_system_type *fs;
	const char *dot = strchr(name, '.');
	int len = dot ? dot - name : strlen(name);

	fs = __get_fs_type(name, len);
	if (!fs && (request_module("fs-%.*s", len, name) == 0))
		fs = __get_fs_type(name, len);

	if (dot && fs && !(fs->fs_flags & FS_HAS_SUBTYPE)) {
		put_filesystem(fs);
		fs = NULL;
	}
	return fs;
}

EXPORT_SYMBOL(get_fs_type);
