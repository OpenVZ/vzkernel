/*
 *  binfmt_misc.c
 *
 *  Copyright (C) 1997 Richard Günther
 *
 *  binfmt_misc detects binaries via a magic or filename extension and invokes
 *  a specified wrapper. This should obsolete binfmt_java, binfmt_em86 and
 *  binfmt_mz.
 *
 *  1997-04-25 first version
 *  [...]
 *  1997-05-19 cleanup
 *  1997-06-26 hpa: pass the real filename rather than argv[0]
 *  1997-06-30 minor cleanup
 *  1997-08-09 removed extension stripping, locking cleanup
 *  2001-02-28 AV: rewritten into something that resembles C. Original didn't.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/magic.h>
#include <linux/binfmts.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/string_helpers.h>
#include <linux/file.h>
#include <linux/pagemap.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/ve.h>

#include <asm/uaccess.h>

enum {
	VERBOSE_STATUS = 1 /* make it zero to save 400 bytes kernel memory */
};

enum {Enabled, Magic};
#define MISC_FMT_PRESERVE_ARGV0 (1<<31)
#define MISC_FMT_OPEN_BINARY (1<<30)
#define MISC_FMT_CREDENTIALS (1<<29)

typedef struct {
	struct list_head list;
	unsigned long flags;		/* type, status, etc. */
	int offset;			/* offset of magic */
	int size;			/* size of magic/mask */
	char *magic;			/* magic or filename extension */
	char *mask;			/* mask, NULL for exact match */
	char *interpreter;		/* filename of interpreter */
	char *name;
	struct dentry *dentry;
} Node;

static struct file_system_type bm_fs_type;

struct binfmt_misc {
	struct list_head entries;
	int enabled;

	rwlock_t entries_lock;
	struct vfsmount *bm_mnt;
	int entry_count;
};

#define BINFMT_MISC(sb)		(((struct ve_struct *)(sb)->s_fs_info)->binfmt_misc)

/* 
 * Check if we support the binfmt
 * if we do, return the node, else NULL
 * locking is done in load_misc_binary
 */
static Node *check_file(struct binfmt_misc *bm_data, struct linux_binprm *bprm)
{
	char *p = strrchr(bprm->interp, '.');
	struct list_head *l;

	list_for_each(l, &bm_data->entries) {
		Node *e = list_entry(l, Node, list);
		char *s;
		int j;

		if (!test_bit(Enabled, &e->flags))
			continue;

		if (!test_bit(Magic, &e->flags)) {
			if (p && !strcmp(e->magic, p + 1))
				return e;
			continue;
		}

		s = bprm->buf + e->offset;
		if (e->mask) {
			for (j = 0; j < e->size; j++)
				if ((*s++ ^ e->magic[j]) & e->mask[j])
					break;
		} else {
			for (j = 0; j < e->size; j++)
				if ((*s++ ^ e->magic[j]))
					break;
		}
		if (j == e->size)
			return e;
	}
	return NULL;
}

/*
 * the loader itself
 */
static int load_misc_binary(struct linux_binprm *bprm)
{
	Node *fmt;
	struct file * interp_file = NULL;
	char iname[BINPRM_BUF_SIZE];
	const char *iname_addr = iname;
	int retval;
	int fd_binary = -1;
	struct binfmt_misc *bm_data = get_exec_env()->binfmt_misc;

	retval = -ENOEXEC;
	if (!bm_data || !bm_data->enabled)
		goto _ret;

	/* to keep locking time low, we copy the interpreter string */
	read_lock(&bm_data->entries_lock);
	fmt = check_file(bm_data, bprm);
	if (fmt)
		strlcpy(iname, fmt->interpreter, BINPRM_BUF_SIZE);
	read_unlock(&bm_data->entries_lock);
	if (!fmt)
		goto _ret;

	if (!(fmt->flags & MISC_FMT_PRESERVE_ARGV0)) {
		retval = remove_arg_zero(bprm);
		if (retval)
			goto _ret;
	}

	if (fmt->flags & MISC_FMT_OPEN_BINARY) {

		/* if the binary should be opened on behalf of the
		 * interpreter than keep it open and assign descriptor
		 * to it */
 		fd_binary = get_unused_fd();
 		if (fd_binary < 0) {
 			retval = fd_binary;
 			goto _ret;
 		}
 		fd_install(fd_binary, bprm->file);

		/* if the binary is not readable than enforce mm->dumpable=0
		   regardless of the interpreter's permissions */
		would_dump(bprm, bprm->file);

		allow_write_access(bprm->file);
		bprm->file = NULL;

		/* mark the bprm that fd should be passed to interp */
		bprm->interp_flags |= BINPRM_FLAGS_EXECFD;
		bprm->interp_data = fd_binary;

 	} else {
 		allow_write_access(bprm->file);
 		fput(bprm->file);
 		bprm->file = NULL;
 	}
	/* make argv[1] be the path to the binary */
	retval = copy_strings_kernel (1, &bprm->interp, bprm);
	if (retval < 0)
		goto _error;
	bprm->argc++;

	/* add the interp as argv[0] */
	retval = copy_strings_kernel (1, &iname_addr, bprm);
	if (retval < 0)
		goto _error;
	bprm->argc ++;

	/* Update interp in case binfmt_script needs it. */
	retval = bprm_change_interp(iname, bprm);
	if (retval < 0)
		goto _error;

	interp_file = open_exec (iname);
	retval = PTR_ERR (interp_file);
	if (IS_ERR (interp_file))
		goto _error;

	bprm->file = interp_file;
	if (fmt->flags & MISC_FMT_CREDENTIALS) {
		/*
		 * No need to call prepare_binprm(), it's already been
		 * done.  bprm->buf is stale, update from interp_file.
		 */
		memset(bprm->buf, 0, BINPRM_BUF_SIZE);
		retval = kernel_read(bprm->file, 0, bprm->buf, BINPRM_BUF_SIZE);
	} else
		retval = prepare_binprm (bprm);

	if (retval < 0)
		goto _error;

	retval = search_binary_handler(bprm);
	if (retval < 0)
		goto _error;

_ret:
	return retval;
_error:
	if (fd_binary > 0)
		sys_close(fd_binary);
	bprm->interp_flags = 0;
	bprm->interp_data = 0;
	goto _ret;
}

/* Command parsers */

/*
 * parses and copies one argument enclosed in del from *sp to *dp,
 * recognising the \x special.
 * returns pointer to the copied argument or NULL in case of an
 * error (and sets err) or null argument length.
 */
static char *scanarg(char *s, char del)
{
	char c;

	while ((c = *s++) != del) {
		if (c == '\\' && *s == 'x') {
			s++;
			if (!isxdigit(*s++))
				return NULL;
			if (!isxdigit(*s++))
				return NULL;
		}
	}
	return s;
}

static char * check_special_flags (char * sfs, Node * e)
{
	char * p = sfs;
	int cont = 1;

	/* special flags */
	while (cont) {
		switch (*p) {
			case 'P':
				p++;
				e->flags |= MISC_FMT_PRESERVE_ARGV0;
				break;
			case 'O':
				p++;
				e->flags |= MISC_FMT_OPEN_BINARY;
				break;
			case 'C':
				p++;
				/* this flags also implies the
				   open-binary flag */
				e->flags |= (MISC_FMT_CREDENTIALS |
						MISC_FMT_OPEN_BINARY);
				break;
			default:
				cont = 0;
		}
	}

	return p;
}
/*
 * This registers a new binary format, it recognises the syntax
 * ':name:type:offset:magic:mask:interpreter:flags'
 * where the ':' is the IFS, that can be chosen with the first char
 */
static Node *create_entry(const char __user *buffer, size_t count)
{
	Node *e;
	int memsize, err;
	char *buf, *p;
	char del;

	/* some sanity checks */
	err = -EINVAL;
	if ((count < 11) || (count > 256))
		goto out;

	err = -ENOMEM;
	memsize = sizeof(Node) + count + 8;
	e = kmalloc(memsize, GFP_USER);
	if (!e)
		goto out;

	p = buf = (char *)e + sizeof(Node);

	memset(e, 0, sizeof(Node));
	if (copy_from_user(buf, buffer, count))
		goto Efault;

	del = *p++;	/* delimeter */

	memset(buf+count, del, 8);

	e->name = p;
	p = strchr(p, del);
	if (!p)
		goto Einval;
	*p++ = '\0';
	if (!e->name[0] ||
	    !strcmp(e->name, ".") ||
	    !strcmp(e->name, "..") ||
	    strchr(e->name, '/'))
		goto Einval;
	switch (*p++) {
		case 'E': e->flags = 1<<Enabled; break;
		case 'M': e->flags = (1<<Enabled) | (1<<Magic); break;
		default: goto Einval;
	}
	if (*p++ != del)
		goto Einval;
	if (test_bit(Magic, &e->flags)) {
		char *s = strchr(p, del);
		if (!s)
			goto Einval;
		*s = '\0';
		if (p != s) {
			int r = kstrtoint(p, 10, &e->offset);
			if (r != 0 || e->offset < 0)
				goto Einval;
		}
		p = s;
		if (*p++)
			goto Einval;
		e->magic = p;
		p = scanarg(p, del);
		if (!p)
			goto Einval;
		p[-1] = '\0';
		if (!e->magic[0])
			goto Einval;
		e->mask = p;
		p = scanarg(p, del);
		if (!p)
			goto Einval;
		p[-1] = '\0';
		if (!e->mask[0])
			e->mask = NULL;
		e->size = string_unescape_inplace(e->magic, UNESCAPE_HEX);
		if (e->mask &&
		    string_unescape_inplace(e->mask, UNESCAPE_HEX) != e->size)
			goto Einval;
		if (e->size > BINPRM_BUF_SIZE ||
		    BINPRM_BUF_SIZE - e->size < e->offset)
			goto Einval;
	} else {
		p = strchr(p, del);
		if (!p)
			goto Einval;
		*p++ = '\0';
		e->magic = p;
		p = strchr(p, del);
		if (!p)
			goto Einval;
		*p++ = '\0';
		if (!e->magic[0] || strchr(e->magic, '/'))
			goto Einval;
		p = strchr(p, del);
		if (!p)
			goto Einval;
		*p++ = '\0';
	}
	e->interpreter = p;
	p = strchr(p, del);
	if (!p)
		goto Einval;
	*p++ = '\0';
	if (!e->interpreter[0])
		goto Einval;


	p = check_special_flags (p, e);

	if (*p == '\n')
		p++;
	if (p != buf + count)
		goto Einval;
	return e;

out:
	return ERR_PTR(err);

Efault:
	kfree(e);
	return ERR_PTR(-EFAULT);
Einval:
	kfree(e);
	return ERR_PTR(-EINVAL);
}

/*
 * Set status of entry/binfmt_misc:
 * '1' enables, '0' disables and '-1' clears entry/binfmt_misc
 */
static int parse_command(const char __user *buffer, size_t count)
{
	char s[4];

	if (!count)
		return 0;
	if (count > 3)
		return -EINVAL;
	if (copy_from_user(s, buffer, count))
		return -EFAULT;
	if (s[count-1] == '\n')
		count--;
	if (count == 1 && s[0] == '0')
		return 1;
	if (count == 1 && s[0] == '1')
		return 2;
	if (count == 2 && s[0] == '-' && s[1] == '1')
		return 3;
	return -EINVAL;
}

/* generic stuff */

static void entry_status(Node *e, char *page)
{
	char *dp;
	char *status = "disabled";
	const char * flags = "flags: ";

	if (test_bit(Enabled, &e->flags))
		status = "enabled";

	if (!VERBOSE_STATUS) {
		sprintf(page, "%s\n", status);
		return;
	}

	sprintf(page, "%s\ninterpreter %s\n", status, e->interpreter);
	dp = page + strlen(page);

	/* print the special flags */
	sprintf (dp, "%s", flags);
	dp += strlen (flags);
	if (e->flags & MISC_FMT_PRESERVE_ARGV0) {
		*dp ++ = 'P';
	}
	if (e->flags & MISC_FMT_OPEN_BINARY) {
		*dp ++ = 'O';
	}
	if (e->flags & MISC_FMT_CREDENTIALS) {
		*dp ++ = 'C';
	}
	*dp ++ = '\n';


	if (!test_bit(Magic, &e->flags)) {
		sprintf(dp, "extension .%s\n", e->magic);
	} else {
		int i;

		sprintf(dp, "offset %i\nmagic ", e->offset);
		dp = page + strlen(page);
		for (i = 0; i < e->size; i++) {
			sprintf(dp, "%02x", 0xff & (int) (e->magic[i]));
			dp += 2;
		}
		if (e->mask) {
			sprintf(dp, "\nmask ");
			dp += 6;
			for (i = 0; i < e->size; i++) {
				sprintf(dp, "%02x", 0xff & (int) (e->mask[i]));
				dp += 2;
			}
		}
		*dp++ = '\n';
		*dp = '\0';
	}
}

static struct inode *bm_get_inode(struct super_block *sb, int mode)
{
	struct inode * inode = new_inode(sb);

	if (inode) {
		inode->i_ino = get_next_ino();
		inode->i_mode = mode;
		inode->i_atime = inode->i_mtime = inode->i_ctime =
			current_fs_time(inode->i_sb);
	}
	return inode;
}

static void bm_evict_inode(struct inode *inode)
{
	clear_inode(inode);
	kfree(inode->i_private);
}

static void kill_node(struct binfmt_misc *bm_data, Node *e)
{
	struct dentry *dentry;

	write_lock(&bm_data->entries_lock);
	dentry = e->dentry;
	if (dentry) {
		list_del_init(&e->list);
		e->dentry = NULL;
	}
	write_unlock(&bm_data->entries_lock);

	if (dentry) {
		drop_nlink(dentry->d_inode);
		d_drop(dentry);
		dput(dentry);
		simple_release_fs(&bm_data->bm_mnt, &bm_data->entry_count);
	}
}

/* /<entry> */

static ssize_t
bm_entry_read(struct file * file, char __user * buf, size_t nbytes, loff_t *ppos)
{
	Node *e = file_inode(file)->i_private;
	ssize_t res;
	char *page;

	if (!(page = (char*) __get_free_page(GFP_KERNEL)))
		return -ENOMEM;

	entry_status(e, page);

	res = simple_read_from_buffer(buf, nbytes, ppos, page, strlen(page));

	free_page((unsigned long) page);
	return res;
}

static ssize_t bm_entry_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *ppos)
{
	struct dentry *root;
	Node *e = file_inode(file)->i_private;
	int res = parse_command(buffer, count);
	struct super_block *sb = file->f_path.dentry->d_sb;
	struct binfmt_misc *bm_data = BINFMT_MISC(sb);

	switch (res) {
		case 1: clear_bit(Enabled, &e->flags);
			break;
		case 2: set_bit(Enabled, &e->flags);
			break;
		case 3: root = dget(sb->s_root);
			mutex_lock(&root->d_inode->i_mutex);

			kill_node(bm_data, e);

			mutex_unlock(&root->d_inode->i_mutex);
			dput(root);
			break;
		default: return res;
	}
	return count;
}

static const struct file_operations bm_entry_operations = {
	.read		= bm_entry_read,
	.write		= bm_entry_write,
	.llseek		= default_llseek,
};

/* /register */

static ssize_t bm_register_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *ppos)
{
	Node *e;
	struct inode *inode;
	struct dentry *root, *dentry;
	struct super_block *sb = file->f_path.dentry->d_sb;
	struct binfmt_misc *bm_data = BINFMT_MISC(sb);
	int err = 0;

	e = create_entry(buffer, count);

	if (IS_ERR(e))
		return PTR_ERR(e);

	root = dget(sb->s_root);
	mutex_lock(&root->d_inode->i_mutex);
	dentry = lookup_one_len(e->name, root, strlen(e->name));
	err = PTR_ERR(dentry);
	if (IS_ERR(dentry))
		goto out;

	err = -EEXIST;
	if (dentry->d_inode)
		goto out2;

	inode = bm_get_inode(sb, S_IFREG | 0644);

	err = -ENOMEM;
	if (!inode)
		goto out2;

	err = simple_pin_fs(&bm_fs_type, &bm_data->bm_mnt, &bm_data->entry_count);
	if (err) {
		iput(inode);
		inode = NULL;
		goto out2;
	}

	e->dentry = dget(dentry);
	inode->i_private = e;
	inode->i_fop = &bm_entry_operations;

	d_instantiate(dentry, inode);
	write_lock(&bm_data->entries_lock);
	list_add(&e->list, &bm_data->entries);
	write_unlock(&bm_data->entries_lock);

	err = 0;
out2:
	dput(dentry);
out:
	mutex_unlock(&root->d_inode->i_mutex);
	dput(root);

	if (err) {
		kfree(e);
		return -EINVAL;
	}
	return count;
}

static const struct file_operations bm_register_operations = {
	.write		= bm_register_write,
	.llseek		= noop_llseek,
};

/* /status */

static ssize_t
bm_status_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
	struct binfmt_misc *bm_data = BINFMT_MISC(file->f_dentry->d_sb);
	char *s = bm_data->enabled ? "enabled\n" : "disabled\n";

	return simple_read_from_buffer(buf, nbytes, ppos, s, strlen(s));
}

static ssize_t bm_status_write(struct file * file, const char __user * buffer,
		size_t count, loff_t *ppos)
{
	struct binfmt_misc *bm_data = BINFMT_MISC(file->f_dentry->d_sb);
	int res = parse_command(buffer, count);
	struct dentry *root;

	switch (res) {
		case 1: bm_data->enabled = 0; break;
		case 2: bm_data->enabled = 1; break;
		case 3: root = dget(file->f_path.dentry->d_sb->s_root);
			mutex_lock(&root->d_inode->i_mutex);

			while (!list_empty(&bm_data->entries))
				kill_node(bm_data, list_first_entry(
					&bm_data->entries, Node, list));

			mutex_unlock(&root->d_inode->i_mutex);
			dput(root);
		default: return res;
	}
	return count;
}

static const struct file_operations bm_status_operations = {
	.read		= bm_status_read,
	.write		= bm_status_write,
	.llseek		= default_llseek,
};

/* Superblock handling */

static void bm_put_super(struct super_block *sb)
{
	struct binfmt_misc *bm_data = BINFMT_MISC(sb);
	struct ve_struct *ve = sb->s_fs_info;

	bm_data->enabled = 0;
	put_ve(ve);
}

static const struct super_operations s_ops = {
	.statfs		= simple_statfs,
	.evict_inode	= bm_evict_inode,
	.put_super	= bm_put_super,
};

static int bm_fill_super(struct super_block * sb, void * data, int silent)
{
	static struct tree_descr bm_files[] = {
		[2] = {"status", &bm_status_operations, S_IWUSR|S_IRUGO},
		[3] = {"register", &bm_register_operations, S_IWUSR},
		/* last one */ {""}
	};
	struct ve_struct *ve = data;
	struct binfmt_misc *bm_data = ve->binfmt_misc;
	int err;

	if (!bm_data) {
		bm_data = kzalloc(sizeof(struct binfmt_misc), GFP_KERNEL);
		if (!bm_data)
			return -ENOMEM;

		INIT_LIST_HEAD(&bm_data->entries);
		rwlock_init(&bm_data->entries_lock);

		ve->binfmt_misc = bm_data;
	}

	err = simple_fill_super(sb, BINFMTFS_MAGIC, bm_files);
	if (err) {
		kfree(bm_data);
		return err;
	}

	sb->s_op = &s_ops;

	bm_data->enabled = 1;
	get_ve(ve);

	return 0;
}

static struct dentry *bm_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	if (!current_user_ns_initial() && !capable(CAP_SYS_ADMIN))
		return ERR_PTR(-EPERM);

	return mount_ns(fs_type, flags, get_exec_env(), get_exec_env(),
			current_user_ns(), bm_fill_super);
}

static struct linux_binfmt misc_format = {
	.module = THIS_MODULE,
	.load_binary = load_misc_binary,
};

static struct file_system_type bm_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "binfmt_misc",
	.mount		= bm_mount,
	.kill_sb	= kill_litter_super,
	.fs_flags	= FS_VIRTUALIZED | FS_USERNS_MOUNT,
};
MODULE_ALIAS_FS("binfmt_misc");

static void ve_binfmt_fini(void *data)
{
	struct ve_struct *ve = data;
	struct binfmt_misc *bm_data = ve->binfmt_misc;

	if (!bm_data)
		return;

	/*
	 * XXX: Note we don't take any locks here. This is safe as long as
	 * nobody uses binfmt_misc outside the owner ve.
	 */
	while (!list_empty(&bm_data->entries))
		kill_node(bm_data, list_first_entry(
			&bm_data->entries, Node, list));
}

static struct ve_hook ve_binfmt_hook = {
	.fini		= ve_binfmt_fini,
	.priority	= HOOK_PRIO_DEFAULT,
	.owner		= THIS_MODULE,
};

static int __init init_misc_binfmt(void)
{
	int err = register_filesystem(&bm_fs_type);
	if (!err) {
		insert_binfmt(&misc_format);
		ve_hook_register(VE_SS_CHAIN, &ve_binfmt_hook);
	}
	return err;
}

static void __exit exit_misc_binfmt(void)
{
	ve_hook_unregister(&ve_binfmt_hook);
	unregister_binfmt(&misc_format);
	unregister_filesystem(&bm_fs_type);
}

core_initcall(init_misc_binfmt);
module_exit(exit_misc_binfmt);
MODULE_LICENSE("GPL");
