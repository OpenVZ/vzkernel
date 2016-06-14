/*
 *  kernel/bc/proc.c
 *
 *  Copyright (c) 2006-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/ve_proto.h>
#include <linux/virtinfo.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/mnt_namespace.h>
#include <linux/lglock.h>
#include <linux/ve.h>
#include <linux/memcontrol.h>

#include <bc/beancounter.h>
#include <bc/proc.h>

/* Generic output formats */
#if BITS_PER_LONG == 32
const char *bc_proc_lu_fmt = "\t%-20s %10lu\n";
const char *bc_proc_lu_lfmt = "\t%-20s %21lu\n";
const char *bc_proc_llu_fmt = "\t%-20s %21llu\n";
const char *bc_proc_lu_lu_fmt = "\t%-20s %10lu %10lu\n";
#else
const char *bc_proc_lu_fmt = "\t%-20s %21lu\n";
const char *bc_proc_lu_lfmt = "\t%-20s %21lu\n";
const char *bc_proc_llu_fmt = "\t%-20s %21llu\n";
const char *bc_proc_lu_lu_fmt = "\t%-20s %21lu %21lu\n";
#endif

#if BITS_PER_LONG == 32
static const char *head_fmt = "%10s  %-12s %10s %10s %10s %10s %10s\n";
static const char *res_fmt = "%10s%c %-12s %10lu %10lu %10lu %10lu %10lu\n";
#else
static const char *head_fmt = "%10s  %-12s %20s %20s %20s %20s %20s\n";
static const char *res_fmt = "%10s%c %-12s %20lu %20lu %20lu %20lu %20lu\n";
#endif

static void ub_show_res(struct seq_file *f, struct user_beancounter *ub,
		int r, int precharge, int show_uid)
{
	struct ubparm *p;
	unsigned long held;

	p = &ub->ub_parms[r];
	held = p->held;
	held = (held > precharge) ? (held - precharge) : 0;

	seq_printf(f, res_fmt,
			show_uid && r == 0 ? ub->ub_name : "",
			show_uid && r == 0 ? ':' : ' ',
		   	ub_rnames[r],
			held,
			p->maxheld,
			p->barrier,
			p->limit,
			p->failcnt);
}

static void __show_resources(struct seq_file *f, struct user_beancounter *ub,
		int show_uid)
{
	int i, precharge[UB_RESOURCES];

	ub_sync_memcg(ub);
	ub_precharge_snapshot(ub, precharge);

	for (i = 0; i < UB_RESOURCES_COMPAT; i++)
		if (strcmp(ub_rnames[i], "dummy") != 0)
			ub_show_res(f, ub, i, precharge[i], show_uid);

	for (i = UB_RESOURCES_COMPAT; i < UB_RESOURCES; i++)
		ub_show_res(f, ub, i, precharge[i], show_uid);
}

static int bc_resources_show(struct seq_file *f, void *v)
{
	__show_resources(f, seq_beancounter(f), 0);
	return 0;
}

static struct bc_proc_entry bc_resources_entry = {
	.name = "resources",
	.u.show = bc_resources_show,
};

static int bc_precharge_show(struct seq_file *f, void *v)
{
	struct user_beancounter *ub;
	int i, cpus = num_possible_cpus();
	int precharge[UB_RESOURCES];

	seq_printf(f, "%-12s %16s %10s %10s\n",
			"resource", "real_held", "precharge", "max_precharge");

	ub = seq_beancounter(f);
	ub_precharge_snapshot(ub, precharge);
	for ( i = 0 ; i < UB_RESOURCES ; i++ ) {
		if (!strcmp(ub_rnames[i], "dummy"))
			continue;
		seq_printf(f, "%-12s %16lu %10d %10d\n", ub_rnames[i],
				ub->ub_parms[i].held,
				precharge[i],
				ub->ub_parms[i].max_precharge * cpus);
	}

	return 0;
}

static struct bc_proc_entry bc_precharge_entry = {
	.name = "precharge",
	.u.show = bc_precharge_show,
};

static int bc_proc_meminfo_show(struct seq_file *f, void *v)
{
	return meminfo_proc_show_ub(f, NULL,
			seq_beancounter(f), VE_MEMINFO_DEFAULT);
}

static struct bc_proc_entry bc_meminfo_entry = {
	.name = "meminfo",
	.u.show = bc_proc_meminfo_show,
};

extern void mem_cgroup_get_nr_pages(struct mem_cgroup *memcg, int nid,
				    unsigned long *pages);

#define K(x) ((x) << (PAGE_SHIFT - 10))
static int bc_proc_nodeinfo_show(struct seq_file *f, void *v)
{
	int nid;
	struct cgroup_subsys_state *css;
	unsigned long pages[NR_LRU_LISTS];

	css = ub_get_mem_css(seq_beancounter(f));
	for_each_node_state(nid, N_HIGH_MEMORY) {
		memset(pages, 0, sizeof(pages));
		mem_cgroup_get_nr_pages(mem_cgroup_from_cont(css->cgroup),
					nid, pages);
		seq_printf(f,
			"Node %d Active:         %8lu kB\n"
			"Node %d Inactive:       %8lu kB\n"
			"Node %d Active(anon):   %8lu kB\n"
			"Node %d Inactive(anon): %8lu kB\n"
			"Node %d Active(file):   %8lu kB\n"
			"Node %d Inactive(file): %8lu kB\n"
			"Node %d Unevictable:    %8lu kB\n",
			nid, K(pages[LRU_ACTIVE_ANON] +
			       pages[LRU_ACTIVE_FILE]),
			nid, K(pages[LRU_INACTIVE_ANON] +
			       pages[LRU_INACTIVE_FILE]),
			nid, K(pages[LRU_ACTIVE_ANON]),
			nid, K(pages[LRU_INACTIVE_ANON]),
			nid, K(pages[LRU_ACTIVE_FILE]),
			nid, K(pages[LRU_INACTIVE_FILE]),
			nid, K(pages[LRU_UNEVICTABLE]));
	}
	css_put(css);
	return 0;
}
#undef K

static struct bc_proc_entry bc_nodeinfo_entry = {
	.name = "nodeinfo",
	.u.show = bc_proc_nodeinfo_show,
};

static int ub_show(struct seq_file *f, void *v)
{
	int i, precharge[UB_RESOURCES];
	struct user_beancounter *ub = v;

	ub_sync_memcg(ub);
	ub_precharge_snapshot(ub, precharge);

	for (i = 0; i < UB_RESOURCES_COMPAT; i++)
		ub_show_res(f, ub, i, precharge[i], 1);
	return 0;
}

static int res_show(struct seq_file *f, void *v)
{
	__show_resources(f, (struct user_beancounter *)v, 1);
	return 0;
}

static int ub_accessible(struct user_beancounter *exec,
		struct user_beancounter *target)
{
	return (exec == get_ub0() || exec == target);
}

static void ub_show_header(struct seq_file *f)
{
	seq_printf(f, "Version: 2.5\n");
	seq_printf(f, head_fmt, "uid", "resource",
			"held", "maxheld", "barrier", "limit", "failcnt");
}

static void *ub_start(struct seq_file *f, loff_t *ppos)
{
	struct user_beancounter *ub, *ret = NULL;
	struct user_beancounter *exec_ub; 
	unsigned long pos;

	pos = *ppos;
	if (pos == 0)
		ub_show_header(f);

	exec_ub = get_exec_ub();

	rcu_read_lock();
	for_each_beancounter(ub) {
		if (!ub_accessible(exec_ub, ub))
			continue;
		if (!get_beancounter_rcu(ub))
			continue;
		if (pos-- == 0) {
			ret = ub;
			break;
		}
		put_beancounter(ub);
	}
	rcu_read_unlock();
	return ret;
}

static void *ub_next(struct seq_file *f, void *v, loff_t *ppos)
{
	struct user_beancounter *ub, *ret = NULL;
	struct user_beancounter *exec_ub;

	exec_ub = get_exec_ub();
	ub = (struct user_beancounter *)v;
	rcu_read_lock();
	put_beancounter(ub);
	list_for_each_entry_continue_rcu(ub, &ub_list_head, ub_list) {
		if (!ub_accessible(exec_ub, ub))
			continue;
		if (!get_beancounter_rcu(ub))
			continue;
		(*ppos)++;
		ret = ub;
		break;
	}
	rcu_read_unlock();
	return ret;
}

static void ub_stop(struct seq_file *f, void *v)
{
	struct user_beancounter *ub;

	ub = (struct user_beancounter *)v;
	put_beancounter(ub);
}

static struct seq_operations ub_seq_ops = {
	.start = ub_start,
	.next  = ub_next,
	.stop  = ub_stop,
	.show  = ub_show,
};

static int ub_open(struct inode *inode, struct file *filp)
{
	if (!(ve_capable(CAP_DAC_OVERRIDE) && ve_capable(CAP_DAC_READ_SEARCH)))
		return -EACCES;

	return seq_open(filp, &ub_seq_ops);
}

static struct file_operations ub_file_operations = {
	.open		= ub_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static struct seq_operations res_seq_ops = {
	.start = ub_start,
	.next  = ub_next,
	.stop  = ub_stop,
	.show  = res_show,
};

static int res_open(struct inode *inode, struct file *filp)
{
	if (!(capable(CAP_DAC_OVERRIDE) && capable(CAP_DAC_READ_SEARCH)))
		return -EACCES;

	return seq_open(filp, &res_seq_ops);
}

static struct file_operations resources_operations = {
	.open		= res_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static struct bc_proc_entry bc_all_resources_entry = {
	.name = "resources",
	.u.fops = &resources_operations,
};

/*
 * Generic showing stuff
 */

static int cookies, num_entries;
static struct bc_proc_entry *bc_entries __read_mostly;
static struct bc_proc_entry *bc_root_entries __read_mostly;
static DEFINE_SPINLOCK(bc_entries_lock);
static struct proc_dir_entry *bc_proc_root;

void bc_register_proc_entry(struct bc_proc_entry *e)
{
	spin_lock(&bc_entries_lock);
	e->cookie = ++cookies;
	e->next = bc_entries;
	bc_entries = e;
	num_entries++;
	spin_unlock(&bc_entries_lock);
}

EXPORT_SYMBOL(bc_register_proc_entry);

void bc_register_proc_root_entry(struct bc_proc_entry *e)
{
	spin_lock(&bc_entries_lock);
	e->cookie = ++cookies;
	e->next = bc_root_entries;
	bc_root_entries = e;
	bc_proc_root->nlink++;
	spin_unlock(&bc_entries_lock);
}

EXPORT_SYMBOL(bc_register_proc_root_entry);

/*
 * small helpers
 */

static inline unsigned long bc_make_ino(struct user_beancounter *ub)
{
	return 0xbc000000 | (ub->css.cgroup->id + 1);
}

static inline unsigned long bc_make_file_ino(struct bc_proc_entry *de)
{
	return 0xbe000000 + de->cookie;
}

static int bc_d_delete(const struct dentry *d)
{
	return 1;
}

static void bc_d_release(struct dentry *d)
{
	put_beancounter((struct user_beancounter *)d->d_fsdata);
}

static struct inode_operations bc_entry_iops;
static struct file_operations bc_entry_fops;
static struct dentry_operations bc_dentry_ops = {
	.d_delete = bc_d_delete,
	.d_release = bc_d_release,
};

/*
 * common directory operations' helpers
 */

static int bc_readdir(struct file *file, filldir_t filler, void *data,
		struct user_beancounter *parent)
{
	int err = 0;
	loff_t pos, filled;
	struct user_beancounter *ub, *prev;
	struct bc_proc_entry *pde;

	if (!(capable(CAP_DAC_OVERRIDE) && capable(CAP_DAC_READ_SEARCH)))
		return -EPERM;

	pos = file->f_pos;
	if (pos == 0) {
		err = (*filler)(data, ".", 1, pos,
				file->f_dentry->d_inode->i_ino, DT_DIR);
		if (err < 0) {
			err = 0;
			goto out;
		}
		pos++;
	}

	if (pos == 1) {
		err = (*filler)(data, "..", 2, pos,
				parent_ino(file->f_dentry), DT_DIR);
		if (err < 0) {
			err = 0;
			goto out;
		}
		pos++;
	}

	filled = 2;
	for (pde = (parent == NULL ? bc_root_entries : bc_entries);
			pde != NULL; pde = pde->next) {
		if (filled++ < pos)
			continue;

		err = (*filler)(data, pde->name, strlen(pde->name), pos,
				bc_make_file_ino(pde), DT_REG);
		if (err < 0) {
			err = 0;
			goto out;
		}
		pos++;
	}

	if (parent)
		goto out;

	rcu_read_lock();
	prev = NULL;
	ub = list_entry(&ub_list_head, struct user_beancounter, ub_list);
	while (1) {
		ub = list_entry(rcu_dereference(ub->ub_list.next),
				struct user_beancounter, ub_list);
		if (&ub->ub_list == &ub_list_head)
			break;

		if (!get_beancounter_rcu(ub))
			continue;

		if (filled++ < pos) {
			put_beancounter(ub);
			continue;
		}

		rcu_read_unlock();
		put_beancounter(prev);

		err = (*filler)(data, ub->ub_name, strlen(ub->ub_name),
				pos, bc_make_ino(ub), DT_DIR);
		if (err < 0) {
			err = 0;
			put_beancounter(ub);
			goto out;
		}

		rcu_read_lock();
		prev = ub;
		pos++;
	}
	rcu_read_unlock();
	put_beancounter(prev);
out:
	file->f_pos = pos;
	return err;
}

static int bc_looktest(struct inode *ino, void *data)
{
	return ino->i_op == &bc_entry_iops && ino->i_private == data;
}

static int bc_lookset(struct inode *ino, void *data)
{
	struct user_beancounter *ub;

	ub = (struct user_beancounter *)data;
	ino->i_private = data;
	ino->i_ino = bc_make_ino(ub);
	ino->i_fop = &bc_entry_fops;
	ino->i_op = &bc_entry_iops;
	ino->i_mode = S_IFDIR | S_IRUSR | S_IXUSR;
	/* subbeancounters are not included, but who cares? */
	ino->__i_nlink = num_entries + 2;
	ino->i_gid = GLOBAL_ROOT_GID;
	ino->i_uid = GLOBAL_ROOT_UID;
	return 0;
}

static struct dentry *bc_lookup(struct user_beancounter *ub, struct inode *dir,
		struct dentry *dentry)
{
	struct inode *ino;

	ino = iget5_locked(dir->i_sb, ub->css.cgroup->id, bc_looktest, bc_lookset, ub);
	if (ino == NULL)
		goto out_put;

	if (ino->i_state & I_NEW)
		unlock_new_inode(ino);
	d_set_d_op(dentry, &bc_dentry_ops);
	dentry->d_fsdata = ub;
	d_add(dentry, ino);
	return NULL;

out_put:
	put_beancounter(ub);
	return ERR_PTR(-ENOENT);
}

/*
 * files (bc_proc_entry) manipulations
 */

static struct dentry *bc_lookup_file(struct inode *dir,
		struct dentry *dentry, struct bc_proc_entry *root,
		int (*test)(struct inode *, void *),
		int (*set)(struct inode *, void *))
{
	struct bc_proc_entry *pde;
	struct inode *ino;

	for (pde = root; pde != NULL; pde = pde->next)
		if (strcmp(pde->name, dentry->d_name.name) == 0)
			break;

	if (pde == NULL)
		return ERR_PTR(-ESRCH);

	ino = iget5_locked(dir->i_sb, pde->cookie, test, set, pde);
	if (ino == NULL)
		return ERR_PTR(-ENOENT);

	if (ino->i_state & I_NEW)
		unlock_new_inode(ino);
	d_set_d_op(dentry, &bc_dentry_ops);
	d_add(dentry, ino);
	return NULL;
}

static int bc_file_open(struct inode *ino, struct file *filp)
{
	struct bc_proc_entry *de;
	struct user_beancounter *ub;

	de = (struct bc_proc_entry *)ino->i_private;
	ub = (struct user_beancounter *)filp->f_dentry->d_parent->d_fsdata;
	BUG_ON(ub->ub_magic != UB_MAGIC);

	/*
	 * ub can't disappear: we hold d_parent, he holds the beancounter
	 */
	return single_open(filp, de->u.show, ub);
}

static struct file_operations bc_file_ops = {
	.open		= bc_file_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int bc_looktest_entry(struct inode *ino, void *data)
{
	return ino->i_fop == &bc_file_ops && ino->i_private == data;
}

static int bc_lookset_entry(struct inode *ino, void *data)
{
	struct bc_proc_entry *de;

	de = (struct bc_proc_entry *)data;
	ino->i_private = data;
	ino->i_ino = bc_make_file_ino(de);
	ino->i_fop = &bc_file_ops,
	ino->i_mode = S_IFREG | S_IRUSR;
	ino->__i_nlink = 1;
	ino->i_gid = GLOBAL_ROOT_GID;
	ino->i_uid = GLOBAL_ROOT_UID;
	return 0;
}

static inline struct dentry *bc_lookup_files(struct inode *dir,
		struct dentry *de)
{
	return bc_lookup_file(dir, de, bc_entries,
			bc_looktest_entry, bc_lookset_entry);
}

static int bc_looktest_root_entry(struct inode *ino, void *data)
{
	struct bc_proc_entry *de;

	de = (struct bc_proc_entry *)data;
	return ino->i_fop == de->u.fops && ino->i_private == data;
}

static int bc_lookset_root_entry(struct inode *ino, void *data)
{
	struct bc_proc_entry *de;

	de = (struct bc_proc_entry *)data;
	ino->i_private = data;
	ino->i_ino = bc_make_file_ino(de);
	ino->i_fop = de->u.fops;
	ino->i_mode = S_IFREG | S_IRUSR;
	ino->__i_nlink = 1;
	ino->i_gid = GLOBAL_ROOT_GID;
	ino->i_uid = GLOBAL_ROOT_UID;
	return 0;
}

static inline struct dentry *bc_lookup_root_files(struct inode *dir,
		struct dentry *de)
{
	return bc_lookup_file(dir, de, bc_root_entries,
			bc_looktest_root_entry, bc_lookset_root_entry);
}

/*
 * /proc/bc/.../<id> directory operations
 */

static int bc_entry_readdir(struct file *file, void *data, filldir_t filler)
{
	return bc_readdir(file, filler, data,
			(struct user_beancounter *)file->f_dentry->d_fsdata);
}

static struct dentry *bc_entry_lookup(struct inode *dir, struct dentry *dentry,
		unsigned int flags)
{
	struct dentry *de;

	if (!(capable(CAP_DAC_OVERRIDE) && capable(CAP_DAC_READ_SEARCH)))
		return ERR_PTR(-EPERM);

	de = bc_lookup_files(dir, dentry);
	if (de != ERR_PTR(-ESRCH))
		return de;

	return ERR_PTR(-ENOENT);
}

static int bc_entry_getattr(struct vfsmount *mnt, struct dentry *dentry,
		struct kstat *stat)
{
	struct user_beancounter *ub;

	generic_fillattr(dentry->d_inode, stat);
	ub = (struct user_beancounter *)dentry->d_fsdata;
	stat->nlink = 2;
	return 0;
}

static struct file_operations bc_entry_fops = {
	.read = generic_read_dir,
	.readdir = bc_entry_readdir,
};

static struct inode_operations bc_entry_iops = {
	.lookup = bc_entry_lookup,
	.getattr = bc_entry_getattr,
};

/*
 * /proc/bc directory operations
 */

static int bc_root_readdir(struct file *file, void *data, filldir_t filler)
{
	return bc_readdir(file, filler, data, NULL);
}

static struct dentry *bc_root_lookup(struct inode *dir, struct dentry *dentry,
		unsigned int flags)
{
	struct user_beancounter *ub;
	struct dentry *de;

	if (!(capable(CAP_DAC_OVERRIDE) && capable(CAP_DAC_READ_SEARCH)))
		return ERR_PTR(-EPERM);

	de = bc_lookup_root_files(dir, dentry);
	if (de != ERR_PTR(-ESRCH))
		return de;

	ub = get_beancounter_by_name(dentry->d_name.name, 0);
	if (IS_ERR_OR_NULL(ub))
		return ub ? ERR_CAST(ub) : ERR_PTR(-ENOENT);

	return bc_lookup(ub, dir, dentry);
}

static int bc_root_getattr(struct vfsmount *mnt, struct dentry *dentry,
	struct kstat *stat)
{
	generic_fillattr(dentry->d_inode, stat);
	stat->nlink = ub_count + 2;
	return 0;
}

static struct file_operations bc_root_fops = {
	.read = generic_read_dir,
	.readdir = bc_root_readdir,
};

static struct inode_operations bc_root_iops = {
	.lookup = bc_root_lookup,
	.getattr = bc_root_getattr,
};

static int ub_vswap_show(struct seq_file *f, void *unused)
{
	seq_puts(f, "Version: 1.0\n");
	return 0;
}

static int ub_vswap_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, ub_vswap_show, NULL);
}

static struct file_operations ub_vswap_fops = {
	.open		= ub_vswap_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init ub_init_proc(void)
{
	struct proc_dir_entry *entry;

	bc_proc_root = proc_mkdir_mode("bc", 0, NULL);
	if (bc_proc_root == NULL)
		panic("Can't create /proc/bc entry");

	bc_proc_root->proc_fops = &bc_root_fops;
	bc_proc_root->proc_iops = &bc_root_iops;

	bc_register_proc_entry(&bc_resources_entry);
	bc_register_proc_entry(&bc_precharge_entry);
	bc_register_proc_root_entry(&bc_all_resources_entry);
	bc_register_proc_entry(&bc_meminfo_entry);
	bc_register_proc_entry(&bc_nodeinfo_entry);

	entry = proc_create("user_beancounters",
			S_IRUSR|S_ISVTX, NULL, &ub_file_operations);
	proc_create("vswap", S_IRUSR, proc_vz_dir, &ub_vswap_fops);
	return 0;
}

core_initcall(ub_init_proc);
