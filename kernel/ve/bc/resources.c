/*
 *  kernel/ve/bc/resources.c
 *
 *  Copyright (c) 2000-2018 Virtuozzo International GmbH.
 *  All rights reserved.
 *
 */

#include <linux/proc_fs.h>
#include <linux/nsproxy.h>
#include <linux/ve.h>

#include <uapi/linux/beancounter.h>
#include <net/net_namespace.h>

#include "proc.h"

/* Generic output formats */
const char *bc_proc_lu_fmt = "\t%-20s %21lu\n";
const char *bc_proc_lu_lfmt = "\t%-20s %21lu\n";
const char *bc_proc_llu_fmt = "\t%-20s %21llu\n";
const char *bc_proc_lu_lu_fmt = "\t%-20s %21lu %21lu\n";

static const char *head_fmt = "%10s  %-12s %20s %20s %20s %20s %20s\n";
static const char *res_fmt = "%10s%c %-12s %20lu %20lu %20lu %20lu %20lu\n";

static const char *ub_rnames[] = {
	"kmemsize",     /* 0 */
	"lockedpages",
	"privvmpages",
	"shmpages",
	"dummy",
	"numproc",      /* 5 */
	"physpages",
	"vmguarpages",
	"oomguarpages",
	"numtcpsock",
	"numflock",     /* 10 */
	"numpty",
	"numsiginfo",
	"tcpsndbuf",
	"tcprcvbuf",
	"othersockbuf", /* 15 */
	"dgramrcvbuf",
	"numothersock",
	"dcachesize",
	"numfile",
	"dummy",        /* 20 */
	"dummy",
	"dummy",
	"numiptent",
	"swappages",
};

static void *ve_to_pde(struct ve_struct *ve)
{
	return (void *)(unsigned long)ve->veid;
}

static struct ve_struct *get_ve_by_inode(struct inode *inode)
{
	envid_t veid = (envid_t)(unsigned long)PDE_DATA(inode);

	if (veid)
		return get_ve_by_id(veid);
	return get_ve(get_ve0());
}

static const char *ve_get_name(struct ve_struct *ve)
{
	static const char *ve0_name = "0";

	if (ve_is_super(ve))
		return ve0_name;
	return ve->ve_name;
}

static struct nsproxy *get_nsproxy_by_ve(struct ve_struct *ve)
{
	struct nsproxy *nsproxy;

	rcu_read_lock();
	nsproxy = rcu_dereference(ve->ve_ns);
	if (nsproxy)
		   get_nsproxy(nsproxy);
	rcu_read_unlock();
	return nsproxy;
}

static void ub_show_res(struct seq_file *f, struct ubparm *p, const char *name,
			int r, int precharge, int show_uid)
{

	unsigned long held;


	held = p->held;
	held = (held > precharge) ? (held - precharge) : 0;

	seq_printf(f, res_fmt,
			show_uid && r == 0 ? name : "",
			show_uid && r == 0 ? ':' : ' ',
			ub_rnames[r],
			held,
			p->maxheld,
			p->barrier,
			p->limit,
			p->failcnt);
}

static void cgroups_sync_ub(struct css_set *cset, struct ubparm *ub_parms)
{
}

static void __show_resources(struct seq_file *f, struct ve_struct *ve,
			     struct nsproxy *nsproxy, int show_uid)
{
	int r, precharge[UB_RESOURCES] = { };

	cgroups_sync_ub(nsproxy->cgroup_ns->root_cset, ve->ub_parms);

	for (r = 0; r < UB_RESOURCES; r++)
		if (strcmp(ub_rnames[r], "dummy") != 0)
			ub_show_res(f, &ve->ub_parms[r], ve_get_name(ve), r,
				    precharge[r], show_uid);
}

static int res_show(struct seq_file *f, void *v)
{
	struct ve_struct *ve = (struct ve_struct *)v;
	struct nsproxy *nsproxy;

	nsproxy = get_nsproxy_by_ve(ve);
	if (nsproxy) {
		__show_resources(f, ve, nsproxy, 1);
		put_nsproxy(nsproxy);
	}
	return 0;
}

static int ve_accessible(struct ve_struct *target)
{
	return (get_exec_env() == get_ve0() || get_exec_env() == target);
}

static void ub_show_header(struct seq_file *f)
{
	seq_printf(f, "Version: 2.5\n");
	seq_printf(f, head_fmt, "uid", "resource",
			"held", "maxheld", "barrier", "limit", "failcnt");
}

static int bc_res_show(struct seq_file *f, void *v)
{
	struct nsproxy *nsproxy = (struct nsproxy *)f->private;

	__show_resources(f, nsproxy->net_ns->owner_ve, nsproxy, 0);
	return 0;
}

static int bc_res_open(struct inode *inode, struct file *filp)
{
	struct ve_struct *ve;
	struct nsproxy *nsproxy;
	int res;

	if (!(capable(CAP_DAC_OVERRIDE) && capable(CAP_DAC_READ_SEARCH)))
		return -EACCES;

	ve = get_ve_by_inode(inode);
	if (!ve)
		return -EINVAL;

	nsproxy = get_nsproxy_by_ve(ve);
	if (!nsproxy) {
		put_ve(ve);
		return -ENODEV;
	}

	res = single_open(filp, bc_res_show, nsproxy);
	if (res) {
		put_nsproxy(nsproxy);
		put_ve(ve);
		return res;
	}

	return 0;
}

static int bc_res_release(struct inode *inode, struct file *file)
{
	struct nsproxy *nsproxy = ((struct seq_file *)file->private_data)->private;
	struct ve_struct *ve = nsproxy->net_ns->owner_ve;

	put_nsproxy(nsproxy);
	put_ve(ve);

	return single_release(inode, file);
}

static struct file_operations resources_operations = {
	.open		= bc_res_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= bc_res_release,
};

static void *ub_start(struct seq_file *f, loff_t *ppos)
{
	struct ve_struct *ve;
	unsigned long pos;

	pos = *ppos;
	if (pos == 0)
		ub_show_header(f);

	mutex_lock(&ve_list_lock);
	for_each_ve(ve) {
		if (!ve_accessible(ve))
			continue;
		if (!get_ve(ve))
			continue;
		if (pos-- == 0)
			return ve;
		put_ve(ve);
	}
	mutex_unlock(&ve_list_lock);
	return NULL;
}

static void *ub_next(struct seq_file *f, void *v, loff_t *ppos)
{
	struct ve_struct *ve = (struct ve_struct *)v;

	for_each_ve_continue(ve) {
		if (!ve_accessible(ve))
			continue;
		if (!get_ve(ve))
			continue;
		(*ppos)++;
		return ve;
	}
	return NULL;
}

static void ub_stop(struct seq_file *f, void *v)
{
	struct ve_struct *ve = (struct ve_struct *)v;

	mutex_unlock(&ve_list_lock);
	put_ve(ve);
}

static struct seq_operations all_res_seq_ops = {
	.start = ub_start,
	.next  = ub_next,
	.stop  = ub_stop,
	.show  = res_show,
};

static int all_res_open(struct inode *inode, struct file *filp)
{
	if (!(capable(CAP_DAC_OVERRIDE) && capable(CAP_DAC_READ_SEARCH)))
		return -EACCES;

	return seq_open(filp, &all_res_seq_ops);
}

static struct file_operations all_resources_operations = {
	.open		= all_res_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

void ub_proc_ve_resources_remove(struct ve_struct *ve)
{
	remove_proc_entry("resources", ve->ub_proc);
}

static void ub_ve_resources_init(struct ve_struct *ve)
{
	int r;
	struct ubparm *p;

	for (r = 0, p = &ve->ub_parms[0]; r < UB_RESOURCES; r++, p++)
		p->barrier = p->limit = UB_MAXVALUE;
}

int ub_proc_ve_resources_create(struct ve_struct *ve)
{
	ub_ve_resources_init(ve);

	if (!proc_create_data("resources", S_IRUSR|S_ISVTX,
				ve->ub_proc, &resources_operations,
				ve_to_pde(ve)))
		return -ENOMEM;
	return 0;
}

int ub_proc_all_resources_create(void)
{
	if (!proc_create("resources", S_IRUSR|S_ISVTX,
			 bc_proc_root, &all_resources_operations))
		return -ENOMEM;
	return 0;
}
