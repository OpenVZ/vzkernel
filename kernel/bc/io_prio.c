/*
 *  kernel/bc/io_prio.c
 *
 *  Copyright (C) 2010  Parallels, inc.
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.Parallels" file.
 *
 */

#include <linux/module.h>
#include <linux/cgroup.h>
#include <bc/beancounter.h>
#include <bc/proc.h>

static unsigned int ioprio_weight[UB_IOPRIO_MAX] = {
	320, 365, 410, 460, 500, 550, 600, 640,
};

extern unsigned int blkcg_get_weight(struct cgroup *cgrp);
extern int blkcg_set_weight(struct cgroup *cgrp, unsigned int weight);
extern void blkcg_show_ub_iostat(struct cgroup *cgrp, struct seq_file *sf);

int ub_set_ioprio(int id, int ioprio)
{
	struct user_beancounter *ub;
	struct cgroup_subsys_state *css;
	int ret;

	ret = -ERANGE;
	if (ioprio < UB_IOPRIO_MIN || ioprio >= UB_IOPRIO_MAX)
		goto out;

	ret = -ESRCH;
	ub = get_beancounter_byuid(id, 0);
	if (!ub)
		goto out;

	css = ub_get_blkio_css(ub);
	ret = blkcg_set_weight(css->cgroup, ioprio_weight[ioprio]);
	css_put(css);
	put_beancounter(ub);
out:
	return ret;
}

#ifdef CONFIG_PROC_FS

static int bc_iostat(struct seq_file *f, struct user_beancounter *bc)
{
	struct cgroup_subsys_state *css;

	seq_printf(f, "flush %s . 0 0 0 0 0 %ld %ld 0 0\n",
			bc->ub_name,
			ub_stat_get_exact(bc, wb_requests),
			ub_stat_get_exact(bc, wb_sectors));

	seq_printf(f, "fuse %s . 0 0 0 0 0 %lu %lu 0 0\n",
			bc->ub_name,
			__ub_percpu_sum(bc, fuse_requests),
			__ub_percpu_sum(bc, fuse_bytes) >> 9);

	css = ub_get_blkio_css(bc);
	blkcg_show_ub_iostat(css->cgroup, f);
	css_put(css);
	return 0;
}

static int bc_iostat_single(struct seq_file *f, void *v)
{
	return bc_iostat(f, seq_beancounter(f));
}

static struct bc_proc_entry bc_iostat_entry = {
	.name = "iostat",
	.u.show = bc_iostat_single,
};

static void *bc_iostat_start(struct seq_file *f, loff_t *ppos)
{
	struct user_beancounter *ub;
	unsigned long pos = *ppos;

	rcu_read_lock();
	for_each_beancounter(ub) {
		if (!pos--)
			return ub;
	}
	return NULL;
}

static void *bc_iostat_next(struct seq_file *f, void *v, loff_t *ppos)
{
	struct user_beancounter *ub = v;

	list_for_each_entry_continue_rcu(ub, &ub_list_head, ub_list) {
		(*ppos)++;
		return ub;
	}
	return NULL;
}

static int bc_iostat_show(struct seq_file *f, void *v)
{
	f->private = v;
	return bc_iostat(f, v);
}

static void bc_iostat_stop(struct seq_file *f, void *v)
{
	rcu_read_unlock();
}

static struct seq_operations iostat_seq_ops = {
	.start = bc_iostat_start,
	.next  = bc_iostat_next,
	.stop  = bc_iostat_stop,
	.show  = bc_iostat_show,
};

static int bc_iostat_open(struct inode *inode, struct file *filp)
{
	if (!(capable(CAP_DAC_OVERRIDE) && capable(CAP_DAC_READ_SEARCH)))
		return -EACCES;

	return seq_open(filp, &iostat_seq_ops);
}

static struct file_operations bc_iostat_ops = {
	.open		= bc_iostat_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static struct bc_proc_entry bc_root_iostat_entry = {
	.name = "iostat",
	.u.fops = &bc_iostat_ops,
};

static int bc_ioprio_show(struct seq_file *f, void *v)
{
	struct user_beancounter *bc;
	struct cgroup_subsys_state *css;
	unsigned int weight;
	int ioprio;

	bc = seq_beancounter(f);

	css = ub_get_blkio_css(bc);
	weight = blkcg_get_weight(css->cgroup);
	css_put(css);

	ioprio = UB_IOPRIO_MAX - 1;
	while (ioprio && weight < ioprio_weight[ioprio])
		ioprio--;

	seq_printf(f, "prio: %d\n", ioprio);
	return 0;
}

static struct bc_proc_entry bc_ioprio_entry = {
	.name = "ioprio",
	.u.show = bc_ioprio_show,
};

static int __init bc_iostat_init(void)
{
	bc_register_proc_entry(&bc_ioprio_entry);
	bc_register_proc_entry(&bc_iostat_entry);
	bc_register_proc_root_entry(&bc_root_iostat_entry);
	return 0;
}
late_initcall(bc_iostat_init);

#endif /* CONFIG_PROC_FS */
