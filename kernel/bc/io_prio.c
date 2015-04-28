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
#include "blk-cgroup.h"

//static u64 ioprio_weight[UB_IOPRIO_MAX] = {320, 365, 410, 460, 500, 550, 600, 640};

void ub_init_ioprio(struct user_beancounter *ub)
{
	//blkio_cgroup_set_ub(ub->blkio_cgroup, ub);
}

void ub_fini_ioprio(struct user_beancounter *ub)
{
	//blkio_cgroup_set_ub(ub->blkio_cgroup, &ub0);
}

int ub_set_ioprio(int id, int ioprio)
{
	struct user_beancounter *ub;
	int ret;

	ret = -ERANGE;
	if (ioprio < UB_IOPRIO_MIN || ioprio >= UB_IOPRIO_MAX)
		goto out;

	ret = -ESRCH;
	ub = get_beancounter_byuid(id, 0);
	if (!ub)
		goto out;

	ret = 0;
#if 0
	if (ub->blkio_cgroup)
//		ret = blkio_cgroup_set_weight(ub->blkio_cgroup,
//				ioprio_weight[ioprio])
		ret = 0;
	else
		ret = -ENOTSUPP;
#endif
	put_beancounter(ub);
out:
	return ret;
}

#if 0

static int bc_iostat(struct seq_file *f, struct user_beancounter *bc)
{
	struct blkio_group_stats *stats;
	struct blkio_cgroup *blkcg;
	struct blkio_group *blkg;
	struct hlist_node *n;

	seq_printf(f, "%s %s %c %lu %lu %lu %u %u %lu %lu\n",
			"flush" ,
			bc->ub_name, '.',
			0ul, 0ul, 0ul, 0, 0,
			ub_stat_get_exact(bc, wb_requests),
			ub_stat_get_exact(bc, wb_sectors));

	seq_printf(f, "%s %s %c %lu %lu %lu %u %u %lu %lu\n",
			"fuse" ,
			bc->ub_name, '.',
			0ul, 0ul, 0ul, 0, 0,
			__ub_percpu_sum(bc, fuse_requests),
			__ub_percpu_sum(bc, fuse_bytes) >> 9);

	if (!bc->blkio_cgroup)
		return 0;

	blkcg = cgroup_to_blkio_cgroup(bc->blkio_cgroup);

	rcu_read_lock();
	hlist_for_each_entry_rcu(blkg, n, &blkcg->blkg_list, blkcg_node) {
		unsigned long queued, serviced, sectors;
		unsigned int used_time, wait_time;
		uint64_t tmp;

		if (!blkg->dev || blkg->plid != BLKIO_POLICY_PROP)
			continue;

		spin_lock_irq(&blkg->stats_lock);
		stats = &blkg->stats;
		queued    = stats->stat_arr[BLKIO_STAT_QUEUED][BLKIO_STAT_READ] +
			    stats->stat_arr[BLKIO_STAT_QUEUED][BLKIO_STAT_WRITE];
		serviced  = blkio_read_stat_cpu(blkg, BLKIO_STAT_CPU_SERVICED, BLKIO_STAT_READ);
		serviced += blkio_read_stat_cpu(blkg, BLKIO_STAT_CPU_SERVICED, BLKIO_STAT_WRITE);
		tmp	  = stats->stat_arr[BLKIO_STAT_WAIT_TIME][BLKIO_STAT_READ] +
			    stats->stat_arr[BLKIO_STAT_WAIT_TIME][BLKIO_STAT_WRITE];
		do_div(tmp, NSEC_PER_MSEC);
		wait_time = tmp;

		used_time = jiffies_to_msecs(stats->time);
		sectors   = blkio_read_stat_cpu(blkg, BLKIO_STAT_CPU_SECTORS, 0);
		spin_unlock_irq(&blkg->stats_lock);

		seq_printf(f, "%s %s %c %lu %lu %lu %u %u %lu %lu\n",
				blkg->dev_name ?: "none" ,
				bc->ub_name, '.',
				queued, 0ul, 0ul,
				wait_time, used_time,
				serviced, sectors);
	}
	rcu_read_unlock();

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
	struct list_head *entry;

	entry = &ub->ub_list;
	list_for_each_continue_rcu(entry, &ub_list_head) {
		ub = list_entry(entry, struct user_beancounter, ub_list);
		(*ppos)++;
		return ub;
	}
	return NULL;
}

static int bc_iostat_show(struct seq_file *f, void *v)
{
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
	struct blkio_cgroup *blkcg;
	int ioprio;

	bc = seq_beancounter(f);

	if (!bc->blkio_cgroup)
		return 0;

	blkcg = cgroup_to_blkio_cgroup(bc->blkio_cgroup);

	ioprio = UB_IOPRIO_MAX - 1;
	while (ioprio && blkcg->weight < ioprio_weight[ioprio])
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
