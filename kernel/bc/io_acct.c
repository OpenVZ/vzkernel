/*
 *  kernel/ub/io_acct.c
 *
 *  Copyright (C) 2006  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 *  Pavel Emelianov <xemul@openvz.org>
 *
 */

#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/mempool.h>
#include <linux/proc_fs.h>
#include <linux/virtinfo.h>
#include <linux/pagemap.h>
#include <linux/module.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>

#include <bc/beancounter.h>
#include <bc/io_acct.h>
#include <bc/proc.h>
#include <bc/vmpages.h>

/*
 * starts writeback at this dirty memory percentage from physpages limit
 */
int ub_dirty_ratio = 50;
int ub_dirty_background_ratio = 30;

/* under write lock mapping->tree_lock */

void ub_io_account_dirty(struct address_space *mapping)
{
	struct user_beancounter *ub = mapping->dirtied_ub;

	WARN_ON_ONCE(!radix_tree_tagged(&mapping->page_tree,
				PAGECACHE_TAG_DIRTY));

	if (!ub)
		ub = mapping->dirtied_ub = get_beancounter(get_io_ub());

	ub_stat_inc(ub, dirty_pages);
}

void ub_io_account_clean(struct address_space *mapping)
{
	struct user_beancounter *ub = mapping->dirtied_ub;
	size_t bytes = PAGE_SIZE;

	if (unlikely(!ub)) {
		WARN_ON_ONCE(1);
		return;
	}

	ub_stat_dec(ub, dirty_pages);

	ub_percpu_inc(ub, async_write_complete);

	ub = set_exec_ub(ub);
	virtinfo_notifier_call(VITYPE_IO, VIRTINFO_IO_ACCOUNT, &bytes);
	ub = set_exec_ub(ub);

	if (!radix_tree_tagged(&mapping->page_tree, PAGECACHE_TAG_DIRTY) &&
	    (!radix_tree_tagged(&mapping->page_tree, PAGECACHE_TAG_WRITEBACK) ||
	     !mapping_cap_account_writeback(mapping))) {
		mapping->dirtied_ub = NULL;
		put_beancounter(ub);
	}
}

void ub_io_account_cancel(struct address_space *mapping)
{
	struct user_beancounter *ub = mapping->dirtied_ub;

	if (unlikely(!ub)) {
		WARN_ON_ONCE(1);
		return;
	}

	ub_stat_dec(ub, dirty_pages);

	ub_percpu_inc(ub, async_write_canceled);

	if (!radix_tree_tagged(&mapping->page_tree, PAGECACHE_TAG_DIRTY) &&
	    (!radix_tree_tagged(&mapping->page_tree, PAGECACHE_TAG_WRITEBACK) ||
	     !mapping_cap_account_writeback(mapping))) {
		mapping->dirtied_ub = NULL;
		put_beancounter(ub);
	}
}

void ub_io_writeback_inc(struct address_space *mapping)
{
	struct user_beancounter *ub = mapping->dirtied_ub;

	WARN_ON_ONCE(!radix_tree_tagged(&mapping->page_tree,
				PAGECACHE_TAG_WRITEBACK));

	if (!ub)
		ub = mapping->dirtied_ub = get_beancounter(get_io_ub());

	ub_stat_inc(ub, writeback_pages);
}

void ub_io_writeback_dec(struct address_space *mapping)
{
	struct user_beancounter *ub = mapping->dirtied_ub;

	if (unlikely(!ub)) {
		WARN_ON_ONCE(1);
		return;
	}

	ub_stat_dec(ub, writeback_pages);

	if (!radix_tree_tagged(&mapping->page_tree, PAGECACHE_TAG_WRITEBACK) &&
	    (!radix_tree_tagged(&mapping->page_tree, PAGECACHE_TAG_DIRTY) ||
	     !mapping_cap_account_dirty(mapping))) {
		mapping->dirtied_ub = NULL;
		put_beancounter(ub);
	}
}

int ub_dirty_limits(unsigned long *pbackground,
		    long *pdirty, struct user_beancounter *ub)
{
	int dirty_ratio;
	unsigned long available_memory;

	dirty_ratio = ub_dirty_ratio;
	if (!dirty_ratio)
		return 0;

	available_memory = ub_total_pages(ub, false);
	if (available_memory == ULONG_MAX || available_memory == 0)
		return 0;

	*pdirty = (dirty_ratio * available_memory) / 100;

	dirty_ratio = ub_dirty_background_ratio;
	*pbackground = (dirty_ratio * available_memory) / 100;
	if (!dirty_ratio || *pbackground >= *pdirty)
		*pbackground = *pdirty / 2;

	return 1;
}

bool ub_should_skip_writeback(struct user_beancounter *ub, struct inode *inode)
{
	struct user_beancounter *dirtied_ub;
	bool ret;

	rcu_read_lock();
	dirtied_ub = rcu_dereference(inode->i_mapping->dirtied_ub);
	ret = !dirtied_ub || (dirtied_ub != ub &&
			!test_bit(UB_DIRTY_EXCEEDED, &dirtied_ub->ub_flags));
	rcu_read_unlock();

	return ret;
}

#ifdef CONFIG_PROC_FS
#define in_flight(var)	(var > var##_done ? var - var##_done : 0)

static int bc_ioacct_show(struct seq_file *f, void *v)
{
	int i;
	unsigned long long read, write, cancel;
	unsigned long sync, sync_done;
	unsigned long fsync, fsync_done;
	unsigned long fdsync, fdsync_done;
	unsigned long frsync, frsync_done;
	struct user_beancounter *ub;
	unsigned long dirty_pages;
	unsigned long long dirtied;
	unsigned long fuse_requests, fuse_bytes;

	ub = seq_beancounter(f);

	dirty_pages = __ub_stat_get(ub, dirty_pages);

	read = write = cancel = 0;
	sync = sync_done = fsync = fsync_done =
		fdsync = fdsync_done = frsync = frsync_done = 0;
	fuse_requests = fuse_bytes = 0;
	for_each_online_cpu(i) {
		struct ub_percpu_struct *ub_percpu;
		ub_percpu = per_cpu_ptr(ub->ub_percpu, i);

		read += ub_percpu->sync_read_bytes;
		write += ub_percpu->sync_write_bytes;

		dirty_pages += ub_percpu->dirty_pages;
		write += (u64)ub_percpu->async_write_complete << PAGE_SHIFT;
		cancel += (u64)ub_percpu->async_write_canceled << PAGE_SHIFT;

		sync += ub_percpu->sync;
		fsync += ub_percpu->fsync;
		fdsync += ub_percpu->fdsync;
		frsync += ub_percpu->frsync;
		sync_done += ub_percpu->sync_done;
		fsync_done += ub_percpu->fsync_done;
		fdsync_done += ub_percpu->fdsync_done;
		frsync_done += ub_percpu->frsync_done;

		fuse_requests += ub_percpu->fuse_requests;
		fuse_bytes += ub_percpu->fuse_bytes;
	}

	if ((long)dirty_pages < 0)
		dirty_pages = 0;

	dirtied = write + cancel;
	dirtied += (u64)dirty_pages << PAGE_SHIFT;

	seq_printf(f, bc_proc_llu_fmt, "read", read);
	seq_printf(f, bc_proc_llu_fmt, "write", write);
	seq_printf(f, bc_proc_llu_fmt, "dirty", dirtied);
	seq_printf(f, bc_proc_llu_fmt, "cancel", cancel);
	seq_printf(f, bc_proc_llu_fmt, "missed", 0ull);

	seq_printf(f, bc_proc_lu_lfmt, "syncs_total", sync);
	seq_printf(f, bc_proc_lu_lfmt, "fsyncs_total", fsync);
	seq_printf(f, bc_proc_lu_lfmt, "fdatasyncs_total", fdsync);
	seq_printf(f, bc_proc_lu_lfmt, "range_syncs_total", frsync);

	seq_printf(f, bc_proc_lu_lfmt, "syncs_active", in_flight(sync));
	seq_printf(f, bc_proc_lu_lfmt, "fsyncs_active", in_flight(fsync));
	seq_printf(f, bc_proc_lu_lfmt, "fdatasyncs_active", in_flight(fsync));
	seq_printf(f, bc_proc_lu_lfmt, "range_syncs_active", in_flight(frsync));

	seq_printf(f, bc_proc_lu_lfmt, "io_pbs", dirty_pages);

	seq_printf(f, bc_proc_lu_lfmt, "fuse_requests", fuse_requests);
	seq_printf(f, bc_proc_lu_lfmt, "fuse_bytes", fuse_bytes);

	return 0;
}

static struct bc_proc_entry bc_ioacct_entry = {
	.name = "ioacct",
	.u.show = bc_ioacct_show,
};

static int bc_ioacct_notify(struct vnotifier_block *self,
		unsigned long event, void *arg, int old_ret)
{
	struct user_beancounter *ub;
	struct ub_percpu_struct *ub_pcpu;
	unsigned long *vm_events;
	unsigned long long bin, bout;
	int i;

	if (event != VIRTINFO_VMSTAT)
		return old_ret;

	ub = get_exec_ub();
	if (ub == get_ub0())
		return old_ret;

	/* Think over: do we need to account here bytes_dirty_missed? */
	bout = 0;
	bin = 0;
	for_each_online_cpu(i) {
		ub_pcpu = per_cpu_ptr(ub->ub_percpu, i);
		bout += (u64)ub_pcpu->async_write_complete << PAGE_SHIFT;
		bout += ub_pcpu->sync_write_bytes;
		bin += ub_pcpu->sync_read_bytes;
	}

	/* convert to Kbytes */
	bout >>= 10;
	bin >>= 10;

	vm_events = ((unsigned long *)arg) + NR_VM_ZONE_STAT_ITEMS;
	vm_events[PGPGOUT] = (unsigned long)bout;
	vm_events[PGPGIN] = (unsigned long)bin;
	return NOTIFY_OK;
}

static struct vnotifier_block bc_ioacct_nb = {
	.notifier_call = bc_ioacct_notify,
};

static int __init bc_ioacct_init(void)
{
	bc_register_proc_entry(&bc_ioacct_entry);

	virtinfo_notifier_register(VITYPE_GENERAL, &bc_ioacct_nb);
	return 0;
}

late_initcall(bc_ioacct_init);
#endif
