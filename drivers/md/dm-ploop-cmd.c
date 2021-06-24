/*
 *  drivers/md/dm-ploop-cmd.c
 *
 *  Copyright (c) 2020-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/init.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/ctype.h>
#include <linux/umh.h>
#include "dm-ploop.h"

#define DM_MSG_PREFIX "ploop"

static void ploop_queue_deferred_cmd(struct ploop *ploop, struct ploop_cmd *cmd)
{
	unsigned long flags;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	BUG_ON(ploop->deferred_cmd && ploop->deferred_cmd != cmd);
	ploop->deferred_cmd = cmd;
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);
	queue_work(ploop->wq, &ploop->worker);
}

/*
 * Assign newly allocated memory for BAT array and holes_bitmap
 * before grow.
 */
static void ploop_advance_holes_bitmap(struct ploop *ploop,
				       struct ploop_cmd *cmd)
{
	unsigned int i, end, size, dst_cluster, *bat_entries;
	struct rb_node *node;
	struct md_page *md;

	/* This is called only once */
	if (cmd->resize.stage != PLOOP_GROW_STAGE_INITIAL)
		return;
	cmd->resize.stage++;

	write_lock_irq(&ploop->bat_rwlock);
	/* Copy and swap holes_bitmap */
	size = DIV_ROUND_UP(ploop->hb_nr, 8);
	memcpy(cmd->resize.holes_bitmap, ploop->holes_bitmap, size);
	swap(cmd->resize.holes_bitmap, ploop->holes_bitmap);
	for (i = ploop->hb_nr; i < size * 8; i++)
		set_bit(i, ploop->holes_bitmap);
	swap(cmd->resize.hb_nr, ploop->hb_nr);
	ploop_for_each_md_page(ploop, md, node) {
		init_bat_entries_iter(ploop, md->id, &i, &end);
		bat_entries = kmap_atomic(md->page);
		for (; i <= end; i++) {
			if (!md_page_cluster_is_in_top_delta(ploop, md, i))
				continue;
			dst_cluster = bat_entries[i];
			/* This may happen after grow->shrink->(now) grow */
			if (dst_cluster < ploop->hb_nr &&
			    test_bit(dst_cluster, ploop->holes_bitmap)) {
				ploop_hole_clear_bit(dst_cluster, ploop);
			}
		}
		kunmap_atomic(bat_entries);
	}
	write_unlock_irq(&ploop->bat_rwlock);
}

static int wait_for_completion_maybe_killable(struct completion *comp,
					      bool killable)
{
	int ret = 0;

	if (killable) {
		ret = wait_for_completion_killable_timeout(comp, PLOOP_INFLIGHT_TIMEOUT);
		if (!ret)
			ret = -ETIMEDOUT;
		else if (ret > 0)
			ret = 0;
	} else {
		wait_for_completion(comp);
	}

	return ret;
}

/*
 * Switch index of ploop->inflight_bios_ref[] and wait till inflight
 * bios are completed. This waits for completion of simple submitted
 * action like write to origin_dev or read from delta, but it never
 * guarantees completion of complex actions like "data write + index
 * writeback" (for index protection look at cluster locks). This is
 * weaker, than "dmsetup suspend".
 * It is called from kwork only, so this can't be executed in parallel.
 */
static int ploop_inflight_bios_ref_switch(struct ploop *ploop, bool killable)
{
	struct completion *comp = &ploop->inflight_bios_ref_comp;
	unsigned int index = ploop->inflight_bios_ref_index;
	int ret;

	WARN_ON_ONCE(current->flags & PF_WQ_WORKER);

	if (ploop->inflight_ref_comp_pending) {
		/* Previous completion was interrupted */
		ret = wait_for_completion_maybe_killable(comp, killable);
		if (ret)
			return ret;
		ploop->inflight_ref_comp_pending = false;
		percpu_ref_reinit(&ploop->inflight_bios_ref[!index]);
	}

	init_completion(comp);

	spin_lock_irq(&ploop->deferred_lock);
	ploop->inflight_bios_ref_index = !index;
	spin_unlock_irq(&ploop->deferred_lock);

	percpu_ref_kill(&ploop->inflight_bios_ref[index]);

	ret = wait_for_completion_maybe_killable(comp, killable);
	if (ret) {
		ploop->inflight_ref_comp_pending = true;
		return ret;
	}

	percpu_ref_reinit(&ploop->inflight_bios_ref[index]);
	return 0;
}

static int ploop_suspend_submitting_pios(struct ploop *ploop)
{
	spin_lock_irq(&ploop->deferred_lock);
	WARN_ON_ONCE(ploop->stop_submitting_pios);
	ploop->stop_submitting_pios = true;
	spin_unlock_irq(&ploop->deferred_lock);

	return ploop_inflight_bios_ref_switch(ploop, true);
}

static void ploop_resume_submitting_pios(struct ploop *ploop)
{
	LIST_HEAD(list);

	spin_lock_irq(&ploop->deferred_lock);
	WARN_ON_ONCE(!ploop->stop_submitting_pios);
	ploop->stop_submitting_pios = false;
	list_splice_tail_init(&ploop->suspended_pios, &list);
	spin_unlock_irq(&ploop->deferred_lock);

	submit_pios(ploop, &list);
}

/* Find existing BAT cluster pointing to dst_cluster */
static unsigned int ploop_find_bat_entry(struct ploop *ploop,
					 unsigned int dst_cluster,
					 bool *is_locked)
{
	unsigned int i, end, *bat_entries, cluster = UINT_MAX;
	struct rb_node *node;
	struct md_page *md;

	read_lock_irq(&ploop->bat_rwlock);
	ploop_for_each_md_page(ploop, md, node) {
		init_bat_entries_iter(ploop, md->id, &i, &end);
		bat_entries = kmap_atomic(md->page);
		for (; i <= end; i++) {
			if (bat_entries[i] != dst_cluster)
				continue;
			if (md_page_cluster_is_in_top_delta(ploop, md, i)) {
				cluster = page_clu_idx_to_bat_clu(md->id, i);
				break;
			}
		}
		kunmap_atomic(bat_entries);
		if (cluster != UINT_MAX)
			break;
	}
	read_unlock_irq(&ploop->bat_rwlock);

	*is_locked = false;
	if (cluster != UINT_MAX) {
		spin_lock_irq(&ploop->deferred_lock);
		*is_locked = find_lk_of_cluster(ploop, cluster);
		spin_unlock_irq(&ploop->deferred_lock);
	}

	return cluster;
}

void pio_prepare_offsets(struct ploop *ploop, struct pio *pio,
			 unsigned int cluster)
{
	int i, nr_pages = nr_pages_in_cluster(ploop);

	pio->bi_iter.bi_idx = 0;
	pio->bi_iter.bi_bvec_done = 0;
	pio->bi_vcnt = nr_pages;

	for (i = 0; i < nr_pages; i++) {
		pio->bi_io_vec[i].bv_offset = 0;
		pio->bi_io_vec[i].bv_len = PAGE_SIZE;
	}
	pio->bi_iter.bi_sector = CLU_TO_SEC(ploop, cluster);
	pio->bi_iter.bi_size = CLU_SIZE(ploop);
}

static void wake_completion(struct pio *pio, void *data, blk_status_t status)
{
	struct completion *completion = data;

	complete(completion);
}

static int ploop_read_cluster_sync(struct ploop *ploop, struct pio *pio,
				   unsigned int dst_cluster)
{
	DECLARE_COMPLETION(completion);

	init_pio(ploop, REQ_OP_READ, pio);
	pio_prepare_offsets(ploop, pio, dst_cluster);

	pio->endio_cb = wake_completion;
	pio->endio_cb_data = &completion;

	map_and_submit_rw(ploop, dst_cluster, pio, top_level(ploop));
	wait_for_completion(&completion);

	if (pio->bi_status)
		return blk_status_to_errno(pio->bi_status);

	return 0;
}

static int ploop_write_cluster_sync(struct ploop *ploop, struct pio *pio,
				    unsigned int dst_cluster)
{
	struct file *file = top_delta(ploop)->file;
	DECLARE_COMPLETION(completion);
	int ret;

	ret = vfs_fsync(file, 0);
	if (ret)
		return ret;

	init_pio(ploop, REQ_OP_WRITE, pio);
	pio_prepare_offsets(ploop, pio, dst_cluster);

	pio->endio_cb = wake_completion;
	pio->endio_cb_data = &completion;

	map_and_submit_rw(ploop, dst_cluster, pio, top_level(ploop));
	wait_for_completion(&completion);

	if (pio->bi_status)
		return blk_status_to_errno(pio->bi_status);

	/* track_bio(ploop, bio); */
	return vfs_fsync(file, 0);
}

static int ploop_write_zero_cluster_sync(struct ploop *ploop,
					 struct pio *pio,
					 unsigned int cluster)
{
	void *data;
	int i;

	for (i = 0; i < pio->bi_vcnt; i++) {
		data = kmap_atomic(pio->bi_io_vec[i].bv_page);
		memset(data, 0, PAGE_SIZE);
		kunmap_atomic(data);
	}

	return ploop_write_cluster_sync(ploop, pio, cluster);
}

static int ploop_grow_relocate_cluster(struct ploop *ploop,
				       struct ploop_index_wb *piwb,
				       struct ploop_cmd *cmd)
{
	unsigned int new_dst, cluster, dst_cluster;
	struct pio *pio = cmd->resize.pio;
	bool is_locked;
	int ret = 0;

	dst_cluster = cmd->resize.dst_cluster;

	/* Relocate cluster and update index */
	cluster = ploop_find_bat_entry(ploop, dst_cluster, &is_locked);
	if (cluster == UINT_MAX || is_locked) {
		/* dst_cluster in top delta is not occupied? */
		if (!test_bit(dst_cluster, ploop->holes_bitmap) || is_locked) {
			WARN_ON_ONCE(1);
			ret = -EIO;
			goto out;
		}
		/* Cluster is free, occupy it. Skip relocaton */
		ploop_hole_clear_bit(dst_cluster, ploop);
		goto not_occupied;
	}

	/* Read full cluster sync */
	ret = ploop_read_cluster_sync(ploop, pio, dst_cluster);
	if (ret < 0)
		goto out;

	ret = ploop_prepare_reloc_index_wb(ploop, piwb, cluster,
					   &new_dst);
	if (ret < 0)
		goto out;

	/* Write cluster to new destination */
	ret = ploop_write_cluster_sync(ploop, pio, new_dst);
	if (ret) {
		ploop_reset_bat_update(piwb);
		goto out;
	}

	/* Write new index on disk */
	ploop_submit_index_wb_sync(ploop, piwb);
	ret = blk_status_to_errno(piwb->bi_status);
	ploop_reset_bat_update(piwb);
	if (ret)
		goto out;

	/* Update local BAT copy */
	write_lock_irq(&ploop->bat_rwlock);
	WARN_ON(!try_update_bat_entry(ploop, cluster, top_level(ploop), new_dst));
	write_unlock_irq(&ploop->bat_rwlock);
not_occupied:
	/*
	 * Now dst_cluster is not referenced in BAT, so increase the value
	 * for next iteration. The place we do this is significant: caller
	 * makes rollback based on this.
	 */
	cmd->resize.dst_cluster++;

	/* Zero new BAT entries on disk. */
	ret = ploop_write_zero_cluster_sync(ploop, pio, dst_cluster);
out:
	return ret;
}

static int ploop_grow_update_header(struct ploop *ploop,
				    struct ploop_index_wb *piwb,
				    struct ploop_cmd *cmd)
{
	unsigned int size, first_block_off;
	struct ploop_pvd_header *hdr;
	u32 nr_be, offset, clus;
	u64 sectors;
	int ret;

	/* hdr is in the same page as bat_entries[0] index */
	ret = ploop_prepare_reloc_index_wb(ploop, piwb, 0, NULL);
	if (ret)
		return ret;

	size = (PLOOP_MAP_OFFSET + cmd->resize.nr_bat_entries);
	size *= sizeof(map_index_t);
	clus = DIV_ROUND_UP(size, CLU_SIZE(ploop));
	first_block_off = CLU_TO_SEC(ploop, clus);

	hdr = kmap_atomic(piwb->bat_page);
	/* TODO: head and cylinders */
	nr_be = hdr->m_Size = cpu_to_le32(cmd->resize.nr_bat_entries);
	sectors = hdr->m_SizeInSectors_v2 = cpu_to_le64(cmd->resize.new_sectors);
	offset = hdr->m_FirstBlockOffset = cpu_to_le32(first_block_off);
	kunmap_atomic(hdr);

	ploop_submit_index_wb_sync(ploop, piwb);
	ret = blk_status_to_errno(piwb->bi_status);
	if (!ret) {
		/* Now update our cached page */
		hdr = kmap_atomic(cmd->resize.md0->page);
		hdr->m_Size = nr_be;
		hdr->m_SizeInSectors_v2 = sectors;
		hdr->m_FirstBlockOffset = offset;
		kunmap_atomic(hdr);
	}

	ploop_reset_bat_update(piwb);
	return ret;
}

static void ploop_add_md_pages(struct ploop *ploop, struct rb_root *from)
{
	struct rb_node *node;
        struct md_page *md;

        while ((node = from->rb_node) != NULL) {
		md = rb_entry(node, struct md_page, node);
		rb_erase(node, from);
		md_page_insert(ploop, md);
	}
}
/*
 * Here we relocate data clusters, which may intersect with BAT area
 * of disk after resize. For user they look as already written to disk,
 * so be careful(!) and protective. Update indexes only after cluster
 * data is written to disk.
 */
static int process_resize_cmd(struct ploop *ploop, struct ploop_cmd *cmd)
{
	struct ploop_index_wb piwb;
	unsigned int dst_cluster;
	int ret = 0;

	ploop_index_wb_init(&piwb, ploop);

	/* Update memory arrays and hb_nr, but do not update nr_bat_entries. */
	ploop_advance_holes_bitmap(ploop, cmd);

	while (cmd->resize.dst_cluster <= cmd->resize.end_dst_cluster) {
		ret = ploop_grow_relocate_cluster(ploop, &piwb, cmd);
		if (ret)
			goto out;
	}

	/* Update header metadata */
	ret = ploop_grow_update_header(ploop, &piwb, cmd);
out:
	write_lock_irq(&ploop->bat_rwlock);
	if (ret) {
		/* Cleanup: mark new BAT overages as free clusters */
		dst_cluster = cmd->resize.dst_cluster - 1;

		while (dst_cluster >= cmd->resize.nr_old_bat_clu) {
			ploop_hole_set_bit(dst_cluster, ploop);
			dst_cluster--;
		}
		swap(ploop->hb_nr, cmd->resize.hb_nr);
	} else {
		ploop_add_md_pages(ploop, &cmd->resize.md_pages_root);
		swap(ploop->nr_bat_entries, cmd->resize.nr_bat_entries);
	}
	write_unlock_irq(&ploop->bat_rwlock);

	return ret;
}

struct pio *alloc_pio_with_pages(struct ploop *ploop)
{
	int i, nr_pages = nr_pages_in_cluster(ploop);
	struct pio *pio;
	u32 size;

	size = sizeof(*pio) + sizeof(*pio->bi_io_vec) * nr_pages;
	pio = kmalloc(size, GFP_NOIO);
	if (!pio)
		return NULL;
	pio->bi_io_vec = (void *)(pio + 1);

	for (i = 0; i < nr_pages; i++) {
		pio->bi_io_vec[i].bv_page = alloc_page(GFP_NOIO);
		if (!pio->bi_io_vec[i].bv_page)
			goto err;
		pio->bi_io_vec[i].bv_offset = 0;
		pio->bi_io_vec[i].bv_len = PAGE_SIZE;
	}

	pio->bi_vcnt = nr_pages;
	pio->bi_iter.bi_size = CLU_SIZE(ploop);

	return pio;
err:
	while (i-- > 0)
		put_page(pio->bi_io_vec[i].bv_page);
	kfree(pio);
	return NULL;
}

void free_pio_with_pages(struct ploop *ploop, struct pio *pio)
{
	int i, nr_pages = pio->bi_vcnt;
	struct page *page;

	/*
	 * Not a error for this function, but the rest of code
	 * may expect this. Sanity check.
	 */
	WARN_ON_ONCE(nr_pages != nr_pages_in_cluster(ploop));

	for (i = 0; i < nr_pages; i++) {
		page = pio->bi_io_vec[i].bv_page;
		put_page(page);
	}

	kfree(pio);
}

/* @new_size is in sectors */
/* TODO: we may delegate this to userspace */
static int ploop_resize(struct ploop *ploop, sector_t new_sectors)
{
	unsigned int nr_bat_entries, nr_old_bat_clusters, nr_bat_clusters;
	struct ploop_cmd cmd = { .resize.md_pages_root = RB_ROOT };
	unsigned int hb_nr, size, old_size;
	struct ploop_pvd_header *hdr;
	sector_t old_sectors;
	struct md_page *md0;
	int ret = -ENOMEM;

	if (ploop->maintaince)
		return -EBUSY;
	if (ploop_is_ro(ploop))
		return -EROFS;

	md0 = md_page_find(ploop, 0);
	if (WARN_ON(!md0))
		return -EIO;
	hdr = kmap(md0->page);
	old_sectors = le64_to_cpu(hdr->m_SizeInSectors_v2);
	kunmap(md0->page);

	if (old_sectors == new_sectors)
		return 0;
	if (old_sectors > new_sectors) {
		DMWARN("online shrink is not supported");
		return -EINVAL;
	} else if (SEC_TO_CLU(ploop, new_sectors) >= UINT_MAX - 2) {
		DMWARN("resize: too large size is requested");
		return -EINVAL;
	} else if (new_sectors & (CLU_TO_SEC(ploop, 1) - 1)) {
		DMWARN("resize: new_sectors is not aligned");
		return -EINVAL;
	}

	nr_bat_entries = SEC_TO_CLU(ploop, new_sectors);

	/* Memory for new md pages */
	if (prealloc_md_pages(&cmd.resize.md_pages_root,
			      ploop->nr_bat_entries, nr_bat_entries) < 0)
		goto err;

	size = (PLOOP_MAP_OFFSET + nr_bat_entries) * sizeof(map_index_t);
	nr_bat_clusters = DIV_ROUND_UP(size, CLU_SIZE(ploop));
	hb_nr = nr_bat_clusters + nr_bat_entries;
	size = round_up(DIV_ROUND_UP(hb_nr, 8), sizeof(unsigned long));

	/* Currently occupied bat clusters */
	nr_old_bat_clusters = ploop_nr_bat_clusters(ploop,
						    ploop->nr_bat_entries);
	/* Memory for holes_bitmap */
	cmd.resize.holes_bitmap = kvmalloc(size, GFP_KERNEL);
	if (!cmd.resize.holes_bitmap)
		goto err;

	/* Mark all new bitmap memory as holes */
	old_size = DIV_ROUND_UP(ploop->hb_nr, 8);
	memset(cmd.resize.holes_bitmap + old_size, 0xff, size - old_size);

	cmd.resize.pio = alloc_pio_with_pages(ploop);
	if (!cmd.resize.pio)
		goto err;

	cmd.resize.cluster = UINT_MAX;
	cmd.resize.dst_cluster = nr_old_bat_clusters;
	cmd.resize.end_dst_cluster = nr_bat_clusters - 1;
	cmd.resize.nr_old_bat_clu = nr_old_bat_clusters;
	cmd.resize.nr_bat_entries = nr_bat_entries;
	cmd.resize.hb_nr = hb_nr;
	cmd.resize.new_sectors = new_sectors;
	cmd.resize.md0 = md0;
	cmd.retval = 0;
	cmd.ploop = ploop;

	ploop_suspend_submitting_pios(ploop);
	ret = process_resize_cmd(ploop, &cmd);
	ploop_resume_submitting_pios(ploop);
err:
	if (cmd.resize.pio)
		free_pio_with_pages(ploop, cmd.resize.pio);
	kvfree(cmd.resize.holes_bitmap);
	free_md_pages_tree(&cmd.resize.md_pages_root);
	return ret;
}

static void ploop_queue_deferred_cmd_wrapper(struct ploop *ploop,
					     int ret, void *data)
{
	struct ploop_cmd *cmd = data;

	if (ret) {
		/* kwork will see this at next time it is on cpu */
		WRITE_ONCE(cmd->retval, ret);
	}
	atomic_inc(&cmd->merge.nr_available);
	ploop_queue_deferred_cmd(cmd->ploop, cmd);
}

/* Find mergeable cluster and return it in cmd->merge.cluster */
static bool iter_delta_clusters(struct ploop *ploop, struct ploop_cmd *cmd)
{
	unsigned int dst_cluster, *cluster = &cmd->merge.cluster;
	u8 level;
	bool skip;

	BUG_ON(cmd->type != PLOOP_CMD_MERGE_SNAPSHOT);

	for (; *cluster < ploop->nr_bat_entries; ++*cluster) {
		/*
		 * Check *cluster is provided by the merged delta.
		 * We are in kwork, so bat_rwlock is not needed
		 * (see comment in process_one_deferred_bio()).
		 */
		/* FIXME: Optimize this. ploop_bat_entries() is overkill */
		dst_cluster = ploop_bat_entries(ploop, *cluster, &level);
		if (dst_cluster == BAT_ENTRY_NONE ||
		    level != ploop->nr_deltas - 2)
			continue;

		spin_lock_irq(&ploop->deferred_lock);
		skip = find_lk_of_cluster(ploop, *cluster);
		spin_unlock_irq(&ploop->deferred_lock);
		if (skip) {
			/*
			 * Cluster is locked (maybe, under COW).
			 * Skip it and try to repeat later.
			 */
			cmd->merge.do_repeat = true;
			continue;
		}

		return true;
	}

	return false;
}

static void process_merge_latest_snapshot_cmd(struct ploop *ploop,
					      struct ploop_cmd *cmd)
{
	unsigned int dst_cluster, *cluster = &cmd->merge.cluster;
	u8 level;

	if (cmd->retval)
		goto out;

	while (iter_delta_clusters(ploop, cmd)) {
		/*
		 * We are in kwork, so bat_rwlock is not needed
		 * (we can't race with changing BAT, since cmds
		 *  are processed before bios and piwb is sync).
		 */
		/* FIXME: Optimize this: ploop_bat_entries() is overkill */
		dst_cluster = ploop_bat_entries(ploop, *cluster, &level);

		/* Check we can submit one more cow in parallel */
		if (!atomic_add_unless(&cmd->merge.nr_available, -1, 0))
			return;
		/*
		 * This adds cluster lk. Further write bios to *cluster will go
		 * from ploop_map to kwork (because bat_levels[*cluster] is not
		 * top_level()), so they will see the lk.
		 */
		if (submit_cluster_cow(ploop, level, *cluster, dst_cluster,
				    ploop_queue_deferred_cmd_wrapper, cmd)) {
			atomic_inc(&cmd->merge.nr_available);
			cmd->retval = -ENOMEM;
			goto out;
		}

		++*cluster;
	}
out:
	if (atomic_read(&cmd->merge.nr_available) != NR_MERGE_BIOS) {
		/* Wait till last COW queues us */
		return;
	}

	complete(&cmd->comp); /* Last touch of cmd memory */
}

static int ploop_merge_latest_snapshot(struct ploop *ploop)
{
	struct ploop_cmd cmd;
	struct file *file;
	u8 level;
	int ret;

	if (ploop->maintaince)
		return -EBUSY;
	if (ploop_is_ro(ploop))
		return -EROFS;
	if (ploop->nr_deltas < 2)
		return -ENOENT;
again:
	memset(&cmd, 0, sizeof(cmd));
	cmd.type = PLOOP_CMD_MERGE_SNAPSHOT;
	cmd.ploop = ploop;
	atomic_set(&cmd.merge.nr_available, NR_MERGE_BIOS);

	init_completion(&cmd.comp);
	ploop_queue_deferred_cmd(ploop, &cmd);
	ret = wait_for_completion_interruptible(&cmd.comp);
	if (ret) {
		/*
		 * process_merge_latest_snapshot_cmd() will see this
		 * later or earlier. Take a lock if you want earlier.
		 */
		WRITE_ONCE(cmd.retval, -EINTR);
		wait_for_completion(&cmd.comp);
	}

	if (cmd.retval)
		goto out;

	if (cmd.merge.do_repeat)
		goto again;

	/* Delta merged. Release delta's file */
	cmd.retval = ploop_suspend_submitting_pios(ploop);
	if (cmd.retval)
		goto out;

	write_lock_irq(&ploop->bat_rwlock);
	level = ploop->nr_deltas - 2;
	file = ploop->deltas[level].file;
	ploop->deltas[level] = ploop->deltas[level + 1];
	ploop->nr_deltas--;
	write_unlock_irq(&ploop->bat_rwlock);
	fput(file);

	ploop_resume_submitting_pios(ploop);
out:
	return cmd.retval;
}

static void notify_delta_merged(struct ploop *ploop, u8 level,
				void *hdr, bool forward)
{
	unsigned int i, end, *bat_entries, *delta_bat_entries;
	struct rb_node *node;
	struct md_page *md;
	struct file *file;

	/* Points to hdr since md_page[0] also contains hdr. */
	delta_bat_entries = (map_index_t *)hdr;

	write_lock_irq(&ploop->bat_rwlock);
	ploop_for_each_md_page(ploop, md, node) {
		init_bat_entries_iter(ploop, md->id, &i, &end);
		bat_entries = kmap_atomic(md->page);
		for (; i <= end; i++) {
			if (md_page_cluster_is_in_top_delta(ploop, md, i) ||
			    delta_bat_entries[i] == BAT_ENTRY_NONE ||
			    md->bat_levels[i] < level)
				continue;

			/* deltas above @level become renumbered */
			if (md->bat_levels[i] > level) {
				md->bat_levels[i]--;
				continue;
			}

			/*
			 * clusters from deltas of @level become pointing to
			 * 1)next delta (which became renumbered) or
			 * 2)prev delta (if !@forward).
			 */
			bat_entries[i] = delta_bat_entries[i];
			WARN_ON(bat_entries[i] == BAT_ENTRY_NONE);
			if (!forward)
				md->bat_levels[i]--;
		}
		kunmap_atomic(bat_entries);
		delta_bat_entries += PAGE_SIZE / sizeof(map_index_t);
	}

	file = ploop->deltas[level].file;
	/* Renumber deltas above @level */
	for (i = level + 1; i < ploop->nr_deltas; i++)
		ploop->deltas[i - 1] = ploop->deltas[i];
	ploop->deltas[--ploop->nr_deltas].file = NULL;
	write_unlock_irq(&ploop->bat_rwlock);
	fput(file);
}

static int process_update_delta_index(struct ploop *ploop, u8 level,
				      const char *map)
{
	unsigned int cluster, dst_cluster, n;
	int ret;

	write_lock_irq(&ploop->bat_rwlock);
	/* Check all */
	while (sscanf(map, "%u:%u;%n", &cluster, &dst_cluster, &n) == 2) {
		if (cluster >= ploop->nr_bat_entries)
			break;
		if (ploop_bat_entries(ploop, cluster, NULL) == BAT_ENTRY_NONE)
			break;
		map += n;
	}
	if (map[0] != '\0') {
		ret = -EINVAL;
		goto unlock;
	}
	/* Commit all */
	while (sscanf(map, "%u:%u;%n", &cluster, &dst_cluster, &n) == 2) {
		try_update_bat_entry(ploop, cluster, level, dst_cluster);
		map += n;
	}
	ret = 0;
unlock:
	write_unlock_irq(&ploop->bat_rwlock);
	return ret;
}

static int ploop_delta_clusters_merged(struct ploop *ploop, u8 level,
				       bool forward)
{
	void *d_hdr = NULL;
	struct file *file;
	int ret;

	/* Reread BAT of deltas[@level + 1] (or [@level - 1]) */
	file = ploop->deltas[level + forward ? 1 : -1].file;

	ret = ploop_read_delta_metadata(ploop, file, &d_hdr);
	if (ret)
		goto out;

	ret = ploop_suspend_submitting_pios(ploop);
	if (ret)
		goto out;

	notify_delta_merged(ploop, level, d_hdr, forward);

	ploop_resume_submitting_pios(ploop);
	ret = 0;
out:
	vfree(d_hdr);
	return ret;
}

static int ploop_notify_merged(struct ploop *ploop, u8 level, bool forward)
{
	if (ploop->maintaince)
		return -EBUSY;
	if (level >= top_level(ploop))
		return -ENOENT;
	if (level == 0 && !forward)
		return -EINVAL;
	if (level == top_level(ploop) - 1 && forward)
		return -EINVAL;
	if (ploop->nr_deltas < 3)
		return -EINVAL;
	/*
	 * Userspace notifies us, it has copied clusters of
	 * ploop->deltas[@level] to ploop->deltas[@level + 1]
	 * (deltas[@level] to deltas[@level - 1] if !@forward).
	 * Now we want to update our bat_entries/levels arrays,
	 * where ploop->deltas[@level] is used currently, to use
	 * @level + 1 instead. Also we want to put @level's file,
	 * and renumerate deltas.
	 */
	return ploop_delta_clusters_merged(ploop, level, forward);
}

static int ploop_get_delta_name_cmd(struct ploop *ploop, u8 level,
				char *result, unsigned int maxlen)
{
	struct file *file;
	int len, ret = 1;
	char *p;

	if (level >= ploop->nr_deltas) {
		result[0] = '\0';
		goto out;
	}

	/*
	 * Nobody can change deltas in parallel, since
	 * another cmds are prohibited, but do this
	 * for uniformity.
	 */
	read_lock_irq(&ploop->bat_rwlock);
	file = get_file(ploop->deltas[level].file);
	read_unlock_irq(&ploop->bat_rwlock);

	p = file_path(file, result, maxlen);
	if (p == ERR_PTR(-ENAMETOOLONG)) {
		/* Notify target_message(), there is not enough space */
		memset(result, 'x', maxlen - 1);
		result[maxlen - 1] = 0;
	} else if (IS_ERR_OR_NULL(p)) {
		ret = PTR_ERR(p);
	} else {
		len = strlen(p);
		memmove(result, p, len);
		result[len] = '\n';
		result[len + 1] = '\0';
	}

	fput(file);
out:
	return ret;
}

static int ploop_update_delta_index(struct ploop *ploop, unsigned int level,
				    const char *map)
{
	int ret;

	if (ploop->maintaince)
		return -EBUSY;
	if (level >= top_level(ploop))
		return -ENOENT;

	ret = ploop_suspend_submitting_pios(ploop);
	if (ret)
		goto out;

	ret = process_update_delta_index(ploop, level, map);

	ploop_resume_submitting_pios(ploop);
out:
	return ret;
}

static int process_flip_upper_deltas(struct ploop *ploop)
{
	unsigned int i, size, end, bat_clusters, hb_nr, *bat_entries;
	void *holes_bitmap = ploop->holes_bitmap;
	u8 level = top_level(ploop) - 1;
	struct rb_node *node;
	struct md_page *md;

	size = (PLOOP_MAP_OFFSET + ploop->nr_bat_entries) * sizeof(map_index_t);
        bat_clusters = DIV_ROUND_UP(size, CLU_SIZE(ploop));
	hb_nr = ploop->hb_nr;

	write_lock_irq(&ploop->bat_rwlock);
	/* Prepare holes_bitmap */
	memset(holes_bitmap, 0xff, hb_nr/8);
	for (i = (hb_nr & ~0x7); i < hb_nr; i++)
		set_bit(i, holes_bitmap);
	for (i = 0; i < bat_clusters; i++)
		clear_bit(i, holes_bitmap);

	/* Flip bat entries */
	ploop_for_each_md_page(ploop, md, node) {
		init_bat_entries_iter(ploop, md->id, &i, &end);
		bat_entries = kmap_atomic(md->page);
		for (; i <= end; i++) {
			if (bat_entries[i] == BAT_ENTRY_NONE)
				continue;
			if (md->bat_levels[i] == level) {
				md->bat_levels[i] = top_level(ploop);
				clear_bit(bat_entries[i], holes_bitmap);
			} else if (md->bat_levels[i] == top_level(ploop)) {
				md->bat_levels[i] = level;
			}
		}
		kunmap_atomic(bat_entries);
	}

	/* FIXME */
	swap(ploop->deltas[level], ploop->deltas[level+1]);
	write_unlock_irq(&ploop->bat_rwlock);
	return 0;
}

static int process_tracking_start(struct ploop *ploop, void *tracking_bitmap,
				  u32 tb_nr)
{
	unsigned int i, nr_pages, end, *bat_entries, dst_cluster, nr;
	struct rb_node *node;
	struct md_page *md;
	int ret = 0;

	write_lock_irq(&ploop->bat_rwlock);
	ploop->tracking_bitmap = tracking_bitmap;
	ploop->tb_nr = tb_nr;

	for_each_clear_bit(i, ploop->holes_bitmap, ploop->hb_nr)
		set_bit(i, tracking_bitmap);
	nr_pages = bat_clu_to_page_nr(ploop->nr_bat_entries - 1) + 1;
	nr = 0;

	ploop_for_each_md_page(ploop, md, node) {
		init_bat_entries_iter(ploop, md->id, &i, &end);
		bat_entries = kmap_atomic(md->page);
		for (; i <= end; i++) {
			dst_cluster = bat_entries[i];
			if (dst_cluster == BAT_ENTRY_NONE ||
			    md->bat_levels[i] != top_level(ploop))
				continue;
			if (WARN_ON(dst_cluster >= tb_nr)) {
				ret = -EIO;
				break;
			}
			set_bit(dst_cluster, tracking_bitmap);
		}
		kunmap_atomic(bat_entries);
		if (ret)
			break;
		nr++;
	}
	write_unlock_irq(&ploop->bat_rwlock);

	BUG_ON(ret == 0 && nr != nr_pages);
	return ret;
}

static int tracking_get_next(struct ploop *ploop, char *result,
			     unsigned int maxlen)
{
	unsigned int i, sz = 0, tb_nr = ploop->tb_nr, prev = ploop->tb_cursor;
	void *tracking_bitmap = ploop->tracking_bitmap;
	int ret = -EAGAIN;

	if (WARN_ON_ONCE(prev > tb_nr - 1))
		prev = 0;

	write_lock_irq(&ploop->bat_rwlock);
	i = find_next_bit(tracking_bitmap, tb_nr, prev + 1);
	if (i < tb_nr)
		goto found;
	i = find_first_bit(tracking_bitmap, prev + 1);
	if (i >= prev + 1)
		goto unlock;
found:
	ret = (DMEMIT("%u\n", i)) ? 1 : 0;
	if (ret)
		clear_bit(i, tracking_bitmap);
unlock:
	write_unlock_irq(&ploop->bat_rwlock);
	if (ret > 0)
		ploop->tb_cursor = i;
	return ret;
}

static unsigned int max_dst_cluster_in_top_delta(struct ploop *ploop)
{
	unsigned int i, nr_pages, nr = 0, end, *bat_entries, dst_cluster = 0;
	struct rb_node *node;
	struct md_page *md;

	nr_pages = bat_clu_to_page_nr(ploop->nr_bat_entries - 1) + 1;

	read_lock_irq(&ploop->bat_rwlock);
	ploop_for_each_md_page(ploop, md, node) {
		init_bat_entries_iter(ploop, md->id, &i, &end);
		bat_entries = kmap_atomic(md->page);
		for (; i <= end; i++) {
			if (dst_cluster < bat_entries[i] &&
			    md->bat_levels[i] == top_level(ploop))
				dst_cluster = bat_entries[i];
		}
		kunmap_atomic(bat_entries);
		nr++;
	}
	read_unlock_irq(&ploop->bat_rwlock);

	BUG_ON(nr != nr_pages);
	return dst_cluster;
}

static int ploop_tracking_cmd(struct ploop *ploop, const char *suffix,
			      char *result, unsigned int maxlen)
{
	void *tracking_bitmap = NULL;
	unsigned int tb_nr, size;
	int ret = 0;

	if (ploop_is_ro(ploop))
		return -EROFS;

	if (!strcmp(suffix, "get_next")) {
		if (!ploop->tracking_bitmap)
			return -ENOENT;
		return tracking_get_next(ploop, result, maxlen);
	}

	if (!strcmp(suffix, "start")) {
		if (ploop->tracking_bitmap)
			return -EEXIST;
		if (ploop->maintaince)
			return -EBUSY;
		/* max_dst_cluster_in_top_delta() may be above hb_nr */
		tb_nr = max_dst_cluster_in_top_delta(ploop) + 1;
		if (tb_nr < ploop->hb_nr)
			tb_nr = ploop->hb_nr;
		/*
		 * After max_dst_cluster_in_top_delta() unlocks the lock,
		 * new entries above tb_nr can't occur, since we always
		 * alloc clusters from holes_bitmap (and they nr < hb_nr).
		 */
		size = DIV_ROUND_UP(tb_nr, 8 * sizeof(unsigned long));
		size *= sizeof(unsigned long);
		tracking_bitmap = kvzalloc(size, GFP_KERNEL);
		if (!tracking_bitmap)
			return -ENOMEM;
		ploop->tb_cursor = tb_nr - 1;

		ret = ploop_suspend_submitting_pios(ploop);
		if (ret)
			return ret;

		ploop->maintaince = true;
		ret = process_tracking_start(ploop, tracking_bitmap, tb_nr);

		ploop_resume_submitting_pios(ploop);

		if (ret)
			goto stop;
	} else if (!strcmp(suffix, "stop")) {
		if (!ploop->tracking_bitmap)
			return -ENOENT;
stop:
		write_lock_irq(&ploop->bat_rwlock);
		kvfree(ploop->tracking_bitmap);
		ploop->tracking_bitmap = NULL;
		write_unlock_irq(&ploop->bat_rwlock);
		ploop->maintaince = false;
	} else {
		return -EINVAL;
	}

	return ret;
}

static int ploop_set_noresume(struct ploop *ploop, char *mode)
{
	bool noresume;

	if (!strcmp(mode, "1"))
		noresume = true;
	else if (!strcmp(mode, "0"))
		noresume = false;
	else
		return -EINVAL;

	if (noresume == ploop->noresume)
		return -EBUSY;

	ploop->noresume = noresume;
	return 0;
}

static int ploop_flip_upper_deltas(struct ploop *ploop)
{
	struct file *file;

	if (!ploop->suspended || !ploop->noresume || ploop->maintaince)
		return -EBUSY;
	if (ploop_is_ro(ploop))
		return -EROFS;
	if (ploop->nr_deltas < 2)
		return -ENOENT;
	if (ploop->deltas[ploop->nr_deltas - 2].is_raw)
		return -EBADSLT;
	file = ploop->deltas[ploop->nr_deltas - 2].file;
        if (!(file->f_mode & FMODE_WRITE))
		return -EACCES;

	return process_flip_upper_deltas(ploop);
}

/* Handle user commands requested via "message" interface */
void process_deferred_cmd(struct ploop *ploop)
	__releases(&ploop->deferred_lock)
	__acquires(&ploop->deferred_lock)
{
	struct ploop_cmd *cmd = ploop->deferred_cmd;

	if (likely(!cmd))
		return;

	ploop->deferred_cmd = NULL;
	spin_unlock_irq(&ploop->deferred_lock);

	if (cmd->type == PLOOP_CMD_MERGE_SNAPSHOT) {
		process_merge_latest_snapshot_cmd(ploop, cmd);
	} else {
		cmd->retval = -EINVAL;
		complete(&cmd->comp);
	}
	spin_lock_irq(&ploop->deferred_lock);
}

static int ploop_get_event(struct ploop *ploop, char *result, unsigned int maxlen)
{
	unsigned int sz = 0;
	int ret = 0;

	spin_lock_irq(&ploop->deferred_lock);
	if (ploop->event_enospc) {
		ret = (DMEMIT("event_ENOSPC\n")) ? 1 : 0;
		if (ret)
			ploop->event_enospc = false;
	}
	spin_unlock_irq(&ploop->deferred_lock);

	return ret;
}

static bool msg_wants_down_read(const char *cmd)
{
	/* TODO: kill get_delta_name */
	if (!strcmp(cmd, "get_delta_name") ||
	    !strcmp(cmd, "get_img_name"))
		return true;

	return false;
}

int ploop_message(struct dm_target *ti, unsigned int argc, char **argv,
		  char *result, unsigned int maxlen)
{
	struct ploop *ploop = ti->private;
	bool read, forward = true;
	int ret = -EPERM;
	u64 val;

	if (!capable(CAP_SYS_ADMIN))
		goto out;

	ret = -EINVAL;
	if (argc < 1)
		goto out;

	if (!strcmp(argv[0], "get_event")) {
		if (argc == 1)
			ret = ploop_get_event(ploop, result, maxlen);
		goto out;
	}

	read = msg_wants_down_read(argv[0]);
	if (read)
		down_read(&ploop->ctl_rwsem);
	else
		down_write(&ploop->ctl_rwsem);

	if (!strcmp(argv[0], "resize")) {
		if (argc != 2 || kstrtou64(argv[1], 10, &val) < 0)
			goto unlock;
		ret = ploop_resize(ploop, val);
	} else if (!strcmp(argv[0], "merge")) {
		if (argc == 1)
			ret = ploop_merge_latest_snapshot(ploop);
	} else if (!strncmp(argv[0], "notify_merged_", 14)) {
		if (!strcmp(&argv[0][14], "backward"))
			forward = false;
		else if (strcmp(&argv[0][14], "forward"))
			goto unlock;
		if (argc != 2 || kstrtou64(argv[1], 10, &val) < 0)
			goto unlock;
		ret = ploop_notify_merged(ploop, val, forward);
	} else if (!strcmp(argv[0], "get_delta_name") ||
		   !strcmp(argv[0], "get_img_name")) {
		if (argc != 2 || kstrtou64(argv[1], 10, &val) < 0)
			goto unlock;
		ret = ploop_get_delta_name_cmd(ploop, (u8)val, result, maxlen);
	} else if (!strcmp(argv[0], "update_delta_index")) {
		if (argc != 3 || kstrtou64(argv[1], 10, &val) < 0)
			goto unlock;
		ret = ploop_update_delta_index(ploop, val, argv[2]);
	} else if (!strncmp(argv[0], "tracking_", 9)) {
		if (argc != 1)
			goto unlock;
		ret = ploop_tracking_cmd(ploop, argv[0] + 9, result, maxlen);
	} else if (!strcmp(argv[0], "set_noresume")) {
		if (argc != 2)
			goto unlock;
		ret = ploop_set_noresume(ploop, argv[1]);
	} else if (!strcmp(argv[0], "flip_upper_deltas")) {
		if (argc != 1)
			goto unlock;
		ret = ploop_flip_upper_deltas(ploop);
	} else {
		ret = -ENOTSUPP;
	}

unlock:
	if (read)
		up_read(&ploop->ctl_rwsem);
	else
		up_write(&ploop->ctl_rwsem);
out:
	return ret;
}
