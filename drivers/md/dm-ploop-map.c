/*
 *  drivers/md/dm-ploop-map.c
 *
 *  Copyright (c) 2020-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/buffer_head.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/sched/mm.h>
#include <linux/cgroup.h>
#include <linux/blk-cgroup.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/uio.h>
#include <linux/blk-mq.h>
#include <uapi/linux/falloc.h>
#include "dm-ploop.h"
#include "dm-rq.h"

#define PREALLOC_SIZE (128ULL * 1024 * 1024)

static void ploop_handle_cleanup(struct ploop *ploop, struct pio *pio);
static void ploop_prq_endio(struct pio *pio, void *prq_ptr,
			    blk_status_t bi_status);

#define DM_MSG_PREFIX "ploop"

static unsigned int ploop_pio_nr_segs(struct pio *pio)
{
	struct bvec_iter bi = {
		.bi_size = pio->bi_iter.bi_size,
		.bi_bvec_done = pio->bi_iter.bi_bvec_done,
		.bi_idx = pio->bi_iter.bi_idx,
	};
	unsigned int nr_segs = 0;
	struct bio_vec bv;

	for_each_bvec(bv, pio->bi_io_vec, bi, bi)
                nr_segs++;

        return nr_segs;
}

static sector_t ploop_rq_pos(struct ploop *ploop, struct request *rq)
{
	return blk_rq_pos(rq) + ploop->skip_off;
}

void ploop_index_wb_init(struct ploop_index_wb *piwb, struct ploop *ploop)
{
	piwb->ploop = ploop;
	piwb->comp = NULL;
	piwb->comp_bi_status = NULL;
	spin_lock_init(&piwb->lock);
	piwb->md = NULL;
	piwb->bat_page = NULL;
	piwb->bi_status = 0;
	INIT_LIST_HEAD(&piwb->ready_data_pios);
	INIT_LIST_HEAD(&piwb->cow_list);
	/* For ploop_bat_write_complete() */
	atomic_set(&piwb->count, 1);
	piwb->completed = false;
	piwb->page_id = PAGE_NR_NONE;
	piwb->type = PIWB_TYPE_ALLOC;
}

void ploop_init_pio(struct ploop *ploop, unsigned int bi_op, struct pio *pio)
{
	pio->ploop = ploop;
	pio->css = NULL;
	pio->bi_op = bi_op;
	pio->wants_discard_index_cleanup = false;
	pio->is_data_alloc = false;
	pio->is_fake_merge = false;
	pio->free_on_endio = false;
	pio->ref_index = PLOOP_REF_INDEX_INVALID;
	pio->queue_list_id = PLOOP_LIST_DEFERRED;
	pio->bi_status = BLK_STS_OK;
	atomic_set(&pio->remaining, 1);
	pio->piwb = NULL;
	INIT_LIST_HEAD(&pio->list);
	INIT_HLIST_NODE(&pio->hlist_node);
	INIT_LIST_HEAD(&pio->endio_list);
	/* FIXME: assign real clu? */
	pio->clu = UINT_MAX;
	pio->level = BAT_LEVEL_INVALID;
}

/* Check that rq end byte is not behind end of device */
static int ploop_rq_valid(struct ploop *ploop, struct request *rq)
{
	sector_t sector = ploop_rq_pos(ploop, rq);
	loff_t end_byte;
	u32 end_clu;

	end_byte = to_bytes(sector) + blk_rq_bytes(rq) - 1;
	end_clu = POS_TO_CLU(ploop, end_byte);

	if (unlikely(end_clu >= ploop->nr_bat_entries)) {
		/*
		 * This mustn't happen, since we set max_io_len
		 * via dm_set_target_max_io_len().
		 */
		WARN_ONCE(1, "sec=%llu, size=%u, end_clu=%u, nr=%u\n",
			  sector, blk_rq_bytes(rq),
			  end_clu, ploop->nr_bat_entries);
		return -EINVAL;
	}

	return 0;
}

static void ploop_init_prq(struct ploop_rq *prq, struct request *rq)
{
	prq->rq = rq;
	prq->bvec = NULL;
	prq->css = NULL;
#ifdef CONFIG_BLK_CGROUP
	if (rq->bio && rq->bio->bi_blkg) {
		prq->css = bio_blkcg_css(rq->bio);
		css_get(prq->css); /* css_put is in prq_endio */
	}
#endif
}

static void ploop_init_prq_and_embedded_pio(struct ploop *ploop,
		struct request *rq, struct ploop_rq *prq, struct pio *pio)
{
	ploop_init_prq(prq, rq);
	ploop_init_pio(ploop, req_op(rq), pio);
	pio->css = prq->css;

	pio->endio_cb = ploop_prq_endio;
	pio->endio_cb_data = prq;
}

void ploop_enospc_timer(struct timer_list *timer)
{
	struct ploop *ploop = from_timer(ploop, timer, enospc_timer);
	unsigned long flags;
	LIST_HEAD(list);

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	list_splice_init(&ploop->enospc_pios, &list);
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	ploop_submit_embedded_pios(ploop, &list);
}

void do_ploop_event_work(struct work_struct *ws)
{
	struct ploop *ploop = container_of(ws, struct ploop, event_work);

	dm_table_event(ploop->ti->table);
}

static bool ploop_try_delay_enospc(struct ploop_rq *prq, struct pio *pio)
{
	struct ploop *ploop = pio->ploop;
	bool delayed = true;
	unsigned long flags;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	if (unlikely(ploop->wants_suspend)) {
		delayed = false;
		goto unlock;
	}

	ploop_init_prq_and_embedded_pio(ploop, prq->rq, prq, pio);

	pr_err_once("ploop: underlying disk is almost full\n");
	ploop->event_enospc = true;
	list_add_tail(&pio->list, &ploop->enospc_pios);
unlock:
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	if (delayed)
		mod_timer(&ploop->enospc_timer, jiffies + PLOOP_ENOSPC_TIMEOUT);
	schedule_work(&ploop->event_work);

	return delayed;
}

static void ploop_prq_endio(struct pio *pio, void *prq_ptr,
			    blk_status_t bi_status)
{
	struct ploop_rq *prq = prq_ptr;
	struct request *rq = prq->rq;

	if (prq->bvec)
		kfree(prq->bvec);
	if (prq->css)
		css_put(prq->css);
	/*
	 * Here is exit point for rq, and here we handle ENOSPC.
	 * Embedded pios will be reinitialized like they've just
	 * came from upper dm level, and later resubmitted after
	 * timeout. Note, that we do not handle merge here: merge
	 * callers receive -ENOSPC synchronous without intermediaries.
	 */
	if (unlikely(bi_status == BLK_STS_NOSPC)) {
		WARN_ON_ONCE(!op_is_write(pio->bi_op));
		if (ploop_try_delay_enospc(prq, pio))
			return;
	}

	mempool_free(prq, pio->ploop->prq_pool);
	dm_complete_request(rq, bi_status);
}

static void ploop_do_pio_endio(struct pio *pio)
{
	ploop_endio_t endio_cb = pio->endio_cb;
	void *endio_cb_data = pio->endio_cb_data;
	bool free_on_endio = pio->free_on_endio;

	if (!atomic_dec_and_test(&pio->remaining))
		return;

	endio_cb(pio, endio_cb_data, pio->bi_status);

	if (free_on_endio)
		ploop_free_pio(pio->ploop, pio);
}

void ploop_pio_endio(struct pio *pio)
{
	struct ploop *ploop = pio->ploop;

	ploop_handle_cleanup(ploop, pio);

	ploop_do_pio_endio(pio);
}

static void ploop_pio_chain_endio(struct pio *pio, void *parent_ptr,
				  blk_status_t bi_status)
{
	struct pio *parent = parent_ptr;

	if (unlikely(bi_status))
		parent->bi_status = bi_status;

	ploop_do_pio_endio(parent);
}

static void ploop_pio_chain(struct pio *pio, struct pio *parent)
{
	BUG_ON(pio->endio_cb_data || pio->endio_cb);

	pio->endio_cb_data = parent;
	pio->endio_cb = ploop_pio_chain_endio;
	atomic_inc(&parent->remaining);
}

/* Clone of bio_advance_iter() */
static void ploop_pio_advance(struct pio *pio, unsigned int bytes)
{
	struct bvec_iter *iter = &pio->bi_iter;

	iter->bi_sector += bytes >> 9;

	if (op_is_discard(pio->bi_op))
		iter->bi_size -= bytes;
	else
		bvec_iter_advance(pio->bi_io_vec, iter, bytes);
}

static struct pio *ploop_split_and_chain_pio(struct ploop *ploop,
		struct pio *pio, u32 len)
{
	struct pio *split;

	split = ploop_alloc_pio(ploop, GFP_NOIO);
	if (!split)
		return NULL;

	ploop_init_pio(ploop, pio->bi_op, split);
	split->css = pio->css;
	split->queue_list_id = pio->queue_list_id;
	split->free_on_endio = true;
	split->bi_io_vec = pio->bi_io_vec;
	split->bi_iter = pio->bi_iter;
	split->bi_iter.bi_size = len;
	split->endio_cb = NULL;
	split->endio_cb_data = NULL;
	ploop_pio_chain(split, pio);
	if (len)
		ploop_pio_advance(pio, len);
	return split;
}

static int ploop_split_pio_to_list(struct ploop *ploop, struct pio *pio,
			     struct list_head *ret_list)
{
	u32 clu_size = CLU_SIZE(ploop);
	struct pio *split;
	LIST_HEAD(list);

	while (1) {
		loff_t start = to_bytes(pio->bi_iter.bi_sector);
		loff_t end = start + pio->bi_iter.bi_size;
		unsigned int len;

		WARN_ON_ONCE(start == end);

		if (start / clu_size == (end - 1) / clu_size)
			break;
		end = round_up(start + 1, clu_size);
		len = end - start;

		split = ploop_split_and_chain_pio(ploop, pio, len);
		if (!split)
			goto err;

		list_add_tail(&split->list, &list);
	}

	list_splice_tail(&list, ret_list);
	list_add_tail(&pio->list, ret_list);
	return 0;
err:
	while ((pio = ploop_pio_list_pop(&list)) != NULL) {
		pio->bi_status = BLK_STS_RESOURCE;
		ploop_pio_endio(pio);
	}
	return -ENOMEM;
}

static void ploop_dispatch_pio(struct ploop *ploop, struct pio *pio,
			       bool *is_data, bool *is_flush)
{
	struct list_head *list = &ploop->pios[pio->queue_list_id];

	lockdep_assert_held(&ploop->deferred_lock);
	WARN_ON_ONCE(pio->queue_list_id >= PLOOP_LIST_COUNT);

	if (pio->queue_list_id == PLOOP_LIST_FLUSH)
		*is_flush = true;
	else
		*is_data = true;

	list_add_tail(&pio->list, list);
}

void ploop_dispatch_pios(struct ploop *ploop, struct pio *pio,
			 struct list_head *pio_list)
{
	bool is_data = false, is_flush = false;
	unsigned long flags;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	if (pio)
		ploop_dispatch_pio(ploop, pio, &is_data, &is_flush);
	if (pio_list) {
		while ((pio = ploop_pio_list_pop(pio_list)) != NULL)
			ploop_dispatch_pio(ploop, pio, &is_data, &is_flush);
	}
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	if (is_data)
		queue_work(ploop->wq, &ploop->worker);
	if (is_flush)
		queue_work(ploop->wq, &ploop->fsync_worker);
}

static bool ploop_delay_if_md_busy(struct ploop *ploop, struct md_page *md,
				   enum piwb_type type, struct pio *pio)
{
	struct ploop_index_wb *piwb;
	unsigned long flags;
	bool busy = false;

	WARN_ON_ONCE(!list_empty(&pio->list));

	write_lock_irqsave(&ploop->bat_rwlock, flags);
	piwb = md->piwb;
	if (piwb && (piwb->type != type || (md->status & MD_WRITEBACK))) {
		list_add_tail(&pio->list, &md->wait_list);
		busy = true;
	}
	write_unlock_irqrestore(&ploop->bat_rwlock, flags);

	return busy;
}

static void ploop_queue_discard_index_wb(struct ploop *ploop, struct pio *pio)
{
	pio->queue_list_id = PLOOP_LIST_DISCARD;
	ploop_dispatch_pios(ploop, pio, NULL);
}

/* Zero @count bytes of @qio->bi_io_vec since @from byte */
static void ploop_zero_fill_pio(struct pio *pio)
{
	struct bvec_iter bi = {
		.bi_size = pio->bi_iter.bi_size,
		.bi_bvec_done = pio->bi_iter.bi_bvec_done,
		.bi_idx = pio->bi_iter.bi_idx,
	};
	struct bio_vec bv;
	void *data;

	for_each_bvec(bv, pio->bi_io_vec, bi, bi) {
		if (!bv.bv_len)
			continue;
		data = kmap(bv.bv_page);
		memset(data + bv.bv_offset, 0, bv.bv_len);
		kunmap(bv.bv_page);
	}
}

struct pio *ploop_find_pio(struct hlist_head head[], u32 clu)
{
	struct hlist_head *slot = ploop_htable_slot(head, clu);
	struct pio *pio;

	BUG_ON(!slot);

	hlist_for_each_entry(pio, slot, hlist_node) {
		if (pio->clu == clu)
			return pio;
	}

	return NULL;
}

static struct pio *ploop_find_inflight_bio(struct ploop *ploop, u32 clu)
{
	lockdep_assert_held(&ploop->inflight_lock);
	return ploop_find_pio(ploop->inflight_pios, clu);
}

struct pio *ploop_find_lk_of_cluster(struct ploop *ploop, u32 clu)
{
	lockdep_assert_held(&ploop->deferred_lock);
	return ploop_find_pio(ploop->exclusive_pios, clu);
}

static void ploop_add_endio_pio(struct pio *head, struct pio *pio)
{
	list_add_tail(&pio->list, &head->endio_list);
}

static void ploop_inc_nr_inflight(struct ploop *ploop, struct pio *pio)
{
	unsigned char ref_index = ploop->inflight_bios_ref_index;

	if (!WARN_ON_ONCE(pio->ref_index != PLOOP_REF_INDEX_INVALID)) {
		percpu_ref_get(&ploop->inflight_bios_ref[ref_index]);
		pio->ref_index = ref_index;
	}
}

static void ploop_dec_nr_inflight(struct ploop *ploop, struct pio *pio)
{
	if (pio->ref_index != PLOOP_REF_INDEX_INVALID) {
		percpu_ref_put(&ploop->inflight_bios_ref[pio->ref_index]);
		pio->ref_index = PLOOP_REF_INDEX_INVALID;
	}
}

static void ploop_link_pio(struct hlist_head head[], struct pio *pio,
		     u32 clu, bool exclusive)
{
	struct hlist_head *slot = ploop_htable_slot(head, clu);

	if (exclusive)
		WARN_ON_ONCE(ploop_find_pio(head, clu) != NULL);

	BUG_ON(!hlist_unhashed(&pio->hlist_node));
	hlist_add_head(&pio->hlist_node, slot);
	pio->clu = clu;
}

/*
 * Removes @pio of completed bio either from inflight_pios_rbtree
 * or from exclusive_bios_rbtree. BIOs from endio_list are requeued
 * to deferred_list.
 */
static void ploop_unlink_pio(struct ploop *ploop, struct pio *pio,
		       struct list_head *pio_list)
{
	BUG_ON(hlist_unhashed(&pio->hlist_node));

	hlist_del_init(&pio->hlist_node);
	list_splice_tail_init(&pio->endio_list, pio_list);
}

static void ploop_add_cluster_lk(struct ploop *ploop, struct pio *pio, u32 clu)
{
	unsigned long flags;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	ploop_link_pio(ploop->exclusive_pios, pio, clu, true);
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);
}

static void ploop_del_cluster_lk(struct ploop *ploop, struct pio *pio)
{
	LIST_HEAD(pio_list);
	unsigned long flags;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	ploop_unlink_pio(ploop, pio, &pio_list);
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	if (!list_empty(&pio_list))
		ploop_dispatch_pios(ploop, NULL, &pio_list);
}

static void ploop_link_submitting_pio(struct ploop *ploop, struct pio *pio,
				      u32 clu)
{
	unsigned long flags;

	spin_lock_irqsave(&ploop->inflight_lock, flags);
	ploop_link_pio(ploop->inflight_pios, pio, clu, false);
	spin_unlock_irqrestore(&ploop->inflight_lock, flags);
}

static void ploop_unlink_completed_pio(struct ploop *ploop, struct pio *pio)
{
	LIST_HEAD(pio_list);
	unsigned long flags;

	if (hlist_unhashed(&pio->hlist_node))
		return;

	spin_lock_irqsave(&ploop->inflight_lock, flags);
	ploop_unlink_pio(ploop, pio, &pio_list);
	spin_unlock_irqrestore(&ploop->inflight_lock, flags);

	if (!list_empty(&pio_list))
		ploop_dispatch_pios(ploop, NULL, &pio_list);
}

static bool ploop_md_make_dirty(struct ploop *ploop, struct md_page *md)
{
	unsigned long flags;
	bool new = false;

	write_lock_irqsave(&ploop->bat_rwlock, flags);
	WARN_ON_ONCE((md->status & MD_WRITEBACK));
	if (!(md->status & MD_DIRTY)) {
		md->status |= MD_DIRTY;
		list_add_tail(&md->wb_link, &ploop->wb_batch_list);
		new = true;
	}
	write_unlock_irqrestore(&ploop->bat_rwlock, flags);

	return new;
}

static bool ploop_pio_endio_if_all_zeros(struct pio *pio)
{
	struct bvec_iter bi = {
		.bi_size = pio->bi_iter.bi_size,
		.bi_bvec_done = pio->bi_iter.bi_bvec_done,
		.bi_idx = pio->bi_iter.bi_idx,
	};
	struct bio_vec bv;
	void *data, *ret;

	for_each_bvec(bv, pio->bi_io_vec, bi, bi) {
		if (!bv.bv_len)
			continue;
		data = kmap(bv.bv_page);
		ret = memchr_inv(data + bv.bv_offset, 0, bv.bv_len);
		kunmap(bv.bv_page);
		if (ret)
			return false;
	}

	ploop_pio_endio(pio);
	return true;
}

static bool ploop_pio_endio_if_merge_fake_pio(struct pio *pio)
{
	if (likely(!ploop_fake_merge_pio(pio)))
		return false;
	ploop_pio_endio(pio);
	return true;
}

static int ploop_punch_hole(struct file *file, loff_t pos, loff_t len)
{
	return vfs_fallocate(file, FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE,
			     pos, len);
}

static int ploop_zero_range(struct file *file, loff_t pos, loff_t len)
{
	return vfs_fallocate(file, FALLOC_FL_ZERO_RANGE|FALLOC_FL_KEEP_SIZE,
			     pos, len);
}

static void ploop_handle_discard_pio(struct ploop *ploop, struct pio *pio,
			       u32 clu, u32 dst_clu)
{
	struct pio *inflight_h;
	unsigned long flags;
	loff_t pos;
	int ret;

	if (!ploop_whole_cluster(ploop, pio)) {
		/*
		 * Despite discard_granularity is given, block level
		 * may submit shorter reqs. E.g., these are boundary
		 * bios around trimed continuous hunk. For discard
		 * it's OK to just ignore such reqs. Keep in mind
		 * this implementing REQ_OP_WRITE_ZEROES etc.
		 */
		ploop_pio_endio(pio);
		return;
	}

	if (!ploop_cluster_is_in_top_delta(ploop, clu)) {
		ploop_pio_endio(pio);
		return;
	}

	/* We can't end with EOPNOTSUPP, since blk-mq prints error */
	if (ploop->nr_deltas != 1)
		goto punch_hole;

	spin_lock_irqsave(&ploop->inflight_lock, flags);
	inflight_h = ploop_find_inflight_bio(ploop, clu);
	if (inflight_h)
		ploop_add_endio_pio(inflight_h, pio);
	spin_unlock_irqrestore(&ploop->inflight_lock, flags);

	if (inflight_h) {
		/* @pio will be requeued on inflight_h's pio end */
		pr_err_once("ploop: delayed discard: device is used as raw?\n");
		return;
	}

	ploop_add_cluster_lk(ploop, pio, clu);
	pio->wants_discard_index_cleanup = true;

punch_hole:
	ploop_remap_to_cluster(ploop, pio, dst_clu);
	pos = to_bytes(pio->bi_iter.bi_sector);
	ret = ploop_punch_hole(ploop_top_delta(ploop)->file, pos,
			       pio->bi_iter.bi_size);
	if (ret || ploop->nr_deltas != 1) {
		if (ret)
			pio->bi_status = errno_to_blk_status(ret);
		ploop_pio_endio(pio);
		return;
	}

	ploop_queue_discard_index_wb(ploop, pio);
}

static void ploop_discard_index_pio_end(struct ploop *ploop, struct pio *pio)
{
	ploop_del_cluster_lk(ploop, pio);
}

static void ploop_queue_or_fail(struct ploop *ploop, int err, void *data)
{
	struct pio *pio = data;

	/* FIXME: do we use BLK_STS_AGAIN? */
	if (err && err != BLK_STS_AGAIN) {
		pio->bi_status = errno_to_blk_status(err);
		ploop_pio_endio(pio);
	} else {
		ploop_dispatch_pios(ploop, pio, NULL);
	}
}

static void ploop_complete_cow(struct ploop_cow *cow, blk_status_t bi_status)
{
	struct pio *aux_pio = cow->aux_pio;
	struct ploop *ploop = cow->ploop;
	u32 dst_clu = cow->dst_clu;
	unsigned long flags;
	struct pio *cow_pio;

	WARN_ON_ONCE(!list_empty(&aux_pio->list));
	cow_pio = cow->cow_pio;

	ploop_del_cluster_lk(ploop, cow_pio);

	if (dst_clu != BAT_ENTRY_NONE && bi_status != BLK_STS_OK) {
		read_lock_irqsave(&ploop->bat_rwlock, flags);
		ploop_hole_set_bit(dst_clu, ploop);
		read_unlock_irqrestore(&ploop->bat_rwlock, flags);
	}

	ploop_queue_or_fail(ploop, blk_status_to_errno(bi_status), cow_pio);

	queue_work(ploop->wq, &ploop->worker);
	ploop_free_pio_with_pages(ploop, cow->aux_pio);
	kmem_cache_free(cow_cache, cow);
}

static void ploop_release_cluster(struct ploop *ploop, u32 clu)
{
	u32 id, *bat_entries, dst_clu;
	struct md_page *md;

	lockdep_assert_held(&ploop->bat_rwlock);

	id = ploop_bat_clu_to_page_nr(clu);
	md = ploop_md_page_find(ploop, id);
	BUG_ON(!md);

	clu = ploop_bat_clu_idx_in_page(clu); /* relative to page */

	bat_entries = kmap_atomic(md->page);
	dst_clu = bat_entries[clu];
	bat_entries[clu] = BAT_ENTRY_NONE;
	md->bat_levels[clu] = 0;
	kunmap_atomic(bat_entries);

	ploop_hole_set_bit(dst_clu, ploop);
}

static void ploop_piwb_discard_completed(struct ploop *ploop,
					 bool success, u32 clu, u32 new_dst_clu)
{
	if (new_dst_clu)
		return;

	if (ploop_cluster_is_in_top_delta(ploop, clu)) {
		WARN_ON_ONCE(ploop->nr_deltas != 1);
		if (success)
			ploop_release_cluster(ploop, clu);
	}
}

/*
 * Update local BAT copy with written indexes on success.
 * Mark allocate clusters as holes on failure.
 * FIXME: a failure may mean some sectors are written, so
 * we have to reread BAT page to check that.
 */
static void ploop_advance_local_after_bat_wb(struct ploop *ploop,
					     struct ploop_index_wb *piwb,
					     bool success)
{
	struct md_page *md = piwb->md;
	u32 i, last, *bat_entries;
	map_index_t *dst_clu, off;
	unsigned long flags;
	LIST_HEAD(list);

	BUG_ON(!md);
	bat_entries = kmap_atomic(md->page);

	/* Absolute number of first index in page (negative for page#0) */
	off = piwb->page_id * PAGE_SIZE / sizeof(map_index_t);
	off -= PLOOP_MAP_OFFSET;

	/* Last and first index in copied page */
	last = ploop->nr_bat_entries - off;
	if (last > PAGE_SIZE / sizeof(map_index_t))
		last = PAGE_SIZE / sizeof(map_index_t);
	i = 0;
	if (!piwb->page_id)
		i = PLOOP_MAP_OFFSET;

	dst_clu = kmap_atomic(piwb->bat_page);
	write_lock_irqsave(&ploop->bat_rwlock, flags);

	for (; i < last; i++) {
		if (piwb->type == PIWB_TYPE_DISCARD) {
			ploop_piwb_discard_completed(ploop, success, i + off, dst_clu[i]);
			continue;
		}

		if (!dst_clu[i])
			continue;

		if (ploop_cluster_is_in_top_delta(ploop, i + off)
						&& piwb->type == PIWB_TYPE_ALLOC) {
			WARN_ON(bat_entries[i] != dst_clu[i]);
			continue;
		}

		if (success) {
			bat_entries[i] = dst_clu[i];
			md->bat_levels[i] = ploop_top_level(ploop);
		} else {
			ploop_hole_set_bit(i + off, ploop);
		}
	}

	WARN_ON_ONCE(!(md->status & MD_WRITEBACK));
	md->status &= ~MD_WRITEBACK;
	md->piwb = NULL;
	list_splice_tail_init(&md->wait_list, &list);
	write_unlock_irqrestore(&ploop->bat_rwlock, flags);
	kunmap_atomic(dst_clu);
	kunmap_atomic(bat_entries);

	if (!list_empty(&list))
		ploop_dispatch_pios(ploop, NULL, &list);
}

static void ploop_free_piwb(struct ploop_index_wb *piwb)
{
	ploop_free_pio(piwb->ploop, piwb->pio);
	put_page(piwb->bat_page);
	kfree(piwb);
}

static void ploop_put_piwb(struct ploop_index_wb *piwb)
{
	if (atomic_dec_and_test(&piwb->count)) {
		struct ploop *ploop = piwb->ploop;
		/*
		 * Index wb failed. Mark clusters as unallocated again.
		 * piwb->count is zero, so all data writers compeleted.
		 */
		if (piwb->bi_status)
			ploop_advance_local_after_bat_wb(ploop, piwb, false);

		if (piwb->comp) {
			if (piwb->comp_bi_status)
				*piwb->comp_bi_status = piwb->bi_status;
			complete(piwb->comp);
		}
		ploop_free_piwb(piwb);
	}
}

/* This handler is called after BAT is updated. */
static void ploop_bat_write_complete(struct ploop_index_wb *piwb,
				     blk_status_t bi_status)
{
	struct ploop *ploop = piwb->ploop;
	struct pio *aux_pio;
	struct ploop_cow *cow;
	struct pio *data_pio;
	unsigned long flags;

	if (!bi_status) {
		/*
		 * Success: now update local BAT copy. We could do this
		 * from our delayed work, but we want to publish new
		 * mapping in the fastest way. This must be done before
		 * data bios completion, since right after we complete
		 * a bio, subsequent read wants to see written data
		 * (ploop_map() wants to see not zero bat_entries[.]).
		 */
		ploop_advance_local_after_bat_wb(ploop, piwb, true);
	}

	spin_lock_irqsave(&piwb->lock, flags);
	piwb->completed = true;
	piwb->bi_status = bi_status;
	spin_unlock_irqrestore(&piwb->lock, flags);

	/*
	 * End pending data bios. Unlocked, as nobody can
	 * add a new element after piwc->completed is true.
	 */
	while ((data_pio = ploop_pio_list_pop(&piwb->ready_data_pios)) != NULL) {
		if (bi_status)
			data_pio->bi_status = bi_status;
		ploop_pio_endio(data_pio);
	}

	while ((aux_pio = ploop_pio_list_pop(&piwb->cow_list))) {
		cow = aux_pio->endio_cb_data;
		ploop_complete_cow(cow, bi_status);
	}

	/*
	 * In case of update BAT is failed, dst_clusters will be
	 * set back to holes_bitmap on last put_piwb().
	 */
	ploop_put_piwb(piwb);
}

static int ploop_prepare_bat_update(struct ploop *ploop, struct md_page *md,
				    enum piwb_type type)
{
	u32 i, off, last, *bat_entries;
	struct ploop_index_wb *piwb;
	bool is_last_page = true;
	u32 page_id = md->id;
	struct page *page;
	struct pio *pio;
	map_index_t *to;

	piwb = kmalloc(sizeof(*piwb), GFP_NOIO);
	if (!piwb)
		return -ENOMEM;
	ploop_index_wb_init(piwb, ploop);

	piwb->bat_page = page = alloc_page(GFP_NOIO);
	piwb->pio = pio = ploop_alloc_pio(ploop, GFP_NOIO);
	if (!page || !pio)
		goto err;
	ploop_init_pio(ploop, REQ_OP_WRITE, pio);

	bat_entries = kmap_atomic(md->page);

	write_lock_irq(&ploop->bat_rwlock);
	md->piwb = piwb;
	piwb->md = md;
	write_unlock_irq(&ploop->bat_rwlock);

	piwb->page_id = page_id;
	to = kmap_atomic(page);
	memcpy((void *)to, bat_entries, PAGE_SIZE);

	/* Absolute number of first index in page (negative for page#0) */
	off = page_id * PAGE_SIZE / sizeof(map_index_t);
	off -= PLOOP_MAP_OFFSET;

	/* Last and first index in copied page */
	last = ploop->nr_bat_entries - off;
	if (last > PAGE_SIZE / sizeof(map_index_t)) {
		last = PAGE_SIZE / sizeof(map_index_t);
		is_last_page = false;
	}
	i = 0;
	if (!page_id)
		i = PLOOP_MAP_OFFSET;

	/* Copy BAT (BAT goes right after hdr, see .ctr) */
	for (; i < last; i++) {
		if (ploop_cluster_is_in_top_delta(ploop, i + off))
			continue;
		to[i] = 0;
	}
	if (is_last_page) {
	/* Fill tail of page with 0 */
		for (i = last; i < PAGE_SIZE / sizeof(map_index_t); i++)
			to[i] = 0;
	}

	kunmap_atomic(to);
	kunmap_atomic(bat_entries);

	piwb->type = type;
	return 0;
err:
	ploop_free_piwb(piwb);
	return -ENOMEM;
}

void ploop_break_bat_update(struct ploop *ploop, struct md_page *md)
{
	struct ploop_index_wb *piwb;
	unsigned long flags;

	write_lock_irqsave(&ploop->bat_rwlock, flags);
	piwb = md->piwb;
	md->piwb = NULL;
	write_unlock_irqrestore(&ploop->bat_rwlock, flags);

	ploop_free_piwb(piwb);
}

static void ploop_bat_page_zero_cluster(struct ploop *ploop,
					struct ploop_index_wb *piwb,
					u32 clu)
{
	map_index_t *to;

	/* Cluster index related to the page[page_id] start */
	clu = ploop_bat_clu_idx_in_page(clu);

	to = kmap_atomic(piwb->bat_page);
	to[clu] = 0;
	kunmap_atomic(to);
}

static int ploop_find_dst_clu_bit(struct ploop *ploop, u32 *ret_dst_clu)
{
	u32 dst_clu;

	/* Find empty clu */
	dst_clu = find_first_bit(ploop->holes_bitmap, ploop->hb_nr);
	if (dst_clu >= ploop->hb_nr)
		return -EIO;
	*ret_dst_clu = dst_clu;
	return 0;
}

static int ploop_truncate_prealloc_safe(struct ploop *ploop,
					struct ploop_delta *delta,
					loff_t len, const char *func)
{
	struct file *file = delta->file;
	loff_t old_len = delta->file_size;
	loff_t new_len = len;
	int ret;

	if (new_len <= old_len)
		return 0;
	new_len = ALIGN(new_len, PREALLOC_SIZE);

	if (!ploop->falloc_new_clu)
		ret = vfs_truncate2(&file->f_path, new_len, file);
	else
		ret = vfs_fallocate(file, 0, old_len, new_len - old_len);
	if (ret) {
		pr_err("ploop: %s->prealloc: %d\n", func, ret);
		return ret;
	}

	ret = vfs_fsync(file, 0);
	if (ret) {
		pr_err("ploop: %s->fsync(): %d\n", func, ret);
		return ret;
	}

	delta->file_size = new_len;
	delta->file_preallocated_area_start = len;
	return 0;
}

static int ploop_allocate_cluster(struct ploop *ploop, u32 *dst_clu)
{
	struct ploop_delta *top = ploop_top_delta(ploop);
	u32 clu_size = CLU_SIZE(ploop);
	loff_t off, pos, end, old_size;
	struct file *file = top->file;
	int ret;

	if (ploop_find_dst_clu_bit(ploop, dst_clu) < 0)
		return -EIO;

	pos = CLU_TO_POS(ploop, *dst_clu);
	end = pos + clu_size;
	old_size = top->file_size;

	if (pos < top->file_preallocated_area_start) {
		/* Clu at @pos may contain dirty data */
		off = min_t(loff_t, old_size, end);
		if (!ploop->falloc_new_clu)
			ret = ploop_punch_hole(file, pos, off - pos);
		else
			ret = ploop_zero_range(file, pos, off - pos);
		if (ret) {
			pr_err("ploop: punch/zero area: %d\n", ret);
			return ret;
		}
	}

	if (end > old_size) {
		ret = ploop_truncate_prealloc_safe(ploop, top, end, __func__);
		if (ret)
			return ret;
	} else if (pos < top->file_preallocated_area_start) {
		/*
		 * Flush punch_hole()/zero_range() modifications.
		 * TODO: track recentry unused blocks and do that
		 * in background.
		 */
		ret = vfs_fsync(file, 0);
		if (ret) {
			pr_err("ploop: fsync: %d\n", ret);
			return ret;
		}
	}

	if (end > top->file_preallocated_area_start)
		top->file_preallocated_area_start = end;
	/*
	 * Mark clu as used. Find & clear bit is unlocked,
	 * since currently this may be called only from deferred
	 * kwork. Note, that set_bit may be made from many places.
	 */
	ploop_hole_clear_bit(*dst_clu, ploop);
	return 0;
}

/*
 * This finds a free dst_clu on origin device, and reflects this
 * in ploop->holes_bitmap and bat_page.
 */
static int ploop_alloc_cluster(struct ploop *ploop, struct ploop_index_wb *piwb,
			       u32 clu, u32 *dst_clu)
{
	struct page *page = piwb->bat_page;
	bool already_alloced = false;
	map_index_t *to;
	int ret = 0;

	/* Cluster index related to the page[page_id] start */
	clu -= piwb->page_id * PAGE_SIZE / sizeof(map_index_t) - PLOOP_MAP_OFFSET;

	to = kmap_atomic(page);
	if (to[clu]) {
		/* Already mapped by one of previous bios */
		*dst_clu = to[clu];
		already_alloced = true;
	}
	kunmap_atomic(to);

	if (already_alloced)
		goto out;

	ret = ploop_allocate_cluster(ploop, dst_clu);
	if (ret < 0)
		goto out;

	to = kmap_atomic(page);
	to[clu] = *dst_clu;
	kunmap_atomic(to);
out:
	return ret;
}

static bool ploop_data_pio_end(struct pio *pio)
{
	struct ploop_index_wb *piwb = pio->piwb;
	unsigned long flags;
	bool completed;

	spin_lock_irqsave(&piwb->lock, flags);
	completed = piwb->completed;
	if (!completed)
		list_add_tail(&pio->list, &piwb->ready_data_pios);
	else if (!pio->bi_status)
		pio->bi_status = piwb->bi_status;
	spin_unlock_irqrestore(&piwb->lock, flags);

	ploop_put_piwb(piwb);

	return completed;
}

static void ploop_attach_end_action(struct pio *pio, struct ploop_index_wb *piwb)
{
	pio->is_data_alloc = true;
	pio->piwb = piwb;

	atomic_inc(&piwb->count);
}

static void ploop_queue_resubmit(struct pio *pio)
{
	struct ploop *ploop = pio->ploop;
	unsigned long flags;

	pio->queue_list_id = PLOOP_LIST_INVALID;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	list_add_tail(&pio->list, &ploop->resubmit_pios);
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	queue_work(ploop->wq, &ploop->worker);
}

static void ploop_data_rw_complete(struct pio *pio)
{
	bool completed;

	if (pio->ret != pio->bi_iter.bi_size) {
		if (pio->ret >= 0) {
			/* Partial IO */
			WARN_ON_ONCE(pio->ret == 0);
			ploop_pio_advance(pio, pio->ret);
			ploop_queue_resubmit(pio);
			return;
		}
		pio->bi_status = errno_to_blk_status(pio->ret);
	}

	if (pio->is_data_alloc) {
		completed = ploop_data_pio_end(pio);
		if (!completed)
			return;
	}

	ploop_pio_endio(pio);
}

/*
 * XXX: Keep in mind, data_rw_complete may queue resubmit after partial IO.
 * Don't use this function from fsync kwork in case of the caller blocks
 * to wait for completion, since kwork is who resubmits after partial IO.
 */
static void ploop_submit_rw_mapped(struct ploop *ploop, struct pio *pio)
{
	unsigned int rw, nr_segs;
	struct bio_vec *bvec;
	struct iov_iter iter;
	struct file *file;
	loff_t pos;

	BUG_ON(pio->level > ploop_top_level(ploop));

	pio->complete = ploop_data_rw_complete;

	rw = (op_is_write(pio->bi_op) ? WRITE : READ);
	nr_segs = ploop_pio_nr_segs(pio);
	bvec = __bvec_iter_bvec(pio->bi_io_vec, pio->bi_iter);

	iov_iter_bvec(&iter, rw, bvec, nr_segs, pio->bi_iter.bi_size);
	iter.iov_offset = pio->bi_iter.bi_bvec_done;

	pos = to_bytes(pio->bi_iter.bi_sector);

	file = ploop->deltas[pio->level].file;

	/* Don't touch @pio after that */
	if (pio->css && !ploop->nokblkcg) {
		kthread_associate_blkcg(pio->css);
		ploop_call_rw_iter(file, pos, rw, &iter, pio);
		kthread_associate_blkcg(NULL);
	} else
		ploop_call_rw_iter(file, pos, rw, &iter, pio);
}

void ploop_map_and_submit_rw(struct ploop *ploop, u32 dst_clu,
			     struct pio *pio, u8 level)
{
	ploop_remap_to_cluster(ploop, pio, dst_clu);
	pio->level = level;

	ploop_submit_rw_mapped(ploop, pio);
}

static void ploop_initiate_delta_read(struct ploop *ploop, unsigned int level,
				      u32 dst_clu, struct pio *pio)
{
	if (dst_clu == BAT_ENTRY_NONE) {
		/* No one delta contains dst_clu. */
		ploop_zero_fill_pio(pio);
		ploop_pio_endio(pio);
		return;
	}

	ploop_map_and_submit_rw(ploop, dst_clu, pio, level);
}

static void ploop_cow_endio(struct pio *aux_pio, void *data,
			    blk_status_t bi_status)
{
	struct ploop_cow *cow = data;
	struct ploop *ploop = cow->ploop;

	aux_pio->queue_list_id = PLOOP_LIST_COW;
	ploop_dispatch_pios(ploop, aux_pio, NULL);
}

static bool ploop_postpone_if_cluster_locked(struct ploop *ploop,
					     struct pio *pio, u32 clu)
{
	struct pio *e_h; /* Exclusively locked */

	spin_lock_irq(&ploop->deferred_lock);
	e_h = ploop_find_lk_of_cluster(ploop, clu);
	if (e_h)
		ploop_add_endio_pio(e_h, pio);
	spin_unlock_irq(&ploop->deferred_lock);

	return e_h != NULL;
}

static int ploop_submit_cluster_cow(struct ploop *ploop, unsigned int level,
			      u32 clu, u32 dst_clu, struct pio *cow_pio)
{
	struct ploop_cow *cow = NULL;
	struct pio *aux_pio = NULL;

	/* Prepare new delta read */
	aux_pio = ploop_alloc_pio_with_pages(ploop);
	cow = kmem_cache_alloc(cow_cache, GFP_NOIO);
	if (!aux_pio || !cow)
		goto err;
	ploop_init_pio(ploop, REQ_OP_READ, aux_pio);
	ploop_pio_prepare_offsets(ploop, aux_pio, clu);
	aux_pio->css = cow_pio->css;
	aux_pio->endio_cb = ploop_cow_endio;
	aux_pio->endio_cb_data = cow;

	cow->ploop = ploop;
	cow->dst_clu = BAT_ENTRY_NONE;
	cow->aux_pio = aux_pio;
	cow->cow_pio = cow_pio;

	ploop_add_cluster_lk(ploop, cow_pio, clu);

	/* Stage #0: read secondary delta full clu */
	ploop_map_and_submit_rw(ploop, dst_clu, aux_pio, level);
	return 0;
err:
	if (aux_pio)
		ploop_free_pio_with_pages(ploop, aux_pio);
	kfree(cow);
	return -ENOMEM;
}

static void ploop_initiate_cluster_cow(struct ploop *ploop, unsigned int level,
				       u32 clu, u32 dst_clu, struct pio *pio)
{
	if (!ploop_submit_cluster_cow(ploop, level, clu, dst_clu, pio))
		return;

	pio->bi_status = BLK_STS_RESOURCE;
	ploop_pio_endio(pio);
}

static void ploop_submit_cluster_write(struct ploop_cow *cow)
{
	struct pio *aux_pio = cow->aux_pio;
	struct ploop *ploop = cow->ploop;
	u32 dst_clu;
	int ret;

	ret = ploop_allocate_cluster(ploop, &dst_clu);
	if (unlikely(ret < 0))
		goto error;
	cow->dst_clu = dst_clu;

	ploop_init_pio(ploop, REQ_OP_WRITE, aux_pio);
	aux_pio->css = cow->cow_pio->css;
	ploop_pio_prepare_offsets(ploop, aux_pio, dst_clu);

	BUG_ON(irqs_disabled());
	aux_pio->endio_cb = ploop_cow_endio;
	aux_pio->endio_cb_data = cow;

	ploop_map_and_submit_rw(ploop, dst_clu, aux_pio,
				ploop_top_level(ploop));
	return;
error:
	ploop_complete_cow(cow, errno_to_blk_status(ret));
}

static void ploop_submit_cow_index_wb(struct ploop_cow *cow)
{
	struct pio *cow_pio = cow->cow_pio;
	struct ploop *ploop = cow->ploop;
	u32 page_id, clu = cow_pio->clu;
	struct ploop_index_wb *piwb;
	struct md_page *md;
	map_index_t *to;

	WARN_ON_ONCE(cow->aux_pio->queue_list_id != PLOOP_LIST_COW);
	page_id = ploop_bat_clu_to_page_nr(clu);
	md = ploop_md_page_find(ploop, page_id);

	if (ploop_delay_if_md_busy(ploop, md, PIWB_TYPE_ALLOC, cow->aux_pio))
		goto out;

	if (!(md->status & MD_DIRTY)) {
		/* Unlocked, since MD_DIRTY is set and cleared from this work */
		if (ploop_prepare_bat_update(ploop, md, PIWB_TYPE_ALLOC) < 0)
			goto err_resource;
		ploop_md_make_dirty(ploop, md);
	}

	piwb = md->piwb;

	clu -= page_id * PAGE_SIZE / sizeof(map_index_t) - PLOOP_MAP_OFFSET;

	to = kmap_atomic(piwb->bat_page);
	WARN_ON(to[clu]);
	to[clu] = cow->dst_clu;
	kunmap_atomic(to);

	/* Prevent double clearing of holes_bitmap bit on complete_cow() */
	cow->dst_clu = BAT_ENTRY_NONE;
	spin_lock_irq(&ploop->deferred_lock);
	list_add_tail(&cow->aux_pio->list, &piwb->cow_list);
	spin_unlock_irq(&ploop->deferred_lock);
out:
	return;
err_resource:
	ploop_complete_cow(cow, BLK_STS_RESOURCE);
}

static void ploop_process_delta_cow(struct ploop *ploop,
				    struct list_head *cow_list)
{
	struct ploop_cow *cow;
	struct pio *aux_pio;

	if (list_empty(cow_list))
		return;

	while ((aux_pio = ploop_pio_list_pop(cow_list)) != NULL) {
		cow = aux_pio->endio_cb_data;
		if (unlikely(aux_pio->bi_status != BLK_STS_OK)) {
			ploop_complete_cow(cow, aux_pio->bi_status);
			continue;
		}

		if (cow->dst_clu == BAT_ENTRY_NONE) {
			/*
			 * Stage #1: assign dst_clu and write data
			 * to top delta.
			 */
			ploop_submit_cluster_write(cow);
		} else {
			/*
			 * Stage #2: data is written to top delta.
			 * Update index.
			 */
			ploop_submit_cow_index_wb(cow);
		}
	}
}

/*
 * This allocates a new clu (if clu wb is not pending yet),
 * or tries to attach a bio to a planned page index wb.
 *
 * We want to update BAT indexes in batch, but we don't want to delay data
 * bios submitting till the batch is assembled, submitted and completed.
 * This function tries to submit data bios before indexes are written
 * on disk.
 * Original bio->bi_end_io mustn't be called before index wb is completed.
 * We handle this in ploop_attach_end_action() by specific callback
 * for ploop_data_pio_end().
 * Note: clu newer becomes locked here, since index update is called
 * synchronously. Keep in mind this in case you make it async.
 */
static bool ploop_locate_new_cluster_and_attach_pio(struct ploop *ploop,
						    struct md_page *md,
						    u32 clu, u32 *dst_clu,
						    struct pio *pio)
{
	bool bat_update_prepared = false;
	struct ploop_index_wb *piwb;
	bool attached = false;
	u32 page_id;
	int err;

	WARN_ON_ONCE(pio->queue_list_id != PLOOP_LIST_DEFERRED);
	if (ploop_delay_if_md_busy(ploop, md, PIWB_TYPE_ALLOC, pio))
		goto out;

	if (!(md->status & MD_DIRTY)) {
		 /* Unlocked since MD_DIRTY is set and cleared from this work */
		page_id = ploop_bat_clu_to_page_nr(clu);
		if (ploop_prepare_bat_update(ploop, md, PIWB_TYPE_ALLOC) < 0) {
			pio->bi_status = BLK_STS_RESOURCE;
			goto error;
		}
		bat_update_prepared = true;
	}

	piwb = md->piwb;

	err = ploop_alloc_cluster(ploop, piwb, clu, dst_clu);
	if (err) {
		pio->bi_status = errno_to_blk_status(err);
		goto error;
	}

	if (bat_update_prepared)
		ploop_md_make_dirty(ploop, md);

	ploop_attach_end_action(pio, piwb);
	attached = true;
out:
	return attached;
error:
	/* Uninit piwb */
	if (bat_update_prepared)
		ploop_break_bat_update(ploop, md);
	ploop_pio_endio(pio);
	return false;
}

static int ploop_process_one_deferred_bio(struct ploop *ploop, struct pio *pio)
{
	sector_t sector = pio->bi_iter.bi_sector;
	struct md_page *md;
	u32 clu, dst_clu;
	u8 level;
	bool ret;

	clu = SEC_TO_CLU(ploop, sector);
	if (ploop_postpone_if_cluster_locked(ploop, pio, clu))
		goto out;

	dst_clu = ploop_bat_entries(ploop, clu, &level, &md);
	if (op_is_discard(pio->bi_op)) {
		/* FIXME: check there is no parallel alloc */
		ploop_handle_discard_pio(ploop, pio, clu, dst_clu);
		goto out;
	}

	if (ploop_cluster_is_in_top_delta(ploop, clu)) {
		/* Already mapped */
		if (ploop_pio_endio_if_merge_fake_pio(pio))
			goto out;
		goto queue;
	} else if (!op_is_write(pio->bi_op)) {
		/*
		 * Simple read from secondary delta. May fail.
		 * (Also handles the case dst_clu == BAT_ENTRY_NONE).
		 */
		ploop_initiate_delta_read(ploop, level, dst_clu, pio);
		goto out;
	} else if (dst_clu != BAT_ENTRY_NONE) {
		/*
		 * Read secondary delta and write to top delta. May fail.
		 * Yes, we can optimize the whole-clu-write case and
		 * a lot of other corner cases, but we don't do that as
		 * snapshots are used and COW occurs very rare.
		 */
		ploop_initiate_cluster_cow(ploop, level, clu, dst_clu, pio);
		goto out;
	}

	if (unlikely(ploop_pio_endio_if_all_zeros(pio)))
		goto out;

	/* Cluster exists nowhere. Allocate it and setup pio as outrunning */
	ret = ploop_locate_new_cluster_and_attach_pio(ploop, md, clu,
						      &dst_clu, pio);
	if (!ret)
		goto out;
queue:
	ploop_link_submitting_pio(ploop, pio, clu);

	ploop_map_and_submit_rw(ploop, dst_clu, pio, ploop_top_level(ploop));
out:
	return 0;
}

static void ploop_md_fsync_endio(struct pio *pio, void *piwb_ptr,
				 blk_status_t bi_status)
{
	struct ploop_index_wb *piwb = piwb_ptr;

	ploop_bat_write_complete(piwb, bi_status);
}

static void ploop_md_write_endio(struct pio *pio, void *piwb_ptr,
				 blk_status_t bi_status)
{
	struct ploop_index_wb *piwb = piwb_ptr;
	struct ploop *ploop = piwb->ploop;

	if (bi_status) {
		ploop_md_fsync_endio(pio, piwb, bi_status);
	} else {
		ploop_init_pio(ploop, REQ_OP_FLUSH, pio);
		pio->endio_cb = ploop_md_fsync_endio;
		pio->endio_cb_data = piwb;

		pio->queue_list_id = PLOOP_LIST_FLUSH;
		ploop_dispatch_pios(ploop, pio, NULL);
	}
}

void ploop_index_wb_submit(struct ploop *ploop, struct ploop_index_wb *piwb)
{
	loff_t pos = (loff_t)piwb->page_id << PAGE_SHIFT;
	struct pio *pio = piwb->pio;
	struct bio_vec *bvec = &piwb->aux_bvec;

	bvec->bv_page = piwb->bat_page;
	bvec->bv_len = PAGE_SIZE;
	bvec->bv_offset = 0;

	pio->bi_iter.bi_sector = to_sector(pos);
	pio->bi_iter.bi_size = PAGE_SIZE;
	pio->bi_iter.bi_idx = 0;
	pio->bi_iter.bi_bvec_done = 0;
	pio->bi_io_vec = bvec;
	pio->level = ploop_top_level(ploop);
	pio->endio_cb = ploop_md_write_endio;
	pio->endio_cb_data = piwb;

	ploop_submit_rw_mapped(ploop, pio);
}

static struct bio_vec *ploop_create_bvec_from_rq(struct request *rq)
{
	struct bio_vec bv, *bvec, *tmp;
	struct req_iterator rq_iter;
	unsigned int nr_bvec = 0;

	rq_for_each_bvec(bv, rq, rq_iter)
		nr_bvec++;

	bvec = kmalloc_array(nr_bvec, sizeof(struct bio_vec),
			     GFP_NOIO);
	if (!bvec)
		goto out;

	tmp = bvec;
	rq_for_each_bvec(bv, rq, rq_iter) {
		*tmp = bv;
		tmp++;
	}
out:
	return bvec;
}

static void ploop_prepare_one_embedded_pio(struct ploop *ploop,
					   struct pio *pio,
					   struct list_head *deferred_pios)
{
	struct ploop_rq *prq = pio->endio_cb_data;
	struct request *rq = prq->rq;
	struct bio_vec *bvec = NULL;
	LIST_HEAD(list);
	int ret;

	if (rq->bio != rq->biotail) {
		if (req_op(rq) == REQ_OP_DISCARD)
			goto skip_bvec;
		/*
		 * Transform a set of bvec arrays related to bios
		 * into a single bvec array (which we can iterate).
		 */
		bvec = ploop_create_bvec_from_rq(rq);
		if (!bvec)
			goto err_nomem;
		prq->bvec = bvec;
skip_bvec:
		pio->bi_iter.bi_size = blk_rq_bytes(rq);
		pio->bi_iter.bi_idx = 0;
		pio->bi_iter.bi_bvec_done = 0;
	} else {
		/* Single bio already provides bvec array */
		bvec = rq->bio->bi_io_vec;

		pio->bi_iter = rq->bio->bi_iter;
	}
	pio->bi_iter.bi_sector = ploop_rq_pos(ploop, rq);
	pio->bi_io_vec = bvec;

	pio->queue_list_id = PLOOP_LIST_DEFERRED;
	ret = ploop_split_pio_to_list(ploop, pio, deferred_pios);
	if (ret)
		goto err_nomem;

	return;
err_nomem:
	pio->bi_status = BLK_STS_RESOURCE;
	ploop_pio_endio(pio);
}

static void ploop_prepare_embedded_pios(struct ploop *ploop,
					struct list_head *pios,
					struct list_head *deferred_pios)
{
	struct pio *pio;

	while ((pio = ploop_pio_list_pop(pios)) != NULL)
		ploop_prepare_one_embedded_pio(ploop, pio, deferred_pios);
}

static void ploop_process_deferred_pios(struct ploop *ploop,
					struct list_head *pios)
{
	struct pio *pio;

	while ((pio = ploop_pio_list_pop(pios)) != NULL)
		ploop_process_one_deferred_bio(ploop, pio);
}

static void ploop_process_one_discard_pio(struct ploop *ploop, struct pio *pio)
{
	bool bat_update_prepared = false;
	u32 page_id, clu = pio->clu;
	struct ploop_index_wb *piwb;
	struct md_page *md;
	map_index_t *to;

	WARN_ON(ploop->nr_deltas != 1 ||
		pio->queue_list_id != PLOOP_LIST_DISCARD);

	page_id = ploop_bat_clu_to_page_nr(clu);
	md = ploop_md_page_find(ploop, page_id);
	if (ploop_delay_if_md_busy(ploop, md, PIWB_TYPE_DISCARD, pio))
		goto out;

	if (!(md->status & MD_DIRTY)) {
		 /* Unlocked since MD_DIRTY is set and cleared from this work */
		if (ploop_prepare_bat_update(ploop, md, PIWB_TYPE_DISCARD) < 0) {
			pio->bi_status = BLK_STS_RESOURCE;
			goto err;
		}
		bat_update_prepared = true;
	}

	piwb = md->piwb;

	/* Cluster index related to the page[page_id] start */
	clu -= piwb->page_id * PAGE_SIZE / sizeof(map_index_t) - PLOOP_MAP_OFFSET;

	to = kmap_atomic(piwb->bat_page);
	if (WARN_ON_ONCE(!to[clu])) {
		pio->bi_status = BLK_STS_IOERR;
		goto err;
	} else {
		to[clu] = 0;
		list_add_tail(&pio->list, &piwb->ready_data_pios);
	}
	kunmap_atomic(to);

	if (bat_update_prepared)
		ploop_md_make_dirty(ploop, md);
out:
	return;
err:
	if (bat_update_prepared)
		ploop_break_bat_update(ploop, md);
	ploop_pio_endio(pio);
}

static void ploop_process_discard_pios(struct ploop *ploop,
				       struct list_head *pios)
{
	struct pio *pio;

	while ((pio = ploop_pio_list_pop(pios)) != NULL)
		ploop_process_one_discard_pio(ploop, pio);
}

static void ploop_process_resubmit_pios(struct ploop *ploop,
					struct list_head *pios)
{
	struct pio *pio;

	while ((pio = ploop_pio_list_pop(pios)) != NULL) {
		pio->queue_list_id = PLOOP_LIST_INVALID;
		ploop_submit_rw_mapped(ploop, pio);
	}
}

static void ploop_submit_metadata_writeback(struct ploop *ploop)
{
	struct md_page *md;

	while (1) {
		write_lock_irq(&ploop->bat_rwlock);
		md = list_first_entry_or_null(&ploop->wb_batch_list,
				struct md_page, wb_link);
		if (!md) {
			write_unlock_irq(&ploop->bat_rwlock);
			break;
		}
		list_del_init(&md->wb_link);
		/* L1L2 mustn't be redirtyed, when wb in-flight! */
		WARN_ON_ONCE(!(md->status & MD_DIRTY) ||
			     (md->status & MD_WRITEBACK));
		md->status |= MD_WRITEBACK;
		md->status &= ~MD_DIRTY;
		write_unlock_irq(&ploop->bat_rwlock);

		ploop_index_wb_submit(ploop, md->piwb);
	}
}

void do_ploop_work(struct work_struct *ws)
{
	struct ploop *ploop = container_of(ws, struct ploop, worker);
	LIST_HEAD(embedded_pios);
	LIST_HEAD(deferred_pios);
	LIST_HEAD(discard_pios);
	LIST_HEAD(cow_pios);
	LIST_HEAD(resubmit_pios);
	unsigned int old_flags = current->flags;

	current->flags |= PF_IO_THREAD|PF_LOCAL_THROTTLE|PF_MEMALLOC_NOIO;

	spin_lock_irq(&ploop->deferred_lock);
	list_splice_init(&ploop->pios[PLOOP_LIST_PREPARE], &embedded_pios);
	list_splice_init(&ploop->pios[PLOOP_LIST_DEFERRED], &deferred_pios);
	list_splice_init(&ploop->pios[PLOOP_LIST_DISCARD], &discard_pios);
	list_splice_init(&ploop->pios[PLOOP_LIST_COW], &cow_pios);
	list_splice_init(&ploop->resubmit_pios, &resubmit_pios);
	spin_unlock_irq(&ploop->deferred_lock);

	ploop_prepare_embedded_pios(ploop, &embedded_pios, &deferred_pios);

	ploop_process_resubmit_pios(ploop, &resubmit_pios);
	ploop_process_deferred_pios(ploop, &deferred_pios);
	ploop_process_discard_pios(ploop, &discard_pios);
	ploop_process_delta_cow(ploop, &cow_pios);

	ploop_submit_metadata_writeback(ploop);

	current->flags = old_flags;
}

void do_ploop_fsync_work(struct work_struct *ws)
{
	struct ploop *ploop = container_of(ws, struct ploop, fsync_worker);
	LIST_HEAD(flush_pios);
	struct file *file;
	struct pio *pio;
	int ret;

	spin_lock_irq(&ploop->deferred_lock);
	list_splice_init(&ploop->pios[PLOOP_LIST_FLUSH], &flush_pios);
	spin_unlock_irq(&ploop->deferred_lock);

	file = ploop_top_delta(ploop)->file;
	ret = vfs_fsync(file, 0);

	while ((pio = ploop_pio_list_pop(&flush_pios)) != NULL) {
		if (unlikely(ret))
			pio->bi_status = errno_to_blk_status(ret);
		ploop_pio_endio(pio);
	}
}

static void ploop_submit_embedded_pio(struct ploop *ploop, struct pio *pio)
{
	struct ploop_rq *prq = pio->endio_cb_data;
	struct request *rq = prq->rq;
	struct work_struct *worker;
	unsigned long flags;
	bool queue = true;

	if (blk_rq_bytes(rq)) {
		pio->queue_list_id = PLOOP_LIST_PREPARE;
		worker = &ploop->worker;
	} else {
		WARN_ON_ONCE(pio->bi_op != REQ_OP_FLUSH);
		pio->queue_list_id = PLOOP_LIST_FLUSH;
		worker = &ploop->fsync_worker;
	}

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	if (unlikely(ploop->stop_submitting_pios)) {
		list_add_tail(&pio->list, &ploop->suspended_pios);
		queue = false;
		goto unlock;
	}

	ploop_inc_nr_inflight(ploop, pio);
	list_add_tail(&pio->list, &ploop->pios[pio->queue_list_id]);
unlock:
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	if (queue)
		queue_work(ploop->wq, worker);
}

void ploop_submit_embedded_pios(struct ploop *ploop, struct list_head *list)
{
	struct pio *pio;

	while ((pio = ploop_pio_list_pop(list)) != NULL)
		ploop_submit_embedded_pio(ploop, pio);
}

int ploop_clone_and_map(struct dm_target *ti, struct request *rq,
		    union map_info *info, struct request **clone)
{
	struct ploop *ploop = ti->private;
	struct ploop_rq *prq;
	struct pio *pio;

	if (blk_rq_bytes(rq) && ploop_rq_valid(ploop, rq) < 0)
		return DM_MAPIO_KILL;

	prq = mempool_alloc(ploop->prq_pool, GFP_ATOMIC);
	if (!prq)
		return DM_MAPIO_KILL;
	pio = (void *)prq + sizeof(*prq);

	ploop_init_prq_and_embedded_pio(ploop, rq, prq, pio);

	ploop_submit_embedded_pio(ploop, pio);
	return DM_MAPIO_SUBMITTED;
}

static void ploop_handle_cleanup(struct ploop *ploop, struct pio *pio)
{
	/*
	 * This function is called from the very beginning
	 * of call_bio_endio().
	 */
	if (pio->wants_discard_index_cleanup)
		ploop_discard_index_pio_end(ploop, pio);

	ploop_unlink_completed_pio(ploop, pio);
	ploop_dec_nr_inflight(ploop, pio);
}

/*
 * Prepare simple index writeback without attached data bios.
 * In case of @dst_clu is passed, this tryes to allocate
 * another index instead of existing. If so, management of
 * old bat_entries[@clu] and of related holes_bitmap bit
 * is caller duty.
 */
int ploop_prepare_reloc_index_wb(struct ploop *ploop,
				 struct md_page **ret_md,
				 u32 clu, u32 *dst_clu)
{
	enum piwb_type type = PIWB_TYPE_ALLOC;
	u32 page_id = ploop_bat_clu_to_page_nr(clu);
	struct md_page *md = ploop_md_page_find(ploop, page_id);
	struct ploop_index_wb *piwb;
	int err;

	if (dst_clu)
		type = PIWB_TYPE_RELOC;

	err = -EIO;
	if ((md->status & (MD_DIRTY|MD_WRITEBACK))) {
		pr_err("ploop: Unexpected md status: %x\n", md->status);
		goto out_error;
	}
	err = ploop_prepare_bat_update(ploop, md, type);
	if (err)
		goto out_error;

	piwb = md->piwb;

	if (dst_clu) {
		/*
		 * For ploop_advance_local_after_bat_wb(): do not concern
		 * about bat_cluster[@clu] is set. Zero bat_page[@clu],
		 * to make ploop_alloc_cluster() allocate new dst_clu from
		 * holes_bitmap.
		 */
		ploop_bat_page_zero_cluster(ploop, piwb, clu);
		err = ploop_alloc_cluster(ploop, piwb, clu, dst_clu);
		if (err)
			goto out_reset;
	}

	*ret_md = md;
	return 0;

out_reset:
	ploop_break_bat_update(ploop, md);
out_error:
	return err;
}
