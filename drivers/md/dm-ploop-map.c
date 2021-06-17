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
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/uio.h>
#include <linux/blk-mq.h>
#include <uapi/linux/falloc.h>
#include "dm-ploop.h"
#include "dm-rq.h"

#define PREALLOC_SIZE (128ULL * 1024 * 1024)

/*
 * The idea of this driver is that the most part of time it does nothing:
 * ploop_map() just replaces bio->bi_iter.bi_sector with the cluster value
 * referred in bat_entries[]. No kwork is involved, all the work becomes
 * delegated to backed device (loop). Kwork starts only when a bio aims
 * to a not present cluster or for service requests.
 *
 * Service operations are also made from kwork, so sometimes we may avoid
 * synchronization because of this. Two different service operations can't
 * be executed in parallel.
 *
 * Discard begins from switching ploop in a special mode, when all requests
 * are managed by kwork, while all not-exclusive bios (e.g., READ or simple
 * WRITE) are linked to inflight_pios_rbtree. Discard bios are linked into
 * exclusive_bios_rbtree, but their start is delayed till all not-exclusive
 * bios going into the same cluster are finished. After exclusive bio is
 * started, the corresponding cluster becomes "locked", and all further bios
 * going into the same cluster becomes delayed.
 * Since the swithing into the mode is expensive, ploop remains in the mode
 * for CLEANUP_DELAY seconds in a hope that a new discard bio will come.
 * After this interval the device returns into normal mode, and ordinary bios
 * become handled in ploop_map() as before.
 */

static void handle_cleanup(struct ploop *ploop, struct pio *pio);

#define DM_MSG_PREFIX "ploop"

#define ploop_bat_lock(ploop, exclusive, flags)					\
	do {									\
		if (exclusive)							\
			write_lock_irqsave(&ploop->bat_rwlock, flags);		\
		else								\
			read_lock_irqsave(&ploop->bat_rwlock, flags);		\
	} while (0)

#define ploop_bat_unlock(ploop, exclusive, flags)				\
	do {									\
		if (exclusive)							\
			write_unlock_irqrestore(&ploop->bat_rwlock, flags);	\
		else								\
			read_unlock_irqrestore(&ploop->bat_rwlock, flags);	\
	} while (0)

static unsigned int pio_nr_segs(struct pio *pio)
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

static void ploop_index_wb_init(struct ploop_index_wb *piwb, struct ploop *ploop)
{
	piwb->ploop = ploop;
	init_completion(&piwb->comp);
	spin_lock_init(&piwb->lock);
	piwb->bat_page = NULL;
	piwb->bi_status = 0;
	INIT_LIST_HEAD(&piwb->ready_data_pios);
	INIT_LIST_HEAD(&piwb->cow_list);
	/* For ploop_bat_write_complete() */
	atomic_set(&piwb->count, 1);
	piwb->completed = false;
	piwb->page_nr = PAGE_NR_NONE;
	piwb->type = PIWB_TYPE_ALLOC;
}

void init_pio(struct ploop *ploop, unsigned int bi_op, struct pio *pio)
{
	pio->ploop = ploop;
	pio->bi_op = bi_op;
	pio->wants_discard_index_cleanup = false;
	pio->is_data_alloc = false;
	pio->free_on_endio = false;
	pio->ref_index = PLOOP_REF_INDEX_INVALID;
	pio->bi_status = BLK_STS_OK;
	atomic_set(&pio->remaining, 1);
	pio->piwb = NULL;
	INIT_LIST_HEAD(&pio->list);
	INIT_HLIST_NODE(&pio->hlist_node);
	INIT_LIST_HEAD(&pio->endio_list);
	/* FIXME: assign real cluster? */
	pio->cluster = UINT_MAX;
}

/* Get cluster related to pio sectors */
static int ploop_pio_valid(struct ploop *ploop, struct pio *pio)
{
	sector_t sector = pio->bi_iter.bi_sector;
	unsigned int end_cluster;
	loff_t end_byte;

	end_byte = to_bytes(sector) + pio->bi_iter.bi_size - 1;
	end_cluster = POS_TO_CLU(ploop, end_byte);

	if (unlikely(end_cluster >= ploop->nr_bat_entries)) {
		/*
		 * This mustn't happen, since we set max_io_len
		 * via dm_set_target_max_io_len().
		 */
		WARN_ONCE(1, "sec=%llu, size=%u, end_clu=%u, nr=%u\n",
			  sector, pio->bi_iter.bi_size,
			  end_cluster, ploop->nr_bat_entries);
		return -EINVAL;
	}

	return 0;
}

static void prq_endio(struct pio *pio, void *prq_ptr, blk_status_t bi_status)
{
        struct ploop_rq *prq = prq_ptr;
        struct request *rq = prq->rq;

	if (prq->bvec)
		kfree(prq->bvec);

	dm_complete_request(rq, bi_status);
}

static void do_pio_endio(struct pio *pio)
{
	ploop_endio_t endio_cb = pio->endio_cb;
	void *endio_cb_data = pio->endio_cb_data;
	bool free_on_endio = pio->free_on_endio;

        if (!atomic_dec_and_test(&pio->remaining))
                return;

	endio_cb(pio, endio_cb_data, pio->bi_status);

	if (free_on_endio)
		kfree(pio);
}

void pio_endio(struct pio *pio)
{
	struct ploop *ploop = pio->ploop;

	if (pio->ref_index != PLOOP_REF_INDEX_INVALID)
		track_pio(ploop, pio);

	handle_cleanup(ploop, pio);

	do_pio_endio(pio);
}

static void pio_chain_endio(struct pio *pio, void *parent_ptr,
			    blk_status_t bi_status)
{
        struct pio *parent = parent_ptr;

        if (unlikely(bi_status))
                parent->bi_status = bi_status;

        do_pio_endio(parent);
}

static void pio_chain(struct pio *pio, struct pio *parent)
{
	BUG_ON(pio->endio_cb_data || pio->endio_cb);

	pio->endio_cb_data = parent;
	pio->endio_cb = pio_chain_endio;
	atomic_inc(&parent->remaining);
}

/* Clone of bio_advance_iter() */
static void pio_advance(struct pio *pio, unsigned int bytes)
{
	struct bvec_iter *iter = &pio->bi_iter;

	iter->bi_sector += bytes >> 9;

	if (op_is_discard(pio->bi_op))
		iter->bi_size -= bytes;
	else
		bvec_iter_advance(pio->bi_io_vec, iter, bytes);
}

static struct pio * split_and_chain_pio(struct ploop *ploop,
		struct pio *pio, u32 len)
{
	struct pio *split;

	split = kmalloc(sizeof(*split), GFP_NOIO);
	if (!split)
		return NULL;

	init_pio(ploop, pio->bi_op, split);
	split->free_on_endio = true;
	split->bi_io_vec = pio->bi_io_vec;
	split->bi_iter = pio->bi_iter;
	split->bi_iter.bi_size = len;
	split->endio_cb = NULL;
	split->endio_cb_data = NULL;
	pio_chain(split, pio);
	if (len)
		pio_advance(pio, len);
	return split;
}

static int split_pio_to_list(struct ploop *ploop, struct pio *pio,
			     struct list_head *list)
{
	u32 clu_size = CLU_SIZE(ploop);
	struct pio *split;

	while (1) {
		loff_t start = to_bytes(pio->bi_iter.bi_sector);
		loff_t end = start + pio->bi_iter.bi_size;
		unsigned int len;

		WARN_ON_ONCE(start == end);

		if (start / clu_size == (end - 1) / clu_size)
			break;
		end = round_up(start + 1, clu_size);
		len = end - start;

		split = split_and_chain_pio(ploop, pio, len);
		if (!split)
			goto err;

		list_add_tail(&split->list, list);
	}

	return 0;
err:
	while ((pio = pio_list_pop(list)) != NULL) {
		pio->bi_status = BLK_STS_RESOURCE;
		pio_endio(pio);
	}
	return -ENOMEM;
}

void defer_pios(struct ploop *ploop, struct pio *pio, struct list_head *pio_list)
{
	unsigned long flags;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	if (pio)
		list_add_tail(&pio->list, &ploop->deferred_pios);
	if (pio_list)
		list_splice_tail_init(pio_list, &ploop->deferred_pios);

	spin_unlock_irqrestore(&ploop->deferred_lock, flags);
	queue_work(ploop->wq, &ploop->worker);
}

void track_dst_cluster(struct ploop *ploop, u32 dst_cluster)
{
	unsigned long flags;

	if (!ploop->tracking_bitmap)
		return;

	read_lock_irqsave(&ploop->bat_rwlock, flags);
	if (ploop->tracking_bitmap && !WARN_ON(dst_cluster >= ploop->tb_nr))
		set_bit(dst_cluster, ploop->tracking_bitmap);
	read_unlock_irqrestore(&ploop->bat_rwlock, flags);
}

/*
 * Userspace calls dm_suspend() to get changed blocks finally.
 * dm_suspend() waits for dm's inflight bios, so this function
 * must be called after @bio is written and before @bio is ended.
 * The only possible exception is writes driven by "message" ioctl.
 * Thus, userspace mustn't do maintaince operations in parallel
 * with tracking.
 */
void __track_pio(struct ploop *ploop, struct pio *pio)
{
	unsigned int dst_cluster = SEC_TO_CLU(ploop, pio->bi_iter.bi_sector);

	if (!op_is_write(pio->bi_op) || !bvec_iter_sectors((pio)->bi_iter))
		return;

	track_dst_cluster(ploop, dst_cluster);
}

static void queue_discard_index_wb(struct ploop *ploop, struct pio *pio)
{
	unsigned long flags;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	list_add_tail(&pio->list, &ploop->discard_pios);
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	queue_work(ploop->wq, &ploop->worker);
}

/* Zero @count bytes of @qio->bi_io_vec since @from byte */
static void zero_fill_pio(struct pio *pio)
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

struct pio *find_pio(struct hlist_head head[], u32 clu)
{
	struct hlist_head *slot = ploop_htable_slot(head, clu);
	struct pio *pio;

	BUG_ON(!slot);

	hlist_for_each_entry(pio, slot, hlist_node) {
		if (pio->cluster == clu)
			return pio;
	}

	return NULL;
}

static struct pio *find_inflight_bio(struct ploop *ploop, unsigned int cluster)
{
	lockdep_assert_held(&ploop->inflight_lock);
	return find_pio(ploop->inflight_pios, cluster);
}

struct pio *find_lk_of_cluster(struct ploop *ploop, unsigned int cluster)
{
	lockdep_assert_held(&ploop->deferred_lock);
	return find_pio(ploop->exclusive_pios, cluster);
}

static void add_endio_pio(struct pio *head, struct pio *pio)
{
	list_add_tail(&pio->list, &head->endio_list);
}

static void inc_nr_inflight(struct ploop *ploop, struct pio *pio)
{
	unsigned char ref_index = ploop->inflight_bios_ref_index;

	if (!WARN_ON_ONCE(pio->ref_index != PLOOP_REF_INDEX_INVALID)) {
		percpu_ref_get(&ploop->inflight_bios_ref[ref_index]);
		pio->ref_index = ref_index;
	}
}

/*
 * Note, that do_ploop_work() waits final ref dec_nr_inflight()
 * (e.g., on grow), so the code decrementing the counter can't
 * depend on the work or some actions it makes.
 *
 * The only intended usecase is that the counter is decremented
 * from endio of bios submitted to underlined device (loop) or
 * from ki_complete of requests submitted to delta files
 * (while increment occurs just right before the submitting).
 */
static void dec_nr_inflight(struct ploop *ploop, struct pio *pio)
{
	if (pio->ref_index != PLOOP_REF_INDEX_INVALID) {
		percpu_ref_put(&ploop->inflight_bios_ref[pio->ref_index]);
		pio->ref_index = PLOOP_REF_INDEX_INVALID;
	}
}

static void link_pio(struct hlist_head head[], struct pio *pio,
		     u32 clu, bool exclusive)
{
	struct hlist_head *slot = ploop_htable_slot(head, clu);

	if (exclusive)
		WARN_ON_ONCE(find_pio(head, clu) != NULL);

	BUG_ON(!hlist_unhashed(&pio->hlist_node));
	hlist_add_head(&pio->hlist_node, slot);
	pio->cluster = clu;
}

/*
 * Removes @pio of completed bio either from inflight_pios_rbtree
 * or from exclusive_bios_rbtree. BIOs from endio_list are requeued
 * to deferred_list.
 */
static void unlink_pio(struct ploop *ploop, struct pio *pio,
		       struct list_head *pio_list)
{
	BUG_ON(hlist_unhashed(&pio->hlist_node));

	hlist_del_init(&pio->hlist_node);
	list_splice_tail_init(&pio->endio_list, pio_list);
}

static void add_cluster_lk(struct ploop *ploop, struct pio *pio, u32 cluster)
{
	unsigned long flags;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	link_pio(ploop->exclusive_pios, pio, cluster, true);
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);
}
static void del_cluster_lk(struct ploop *ploop, struct pio *pio)
{
	LIST_HEAD(pio_list);
	unsigned long flags;
	bool queue = false;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	unlink_pio(ploop, pio, &pio_list);
	if (!list_empty(&pio_list)) {
		list_splice_tail(&pio_list, &ploop->deferred_pios);
		queue = true;
	}
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	if (queue)
		queue_work(ploop->wq, &ploop->worker);

}

static void link_submitting_pio(struct ploop *ploop, struct pio *pio,
				unsigned int cluster)
{
	unsigned long flags;

	spin_lock_irqsave(&ploop->inflight_lock, flags);
	link_pio(ploop->inflight_pios, pio, cluster, false);
	spin_unlock_irqrestore(&ploop->inflight_lock, flags);
}
static void unlink_completed_pio(struct ploop *ploop, struct pio *pio)
{
	LIST_HEAD(pio_list);
	unsigned long flags;

	if (hlist_unhashed(&pio->hlist_node))
		return;

	spin_lock_irqsave(&ploop->inflight_lock, flags);
	unlink_pio(ploop, pio, &pio_list);
	spin_unlock_irqrestore(&ploop->inflight_lock, flags);

	if (!list_empty(&pio_list)) {
		spin_lock_irqsave(&ploop->deferred_lock, flags);
		list_splice_tail(&pio_list, &ploop->deferred_pios);
		spin_unlock_irqrestore(&ploop->deferred_lock, flags);

		queue_work(ploop->wq, &ploop->worker);
	}
}

static bool pio_endio_if_all_zeros(struct pio *pio)
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

	pio_endio(pio);
	return true;
}

static int punch_hole(struct file *file, loff_t pos, loff_t len)
{
	return vfs_fallocate(file, FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE,
			     pos, len);
}

static void handle_discard_pio(struct ploop *ploop, struct pio *pio,
		     unsigned int cluster, unsigned int dst_cluster)
{
	struct pio *inflight_h;
	unsigned long flags;
	loff_t pos;
	int ret;

	if (!whole_cluster(ploop, pio)) {
		/*
		 * Despite discard_granularity is given, block level
		 * may submit shorter reqs. E.g., these are boundary
		 * bios around trimed continuous hunk. For discard
		 * it's OK to just ignore such reqs. Keep in mind
		 * this implementing REQ_OP_WRITE_ZEROES etc.
		 */
		pio_endio(pio);
		return;
	}

	if (!cluster_is_in_top_delta(ploop, cluster)) {
		pio_endio(pio);
		return;
	}

	/* We can't end with EOPNOTSUPP, since blk-mq prints error */
	if (ploop->nr_deltas != 1)
		goto punch_hole;

	spin_lock_irqsave(&ploop->inflight_lock, flags);
	inflight_h = find_inflight_bio(ploop, cluster);
	if (inflight_h)
		add_endio_pio(inflight_h, pio);
	spin_unlock_irqrestore(&ploop->inflight_lock, flags);

	if (inflight_h) {
		/* @pio will be requeued on inflight_h's pio end */
		pr_err_once("ploop: delayed discard: device is used as raw?\n");
		return;
	}

	add_cluster_lk(ploop, pio, cluster);
	pio->wants_discard_index_cleanup = true;

punch_hole:
	remap_to_cluster(ploop, pio, dst_cluster);
	pos = to_bytes(pio->bi_iter.bi_sector);
	ret = punch_hole(top_delta(ploop)->file, pos, pio->bi_iter.bi_size);
	if (ret || ploop->nr_deltas != 1) {
		if (ret)
			pio->bi_status = errno_to_blk_status(ret);
		pio_endio(pio);
		return;
	}

	queue_discard_index_wb(ploop, pio);
}

static void ploop_discard_index_pio_end(struct ploop *ploop, struct pio *pio)
{
	del_cluster_lk(ploop, pio);
}

static void complete_cow(struct ploop_cow *cow, blk_status_t bi_status)
{
	unsigned int dst_cluster = cow->dst_cluster;
	struct pio *cluster_pio = cow->cluster_pio;
	struct ploop *ploop = cow->ploop;
	unsigned long flags;
	struct pio *aux_pio;

	WARN_ON_ONCE(!list_empty(&cluster_pio->list));
	aux_pio = &cow->aux_pio;

	del_cluster_lk(ploop, aux_pio);

	if (dst_cluster != BAT_ENTRY_NONE && bi_status != BLK_STS_OK) {
		read_lock_irqsave(&ploop->bat_rwlock, flags);
		ploop_hole_set_bit(dst_cluster, ploop);
		read_unlock_irqrestore(&ploop->bat_rwlock, flags);
	}

	if (cow->end_fn)
		cow->end_fn(ploop, blk_status_to_errno(bi_status), cow->data);

	queue_work(ploop->wq, &ploop->worker);
	free_pio_with_pages(ploop, cow->cluster_pio);
	kmem_cache_free(cow_cache, cow);
}

static void ploop_release_cluster(struct ploop *ploop,
				  unsigned int cluster)
{
	unsigned int id, *bat_entries, dst_cluster;
	struct md_page *md;

	lockdep_assert_held(&ploop->bat_rwlock);

	id = bat_clu_to_page_nr(cluster);
        md = md_page_find(ploop, id);
        BUG_ON(!md);

	cluster = bat_clu_idx_in_page(cluster); /* relative to page */

	bat_entries = kmap_atomic(md->page);
	dst_cluster = bat_entries[cluster];
	bat_entries[cluster] = BAT_ENTRY_NONE;
	md->bat_levels[cluster] = 0;
	kunmap_atomic(bat_entries);

	ploop_hole_set_bit(dst_cluster, ploop);
}

static void piwb_discard_completed(struct ploop *ploop, bool success,
		  unsigned int cluster, unsigned int new_dst_cluster)
{
	if (new_dst_cluster)
		return;

	if (cluster_is_in_top_delta(ploop, cluster)) {
		WARN_ON_ONCE(ploop->nr_deltas != 1);
		if (success)
			ploop_release_cluster(ploop, cluster);
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
	struct md_page *md = md_page_find(ploop, piwb->page_nr);
	unsigned int i, last, *bat_entries;
	map_index_t *dst_cluster, off;
	unsigned long flags;

	BUG_ON(!md);
	bat_entries = kmap_atomic(md->page);

	/* Absolute number of first index in page (negative for page#0) */
	off = piwb->page_nr * PAGE_SIZE / sizeof(map_index_t);
	off -= PLOOP_MAP_OFFSET;

	/* Last and first index in copied page */
	last = ploop->nr_bat_entries - off;
	if (last > PAGE_SIZE / sizeof(map_index_t))
		last = PAGE_SIZE / sizeof(map_index_t);
	i = 0;
	if (!piwb->page_nr)
		i = PLOOP_MAP_OFFSET;

	dst_cluster = kmap_atomic(piwb->bat_page);
	ploop_bat_lock(ploop, success, flags);

	for (; i < last; i++) {
		if (piwb->type == PIWB_TYPE_DISCARD) {
			piwb_discard_completed(ploop, success, i + off, dst_cluster[i]);
			continue;
		}

		if (!dst_cluster[i])
			continue;

		if (cluster_is_in_top_delta(ploop, i + off) && piwb->type == PIWB_TYPE_ALLOC) {
			WARN_ON(bat_entries[i] != dst_cluster[i]);
			continue;
		}

		if (success) {
			bat_entries[i] = dst_cluster[i];
			md->bat_levels[i] = top_level(ploop);
		} else {
			/*
			 * Despite set_bit() is atomic, we take read_lock()
			 * to access ploop->bat_entries[] above (really it's
			 * not need, since new wb to this page can't start
			 * before this wb is ended).
			 */
			ploop_hole_set_bit(i + off, ploop);
		}
	}

	ploop_bat_unlock(ploop, success, flags);
	kunmap_atomic(dst_cluster);
	kunmap_atomic(bat_entries);
}

static void put_piwb(struct ploop_index_wb *piwb)
{
	if (atomic_dec_and_test(&piwb->count)) {
		struct ploop *ploop = piwb->ploop;
		/*
		 * Index wb failed. Mark clusters as unallocated again.
		 * piwb->count is zero, so all data writers compeleted.
		 */
		if (piwb->bi_status)
			ploop_advance_local_after_bat_wb(ploop, piwb, false);

		complete(&piwb->comp);
	}
}

/* This handler is called after BAT is updated. */
static void ploop_bat_write_complete(struct ploop_index_wb *piwb,
				     blk_status_t bi_status)
{
	struct ploop *ploop = piwb->ploop;
	struct pio *cluster_pio;
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
	while ((data_pio = pio_list_pop(&piwb->ready_data_pios)) != NULL) {
		if (bi_status)
			data_pio->bi_status = bi_status;
		pio_endio(data_pio);
	}

	while ((cluster_pio = pio_list_pop(&piwb->cow_list))) {
		cow = cluster_pio->endio_cb_data;
		complete_cow(cow, bi_status);
	}

	/*
	 * In case of update BAT is failed, dst_clusters will be
	 * set back to holes_bitmap on last put_piwb().
	 */
	put_piwb(piwb);
}

static int ploop_prepare_bat_update(struct ploop *ploop, unsigned int page_nr,
				    struct ploop_index_wb *piwb)
{
	unsigned int i, off, last, *bat_entries;
	bool is_last_page = true;
	struct md_page *md;
	struct page *page;
	map_index_t *to;

	piwb->bat_page = page = alloc_page(GFP_NOIO);
	if (!page)
		return -ENOMEM;

	md = md_page_find(ploop, page_nr);
	BUG_ON(!md);
	bat_entries = kmap_atomic(md->page);

	piwb->page_nr = page_nr;
	to = kmap_atomic(page);
	memcpy((void *)to, bat_entries, PAGE_SIZE);

	/* Absolute number of first index in page (negative for page#0) */
	off = page_nr * PAGE_SIZE / sizeof(map_index_t);
	off -= PLOOP_MAP_OFFSET;

	/* Last and first index in copied page */
	last = ploop->nr_bat_entries - off;
	if (last > PAGE_SIZE / sizeof(map_index_t)) {
		last = PAGE_SIZE / sizeof(map_index_t);
		is_last_page = false;
	}
	i = 0;
	if (!page_nr)
		i = PLOOP_MAP_OFFSET;

	/* Copy BAT (BAT goes right after hdr, see .ctr) */
	for (; i < last; i++) {
		if (cluster_is_in_top_delta(ploop, i + off))
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
	return 0;
}

void ploop_reset_bat_update(struct ploop_index_wb *piwb)
{
	struct ploop *ploop = piwb->ploop;

	put_page(piwb->bat_page);
	ploop_index_wb_init(piwb, ploop);
}

static void ploop_bat_page_zero_cluster(struct ploop *ploop,
					struct ploop_index_wb *piwb,
					unsigned int cluster)
{
	map_index_t *to;

	/* Cluster index related to the page[page_nr] start */
	cluster = bat_clu_idx_in_page(cluster);

	to = kmap_atomic(piwb->bat_page);
	to[cluster] = 0;
	kunmap_atomic(to);
}

static int find_dst_cluster_bit(struct ploop *ploop,
		      unsigned int *ret_dst_cluster)
{
	unsigned int dst_cluster;

	WARN_ON_ONCE(!(current->flags & PF_WQ_WORKER));

	/* Find empty cluster */
	dst_cluster = find_first_bit(ploop->holes_bitmap, ploop->hb_nr);
	if (dst_cluster >= ploop->hb_nr)
		return -EIO;
	*ret_dst_cluster = dst_cluster;
	return 0;
}

static int truncate_prealloc_safe(struct ploop_delta *delta, loff_t len, const char *func)
{
	struct file *file = delta->file;
	loff_t new_len = len;
	int ret;

	if (new_len <= delta->file_size)
		return 0;
	new_len = ALIGN(new_len, PREALLOC_SIZE);

	ret = vfs_truncate(&file->f_path, new_len);
	if (ret) {
		pr_err("ploop: %s->truncate(): %d\n", func, ret);
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

static int allocate_cluster(struct ploop *ploop, unsigned int *dst_cluster)
{
	struct ploop_delta *top = top_delta(ploop);
	u32 clu_size = CLU_SIZE(ploop);
	loff_t off, pos, end, old_size;
	struct file *file = top->file;
	int ret;

	if (find_dst_cluster_bit(ploop, dst_cluster) < 0)
		return -EIO;

	pos = CLU_TO_POS(ploop, *dst_cluster);
	end = pos + clu_size;
	old_size = top->file_size;

	if (pos < top->file_preallocated_area_start) {
		/* Clu at @pos may contain dirty data */
		off = min_t(loff_t, old_size, end);
		ret = punch_hole(file, pos, off - pos);
		if (ret) {
			pr_err("ploop: punch hole: %d\n", ret);
			return ret;
		}
	}

	if (end > old_size) {
		ret = truncate_prealloc_safe(top, end, __func__);
		if (ret)
			return ret;
	} else if (pos < top->file_preallocated_area_start) {
		/*
		 * Flush punch_hole() modifications.
		 * TODO: track recentry unused blocks
		 * and punch holes in background.
		 */
		ret = vfs_fsync(file, 0);
		if (ret)
			return ret;
	}

	if (end > top->file_preallocated_area_start)
		top->file_preallocated_area_start = end;
	/*
	 * Mark cluster as used. Find & clear bit is unlocked,
	 * since currently this may be called only from deferred
	 * kwork. Note, that set_bit may be made from many places.
	 */
	ploop_hole_clear_bit(*dst_cluster, ploop);
	return 0;
}

/*
 * This finds a free dst_cluster on origin device, and reflects this
 * in ploop->holes_bitmap and bat_page.
 */
static int ploop_alloc_cluster(struct ploop *ploop, struct ploop_index_wb *piwb,
			       unsigned int cluster, unsigned int *dst_cluster)
{
	struct page *page = piwb->bat_page;
	bool already_alloced = false;
	map_index_t *to;
	int ret = 0;

	/* Cluster index related to the page[page_nr] start */
	cluster -= piwb->page_nr * PAGE_SIZE / sizeof(map_index_t) - PLOOP_MAP_OFFSET;

	to = kmap_atomic(page);
	if (to[cluster]) {
		/* Already mapped by one of previous bios */
		*dst_cluster = to[cluster];
		already_alloced = true;
	}
	kunmap_atomic(to);

	if (already_alloced)
		goto out;

	if (allocate_cluster(ploop, dst_cluster) < 0) {
		ret = -EIO;
		goto out;
	}

	to = kmap_atomic(page);
	to[cluster] = *dst_cluster;
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

	put_piwb(piwb);

	return completed;
}

static bool ploop_attach_end_action(struct pio *pio, struct ploop_index_wb *piwb)
{
	/* Currently this can't fail. */
	if (!atomic_inc_not_zero(&piwb->count))
		return false;

	pio->is_data_alloc = true;
	pio->piwb = piwb;

	return true;
}

static void data_rw_complete(struct pio *pio)
{
	bool completed;

	if (pio->ret != pio->bi_iter.bi_size)
                pio->bi_status = BLK_STS_IOERR;

	if (pio->is_data_alloc) {
		completed = ploop_data_pio_end(pio);
		if (!completed)
			return;
	}

	pio_endio(pio);
}

void submit_rw_mapped(struct ploop *ploop, u32 dst_clu, struct pio *pio, u8 level)
{
	unsigned int rw, nr_segs;
	struct bio_vec *bvec;
	struct iov_iter iter;
	struct file *file;
	loff_t pos;

	BUG_ON(level > top_level(ploop));

	pio->complete = data_rw_complete;

	rw = (op_is_write(pio->bi_op) ? WRITE : READ);
	nr_segs = pio_nr_segs(pio);
	bvec = __bvec_iter_bvec(pio->bi_io_vec, pio->bi_iter);

	iov_iter_bvec(&iter, rw, bvec, nr_segs, pio->bi_iter.bi_size);
	iter.iov_offset = pio->bi_iter.bi_bvec_done;

	remap_to_cluster(ploop, pio, dst_clu);
	pos = to_bytes(pio->bi_iter.bi_sector);

	file = ploop->deltas[level].file;
	ploop_call_rw_iter(file, pos, rw, &iter, pio);
}

/*
 * Read cluster or its part from secondary delta.
 * Note, that nr inflight is not incremented here, so delegate this to caller
 * (if you need).
 */
static void submit_delta_read(struct ploop *ploop, unsigned int level,
			    unsigned int dst_cluster, struct pio *pio)
{
	struct bio_vec *bvec;
	struct iov_iter iter;
	unsigned int offset;
	struct file *file;
	loff_t pos;

	pio->complete = data_rw_complete;

	remap_to_cluster(ploop, pio, dst_cluster);

	bvec = __bvec_iter_bvec(pio->bi_io_vec, pio->bi_iter);
	offset = pio->bi_iter.bi_bvec_done;

	iov_iter_bvec(&iter, READ, bvec, 1, pio->bi_iter.bi_size);
	iter.iov_offset = offset;

	pos = (pio->bi_iter.bi_sector << SECTOR_SHIFT);
	file = ploop->deltas[level].file;

	ploop_call_rw_iter(file, pos, READ, &iter, pio);
}

static void initiate_delta_read(struct ploop *ploop, unsigned int level,
				unsigned int dst_cluster, struct pio *pio)
{
	if (dst_cluster == BAT_ENTRY_NONE) {
		/* No one delta contains dst_cluster. */
		zero_fill_pio(pio);
		pio_endio(pio);
		return;
	}

	submit_delta_read(ploop, level, dst_cluster, pio);
}

static void ploop_cow_endio(struct pio *cluster_pio, void *data, blk_status_t bi_status)
{
	struct ploop_cow *cow = data;
	struct ploop *ploop = cow->ploop;
	unsigned long flags;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	list_add_tail(&cluster_pio->list, &ploop->delta_cow_action_list);
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	queue_work(ploop->wq, &ploop->worker);
}

static bool postpone_if_cluster_locked(struct ploop *ploop, struct pio *pio,
				       unsigned int cluster)
{
	struct pio *e_h; /* Exclusively locked */

	spin_lock_irq(&ploop->deferred_lock);
	e_h = find_lk_of_cluster(ploop, cluster);
	if (e_h)
		add_endio_pio(e_h, pio);
	spin_unlock_irq(&ploop->deferred_lock);

	return e_h != NULL;
}

int submit_cluster_cow(struct ploop *ploop, unsigned int level,
		       unsigned int cluster, unsigned int dst_cluster,
		       void (*end_fn)(struct ploop *, int, void *), void *data)
{
	struct ploop_cow *cow = NULL;
	struct pio *pio = NULL;

	/* Prepare new delta read */
	pio = alloc_pio_with_pages(ploop);
	cow = kmem_cache_alloc(cow_cache, GFP_NOIO);
	if (!pio || !cow)
		goto err;
	init_pio(ploop, REQ_OP_READ, pio);
	pio_prepare_offsets(ploop, pio, cluster);
	pio->endio_cb = ploop_cow_endio;
	pio->endio_cb_data = cow;

	cow->ploop = ploop;
	cow->dst_cluster = BAT_ENTRY_NONE;
	cow->cluster_pio = pio;
	cow->end_fn = end_fn;
	cow->data = data;

	init_pio(ploop, REQ_OP_WRITE, &cow->aux_pio);
	add_cluster_lk(ploop, &cow->aux_pio, cluster);

	/* Stage #0: read secondary delta full cluster */
	submit_delta_read(ploop, level, dst_cluster, pio);
	return 0;
err:
	if (pio)
		free_pio_with_pages(ploop, pio);
	kfree(cow);
	return -ENOMEM;
}

static void queue_or_fail(struct ploop *ploop, int err, void *data)
{
	struct pio *pio = data;

	/* FIXME: do we use BLK_STS_AGAIN? */
	if (err && err != BLK_STS_AGAIN) {
		pio->bi_status = errno_to_blk_status(err);
		pio_endio(pio);
	} else {
		defer_pios(ploop, pio, NULL);
	}
}

static void initiate_cluster_cow(struct ploop *ploop, unsigned int level,
		unsigned int cluster, unsigned int dst_cluster, struct pio *pio)
{
	if (!submit_cluster_cow(ploop, level, cluster, dst_cluster,
				queue_or_fail, pio))
		return;

	pio->bi_status = BLK_STS_RESOURCE;
	pio_endio(pio);
}

static void submit_cluster_write(struct ploop_cow *cow)
{
	struct pio *pio = cow->cluster_pio;
	struct ploop *ploop = cow->ploop;
	unsigned int dst_cluster;

	if (allocate_cluster(ploop, &dst_cluster) < 0)
		goto error;
	cow->dst_cluster = dst_cluster;

	init_pio(ploop, REQ_OP_WRITE, pio);
	pio_prepare_offsets(ploop, pio, dst_cluster);

	BUG_ON(irqs_disabled());
	pio->endio_cb = ploop_cow_endio;
	pio->endio_cb_data = cow;

	submit_rw_mapped(ploop, dst_cluster, pio, top_level(ploop));
	return;
error:
	complete_cow(cow, BLK_STS_IOERR);
}

static void submit_cow_index_wb(struct ploop_cow *cow,
				struct ploop_index_wb *piwb)
{
	struct pio *aux_pio = &cow->aux_pio;
	unsigned int cluster = aux_pio->cluster;
	struct ploop *ploop = cow->ploop;
	unsigned int page_nr;
	map_index_t *to;

	page_nr = bat_clu_to_page_nr(cluster);

	if (piwb->page_nr == PAGE_NR_NONE) {
		/* No index wb in process. Prepare a new one */
		if (ploop_prepare_bat_update(ploop, page_nr, piwb) < 0)
			goto err_resource;
	}

	if (piwb->page_nr != page_nr || piwb->type != PIWB_TYPE_ALLOC) {
		/* Another BAT page wb is in process */
		spin_lock_irq(&ploop->deferred_lock);
		list_add_tail(&cow->cluster_pio->list,
			      &ploop->delta_cow_action_list);
		spin_unlock_irq(&ploop->deferred_lock);
		queue_work(ploop->wq, &ploop->worker);
		goto out;
	}

	cluster -= page_nr * PAGE_SIZE / sizeof(map_index_t) - PLOOP_MAP_OFFSET;

	to = kmap_atomic(piwb->bat_page);
	WARN_ON(to[cluster]);
	to[cluster] = cow->dst_cluster;
	kunmap_atomic(to);

	/* Prevent double clearing of holes_bitmap bit on complete_cow() */
	cow->dst_cluster = BAT_ENTRY_NONE;
	spin_lock_irq(&ploop->deferred_lock);
	list_add_tail(&cow->cluster_pio->list, &piwb->cow_list);
	spin_unlock_irq(&ploop->deferred_lock);
out:
	return;
err_resource:
	complete_cow(cow, BLK_STS_RESOURCE);
}

static void process_delta_wb(struct ploop *ploop, struct ploop_index_wb *piwb)
{
	struct pio *cluster_pio;
	struct ploop_cow *cow;
	LIST_HEAD(cow_list);

	if (list_empty(&ploop->delta_cow_action_list))
		return;
	list_splice_tail_init(&ploop->delta_cow_action_list, &cow_list);
	spin_unlock_irq(&ploop->deferred_lock);

	while ((cluster_pio = pio_list_pop(&cow_list)) != NULL) {
		cow = cluster_pio->endio_cb_data;
		if (unlikely(cluster_pio->bi_status != BLK_STS_OK)) {
			complete_cow(cow, cluster_pio->bi_status);
			continue;
		}

		if (cow->dst_cluster == BAT_ENTRY_NONE) {
			/*
			 * Stage #1: assign dst_cluster and write data
			 * to top delta.
			 */
			submit_cluster_write(cow);
		} else {
			/*
			 * Stage #2: data is written to top delta.
			 * Update index.
			 */
			submit_cow_index_wb(cow, piwb);
		}
	}

	spin_lock_irq(&ploop->deferred_lock);
}

/*
 * This allocates a new cluster (if cluster wb is not pending yet),
 * or tries to attach a bio to a planned page index wb.
 *
 * We want to update BAT indexes in batch, but we don't want to delay data
 * bios submitting till the batch is assembled, submitted and completed.
 * This function tries to submit data bios before indexes are written
 * on disk.
 * Original bio->bi_end_io mustn't be called before index wb is completed.
 * We handle this in ploop_attach_end_action() by specific callback
 * for ploop_data_pio_end().
 * Note: cluster newer becomes locked here, since index update is called
 * synchronously. Keep in mind this in case you make it async.
 */
static bool locate_new_cluster_and_attach_pio(struct ploop *ploop,
					      struct ploop_index_wb *piwb,
					      unsigned int cluster,
					      unsigned int *dst_cluster,
					      struct pio *pio)
{
	bool bat_update_prepared = false;
	bool attached = false;
	unsigned int page_nr;

	page_nr = bat_clu_to_page_nr(cluster);

	if (piwb->page_nr == PAGE_NR_NONE) {
		/* No index wb in process. Prepare a new one */
		if (ploop_prepare_bat_update(ploop, page_nr, piwb) < 0) {
			pio->bi_status = BLK_STS_RESOURCE;
			goto error;
		}
		bat_update_prepared = true;
	}

	if (piwb->page_nr != page_nr || piwb->type != PIWB_TYPE_ALLOC) {
		/* Another BAT page wb is in process */
		defer_pios(ploop, pio, NULL);
		goto out;
	}

	if (ploop_alloc_cluster(ploop, piwb, cluster, dst_cluster)) {
		pio->bi_status = BLK_STS_IOERR;
		goto error;
	}

	attached = ploop_attach_end_action(pio, piwb);
	if (!attached) {
		/*
		 * Could not prepare data pio to be submitted before index wb
		 * batch? Delay submitting. Good thing, that cluster allocation
		 * has already made, and it goes in the batch.
		 */
		defer_pios(ploop, pio, NULL);
	}
out:
	return attached;
error:
	/* Uninit piwb */
	if (bat_update_prepared)
		ploop_reset_bat_update(piwb);
	pio_endio(pio);
	return false;
}

static int process_one_deferred_bio(struct ploop *ploop, struct pio *pio,
				    struct ploop_index_wb *piwb)
{
	sector_t sector = pio->bi_iter.bi_sector;
	unsigned int cluster, dst_cluster;
	u8 level;
	bool ret;

	/*
	 * Unlocked, since no one can update BAT in parallel:
	 * we update BAT only 1)from *this* kwork, and 2)from
	 * ploop_advance_local_after_bat_wb(), which we start
	 * and wait synchronously from *this* kwork.
	 */
	cluster = SEC_TO_CLU(ploop, sector);
	dst_cluster = ploop_bat_entries(ploop, cluster, &level);

	if (postpone_if_cluster_locked(ploop, pio, cluster))
		goto out;

	if (op_is_discard(pio->bi_op)) {
		handle_discard_pio(ploop, pio, cluster, dst_cluster);
		goto out;
	}

	if (cluster_is_in_top_delta(ploop, cluster)) {
		/* Already mapped */
		goto queue;
	} else if (!op_is_write(pio->bi_op)) {
		/*
		 * Simple read from secondary delta. May fail.
		 * (Also handles the case dst_cluster == BAT_ENTRY_NONE).
		 */
		initiate_delta_read(ploop, level, dst_cluster, pio);
		goto out;
	} else if (dst_cluster != BAT_ENTRY_NONE) {
		/*
		 * Read secondary delta and write to top delta. May fail.
		 * Yes, we can optimize the whole-cluster-write case and
		 * a lot of other corner cases, but we don't do that as
		 * snapshots are used and COW occurs very rare.
		 */
		initiate_cluster_cow(ploop, level, cluster, dst_cluster, pio);
		goto out;
	}

	if (unlikely(pio_endio_if_all_zeros(pio)))
		goto out;

	/* Cluster exists nowhere. Allocate it and setup pio as outrunning */
	ret = locate_new_cluster_and_attach_pio(ploop, piwb, cluster,
						&dst_cluster, pio);
	if (!ret)
		goto out;
queue:
	link_submitting_pio(ploop, pio, cluster);

	submit_rw_mapped(ploop, dst_cluster, pio, top_level(ploop));
out:
	return 0;
}

void ploop_submit_index_wb_sync(struct ploop *ploop,
				struct ploop_index_wb *piwb)
{
	blk_status_t status = BLK_STS_OK;
	u32 dst_cluster;
	int ret;

	/* track_bio() will be called in ploop_bat_write_complete() */

	ret = ploop_rw_page_sync(WRITE, top_delta(ploop)->file,
				 piwb->page_nr, piwb->bat_page);
	if (ret)
		status = errno_to_blk_status(ret);

	dst_cluster = ((u64)piwb->page_nr << PAGE_SHIFT) / CLU_SIZE(ploop);
	track_dst_cluster(ploop, dst_cluster);

	ploop_bat_write_complete(piwb, status);
	wait_for_completion(&piwb->comp);
}

static void process_deferred_pios(struct ploop *ploop, struct list_head *pios,
				  struct ploop_index_wb *piwb)
{
	struct pio *pio;

	while ((pio = pio_list_pop(pios)) != NULL)
		process_one_deferred_bio(ploop, pio, piwb);
}

static int process_one_discard_pio(struct ploop *ploop, struct pio *pio,
				   struct ploop_index_wb *piwb)
{
	unsigned int page_nr, cluster;
	bool bat_update_prepared;
	map_index_t *to;

	WARN_ON(ploop->nr_deltas != 1);

	cluster = pio->cluster;
	page_nr = bat_clu_to_page_nr(cluster);
	bat_update_prepared = false;

	if (piwb->page_nr == PAGE_NR_NONE) {
		/* No index wb in process. Prepare a new one */
		if (ploop_prepare_bat_update(ploop, page_nr, piwb) < 0) {
			pio->bi_status = BLK_STS_RESOURCE;
			pio_endio(pio);
			goto out;
		}
		piwb->type = PIWB_TYPE_DISCARD;
		bat_update_prepared = true;
	}

	if (piwb->page_nr != page_nr || piwb->type != PIWB_TYPE_DISCARD) {
		queue_discard_index_wb(ploop, pio);
		goto out;
	}

	/* Cluster index related to the page[page_nr] start */
	cluster -= piwb->page_nr * PAGE_SIZE / sizeof(map_index_t) - PLOOP_MAP_OFFSET;

	to = kmap_atomic(piwb->bat_page);
	if (WARN_ON_ONCE(!to[cluster])) {
		pio->bi_status = BLK_STS_IOERR;
		pio_endio(pio);
		if (bat_update_prepared)
			ploop_reset_bat_update(piwb);
	} else {
		to[cluster] = 0;
		list_add_tail(&pio->list, &piwb->ready_data_pios);
	}
	kunmap_atomic(to);
out:
	return 0;
}

static void process_discard_pios(struct ploop *ploop, struct list_head *pios,
				 struct ploop_index_wb *piwb)
{
	struct pio *pio;

	while ((pio = pio_list_pop(pios)) != NULL)
		process_one_discard_pio(ploop, pio, piwb);
}

void do_ploop_work(struct work_struct *ws)
{
	struct ploop *ploop = container_of(ws, struct ploop, worker);
	struct ploop_index_wb piwb;
	LIST_HEAD(deferred_pios);
	LIST_HEAD(discard_pios);
	unsigned int pf_io_thread = (current->flags & PF_IO_THREAD);

	current->flags |= PF_IO_THREAD;

	/*
	 * In piwb we collect inquires of indexes updates, which are
	 * related to the same page (of PAGE_SIZE), and then we submit
	 * all of them in batch in ploop_submit_index_wb_sync().
	 *
	 * Currenly, it's impossible to submit two bat pages update
	 * in parallel, since the update uses global ploop->bat_page.
	 * Note, that process_deferred_cmd() expects there is no
	 * pending index wb.
	 */
	ploop_index_wb_init(&piwb, ploop);

	spin_lock_irq(&ploop->deferred_lock);
	process_deferred_cmd(ploop, &piwb);
	process_delta_wb(ploop, &piwb);

	list_splice_init(&ploop->deferred_pios, &deferred_pios);
	list_splice_init(&ploop->discard_pios, &discard_pios);
	spin_unlock_irq(&ploop->deferred_lock);

	process_deferred_pios(ploop, &deferred_pios, &piwb);
	process_discard_pios(ploop, &discard_pios, &piwb);

	if (piwb.page_nr != PAGE_NR_NONE) {
		/* Index wb was prepared -- submit and wait it */
		ploop_submit_index_wb_sync(ploop, &piwb);
		ploop_reset_bat_update(&piwb);
	}

	current->flags = (current->flags & ~PF_IO_THREAD) | pf_io_thread;
}

void do_ploop_fsync_work(struct work_struct *ws)
{
	struct ploop *ploop = container_of(ws, struct ploop, fsync_worker);
	LIST_HEAD(flush_pios);
	struct file *file;
	struct pio *pio;
	int ret;

	spin_lock_irq(&ploop->deferred_lock);
	list_splice_init(&ploop->flush_pios, &flush_pios);
	spin_unlock_irq(&ploop->deferred_lock);

	file = top_delta(ploop)->file;
	ret = vfs_fsync(file, 0);

	while ((pio = pio_list_pop(&flush_pios)) != NULL) {
		if (unlikely(ret))
			pio->bi_status = errno_to_blk_status(ret);
		pio_endio(pio);
	}
}

static void init_prq(struct ploop_rq *prq, struct request *rq)
{
	prq->rq = rq;
	prq->bvec = NULL;
}

static noinline struct bio_vec *create_bvec_from_rq(struct request *rq)
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

static void submit_pio(struct ploop *ploop, struct pio *pio)
{
	struct list_head *queue_list;
	struct work_struct *worker;
	unsigned long flags;
	bool queue = true;
	LIST_HEAD(list);
	int ret;

	if (pio->bi_iter.bi_size) {
		queue_list = &ploop->deferred_pios;
		worker = &ploop->worker;

		if (ploop_pio_valid(ploop, pio) < 0)
			goto kill;

		ret = split_pio_to_list(ploop, pio, &list);
		if (ret) {
			pio->bi_status = BLK_STS_RESOURCE;
			goto endio;
		}
	} else {
		queue_list = &ploop->flush_pios;
		worker = &ploop->fsync_worker;

		if (WARN_ON_ONCE(pio->bi_op != REQ_OP_FLUSH))
			goto kill;
	}

	list_add(&pio->list, &list);

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	if (unlikely(ploop->stop_submitting_pios)) {
		list_splice_tail(&list, &ploop->delayed_pios);
		queue = false;
		goto unlock;
	}

	inc_nr_inflight(ploop, pio);
	list_splice_tail(&list, queue_list);
unlock:
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	if (queue)
		queue_work(ploop->wq, worker);
	return;
kill:
	pio->bi_status = BLK_STS_IOERR;
endio:
	pio_endio(pio);
}

void submit_pios(struct ploop *ploop, struct list_head *list)
{
        struct pio *pio;

        while ((pio = pio_list_pop(list)) != NULL)
                submit_pio(ploop, pio);
}

int ploop_clone_and_map(struct dm_target *ti, struct request *rq,
		    union map_info *info, struct request **clone)
{
	struct ploop *ploop = ti->private;
	struct bio_vec *bvec = NULL;
	struct ploop_rq *prq;
	struct pio *pio;

	prq = map_info_to_prq(info);
	init_prq(prq, rq);

	pio = map_info_to_pio(info); /* Embedded pio */
	init_pio(ploop, req_op(rq), pio);

	if (rq->bio != rq->biotail) {
		if (req_op(rq) == REQ_OP_DISCARD)
			goto skip_bvec;
		/*
		 * Transform a set of bvec arrays related to bios
		 * into a single bvec array (which we can iterate).
		 */
		bvec = create_bvec_from_rq(rq);
		if (!bvec)
			return DM_MAPIO_KILL;
		prq->bvec = bvec;
skip_bvec:
		pio->bi_iter.bi_sector = blk_rq_pos(rq);
		pio->bi_iter.bi_size = blk_rq_bytes(rq);
		pio->bi_iter.bi_idx = 0;
		pio->bi_iter.bi_bvec_done = 0;
        } else if (rq->bio) {
                /* Single bio already provides bvec array */
		bvec = rq->bio->bi_io_vec;

		pio->bi_iter = rq->bio->bi_iter;
        } /* else FLUSH */

        pio->bi_io_vec = bvec;
        pio->endio_cb = prq_endio;
        pio->endio_cb_data = prq;

	submit_pio(ploop, pio);
	return DM_MAPIO_SUBMITTED;
}

static void handle_cleanup(struct ploop *ploop, struct pio *pio)
{
	/*
	 * This function is called from the very beginning
	 * of call_bio_endio().
	 *
	 * DM_ENDIO_DONE return value means handling goes OK.
	 * DM_ENDIO_INCOMPLETE tells the caller to stop end io
	 * processing, and that we are going to call bi_end_io
	 * directly later again.
	 */
	if (pio->wants_discard_index_cleanup)
		ploop_discard_index_pio_end(ploop, pio);

	unlink_completed_pio(ploop, pio);
	dec_nr_inflight(ploop, pio);
}

/*
 * Prepare simple index writeback without attached data bios.
 * In case of @dst_cluster is passed, this tryes to allocate
 * another index instead of existing. If so, management of
 * old bat_entries[@cluster] and of related holes_bitmap bit
 * is caller duty.
 */
int ploop_prepare_reloc_index_wb(struct ploop *ploop,
				 struct ploop_index_wb *piwb,
				 unsigned int cluster,
				 unsigned int *dst_cluster)
{
	unsigned int page_nr = bat_clu_to_page_nr(cluster);

	if (piwb->page_nr != PAGE_NR_NONE ||
	    ploop_prepare_bat_update(ploop, page_nr, piwb))
		goto out_eio;
	if (dst_cluster) {
		/*
		 * For ploop_advance_local_after_bat_wb(): do not concern
		 * about bat_cluster[@cluster] is set. Zero bat_page[@cluster],
		 * to make ploop_alloc_cluster() allocate new dst_cluster from
		 * holes_bitmap.
		 */
		piwb->type = PIWB_TYPE_RELOC;
		ploop_bat_page_zero_cluster(ploop, piwb, cluster);
		if (ploop_alloc_cluster(ploop, piwb, cluster, dst_cluster))
			goto out_reset;
	}

	return 0;

out_reset:
	ploop_reset_bat_update(piwb);
out_eio:
	return -EIO;
}
