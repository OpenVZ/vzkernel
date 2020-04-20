#include <linux/buffer_head.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/uio.h>
#include "dm-ploop.h"

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
 * WRITE) are linked to inflight_bios_rbtree. Discard bios are linked into
 * exclusive_bios_rbtree, but their start is delayed till all not-exclusive
 * bios going into the same cluster are finished. After exclusive bio is
 * started, the corresponding cluster becomes "locked", and all further bios
 * going into the same cluster becomes delayed.
 * Since the swithing into the mode is expensive, ploop remains in the mode
 * for CLEANUP_DELAY seconds in a hope that a new discard bio will come.
 * After this interval the device returns into normal mode, and ordinary bios
 * become handled in ploop_map() as before.
 */

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

static void ploop_index_wb_init(struct ploop_index_wb *piwb, struct ploop *ploop)
{
	piwb->ploop = ploop;
	init_completion(&piwb->comp);
	spin_lock_init(&piwb->lock);
	piwb->bat_page = NULL;
	piwb->bat_bio = NULL;
	piwb->bi_status = 0;
	bio_list_init(&piwb->ready_data_bios);
	bio_list_init(&piwb->cow_list);
	/* For ploop_bat_write_complete() */
	atomic_set(&piwb->count, 1);
	piwb->completed = false;
	piwb->page_nr = PAGE_NR_NONE;
	piwb->type = PIWB_TYPE_ALLOC;
}

static struct dm_ploop_endio_hook *bio_to_endio_hook(struct bio *bio)
{
	return dm_per_bio_data(bio, sizeof(struct dm_ploop_endio_hook));
}

static void __ploop_init_end_io(struct ploop *ploop,
				struct dm_ploop_endio_hook *h)
{
	h->action = PLOOP_END_IO_NONE;
	h->ref_index = PLOOP_REF_INDEX_INVALID;
	h->piwb = NULL;
	memset(&h->list, 0, sizeof(h->list));
	h->endio_bio_list = NULL;
	/* FIXME: assign real cluster? */
	h->cluster = UINT_MAX;
	RB_CLEAR_NODE(&h->node);
}

static void ploop_init_end_io(struct ploop *ploop, struct bio *bio)
{
	struct dm_ploop_endio_hook *h = bio_to_endio_hook(bio);

	__ploop_init_end_io(ploop, h);
}

/* Get cluster related to bio sectors */
static int ploop_bio_cluster(struct ploop *ploop, struct bio *bio,
			     unsigned int *ret_cluster)
{
	sector_t sector = bio->bi_iter.bi_sector;
	unsigned int cluster, end_cluster;
	loff_t end_byte;

	cluster = sector >> ploop->cluster_log;
	end_byte = ((sector << 9) + bio->bi_iter.bi_size - 1);
	end_cluster = end_byte >> (ploop->cluster_log + 9);

	if (unlikely(cluster > ploop->nr_bat_entries) ||
		     cluster != end_cluster) {
		/*
		 * This mustn't happen, since we set max_io_len
		 * via dm_set_target_max_io_len().
		 */
		WARN_ONCE(1, "sec=%lu, size=%u, clu=%u, end=%u, nr=%u\n",
			  sector, bio->bi_iter.bi_size, cluster,
			  end_cluster, ploop->nr_bat_entries);
		return -EINVAL;
	}

	*ret_cluster = cluster;
	return 0;
}

void defer_bio(struct ploop *ploop, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	bio_list_add(&ploop->deferred_bios, bio);
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	queue_work(ploop->wq, &ploop->worker);
}

void defer_bio_list(struct ploop *ploop, struct bio_list *bio_list)
{
	unsigned long flags;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	bio_list_merge(&ploop->deferred_bios, bio_list);
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);
	queue_work(ploop->wq, &ploop->worker);
}

/*
 * Userspace calls dm_suspend() to get changed blocks finally.
 * dm_suspend() waits for dm's inflight bios, so this function
 * must be called after @bio is written and before @bio is ended.
 * The only possible exception is writes driven by "message" ioctl.
 * Thus, userspace mustn't do maintaince operations in parallel
 * with tracking.
 */
void __track_bio(struct ploop *ploop, struct bio *bio)
{
	unsigned int dst_cluster = bio->bi_iter.bi_sector >> ploop->cluster_log;
	unsigned long flags;

	if (!op_is_write(bio->bi_opf) || !bio_sectors(bio))
		return;

	WARN_ON_ONCE(bio->bi_disk != ploop->origin_dev->bdev->bd_disk);

	read_lock_irqsave(&ploop->bat_rwlock, flags);
	if (ploop->tracking_bitmap && !WARN_ON(dst_cluster >= ploop->tb_nr))
		set_bit(dst_cluster, ploop->tracking_bitmap);
	read_unlock_irqrestore(&ploop->bat_rwlock, flags);
}

static void queue_discard_index_wb(struct ploop *ploop, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	bio_list_add(&ploop->discard_bios, bio);
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	queue_work(ploop->wq, &ploop->worker);
}

/* This 1)defers looking suitable discard bios and 2)ends the rest of them. */
static int ploop_map_discard(struct ploop *ploop, struct bio *bio)
{
	bool supported = false;
	unsigned int cluster;
	unsigned long flags;

	/* Only whole cluster in no-snapshots case can be discarded. */
	if (whole_cluster(ploop, bio)) {
		cluster = bio->bi_iter.bi_sector >> ploop->cluster_log;
		read_lock_irqsave(&ploop->bat_rwlock, flags);
		/* Early checks to not wake up work for nought. */
		if (cluster_is_in_top_delta(ploop, cluster) &&
		    !ploop->nr_deltas)
			supported = true;
		read_unlock_irqrestore(&ploop->bat_rwlock, flags);
	}

	if (supported) {
		defer_bio(ploop, bio);
	} else {
		bio->bi_status = BLK_STS_NOTSUPP;
		bio_endio(bio);
	}

	return DM_MAPIO_SUBMITTED;
}

struct dm_ploop_endio_hook *find_endio_hook_range(struct ploop *ploop,
						  struct rb_root *root,
						  unsigned int left,
						  unsigned int right)
{
	struct rb_node *node = root->rb_node;
	struct dm_ploop_endio_hook *h;

	while (node) {
		h = rb_entry(node, struct dm_ploop_endio_hook, node);
		if (right < h->cluster)
			node = node->rb_left;
		else if (left > h->cluster)
			node = node->rb_right;
		else
			return h;
	}

	return NULL;
}

static struct dm_ploop_endio_hook *find_inflight_bio(struct ploop *ploop,
						     unsigned int cluster)
{
	lockdep_assert_held(&ploop->deferred_lock);
	return find_endio_hook(ploop, &ploop->inflight_bios_rbtree, cluster);
}

struct dm_ploop_endio_hook *find_lk_of_cluster(struct ploop *ploop,
					       unsigned int cluster)
{
	lockdep_assert_held(&ploop->deferred_lock);
	return find_endio_hook(ploop, &ploop->exclusive_bios_rbtree, cluster);
}

static void add_endio_bio(struct dm_ploop_endio_hook *h, struct bio *later_bio)
{
	later_bio->bi_next = h->endio_bio_list;
	h->endio_bio_list = later_bio;
}

static void inc_nr_inflight_raw(struct ploop *ploop,
				struct dm_ploop_endio_hook *h)
{
	unsigned char ref_index = ploop->inflight_bios_ref_index;

	if (!WARN_ON_ONCE(h->ref_index != PLOOP_REF_INDEX_INVALID)) {
		percpu_ref_get(&ploop->inflight_bios_ref[ref_index]);
		h->ref_index = ref_index;
	}
}

static void inc_nr_inflight(struct ploop *ploop, struct bio *bio)
{
	struct dm_ploop_endio_hook *h = bio_to_endio_hook(bio);

	inc_nr_inflight_raw(ploop, h);
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
static void dec_nr_inflight_raw(struct ploop *ploop,
				struct dm_ploop_endio_hook *h)
{
	if (h->ref_index != PLOOP_REF_INDEX_INVALID) {
		percpu_ref_put(&ploop->inflight_bios_ref[h->ref_index]);
		h->ref_index = PLOOP_REF_INDEX_INVALID;
	}
}

static void dec_nr_inflight(struct ploop *ploop, struct bio *bio)
{
	struct dm_ploop_endio_hook *h = bio_to_endio_hook(bio);

	dec_nr_inflight_raw(ploop, h);
}

static void link_endio_hook(struct ploop *ploop, struct dm_ploop_endio_hook *new,
		      struct rb_root *root, unsigned int cluster, bool exclusive)
{
	struct rb_node *parent, **node = &root->rb_node;
	struct dm_ploop_endio_hook *h;

	BUG_ON(!RB_EMPTY_NODE(&new->node));
	parent = NULL;

	while (*node) {
		h = rb_entry(*node, struct dm_ploop_endio_hook, node);
		parent = *node;
		if (cluster < h->cluster)
			node = &parent->rb_left;
		else if (cluster > h->cluster)
			node = &parent->rb_right;
		else {
			if (exclusive)
				BUG();
			if (new < h)
				node = &parent->rb_left;
			else if (new > h)
				node = &parent->rb_right;
			else
				BUG();
		}
	}

	new->cluster = cluster;
	rb_link_node(&new->node, parent, node);
	rb_insert_color(&new->node, root);
}

/*
 * Removes endio hook of completed bio either from inflight_bios_rbtree
 * or from exclusive_bios_rbtree. BIOs from endio_bio_list are requeued
 * to deferred_list.
 */
static void unlink_endio_hook(struct ploop *ploop, struct rb_root *root,
		struct dm_ploop_endio_hook *h, struct bio_list *bio_list)
{
	struct bio *iter;

	BUG_ON(RB_EMPTY_NODE(&h->node));

	rb_erase(&h->node, root);
	RB_CLEAR_NODE(&h->node);
	while ((iter = h->endio_bio_list) != NULL) {
		h->endio_bio_list = iter->bi_next;
		iter->bi_next = NULL;
		bio_list_add(bio_list, iter);
	}
}

static void add_cluster_lk(struct ploop *ploop, struct dm_ploop_endio_hook *h,
			   unsigned int cluster)
{
	unsigned long flags;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	link_endio_hook(ploop, h, &ploop->exclusive_bios_rbtree, cluster, true);
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);
}
static void del_cluster_lk(struct ploop *ploop, struct dm_ploop_endio_hook *h)
{
	struct bio_list bio_list = BIO_EMPTY_LIST;
	unsigned long flags;
	bool queue = false;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	unlink_endio_hook(ploop, &ploop->exclusive_bios_rbtree, h, &bio_list);
	if (!bio_list_empty(&bio_list)) {
		bio_list_merge(&ploop->deferred_bios, &bio_list);
		queue = true;
	}
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	if (queue)
		queue_work(ploop->wq, &ploop->worker);

}

static void maybe_link_submitting_bio(struct ploop *ploop, struct bio *bio,
				      unsigned int cluster)
{
	struct dm_ploop_endio_hook *h = bio_to_endio_hook(bio);
	unsigned long flags;

	if (!ploop->force_link_inflight_bios)
		return;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	link_endio_hook(ploop, h, &ploop->inflight_bios_rbtree, cluster, false);
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);
}
static void maybe_unlink_completed_bio(struct ploop *ploop, struct bio *bio)
{
	struct dm_ploop_endio_hook *h = bio_to_endio_hook(bio);
	struct bio_list bio_list = BIO_EMPTY_LIST;
	unsigned long flags;
	bool queue = false;

	if (likely(RB_EMPTY_NODE(&h->node)))
		return;

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	unlink_endio_hook(ploop, &ploop->inflight_bios_rbtree, h, &bio_list);
	if (!bio_list_empty(&bio_list)) {
		bio_list_merge(&ploop->deferred_bios, &bio_list);
		queue = true;
	}
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	if (queue)
		queue_work(ploop->wq, &ploop->worker);
}

static void handle_discard_bio(struct ploop *ploop, struct bio *bio,
		     unsigned int cluster, unsigned int dst_cluster)
{
	struct dm_ploop_endio_hook *h = bio_to_endio_hook(bio);
	struct dm_ploop_endio_hook *inflight_h;
	unsigned long flags;
	int ret;

	if (!cluster_is_in_top_delta(ploop, cluster) || ploop->nr_deltas) {
enotsupp:
		bio->bi_status = BLK_STS_NOTSUPP;
		bio_endio(bio);
		return;
	}

	if (!ploop->force_link_inflight_bios) {
		/*
		 * Switch ploop to mode, when requests are handled
		 * from kwork only, and force all not exclusive
		 * inflight bios to link into inflight_bios_rbtree.
		 * Note, that this does not wait completion of
		 * two-stages requests (currently, these may be only
		 * cow, which take cluster lk, so we are safe with
		 * them).
		 */
		ploop->force_link_inflight_bios = true;
		force_defer_bio_count_inc(ploop);
		ret = ploop_inflight_bios_ref_switch(ploop, true);
		if (ret) {
			pr_err_ratelimited("ploop: discard ignored by err=%d\n",
					ret);
			ploop->force_link_inflight_bios = false;
			force_defer_bio_count_dec(ploop);
			goto enotsupp;
		}
	}

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	inflight_h = find_inflight_bio(ploop, cluster);
	if (inflight_h)
		add_endio_bio(inflight_h, bio);
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	if (inflight_h) {
		/* @bio will be requeued on inflight_h's bio end */
		pr_err_once("ploop: delayed discard: device is used as raw?\n");
		return;
	}

	h->action = PLOOP_END_IO_DISCARD_BIO;
	add_cluster_lk(ploop, h, cluster);

	read_lock_irq(&ploop->bat_rwlock);
	inc_nr_inflight(ploop, bio);
	read_unlock_irq(&ploop->bat_rwlock);
	atomic_inc(&ploop->nr_discard_bios);

	remap_to_cluster(ploop, bio, dst_cluster);
	remap_to_origin(ploop, bio);
	generic_make_request(bio);
}

static int ploop_discard_bio_end(struct ploop *ploop, struct bio *bio)
{
	struct dm_ploop_endio_hook *h = bio_to_endio_hook(bio);

	dec_nr_inflight(ploop, bio);
	if (bio->bi_status == BLK_STS_OK)
		queue_discard_index_wb(ploop, bio);
	else
		h->action = PLOOP_END_IO_DISCARD_INDEX_BIO;
	return DM_ENDIO_INCOMPLETE;
}

static int ploop_discard_index_bio_end(struct ploop *ploop, struct bio *bio)
{
	struct dm_ploop_endio_hook *h = bio_to_endio_hook(bio);

	del_cluster_lk(ploop, h);

	WRITE_ONCE(ploop->pending_discard_cleanup, jiffies);
	/* Pairs with barrier in do_discard_cleanup() */
	smp_mb__before_atomic();
	atomic_dec(&ploop->nr_discard_bios);
	return DM_ENDIO_DONE;
}

static void complete_cow(struct ploop_cow *cow, blk_status_t bi_status)
{
	unsigned int dst_cluster = cow->dst_cluster;
	struct bio *cluster_bio = cow->cluster_bio;
	struct ploop *ploop = cow->ploop;
	struct dm_ploop_endio_hook *h;
	unsigned long flags;

	WARN_ON_ONCE(cluster_bio->bi_next);
	h = &cow->hook;

	del_cluster_lk(ploop, h);

	if (dst_cluster != BAT_ENTRY_NONE && bi_status != BLK_STS_OK) {
		read_lock_irqsave(&ploop->bat_rwlock, flags);
		ploop_hole_set_bit(dst_cluster, ploop);
		read_unlock_irqrestore(&ploop->bat_rwlock, flags);
	}

	if (cow->end_fn)
		cow->end_fn(ploop, blk_status_to_errno(bi_status), cow->data);

	queue_work(ploop->wq, &ploop->worker);
	free_bio_with_pages(ploop, cow->cluster_bio);
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
		WARN_ON_ONCE(ploop->nr_deltas);
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
			md->bat_levels[i] = BAT_LEVEL_TOP;
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
static void ploop_bat_write_complete(struct bio *bio)
{
	struct ploop_index_wb *piwb = bio->bi_private;
	struct bio *data_bio, *cluster_bio;
	struct ploop *ploop = piwb->ploop;
	struct ploop_cow *cow;
	unsigned long flags;

	track_bio(ploop, bio);

	if (!bio->bi_status) {
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
	piwb->bi_status = bio->bi_status;
	spin_unlock_irqrestore(&piwb->lock, flags);

	/*
	 * End pending data bios. Unlocked, as nobody can
	 * add a new element after piwc->completed is true.
	 */
	while ((data_bio = bio_list_pop(&piwb->ready_data_bios))) {
		if (bio->bi_status)
			data_bio->bi_status = bio->bi_status;
		if (data_bio->bi_end_io)
			data_bio->bi_end_io(data_bio);
	}

	while ((cluster_bio = bio_list_pop(&piwb->cow_list))) {
		cow = cluster_bio->bi_private;
		complete_cow(cow, bio->bi_status);
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
	struct md_page *md;
	struct page *page;
	struct bio *bio;
	map_index_t *to;
	sector_t sector;

	piwb->bat_page = page = alloc_page(GFP_NOIO);
	if (!page)
		return -ENOMEM;
	piwb->bat_bio = bio = bio_alloc(GFP_NOIO, 1);
	if (!bio) {
		put_page(page);
		piwb->bat_page = NULL;
		return -ENOMEM;
	}

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
	if (last > PAGE_SIZE / sizeof(map_index_t))
		last = PAGE_SIZE / sizeof(map_index_t);
	i = 0;
	if (!page_nr)
		i = PLOOP_MAP_OFFSET;

	/* Copy BAT (BAT goes right after hdr, see .ctr) */
	for (; i < last; i++) {
		if (cluster_is_in_top_delta(ploop, i + off))
			continue;
		to[i] = 0;
	}

	kunmap_atomic(to);
	kunmap_atomic(bat_entries);

	sector = (page_nr * PAGE_SIZE) >> SECTOR_SHIFT;
	bio->bi_iter.bi_sector = sector;
	remap_to_origin(ploop, bio);

	bio->bi_private = piwb;
	bio->bi_end_io = ploop_bat_write_complete;
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_SYNC | REQ_FUA | REQ_PREFLUSH);
	bio_add_page(bio, page, PAGE_SIZE, 0);

	return 0;
}

void ploop_reset_bat_update(struct ploop_index_wb *piwb)
{
	struct ploop *ploop = piwb->ploop;

	put_page(piwb->bat_page);
	bio_put(piwb->bat_bio);
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

static int find_and_clear_dst_cluster_bit(struct ploop *ploop,
					  unsigned int *ret_dst_cluster)
{
	unsigned int dst_cluster;

	WARN_ON_ONCE(!(current->flags & PF_WQ_WORKER));

	/* Find empty cluster */
	dst_cluster = find_first_bit(ploop->holes_bitmap, ploop->hb_nr);
	if (dst_cluster >= ploop->hb_nr)
		return -EIO;
	/*
	 * Mark cluster as used. Find & clear bit is unlocked,
	 * since currently this may be called only from deferred
	 * kwork. Note, that set_bit may be made from many places.
	 */
	ploop_hole_clear_bit(dst_cluster, ploop);

	*ret_dst_cluster = dst_cluster;
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
	map_index_t *to;
	int ret = 0;

	/* Cluster index related to the page[page_nr] start */
	cluster -= piwb->page_nr * PAGE_SIZE / sizeof(map_index_t) - PLOOP_MAP_OFFSET;

	to = kmap_atomic(page);
	if (to[cluster]) {
		/* Already mapped by one of previous bios */
		*dst_cluster = to[cluster];
		goto unmap;
	}

	if (find_and_clear_dst_cluster_bit(ploop, dst_cluster) < 0) {
		ret = -EIO;
		goto unmap;
	}

	to[cluster] = *dst_cluster;
unmap:
	kunmap_atomic(to);
	return ret;
}


static int ploop_data_bio_end(struct bio *bio)
{
	struct dm_ploop_endio_hook *h = bio_to_endio_hook(bio);
	struct ploop_index_wb *piwb = h->piwb;
	unsigned long flags;
	bool completed;

	spin_lock_irqsave(&piwb->lock, flags);
	completed = piwb->completed;
	if (!completed)
		bio_list_add(&piwb->ready_data_bios, bio);
	else if (!bio->bi_status)
		bio->bi_status = piwb->bi_status;
	spin_unlock_irqrestore(&piwb->lock, flags);

	dec_nr_inflight(piwb->ploop, bio);

	if (!completed)
		return DM_ENDIO_INCOMPLETE;

	put_piwb(piwb);
	return DM_ENDIO_DONE;
}

static bool ploop_attach_end_action(struct bio *bio, struct ploop_index_wb *piwb)
{
	struct dm_ploop_endio_hook *h = bio_to_endio_hook(bio);

	if (WARN_ON_ONCE(h->action != PLOOP_END_IO_NONE)) {
		h->action = PLOOP_END_IO_NONE;
		return false;
	}

	/* Currently this can't fail. */
	if (!atomic_inc_not_zero(&piwb->count))
		return false;

	h->action = PLOOP_END_IO_DATA_BIO;
	h->piwb = piwb;

	return true;
}

static void ploop_read_aio_do_completion(struct ploop_iocb *piocb)
{
	struct bio *bio = piocb->bio;

	if (!atomic_dec_and_test(&piocb->count))
		return;
	bio_endio(bio);
	kmem_cache_free(piocb_cache, piocb);
}

static void ploop_read_aio_complete(struct kiocb *iocb, long ret, long ret2)
{
        struct ploop_iocb *piocb = container_of(iocb, struct ploop_iocb, iocb);
	struct bio *bio = piocb->bio;

	if (ret != bio->bi_iter.bi_size)
		bio->bi_status = BLK_STS_IOERR;
	else
		bio->bi_status = BLK_STS_OK;
        ploop_read_aio_do_completion(piocb);
}
/*
 * Read cluster or its part from secondary delta.
 * @bio is dm's or plain (w/o dm_ploop_endio_hook container and ploop_endio()).
 * Note, that nr inflight is not incremented here, so delegate this to caller
 * (if you need).
 */
static void submit_delta_read(struct ploop *ploop, unsigned int level,
			    unsigned int dst_cluster, struct bio *bio)
{
	struct ploop_iocb *piocb;
	struct bio_vec *bvec;
	struct iov_iter iter;
	unsigned int offset;
	struct file *file;
	loff_t pos;
	int ret;

	piocb = kmem_cache_zalloc(piocb_cache, GFP_NOIO);
	if (!piocb) {
		bio->bi_status = BLK_STS_RESOURCE;
		bio_endio(bio);
		return;
	}
	atomic_set(&piocb->count, 2);
	piocb->bio = bio;

	remap_to_cluster(ploop, bio, dst_cluster);

	bvec = __bvec_iter_bvec(bio->bi_io_vec, bio->bi_iter);
	offset = bio->bi_iter.bi_bvec_done;

	iov_iter_bvec(&iter, READ|ITER_BVEC, bvec, 1, bio->bi_iter.bi_size);
	iter.iov_offset = offset;

	pos = (bio->bi_iter.bi_sector << SECTOR_SHIFT);
	file = ploop->deltas[level].file;

	piocb->iocb.ki_pos = pos;
	piocb->iocb.ki_filp = file;
	piocb->iocb.ki_complete = ploop_read_aio_complete;
	piocb->iocb.ki_flags = IOCB_DIRECT;
	piocb->iocb.ki_ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0);

	ret = call_read_iter(file, &piocb->iocb, &iter);

	ploop_read_aio_do_completion(piocb);

	if (ret != -EIOCBQUEUED)
		piocb->iocb.ki_complete(&piocb->iocb, ret, 0);
}

static void initiate_delta_read(struct ploop *ploop, unsigned int level,
				unsigned int dst_cluster, struct bio *bio)
{
	if (dst_cluster == BAT_ENTRY_NONE) {
		/* No one delta contains dst_cluster. */
		zero_fill_bio(bio);
		bio_endio(bio);
		return;
	}

	submit_delta_read(ploop, level, dst_cluster, bio);
}

static void ploop_cow_endio(struct bio *cluster_bio)
{
	struct ploop_cow *cow = cluster_bio->bi_private;
	struct ploop *ploop = cow->ploop;
	unsigned long flags;

	track_bio(ploop, cluster_bio);

	spin_lock_irqsave(&ploop->deferred_lock, flags);
	bio_list_add(&ploop->delta_cow_action_list, cluster_bio);
	spin_unlock_irqrestore(&ploop->deferred_lock, flags);

	dec_nr_inflight_raw(ploop, &cow->hook);
	queue_work(ploop->wq, &ploop->worker);
}

static bool postpone_if_cluster_locked(struct ploop *ploop, struct bio *bio,
				       unsigned int cluster)
{
	struct dm_ploop_endio_hook *e_h; /* Exclusively locked */

	spin_lock_irq(&ploop->deferred_lock);
	e_h = find_lk_of_cluster(ploop, cluster);
	if (e_h)
		add_endio_bio(e_h, bio);
	spin_unlock_irq(&ploop->deferred_lock);

	return e_h != NULL;
}

static bool postpone_if_required_for_backup(struct ploop *ploop,
			  struct bio *bio, unsigned int cluster)
{
	struct push_backup *pb = ploop->pb;
	bool first, queue_timer = false;
	struct dm_ploop_endio_hook *h;

	if (likely(!pb || !pb->alive))
		return false;
	if (!op_is_write(bio->bi_opf))
		return false;
	if (!test_bit(cluster, pb->ppb_map))
		return false;
	spin_lock_irq(&ploop->pb_lock);
	if (!test_bit(cluster, pb->ppb_map)) {
		spin_unlock_irq(&ploop->pb_lock);
		return false;
	}

	h = find_endio_hook(ploop, &pb->rb_root, cluster);
	if (h) {
		add_endio_bio(h, bio);
		spin_unlock_irq(&ploop->pb_lock);
		return true;
	}

	if (RB_EMPTY_ROOT(&pb->rb_root)) {
		pb->deadline_jiffies = get_jiffies_64() + pb->timeout_in_jiffies;
		queue_timer = true;
	}

	h = bio_to_endio_hook(bio);
	link_endio_hook(ploop, h, &pb->rb_root, cluster, true);
	first = list_empty(&pb->pending);
	list_add_tail(&h->list, &pb->pending);
	spin_unlock_irq(&ploop->pb_lock);

	if (first)
		wake_up_interruptible(&pb->wq);

	if (queue_timer)
		mod_timer(&pb->deadline_timer, pb->timeout_in_jiffies + 1);

	return true;
}

int submit_cluster_cow(struct ploop *ploop, unsigned int level,
		       unsigned int cluster, unsigned int dst_cluster,
		       void (*end_fn)(struct ploop *, int, void *), void *data)
{
	struct bio *bio = NULL;
	struct ploop_cow *cow;

	/* Prepare new delta read */
	bio = alloc_bio_with_pages(ploop);
	if (!bio)
		goto err;

	cow = kmem_cache_alloc(cow_cache, GFP_NOIO);
	if (!cow)
		goto err;

	cow->ploop = ploop;
	cow->dst_cluster = BAT_ENTRY_NONE;
	cow->cluster_bio = bio;
	cow->end_fn = end_fn;
	cow->data = data;

	bio_prepare_offsets(ploop, bio, cluster);
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
	bio->bi_end_io = ploop_cow_endio;
	bio->bi_private = cow;

	__ploop_init_end_io(ploop, &cow->hook);
	add_cluster_lk(ploop, &cow->hook, cluster);

	/* Stage #0: read secondary delta full cluster */
	submit_delta_read(ploop, level, dst_cluster, bio);
	return 0;
err:
	if (bio)
		free_bio_with_pages(ploop, bio);
	return -ENOMEM;
}

static void queue_or_fail(struct ploop *ploop, int err, void *data)
{
	struct bio *bio = data;

	if (err && err != BLK_STS_AGAIN) {
		bio->bi_status = errno_to_blk_status(err);
		bio_endio(bio);
	} else {
		defer_bio(ploop, bio);
	}
}

static void initiate_cluster_cow(struct ploop *ploop, unsigned int level,
		unsigned int cluster, unsigned int dst_cluster, struct bio *bio)
{
	if (!submit_cluster_cow(ploop, level, cluster, dst_cluster,
				queue_or_fail, bio))
		return;

	bio->bi_status = BLK_STS_RESOURCE;
	bio_endio(bio);
}

static void submit_cluster_write(struct ploop_cow *cow)
{
	struct bio *bio = cow->cluster_bio;
	struct ploop *ploop = cow->ploop;
	unsigned int dst_cluster;

	if (find_and_clear_dst_cluster_bit(ploop, &dst_cluster) < 0)
		goto error;
	cow->dst_cluster = dst_cluster;

	bio_reset(bio);
	bio_prepare_offsets(ploop, bio, dst_cluster);
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
	remap_to_origin(ploop, bio);

	BUG_ON(irqs_disabled());
	read_lock_irq(&ploop->bat_rwlock);
	inc_nr_inflight_raw(ploop, &cow->hook);
	read_unlock_irq(&ploop->bat_rwlock);
	bio->bi_end_io = ploop_cow_endio;
	bio->bi_private = cow;

	submit_bio(bio);
	return;
error:
	complete_cow(cow, BLK_STS_IOERR);
}

static void submit_cow_index_wb(struct ploop_cow *cow,
				struct ploop_index_wb *piwb)
{
	struct dm_ploop_endio_hook *h = &cow->hook;
	unsigned int cluster = h->cluster;
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
		bio_list_add(&ploop->delta_cow_action_list, cow->cluster_bio);
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
	bio_list_add(&piwb->cow_list, cow->cluster_bio);
	spin_unlock_irq(&ploop->deferred_lock);
out:
	return;
err_resource:
	complete_cow(cow, BLK_STS_RESOURCE);
}

static void process_delta_wb(struct ploop *ploop, struct ploop_index_wb *piwb)
{
	struct bio_list cow_list = BIO_EMPTY_LIST;
	struct bio *cluster_bio;
	struct ploop_cow *cow;

	if (bio_list_empty(&ploop->delta_cow_action_list))
		return;
	bio_list_merge(&cow_list, &ploop->delta_cow_action_list);
	bio_list_init(&ploop->delta_cow_action_list);
	spin_unlock_irq(&ploop->deferred_lock);

	while ((cluster_bio = bio_list_pop(&cow_list)) != NULL) {
		cow = cluster_bio->bi_private;
		if (unlikely(cluster_bio->bi_status != BLK_STS_OK)) {
			complete_cow(cow, cluster_bio->bi_status);
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

void restart_delta_cow(struct ploop *ploop)
{
	struct bio_list cow_list = BIO_EMPTY_LIST;
	struct bio *cluster_bio;
	struct ploop_cow *cow;

	spin_lock_irq(&ploop->deferred_lock);
	bio_list_merge(&cow_list, &ploop->delta_cow_action_list);
	bio_list_init(&ploop->delta_cow_action_list);
	spin_unlock_irq(&ploop->deferred_lock);

	while ((cluster_bio = bio_list_pop(&cow_list)) != NULL) {
		cow = cluster_bio->bi_private;
		/* This may restart only normal cow */
		WARN_ON_ONCE(cow->end_fn != queue_or_fail);
		complete_cow(cow, BLK_STS_AGAIN);
	}
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
 * for ploop_data_bio_end().
 * Note: cluster newer becomes locked here, since index update is called
 * synchronously. Keep in mind this in case you make it async.
 */
static bool locate_new_cluster_and_attach_bio(struct ploop *ploop,
					      struct ploop_index_wb *piwb,
					      unsigned int cluster,
					      unsigned int *dst_cluster,
					      struct bio *bio)
{
	bool bat_update_prepared = false;
	bool attached = false;
	unsigned int page_nr;

	page_nr = bat_clu_to_page_nr(cluster);

	if (piwb->page_nr == PAGE_NR_NONE) {
		/* No index wb in process. Prepare a new one */
		if (ploop_prepare_bat_update(ploop, page_nr, piwb) < 0) {
			bio->bi_status = BLK_STS_RESOURCE;
			goto error;
		}
		bat_update_prepared = true;
	}

	if (piwb->page_nr != page_nr || piwb->type != PIWB_TYPE_ALLOC) {
		/* Another BAT page wb is in process */
		defer_bio(ploop, bio);
		goto out;
	}

	if (ploop_alloc_cluster(ploop, piwb, cluster, dst_cluster)) {
		bio->bi_status = BLK_STS_IOERR;
		goto error;
	}

	attached = ploop_attach_end_action(bio, piwb);
	if (!attached) {
		/*
		 * Could not prepare data bio to be submitted before index wb
		 * batch? Delay submitting. Good thing, that cluster allocation
		 * has already made, and it goes in the batch.
		 */
		defer_bio(ploop, bio);
	}
out:
	return attached;
error:
	/* Uninit piwb */
	if (bat_update_prepared)
		ploop_reset_bat_update(piwb);
	bio_endio(bio);
	return false;
}

static int process_one_deferred_bio(struct ploop *ploop, struct bio *bio,
				    struct ploop_index_wb *piwb)
{
	sector_t sector = bio->bi_iter.bi_sector;
	unsigned int cluster, dst_cluster;
	u8 level;
	bool ret;

	/*
	 * Unlocked, since no one can update BAT in parallel:
	 * we update BAT only 1)from *this* kwork, and 2)from
	 * ploop_advance_local_after_bat_wb(), which we start
	 * and wait synchronously from *this* kwork.
	 */
	cluster = sector >> ploop->cluster_log;
	dst_cluster = ploop_bat_entries(ploop, cluster, &level);

	if (postpone_if_cluster_locked(ploop, bio, cluster))
		goto out;
	if (postpone_if_required_for_backup(ploop, bio, cluster))
		goto out;

	if (op_is_discard(bio->bi_opf)) {
		handle_discard_bio(ploop, bio, cluster, dst_cluster);
		goto out;
	}

	if (cluster_is_in_top_delta(ploop, cluster)) {
		/* Already mapped */
		goto queue;
	} else if (!op_is_write(bio->bi_opf)) {
		/*
		 * Simple read from secondary delta. May fail.
		 * (Also handles the case dst_cluster == BAT_ENTRY_NONE).
		 */
		initiate_delta_read(ploop, level, dst_cluster, bio);
		goto out;
	} else if (dst_cluster != BAT_ENTRY_NONE) {
		/*
		 * Read secondary delta and write to top delta. May fail.
		 * Yes, we can optimize the whole-cluster-write case and
		 * a lot of other corner cases, but we don't do that as
		 * snapshots are used and COW occurs very rare.
		 */
		initiate_cluster_cow(ploop, level, cluster, dst_cluster, bio);
		goto out;
	}

	/* Cluster exists nowhere. Allocate it and setup bio as outrunning */
	ret = locate_new_cluster_and_attach_bio(ploop, piwb, cluster,
						&dst_cluster, bio);
	if (!ret)
		goto out;
queue:
	/* To improve: read lock may be avoided */
	read_lock_irq(&ploop->bat_rwlock);
	inc_nr_inflight(ploop, bio);
	read_unlock_irq(&ploop->bat_rwlock);

	maybe_link_submitting_bio(ploop, bio, cluster);

	remap_to_cluster(ploop, bio, dst_cluster);
	remap_to_origin(ploop, bio);
	generic_make_request(bio);
out:
	return 0;
}

void ploop_submit_index_wb_sync(struct ploop *ploop,
				struct ploop_index_wb *piwb)
{
	struct block_device *bdev = ploop->origin_dev->bdev;

	/* track_bio() will be called in ploop_bat_write_complete() */
	submit_bio(piwb->bat_bio);
	wait_for_completion(&piwb->comp);

	if (!blk_queue_fua(bdev_get_queue(bdev))) {
		/*
		 * Error here does not mean that cluster write is failed,
		 * since ploop_map() could submit more bios in parallel.
		 * But it's not possible to differ them. Should we block
		 * ploop_map() during we do this?
		 */
		WARN_ON(blkdev_issue_flush(bdev, GFP_NOIO, NULL));
	}
}

static void process_deferred_bios(struct ploop *ploop, struct bio_list *bios,
				  struct ploop_index_wb *piwb)
{
	struct bio *bio;

	while ((bio = bio_list_pop(bios)))
		process_one_deferred_bio(ploop, bio, piwb);
}

static int process_one_discard_bio(struct ploop *ploop, struct bio *bio,
				   struct ploop_index_wb *piwb)
{
	struct dm_ploop_endio_hook *h;
	unsigned int page_nr, cluster;
	bool bat_update_prepared;
	map_index_t *to;

	WARN_ON(ploop->nr_deltas);

	h = bio_to_endio_hook(bio);
	cluster = h->cluster;
	page_nr = bat_clu_to_page_nr(cluster);
	bat_update_prepared = false;

	if (piwb->page_nr == PAGE_NR_NONE) {
		/* No index wb in process. Prepare a new one */
		if (ploop_prepare_bat_update(ploop, page_nr, piwb) < 0) {
			bio->bi_status = BLK_STS_RESOURCE;
			bio_endio(bio);
			goto out;
		}
		piwb->type = PIWB_TYPE_DISCARD;
		bat_update_prepared = true;
	}

	if (piwb->page_nr != page_nr || piwb->type != PIWB_TYPE_DISCARD) {
		queue_discard_index_wb(ploop, bio);
		goto out;
	}

	h->action = PLOOP_END_IO_DISCARD_INDEX_BIO;

	/* Cluster index related to the page[page_nr] start */
	cluster -= piwb->page_nr * PAGE_SIZE / sizeof(map_index_t) - PLOOP_MAP_OFFSET;

	to = kmap_atomic(piwb->bat_page);
	if (WARN_ON_ONCE(!to[cluster])) {
		bio_io_error(bio);
		if (bat_update_prepared)
			ploop_reset_bat_update(piwb);
	} else {
		to[cluster] = 0;
		bio_list_add(&piwb->ready_data_bios, bio);
	}
	kunmap_atomic(to);
out:
	return 0;
}

static void do_discard_cleanup(struct ploop *ploop)
{
	unsigned long cleanup_jiffies;

	if (ploop->force_link_inflight_bios &&
	    !atomic_read(&ploop->nr_discard_bios)) {
		/* Pairs with barrier in ploop_discard_index_bio_end() */
		smp_rmb();
		cleanup_jiffies = READ_ONCE(ploop->pending_discard_cleanup);

		if (time_after(jiffies, cleanup_jiffies + CLEANUP_DELAY * HZ)) {
			ploop->force_link_inflight_bios = false;
			force_defer_bio_count_dec(ploop);
		}
	}
}

/*
 * This processes discard bios waiting index writeback after REQ_DISCARD
 * to backing device has finished (PLOOP_END_IO_DISCARD_INDEX_BIO stage).
 *
 * Also this switches the device back in !force_link_inflight_bios mode
 * after cleanup timeout has expired.
 */
static void process_discard_bios(struct ploop *ploop, struct bio_list *bios,
				 struct ploop_index_wb *piwb)
{
	struct dm_ploop_endio_hook *h;
	struct bio *bio;

	while ((bio = bio_list_pop(bios))) {
		h = bio_to_endio_hook(bio);

		if (WARN_ON_ONCE(h->action != PLOOP_END_IO_DISCARD_BIO)) {
			bio_io_error(bio);
			continue;
		}
		process_one_discard_bio(ploop, bio, piwb);
	}
}

void cancel_discard_bios(struct ploop *ploop)
{
	struct bio_list bio_list = BIO_EMPTY_LIST;
	struct bio *bio;

	spin_lock_irq(&ploop->deferred_lock);
	bio_list_merge(&bio_list, &ploop->discard_bios);
	bio_list_init(&ploop->discard_bios);
	spin_unlock_irq(&ploop->deferred_lock);

	while ((bio = bio_list_pop(&bio_list)) != NULL) {
		bio->bi_status = BLK_STS_NOTSUPP;
		bio_endio(bio);
	}
}

/* Remove from tree bio and endio bio chain */
void unlink_postponed_backup_endio(struct ploop *ploop,
				   struct bio_list *bio_list,
				   struct dm_ploop_endio_hook *h)
{
	struct push_backup *pb = ploop->pb;
	struct bio *bio;

	/* Remove from tree and queue attached bios */
	unlink_endio_hook(ploop, &pb->rb_root, h, bio_list);

	/* Unlink from pb->pending */
	list_del(&h->list);
	/* Zero {list,piwb} union as it may be used later in further */
	memset(&h->list, 0, sizeof(h->list));

	/* Queue relared bio itself */
	bio = dm_bio_from_per_bio_data(h, sizeof(*h));
	bio_list_add(bio_list, bio);
}

void cleanup_backup(struct ploop *ploop)
{
	struct bio_list bio_list = BIO_EMPTY_LIST;
	struct push_backup *pb = ploop->pb;
	struct dm_ploop_endio_hook *h;
	struct rb_node *node;

	spin_lock_irq(&ploop->pb_lock);
	/* Take bat_rwlock for visability in ploop_map() */
	write_lock(&ploop->bat_rwlock);
	pb->alive = false;
	write_unlock(&ploop->bat_rwlock);

	while ((node = pb->rb_root.rb_node) != NULL) {
		h = rb_entry(node, struct dm_ploop_endio_hook, node);
		unlink_postponed_backup_endio(ploop, &bio_list, h);
	}
	spin_unlock_irq(&ploop->pb_lock);

	if (!bio_list_empty(&bio_list))
		defer_bio_list(ploop, &bio_list);

	del_timer_sync(&pb->deadline_timer);
}

static void check_backup_deadline(struct ploop *ploop)
{
	u64 deadline, now = get_jiffies_64();
	struct push_backup *pb = ploop->pb;

	if (likely(!pb || !pb->alive))
		return;

	spin_lock_irq(&ploop->pb_lock);
	deadline = READ_ONCE(pb->deadline_jiffies);
	spin_unlock_irq(&ploop->pb_lock);

	if (time_before64(now, deadline))
		return;

	cleanup_backup(ploop);
}

static void check_services_timeout(struct ploop *ploop)
{
	do_discard_cleanup(ploop);
	check_backup_deadline(ploop);
}

void do_ploop_work(struct work_struct *ws)
{
	struct ploop *ploop = container_of(ws, struct ploop, worker);
	struct bio_list deferred_bios = BIO_EMPTY_LIST;
	struct bio_list discard_bios = BIO_EMPTY_LIST;
	struct ploop_index_wb piwb;

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

	bio_list_merge(&deferred_bios, &ploop->deferred_bios);
	bio_list_merge(&discard_bios, &ploop->discard_bios);
	bio_list_init(&ploop->deferred_bios);
	bio_list_init(&ploop->discard_bios);
	spin_unlock_irq(&ploop->deferred_lock);

	process_deferred_bios(ploop, &deferred_bios, &piwb);
	process_discard_bios(ploop, &discard_bios, &piwb);

	if (piwb.page_nr != PAGE_NR_NONE) {
		/* Index wb was prepared -- submit and wait it */
		ploop_submit_index_wb_sync(ploop, &piwb);
		ploop_reset_bat_update(&piwb);
	}

	check_services_timeout(ploop);
}

static bool should_defer_bio(struct ploop *ploop, struct bio *bio,
			     unsigned int cluster)
{
	struct push_backup *pb = ploop->pb;

	lockdep_assert_held(&ploop->bat_rwlock);

	if (ploop->force_defer_bio_count)
		return true;
	if (pb && pb->alive && op_is_write(bio->bi_opf))
		return test_bit(cluster, pb->ppb_map);
	return false;
}

/*
 * ploop_map() tries to map bio to origins or delays it.
 * It never modifies ploop->bat_entries and other cached
 * metadata: this should be made in do_ploop_work() only.
 */
int ploop_map(struct dm_target *ti, struct bio *bio)
{
	struct ploop *ploop = ti->private;
	unsigned int cluster, dst_cluster;
	unsigned long flags;
	bool in_top_delta;

	ploop_init_end_io(ploop, bio);

	if (bio_sectors(bio)) {
		if (op_is_discard(bio->bi_opf))
			return ploop_map_discard(ploop, bio);
		if (ploop_bio_cluster(ploop, bio, &cluster) < 0)
			return DM_MAPIO_KILL;

		/* map it */
		read_lock_irqsave(&ploop->bat_rwlock, flags);
		dst_cluster = ploop_bat_entries(ploop, cluster, NULL);
		in_top_delta = cluster_is_in_top_delta(ploop, cluster);
		if (unlikely(should_defer_bio(ploop, bio, cluster))) {
			/* defer all bios */
			in_top_delta = false;
			dst_cluster = 0;
		}
		if (in_top_delta)
			inc_nr_inflight(ploop, bio);
		read_unlock_irqrestore(&ploop->bat_rwlock, flags);

		if (!in_top_delta) {
			if (op_is_write(bio->bi_opf) || dst_cluster != BAT_ENTRY_NONE) {
				defer_bio(ploop, bio);
			} else {
				zero_fill_bio(bio);
				bio_endio(bio);
			}

			return DM_MAPIO_SUBMITTED;
		}

		remap_to_cluster(ploop, bio, dst_cluster);
	}

	remap_to_origin(ploop, bio);

	return DM_MAPIO_REMAPPED;
}

int ploop_endio(struct dm_target *ti, struct bio *bio, blk_status_t *err)
{
	struct dm_ploop_endio_hook *h = bio_to_endio_hook(bio);
	struct ploop *ploop = ti->private;
	int ret = DM_ENDIO_DONE;

	if (h->ref_index != PLOOP_REF_INDEX_INVALID) {
		/*
		 * This function may be called twice for discard
		 * and for data bios. Check for ref_index to not
		 * track @bio twice.
		 */
		track_bio(ploop, bio);
	}
	/*
	 * This function is called from the very beginning
	 * of bio->bi_end_io (which is dm.c::clone_endio()).
	 *
	 * DM_ENDIO_DONE return value means handling goes OK.
	 * DM_ENDIO_INCOMPLETE tells the caller to stop end io
	 * processing, and that we are going to call bi_end_io
	 * directly later again. This function (ploop_endio)
	 * also will be called again then!
	 * See dm.c::clone_endio() for the details.
	 */
	if (h->action == PLOOP_END_IO_DATA_BIO)
		ret = ploop_data_bio_end(bio);

	if (h->action == PLOOP_END_IO_DISCARD_BIO)
		ret = ploop_discard_bio_end(ploop, bio);

	if (h->action == PLOOP_END_IO_DISCARD_INDEX_BIO)
		ret = ploop_discard_index_bio_end(ploop, bio);

	if (ret == DM_ENDIO_DONE) {
		maybe_unlink_completed_bio(ploop, bio);
		dec_nr_inflight(ploop, bio);
	}

	return ret;
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
