// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2021 Virtuozzo International GmbH. All rights reserved.
 */
#include <linux/spinlock.h>
#include <linux/uio.h>
#include <linux/fs.h>
#include <uapi/linux/falloc.h>
#include <linux/blk-mq.h>
#include <linux/zlib.h>
#include <linux/error-injection.h>

#include "dm.h"
#include "dm-rq.h"
#include "dm-qcow2.h"

/* "Exactly one bit" has the same number in L1 and L2 */
#define LX_REFCOUNT_EXACTLY_ONE (1ULL << 63)
#define L1_RESERVED_ZERO_MASK 0x7F000000000001FFULL
#define L2_READS_ALL_ZEROES (1ULL << 0)
#define L2_COMPRESSED_CLUSTER (1ULL << 62)
#define L2_RESERVED_ZERO_MASK 0x3F000000000001FEULL
#define R1_RESERVED_ZERO_MASK 0x1FFULL

#define qcow2_for_each_bvec(iter, bv, start_iter, from_bv)			\
	for (iter = start_iter;							\
	     iter.bi_size && ((bv = mp_bvec_iter_bvec(from_bv, iter)), 1);	\
	     bvec_iter_advance(from_bv, &iter, bv.bv_len))

struct qcow2_map_item {
	/*
	 * Index in clu and index in page.
	 * For L1, L2 and R1 is measured in u64 (even if extended L2).
	 * For R2 is measured in R2 size (may refer to the middle of byte).
	 */
	u32 index;
	u32 index_in_page;
	u64 page_id;
	struct md_page *md;
};

struct qcow2_map {
	struct qcow2_map_item l1, l2;
	struct qcow2_map_item r1, r2;
#define L1_LEVEL (1 << 0)
#define L2_LEVEL (1 << 1)
	u8 level; /* Cached levels */
	/* L2 entry has "reads all zeroes", and refers to prealloced block */
	bool prealloced:1;
	bool compressed:1;
	bool clu_is_cow:1;
	bool all_zeroes:1;
	/*
	 * DATA clu is allocated (the same time "all zeroes
	 * read" or "sublu is not allocated" may be set).
	 */
	bool data_clu_alloced:1;
	bool backing_file_cow:1;

	u32 compressed_sectors;
	u32 subclus_mask;
	/*
	 * Cluster-aligned COW source: clusters containing
	 * compressed sectors or internal snapshot cluster.
	 * Their usage count will be decremented after COW.
	 */
	loff_t cow_clu_pos;
	loff_t cow_clu_end;

	u64 ext_l2;
	u64 data_clu_pos;

	struct qcow2 *qcow2;
};

struct qcow2_bvec {
	unsigned int nr_pages;
	struct bio_vec bvec[0];
};

static int qcow2_handle_r1r2_maps(struct qcow2 *qcow2, loff_t pos, struct qio **qio,
	struct qcow2_map_item *r1, struct qcow2_map_item *r2, bool compressed);
static int qcow2_punch_hole(struct file *file, loff_t pos, loff_t len);
static void handle_cleanup_mask(struct qio *qio);
static void process_read_qio(struct qcow2 *qcow2, struct qio *qio,
			     struct qcow2_map *map);
static void init_qrq_and_embedded_qio(struct qcow2_target *tgt, struct request *rq,
				      struct qcow2_rq *qrq, struct qio *qio);

static loff_t bytes_off_in_cluster(struct qcow2 *qcow2, struct qio *qio)
{
	return CLU_OFF(qcow2, to_bytes(qio->bi_iter.bi_sector));
}

static loff_t bio_sector_to_file_pos(struct qcow2 *qcow2, struct qio *qio,
				     struct qcow2_map *map)
{
	WARN_ON_ONCE(!map->data_clu_pos);

	return map->data_clu_pos + bytes_off_in_cluster(qcow2, qio);
}

static loff_t compressed_clu_end_pos(loff_t start, sector_t compressed_sectors)
{
	if (start % SECTOR_SIZE == 0)
		compressed_sectors++;

	return start + to_bytes(compressed_sectors);
}

static u8 qio_subclu_indexes(struct qcow2 *qcow2, struct qio *qio, u8 *end_bit)
{
	u64 off = bytes_off_in_cluster(qcow2, qio);

	WARN_ON_ONCE(!qcow2->ext_l2 || !qio->bi_iter.bi_size);
	*end_bit = (off + qio->bi_iter.bi_size - 1) / qcow2->subclu_size;

	return off / qcow2->subclu_size;
}

static u32 qio_subclus_mask(struct qcow2 *qcow2, struct qio *qio)
{
	u8 start_bit, end_bit;
	u32 mask = ~0U;

	WARN_ON_ONCE(!qcow2->ext_l2 || !qio->bi_iter.bi_size);

	start_bit = qio_subclu_indexes(qcow2, qio, &end_bit);
	mask = (mask >> start_bit) << start_bit;
	mask = (mask << (31 - end_bit)) >> (31 - end_bit);

	return mask;
}

static u32 next_bit(u32 mask, u32 from)
{
	mask >>= from;
	if (!mask)
		return 32;
	return __ffs(mask) + from;
}

static u32 next_zero_bit(u32 mask, u32 from)
{
	return next_bit(~mask, from);
}

static u8 find_bits_range_from(u32 mask, u8 from, u8 *nr)
{
	u8 left, right;

	if (from == 32)
		return 32;
	left = next_bit(mask, from);
	if (left == 32)
		return 32;
	right = next_zero_bit(mask, left);
	*nr = right - left;
	return left;
}

static u32 get_bits_range_from(u32 mask, u8 from)
{
	u8 nr;

	from = find_bits_range_from(mask, from, &nr);
	if (from == 32)
		return 0;
	return (~(u32)0 >> (32 - nr)) << from;
}

static u32 get_bits_range_up_to(u32 mask, u8 to)
{
	int i, next = 0;

	if (to == 0)
		return (1 << 0) & mask;
	if (!(mask << (31 - to) >> (31 - to)))
		return 0;

	while (next < to) {
		i = next;
		next = next_zero_bit(mask, i + 1);
	}

	mask = (mask >> i) << i; /* i is last prev zero bit */
	mask = (mask << (31 - to)) >> (31 - to);
	return mask;
}

static u64 get_u64_from_page(struct page *page, int index_in_page)
{
	u64 *indexes, val;

	indexes = kmap_atomic(page);
	val = indexes[index_in_page];
	kunmap_atomic(indexes);

	return val;
}

static u64 get_u64_from_be_page(struct page *page, int index_in_page)
{
	return be64_to_cpu(get_u64_from_page(page, index_in_page));
}

static void set_u64_to_page(struct page *page, int index_in_page, u64 val)
{
	u64 *indexes;

	indexes = kmap_atomic(page);
	indexes[index_in_page] = val;
	kunmap_atomic(indexes);
}

static void set_u64_to_be_page(struct page *page, int index_in_page, u64 val)
{
	return set_u64_to_page(page, index_in_page, cpu_to_be64(val));
}

struct qcow2 *qcow2_ref_inc(struct qcow2_target *tgt, u8 *ref_index)
{
	struct percpu_ref *ref;
	struct qcow2 *qcow2;

	rcu_read_lock();
	do {
		*ref_index = tgt->inflight_ref_index;
		smp_rmb(); /* Pairs with qcow2_merge_backward() */
		qcow2 = tgt->top;
		ref = &tgt->inflight_ref[*ref_index];
	} while (unlikely(!percpu_ref_tryget(ref)));
	rcu_read_unlock();

	return qcow2;
}

void qcow2_ref_dec(struct qcow2_target *tgt, u8 ref_index)
{
	struct percpu_ref *ref = &tgt->inflight_ref[ref_index];

	percpu_ref_put(ref);
}

/* Zero @count bytes of @bi_iter pointed @bi_io_vec since @from byte */
static void zero_fill_iter_bvec(struct bvec_iter *bi_iter, struct bio_vec *bi_io_vec,
				u32 from, u32 count)
{
	struct bvec_iter iter;
	struct bio_vec bv;
	u32 bytes;

	qcow2_for_each_bvec(iter, bv, *bi_iter, bi_io_vec) {
		void *data;

		if (!count)
			break;
		if (from >= bv.bv_len) {
			from -= bv.bv_len;
			continue;
		}

		bytes = bv.bv_len - from;
		if (bytes > count)
			bytes = count;

		data = kmap(bv.bv_page);
		memset(data + bv.bv_offset + from, 0, bytes);
		flush_dcache_page(bv.bv_page);
		kunmap(bv.bv_page);
		from = 0;
		count -= bytes;
	}
}

/* Zero @count bytes of @qio->bi_io_vec since @from byte */
static void zero_fill_qio(struct qio *qio, u32 from, u32 count)
{
	zero_fill_iter_bvec(&qio->bi_iter, qio->bi_io_vec, from, count);
}

static bool maybe_mapped_in_lower_delta(struct qcow2 *qcow2, struct qio *qio)
{
	if (!qcow2->lower)
		return false;
	return (to_bytes(qio->bi_iter.bi_sector) < qcow2->lower->hdr.size);
}

/* Shorten tail behind qcow2 max possible size */
static void shorten_and_zero_qio_tail(struct qcow2 *qcow2, struct qio *qio)
{
	loff_t start = to_bytes(qio->bi_iter.bi_sector);
	loff_t end = start + qio->bi_iter.bi_size;
	loff_t size = qcow2->hdr.size;

	if (likely(size >= end))
		return;
	if (WARN_ON_ONCE(start >= size))
		return;
	zero_fill_qio(qio, size - start, end - size);
	qio->bi_iter.bi_size -= end - size;
}

static unsigned int qio_nr_segs(struct qio *qio)
{
	unsigned int nr_segs = 0;
	struct bvec_iter iter;
	struct bio_vec bv;

	qcow2_for_each_bvec(iter, bv, qio->bi_iter, qio->bi_io_vec)
		nr_segs++;

	return nr_segs;
}

struct qio *qcow2_alloc_qio(mempool_t *pool, bool zero)
{
	struct qio *qio;

	qio = mempool_alloc(pool, GFP_NOIO);
	if (qio) {
		if (zero)
			memset(qio, 0, sizeof(*qio));
	}
	return qio;
}
ALLOW_ERROR_INJECTION(qcow2_alloc_qio, NULL);

void qcow2_init_qio(struct qio *qio, unsigned int bi_op, struct qcow2 *qcow2)
{
	qio->qcow2 = qcow2;
	qio->queue_list_id = QLIST_DEFERRED;
	qio->ext = NULL;
	qio->data = NULL;
	qio->bi_op = bi_op;
	qio->bi_io_vec = NULL;
	qio->flags = 0;
	qio->ref_index = REF_INDEX_INVALID;
	atomic_set(&qio->remaining, 1);

	/*
	 * Initially set into BLK_STS_OK, while aio complete,
	 * md write complete, etc rewrite bi_status on error.
	 */
	qio->bi_status = BLK_STS_OK;
}

static int qcow2_alloc_qio_ext(struct qio *qio)
{
	if (WARN_ON_ONCE(qio->ext))
		return -EIO;
	qio->ext = kzalloc(sizeof(*(qio->ext)), GFP_NOIO);
	if (!qio->ext)
		return -ENOMEM;
	return 0;
}
ALLOW_ERROR_INJECTION(qcow2_alloc_qio_ext, ERRNO);

static void finalize_qio_ext(struct qio *qio)
{
	if (qio->ext) {
		handle_cleanup_mask(qio);
		kfree(qio->ext);
		qio->ext = NULL;
	}
}

static void qcow2_free_qio(struct qio *qio, mempool_t *pool)
{
	mempool_free(qio, pool);
}

static void do_qio_endio(struct qio *qio)
{
	struct qcow2 *qcow2 = qio->qcow2;
	struct qcow2_target *tgt = qcow2->tgt;
	qcow2_endio_t endio_cb = qio->endio_cb;
	void *endio_cb_data = qio->endio_cb_data;
	unsigned int flags = qio->flags;
	u8 ref_index = qio->ref_index;

	if (!atomic_dec_and_test(&qio->remaining))
		return;

	qio->ref_index = REF_INDEX_INVALID;
	/* Note, that this may free qio or its container memory */
	if (endio_cb)
		endio_cb(tgt, qio, endio_cb_data, qio->bi_status);

	if (ref_index < REF_INDEX_INVALID)
		qcow2_ref_dec(tgt, ref_index);
	if (flags & QIO_FREE_ON_ENDIO_FL)
		qcow2_free_qio(qio, tgt->qio_pool);
}

static void qio_endio(struct qio *qio)
{
	finalize_qio_ext(qio);

	do_qio_endio(qio);
}

static void qcow2_dispatch_qio(struct qcow2 *qcow2, struct qio *qio)
{
	WARN_ON_ONCE(qcow2 != qio->qcow2 ||
		     qio->queue_list_id >= QLIST_INVALID);
	lockdep_assert_held(&qcow2->deferred_lock);

	list_add_tail(&qio->link, &qcow2->qios[qio->queue_list_id]);
}

void qcow2_dispatch_qios(struct qcow2 *qcow2, struct qio *qio,
		   struct list_head *qio_list)
{
	unsigned long flags;

	if (!qio && (!qio_list || list_empty(qio_list)))
		return;

	spin_lock_irqsave(&qcow2->deferred_lock, flags);
	if (qio)
		qcow2_dispatch_qio(qcow2, qio);
	if (qio_list) {
		while ((qio = qio_list_pop(qio_list)) != NULL)
			qcow2_dispatch_qio(qcow2, qio);
	}

	spin_unlock_irqrestore(&qcow2->deferred_lock, flags);

	queue_work(qcow2->tgt->wq, &qcow2->worker);
}

static void end_qios(struct list_head *qio_list, blk_status_t status)
{
	struct qio *qio;

	while ((qio = qio_list_pop(qio_list)) != NULL) {
		if (status != BLK_STS_OK)
			qio->bi_status = status;
		qio_endio(qio);
	}
}

static void qio_chain_endio(struct qcow2_target *tgt, struct qio *qio,
			    void *parent_ptr, blk_status_t bi_status)
{
	struct qio *parent = parent_ptr;

	if (unlikely(bi_status))
		parent->bi_status = bi_status;

	do_qio_endio(parent);
}

static void qio_chain(struct qio *qio, struct qio *parent)
{
	WARN_ON(qio->endio_cb_data || qio->endio_cb);

	qio->endio_cb_data = parent;
	qio->endio_cb = qio_chain_endio;
	atomic_inc(&parent->remaining);
}

/* Clone of bio_advance_iter() */
static void qio_advance(struct qio *qio, unsigned int bytes)
{
	struct bvec_iter *iter = &qio->bi_iter;

	iter->bi_sector += bytes >> 9;

	if (op_is_discard(qio->bi_op))
		iter->bi_size -= bytes;
	else
		bvec_iter_advance(qio->bi_io_vec, iter, bytes);
}

static struct qio *split_and_chain_qio(struct qcow2 *qcow2,
				       struct qio *qio, u32 len)
{
	struct qio *split;

	split = qcow2_alloc_qio(qcow2->tgt->qio_pool, true);
	if (!split)
		return NULL;

	qcow2_init_qio(split, qio->bi_op, qcow2);
	split->queue_list_id = qio->queue_list_id;
	split->flags |= QIO_FREE_ON_ENDIO_FL;
	split->flags |= (qio->flags & QIO_SPLIT_INHERITED_FLAGS);
	split->bi_io_vec = qio->bi_io_vec;
	split->bi_iter = qio->bi_iter;
	split->bi_iter.bi_size = len;
	split->endio_cb = NULL;
	split->endio_cb_data = NULL;
	qio_chain(split, qio);
	if (len)
		qio_advance(qio, len);
	return split;
}

static int qcow2_split_qio_to_list(struct qcow2 *qcow2, struct qio *qio,
			     struct list_head *ret_list)
{
	u32 clu_size = qcow2->clu_size;
	struct qio *split;
	LIST_HEAD(list);

	while (1) {
		loff_t start = to_bytes(qio->bi_iter.bi_sector);
		loff_t end = start + qio->bi_iter.bi_size;
		unsigned int len;

		WARN_ON_ONCE(start == end);

		if (start / clu_size == (end - 1) / clu_size)
			break;
		end = round_up(start + 1, clu_size);
		len = end - start;

		split = split_and_chain_qio(qcow2, qio, len);
		if (!split)
			goto err;

		list_add_tail(&split->link, &list);
	}

	list_splice_tail(&list, ret_list);
	list_add_tail(&qio->link, ret_list);
	return 0;
err:
	while ((qio = qio_list_pop(&list)) != NULL) {
		qio->bi_status = BLK_STS_RESOURCE;
		qio_endio(qio);
	}
	return -ENOMEM;
}
ALLOW_ERROR_INJECTION(qcow2_split_qio_to_list, ERRNO);

static void perform_zero_read(struct qio *qio, u32 size)
{
	zero_fill_qio(qio, 0, size);
}

static void inc_wpc_readers(struct md_page *md)
{
	atomic_inc(&md->wpc_readers);
}

static void dec_wpc_readers(struct qcow2 *qcow2, struct md_page *md)
{
	LIST_HEAD(wait_list);
	unsigned long flags;
	bool last;

	last = atomic_dec_and_lock_irqsave(&md->wpc_readers,
					   &qcow2->md_pages_lock, flags);
	if (last) {
		list_splice_tail_init(&md->wpc_readers_wait_list, &wait_list);
		spin_unlock_irqrestore(&qcow2->md_pages_lock, flags);
		qcow2_dispatch_qios(qcow2, NULL, &wait_list);
	}
}

static bool delay_if_has_wpc_readers(struct qcow2 *qcow2, struct md_page *md,
				     struct qio **qio)
{
	bool ret = false;

	spin_lock_irq(&qcow2->md_pages_lock);
	if (atomic_read(&md->wpc_readers)) {
		list_add_tail(&(*qio)->link, &md->wpc_readers_wait_list);
		*qio = NULL;
		ret = true;
	}
	spin_unlock_irq(&qcow2->md_pages_lock);

	return ret;
}

static u32 calc_cow_mask(struct qcow2 *qcow2, u64 ext_l2,
			 struct qio *qio, bool wants_backing,
			 bool wants_data, bool wants_zeroes)
{
	loff_t start = to_bytes(qio->bi_iter.bi_sector);
	loff_t end = start + qio->bi_iter.bi_size;
	u32 mask, subclus_mask, mapped_mask, cow_mask;
	u8 start_bit, end_bit;

	subclus_mask = cow_mask = 0;
	if (!qcow2->ext_l2)
		goto out;

	if (fake_merge_qio(qio) || !op_is_write(qio->bi_op)) {
		WARN_ON_ONCE(wants_backing);
		goto continue_mask;
	}

	WARN_ON_ONCE(start == end);
	start_bit = qio_subclu_indexes(qcow2, qio, &end_bit);
	mapped_mask = (u32)ext_l2|(ext_l2 >> 32);
	subclus_mask = qio_subclus_mask(qcow2, qio);

	if (SUBCLU_OFF(qcow2, start)) {
		if ((wants_backing && ((1 << start_bit) & ~mapped_mask)) ||
		    (wants_data && ((1 << start_bit) & (u32)ext_l2)) ||
		    (wants_zeroes && ((1 << start_bit) & (ext_l2 >> 32))))
			cow_mask |= (1 << start_bit);
	}
	if (SUBCLU_OFF(qcow2, end)) {
		if ((wants_backing && ((1 << end_bit) & ~mapped_mask)) ||
		    (wants_data && ((1 << end_bit) & (u32)ext_l2)) ||
		    (wants_zeroes && ((1 << end_bit) & (ext_l2 >> 32))))
			cow_mask |= (1 << end_bit);
	}

continue_mask:
	if (wants_data) {
		/* Unchanged COW subclus */
		mask = (u32)ext_l2 & ~subclus_mask;
		cow_mask |= mask;
	}
	if (wants_zeroes) {
		mask = (ext_l2 >> 32) & ~subclus_mask;
		cow_mask |= mask;
	}
out:
	return cow_mask;
}

#define CB_OR_RET(start, end, d_p, d2_p, d3_p)			\
	do {							\
		int __ret = cb(start, end, d_p, d2_p, d3_p);	\
		if (__ret)					\
			return __ret;				\
	} while (0)

static int for_each_cow_interval_ext_l2(struct qio *qio, loff_t start, loff_t end,
				 int (*cb)(loff_t, loff_t, void *, void *, void *),
				 void *d_p, void *d2_p, void *d3_p)
{
	loff_t from, to, i_from[2], i_to[2], pos;
	struct qcow2 *qcow2 = qio->qcow2;
	struct qio_ext *ext = qio->ext;
	u32 subclu_size = qcow2->subclu_size;
	u32 mask, cow_mask = ext->cow_mask;
	u8 start_bit, i, j, nr, end_bit;

	i_from[0] = i_from[1] = OFFSET_MAX;

	if (fake_merge_qio(qio) || !op_is_write(qio->bi_op))
		goto iterate;

	start_bit = qio_subclu_indexes(qcow2, qio, &end_bit);
	/* Firstly, find two intervals near qio boundaries: */
	if (SUBCLU_OFF(qcow2, start) && ((1 << start_bit) & cow_mask)) {
		/* Left boundary */
		pos = round_down(start, subclu_size);
		if (start_bit != 0 && (cow_mask & (1 << (start_bit - 1)))) {
			/* Left mapped neighbours */
			mask = get_bits_range_up_to(cow_mask, start_bit - 1);
			cow_mask &= ~mask;
			pos -= hweight32(mask) * subclu_size;
		}
		i_from[0] = pos;
		i_to[0] = start;
	}
	if (SUBCLU_OFF(qcow2, end) && ((1 << end_bit) & cow_mask)) {
		/* Right boundary */
		pos = round_up(end, subclu_size);
		if (end_bit != 31 && (cow_mask & (1 << (end_bit + 1)))) {
			/* Right mapped neighbours */
			mask = get_bits_range_from(cow_mask, end_bit + 1);
			cow_mask &= ~mask;
			pos += hweight32(mask) * subclu_size;
		}
		i_from[1] = end;
		i_to[1] = pos;
	}
	cow_mask &= ~((1 << start_bit) | (1 << end_bit));

iterate:
	/*
	 * Start ordered iteration over unchanged COW subclus
	 * and two above intervals:
	 */
	if (cow_mask) {
		pos = round_down(start, qcow2->clu_size);
		for (i = 0;
		     (i = find_bits_range_from(cow_mask, i, &nr)) < 32;
		     i += nr) {
			from = pos + (loff_t)i * subclu_size;
			to = pos + (loff_t)(i + nr) * subclu_size;

			for (j = 0; j < 2; j++) {
				if (i_from[j] >= from)
					continue;
				CB_OR_RET(i_from[j], i_to[j], d_p, d2_p, d3_p);
				i_from[j] = OFFSET_MAX;
			}
			CB_OR_RET(from, to, d_p, d2_p, d3_p);
		}
	}
	/* Iterate boundary intervals, if we haven't done that yet: */
	for (j = 0; j < 2; j++) {
		if (i_from[j] != OFFSET_MAX)
			CB_OR_RET(i_from[j], i_to[j], d_p, d2_p, d3_p);
	}

	return 0;
}

/*
 * This function calls @cb for each interval of COW clu,
 * which is not rewritten by @qio. E.g., let bi_iter of WRITE
 * @qio refers to [off + clu_size / 4, off + clu_size / 3],
 * where off is multiply of clu_size, while ext_l2 is disabled.
 * Then, @cb will be called twice from inside the function:
 * 1)@cb(off, off + clu_size / 4, ...)
 * 2)@cb(off + clu_size / 3, off + clu_size, ...).
 * ext_l2 case also cares about allocated subclus.
 *
 * We use this to allocate a single bio_vec[] array with pages
 * to accommodate and to read/write only not-rewritable data
 * from COW clu to new place.
 */
static int for_each_cow_interval(struct qio *qio,
				 int (*cb)(loff_t, loff_t, void *, void *, void *),
				 void *d_p, void *d2_p, void *d3_p)
{
	loff_t start = to_bytes(qio->bi_iter.bi_sector);
	loff_t end = start + qio->bi_iter.bi_size;
	struct qcow2 *qcow2 = qio->qcow2;
	u32 clu_size = qcow2->clu_size;

	if (!qcow2->ext_l2) {
		if (fake_merge_qio(qio) || !op_is_write(qio->bi_op)) {
			return cb(round_down(start, clu_size),
				  round_up(start + 1, clu_size),
				  d_p, d2_p, d3_p);
		}

		if (CLU_OFF(qcow2, start) != 0)
			CB_OR_RET(round_down(start, clu_size), start, d_p, d2_p, d3_p);
		if (CLU_OFF(qcow2, end) != 0)
			CB_OR_RET(end, round_up(end, clu_size), d_p, d2_p, d3_p);
		return 0;
	}

	return for_each_cow_interval_ext_l2(qio, start, end, cb, d_p, d2_p, d3_p);
}
#undef CB_OR_RET

static int count_cow_pages(loff_t start, loff_t end, void *nr_pages_p,
			   void *nr_segs_p, void *unused)
{
	u32 *nr_pages = nr_pages_p, *nr_segs = nr_segs_p;

	start = round_down(start, PAGE_SIZE);
	end = round_up(end, PAGE_SIZE);

	*nr_pages += (end - start) / PAGE_SIZE;
	*nr_segs += 1;
	return 0;
}

static struct qcow2_bvec *qcow2_alloc_qvec_with_data(u32 nr_vecs, void **data, u32 data_sz)
{
	struct qcow2_bvec *qvec = NULL;
	unsigned int size;

	size = sizeof(struct qcow2_bvec) + nr_vecs * sizeof(struct bio_vec);
	qvec = kzalloc(size + data_sz, GFP_NOIO);
	if (qvec)
		qvec->nr_pages = nr_vecs;
	if (data)
		*data = (void *)qvec + size;
	return qvec;
}

static void qcow2_free_qvec_with_pages(struct qcow2_bvec *qvec)
{
	if (qvec) {
		while (qvec->nr_pages-- > 0)
			put_page(qvec->bvec[qvec->nr_pages].bv_page);
		kfree(qvec);
	}
}

static struct qcow2_bvec *qcow2_alloc_qvec_with_pages(ushort nr_pages, bool wants_pages)
{
	struct qcow2_bvec *qvec;
	struct bio_vec *bvec;
	int i;

	qvec = qcow2_alloc_qvec_with_data(nr_pages, NULL, 0);
	if (!qvec || !wants_pages)
		return qvec;

	bvec = qvec->bvec;
	for (i = 0; i < nr_pages; i++) {
		bvec[i].bv_page = alloc_page(GFP_NOIO);
		if (!bvec[i].bv_page)
			goto err;
		bvec[i].bv_len = PAGE_SIZE;
		bvec[i].bv_offset = 0;
	}

	return qvec;
err:
	qvec->nr_pages = i;
	qcow2_free_qvec_with_pages(qvec);
	return NULL;
}

static struct qio *qcow2_alloc_qio_with_qvec(struct qcow2 *qcow2, u32 nr_pages,
				       unsigned int bi_op, bool wants_pages,
				       struct qcow2_bvec **qvec)
{
	struct qcow2_target *tgt = qcow2->tgt;
	struct qio *qio;

	qio = qcow2_alloc_qio(tgt->qio_pool, true);
	if (!qio)
		return NULL;

	*qvec = qcow2_alloc_qvec_with_pages(nr_pages, wants_pages);
	if (!*qvec) {
		qcow2_free_qio(qio, tgt->qio_pool);
		return NULL;
	}

	qcow2_init_qio(qio, bi_op, qcow2);
	qio->bi_io_vec = (*qvec)->bvec;
	qio->bi_iter.bi_size = nr_pages << PAGE_SHIFT;
	qio->bi_iter.bi_idx = 0;
	qio->bi_iter.bi_bvec_done = 0;
	return qio;
}

static void free_wbd(struct wb_desc *wbd)
{
	if (wbd) {
		if (wbd->pe_page)
			put_page(wbd->pe_page);
		kfree(wbd->changed_indexes);
		kfree(wbd);
	}
}

static struct wb_desc *alloc_wbd(bool needs_prealloced)
{
	struct wb_desc *wbd;

	wbd = kzalloc(sizeof(*wbd), GFP_NOIO);
	if (!wbd)
		return NULL;
	wbd->changed_indexes = kzalloc(LX_INDEXES_BYTES, GFP_NOIO);
	if (!wbd->changed_indexes)
		goto err;
	if (needs_prealloced) {
		wbd->pe_page = alloc_page(GFP_NOIO|__GFP_ZERO);
		if (!wbd->pe_page)
			goto err;
	}

	INIT_LIST_HEAD(&wbd->completed_list);
	INIT_LIST_HEAD(&wbd->dependent_list);
	return wbd;
err:
	free_wbd(wbd);
	return NULL;
}

void qcow2_slow_wb_timer_fn(struct timer_list *t)
{
	struct qcow2 *qcow2 = from_timer(qcow2, t, slow_wb_timer);
	unsigned long flags;
	bool queue;

	spin_lock_irqsave(&qcow2->md_pages_lock, flags);
	queue = !list_empty(&qcow2->slow_wb_batch_list);
	list_splice_init(&qcow2->slow_wb_batch_list, &qcow2->wb_batch_list);
	spin_unlock_irqrestore(&qcow2->md_pages_lock, flags);

	if (queue)
		queue_work(qcow2->tgt->wq, &qcow2->worker);
}

static bool qcow2_md_make_dirty(struct qcow2 *qcow2, struct md_page *md, bool is_refs)
{
	struct list_head *head;
	bool new = false;

	head = !is_refs ? &qcow2->wb_batch_list : &qcow2->slow_wb_batch_list;

	/* md->status must be visible for complete handlers */
	lockdep_assert_held(&qcow2->md_pages_lock);

	if (!(md->status & MD_DIRTY)) {
		md->status |= MD_DIRTY;
		list_add_tail(&md->wb_link, head);
		new = true;

		if (is_refs && !timer_pending(&qcow2->slow_wb_timer))
			mod_timer(&qcow2->slow_wb_timer,
				  jiffies + WB_TIMEOUT_JI);
		/* Sanity: 1)only L1L2 have wbd, 2)only R1R2 allow redirtying */
		WARN_ON(md->wbd && ((md->status & MD_WRITEBACK) || is_refs));
	}
	return new;
}

static u64 get_r2_entry(struct qcow2 *qcow2, struct md_page *md,
			u32 r2_index_in_page)
{
	u32 index, start, tail, bits = qcow2->refblock_bits;
	u64 entry;

	/* index of u64 qword containing our refcounter */
	index = r2_index_in_page * bits / 64;
	entry = get_u64_from_page(md->page, index);

	if (bits == 64)
		return be64_to_cpu(entry);
	if (bits == 32)
		return be32_to_cpu(((u32 *)&entry)[r2_index_in_page % 2]);
	if (bits == 16)
		return be16_to_cpu(((u16 *)&entry)[r2_index_in_page % 4]);
	/*
	 * We want to swab original BE u64 qword on both BE and LE.
	 * For LE it is already done because of get_u64_from_page().
	 * For BE it is made here.
	 */
	entry = cpu_to_le64(entry);
	/* Bit start in u64 qword */
	start = r2_index_in_page * bits % 64;
	/* Cut tail bits */
	tail = 64 - bits - start;
	entry = (entry << tail) >> tail;
	/* Cut bits before start */
	entry >>= start;
	return entry;
}

static void set_r2_entry(struct qcow2 *qcow2, struct md_page *md,
			 u32 r2_index_in_page, u64 val)
{
	u32 index, start, bits = qcow2->refblock_bits;
	u64 mask, entry;

	/* index of u64 qword containing our refcounter */
	index = r2_index_in_page * bits / 64;

	if (bits == 64) {
		entry = cpu_to_be64(val);
		goto set;
	}

	entry = get_u64_from_page(md->page, index);

	if (bits == 32) {
		((u32 *)&entry)[r2_index_in_page % 2] = cpu_to_be32(val);
		goto set;
	}
	if (bits == 16) {
		((u16 *)&entry)[r2_index_in_page % 4] = cpu_to_be16(val);
		goto set;
	}

	/* Bit start in u64 qword */
	start = r2_index_in_page * bits % 64;
	/* 0b0000...11 mask */
	mask = (~(u64)0) >> (64 - bits);
	/* Move to position and swab on BE */
	mask = cpu_to_le64(mask << start);
	val = cpu_to_le64(val << start);
	/* Clear old bits and set new bits */
	entry &= ~mask;
	entry |= val;
set:
	/* Store to BE page: swab on LE */
	set_u64_to_page(md->page, index, entry);
}

static void calc_page_id_and_index(loff_t pos, u64 *page_id, u32 *index_in_page)
{
	*page_id = pos >> PAGE_SHIFT;
	*index_in_page = (pos & ~PAGE_MASK) / sizeof(u64);
}

static int qcow2_calc_cluster_map(struct qcow2 *qcow2, struct qio *qio,
			    struct qcow2_map *map)
{
	loff_t start = to_bytes(qio->bi_iter.bi_sector);
	loff_t end = start + qio->bi_iter.bi_size;
	u32 clu_size = qcow2->clu_size;
	loff_t pos;

	if (unlikely(start / clu_size != (end - 1) / clu_size &&
		     (start != end || !fake_service_qio(qio))))
		goto eio;
	if (unlikely(end > qcow2->hdr.size))
		goto eio;

	map->l2.index = (start / clu_size) % qcow2->l2_entries;
	map->l1.index = (start / clu_size) / qcow2->l2_entries;

	if (qcow2->ext_l2) {
		/*
		 * Unlike proposed in qcow2 documentation,
		 * we measure index in sizeof(u64).
		 */
		map->l2.index *= 2;
	}

	if (unlikely(map->l1.index >= qcow2->hdr.l1_size))
		goto eio;

	pos = qcow2->hdr.l1_table_offset + map->l1.index * sizeof(u64);
	calc_page_id_and_index(pos, &map->l1.page_id, &map->l1.index_in_page);
	/* TODO: we can count l2.index_in_page. See calc_refcounters_map() */
	return 0;
eio:
	WARN_ONCE(1, "qio(%lld,%lld, 0x%x), map(%u, %u)\n", start, end,
		      qio->bi_op, map->l1.index, map->l2.index);
	return -EIO;
}

static int calc_refcounters_map(struct qcow2 *qcow2, loff_t pos,
				struct qcow2_map_item *r1,
				struct qcow2_map_item *r2)
{
	u32 refblock_entries = qcow2->refblock_entries;
	u32 clus = qcow2->hdr.refcount_table_clusters;
	u32 bits = qcow2->refblock_bits;
	u32 clu_size = qcow2->clu_size;

	r2->index = (pos / clu_size) % refblock_entries;
	r1->index = (pos / clu_size) / refblock_entries;

	if (unlikely((u64)r1->index * sizeof(u64) >= (u64)clus * clu_size))
		goto eio;

	pos = qcow2->hdr.refcount_table_offset + r1->index * sizeof(u64);
	calc_page_id_and_index(pos, &r1->page_id, &r1->index_in_page);
	/*
	 * Since cluster is multiply of PAGE_SIZE, we may count index_in_page.
	 * Note, this may be half/quarter of byte (the same as r2->index).
	 */
	r2->index_in_page = r2->index % (PAGE_SIZE * 8 / bits);
	return 0;
eio:
	WARN_ONCE(1, "ref(%u, %u)\n", r1->index, r2->index);
	return -EIO;
}

static int calc_r2_page_id(struct qcow2 *qcow2, struct qcow2_map_item *r1,
						struct qcow2_map_item *r2)
{
	u64 entry = get_u64_from_be_page(r1->md->page, r1->index_in_page);
	u32 bits = qcow2->refblock_bits;
	loff_t pos;

	if (WARN_ON_ONCE((entry & R1_RESERVED_ZERO_MASK) ||
			 (CLU_OFF(qcow2, entry) != 0)))
		return -EIO;

	/* The corresponding refcount block has not yet been allocated */
	if (!entry)
		return -ENOENT;

	pos = entry + r2->index * bits / 8;
	r2->page_id = pos >> PAGE_SHIFT;
	return 0;
}

/* Whether L1 or L2 md is under writeback and @index is allocating */
static bool dirty_or_writeback(struct qcow2 *qcow2, struct md_page *md,
			       u32 index_in_page)
{
	bool ret = false;

	lockdep_assert_held(&qcow2->md_pages_lock);
	if (md->wbd && (md->status & (MD_DIRTY|MD_WRITEBACK)))
		ret = test_bit(index_in_page, md->wbd->changed_indexes);
	return ret;
}

static bool delay_if_dirty(struct qcow2 *qcow2, struct md_page *md,
			   u32 index_in_page, struct qio **qio)
{
	bool ret = false;

	lockdep_assert_held(&qcow2->md_pages_lock);
	if (md->status & MD_DIRTY) {
		ret = test_bit(index_in_page, md->wbd->changed_indexes);
		if (ret) {
			list_add_tail(&(*qio)->link, &md->wait_list);
			*qio = NULL;
		}
	}
	return ret;
}

/*
 * This is helper for parse_metadata().
 * In case of writeback is in progress, it's prohibited to:
 * 1)write to indexes, which are under writeback;
 * 2)add completely new allocations;
 * 3)reuse preallocations (they force L2 entry update).
 * I.e., we may write only to clusters, whose indexes are
 * already written in image file.
 */
static bool __delay_if_writeback(struct qcow2 *qcow2, struct md_page *md,
				 u32 index_in_page, struct qio **qio,
				 bool wants_allocation)
{
	bool ret = false;

	lockdep_assert_held(&qcow2->md_pages_lock);

	if ((md->status & MD_WRITEBACK) &&
	    (wants_allocation ||
	     test_bit(index_in_page, md->wbd->changed_indexes))) {
		list_add_tail(&(*qio)->link, &md->wait_list);
		*qio = NULL;
		ret = true;
	}
	return ret;
}

static bool delay_if_writeback(struct qcow2 *qcow2, struct md_page *md,
			       u32 index_in_page, struct qio **qio,
			       bool wants_allocation)
{
	bool ret;

	spin_lock_irq(&qcow2->md_pages_lock);
	ret = __delay_if_writeback(qcow2, md, index_in_page,
				   qio, wants_allocation);
	spin_unlock_irq(&qcow2->md_pages_lock);

	return ret;
}

static bool delay_if_wpc_readers_locked(struct qcow2 *qcow2, struct md_page *md,
					struct qio **qio)
{
	bool ret = false;

	lockdep_assert_held(&qcow2->md_pages_lock);
	if (md->wpc_noread_count) {
		list_add_tail(&(*qio)->link, &md->wait_list);
		*qio = NULL;
		ret = true;
	}

	return ret;
}

static void md_index_set_locked(struct qcow2 *qcow2, struct md_page *md,
				u32 index_in_page)
{
	lockdep_assert_held(&qcow2->md_pages_lock);
	WARN_ON_ONCE(test_bit(index_in_page, md->lockd->indexes));
	set_bit(index_in_page, md->lockd->indexes);
	md->lockd->nr++;
}

static bool delay_if_locked(struct qcow2 *qcow2, struct md_page *md,
			    u32 index_in_page, struct qio **qio)
{
	bool ret = false;

	lockdep_assert_held(&qcow2->md_pages_lock);
	if (md->lockd && test_bit(index_in_page, md->lockd->indexes)) {
		list_add_tail(&(*qio)->link, &md->wait_list);
		*qio = NULL;
		ret = true;
	}

	return ret;
}


/*
 * Note, that we delay R1 and R2 pages writeback. In case of power down,
 * they can easily be restored from L1, L2 and other stable metadata.
 */
static void mark_cluster_used(struct qcow2 *qcow2, struct md_page *r2_md,
			      u32 r2_index_in_page)
{
	WARN_ON_ONCE(READ_ONCE(r2_md->status) & MD_WRITEBACK);

	spin_lock_irq(&qcow2->md_pages_lock);
	WARN_ON_ONCE(get_r2_entry(qcow2, r2_md, r2_index_in_page));
	set_r2_entry(qcow2, r2_md, r2_index_in_page, 1);
	WARN_ON_ONCE(get_r2_entry(qcow2, r2_md, r2_index_in_page) != 1);

	qcow2_md_make_dirty(qcow2, r2_md, true);
	spin_unlock_irq(&qcow2->md_pages_lock);
}

static void mark_cluster_unused(struct qcow2 *qcow2, struct md_page *r2_md,
				u32 r2_index_in_page, loff_t pos)
{
	unsigned long flags;

	spin_lock_irqsave(&qcow2->md_pages_lock, flags);
	WARN_ON_ONCE(get_r2_entry(qcow2, r2_md, r2_index_in_page) != 1);
	set_r2_entry(qcow2, r2_md, r2_index_in_page, 0);
	WARN_ON_ONCE(get_r2_entry(qcow2, r2_md, r2_index_in_page) != 0);

	qcow2_md_make_dirty(qcow2, r2_md, true);
	if (qcow2->free_cluster_search_pos > pos)
		qcow2->free_cluster_search_pos = pos;
	spin_unlock_irqrestore(&qcow2->md_pages_lock, flags);
}

static void dec_cluster_usage(struct qcow2 *qcow2, struct md_page *r2_md,
			      u32 r2_index_in_page, loff_t pos)
{
	unsigned long flags;
	u64 val;

	spin_lock_irqsave(&qcow2->md_pages_lock, flags);
	val = get_r2_entry(qcow2, r2_md, r2_index_in_page);
	WARN_ON_ONCE(val < 1);
	val--;
	set_r2_entry(qcow2, r2_md, r2_index_in_page, val);
	WARN_ON_ONCE(get_r2_entry(qcow2, r2_md, r2_index_in_page) != val);

	qcow2_md_make_dirty(qcow2, r2_md, true);
	if (!val && qcow2->free_cluster_search_pos > pos)
		qcow2->free_cluster_search_pos = pos;
	spin_unlock_irqrestore(&qcow2->md_pages_lock, flags);
}

static void __submit_rw_mapped(struct qcow2 *qcow2, struct qio *qio, u32 nr_segs)
{
	struct bio_vec *bvec;
	struct iov_iter iter;
	unsigned int rw;
	loff_t pos;

	rw = (op_is_write(qio->bi_op) ? WRITE : READ);
	bvec = __bvec_iter_bvec(qio->bi_io_vec, qio->bi_iter);
	pos = to_bytes(qio->bi_iter.bi_sector);

	iov_iter_bvec(&iter, rw, bvec, nr_segs, qio->bi_iter.bi_size);
	iter.iov_offset = qio->bi_iter.bi_bvec_done;

	qcow2_call_rw_iter(qcow2, pos, rw, &iter, qio);
}

static void submit_rw_mapped(struct qcow2 *qcow2, struct qio *qio)
{
	u32 nr_segs = qio_nr_segs(qio);

	__submit_rw_mapped(qcow2, qio, nr_segs);
}

static void map_and_submit_rw(struct qcow2 *qcow2, loff_t clu_pos, struct qio *qio)
{
	WARN_ON_ONCE(qio->qcow2 != qcow2);
	remap_to_clu(qcow2, qio, clu_pos);

	submit_rw_mapped(qcow2, qio);
}

static void do_md_page_read_complete(int ret, struct qcow2 *qcow2,
				     struct md_page *md)
{
	LIST_HEAD(wait_list);
	unsigned long flags;

	spin_lock_irqsave(&qcow2->md_pages_lock, flags);
	if (ret < 0)
		qcow2_md_page_erase(qcow2, md);
	else
		md->status |= MD_UPTODATE;

	list_splice_tail_init(&md->wait_list, &wait_list);
	spin_unlock_irqrestore(&qcow2->md_pages_lock, flags);

	if (ret < 0) {
		qcow2_free_md_page(md);
		end_qios(&wait_list, errno_to_blk_status(ret));
	} else {
		qcow2_dispatch_qios(qcow2, NULL, &wait_list);
	}
}

/* Be careful with dirty_or_writeback()/etc! Check races. */
static void revert_clusters_alloc(struct qcow2 *qcow2, struct wb_desc *wbd)
{
	struct qcow2_map_item r1, r2;
	struct page *pe_page;
	u64 pos, old;
	int i, ret;

	lockdep_assert_held(&qcow2->md_pages_lock);
	for_each_set_bit(i, wbd->changed_indexes, LX_INDEXES_PER_PAGE) {
		pos = get_u64_from_be_page(wbd->md->page, i);
		WARN_ON_ONCE(!(pos & ~LX_REFCOUNT_EXACTLY_ONE) ||
			     !(pos & LX_REFCOUNT_EXACTLY_ONE));

		/* Here we restore prealloced and compressed clu mappings */
		pe_page = wbd->pe_page;
		if (pe_page) { /* Only L2 has this. */
			old = get_u64_from_be_page(pe_page, i);
			if (old != 0) {
				set_u64_to_be_page(wbd->md->page, i, old);
				continue; /* Avoid mark_cluster_unused() */
			}
		}

		set_u64_to_be_page(wbd->md->page, i, 0);
		spin_unlock(&qcow2->md_pages_lock);
		pos &= ~LX_REFCOUNT_EXACTLY_ONE;

		/*
		 * R1/R2 should be cached, since we was able
		 * to submit cluster allocation.
		 */
		ret = qcow2_handle_r1r2_maps(qcow2, pos, NULL, &r1, &r2, false);
		if (WARN_ON_ONCE(ret <= 0))
			continue;

		mark_cluster_unused(qcow2, r2.md, r2.index_in_page, pos);
		spin_lock(&qcow2->md_pages_lock);
	}
}

static void clear_writeback_status(struct qcow2 *qcow2, struct md_page *md,
				   int ret, struct list_head *wait_list,
				   struct list_head *end_list)
{
	lockdep_assert_held(&qcow2->md_pages_lock);

	md->status &= ~(MD_WRITEBACK|MD_WRITEBACK_ERROR);
	list_splice_init(&md->wait_list, wait_list);
	if (ret && !md->wbd) {
		/*
		 * L1L2 updates can do safe revert,
		 * so here we care about R1R2 only.
		 */
		md->status |= MD_WRITEBACK_ERROR;
	}
	if (md->wbd) {
		if (likely(ret == 0))
			list_splice_init(&md->wbd->dependent_list, wait_list);
		else
			list_splice_init(&md->wbd->dependent_list, end_list);
		md->wbd = NULL;
	}
}

static void complete_wbd(struct qcow2 *qcow2, struct wb_desc *wbd)
{
	if (unlikely(wbd->ret < 0)) {
		LIST_HEAD(wait_list);
		LIST_HEAD(end_list);
		unsigned long flags;

		spin_lock_irqsave(&qcow2->md_pages_lock, flags);
		revert_clusters_alloc(qcow2, wbd);
		clear_writeback_status(qcow2, wbd->md, wbd->ret,
				       &wait_list, &end_list);
		spin_unlock_irqrestore(&qcow2->md_pages_lock, flags);

		qcow2_dispatch_qios(qcow2, NULL, &wait_list);
		end_qios(&end_list, errno_to_blk_status(wbd->ret));
	}
	free_wbd(wbd);
}

static void do_md_page_write_complete(int ret, struct qcow2 *qcow2,
				      struct md_page *md)
{
	struct wb_desc *wbd = NULL;
	bool finalize_wbd = false;
	LIST_HEAD(wait_list);
	LIST_HEAD(end_list);

	spin_lock_irq(&qcow2->md_pages_lock);
	WARN_ON_ONCE(!(md->status & MD_WRITEBACK));
	wbd = md->wbd;
	if (wbd) {
		wbd->completed = true;
		wbd->ret = ret;
		list_splice_init(&wbd->completed_list, &end_list);
		/*
		 * In case of this md writeback completed before
		 * parallel data qios, wbd is finalized by last
		 * completed data qio.
		 */
		finalize_wbd = (wbd->nr_submitted == 0);
		/*
		 * We can finish wb only in case of success.
		 * Otherwise this is done in finalize_wbd()
		 * after data qios stopped use wbd clusters
		 * and clusters allocations reverted.
		 */
		if (likely(ret == 0)) {
			clear_writeback_status(qcow2, md, ret,
					       &wait_list, &end_list);
		}
		/* FIXME: we should reread md after write fail */
	} else {
		clear_writeback_status(qcow2, md, ret, &wait_list, &end_list);
	}
	spin_unlock_irq(&qcow2->md_pages_lock);

	end_qios(&end_list, errno_to_blk_status(ret));
	qcow2_dispatch_qios(qcow2, NULL, &wait_list);
	if (finalize_wbd)
		complete_wbd(qcow2, wbd);
}

static void md_page_read_complete(struct qio *qio)
{
	struct qcow2_bvec *qvec = qio->data;
	struct md_page *md = qio->ext->md;
	struct qcow2 *qcow2 = qio->qcow2;
	int ret = qio->ret;
	mode_t mode;

	BUG_ON(qvec->bvec[0].bv_page != md->page);

	if (unlikely(ret != PAGE_SIZE && ret > 0)) {
		/* Read near EOF? See qcow2_attach_file() */
		loff_t pos = (md->id << PAGE_SHIFT) + ret;

		mode = qcow2->file->f_mode;
		if (pos == qcow2->file_size && !(mode & FMODE_WRITE)) {
			qcow2_zero_fill_page_from(md->page, ret);
			ret = PAGE_SIZE;
		}
	}
	if (unlikely(ret != PAGE_SIZE))
		ret = -EIO;
	else
		ret = 0;

	do_md_page_read_complete(ret, qcow2, md);
	if (ret)
		qio->bi_status = errno_to_blk_status(ret);
	kfree(qvec);
	qio_endio(qio);
}

static void md_page_write_complete(struct qio *qio)
{
	struct qcow2 *qcow2 = qio->qcow2;
	unsigned long flags;

	qio->queue_list_id = QLIST_COMPLETED_WB;
	spin_lock_irqsave(&qcow2->deferred_lock, flags);
	list_add_tail(&qio->link, &qcow2->qios[QLIST_COMPLETED_WB]);
	spin_unlock_irqrestore(&qcow2->deferred_lock, flags);
	queue_work(qcow2->tgt->wq, &qcow2->fsync_worker);
}

static void submit_rw_md_page(unsigned int rw, struct qcow2 *qcow2,
			      struct md_page *md)
{
	struct qcow2_target *tgt = qcow2->tgt;
	loff_t pos = md->id << PAGE_SHIFT;
	struct qcow2_bvec *qvec = NULL;
	struct bio_vec *bvec;
	unsigned int bi_op;
	struct qio *qio;
	u8 ref_index;
	int err = 0;

	bi_op = (rw == READ ? REQ_OP_READ : REQ_OP_WRITE);

	if (pos > qcow2->file_size) {
		pr_err_once("qcow2: rw=%x pos=%lld behind EOF %lld\n",
			     rw, pos, qcow2->file_size);
		err = -EIO;
	} else {
		/*
		 * Note, this is fake qio, and qio_endio()
		 * can't be called on it!
		 */
		qio = qcow2_alloc_qio_with_qvec(qcow2, 1, bi_op, false, &qvec);
		if (!qio || qcow2_alloc_qio_ext(qio)) {
			if (qio)
				qcow2_free_qio(qio, tgt->qio_pool);
			err = -ENOMEM;
		}
	}
	if (err) {
		if (rw == READ)
			do_md_page_read_complete(err, qcow2, md);
		else
			do_md_page_write_complete(err, qcow2, md);
		return;
	}

	WARN_ON_ONCE(qio->endio_cb);
	qio->flags |= QIO_FREE_ON_ENDIO_FL;
	qio->data = qvec;
	qio->ext->md = md;
	if (rw == READ)
		qio->complete = md_page_read_complete;
	else
		qio->complete = md_page_write_complete;

	/* This may return other qcow2, and it does not matter */
	qcow2_ref_inc(tgt, &ref_index);
	qio->ref_index = ref_index;

	bvec = &qvec->bvec[0];
	bvec->bv_page = md->page;
	bvec->bv_len = PAGE_SIZE;
	bvec->bv_offset = 0;

	/* @pos is not clu-aligned, so we can't use map_and_submit_rw() */
	qio->bi_iter.bi_sector = to_sector(pos);
	__submit_rw_mapped(qcow2, qio, 1);
}

static int submit_read_md_page(struct qcow2 *qcow2, struct qio **qio,
			       u64 page_id)
{
	struct md_page *md;
	int ret;

	lockdep_assert_held(&qcow2->md_pages_lock);
	spin_unlock_irq(&qcow2->md_pages_lock);

	ret = qcow2_alloc_and_insert_md_page(qcow2, page_id, &md);
	if (ret < 0)
		goto out_lock;

	spin_lock_irq(&qcow2->md_pages_lock);
	list_add_tail(&(*qio)->link, &md->wait_list);
	*qio = NULL;
	spin_unlock_irq(&qcow2->md_pages_lock);

	submit_rw_md_page(READ, qcow2, md);
out_lock:
	spin_lock_irq(&qcow2->md_pages_lock);
	return ret;
}

/*
 * This may be called with @qio == NULL, in case of we are
 * interesting in searching cached in memory md only.
 * This is aimed to be called not only from main kwork
 * for L1/L2 pages, so all callers looking for L1/L2
 * must care about submit_read_md_page() may return EEXIST.
 */
static int __handle_md_page(struct qcow2 *qcow2, u64 page_id,
			    struct qio **qio, struct md_page **ret_md)
{
	struct md_page *md;

	lockdep_assert_held(&qcow2->md_pages_lock);
	md = qcow2_md_page_find_or_postpone(qcow2, page_id, qio);
	if (!md) {
		if (qio && *qio)
			return submit_read_md_page(qcow2, qio, page_id);
		return 0;
	}

	*ret_md = md;
	return 1;
}

static int handle_md_page(struct qcow2 *qcow2, u64 page_id,
		 struct qio **qio, struct md_page **ret_md)
{
	int ret;

	spin_lock_irq(&qcow2->md_pages_lock);
	ret = __handle_md_page(qcow2, page_id, qio, ret_md);
	spin_unlock_irq(&qcow2->md_pages_lock);
	return ret;
}

static u32 qio_subclus_covered_start_size(struct qcow2 *qcow2,
					  struct qio *qio,
					  u32 subclus_mask)
{
	u8 start_bit, end_bit, bit;

	start_bit = qio_subclu_indexes(qcow2, qio, &end_bit);

	bit = next_zero_bit(subclus_mask, start_bit);
	if (bit == start_bit)
		return 0;
	if (bit > end_bit)
		return qio->bi_iter.bi_size;
	return bit * qcow2->subclu_size - bytes_off_in_cluster(qcow2, qio);
}

static u32 qio_unmapped_size(struct qcow2 *qcow2, struct qio *qio,
			     struct qcow2_map *map)
{
	u32 mapped_mask = (map->ext_l2 >> 32) | (u32)map->ext_l2;

	if (!qcow2->ext_l2) {
		if (!map->data_clu_alloced && !map->all_zeroes)
			return qio->bi_iter.bi_size;
		return 0;
	}

	return qio_subclus_covered_start_size(qcow2, qio, ~mapped_mask);
}

static u32 qio_mapped_not_zeroes_size(struct qcow2 *qcow2, struct qio *qio,
				      struct qcow2_map *map)
{
	if (!qcow2->ext_l2) {
		if (map->data_clu_alloced && !map->all_zeroes)
			return qio->bi_iter.bi_size;
		return 0;
	}

	return qio_subclus_covered_start_size(qcow2, qio, (u32)map->ext_l2);
}
static u32 qio_all_zeroes_size(struct qcow2 *qcow2, struct qio *qio,
			       struct qcow2_map *map)
{
	if (!qcow2->ext_l2) {
		if (map->all_zeroes)
			return qio->bi_iter.bi_size;
		return 0;
	}

	return qio_subclus_covered_start_size(qcow2, qio, map->ext_l2 >> 32);
}

static bool qio_border_is_inside_unmapped_unit(struct qcow2 *qcow2,
					       struct qio *qio,
					       struct qcow2_map *map)
{
	u64 start_off, end_off;
	u8 start_bit, end_bit;
	u32 mapped_mask;
	bool ret;

	if (WARN_ON_ONCE(!(map->level & L2_LEVEL)))
		return false;

	if (qio->bi_iter.bi_size == qcow2->clu_size)
		return false;

	if (!qcow2->ext_l2)
		return !map->data_clu_alloced && !map->all_zeroes;

	start_bit = qio_subclu_indexes(qcow2, qio, &end_bit);
	start_off = bytes_off_in_cluster(qcow2, qio);
	end_off = start_off + qio->bi_iter.bi_size;
	mapped_mask = (u32)map->ext_l2 | (map->ext_l2 >> 32);

	ret = SUBCLU_OFF(qcow2, start_off) != 0 && ((1 << start_bit) & ~mapped_mask);
	ret |= SUBCLU_OFF(qcow2, end_off) != 0 && ((1 << end_bit) & ~mapped_mask);
	return ret;
}

static bool qio_is_fully_alloced(struct qcow2 *qcow2, struct qio *qio,
				 struct qcow2_map *map)
{
	u32 subclus_mask, alloced_mask;

	if (!(map->level & L2_LEVEL))
		return false;

	if (!qcow2->ext_l2)
		return map->data_clu_alloced && !map->all_zeroes;

	subclus_mask = qio_subclus_mask(qcow2, qio);
	alloced_mask = (u32)map->ext_l2;

	return !(subclus_mask & ~alloced_mask);
}

static loff_t parse_l1(struct qcow2 *qcow2, struct qcow2_map *map,
		       struct qio **qio, bool write)

{
	struct qcow2_map_item *l1 = &map->l1;
	bool wants_alloc, exactly_one;
	u64 pos, entry;
	loff_t ret;

	lockdep_assert_held(&qcow2->md_pages_lock);
	entry = get_u64_from_be_page(l1->md->page, l1->index_in_page);
	exactly_one = entry & LX_REFCOUNT_EXACTLY_ONE;
	pos = entry & ~LX_REFCOUNT_EXACTLY_ONE;

	ret = -EIO;
	if (WARN_ON_ONCE(entry & L1_RESERVED_ZERO_MASK))
		goto out;
	if (WARN_ON_ONCE(CLU_OFF(qcow2, pos) != 0))
		goto out;
	if (WARN_ON_ONCE(pos && !qcow2->hdr.nb_snapshots && !exactly_one))
		goto out;

	if (pos && !exactly_one) {
		map->clu_is_cow = true;
		map->cow_clu_pos = pos;
		map->cow_clu_end = pos + qcow2->clu_size;
	}

	ret = 0;
	if (delay_if_locked(qcow2, l1->md, l1->index_in_page, qio))
		goto out;
	wants_alloc = write && (pos == 0 || map->clu_is_cow);
	if (__delay_if_writeback(qcow2, l1->md, l1->index_in_page, qio, wants_alloc))
		goto out;
	if (delay_if_dirty(qcow2, l1->md, l1->index_in_page, qio))
		goto out;
	if (write && map->clu_is_cow)
		goto out; /* Avoid to return pos */

	ret = pos;
out:
	return ret;
}

static int parse_compressed_l2(struct qcow2 *qcow2, struct qcow2_map *map,
			       struct qio **qio, bool write, u64 entry)
{
	u8 offset_bits = 62 - (qcow2->hdr.cluster_bits - 8);
	struct qcow2_map_item *l2 = &map->l2;
	u64 pos, end;

	/* Even for write: it reads compressed clu firstly */
	if (delay_if_wpc_readers_locked(qcow2, l2->md, qio))
		return 0;
	if (WARN_ON_ONCE(dirty_or_writeback(qcow2, l2->md, l2->index_in_page)))
		return -EIO;

	map->compressed = true;
	pos = entry << (64 - offset_bits) >> (64 - offset_bits);
	map->compressed_sectors = entry >> offset_bits;
	end = compressed_clu_end_pos(pos, map->compressed_sectors);

	map->clu_is_cow = true;
	/* @pos may point to middle of cluster, so this may take 2 clusters */
	map->cow_clu_pos = round_down(pos, qcow2->clu_size);
	map->cow_clu_end = round_up(end, qcow2->clu_size);
	map->ext_l2 = ~(u32)0;

	if (WARN_ON_ONCE((pos >> 56) != 0 || !entry ||
			 /* This would be very strange compression */
			 end - pos > qcow2->clu_size))
		return -EIO;
	map->data_clu_alloced = true;
	return pos;
}

static loff_t parse_l2(struct qcow2 *qcow2, struct qcow2_map *map,
		       struct qio **qio, bool write)

{
	bool wants_alloc, exactly_one, all_zeroes;
	struct qcow2_map_item *l2 = &map->l2;
	u64 entry, pos, ext_l2;
	loff_t ret;

	lockdep_assert_held(&qcow2->md_pages_lock);
	entry = get_u64_from_be_page(l2->md->page, l2->index_in_page);
	exactly_one = entry & LX_REFCOUNT_EXACTLY_ONE;
	entry &= ~LX_REFCOUNT_EXACTLY_ONE;

	/*
	 * COW -- note that original cluster type here may be even compressed.
	 * READ: cluster data may disappear and become reused after
	 *	 compressed COW fail.
	 * WRITE: now we don't handle sending of accompanying qios.
	 */
	ret = 0;
	if (delay_if_locked(qcow2, l2->md, l2->index_in_page, qio))
		goto out;

	ret = -EIO;
	if (entry & L2_COMPRESSED_CLUSTER) {
		entry &= ~L2_COMPRESSED_CLUSTER;
		if (WARN_ON_ONCE(exactly_one || !entry))
			goto out;
		ret = parse_compressed_l2(qcow2, map, qio, write, entry);
		goto out;
	}

	all_zeroes = map->all_zeroes = entry & L2_READS_ALL_ZEROES;
	entry &= ~L2_READS_ALL_ZEROES;
	pos = entry;

	if (pos && !exactly_one) {
		map->clu_is_cow = true;
		map->cow_clu_pos = pos;
		map->cow_clu_end = pos + qcow2->clu_size;
	}

	if (WARN_ON_ONCE(entry & L2_RESERVED_ZERO_MASK))
		goto out;
	if (WARN_ON_ONCE(pos && !qcow2->hdr.nb_snapshots && !exactly_one))
		goto out;
	if (WARN_ON_ONCE(CLU_OFF(qcow2, entry) != 0))
		goto out;

	if (!qcow2->ext_l2) {
		if (all_zeroes && pos)
			map->prealloced = true;

		if (WARN_ON_ONCE(map->prealloced && !exactly_one))
			goto out;
		if (WARN_ON_ONCE(map->clu_is_cow && all_zeroes))
			goto out;

		ret = 0;

		wants_alloc = (pos == 0 || map->prealloced || map->clu_is_cow);
		if (write && __delay_if_writeback(qcow2, l2->md, l2->index_in_page,
						  qio, wants_alloc))
			goto out;
		/*
		 * When cluster is under allocation, READ should see zeroes.
		 * On writeback, we could delay READ like for WRITE is done,
		 * but fast zeroing may be useful optimizations on big
		 * clusters (say, 1Mb).
		 * In case of md is dirty, WRITE is not delayed. It becomes
		 * referred to md->wbd in perform_rw_mapped(), and it runs
		 * in parallel with md writeback (accompanying qio).
		 */
		if (!write && dirty_or_writeback(qcow2, l2->md, l2->index_in_page)) {
			perform_zero_read(*qio, (*qio)->bi_iter.bi_size);
			goto out;
		}
	} else {
		ext_l2 = get_u64_from_be_page(l2->md->page,
					      l2->index_in_page + 1);
		map->ext_l2 = ext_l2;
		map->subclus_mask = 0;
		if (!fake_service_qio(*qio))
			map->subclus_mask = qio_subclus_mask(qcow2, *qio);

		if (WARN_ON_ONCE(all_zeroes || (ext_l2 & (ext_l2 >> 32))))
			goto out;

		/*
		 * Note, that if "l2->index_in_page" is changed,
		 * then "l2->index_in_page + 1" is also changed.
		 * So, here we check only the second of them.
		 */
		ret = 0;
		if (!write &&
		    delay_if_dirty(qcow2, l2->md, l2->index_in_page + 1, qio))
			goto out;
		if (__delay_if_writeback(qcow2, l2->md, l2->index_in_page + 1,
					 qio, true))
			goto out;
	}

	if (pos)
		map->data_clu_alloced = true;

	/* See comment in submit_read_whole_cow_clu() */
	if (!write && pos && !all_zeroes && !exactly_one &&
	    delay_if_wpc_readers_locked(qcow2, l2->md, qio))
		goto out;

	ret = pos;
out:
	return ret;
}

/*
 * This may be called with @qio == NULL, in case of we sure
 * that R1/R2 are already cached and up to date.
 * Returned R1 is *unstable* if we are not in main kwork,
 * since relocate_refcount_table() may move it right after
 * md_pages_lock release.
 */
static int __handle_r1r2_maps(struct qcow2 *qcow2, loff_t pos, struct qio **qio,
			   struct qcow2_map_item *r1, struct qcow2_map_item *r2)
{
	int ret = -EIO;
	/*
	 * We hold the lock while dereferencing both of R1 and R2
	 * to close the race with relocate_refcount_table().
	 */
	spin_lock_irq(&qcow2->md_pages_lock);
	if (calc_refcounters_map(qcow2, pos, r1, r2) < 0)
		goto unlock;

	/* Check R1 table */
	ret = __handle_md_page(qcow2, r1->page_id, qio, &r1->md);
	if (ret <= 0)
		goto unlock;

	ret = calc_r2_page_id(qcow2, r1, r2);
	if (ret < 0)
		goto unlock;

	/* Check R2 table */
	ret = __handle_md_page(qcow2, r2->page_id, qio, &r2->md);
unlock:
	spin_unlock_irq(&qcow2->md_pages_lock);
	if (ret <= 0)
		return ret;
	/*
	 * XXX: we do not care about R1 or R2 may be under writeback,
	 * since the most actual version of them is cached in memory.
	 */
	return 1;
}

/*
 * This aims to be called for resolving R1 and R2 md pages
 * related to already allocated cluster at @pos.
 * Return value: 1 if pages are found and cached; 0 in case
 * of read md page was submitted; negative in case of error.
 * The difference to raw __handle_r1r2_maps() is in sanity
 * checks of R2 cluster exists and refblock entry is sane.
 * Sanity check is disabled on clusters containing compressed
 * clusters (their refcount is equal to num of compressed users).
 */
static int qcow2_handle_r1r2_maps(struct qcow2 *qcow2, loff_t pos, struct qio **qio,
	struct qcow2_map_item *r1, struct qcow2_map_item *r2, bool compressed)
{
	u64 entry;
	int ret;

	ret = __handle_r1r2_maps(qcow2, pos, qio, r1, r2);
	/* Cluster mapped, but refcount table doesn't know? */
	WARN_ON_ONCE(ret == -ENOENT);

	if (ret == 1 && !qcow2->hdr.nb_snapshots && !compressed) {
		entry = get_r2_entry(qcow2, r2->md, r2->index_in_page);
		/* Sanity check */
		if (unlikely(entry > 1)) {
			pr_err("refblock=%llu, while no snapshots\n", entry);
			return -EIO;
		}
	}

	return ret;
}

/*
 * This caches pages of allocated on disk md levels, which are
 * required for submission @qio, and checks they are stable.
 * The result of parsing L1/L2 entries is stored in @map.
 * Returns: negative in case of error, or 0 if success.
 * Special case: return 0 with zeroed @qio means @qio was deferred
 * till some event: reading of md page, end of writeback, etc.
 */
static int parse_metadata(struct qcow2 *qcow2, struct qio **qio,
			  struct qcow2_map *map)
{
	bool write = op_is_write((*qio)->bi_op);
	struct md_page *md;
	u64 pos;
	s64 ret;

	WARN_ON_ONCE(map->data_clu_pos != 0);
	if (qcow2_calc_cluster_map(qcow2, *qio, map) < 0)
		return -EIO;
	spin_lock_irq(&qcow2->md_pages_lock);
again:
	/* Check L1 page */
	ret = __handle_md_page(qcow2, map->l1.page_id, qio, &md);
	if (ret <= 0)
		goto unlock;
	map->l1.md = md;
	map->level = L1_LEVEL;

	/* Find L2 cluster (from L1 page) */
	pos = ret = parse_l1(qcow2, map, qio, write);
	if (ret <= 0) /* Err, delayed, L2 is not allocated, or zero read */
		goto unlock;

	/* pos is start of cluster */
	pos += map->l2.index * sizeof(u64);
	calc_page_id_and_index(pos, &map->l2.page_id, &map->l2.index_in_page);

	/* Check L2 page */
	ret = __handle_md_page(qcow2, map->l2.page_id, qio, &md);
	/*
	 * Only main kwork initiates md changes, but there is side readers.
	 * This is to order kwork changes with readers, so they get consistent L2.
	 */
	if (unlikely(ret == -EAGAIN)) {
		map->level = 0; /* This should be enough */
		goto again;
	} else if (ret <= 0) {
		goto unlock;
	}
	map->l2.md = md;
	map->level |= L2_LEVEL;

	/* Find DATA cluster (from L2 page) */
	pos = ret = parse_l2(qcow2, map, qio, write);
unlock:
	spin_unlock_irq(&qcow2->md_pages_lock);
	if (ret <= 0) /* Err, delayed, DATA is not allocated, or zero read */
		return ret;

	map->data_clu_pos = pos;
	if (!write || !map->clu_is_cow)
		return 0;

	/* Now refcounters table/block */
	ret = qcow2_handle_r1r2_maps(qcow2, pos, qio, &map->r1,
			       &map->r2, map->compressed);
	return ret < 0 ? ret : 0;
}

/*
 * This occupies cluster at @r2_pos for R2 cluster,
 * and connects it to R1 table entry.
 */
static int place_r2(struct qcow2 *qcow2, struct qcow2_map_item *r1,
		    struct qcow2_map_item *r2, loff_t r2_pos, struct qio **qio)
{
	u64 page_id = r2_pos >> PAGE_SHIFT;
	int ret;

	if (delay_if_writeback(qcow2, r1->md, r1->index_in_page, qio, true))
		return 0;

	ret = qcow2_punch_hole(qcow2->file, r2_pos, qcow2->clu_size);
	if (ret) {
		pr_err("qcow2: punch hole: %d\n", ret);
		return ret;
	}

	ret = qcow2_alloc_and_insert_md_page(qcow2, page_id, &r2->md);
	if (ret < 0) {
		pr_err("Can't alloc: ret=%d, page_id=%llu\n", ret, page_id);
		return ret;
	}

	qcow2_zero_fill_page_from(r2->md->page, 0);

	spin_lock_irq(&qcow2->md_pages_lock);
	set_u64_to_be_page(r1->md->page, r1->index_in_page, r2_pos);
	qcow2_md_make_dirty(qcow2, r1->md, true);
	r2->md->status |= MD_UPTODATE;
	spin_unlock_irq(&qcow2->md_pages_lock);

	mark_cluster_used(qcow2, r2->md, r2->index_in_page);
	return 1;
}

static s32 find_unused_block_entry(struct qcow2 *qcow2, struct md_page *md,
				   u32 from)
{
	u32 indexes_per_page = PAGE_SIZE * 8 / qcow2->refblock_bits;
	long i, ret = -ENOENT;

	lockdep_assert_held(&qcow2->md_pages_lock);
	for (i = from; i < indexes_per_page; i++) {
		if (get_r2_entry(qcow2, md, i) == 0) {
			ret = i;
			break;
		}
	}

	return ret;
}

static loff_t find_unused_cluster(struct qcow2 *qcow2, struct qio **qio,
				  struct qcow2_map_item *r1,
				  struct qcow2_map_item *r2)
{
	u32 clu_size = qcow2->clu_size;
	s32 index, ret;
	loff_t pos;
again:
	pos = READ_ONCE(qcow2->free_cluster_search_pos);
	if (pos >= qcow2->reftable_max_file_size)
		return -ENOENT;

	ret = __handle_r1r2_maps(qcow2, pos, qio, r1, r2);
	if (ret <= 0) {
		if (ret != -ENOENT)
			return ret;
		/*
		 * Since pos is not covered by R2, the whole cluster
		 * must be unused. Use it to store R2 cluster.
		 * Both indexes must be 0 here, because of we allocate
		 * clusters from small to big.
		 */
		WARN_ON_ONCE(r2->index_in_page != 0 || r2->index != 0);
		ret = place_r2(qcow2, r1, r2, pos, qio);
		if (ret <= 0)
			return ret;
		goto again;
	}

	spin_lock_irq(&qcow2->md_pages_lock);
	/*
	 * This is rare usually and very rare during intensive write,
	 * since R1 and R2 writeback are delayed. We faster make all
	 * blocks of the page to be used, than writeback starts.
	 */
	if (__delay_if_writeback(qcow2, r2->md, r2->index_in_page, qio, true)) {
		pos = 0;
		goto unlock;
	}

	if (unlikely(pos != qcow2->free_cluster_search_pos)) {
		/* Parallel mark_cluster_unused() changed it */
		spin_unlock_irq(&qcow2->md_pages_lock);
		goto again;
	}

	index = find_unused_block_entry(qcow2, r2->md, r2->index_in_page);
	if (index < 0) {
		/* No unused entries in this page */
		pos = round_up(pos + 1, qcow2->r2_page_covered_file_size);
		qcow2->free_cluster_search_pos = pos;
		spin_unlock_irq(&qcow2->md_pages_lock);
		goto again;
	}

	/* Advance pos and R2 indexes to point to the block entry */
	pos += (u64)(index - r2->index_in_page) * clu_size;
	r2->index += index - r2->index_in_page;
	r2->index_in_page = index;

	/* In case of caller fails, we have this value cached */
	qcow2->free_cluster_search_pos = pos;
unlock:
	spin_unlock_irq(&qcow2->md_pages_lock);

	return pos;
}

int qcow2_truncate_safe(struct file *file, loff_t new_len)
{
	int ret;

	ret = vfs_truncate2(&file->f_path, new_len, file);
	if (ret)
		return ret;

	return vfs_fsync(file, 0);
}

static int truncate_prealloc_safe(struct qcow2 *qcow2, loff_t len, const char *func)
{
	loff_t prealloc_len, max_prealloc_len = qcow2->reftable_max_file_size;
	struct file *file = qcow2->file;
	loff_t new_len = len;
	int ret;

	if (new_len <= qcow2->file_size)
		return 0;
	if (new_len < qcow2->reftable_max_file_size) {
		prealloc_len = ALIGN(new_len, PREALLOC_SIZE);
		new_len = min_t(loff_t, prealloc_len, max_prealloc_len);
	}

	ret = qcow2_truncate_safe(file, new_len);
	if (ret) {
		pr_err("qcow2: %s->truncate: %d\n", func, ret);
		return ret;
	}

	qcow2->file_size = new_len;
	qcow2->file_preallocated_area_start = len;
	return 0;
}

static int qcow2_punch_hole(struct file *file, loff_t pos, loff_t len)
{
	return vfs_fallocate(file, FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE,
			     pos, len);
}

static void set_reftable_in_raw_hdr(struct page *page0, loff_t pos, loff_t clus)
{
	struct QCowHeader *raw_hdr;

	raw_hdr = kmap(page0);
	raw_hdr->refcount_table_offset = cpu_to_be64(pos);
	raw_hdr->refcount_table_clusters = cpu_to_be32(clus);
	kunmap(page0);
}

/*
 * After all file space covered by current reftable (R1) became used,
 * this relocates reftable (R1) to new place and extends its size.
 * The situation is rather rare, and since the function is already
 * complicated, we should not demonstrate excessive creativity
 * and optimize it in prejudice of readability.
 *
 * We act in the way to provide safe rollback throughout whole function.
 * Firstly, we cache every related md we're going to use on relocation.
 * New reftable (R1) is placed next to max cluster covered by old R1.
 * Since new reftable (R1) clusters should be marked as used after
 * relocation, we also allocate md for new refblocks (R2) (they should
 * cover both new R1 and new R2 -- themself). Note, that new R1 and R2
 * clusters are in the part of file, which is not covered by old R1.
 *
 * Then, we try to write new hdr on disk. In case of failure, we
 * restore old hdr in memory and do safe rollback. In case of success,
 * there should not be more reasons to fail (only this driver's bugs).
 * Cached old reftable (R1) pages we renumber to point to new reftable (R1)
 * place. Then we mark old reftable (R1) clusters as unused, while
 * new reftable (R1) clusters as used.
 *
 * In further, updated R1 and R2 pages will be written on disk
 * on writeback like during any other R1/R2 update. Even in case of
 * power down, when refcounts become lost, check util on next mount
 * can easily restore them by L1 and L2, which are stable.
 */
static int relocate_refcount_table(struct qcow2 *qcow2, struct qio **qio)
{
	loff_t i, old_pos, old_end, pos, end, r2_end, delta;
	u32 old_clus, clus, clu_size = qcow2->clu_size;
	u32 r2_clus, bits = qcow2->refblock_bits;
	unsigned long nr_pages, index;
	struct qcow2_map_item r1, r2;
	struct md_page *md0, *md;
	int ret;

	/* FIXME: check there is no in-flight operations */
	old_clus = qcow2->hdr.refcount_table_clusters;
	clus = min_t(u32, old_clus + 1, REFCOUNT_TABLE_MAX_SIZE / clu_size);
	if (clus <= old_clus) {
		pr_debug_ratelimited("qcow2: maximal refcount table size\n");
		return -ENFILE;
	}

	/* Boundaries of old reftable (R1) */
	old_pos = qcow2->hdr.refcount_table_offset;
	old_end = old_pos + (u64)old_clus * clu_size;
	nr_pages = (old_end - old_pos) / PAGE_SIZE;

	/* Cache old reftable (R1) pages and image header */
	index = old_pos / PAGE_SIZE;
	for (i = 0; i <= nr_pages; i++, index++) {
		if (i == nr_pages)
			index = 0; /* hdr */
		ret = handle_md_page(qcow2, index, qio, &md);
		if (ret <= 0)
			return ret;
		/*
		 * Writeback mustn't require cluster allocation,
		 * otherwise it may result in deadlock here.
		 */
		if (delay_if_writeback(qcow2, md, -1, qio, true))
			return 0;
	}
	md0 = md;

	/* Cache R1/R2 pages covering clusters of old reftable (R1) */
	for (i = old_pos; i < old_end; i += PAGE_SIZE) {
		ret = qcow2_handle_r1r2_maps(qcow2, i, qio, &r1, &r2, false);
		if (ret <= 0)
			return ret;
		if (delay_if_writeback(qcow2, r1.md, -1, qio, true))
			return 0;
	}

	/*
	 * We need R2 clusters to mark used both: new reftable (R1) clusters
	 * and these refblock clusters (R2) themself. This number comes from:
	 * r2_clus >= (clus + r2_clus) * bits / (8 * clu_size)
	 */
	r2_clus = DIV_ROUND_UP((u64)clus * bits, 8 * clu_size - bits);

	/* Choose position next to max cluster covered by old R1/R2 */
	pos = qcow2->reftable_max_file_size;
	end = pos + (u64)clus * clu_size;
	r2_end = end + (u64)r2_clus * clu_size;
	ret = truncate_prealloc_safe(qcow2, r2_end, __func__);
	if (ret)
		return ret;

	/* Alloc R1/R2 pages covering clusters of new R1 and new R2 */
	for (i = pos + (u64)old_clus * clu_size; i < r2_end; i += PAGE_SIZE) {
		ret = qcow2_alloc_and_insert_md_page(qcow2, i >> PAGE_SHIFT, &md);
		if (ret < 0)
			goto err_free_r2_pages;
		spin_lock_irq(&qcow2->md_pages_lock);
		qcow2_zero_fill_page_from(md->page, 0);
		md->status |= MD_UPTODATE;
		spin_unlock_irq(&qcow2->md_pages_lock);
	}

	set_reftable_in_raw_hdr(md0->page, pos, clus);
	/* Write new hdr: last potential failing operation */
	ret = qcow2_rw_page_sync(WRITE, qcow2, 0, md0->page);
	if (ret) {
		/* Restore old R1 */
		set_reftable_in_raw_hdr(md0->page, old_pos, old_clus);
		goto err_free_r2_pages;
	}

	/*
	 * __handle_r1r2_maps() want to get consistent values:
	 * refcount_table_offset must match correct md pages.
	 */
	spin_lock_irq(&qcow2->md_pages_lock);
	/* Update cached values */
	qcow2->hdr.refcount_table_offset = pos;
	qcow2->hdr.refcount_table_clusters = clus;
	qcow2_calc_cached_parameters(qcow2, &qcow2->hdr);

	/* Now renumber R1 cached pages to point new place and mark dirty */
	index = old_pos / PAGE_SIZE;
	delta = (pos - old_pos) / PAGE_SIZE;
	for (i = 0; i < nr_pages; i++, index++) {
		md = qcow2_md_page_renumber(qcow2, index, index + delta);
		if (!WARN_ON_ONCE(!md))
			qcow2_md_make_dirty(qcow2, md, true);
		if (!md)
			break; /* goto err_free_r2_pages */
	}
	spin_unlock_irq(&qcow2->md_pages_lock);
	if (i != nr_pages)
		goto err_free_r2_pages;

	/* Connect new R2 to new R1 */
	for (i = end; i < r2_end; i += clu_size) {
		if (calc_refcounters_map(qcow2, i, &r1, &r2) < 0) {
			WARN_ON_ONCE(1);
			goto err_free_r2_pages;
		}
		ret = handle_md_page(qcow2, r1.page_id, NULL, &md);
		if (WARN_ON_ONCE(ret <= 0))
			goto err_free_r2_pages;
		spin_lock_irq(&qcow2->md_pages_lock);
		set_u64_to_be_page(md->page, r1.index_in_page, i);
		qcow2_md_make_dirty(qcow2, md, true);
		spin_unlock_irq(&qcow2->md_pages_lock);
	}

	/* Mark used new R1 and R2 clusters */
	for (i = pos; i < r2_end; i += clu_size) {
		ret = qcow2_handle_r1r2_maps(qcow2, i, NULL, &r1, &r2, false);
		if (WARN_ON_ONCE(ret <= 0))
			goto err_free_r2_pages;
		mark_cluster_used(qcow2, r2.md, r2.index_in_page);
	}

	/* Mark unused old reftable (R1) clusters */
	for (i = old_pos; i < old_end; i += clu_size) {
		ret = qcow2_handle_r1r2_maps(qcow2, i, NULL, &r1, &r2, false);
		if (WARN_ON_ONCE(ret <= 0))
			goto err_free_r2_pages;
		mark_cluster_unused(qcow2, r2.md, r2.index_in_page, i);
	}

	return 1;

err_free_r2_pages:
	for (i = end; i < r2_end; i += clu_size) {
		ret = handle_md_page(qcow2, i >> PAGE_SHIFT, NULL, &md);
		if (ret <= 0)
			break;
		spin_lock_irq(&qcow2->md_pages_lock);
		qcow2_md_page_erase(qcow2, md);
		spin_unlock_irq(&qcow2->md_pages_lock);
		qcow2_free_md_page(md);
	}
	/* TODO: switch to RO */
	return -EIO;
}

/*
 * This function is aimed to be called only from main work.
 * In case of wish to use it from more places, it's needed
 * to make sure nobody can reuse cluster obtained from
 * find_unused_cluster() before mark_cluster_used() in done.
 */
static loff_t allocate_cluster(struct qcow2 *qcow2, struct qio *qio,
		      struct md_page **r2_md, u32 *r2_index_in_page)
{
	u32 clu_size = qcow2->clu_size;
	struct file *file = qcow2->file;
	loff_t pos, off, end, old_size;
	struct qcow2_map_item r1, r2;
	int ret;
again:
	pos = find_unused_cluster(qcow2, &qio, &r1, &r2);
	if (unlikely(pos == -ENOENT)) {
		ret = relocate_refcount_table(qcow2, &qio);
		if (ret <= 0)
			return ret;
		goto again;
	}
	if (pos <= 0)
		return pos;

	end = pos + clu_size;
	old_size = qcow2->file_size;

	if (pos < qcow2->file_preallocated_area_start) {
		/* Clu at @pos may contain dirty data */
		off = min_t(loff_t, old_size, end);
		ret = qcow2_punch_hole(file, pos, off - pos);
		if (ret) {
			pr_err("qcow2: punch hole: %d\n", ret);
			return ret;
		}
	}

	if (end > old_size) {
		ret = truncate_prealloc_safe(qcow2, end, __func__);
		if (ret)
			return ret;
	} else if (pos < qcow2->file_preallocated_area_start) {
		/*
		 * Flush punch_hole() modifications.
		 * TODO: track recentry unused blocks
		 * and punch holes in background.
		 */
		ret = vfs_fsync(file, 0);
		if (ret)
			return ret;
	}

	if (end > qcow2->file_preallocated_area_start)
		qcow2->file_preallocated_area_start = end;

	mark_cluster_used(qcow2, r2.md, r2.index_in_page);
	if (r2_md)
		*r2_md = r2.md;
	if (r2_index_in_page)
		*r2_index_in_page = r2.index_in_page;
	return pos;
}

#define LU_SET_ONE_MASK		(1 << 0)
#define LU_WANTS_PE_PAGE	(1 << 1)
#define LU_WANTS_ALLOC		(1 << 2)
#define LU_IGN_CHANGED_IND	(1 << 3)
static int prepare_l_entry_update(struct qcow2 *qcow2, struct qio *qio,
				  struct md_page *md, u32 index_in_page,
				  u64 *pval, u32 arg_mask)
{
	bool wants_pe_page = (arg_mask & LU_WANTS_PE_PAGE);
	struct wb_desc *new_wbd = NULL;
	struct page *pe_page = NULL;
	u64 old_val, val = *pval;

	/* parse_metadata()->delay_if_writeback() delays them */
	if (WARN_ON_ONCE(READ_ONCE(md->status) & MD_WRITEBACK))
		return -EIO;
	/*
	 * L1/L2 pages become set and unset dirty from main
	 * work only, so lock is not required for visibility.
	 */
	if (!(md->status & MD_DIRTY)) {
		/* We're the first changing entry in this md page. */
		new_wbd = alloc_wbd(wants_pe_page);
		if (!new_wbd)
			return -ENOMEM;
		new_wbd->md = md;
	} else if (wants_pe_page && !md->wbd->pe_page) {
		pe_page = alloc_page(GFP_NOIO|__GFP_ZERO);
		if (!pe_page)
			return -ENOMEM;
	}

	if (arg_mask & LU_WANTS_ALLOC) {
		/* Allocate new zeroed data cluster: no failing actions after it */
		loff_t pos = allocate_cluster(qcow2, qio, NULL, NULL);

		if (pos <= 0) {
			free_wbd(new_wbd);
			if (pe_page)
				put_page(pe_page);
			return (int)pos;
		}
		val = *pval = pos;
	}

	spin_lock_irq(&qcow2->md_pages_lock);
	if (qcow2_md_make_dirty(qcow2, md, false))
		md->wbd = new_wbd;
	else
		WARN_ON_ONCE(new_wbd);
	if (!(arg_mask & LU_IGN_CHANGED_IND))
		WARN_ON_ONCE(test_bit(index_in_page, md->wbd->changed_indexes));
	set_bit(index_in_page, md->wbd->changed_indexes);

	if (wants_pe_page && !md->wbd->pe_page)
		md->wbd->pe_page = pe_page;
	else
		WARN_ON_ONCE(pe_page);
	if (wants_pe_page) {
		old_val = get_u64_from_be_page(md->page, index_in_page);
		set_u64_to_be_page(md->wbd->pe_page, index_in_page, old_val);
	}

	/* Set new mapping */
	if (arg_mask & LU_SET_ONE_MASK)
		val |= LX_REFCOUNT_EXACTLY_ONE;
	set_u64_to_be_page(md->page, index_in_page, val);

	/* Keep in mind, we link qio to md in perform_rw_mapped() */
	spin_unlock_irq(&qcow2->md_pages_lock);
	return 1;
}

static int prepare_l1l2_allocation(struct qcow2 *qcow2, struct qio *qio,
				   struct qcow2_map *map)
{
	u32 arg_mask, subclus_mask;
	u64 val;
	int ret;

	if (WARN_ON_ONCE(!(map->level & L1_LEVEL)))
		return -EIO; /* Sanity check: L1 must be cached */

	if (!(map->level & L2_LEVEL)) {
		WARN_ON_ONCE(map->prealloced || map->compressed);
		/* Allocate cluster for L2 entries, and prepare L1 update */
		ret = prepare_l_entry_update(qcow2, qio, map->l1.md,
					     map->l1.index_in_page, &val,
					     LU_SET_ONE_MASK|LU_WANTS_ALLOC);
		if (ret <= 0)
			return ret;

		/*
		 * 1)For now we don't do parallel L1 and L2 updates.
		 * 2)For COW from backing file this is must.
		 */
		spin_lock_irq(&qcow2->md_pages_lock);
		list_add_tail(&qio->link, &map->l1.md->wait_list);
		spin_unlock_irq(&qcow2->md_pages_lock);
		return 0;
	}

	if (!map->data_clu_alloced || map->all_zeroes) {
		WARN_ON_ONCE(!map->prealloced != !map->data_clu_pos ||
			     map->compressed || map->clu_is_cow);
		/* Allocate cluster for DATA, and prepare L2 update */
		arg_mask = LU_SET_ONE_MASK;
		if (map->prealloced || qcow2->ext_l2)
			arg_mask |= LU_WANTS_PE_PAGE;
		if (!map->prealloced)
			arg_mask |= LU_WANTS_ALLOC;

		ret = prepare_l_entry_update(qcow2, qio, map->l2.md,
					     map->l2.index_in_page,
					     &map->data_clu_pos, arg_mask);
		if (ret <= 0)
			return ret;

		if (!qcow2->ext_l2)
			return 1;

		/*
		 * pe_page is allocated => ext_l2 update won't fail =>
		 * revert of prepare_l_entry_update() won't be needed.
		 */
		WARN_ON_ONCE(!map->l2.md->wbd->pe_page);
	}

	subclus_mask = qio_subclus_mask(qcow2, qio);
	val = map->ext_l2 | subclus_mask;
	val &= ~((u64)subclus_mask << 32);
	arg_mask = LU_WANTS_PE_PAGE|LU_IGN_CHANGED_IND;

	return prepare_l_entry_update(qcow2, qio, map->l2.md,
				      map->l2.index_in_page + 1,
				      &val, arg_mask);
}

/*
 * Set some wb index to block WRITEs to this cluster.
 * READs also must be blocked, since they may get data
 * from cluster, after WRITE marked it's unused. Also,
 * we have to wait all previous READs. We do that around
 * index wb. See md->wpc_noread_count update details.
 */
static int prepare_l_entry_cow(struct qcow2 *qcow2, struct qcow2_map *map,
			       struct qio *qio, struct md_page *md,
			       u32 index_in_page, loff_t cow_clu_pos,
			       loff_t cow_clu_end, u8 cow_level)
{
	struct lock_desc *lockd = NULL;
	struct qio_ext *ext;

	if (qcow2_alloc_qio_ext(qio))
		return -ENOMEM;

	ext = qio->ext;
	ext->cow_clu_pos = cow_clu_pos;
	ext->cow_clu_end = cow_clu_end;
	ext->cow_level = cow_level;

	spin_lock_irq(&qcow2->md_pages_lock);
	if (!md->lockd) {
		spin_unlock_irq(&qcow2->md_pages_lock);
		lockd = kzalloc(sizeof(*lockd), GFP_NOIO);
		if (!lockd)
			return -ENOMEM;
		spin_lock_irq(&qcow2->md_pages_lock);
		md->lockd = lockd;
	}

	md_index_set_locked(qcow2, md, index_in_page);
	spin_unlock_irq(&qcow2->md_pages_lock);

	/* Setup ext, so qio_endio() on error will make all cleanup */
	ext->cleanup_mask = MD_INDEX_SET_UNLOCKED;
	ext->lx_index_in_page = index_in_page;
	return 1;
}

static int prepare_l1l2_cow(struct qcow2 *qcow2, struct qio *qio,
			    struct qcow2_map *map)
{
	if (WARN_ON_ONCE(!(map->level & L1_LEVEL)))
		return -EIO; /* Sanity check: L1 must be cached */

	if (!(map->level & L2_LEVEL)) {
		return prepare_l_entry_cow(qcow2, map, qio, map->l1.md,
					   map->l1.index_in_page,
					   map->cow_clu_pos,
					   map->cow_clu_end, L1_LEVEL);
	}

	return prepare_l_entry_cow(qcow2, map, qio, map->l2.md,
				  map->l2.index_in_page,
				  map->cow_clu_pos,
				  map->cow_clu_end, L2_LEVEL);
}

static void backward_merge_write_complete(struct qcow2_target *tgt, struct qio *unused,
					  void *qio_ptr, blk_status_t bi_status)
{
	struct qio *qio = qio_ptr;
	struct qcow2 *qcow2 = qio->qcow2;

	if (unlikely(bi_status)) {
		qio->bi_status = bi_status;
		qio_endio(qio);
		return;
	}

	WARN_ON_ONCE(qio->flags & QIO_IS_DISCARD_FL);
	qio->flags |= QIO_IS_DISCARD_FL;

	qio->queue_list_id = QLIST_COW_INDEXES;
	qcow2_dispatch_qios(qcow2, qio, NULL);
}

static void backward_merge_read_complete(struct qcow2_target *tgt, struct qio *unused,
					 void *qio_ptr, blk_status_t bi_status)
{
	struct qio *qio = qio_ptr;
	struct qcow2 *qcow2 = qio->qcow2;

	if (unlikely(bi_status)) {
		qio->bi_status = bi_status;
		qio_endio(qio);
		return;
	}

	qio->queue_list_id = QLIST_BMERGE_WRITE;
	qcow2_dispatch_qios(qcow2, qio, NULL);
}

static void requeue_if_ok(struct qcow2_target *tgt, struct qio *unused,
			  void *qio_ptr, blk_status_t bi_status)
{
	struct qio *qio = qio_ptr;

	if (bi_status) {
		qio->bi_status = bi_status;
		qio_endio(qio);
		return;
	}

	qcow2_dispatch_qios(qio->qcow2, qio, NULL);
}

static int prepare_backward_merge(struct qcow2 *qcow2, struct qio **qio,
				  struct qcow2_map *map, bool write)
{
	struct qio *aux_qio;
	int ret;

	if (!map->data_clu_alloced) {
		WARN_ON_ONCE(map->clu_is_cow); /* Strange COW at L1 */
		if (fake_merge_qio(*qio)) {
			/* Nothing is to merge */
			goto endio;
		}
		WARN_ON_ONCE(!maybe_mapped_in_lower_delta(qcow2, *qio));
		WARN_ON_ONCE((*qio)->queue_list_id != QLIST_DEFERRED);
		(*qio)->qcow2 = qcow2->lower;
		qcow2_dispatch_qios((*qio)->qcow2, *qio, NULL);
		return 0;
	}

	if (!op_is_write((*qio)->bi_op)) {
		/*
		 * READ qio may data may be contained in several deltas.
		 * We can't read lower delta after prepare_l1l2_cow()
		 * prepares us.
		 */
		aux_qio = qcow2_alloc_qio(qcow2->tgt->qio_pool, true);
		if (!aux_qio) {
			(*qio)->bi_status = BLK_STS_RESOURCE;
			goto endio;
		}

		qcow2_init_qio(aux_qio, REQ_OP_WRITE, qcow2);
		aux_qio->flags = QIO_IS_MERGE_FL|QIO_FREE_ON_ENDIO_FL;
		aux_qio->bi_io_vec = (*qio)->bi_io_vec;
		aux_qio->bi_iter = (*qio)->bi_iter;
		aux_qio->bi_iter.bi_size = 0;
		aux_qio->endio_cb = requeue_if_ok;
		aux_qio->endio_cb_data = *qio;
		WARN_ON_ONCE(!fake_merge_qio(aux_qio));
		*qio = aux_qio;
	}

	/*
	 * Mark as COW, as this completely defers any parallel qios.
	 * @qio is COW status holder.
	 */
	ret = prepare_l1l2_cow(qcow2, *qio, map);
	if (ret < 0) {
		(*qio)->bi_status = errno_to_blk_status(ret);
		goto endio;
	}

	if (!map->clu_is_cow) {
		/* Forced set these to unuse them after discard */
		(*qio)->ext->cow_clu_pos = map->data_clu_pos;
		(*qio)->ext->cow_clu_end = map->data_clu_pos + qcow2->clu_size;
	}

	return 1;
endio:
	qio_endio(*qio); /* Breaks COW set in prepare_l1l2_cow() */
	return 0;
}

static void qcow2_queue_resubmit(struct qio *qio)
{
	struct qcow2 *qcow2 = qio->qcow2;
	unsigned long flags;

	qio->queue_list_id = QLIST_INVALID;

	spin_lock_irqsave(&qcow2->deferred_lock, flags);
	list_add_tail(&qio->link, &qcow2->resubmit_qios);
	spin_unlock_irqrestore(&qcow2->deferred_lock, flags);
	queue_work(qcow2->tgt->wq, &qcow2->worker);
}

static void data_rw_complete(struct qio *qio)
{
	bool finalize_wbd = false, call_endio = true;
	bool write = op_is_write(qio->bi_op);
	blk_status_t bi_status = BLK_STS_OK;
	struct qcow2 *qcow2 = qio->qcow2;
	struct wb_desc *wbd;
	unsigned long flags;

	if (unlikely(qio->ret != qio->bi_iter.bi_size)) {
		if (qio->ret >= 0) {
			WARN_ON_ONCE(qio->ret == 0);
			qio_advance(qio, qio->ret);
			qcow2_queue_resubmit(qio);
			return;
		}
		bi_status = errno_to_blk_status(qio->ret);
	}

	wbd = qio->data;
	if (wbd) {
		WARN_ON_ONCE(!write);
		spin_lock_irqsave(&qcow2->md_pages_lock, flags);
		wbd->nr_submitted--;
		if (wbd->completed) {
			if (wbd->ret != 0)
				bi_status = errno_to_blk_status(wbd->ret);
			/* Last user of wbd? */
			finalize_wbd = (wbd->nr_submitted == 0);
		} else if (bi_status == BLK_STS_OK) {
			call_endio = false;
			list_add_tail(&qio->link, &wbd->completed_list);
		}
		spin_unlock_irqrestore(&qcow2->md_pages_lock, flags);
	}

	if (call_endio) {
		if (bi_status != BLK_STS_OK)
			qio->bi_status = bi_status;
		qio_endio(qio);
	}
	if (finalize_wbd)
		complete_wbd(qcow2, wbd);
}

static void perform_rw_mapped(struct qcow2_map *map, struct qio *qio)
{
	struct qcow2 *qcow2 = map->qcow2;
	struct md_page *md = map->l2.md;
	unsigned long flags;
	u32 index_in_page;
	unsigned int rw;

	rw = (op_is_write(qio->bi_op) ? WRITE : READ);
	qio->complete = data_rw_complete;
	qio->data = NULL;

	/*
	 * The idea is to submit L2 update and qio data write in parallel
	 * for better performance. But since qio_endio() can't be called
	 * till both of them are written, we attach qio to md to track that.
	 * In case of qio is not related to changed indexes, it shouldn't
	 * wait for md writeback completion.
	 *
	 * L1/L2 pages become set and unset dirty from main work only,
	 * so lock is not needed for MD_DIRTY/changed_indexes visibility.
	 */
	index_in_page = map->l2.index_in_page + !!(qcow2->ext_l2);
	if (rw == WRITE && (md->status & MD_DIRTY) &&
	    test_bit(index_in_page, md->wbd->changed_indexes)) {
		spin_lock_irqsave(&qcow2->md_pages_lock, flags);
		md->wbd->nr_submitted++;
		qio->data = md->wbd;
		spin_unlock_irqrestore(&qcow2->md_pages_lock, flags);
	}

	map_and_submit_rw(qcow2, map->data_clu_pos, qio);
}

static void cow_read_endio(struct qcow2_target *tgt, struct qio *unused,
			   void *qio_ptr, blk_status_t bi_status)

{
	struct qio *qio = qio_ptr;
	struct md_page *md = qio->ext->lx_md;
	struct qcow2 *qcow2 = qio->qcow2;

	dec_wpc_readers(qcow2, md); /* We ended to use shared clu on disk */

	if (unlikely(bi_status)) {
		qio->bi_status = bi_status;
		qio_endio(qio);
		return;
	}

	qio->queue_list_id = QLIST_COW_DATA;
	qcow2_dispatch_qios(qio->qcow2, qio, NULL);
}

static void submit_read_whole_cow_clu(struct qcow2_map *map, struct qio *qio)
{
	loff_t clu_pos = map->cow_clu_pos;
	struct qcow2 *qcow2 = map->qcow2;
	struct md_page *md = map->l1.md;
	u32 clu_size = qcow2->clu_size;
	struct qcow2_bvec *qvec;
	struct qio *read_qio;
	u32 nr_pages;

	WARN_ON_ONCE(map->level & L2_LEVEL);

	nr_pages = clu_size >> PAGE_SHIFT;
	read_qio = qcow2_alloc_qio_with_qvec(qcow2, nr_pages, REQ_OP_READ, true, &qvec);
	if (!read_qio) {
		qio->bi_status = BLK_STS_RESOURCE;
		qio_endio(qio); /* Frees ext */
		return;
	}
	read_qio->bi_iter.bi_sector = 0;
	read_qio->complete = data_rw_complete;
	read_qio->data = NULL;
	read_qio->flags |= QIO_FREE_ON_ENDIO_FL;
	read_qio->endio_cb = cow_read_endio;
	read_qio->endio_cb_data = qio;

	qio->data = qvec;
	qio->ext->cleanup_mask |= FREE_QIO_DATA_QVEC;
	qio->ext->lx_md = md;
	/*
	 * This is not obligatory, since cluster under COW can't disappear
	 * after we decrement its counter (another snap refers to it). We
	 * do that for the uniformity with compressed COW and better testing.
	 */
	inc_wpc_readers(md);

	map_and_submit_rw(qcow2, clu_pos, read_qio);
}

static int decompress_zlib_clu(struct qcow2 *qcow2, struct qcow2_bvec *qvec,
			       u16 page0_off, int count, void *buf, void *ws)
{
	unsigned int off = page0_off;
	struct z_stream_s strm;
	void *from;
	int i, ret;

	memset(&strm, 0, sizeof(strm));
	strm.workspace = ws;
	strm.next_out = buf;
	strm.avail_out = qcow2->clu_size;
	strm.total_out = 0;

	ret = zlib_inflateInit2(&strm, -MAX_WBITS); /* minus is zlib (!gzip) */
	if (ret != Z_OK)
		return -ENOMEM;

	count -= off;
	for (i = 0; i < qvec->nr_pages && count > 0; i++, off = 0) {
		from = kmap(qvec->bvec[i].bv_page);
		strm.next_in = from + off;
		strm.avail_in = min_t(int, qvec->bvec[i].bv_len - off, count);
		strm.total_in = 0;
		count -= strm.avail_in;
		ret = zlib_inflate(&strm, Z_NO_FLUSH);
		kunmap(qvec->bvec[i].bv_page);
		if (ret == Z_STREAM_END) {
			ret = Z_OK;
			break;
		}
		if (ret != Z_OK)
			break;
	}

	zlib_inflateEnd(&strm);
	if (ret == Z_OK && strm.total_out == qcow2->clu_size)
		return strm.total_out;
	return -EIO;
}

static int extract_one_compressed(struct qcow2 *qcow2, void *buf,
				  struct qcow2_bvec *qvec,
				  u16 page0_off, u32 qvec_len)
{
	void *ws = buf + qcow2->clu_size;

	return decompress_zlib_clu(qcow2, qvec, page0_off, qvec_len, buf, ws);
}

static int copy_buf_to_bvec_iter(const struct bio_vec *bvec,
				 const struct bvec_iter *biter,
				 const void *buf, u32 max)
{
	struct bvec_iter iter;
	struct bio_vec bv;
	void *to, *addr;
	int ret = 0;

	/* This is equivalent of bio_for_each_bvec() */
	qcow2_for_each_bvec(iter, bv, *biter, bvec) {
		if (WARN_ON_ONCE(bv.bv_len > max)) {
			ret = -EIO;
			break;
		}
		addr = kmap(bv.bv_page);
		to = addr + bv.bv_offset;
		memcpy(to, buf, bv.bv_len);
		kunmap(bv.bv_page);
		max -= bv.bv_len;
		buf += bv.bv_len;
	}

	return ret;
}

static int copy_clu_part_to_qio(struct qcow2 *qcow2, const void *buf, struct qio *qio)
{
	u32 max, seek, clu_size = qcow2->clu_size;

	seek = bytes_off_in_cluster(qcow2, qio);
	if (WARN_ON_ONCE(seek >= clu_size))
		return -EINVAL;

	buf += seek;
	max = clu_size - seek;

	return copy_buf_to_bvec_iter(qio->bi_io_vec, &qio->bi_iter, buf, max);
}

static int copy_zcow_slice(loff_t start, loff_t end, void *qio_p,
			   void *buf, void *consumed_p)
{
	struct qio *qio = qio_p;
	struct qcow2 *qcow2 = qio->qcow2;
	u32 clu_size = qcow2->clu_size;
	loff_t *consumed = consumed_p;
	struct qcow2_bvec *qvec = qio->data;
	struct bio_vec *bvec = qvec->bvec;
	struct bvec_iter iter;
	u32 off = CLU_OFF(qcow2, start);

	if (WARN_ON_ONCE(start >= end))
		return -EINVAL;

	iter.bi_size = end - start;
	iter.bi_idx = *consumed / PAGE_SIZE;
	iter.bi_bvec_done = off & ~PAGE_MASK;

	*consumed += round_up(end, PAGE_SIZE) - round_down(start, PAGE_SIZE);

	return copy_buf_to_bvec_iter(bvec, &iter, buf + off, clu_size - off);
}

static int prepare_zcow_slices(struct qcow2 *qcow2, void *buf, struct qio *qio)
{
	loff_t consumed = 0;
	/* Place required slices in that pages like further COW expects */
	for_each_cow_interval(qio, copy_zcow_slice, qio, buf, &consumed);
	return 0;
}

static void compressed_read_endio(struct qcow2_target *tgt, struct qio *unused,
				  void *qio_ptr, blk_status_t bi_status)

{
	struct qio *qio = qio_ptr;
	struct md_page *md = qio->ext->lx_md;
	struct qcow2 *qcow2 = qio->qcow2;

	dec_wpc_readers(qcow2, md); /* We ended to use compressed clu on disk */
	/*
	 * We don't interpret as error a positive ret, which is less,
	 * then submitted. Decompress will fail, if we read not enough.
	 */
	if (bi_status) {
		qio->bi_status = bi_status;
		qio_endio(qio);
		return;
	}

	qio->queue_list_id = QLIST_ZREAD;
	qcow2_dispatch_qios(qcow2, qio, NULL);
}

static void submit_read_compressed(struct qcow2_map *map, struct qio *qio,
				   bool for_cow)
{
	struct qcow2 *qcow2 = map->qcow2;
	struct qcow2_target *tgt = qcow2->tgt;
	u32 off, nr_pages, nr_alloc, nr_segs;
	struct md_page *l2_md = map->l2.md;
	u32 clu_size = qcow2->clu_size;
	struct qcow2_bvec *qvec;
	struct qio *read_qio;
	loff_t pos, end;

	WARN_ON_ONCE(!map->data_clu_pos);
	pos = round_down(map->data_clu_pos, PAGE_SIZE);
	end = compressed_clu_end_pos(map->data_clu_pos, map->compressed_sectors);
	end = round_up(end, PAGE_SIZE);
	nr_pages = (end - pos) / PAGE_SIZE;

	nr_alloc = nr_pages;
	if (for_cow) {
		qio->ext->cow_mask = calc_cow_mask(qcow2, map->ext_l2, qio,
					     true, map->clu_is_cow, false);

		/* COW reuses this qvec to write rest of cluster */
		nr_alloc = nr_segs = 0;
		for_each_cow_interval(qio, count_cow_pages,
				&nr_alloc, &nr_segs, NULL);
		if (unlikely(nr_alloc < nr_pages))
			nr_alloc = nr_pages;
		qio->ext->cow_segs = nr_segs;
	}

	read_qio = qcow2_alloc_qio_with_qvec(qcow2, nr_alloc, REQ_OP_READ,
				       true, &qvec);
	/* COW may already allocate qio->ext */
	if (!read_qio || (!qio->ext && qcow2_alloc_qio_ext(qio) < 0)) {
		if (read_qio) {
			qcow2_free_qvec_with_pages(qvec);
			qcow2_free_qio(read_qio, tgt->qio_pool);
		}
		qio->bi_status = BLK_STS_RESOURCE;
		qio_endio(qio); /* Frees ext */
		return;
	}
	qio->ext->zdata_off = off = map->data_clu_pos - pos;
	WARN_ON_ONCE(off > ~(u16)0);

	/* Reuse this to pass len to process_compressed_read() */
	qio->ret = end - pos;
	qio->data = qvec;
	qio->ext->cleanup_mask |= FREE_QIO_DATA_QVEC;
	qio->ext->lx_md = l2_md;
	if (for_cow && qcow2->ext_l2)
		qio->ext->new_ext_l2 = 0x00000000FFFFFFFF;
	inc_wpc_readers(l2_md);

	if (qio->bi_iter.bi_size == clu_size && for_cow) {
		/*
		 * Optimization: do not read clu from disk
		 * in case of here is complete clu rewrite.
		 * See the way process_cow_data_write()
		 * updates qvec. Also skips extract part.
		 */
		cow_read_endio(qcow2->tgt, NULL, qio, BLK_STS_OK);
		qcow2_free_qio(read_qio, tgt->qio_pool);
		return;
	}

	read_qio->flags |= QIO_FREE_ON_ENDIO_FL;
	read_qio->endio_cb = compressed_read_endio;
	read_qio->endio_cb_data = qio;

	read_qio->complete = data_rw_complete;
	read_qio->data = NULL;
	read_qio->bi_iter.bi_sector = to_sector(pos);
	read_qio->bi_iter.bi_size = end - pos;

	__submit_rw_mapped(qcow2, read_qio, nr_pages);
}

static void sliced_cow_read_complete(struct qcow2_target *tgt, struct qio *read_qio,
				     void *qio_ptr, blk_status_t bi_status)
{
	struct qio *qio = qio_ptr;
	struct qcow2 *qcow2 = qio->qcow2;

	if (unlikely(bi_status)) {
		qio->bi_status = bi_status;
		qio_endio(qio);
	} else {
		qio->queue_list_id = QLIST_COW_DATA;
		qcow2_dispatch_qios(qcow2, qio, NULL);
	}
}

/*
 * This creates a chain from qios going to discontinuous
 * slices of COW cluster. The main qio of chain will call
 * endio_cb only after all children qios are completed.
 */
static int split_sliced_cow_qio(loff_t start, loff_t end,
				void *qio_p, void *list_p,
				void *nr_segs_remaining_p)
{
	u32 *nr_segs = nr_segs_remaining_p;
	struct qio *split, *qio = qio_p;
	struct qcow2 *qcow2 = qio->qcow2;
	struct list_head *list = list_p;
	u32 size = end - start;

	if (WARN_ON_ONCE(start >= end))
		return -EINVAL;

	qio->bi_iter.bi_size = UINT_MAX; /* Silence qio_advance() */

	if (start & ~PAGE_MASK) {
		/* Skip our alignment. This only advances qio->bi_io_vec */
		qio_advance(qio, start & ~PAGE_MASK);
	}

	if (--*nr_segs > 0) {
		split = split_and_chain_qio(qcow2, qio, size);
		if (!split)
			return -ENOMEM;
		if (end & ~PAGE_MASK) {
			/* Skip our alignment: next does not want it */
			qio_advance(qio, PAGE_SIZE - (end & ~PAGE_MASK));
		}
		list_add_tail(&split->link, list);
		qio = split;
	}

	qio->bi_iter.bi_sector = to_sector(start);
	qio->bi_iter.bi_size = size;
	return 0;
}

static void submit_read_sliced_clu(struct qcow2_map *map, struct qio *qio,
				   qcow2_endio_t endio_cb)

{
	struct qcow2 *qcow2 = map->qcow2;
	struct qcow2_bvec *qvec;
	u32 nr_pages, nr_segs;
	struct qio *read_qio;
	LIST_HEAD(list);
	int ret;

	nr_pages = nr_segs = 0;
	for_each_cow_interval(qio, count_cow_pages,
			      &nr_pages, &nr_segs, NULL);

	qio->ext->lx_md = map->l2.md;
	qio->ext->cow_segs = nr_segs;

	if (!nr_segs) { /* Full overwrite */
		qio->data = NULL; /* qvec */
		endio_cb(qcow2->tgt, NULL, qio, BLK_STS_OK);
		goto out;
	}

	read_qio = qcow2_alloc_qio_with_qvec(qcow2, nr_pages, REQ_OP_READ, true, &qvec);
	if (!read_qio)
		goto err_alloc;
	read_qio->flags |= QIO_FREE_ON_ENDIO_FL;
	read_qio->endio_cb = endio_cb;
	read_qio->endio_cb_data = qio;

	qio->data = qvec;
	qio->ext->cleanup_mask |= FREE_QIO_DATA_QVEC;

	ret = for_each_cow_interval(qio, split_sliced_cow_qio,
				    read_qio, &list, &nr_segs);
	list_add_tail(&read_qio->link, &list);
	if (ret)
		goto err_split;

	while ((read_qio = qio_list_pop(&list)) != NULL)
		process_read_qio(qcow2, read_qio, map);
out:
	return;
err_split:
	end_qios(&list, BLK_STS_RESOURCE);
	goto out;
err_alloc:
	qio->bi_status = BLK_STS_RESOURCE;
	qio_endio(qio);
	goto out;

}

static void submit_read_sliced_cow_clu(struct qcow2_map *map, struct qio *qio)
{
	struct qcow2 *qcow2 = map->qcow2;
	u64 mask = 0;

	WARN_ON_ONCE(!(map->level & L2_LEVEL));

	if (qcow2->ext_l2) {
		mask = map->ext_l2 & ~((u64)map->subclus_mask << 32);
		qio->ext->new_ext_l2 = mask | map->subclus_mask;
		if (map->data_clu_alloced && !map->clu_is_cow) {
			qio->ext->only_set_ext_l2 = true;
			qio->ext->allocated_clu_pos = map->data_clu_pos;
		}
		qio->ext->cow_mask = calc_cow_mask(qcow2, map->ext_l2, qio,
					     true, map->clu_is_cow, false);
	}

	submit_read_sliced_clu(map, qio, sliced_cow_read_complete);
}

static void submit_top_delta_read(struct qcow2_map *map, struct qio *qio)
{
	struct qcow2 *qcow2 = map->qcow2;

	if (qcow2->ext_l2) {
		qio->ext->cow_mask = calc_cow_mask(qcow2, map->ext_l2, qio,
						   false, true, true);
		qio->ext->new_ext_l2 = 0; /* For discard */
	}
	submit_read_sliced_clu(map, qio, backward_merge_read_complete);
}

static void issue_discard(struct qcow2_map *map, struct qio *qio)
{
	struct qcow2 *qcow2 = map->qcow2;
	loff_t pos;
	int ret;

	WARN_ON_ONCE(!(map->level & L2_LEVEL));
	pos = bio_sector_to_file_pos(qcow2, qio, map);
	ret = qcow2_punch_hole(qcow2->file, pos, qio->bi_iter.bi_size);

	if (ret)
		qio->bi_status = errno_to_blk_status(ret);
	qio_endio(qio);
}

static int handle_metadata(struct qcow2 *qcow2, struct qio **qio,
			   struct qcow2_map *map)
{
	bool write = op_is_write((*qio)->bi_op);
	int ret;

	ret = parse_metadata(qcow2, qio, map);
	if (ret < 0 || !*qio) /* Error or postponed */
		goto check_err;

	ret = 1;
	if (unlikely(qcow2->backward_merge_in_process)) {
		/* Keep in mind the below may replace *qio */
		ret = prepare_backward_merge(qcow2, qio, map, write);
	} else if (unlikely(fake_l1cow_qio(*qio)) &&
		(!map->clu_is_cow || (map->level & L2_LEVEL))) {
		/* Nothing to COW or L1 is mapped exactly once */
		qio_endio(*qio);
		ret = 0;
	} else if (write &&
		   (!qio_is_fully_alloced(qcow2, *qio, map) || map->clu_is_cow)) {
		if (map->clu_is_cow) {
			/* COW to compressed or shared with snapshot cluster */
			ret = prepare_l1l2_cow(qcow2, *qio, map);
		} else if ((map->level & L2_LEVEL) &&
		    qio_border_is_inside_unmapped_unit(qcow2, *qio, map) &&
		    maybe_mapped_in_lower_delta(qcow2, *qio)) {
			/*
			 * Backing file is about data COW, and it is
			 * never about metadata COW (unlike internal
			 * snapshots). Here is data COW on L2_LEVEL.
			 */
			map->backing_file_cow = true;
			ret = prepare_l1l2_cow(qcow2, *qio, map);
		} else if (unlikely(op_is_discard((*qio)->bi_op) &&
				    (map->level & L2_LEVEL))) {
			if (!map->data_clu_alloced) {
				qio_endio(*qio);
				ret = 0;
			}
			/* Otherwise issue_discard(). TODO: update L2 */
		} else {
			/* Wants L1 or L2 entry allocation */
			ret = prepare_l1l2_allocation(qcow2, *qio, map);
		}
	}

check_err:
	if (ret < 0) {
		(*qio)->bi_status = errno_to_blk_status(ret);
		qio_endio(*qio);
		ret = 0;
	}

	return ret;
}

static void process_read_qio(struct qcow2 *qcow2, struct qio *qio,
			     struct qcow2_map *map)
{
	bool unmapped, zeroes, try_lower;
	struct qio *split;
	u32 size;

	do {
		unmapped = try_lower = false;
		split = NULL;

		zeroes = (size = qio_all_zeroes_size(qcow2, qio, map));
		if (!size)
			unmapped = (size = qio_unmapped_size(qcow2, qio, map));
		if (!size)
			size = qio_mapped_not_zeroes_size(qcow2, qio, map);

		if (unmapped)
			try_lower = maybe_mapped_in_lower_delta(qcow2, qio);

		if (zeroes || (unmapped && !try_lower)) {
			/* All zeroes or clu is not allocated */
			perform_zero_read(qio, size);
			if (size == qio->bi_iter.bi_size) {
				qio_endio(qio);
				break;
			}
			qio_advance(qio, size);
			continue;
		}

		if (size < qio->bi_iter.bi_size) {
			split = split_and_chain_qio(qcow2, qio, size);
			if (!split)
				goto err;
			swap(qio, split);
		}

		if (unmapped && try_lower) {
			/* Try to read from lower delta */
			shorten_and_zero_qio_tail(qcow2->lower, qio);
			qio->qcow2 = qcow2->lower;
			WARN_ON_ONCE(qio->queue_list_id != QLIST_DEFERRED);
			qcow2_dispatch_qios(qio->qcow2, qio, NULL);
		} else {
			/* Mapped */
			perform_rw_mapped(map, qio);
		}

		qio = split;
	} while (qio);

	return;
err:
	qio->bi_status = BLK_STS_RESOURCE;
	qio_endio(qio);
}

static void process_one_qio(struct qcow2 *qcow2, struct qio *qio)
{
	struct qcow2_map map = { .qcow2 = qcow2, };
	bool write;

	if (!handle_metadata(qcow2, &qio, &map))
		return;

	if (unlikely(qcow2->backward_merge_in_process)) {
		submit_top_delta_read(&map, qio);
		return;
	}

	write = op_is_write(qio->bi_op);

	if (unlikely(map.compressed)) {
		/* Compressed qio never uses sub-clus */
		submit_read_compressed(&map, qio, write);
		return;
	}

	if (!write) {
		process_read_qio(qcow2, qio, &map);
	} else { /* write */
		if (unlikely(map.clu_is_cow && !(map.level & L2_LEVEL)))
			submit_read_whole_cow_clu(&map, qio);
		else if (unlikely(map.clu_is_cow || map.backing_file_cow))
			submit_read_sliced_cow_clu(&map, qio);
		else if (unlikely(op_is_discard(qio->bi_op)))
			issue_discard(&map, qio);
		else
			perform_rw_mapped(&map, qio);
	}
}

static struct bio_vec *create_bvec_from_rq(struct request *rq)
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

static void prepare_one_embedded_qio(struct qcow2 *qcow2, struct qio *qio,
				     struct list_head *deferred_qios)
{
	struct qcow2_rq *qrq = qio->endio_cb_data;
	struct request *rq = qrq->rq;
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
		bvec = create_bvec_from_rq(rq);
		if (unlikely(!bvec))
			goto err;
		qrq->bvec = bvec;
skip_bvec:
		qio->bi_iter.bi_sector = blk_rq_pos(rq);
		qio->bi_iter.bi_size = blk_rq_bytes(rq);
		qio->bi_iter.bi_idx = 0;
		qio->bi_iter.bi_bvec_done = 0;
	} else {
		/* Single bio already provides bvec array */
		bvec = rq->bio->bi_io_vec;

		qio->bi_iter = rq->bio->bi_iter;
	}

	qio->bi_io_vec = bvec;
	qio->queue_list_id = QLIST_DEFERRED;

	ret = qcow2_split_qio_to_list(qcow2, qio, deferred_qios);
	if (unlikely(ret < 0))
		goto err;

	return;
err:
	qio->bi_status = BLK_STS_RESOURCE;
	qio_endio(qio);
}

static void process_embedded_qios(struct qcow2 *qcow2, struct list_head *qios,
				  struct list_head *deferred_qios)
{
	struct qio *qio;

	while ((qio = qio_list_pop(qios)))
		prepare_one_embedded_qio(qcow2, qio, deferred_qios);
}

static void process_deferred_qios(struct qcow2 *qcow2, struct list_head *qios)
{
	struct qio *qio;

	while ((qio = qio_list_pop(qios))) {
		/* Sanity: on this stage we do not expect ext */
		if (WARN_ON_ONCE(qio->ext != NULL)) {
			qio->bi_status = BLK_STS_IOERR;
			qio_endio(qio);
			continue;
		}

		process_one_qio(qcow2, qio);
	}
}

static void submit_metadata_writeback(struct qcow2 *qcow2)
{
	struct md_page *md;

	while (1) {
		spin_lock_irq(&qcow2->md_pages_lock);
		md = list_first_entry_or_null(&qcow2->wb_batch_list,
					      struct md_page, wb_link);
		if (!md) {
			spin_unlock_irq(&qcow2->md_pages_lock);
			break;
		}
		list_del_init(&md->wb_link);
		/* L1L2 mustn't be redirtyed, when wb in-flight! */
		WARN_ON_ONCE(!(md->status & MD_DIRTY) ||
			      (md->wbd && (md->status & MD_WRITEBACK)));
		md->status |= MD_WRITEBACK;
		md->status &= ~MD_DIRTY;
		spin_unlock_irq(&qcow2->md_pages_lock);

		submit_rw_md_page(WRITE, qcow2, md);
	}
}

static int complete_metadata_writeback(struct qcow2 *qcow2)
{
	struct qcow2_bvec *qvec;
	struct md_page *md;
	int fsync_ret, ret;
	LIST_HEAD(wb_list);
	struct qio *qio;

	spin_lock_irq(&qcow2->deferred_lock);
	list_splice_init(&qcow2->qios[QLIST_COMPLETED_WB], &wb_list);
	spin_unlock_irq(&qcow2->deferred_lock);
	if (unlikely(list_empty(&wb_list)))
		return -EAGAIN;

	fsync_ret = vfs_fsync(qcow2->file, 0);
	/* FIXME: We should reread md page on error */
	if (unlikely(fsync_ret))
		pr_err_ratelimited("qcow2: can't sync md: %d\n", fsync_ret);

	while ((qio = qio_list_pop(&wb_list)) != NULL) {
		md = qio->ext->md;
		qvec = qio->data;
		ret = qio->ret;
		if (unlikely(ret != PAGE_SIZE))
			ret = -EIO;
		else
			ret = fsync_ret;

		do_md_page_write_complete(ret, qcow2, md);
		if (ret)
			qio->bi_status = errno_to_blk_status(ret);
		kfree(qvec);
		qio_endio(qio);
	}

	return fsync_ret;
}

/* Process completed compressed READs */
static void process_compressed_read(struct qcow2 *qcow2, struct list_head *read_list,
				    struct list_head *cow_list)
{
	struct qcow2_bvec *qvec;
	struct qio_ext *ext;
	blk_status_t ret;
	void *buf = NULL;
	struct qio *qio;
	bool for_cow;

	if (list_empty(read_list))
		return;

	buf = kmalloc(qcow2->clu_size + zlib_inflate_workspacesize(), GFP_NOIO);
	if (!buf) {
		end_qios(read_list, BLK_STS_RESOURCE);
		return;
	}

	while ((qio = qio_list_pop(read_list)) != NULL) {
		qvec = qio->data;
		ext = qio->ext;

		ret = extract_one_compressed(qcow2, buf, qvec,
				    ext->zdata_off, qio->ret);
		if (ret)
			goto err;

		for_cow = op_is_write(qio->bi_op);
		if (!for_cow)
			ret = copy_clu_part_to_qio(qcow2, buf, qio);
		else
			ret = prepare_zcow_slices(qcow2, buf, qio);

		if (!for_cow || ret) {
err:
			if (ret)
				qio->bi_status = errno_to_blk_status(ret);
			qio_endio(qio);
			continue;
		}

		/* Further COW processing */
		qio->queue_list_id = QLIST_COW_DATA;
		list_add_tail(&qio->link, cow_list);
	}

	kfree(buf);
}

static int prepare_sliced_data_write(struct qcow2 *qcow2, struct qio *qio,
			      struct list_head *list, qcow2_endio_t endio)
{
	struct qcow2_target *tgt = qcow2->tgt;
	struct qcow2_bvec *qvec = qio->data;
	u32 nr_segs = qio->ext->cow_segs;
	struct qio *write_qio, *aux_qio;
	int ret;

	WARN_ON_ONCE(qio->bi_op == REQ_OP_READ && nr_segs == 0);

	write_qio = qcow2_alloc_qio(tgt->qio_pool, true);
	if (!write_qio)
		goto err_qio;
	qcow2_init_qio(write_qio, REQ_OP_WRITE, qcow2);
	write_qio->flags |= QIO_FREE_ON_ENDIO_FL;
	write_qio->endio_cb = endio;
	write_qio->endio_cb_data = qio;

	if (qio->bi_op != REQ_OP_READ && !fake_merge_qio(qio)) {
		/* Create aux qio to chain @qio bytes write there */
		aux_qio = write_qio;
		if (nr_segs) {
			aux_qio = split_and_chain_qio(qcow2, write_qio, 0);
			if (!aux_qio) {
				qcow2_free_qio(write_qio, tgt->qio_pool);
				goto err_qio;
			}
			list_add(&aux_qio->link, list);
		}
		aux_qio->bi_op = qio->bi_op;
		aux_qio->bi_io_vec = qio->bi_io_vec;
		aux_qio->bi_iter = qio->bi_iter;

		if (!nr_segs) { /* Full overwrite */
			list_add(&aux_qio->link, list);
			goto out;
		}
	}

	write_qio->bi_io_vec = qvec->bvec;
	write_qio->bi_iter.bi_idx = 0;
	write_qio->bi_iter.bi_bvec_done = 0;

	ret = for_each_cow_interval(qio, split_sliced_cow_qio,
				    write_qio, list, &nr_segs);
	list_add_tail(&write_qio->link, list);
	if (ret)
		goto err_split;
out:
	return 0;
err_split:
	end_qios(list, BLK_STS_RESOURCE);
	goto out;
err_qio:
	qio->bi_status = BLK_STS_RESOURCE;
	qio_endio(qio);
	goto out;
}

static void process_backward_merge_write(struct qcow2 *qcow2, struct list_head *qio_list)
{
	qcow2_endio_t endio = backward_merge_write_complete;
	struct qio *qio;
	LIST_HEAD(list);

	while (1) {
		qio = qio_list_pop(qio_list);
		if (!qio)
			break;

		if (prepare_sliced_data_write(qcow2->lower, qio,
					      &list, endio) < 0)
			continue;

		qcow2_dispatch_qios(qcow2->lower, NULL, &list);
	}
}

static void cow_data_write_endio(struct qcow2_target *tgt, struct qio *unused,
				 void *qio_ptr, blk_status_t bi_status)

{
	struct qio *qio = qio_ptr;
	struct qcow2 *qcow2 = qio->qcow2;

	BUG_ON(!qio->ext);

	if (unlikely(bi_status)) {
		qio->bi_status = bi_status;
		qio_endio(qio);
	} else {
		qio->queue_list_id = QLIST_COW_INDEXES;
		qcow2_dispatch_qios(qcow2, qio, NULL);
	}
}

static void submit_cow_data_write(struct qcow2 *qcow2, struct qio *qio, loff_t pos)
{
	struct qcow2_target *tgt = qcow2->tgt;
	struct qcow2_bvec *qvec = qio->data;
	u32 clu_size = qcow2->clu_size;
	struct qio *write_qio;

	write_qio = qcow2_alloc_qio(tgt->qio_pool, true);
	if (!write_qio) {
		qio->bi_status = BLK_STS_RESOURCE;
		qio_endio(qio);
		return;
	}
	qcow2_init_qio(write_qio, REQ_OP_WRITE, qcow2);

	write_qio->flags |= QIO_FREE_ON_ENDIO_FL;
	write_qio->bi_io_vec = qvec->bvec;
	write_qio->bi_iter.bi_size = clu_size;
	write_qio->bi_iter.bi_idx = 0;
	write_qio->bi_iter.bi_bvec_done = 0;
	write_qio->endio_cb = cow_data_write_endio;
	write_qio->endio_cb_data = qio;
	write_qio->complete = data_rw_complete;
	write_qio->data = NULL;

	write_qio->bi_iter.bi_sector = to_sector(pos);

	__submit_rw_mapped(qcow2, write_qio, clu_size >> PAGE_SHIFT);
}

static void sliced_cow_data_write_complete(struct qcow2_target *tgt, struct qio *unused,
					   void *qio_ptr, blk_status_t bi_status)

{
	struct qio *qio = qio_ptr;
	struct qcow2 *qcow2 = qio->qcow2;

	BUG_ON(!qio->ext);

	if (bi_status) {
		qio->bi_status = bi_status;
		qio_endio(qio);
	} else {
		qio->queue_list_id = QLIST_COW_INDEXES;
		qcow2_dispatch_qios(qcow2, qio, NULL);
	}
}

static void submit_sliced_cow_data_write(struct qcow2 *qcow2, struct qio *qio, loff_t clu_pos)
{
	qcow2_endio_t endio = sliced_cow_data_write_complete;
	struct qio *write_qio;
	LIST_HEAD(list);

	if (prepare_sliced_data_write(qcow2, qio, &list, endio) < 0)
		return;

	while ((write_qio = qio_list_pop(&list)) != NULL) {
		write_qio->complete = data_rw_complete;
		write_qio->data = NULL;
		map_and_submit_rw(qcow2, clu_pos, write_qio);
	}
}

static void process_cow_data_write(struct qcow2 *qcow2, struct list_head *cow_list)
{
	struct qio_ext *ext;
	struct qio *qio;
	loff_t pos;

	while (1) {
		qio = qio_list_pop(cow_list);
		if (!qio)
			break;
		ext = qio->ext;

		if (ext->only_set_ext_l2) {
			WARN_ON_ONCE(ext->cow_level != L2_LEVEL);
			pos = ext->allocated_clu_pos;
			goto submit;
		}

		WARN_ON_ONCE(qio->queue_list_id != QLIST_COW_DATA);
		pos = allocate_cluster(qcow2, qio, &ext->r2_md,
				       &ext->r2_index_in_page);
		if (pos < 0) {
			qio->bi_status = errno_to_blk_status(pos);
			qio_endio(qio);
		}

		if (pos <= 0)
			continue;

		ext->allocated_clu_pos = pos;
		ext->cleanup_mask |= FREE_ALLOCATED_CLU;
submit:
		if (ext->cow_level == L2_LEVEL)
			submit_sliced_cow_data_write(qcow2, qio, pos);
		else
			submit_cow_data_write(qcow2, qio, pos);
	}
}

static void process_cow_indexes_write(struct qcow2 *qcow2,
				      struct list_head *qio_list)
{
	struct qcow2_bvec *qvec;
	struct md_page *lx_md;
	struct qio_ext *ext;
	struct qio *qio;
	bool discard;
	u32 arg_mask;
	int ret;

	while (1) {
		qio = qio_list_pop(qio_list);
		if (!qio)
			break;
		ext = qio->ext;
		qvec = qio->data;
		lx_md = ext->lx_md;

		/* Return back to the same stage in case of writeback */
		qio->queue_list_id = QLIST_COW_INDEXES;
		if (delay_if_writeback(qcow2, lx_md, -1, &qio, true))
			continue;

		discard = (qio->flags & QIO_IS_DISCARD_FL) ? true : false;
		WARN_ON_ONCE(discard && ext->allocated_clu_pos);

		arg_mask = (discard ? 0 : LU_SET_ONE_MASK) | LU_WANTS_PE_PAGE;
		if (ext->only_set_ext_l2) {
			WARN_ON_ONCE(ext->cow_level != L2_LEVEL);
			goto set_ext_l2;
		}

		/* XXX: check prealloced_pos ==> revert */
		ret = prepare_l_entry_update(qcow2, qio, lx_md,
					     ext->lx_index_in_page,
					     &ext->allocated_clu_pos,
					     arg_mask);
		if (ret < 0) {
			qio->bi_status = errno_to_blk_status(ret);
			qio_endio(qio);
			continue;
		}
set_ext_l2:
		if (qcow2->ext_l2 && ext->cow_level == L2_LEVEL) {
			arg_mask &= ~LU_SET_ONE_MASK;
			ret = prepare_l_entry_update(qcow2, qio, lx_md,
					     ext->lx_index_in_page + 1,
					   &ext->new_ext_l2, arg_mask);
			WARN_ON_ONCE(ret < 0);
		}

		/* Next stage */
		qio->queue_list_id = QLIST_COW_END;

		spin_lock_irq(&qcow2->md_pages_lock);
		/*
		 * Prohibit to start new reads from WP clusters.
		 * Otherwise, "wpc_readers == 0" never happens.
		 */
		WARN_ON_ONCE(lx_md->wpc_noread_count++ < 0);
		ext->cleanup_mask |= DEC_WPC_NOREAD_COUNT;

		/* Wait md page writeback */
		list_add_tail(&qio->link, &lx_md->wbd->dependent_list);
		spin_unlock_irq(&qcow2->md_pages_lock);
	}
}

/* Finalize successful COW */
static void process_cow_end(struct qcow2 *qcow2, struct list_head *qio_list)
{
	u32 mask, clu_size = qcow2->clu_size;
	struct qcow2_map_item r1, r2;
	struct qio_ext *ext;
	struct qio *qio;
	loff_t pos;
	int ret;

	while (1) {
next:		qio = qio_list_pop(qio_list);
		if (!qio)
			break;
		ext = qio->ext;
		/* L2 index was written, cluster became used */
		if (ext->cleanup_mask & FREE_ALLOCATED_CLU)
			ext->cleanup_mask &= ~FREE_ALLOCATED_CLU;

		/* Should be already set... */
		qio->queue_list_id = QLIST_COW_END;
		/*
		 * Wait last user before we (possible) mark clusters
		 * unused. In real only compressed COW requires this.
		 */
		if (delay_if_has_wpc_readers(qcow2, ext->lx_md, &qio))
			goto next;

		pos = ext->cow_clu_pos;
		for (; pos < ext->cow_clu_end; pos += clu_size) {
			ret = __handle_r1r2_maps(qcow2, pos, &qio, &r1, &r2);
			if (ret == 0) /* We never shrink md pages, impossible */
				goto next;
			if (WARN_ON_ONCE(ret < 0))
				pr_err("qcow2: clu at %lld leaked\n", pos);
			else
				dec_cluster_usage(qcow2, r2.md, r2.index_in_page, pos);
			ext->cow_clu_pos += clu_size;
		}

		mask = MD_INDEX_SET_UNLOCKED|DEC_WPC_NOREAD_COUNT;
		if (qio->data)
			mask |= FREE_QIO_DATA_QVEC;
		WARN_ON_ONCE(ext->cleanup_mask != mask); /* Sanity check */

		if (ext->cow_level == L1_LEVEL) {
			finalize_qio_ext(qio);
			/* COW on L1 completed, it's time for COW on L2 */
			qio->queue_list_id = QLIST_DEFERRED;
			qcow2_dispatch_qios(qcow2, qio, NULL);
		} else {
			/*
			 * This qio was already written together with clu.
			 * Nothing to do. See process_cow_data_write().
			 */
			qio_endio(qio); /* Makes all cleanup */
		}
	}
}
static void process_resubmit_qios(struct qcow2 *qcow2, struct list_head *qios)
{
	struct qio *qio;

	while ((qio = qio_list_pop(qios)) != NULL) {
		qio->queue_list_id = QLIST_INVALID;
		submit_rw_mapped(qcow2, qio);
	}
}

void do_qcow2_work(struct work_struct *ws)
{
	struct qcow2 *qcow2 = container_of(ws, struct qcow2, worker);
	LIST_HEAD(embedded_qios);
	LIST_HEAD(deferred_qios);
	LIST_HEAD(zread_qios);
	LIST_HEAD(bwrite_qios);
	LIST_HEAD(cow_data_qios);
	LIST_HEAD(cow_indexes_qios);
	LIST_HEAD(cow_end_qios);
	LIST_HEAD(resubmit_qios);
	unsigned int pflags = current->flags;

	current->flags |= PF_LOCAL_THROTTLE|PF_MEMALLOC_NOIO;
	spin_lock_irq(&qcow2->deferred_lock);
	list_splice_init(&qcow2->qios[QLIST_EMBEDDED], &embedded_qios);
	list_splice_init(&qcow2->qios[QLIST_DEFERRED], &deferred_qios);
	list_splice_init(&qcow2->qios[QLIST_ZREAD], &zread_qios);
	list_splice_init(&qcow2->qios[QLIST_BMERGE_WRITE], &bwrite_qios);
	list_splice_init(&qcow2->qios[QLIST_COW_DATA], &cow_data_qios);
	list_splice_init(&qcow2->qios[QLIST_COW_INDEXES], &cow_indexes_qios);
	list_splice_init(&qcow2->qios[QLIST_COW_END], &cow_end_qios);
	list_splice_init(&qcow2->resubmit_qios, &resubmit_qios);
	spin_unlock_irq(&qcow2->deferred_lock);

	process_embedded_qios(qcow2, &embedded_qios, &deferred_qios);
	process_deferred_qios(qcow2, &deferred_qios);
	process_compressed_read(qcow2, &zread_qios, &cow_data_qios);
	process_backward_merge_write(qcow2, &bwrite_qios);
	process_cow_data_write(qcow2, &cow_data_qios);
	process_cow_indexes_write(qcow2, &cow_indexes_qios);
	process_cow_end(qcow2, &cow_end_qios);
	process_resubmit_qios(qcow2, &resubmit_qios);

	/* This actually submits batch of md writeback, initiated above */
	submit_metadata_writeback(qcow2);

	current_restore_flags(pflags, PF_LOCAL_THROTTLE|PF_MEMALLOC_NOIO);
}

void do_qcow2_fsync_work(struct work_struct *ws)
{
	struct qcow2 *qcow2 = container_of(ws, struct qcow2, fsync_worker);
	unsigned int pflags = current->flags;
	LIST_HEAD(flush_qios);
	int fsync_ret;

	current->flags |= PF_LOCAL_THROTTLE|PF_MEMALLOC_NOIO;
	spin_lock_irq(&qcow2->deferred_lock);
	list_splice_tail_init(&qcow2->qios[QLIST_FLUSH], &flush_qios);
	spin_unlock_irq(&qcow2->deferred_lock);

	fsync_ret = complete_metadata_writeback(qcow2);
	/*
	 * Metadata writeback and flush bios are independent
	 * each other, but we want avoid excess fsync() call,
	 * if it's already done.
	 */
	if (fsync_ret == -EAGAIN)
		fsync_ret = vfs_fsync(qcow2->file, 0);

	end_qios(&flush_qios, errno_to_blk_status(fsync_ret));

	current_restore_flags(pflags, PF_LOCAL_THROTTLE|PF_MEMALLOC_NOIO);
}

static bool qcow2_try_delay_enospc(struct qcow2_target *tgt, struct qcow2_rq *qrq, struct qio *qio)
{
	bool delayed = true;
	unsigned long flags;

	spin_lock_irqsave(&tgt->event_lock, flags);
	if (unlikely(tgt->wants_suspend)) {
		delayed = false;
		goto unlock;
	}

	init_qrq_and_embedded_qio(tgt, qrq->rq, qrq, qio);

	pr_err_once("qcow2: underlying disk is almost full\n");
	tgt->event_enospc = true;
	list_add_tail(&qio->link, &tgt->enospc_qios);
unlock:
	spin_unlock_irqrestore(&tgt->event_lock, flags);

	if (delayed)
		mod_timer(&tgt->enospc_timer, jiffies + ENOSPC_TIMEOUT_JI);
	schedule_work(&tgt->event_work);

	return delayed;
}

static void qrq_endio(struct qcow2_target *tgt, struct qio *qio,
		      void *qrq_ptr, blk_status_t bi_status)
{
	struct qcow2_rq *qrq = qrq_ptr;
	struct request *rq = qrq->rq;

	if (qrq->bvec)
		kfree(qrq->bvec);
	/*
	 * Here is exit point for rq, and here we handle ENOSPC.
	 * Embedded qios will be reinitialized like they've just
	 * came from upper dm level, and later resubmitted after
	 * timeout. Note, that we do not handle merge here: merge
	 * callers receive -ENOSPC synchronous without intermediaries.
	 */
	if (unlikely(bi_status == BLK_STS_NOSPC)) {
		WARN_ON_ONCE(!op_is_write(qio->bi_op));
		if (qcow2_try_delay_enospc(tgt, qrq, qio))
			return;
	}

	mempool_free(qrq, tgt->qrq_pool);
	dm_complete_request(rq, bi_status);
}

static void init_qrq(struct qcow2_rq *qrq, struct request *rq)
{
	qrq->rq = rq;
	qrq->bvec = NULL;
}

static void init_qrq_and_embedded_qio(struct qcow2_target *tgt, struct request *rq,
				      struct qcow2_rq *qrq, struct qio *qio)
{
	init_qrq(qrq, rq);
	qcow2_init_qio(qio, req_op(rq), NULL);

	qio->endio_cb = qrq_endio;
	qio->endio_cb_data = qrq;
}

void qcow2_submit_embedded_qio(struct qcow2_target *tgt, struct qio *qio)
{
	struct qcow2_rq *qrq = qio->endio_cb_data;
	struct request *rq = qrq->rq;
	u8 queue_list_id, ref_index;
	struct work_struct *worker;
	struct qcow2 *qcow2;
	unsigned long flags;
	bool queue = true;

	qcow2 = qcow2_ref_inc(tgt, &ref_index);

	if (blk_rq_bytes(rq)) {
		queue_list_id = QLIST_EMBEDDED;
		worker = &qcow2->worker;
	} else {
		WARN_ON_ONCE(qio->bi_op != REQ_OP_FLUSH);
		queue_list_id = QLIST_FLUSH;
		worker = &qcow2->fsync_worker;
	}

	spin_lock_irqsave(&qcow2->deferred_lock, flags);
	if (unlikely(qcow2->pause_submitting_qios)) {
		qcow2_ref_dec(tgt, ref_index);
		list_add_tail(&qio->link, &qcow2->paused_qios);
		queue = false;
	} else {
		qio->qcow2 = qcow2;
		qio->queue_list_id = queue_list_id;
		qio->ref_index = ref_index;
		list_add_tail(&qio->link, &qcow2->qios[qio->queue_list_id]);
	}
	spin_unlock_irqrestore(&qcow2->deferred_lock, flags);

	if (queue)
		queue_work(tgt->wq, worker);
}

void qcow2_submit_embedded_qios(struct qcow2_target *tgt, struct list_head *list)
{
	struct qio *qio;

	while ((qio = qio_list_pop(list)) != NULL)
		qcow2_submit_embedded_qio(tgt, qio);
}

int qcow2_clone_and_map(struct dm_target *ti, struct request *rq,
		    union map_info *info, struct request **clone)
{
	struct qcow2_target *tgt = to_qcow2_target(ti);
	struct qcow2_rq *qrq;
	struct qio *qio;

	qrq = mempool_alloc(tgt->qrq_pool, GFP_ATOMIC);
	if (!qrq)
		return DM_MAPIO_KILL;
	qio = (void *)qrq + sizeof(*qrq);
	init_qrq_and_embedded_qio(tgt, rq, qrq, qio);

	/*
	 * Note, this qcow2_clone_and_map() may be called from atomic
	 * context, so here we just delegate qio splitting to kwork.
	 */
	qcow2_submit_embedded_qio(tgt, qio);
	return DM_MAPIO_SUBMITTED;
}

static void handle_cleanup_mask(struct qio *qio)
{
	struct qcow2 *qcow2 = qio->qcow2;
	struct qio_ext *ext = qio->ext;
	struct lock_desc *lockd = NULL;
	LIST_HEAD(qio_list);
	unsigned long flags;
	bool last;

	if (ext->cleanup_mask & MD_INDEX_SET_UNLOCKED) {
		struct md_page *md = ext->lx_md;

		spin_lock_irqsave(&qcow2->md_pages_lock, flags);
		clear_bit(ext->lx_index_in_page, md->lockd->indexes);
		WARN_ON_ONCE(--md->lockd->nr < 0);
		if (!md->lockd->nr)
			swap(md->lockd, lockd);
		list_splice_init(&md->wait_list, &qio_list);
		spin_unlock_irqrestore(&qcow2->md_pages_lock, flags);
		qcow2_dispatch_qios(qcow2, NULL, &qio_list);
		kfree(lockd);
		ext->cleanup_mask &= ~MD_INDEX_SET_UNLOCKED;
	}

	if (ext->cleanup_mask & DEC_WPC_NOREAD_COUNT) {
		struct md_page *md = ext->lx_md;

		spin_lock_irqsave(&qcow2->md_pages_lock, flags);
		last = !(--md->wpc_noread_count);
		if (last)
			list_splice_init(&md->wait_list, &qio_list);
		spin_unlock_irqrestore(&qcow2->md_pages_lock, flags);
		if (last)
			qcow2_dispatch_qios(qcow2, NULL, &qio_list);
		ext->cleanup_mask &= ~DEC_WPC_NOREAD_COUNT;
	}

	if (ext->cleanup_mask & FREE_QIO_DATA_QVEC) {
		struct qcow2_bvec *qvec = qio->data;

		qcow2_free_qvec_with_pages(qvec);
		qio->data = NULL;
		ext->cleanup_mask &= ~FREE_QIO_DATA_QVEC;
	}

	if (ext->cleanup_mask & FREE_ALLOCATED_CLU) {
		u32 index_in_page = ext->r2_index_in_page;
		loff_t pos = ext->allocated_clu_pos;
		struct md_page *md = ext->r2_md;

		mark_cluster_unused(qcow2, md, index_in_page, pos);
		ext->cleanup_mask &= ~FREE_ALLOCATED_CLU;
	}
}
