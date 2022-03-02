/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __DM_QCOW2_H
#define __DM_QCOW2_H

#include <linux/percpu-refcount.h>
#include <linux/device-mapper.h>
#include <linux/fs.h>

#define DM_MSG_PREFIX "qcow2"

#define QCOW_MAGIC (('Q' << 24) | ('F' << 16) | ('I' << 8) | 0xfb)
/*
 * QEMU has this limit, so we should follow it to keep our images
 * mountable in VMs... Note, that it's possible to create a disk
 * with parameters in QEMU, whose size can't be covered by refcount table.
 */
#define REFCOUNT_TABLE_MAX_SIZE (8 * 1024 * 1024)

#define MIN_QIOS 512
#define WB_TIMEOUT_JI (60 * HZ)
#define ENOSPC_TIMEOUT_JI (20 * HZ)
#define PREALLOC_SIZE (128ULL * 1024 * 1024)

struct QCowHeader {
	uint32_t magic;
	uint32_t version;
	uint64_t backing_file_offset;
	uint32_t backing_file_size;
	uint32_t cluster_bits;
	uint64_t size; /* in bytes */
	uint32_t crypt_method;
	uint32_t l1_size; /* number of entries in the active L1 table (not clusters) */
	uint64_t l1_table_offset;
	uint64_t refcount_table_offset;
	uint32_t refcount_table_clusters;
	uint32_t nb_snapshots;
	uint64_t snapshots_offset;

	/* The following fields are only valid for version >= 3 */
#define INCOMPATIBLE_FEATURES_DIRTY_BIT	(1 << 0)
#define INCOMPATIBLE_FEATURES_EXTL2_BIT	(1 << 4)
	uint64_t incompatible_features;
	uint64_t compatible_features;
	uint64_t autoclear_features;

	uint32_t refcount_order;
	uint32_t header_length;

	/* Additional fields */
	uint8_t compression_type;

	/* header must be a multiple of 8 */
	uint8_t padding[7];
} __packed;

struct wb_desc {
	struct md_page *md;
#define LX_INDEXES_PER_PAGE (PAGE_SIZE / sizeof(u64))
#define LX_INDEXES_BYTES (BITS_TO_LONGS(LX_INDEXES_PER_PAGE) * sizeof(unsigned long))
	unsigned long *changed_indexes;
	/*
	 * Contains old stable values of preallocated/cow entries
	 * to restore them in case of md writeback fails.
	 */
	struct page *pe_page;
	struct list_head completed_list;
	/*
	 * These bios want to be dispatched in case of writeback
	 * success, or bio_endio() in case of error.
	 * XXX: Possible we need the same for plain struct md_page.
	 */
	struct list_head dependent_list;
	int nr_submitted;
	bool completed;
	int ret;
};

struct lock_desc {
	int nr; /* Number of set bits */
	unsigned long indexes[LX_INDEXES_BYTES/sizeof(unsigned long)];
};

struct md_page {
	struct rb_node node;
	u64 id; /* Number of this page starting from hdr */
#define MD_UPTODATE	(1U << 0) /* Page was read from disk */
#define MD_DIRTY	(1U << 1) /* Page contains changes and wants writeback */
#define MD_WRITEBACK	(1U << 2) /* Writeback was submitted */
#define MD_WRITEBACK_ERROR (1U << 3) /* Last writeback failed with error */
	unsigned int status;
	struct page *page;
	struct list_head wait_list;
	/* To link in qcow2::{,slow}wb_batch_list and qcow2::QLIST_COMPLETED_WB */
	struct list_head wb_link;
	struct wb_desc *wbd; /* For L1 and L2 update */
	struct lock_desc *lockd; /* Locked clus map */
	/*
	 * Readers of clusters, WRITE to which results in COW.
	 * These are compressed clusters, snapshot clusters, etc.
	 */
	atomic_t wpc_readers;
	int wpc_noread_count; /* Read is prohibited, if positive */
	struct list_head wpc_readers_wait_list;
};

struct qcow2_target {
	struct dm_target *ti;
#define QCOW2_QRQ_POOL_SIZE 512 /* Twice nr_requests from blk_mq_init_sched() */
	mempool_t *qrq_pool;
	mempool_t *qio_pool;
	/*
	 * start_processing_qrq() is the only place during IO handling,
	 * where it's allowed to dereference @top. See backward merge.
	 */
	struct qcow2 *top;
	struct workqueue_struct *wq;

	struct completion inflight_ref_comp;
	struct percpu_ref inflight_ref[2];
	unsigned int inflight_ref_index:1;

	bool service_operations_allowed;
	bool wants_suspend;
	bool md_writeback_error;
	bool truncate_error;
	bool event_enospc;

	atomic_t service_qios;
	struct wait_queue_head service_wq;

	struct list_head enospc_qios; /* Delayed after ENOSPC */
	struct timer_list enospc_timer;

	struct work_struct event_work;
	spinlock_t event_lock;
	struct mutex ctl_mutex;
};

enum {
	QLIST_EMBEDDED = 0, /*
			     * List for initial setup embedded qios
			     * related to prq (in process context).
			     * This is used only for top qcow2 image.
			     */
	QLIST_DEFERRED,
	QLIST_FLUSH,
	QLIST_COMPLETED_WB,
	QLIST_ZREAD,
	QLIST_BMERGE_WRITE,
	QLIST_COW_DATA,
	QLIST_COW_INDEXES,
	QLIST_COW_END,

	QLIST_COUNT,
	QLIST_INVALID = QLIST_COUNT,
};

struct qcow2 {
	struct qcow2_target *tgt;
	struct file *file;
	loff_t file_size;
	loff_t file_preallocated_area_start;
	/* Maximum file size covered by refcount table */
	loff_t reftable_max_file_size;
	/* Position to search next unused cluster */
	loff_t free_cluster_search_pos;

	u32 img_id;
	struct qcow2 *lower; /* Lower delta (backing file) */

	struct rb_root md_pages; /* Metadata pages */
	struct QCowHeader hdr;
	u32 clu_size;
	u32 subclu_size;
	u32 l2_entries;
	u32 refblock_bits;
	u32 refblock_entries;
	bool ext_l2;

	bool pause_submitting_qios; /* This is used only on top qcow2 image */
	bool backward_merge_in_process;
	/* File size covered by single page of block entries */
	loff_t r2_page_covered_file_size;

#define QCOW2_FAULT_RATIO 1000
	u32 fault_injection; /* In 1%/QCOW2_FAULT_RATIO */

	spinlock_t deferred_lock ____cacheline_aligned;
	spinlock_t md_pages_lock;

	struct list_head qios[QLIST_COUNT];
	struct list_head resubmit_qios;
	struct list_head paused_qios; /* For pause_submitting_qios */

	/* For batching md update: */
	struct list_head wb_batch_list;
	struct list_head slow_wb_batch_list;
	struct timer_list slow_wb_timer;

	struct work_struct worker;
	struct work_struct fsync_worker;
};

/*
 * struct qio is embedded in every incoming bio, so we keep it
 * as small as possible. It is aimed to fit enough bytes only
 * for the most likely actions. To process COW, compressed
 * clusters and other rare actions we need more auxiliary bytes,
 * so we introduce this struct qio_ext in addition to struct qio.
 */
struct qio_ext {
	struct md_page *lx_md, *r2_md, *md;
	u32 lx_index_in_page, r2_index_in_page;
	u64 allocated_clu_pos;

	loff_t cow_clu_pos;
	loff_t cow_clu_end;
	u64 new_ext_l2;
	u32 cow_mask;
	bool only_set_ext_l2:1;

	u8 cow_level;

#define MD_INDEX_SET_UNLOCKED	(1ULL << 0)
#define DEC_WPC_NOREAD_COUNT	(1ULL << 1)
#define FREE_QIO_DATA_QVEC	(1ULL << 2)
#define FREE_ALLOCATED_CLU	(1ULL << 3)
	u8 cleanup_mask;
	u16 zdata_off; /* Offset in first page: */
	u16 cow_segs;
};

struct qcow2_rq {
	struct request *rq;
	struct bio_vec *bvec;
};

struct qio;
typedef void (*qcow2_endio_t)(struct qcow2_target *, struct qio *,
			      void *, blk_status_t);

struct qio {
	struct bvec_iter bi_iter;
	struct bio_vec *bi_io_vec;
	unsigned int bi_op;
	blk_status_t bi_status;
#define QIO_FREE_ON_ENDIO_FL	(1 << 0) /* Free this qio memory from qio_endio() */
#define QIO_IS_MERGE_FL		(1 << 3) /* This is service merge qio */
#define QIO_IS_DISCARD_FL	(1 << 4) /* This zeroes index on backward merge */
#define QIO_IS_L1COW_FL		(1 << 5) /* This qio only wants COW at L1 */
#define QIO_SPLIT_INHERITED_FLAGS (QIO_IS_DISCARD_FL)
	u8 flags;
#define REF_INDEX_INVALID 2
	u8 ref_index:2;
	/*
	 * Some operations (say, COW) have more than one stage.
	 * In case of a stage may delay bio (say, it may want
	 * to wait reading md page from disk, or when some counter
	 * becomes zero), this queue_list_id shows the place, where
	 * bio processing should resume.
	 */
	u8 queue_list_id:4;

	atomic_t remaining;

	struct kiocb iocb;
	atomic_t aio_ref;
	int ret; /* iocb result */
	void (*complete)(struct qio *me);
	void *data;
	/* Some operations (COW) require special destruction or requeue */
	struct qio_ext *ext;
	struct list_head link;
	struct qcow2 *qcow2;
	qcow2_endio_t endio_cb;
	void *endio_cb_data;
};

#define CLU_OFF(qcow2, pos) (pos & (qcow2->clu_size - 1))
#define SUBCLU_OFF(qcow2, pos) (pos & (qcow2->subclu_size - 1))

void qcow2_destroy(struct qcow2 *qcow2);
int qcow2_set_image_file_features(struct qcow2 *qcow2, bool dirty);
int qcow2_message(struct dm_target *ti, unsigned int argc, char **argv,
		  char *result, unsigned int maxlen);
int qcow2_clone_and_map(struct dm_target *ti, struct request *rq,
		   union map_info *info, struct request **clone);

void do_qcow2_work(struct work_struct *ws);
void do_qcow2_fsync_work(struct work_struct *ws);
int alloc_and_insert_md_page(struct qcow2 *qcow2, u64 index, struct md_page **md);
struct md_page *md_page_find_or_postpone(struct qcow2 *qcow2, unsigned int id, struct qio **qio);
struct md_page *md_page_renumber(struct qcow2 *qcow2, unsigned int id, unsigned int new_id);
void md_page_erase(struct qcow2 *qcow2, struct md_page *md);
void free_md_page(struct md_page *md);
void zero_fill_page_from(struct page *page, unsigned int from);
int rw_page_sync(unsigned int rw, struct qcow2 *qcow2, u64 index, struct page *page);
void call_rw_iter(struct qcow2 *qcow2, loff_t pos, unsigned int rw,
		  struct iov_iter *iter, struct qio *qio);
void calc_cached_parameters(struct qcow2 *qcow2, struct QCowHeader *hdr);
void slow_wb_timer_fn(struct timer_list *t);
struct qio *alloc_qio(mempool_t *pool, bool zero);
void init_qio(struct qio *qio, unsigned int bi_op, struct qcow2 *qcow2);
void dispatch_qios(struct qcow2 *qcow2, struct qio *qio,
		   struct list_head *qio_list);
void submit_embedded_qios(struct qcow2_target *tgt, struct list_head *list);
struct qcow2 *qcow2_ref_inc(struct qcow2_target *tgt, u8 *ref_index);
void qcow2_ref_dec(struct qcow2_target *tgt, u8 ref_index);
int qcow2_inflight_ref_switch(struct qcow2_target *tgt);
void flush_deferred_activity(struct qcow2_target *tgt, struct qcow2 *qcow2);
int qcow2_truncate_safe(struct file *file, loff_t new_len);

static inline struct qcow2_target *to_qcow2_target(struct dm_target *ti)
{
	return ti->private;
}

static inline struct qcow2 *top_qcow2_protected(struct dm_target *ti)
{
	struct qcow2_target *tgt = to_qcow2_target(ti);

	return tgt->top;
}

static inline struct qio *qio_list_pop(struct list_head *qio_list)
{
	struct qio *qio;

	qio = list_first_entry_or_null(qio_list, struct qio, link);
	if (qio)
		list_del_init(&qio->link);
	return qio;
}

static inline bool fake_merge_qio(struct qio *qio)
{
	return (qio->bi_op == REQ_OP_WRITE &&
		qio->bi_iter.bi_size == 0 &&
		(qio->flags & QIO_IS_MERGE_FL));
}

static inline bool fake_l1cow_qio(struct qio *qio)
{
	return (qio->bi_op == REQ_OP_WRITE &&
		qio->bi_iter.bi_size == 0 &&
		(qio->flags & QIO_IS_L1COW_FL));
}

static inline bool qcow2_wants_check(struct qcow2_target *tgt)
{

	return !!(tgt->md_writeback_error|tgt->truncate_error);
}

static inline void remap_to_clu(struct qcow2 *qcow2, struct qio *qio, loff_t clu_pos)
{
	qio->bi_iter.bi_sector &= (to_sector(qcow2->clu_size) - 1);
	qio->bi_iter.bi_sector |= (to_sector(clu_pos));
}
#endif
