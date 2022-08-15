/*
 *  drivers/md/dm-ploop.h
 *
 *  Copyright (c) 2020-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef __DM_PLOOP_H
#define __DM_PLOOP_H

#include <linux/device-mapper.h>
#include <linux/bio.h>

#define PLOOP_MAP_OFFSET 16
typedef u32 map_index_t;
#define BAT_ENTRIES_PER_PAGE (PAGE_SIZE / sizeof(map_index_t))

#define SIGNATURE_DISK_IN_USE           0x746F6E59

#pragma pack(push, 1)
struct ploop_pvd_header {
	__u8  m_Sig[16];	/* Signature */
	__u32 m_Type;		/* Disk type */
	__u32 m_Heads;		/* heads count */
	__u32 m_Cylinders;	/* tracks count */
	__u32 m_Sectors;	/* Sectors per track count */
	__u32 m_Size;		/* Size of disk in tracks */
	union {			/* Size of disk in 512-byte sectors */
		struct {
			__u32 m_SizeInSectors_v1;
			__u32 Unused;
		};
		__u64 m_SizeInSectors_v2;
	};
	__u32 m_DiskInUse;	/* Disk in use */
	__u32 m_FirstBlockOffset; /* First data block offset (in sectors) */
	__u32 m_Flags;		/* Misc flags */
	__u8  m_Reserved[8];	/* Reserved */
};
#pragma pack(pop)

struct ploop_delta {
	struct file *file;
	loff_t file_size;
	loff_t file_preallocated_area_start;
	u32 nr_be; /* nr BAT entries (or file length in clus if RAW) */
	bool is_raw;
};

#define MERGE_PIOS_MAX			64

struct ploop_cmd {
	union {
		struct {
			sector_t new_sectors;
			/* Preallocated data */
			struct rb_root md_pages_root;
			struct md_page *md0;
			void *holes_bitmap;
#define PLOOP_GROW_STAGE_INITIAL	0
			unsigned int stage;
			unsigned int nr_bat_entries;
			unsigned int hb_nr;
			unsigned int end_dst_clu;
			unsigned int nr_old_bat_clu;
			unsigned int clu, dst_clu;
			struct pio *pio;
		} resize;
	};
};

#define PAGE_NR_NONE		U32_MAX
/* We can't use 0 for unmapped clusters, since RAW image references 0 clu */
#define BAT_ENTRY_NONE		U32_MAX

#define PLOOP_INFLIGHT_TIMEOUT	(60 * HZ)
#define PLOOP_ENOSPC_TIMEOUT	(20 * HZ)

#define PLOOP_BIOS_HTABLE_BITS	8
#define PLOOP_BIOS_HTABLE_SIZE	(1 << PLOOP_BIOS_HTABLE_BITS)
#define CLU_OFF(ploop, pos) (pos & (to_bytes(1 << ploop->cluster_log) - 1))
#define CLU_TO_POS(ploop, clu) to_bytes((loff_t)clu << ploop->cluster_log)
#define POS_TO_CLU(ploop, pos) (to_sector(pos) >> ploop->cluster_log)
#define SEC_TO_CLU(ploop, sec) (sec >> ploop->cluster_log)
#define CLU_TO_SEC(ploop, clu) ((sector_t)clu << ploop->cluster_log)
#define CLU_SIZE(ploop) to_bytes((u32)1 << ploop->cluster_log)

enum piwb_type {
	PIWB_TYPE_ALLOC = 0,	/* Allocation of new clusters */
	PIWB_TYPE_RELOC,	/* Relocation of clu (on BAT grow) */
	PIWB_TYPE_DISCARD,	/* Zeroing index on discard */
};

struct ploop_index_wb {
	struct ploop *ploop;
	struct completion *comp;
	blk_status_t *comp_bi_status;
	enum piwb_type type;
	spinlock_t lock;
	struct md_page *md;
	struct pio *pio;
	struct page *bat_page;
	struct list_head ready_data_pios;
	struct list_head cow_list;
	atomic_t count;
	bool completed;
	blk_status_t bi_status;
	u32 page_id;
	struct bio_vec aux_bvec;
};

/* Metadata page */
struct md_page {
	struct rb_node node;
	u32 id; /* Number of this page starting from hdr */
#define MD_DIRTY	(1U << 1) /* Page contains changes and wants writeback */
#define MD_WRITEBACK	(1U << 2) /* Writeback was submitted */
	unsigned int status;
	struct page *page;
	u8 *bat_levels;
	struct list_head wait_list;

	struct list_head wb_link;
	struct ploop_index_wb *piwb;
};

enum {
	PLOOP_LIST_PREPARE = 0, /* List for initial preparation and splitting
				 * embedded pios related to prq */
	PLOOP_LIST_DEFERRED,
	PLOOP_LIST_FLUSH,
	PLOOP_LIST_DISCARD,
	PLOOP_LIST_COW,

	PLOOP_LIST_COUNT,
	PLOOP_LIST_INVALID = PLOOP_LIST_COUNT,
};

struct ploop {
	struct dm_target *ti;
#define PLOOP_PRQ_POOL_SIZE 512 /* Twice nr_requests from blk_mq_init_sched() */
	mempool_t *prq_pool;
#define PLOOP_PIO_POOL_SIZE 256
	mempool_t *pio_pool;

	struct rb_root bat_entries;
	struct ploop_delta *deltas;
	u8 nr_deltas;
	bool falloc_new_clu; /* fallocate() instead of truncate() */
	u32 nr_bat_entries;
	unsigned int cluster_log; /* In sectors */
	sector_t skip_off; /* To cut beginning of ploop device */

	u8 m_Sig[16]; /* Signature */
	u32 m_Type; /* Disk type */
	u32 m_Sectors; /* Sectors per clu */

	/*
	 * Absolute values from start of file. BAT-related clusters
	 * are also included, and their bits must be zeroed.
	 */
	void *holes_bitmap; /* Clearing a bit occurs from kwork only */
	u32 hb_nr; /* holes_bitmap size in bits */
	rwlock_t bat_rwlock;

	struct list_head wb_batch_list;

	/*
	 * Hash table to link non-exclusive submitted bios.
	 * This is needed for discard to check, nobody uses
	 * the discarding clu.
	 */
	struct hlist_head *inflight_pios;
	/*
	 * Hash table to link exclusive submitted bios.
	 * This allows to delay bios going in some clu.
	 */
	struct hlist_head *exclusive_pios;

	struct workqueue_struct *wq;
	struct work_struct worker;
	struct work_struct fsync_worker;
	struct work_struct event_work;

	struct completion inflight_bios_ref_comp;
	struct percpu_ref inflight_bios_ref[2];
	bool inflight_ref_comp_pending;
	unsigned int inflight_bios_ref_index:1;

	struct list_head suspended_pios;
	bool stop_submitting_pios;

	spinlock_t inflight_lock;
	spinlock_t deferred_lock;

	struct list_head pios[PLOOP_LIST_COUNT];

	struct list_head resubmit_pios; /* After partial IO */
	struct list_head enospc_pios; /* Delayed after ENOSPC */

	atomic_t service_pios;
	struct wait_queue_head service_wq;

	spinlock_t err_status_lock;
	struct rw_semaphore ctl_rwsem;

	/*
	 * List of locked clusters (no write is possible).
	 * Make @cluster_lk_list hash table or smth like this.
	 */
	struct list_head cluster_lk_list;

	/* Resume is prohibited */
	bool noresume;
	/* Device is suspended */
	bool suspended;
	/* Device wants suspend */
	bool wants_suspend;

	/* Maintaince in process */
	bool maintaince;
	/*
	 * Don't associate kthread with @pio's
	 * block cgroup. This allows to distinguish
	 * and limit IO traffic from swap and ploop
	 * when they are sharing a physical disk.
	 */
	bool nokblkcg;

	struct timer_list enospc_timer;
	bool event_enospc;
};

struct ploop_rq {
	struct request *rq;
	struct bio_vec *bvec;
	struct cgroup_subsys_state *css;
};

struct pio;
typedef void (*ploop_endio_t)(struct pio *, void *, blk_status_t);

struct pio {
	struct ploop *ploop;
	struct cgroup_subsys_state *css;

	struct list_head list;
	struct hlist_node hlist_node;
	/* List of pios, which will be queued from this pio end */
	struct list_head endio_list;

	struct bvec_iter	bi_iter;
	struct bio_vec		*bi_io_vec;
	unsigned int		bi_op;
	unsigned int		bi_vcnt;
	blk_status_t bi_status;
	atomic_t remaining;

	ploop_endio_t endio_cb;
	void *endio_cb_data;

	u32 clu;
	u8 level;

	bool is_data_alloc:1;
	bool wants_discard_index_cleanup:1;
	bool is_fake_merge:1;
	bool free_on_endio:1;
	/*
	 * 0 and 1 are related to inflight_bios_ref[],
	 * 2 means index is not assigned.
	 */
#define PLOOP_REF_INDEX_INVALID	2
	unsigned int ref_index:2;

	u8 queue_list_id:3; /* id in ploop->pios */

	struct ploop_index_wb *piwb;

	struct kiocb iocb;
	atomic_t aio_ref;
	int ret; /* iocb result */
	void (*complete)(struct pio *me);
	void *data;
};

/* Delta COW private */
struct ploop_cow {
	struct ploop *ploop;
	struct pio *aux_pio;
	u32 dst_clu;

	struct pio *cow_pio;
};

extern bool ignore_signature_disk_in_use;
extern struct kmem_cache *cow_cache;

#define rb_root_for_each_md_page(rb_root, md, node)	\
	for (node = rb_first(rb_root),			\
	     md = rb_entry(node, struct md_page, node); \
	     node != NULL;				\
	     node = rb_next(node),			\
	     md = rb_entry(node, struct md_page, node))

#define ploop_for_each_md_page(ploop, md, node)	\
	rb_root_for_each_md_page(&ploop->bat_entries, md, node)

static inline bool ploop_is_ro(struct ploop *ploop)
{
	return (dm_table_get_mode(ploop->ti->table) & FMODE_WRITE) == 0;
}

static inline void ploop_remap_to_cluster(struct ploop *ploop,
					  struct pio *pio, u32 clu)
{
	pio->bi_iter.bi_sector &= ((1 << ploop->cluster_log) - 1);
	pio->bi_iter.bi_sector |= (clu << ploop->cluster_log);
}

static inline bool ploop_whole_cluster(struct ploop *ploop, struct pio *pio)
{
	sector_t end_sector = bvec_iter_end_sector(pio->bi_iter);

	if (pio->bi_iter.bi_size != CLU_SIZE(ploop))
		return false;
	/*
	 * There is no sacral meaning in bio_end_sector(),
	 * it's just a suitable and existing primitive.
	 */
	return !(end_sector & ((1 << ploop->cluster_log) - 1));
}

#define BAT_LEVEL_MAX		(U8_MAX - 1)
#define BAT_LEVEL_INVALID	U8_MAX
static inline u8 ploop_top_level(struct ploop *ploop)
{
	return ploop->nr_deltas - 1;
}

static inline struct ploop_delta *ploop_top_delta(struct ploop *ploop)
{
	return &ploop->deltas[ploop_top_level(ploop)];
}

static inline void ploop_hole_set_bit(unsigned long nr, struct ploop *ploop)
{
	if (!WARN_ON_ONCE(nr >= ploop->hb_nr))
		set_bit(nr, ploop->holes_bitmap);
}

static inline void ploop_hole_clear_bit(u32 nr, struct ploop *ploop)
{
	if (!WARN_ON_ONCE(nr >= ploop->hb_nr))
		clear_bit(nr, ploop->holes_bitmap);
}

static inline unsigned int ploop_nr_pages_in_cluster(struct ploop *ploop)
{
	return 1 << (ploop->cluster_log + 9 - PAGE_SHIFT);
}

/* Get number of clusters, occupied by hdr and BAT */
static inline unsigned int ploop_nr_bat_clusters(struct ploop *ploop,
						 u32 nr_bat_entries)
{
	unsigned long size, bat_clusters;

	size = (PLOOP_MAP_OFFSET + nr_bat_entries) * sizeof(map_index_t);
	bat_clusters = DIV_ROUND_UP(size, CLU_SIZE(ploop));

	return bat_clusters;
}

static inline u32 ploop_bat_clu_to_page_nr(u32 clu)
{
	u64 byte;

	byte = (clu + PLOOP_MAP_OFFSET) * sizeof(map_index_t);
	return byte >> PAGE_SHIFT;
}

static inline u32 ploop_bat_clu_idx_in_page(u32 clu)
{
	return (clu + PLOOP_MAP_OFFSET) % (PAGE_SIZE / sizeof(map_index_t));
}

static inline u32 ploop_page_clu_idx_to_bat_clu(u32 page_id, u32 cluster_rel)
{
	unsigned int off;
	off = (u64)page_id * PAGE_SIZE / sizeof(map_index_t) - PLOOP_MAP_OFFSET;
	return off + cluster_rel;
}

static inline struct md_page *ploop_md_first_entry(struct rb_root *md_root)
{
	struct rb_node *node = rb_first(md_root);
	return rb_entry(node, struct md_page, node);
}
static inline struct md_page *ploop_md_next_entry(struct md_page *md)
{
	return rb_entry(rb_next(&md->node), struct md_page, node);
}


extern struct md_page *ploop_md_page_find(struct ploop *ploop, u32 id);

/*
 * This should be called in very rare cases. Avoid this function
 * in cycles by clu, use ploop_for_each_md_page()-based
 * iterations instead.
 */
static inline u32 ploop_bat_entries(struct ploop *ploop, u32 clu,
			  u8 *bat_level, struct md_page **md_ret)
{
	u32 *bat_entries, dst_clu, id;
	struct md_page *md;

	id = ploop_bat_clu_to_page_nr(clu);
	md = ploop_md_page_find(ploop, id);
	BUG_ON(!md);

	/* Cluster index related to the page[page_id] start */
	clu = ploop_bat_clu_idx_in_page(clu);

	if (bat_level)
		*bat_level = md->bat_levels[clu];
	if (md_ret)
		*md_ret = md;

	bat_entries = kmap_atomic(md->page);
	dst_clu = bat_entries[clu];
	kunmap_atomic(bat_entries);
	return dst_clu;
}

static inline bool ploop_cluster_is_in_top_delta(struct ploop *ploop, u32 clu)
{
	u32 dst_clu;
	u8 level;

	if (WARN_ON(clu >= ploop->nr_bat_entries))
		return false;
	dst_clu = ploop_bat_entries(ploop, clu, &level, NULL);

	if (dst_clu == BAT_ENTRY_NONE || level < ploop_top_level(ploop))
		return false;
	return true;
}

static inline bool ploop_md_page_cluster_is_in_top_delta(struct ploop *ploop,
					   struct md_page *md, u32 clu)
{
	u32 count, *bat_entries;
	bool ret = true;

	count = PAGE_SIZE / sizeof(map_index_t);
	if ((clu + 1) * sizeof(u8) > ksize(md->bat_levels) ||
	    clu >= count) {
		WARN_ONCE(1, "clu=%u count=%u\n", clu, count);
		return false;
	}

	bat_entries = kmap_atomic(md->page);
	if (bat_entries[clu] == BAT_ENTRY_NONE ||
	    md->bat_levels[clu] < ploop_top_level(ploop))
		ret = false;
	kunmap_atomic(bat_entries);
	return ret;
}

static inline void init_be_iter(u32 nr_be, u32 page_id,
				u32 *start, u32 *end)
{
	unsigned int count = PAGE_SIZE / sizeof(map_index_t);
	u32 rem, last_page = ploop_bat_clu_to_page_nr(nr_be - 1);

	*start = 0;
	if (page_id == 0)
		*start = PLOOP_MAP_OFFSET;

	*end = count - 1;
	if (page_id == last_page) {
		rem = (nr_be + PLOOP_MAP_OFFSET) % count;
		/* Adjust *end only in case last page is not full. */
		if (rem)
			*end = rem - 1;
	}
}

static inline void ploop_init_be_iter(struct ploop *ploop, u32 page_id,
				      u32 *start, u32 *end)
{
	init_be_iter(ploop->nr_bat_entries, page_id, start, end);
}

extern struct pio *ploop_find_pio(struct hlist_head head[], u32 clu);

extern int ploop_prealloc_md_pages(struct rb_root *root, u32 nr_bat_entries,
			     u32 new_nr_bat_entries);

static inline struct pio *ploop_bio_to_endio_hook(struct bio *bio)
{
	return dm_per_bio_data(bio, sizeof(struct pio));
}

static inline struct pio *ploop_pio_list_pop(struct list_head *pio_list)
{
	struct pio *pio;

	pio = list_first_entry_or_null(pio_list, struct pio, list);
	if (pio)
		list_del_init(&pio->list);
	return pio;
}

#define PLOOP_HASH_TABLE_BITS 5
#define PLOOP_HASH_TABLE_SIZE (1 << PLOOP_HASH_TABLE_BITS)
static inline struct hlist_head *ploop_htable_slot(struct hlist_head head[], u32 clu)
{
	return &head[hash_32(clu, PLOOP_HASH_TABLE_BITS)];
}

static inline bool ploop_fake_merge_pio(struct pio *pio)
{
	if (pio->is_fake_merge) {
		WARN_ON_ONCE(pio->bi_iter.bi_size ||
			     pio->bi_op != REQ_OP_WRITE);
		return true;
	}
	return false;
}

static inline struct pio *ploop_alloc_pio(struct ploop *ploop, gfp_t flags)
{
	return mempool_alloc(ploop->pio_pool, flags);
}

static inline void ploop_free_pio(struct ploop *ploop, struct pio *pio)
{
	mempool_free(pio, ploop->pio_pool);
}

extern void ploop_md_page_insert(struct ploop *ploop, struct md_page *md);
extern void ploop_free_md_page(struct md_page *md);
extern void ploop_free_md_pages_tree(struct rb_root *root);
extern bool ploop_try_update_bat_entry(struct ploop *ploop, u32 clu,
				       u8 level, u32 dst_clu);

extern int ploop_add_delta(struct ploop *ploop, u32 level,
			   struct file *file, bool is_raw);
extern int ploop_check_delta_length(struct ploop *ploop, struct file *file,
				    loff_t *file_size);
extern void ploop_submit_embedded_pios(struct ploop *ploop,
				       struct list_head *list);
extern void ploop_dispatch_pios(struct ploop *ploop, struct pio *pio,
				struct list_head *pio_list);
extern void do_ploop_work(struct work_struct *ws);
extern void do_ploop_fsync_work(struct work_struct *ws);
extern void do_ploop_event_work(struct work_struct *work);
extern int ploop_clone_and_map(struct dm_target *ti, struct request *rq,
			       union map_info *map_context,
			       struct request **clone);
extern struct pio *ploop_find_lk_of_cluster(struct ploop *ploop, u32 clu);
extern void ploop_init_pio(struct ploop *ploop, unsigned int bi_op,
			   struct pio *pio);
extern int ploop_rw_page_sync(unsigned rw, struct file *file,
			      u64 index, struct page *page);
extern void ploop_map_and_submit_rw(struct ploop *ploop, u32 dst_clu,
				    struct pio *pio, u8 level);
extern int ploop_prepare_reloc_index_wb(struct ploop *ploop,
					struct md_page **ret_md, u32 clu, u32 *dst_clu);
extern void ploop_break_bat_update(struct ploop *ploop, struct md_page *md);
extern void ploop_index_wb_submit(struct ploop *, struct ploop_index_wb *);
extern int ploop_message(struct dm_target *ti, unsigned int argc, char **argv,
			 char *result, unsigned int maxlen);

extern struct pio *ploop_alloc_pio_with_pages(struct ploop *ploop);
extern void ploop_free_pio_with_pages(struct ploop *ploop, struct pio *pio);
extern void ploop_pio_prepare_offsets(struct ploop *ploop, struct pio *pio, u32 clu);

extern int ploop_setup_metadata(struct ploop *ploop, struct page *page);
extern int ploop_read_delta_metadata(struct ploop *ploop, struct file *file,
				     struct rb_root *md_root, u32 *delta_nr_be);
extern void ploop_index_wb_init(struct ploop_index_wb *piwb,
				struct ploop *ploop);
extern void ploop_call_rw_iter(struct file *file, loff_t pos, unsigned rw,
			       struct iov_iter *iter, struct pio *pio);
extern void ploop_enospc_timer(struct timer_list *timer);
#endif /* __DM_PLOOP_H */
