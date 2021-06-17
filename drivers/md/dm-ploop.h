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
	u32 size_in_clus;
	bool is_raw;
};

struct ploop_cmd {
#define PLOOP_CMD_RESIZE		1
#define PLOOP_CMD_MERGE_SNAPSHOT	3
	struct completion comp;
	struct ploop *ploop;
	unsigned int type;
	int retval;
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
			unsigned int end_dst_cluster;
			unsigned int nr_old_bat_clu;
			unsigned int cluster, dst_cluster;
			struct pio *pio;
		} resize;
		struct {
#define NR_MERGE_BIOS			64
			atomic_t nr_available;
			unsigned int cluster; /* Currently iterated cluster */
			bool do_repeat;
		} merge;
	};
};

#define PAGE_NR_NONE		UINT_MAX
/* We can't use 0 for unmapped clusters, since RAW image references 0 cluster */
#define BAT_ENTRY_NONE		UINT_MAX

#define CLEANUP_DELAY		20
#define PLOOP_INFLIGHT_TIMEOUT	(60 * HZ)

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
	PIWB_TYPE_RELOC,	/* Relocation of cluster (on BAT grow) */
	PIWB_TYPE_DISCARD,	/* Zeroing index on discard */
};

struct ploop_index_wb {
	struct ploop *ploop;
	struct completion comp;
	enum piwb_type type;
	spinlock_t lock;
	struct page *bat_page;
	struct list_head ready_data_pios;
	struct list_head cow_list;
	atomic_t count;
	bool completed;
	int bi_status;
	unsigned int page_nr;
};

/* Metadata page */
struct md_page {
	struct rb_node node;
	unsigned int id; /* Number of this page starting from hdr */
	struct page *page;
	u8 *bat_levels;
};

struct ploop {
	struct dm_target *ti;

	struct rb_root bat_entries;
	struct ploop_delta *deltas;
	u8 nr_deltas;
	unsigned int nr_bat_entries;
	unsigned int cluster_log; /* In sectors */

	u8 m_Sig[16]; /* Signature */
	u32 m_Type; /* Disk type */
	u32 m_Sectors; /* Sectors per clu */

	/*
	 * Absolute values from start of file. BAT-related clusters
	 * are also included, and their bits must be zeroed.
	 */
	void *holes_bitmap; /* Clearing a bit occurs from kwork only */
	unsigned int hb_nr; /* holes_bitmap size in bits */
	rwlock_t bat_rwlock;

	void *tracking_bitmap;
	unsigned int tb_nr; /* tracking_bitmap size in bits */
	unsigned int tb_cursor;

	/*
	 * Hash table to link non-exclusive submitted bios.
	 * This is needed for discard to check, nobody uses
	 * the discarding cluster.
	 */
	struct hlist_head *inflight_pios;
	/*
	 * Hash table to link exclusive submitted bios.
	 * This allows to delay bios going in some cluster.
	 */
	struct hlist_head *exclusive_pios;

	struct workqueue_struct *wq;
	struct work_struct worker;
	struct work_struct fsync_worker;

	struct completion inflight_bios_ref_comp;
	struct percpu_ref inflight_bios_ref[2];
	bool inflight_ref_comp_pending;
	unsigned int inflight_bios_ref_index:1;

	struct list_head delayed_pios;
	bool stop_submitting_pios;

	spinlock_t inflight_lock;
	spinlock_t deferred_lock;
	struct list_head deferred_pios;
	struct list_head flush_pios;
	struct list_head discard_pios;
	struct list_head resubmit_pios; /* After partial IO */

	struct rw_semaphore ctl_rwsem;
	struct ploop_cmd *deferred_cmd;

	/*
	 * List of locked clusters (no write is possible).
	 * Make @cluster_lk_list hash table or smth like this.
	 */
	struct list_head cluster_lk_list;

	/* List of COW requests requiring action. */
	struct list_head delta_cow_action_list;

	/* Resume is prohibited */
	bool noresume;

	/* Maintaince in process */
	bool maintaince;
};

struct ploop_rq {
	struct request *rq;
	struct bio_vec *bvec;
};

struct pio;
typedef void (*ploop_endio_t)(struct pio *, void *, blk_status_t);

struct pio {
	struct ploop *ploop;

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

	unsigned int cluster;
	u8 level;

	bool is_data_alloc:1;
	bool wants_discard_index_cleanup:1;
	bool free_on_endio:1;
	/*
	 * 0 and 1 are related to inflight_bios_ref[],
	 * 2 means index is not assigned.
	 */
#define PLOOP_REF_INDEX_INVALID	2
	unsigned int ref_index:2;

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
	struct pio *cluster_pio;
	unsigned int dst_cluster;

	struct pio aux_pio;

	void (*end_fn)(struct ploop *, int, void *);
	void *data; /* Second argument of end_fn */
};

extern bool ignore_signature_disk_in_use;
extern struct kmem_cache *cow_cache;

#define ploop_for_each_md_page(ploop, md, node)		\
	for (node = rb_first(&ploop->bat_entries),	\
	     md = rb_entry(node, struct md_page, node); \
	     node != NULL;				\
	     node = rb_next(node),			\
	     md = rb_entry(node, struct md_page, node))

static inline bool ploop_is_ro(struct ploop *ploop)
{
	return (dm_table_get_mode(ploop->ti->table) & FMODE_WRITE) == 0;
}

static inline void remap_to_cluster(struct ploop *ploop, struct pio *pio,
				    unsigned int cluster)
{
	pio->bi_iter.bi_sector &= ((1 << ploop->cluster_log) - 1);
	pio->bi_iter.bi_sector |= (cluster << ploop->cluster_log);
}

static inline bool whole_cluster(struct ploop *ploop, struct pio *pio)
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

static inline ssize_t ploop_per_io_data_size(void)
{
	return sizeof(struct ploop_rq) + sizeof(struct pio);
}
static inline struct ploop_rq *map_info_to_prq(union map_info *info)
{
	return (void *)info->ptr;
}
static inline struct pio *map_info_to_pio(union map_info *info)
{
	return (void *)info->ptr + sizeof(struct ploop_rq);
}

#define BAT_LEVEL_MAX		(U8_MAX - 1)
#define BAT_LEVEL_INVALID	U8_MAX
static inline u8 top_level(struct ploop *ploop)
{
	return ploop->nr_deltas - 1;
}

static inline struct ploop_delta *top_delta(struct ploop *ploop)
{
	return &ploop->deltas[top_level(ploop)];
}

static inline void ploop_hole_set_bit(unsigned long nr, struct ploop *ploop)
{
	if (!WARN_ON_ONCE(nr >= ploop->hb_nr))
		set_bit(nr, ploop->holes_bitmap);
}

static inline void ploop_hole_clear_bit(unsigned int nr, struct ploop *ploop)
{
	if (!WARN_ON_ONCE(nr >= ploop->hb_nr))
		clear_bit(nr, ploop->holes_bitmap);
}

static inline unsigned int nr_pages_in_cluster(struct ploop *ploop)
{
	return 1 << (ploop->cluster_log + 9 - PAGE_SHIFT);
}

/* Get number of clusters, occupied by hdr and BAT */
static inline unsigned int ploop_nr_bat_clusters(struct ploop *ploop,
						 unsigned int nr_bat_entries)
{
	unsigned long size, bat_clusters;

	size = (PLOOP_MAP_OFFSET + nr_bat_entries) * sizeof(map_index_t);
	bat_clusters = DIV_ROUND_UP(size, CLU_SIZE(ploop));

	return bat_clusters;
}

static inline unsigned int bat_clu_to_page_nr(unsigned int cluster)
{
	unsigned int byte;

	byte = (cluster + PLOOP_MAP_OFFSET) * sizeof(map_index_t);
	return byte >> PAGE_SHIFT;
}

static inline unsigned int bat_clu_idx_in_page(unsigned int cluster)
{
	return (cluster + PLOOP_MAP_OFFSET) % (PAGE_SIZE / sizeof(map_index_t));
}

static inline unsigned int page_clu_idx_to_bat_clu(unsigned int page_id,
						   unsigned int cluster_rel)
{
	unsigned int off;
	off = page_id * PAGE_SIZE / sizeof(map_index_t) - PLOOP_MAP_OFFSET;
	return off + cluster_rel;
}

extern struct md_page * md_page_find(struct ploop *ploop, unsigned int id);

/*
 * This should be called in very rare cases. Avoid this function
 * in cycles by cluster, use ploop_for_each_md_page()-based
 * iterations instead.
 */
static inline unsigned int ploop_bat_entries(struct ploop *ploop,
					     unsigned int cluster,
					     u8 *bat_level)
{
	unsigned int *bat_entries, dst_cluster, id;
	struct md_page *md;

	id = bat_clu_to_page_nr(cluster);
	md = md_page_find(ploop, id);
	BUG_ON(!md);

	/* Cluster index related to the page[page_nr] start */
	cluster = bat_clu_idx_in_page(cluster);

	if (bat_level)
		*bat_level = md->bat_levels[cluster];

	bat_entries = kmap_atomic(md->page);
	dst_cluster = bat_entries[cluster];
	kunmap_atomic(bat_entries);
	return dst_cluster;
}

static inline bool cluster_is_in_top_delta(struct ploop *ploop,
					   unsigned int cluster)
{
	unsigned int dst_cluster;
	u8 level;

	if (WARN_ON(cluster >= ploop->nr_bat_entries))
		return false;
	dst_cluster = ploop_bat_entries(ploop, cluster, &level);

	if (dst_cluster == BAT_ENTRY_NONE || level < top_level(ploop))
		return false;
	return true;
}

static inline bool md_page_cluster_is_in_top_delta(struct ploop *ploop,
			      struct md_page *md, unsigned int cluster)
{
	unsigned int count, *bat_entries;
	bool ret = true;

	count = PAGE_SIZE / sizeof(map_index_t);
	if ((cluster + 1) * sizeof(u8) > ksize(md->bat_levels) ||
	    cluster >= count) {
		WARN_ONCE(1, "cluster=%u count=%u\n", cluster, count);
		return false;
	}

	bat_entries = kmap_atomic(md->page);
	if (bat_entries[cluster] == BAT_ENTRY_NONE ||
	    md->bat_levels[cluster] < top_level(ploop))
		ret = false;
	kunmap_atomic(bat_entries);
	return ret;
}

static inline void init_bat_entries_iter(struct ploop *ploop, unsigned int page_id,
					 unsigned int *start, unsigned int *end)
{
	unsigned int last_page = bat_clu_to_page_nr(ploop->nr_bat_entries - 1);
	unsigned int count = PAGE_SIZE / sizeof(map_index_t);

	*start = 0;
	if (page_id == 0)
		*start = PLOOP_MAP_OFFSET;

	*end = count - 1;
	if (page_id == last_page)
		*end = ((ploop->nr_bat_entries + PLOOP_MAP_OFFSET) % count) - 1;
}

extern void __track_pio(struct ploop *ploop, struct pio *pio);

static inline void track_pio(struct ploop *ploop, struct pio *pio)
{
	/* See comment in process_tracking_start() about visibility */
	if (unlikely(ploop->tracking_bitmap))
		__track_pio(ploop, pio);
}

extern struct pio *find_pio(struct hlist_head head[], u32 clu);

extern int prealloc_md_pages(struct rb_root *root, unsigned int nr_bat_entries,
			     unsigned int new_nr_bat_entries);

static inline struct pio *bio_to_endio_hook(struct bio *bio)
{
	return dm_per_bio_data(bio, sizeof(struct pio));
}

static inline struct pio *pio_list_pop(struct list_head *pio_list)
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

extern void md_page_insert(struct ploop *ploop, struct md_page *md);
extern void ploop_free_md_page(struct md_page *md);
extern void free_md_pages_tree(struct rb_root *root);
extern bool try_update_bat_entry(struct ploop *ploop, unsigned int cluster,
				 u8 level, unsigned int dst_cluster);
extern int convert_bat_entries(u32 *bat_entries, u32 count);

extern int ploop_add_delta(struct ploop *ploop, u32 level, struct file *file, bool is_raw);
extern void submit_pios(struct ploop *ploop, struct list_head *list);
extern void defer_pios(struct ploop *ploop, struct pio *pio, struct list_head *pio_list);
extern void do_ploop_work(struct work_struct *ws);
extern void do_ploop_fsync_work(struct work_struct *ws);
extern void process_deferred_cmd(struct ploop *ploop,
			struct ploop_index_wb *piwb);
extern int ploop_clone_and_map(struct dm_target *ti, struct request *rq,
		    union map_info *map_context, struct request **clone);
extern struct pio *find_lk_of_cluster(struct ploop *ploop, u32 cluster);
extern void init_pio(struct ploop *ploop, unsigned int bi_op, struct pio *pio);
extern int ploop_rw_page_sync(unsigned rw, struct file *file,
			      u64 index, struct page *page);
extern void map_and_submit_rw(struct ploop *ploop, u32 dst_clu, struct pio *pio, u8 level);

extern int ploop_prepare_reloc_index_wb(struct ploop *, struct ploop_index_wb *,
					unsigned int, unsigned int *);
extern void ploop_reset_bat_update(struct ploop_index_wb *);
extern void ploop_submit_index_wb_sync(struct ploop *, struct ploop_index_wb *);
extern int ploop_message(struct dm_target *ti, unsigned int argc, char **argv,
			 char *result, unsigned int maxlen);
extern int submit_cluster_cow(struct ploop *ploop, unsigned int level,
			      unsigned int cluster, unsigned int dst_cluster,
			      void (*end_fn)(struct ploop *, int, void *), void *data);

extern struct pio * alloc_pio_with_pages(struct ploop *ploop);
extern void free_pio_with_pages(struct ploop *ploop, struct pio *pio);
extern void pio_prepare_offsets(struct ploop *, struct pio *, unsigned int);

extern int ploop_setup_metadata(struct ploop *ploop, struct page *page);
extern int ploop_read_delta_metadata(struct ploop *ploop, struct file *file,
				     void **d_hdr);
extern void ploop_call_rw_iter(struct file *file, loff_t pos, unsigned rw,
			       struct iov_iter *iter, struct pio *pio);
#endif /* __DM_PLOOP_H */
