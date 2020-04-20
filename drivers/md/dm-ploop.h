#ifndef __DM_PLOOP_H
#define __DM_PLOOP_H

#include <linux/device-mapper.h>
#include <linux/bio.h>

#define PLOOP_MAP_OFFSET 16
typedef u32 map_index_t;

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
	bool is_raw;
};

struct ploop_cmd {
#define PLOOP_CMD_RESIZE		1
#define PLOOP_CMD_ADD_DELTA		2
#define PLOOP_CMD_MERGE_SNAPSHOT	3
#define PLOOP_CMD_NOTIFY_DELTA_MERGED	4
#define PLOOP_CMD_SWITCH_TOP_DELTA	5
#define PLOOP_CMD_UPDATE_DELTA_INDEX	6
#define PLOOP_CMD_TRACKING_START	7
#define PLOOP_CMD_FLIP_UPPER_DELTAS	8
#define PLOOP_CMD_SET_PUSH_BACKUP	9
#define PLOOP_CMD_TRY_PREFLUSH		10
	struct completion comp;
	struct ploop *ploop;
	unsigned int type;
	int retval;
	union {
		struct {
			u64 new_size;
			/* Preallocated data */
			struct rb_root md_pages_root;
			void *holes_bitmap;
#define PLOOP_GROW_STAGE_INITIAL	0
			unsigned int stage;
			unsigned int nr_bat_entries;
			unsigned int hb_nr;
			unsigned int end_dst_cluster;
			unsigned int nr_old_bat_clu;
			unsigned int cluster, dst_cluster;
			struct bio *bio;
		} resize;
		struct {
			struct file *file;
			struct ploop_delta *deltas;
			void *hdr; /* hdr and bat_entries consequentially */
			unsigned int raw_clusters;
		} add_delta;
		struct {
#define NR_MERGE_BIOS			64
			atomic_t nr_available;
			unsigned int cluster; /* Currently iterated cluster */
			bool do_repeat;
		} merge;
		struct {
			void *hdr; /* hdr and bat_entries consequentially */
			u8 level;
			bool forward;
		} notify_delta_merged;
		struct {
			struct dm_dev *origin_dev;
			struct ploop_delta *deltas;
		} switch_top_delta;
		struct {
			u8 level;
			const char *map;
		} update_delta_index;
		struct {
			void *tracking_bitmap;
			unsigned int tb_nr;
		} tracking_start;
		struct {
			struct dm_dev *origin_dev;
			struct file *file;
		} flip_upper_deltas;
		struct {
			struct push_backup *pb;
		} set_push_backup;
	};
};

#define PAGE_NR_NONE		UINT_MAX
/* We can't use 0 for unmapped clusters, since RAW image references 0 cluster */
#define BAT_ENTRY_NONE		UINT_MAX

#define BAT_LEVEL_TOP		U8_MAX
#define CLEANUP_DELAY		20
#define PLOOP_INFLIGHT_TIMEOUT	(60 * HZ)

#define PLOOP_BIOS_HTABLE_BITS	8
#define PLOOP_BIOS_HTABLE_SIZE	(1 << PLOOP_BIOS_HTABLE_BITS)

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
	struct bio *bat_bio;
	struct bio_list ready_data_bios;
	struct bio_list cow_list;
	atomic_t count;
	bool completed;
	int bi_status;
	unsigned int page_nr;
};

struct push_backup {
	struct ploop *ploop;
	/* Store uuid as string and avoid convertation on every read/write */
	u8 uuid[33];
	bool alive;

	void *ppb_map;

	u64 timeout_in_jiffies;
	u64 deadline_jiffies;
	struct timer_list deadline_timer;

	/* This tree is for looking for delayed bio by cluster */
	struct rb_root rb_root;

	struct wait_queue_head wq;
	struct list_head pending;
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

	struct dm_dev *origin_dev;
	struct rb_root bat_entries;
	struct ploop_delta *deltas;
	u8 nr_deltas;
	unsigned int nr_bat_entries;
	unsigned int cluster_log; /* In sectors */
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

	int force_defer_bio_count; /* Protected by bat_rwlock */
	bool force_link_inflight_bios;
	/*
	 * Hash table to link non-exclusive submitted bios.
	 * This is needed for discard to check, nobody uses
	 * the discarding cluster. Only made when the above
	 * force_link_inflight_bios is enabled.
	 */
	struct rb_root inflight_bios_rbtree;
	/*
	 * Hash table to link exclusive submitted bios.
	 * This allows to delay bios going in some cluster.
	 */
	struct rb_root exclusive_bios_rbtree;

	atomic_t nr_discard_bios;
	unsigned long pending_discard_cleanup;

	struct workqueue_struct *wq;
	struct work_struct worker;

	struct completion inflight_bios_ref_comp;
	struct percpu_ref inflight_bios_ref[2];
	bool inflight_ref_comp_pending;
	unsigned int inflight_bios_ref_index:1;

	spinlock_t deferred_lock;
	struct bio_list deferred_bios;
	struct bio_list discard_bios;

	struct rw_semaphore ctl_rwsem;
	struct ploop_cmd *deferred_cmd;

	/*
	 * List of locked clusters (no write is possible).
	 * Make @cluster_lk_list hash table or smth like this.
	 */
	struct list_head cluster_lk_list;

	/* List of COW requests requiring action. */
	struct bio_list delta_cow_action_list;

	/* Resume is prohibited */
	bool noresume;

	/* Maintaince in process */
	bool maintaince;

	/* Push Backup */
	struct push_backup *pb;
	spinlock_t pb_lock;
};

struct dm_ploop_endio_hook {
	union {
		struct ploop_index_wb *piwb;
		struct list_head list;
	};
	struct rb_node node;
	/* List of bios, which will be queued from this bio end */
	struct bio *endio_bio_list;

	unsigned int cluster;

#define PLOOP_END_IO_NONE		0
#define PLOOP_END_IO_DATA_BIO		1
#define PLOOP_END_IO_DISCARD_BIO	2
#define PLOOP_END_IO_DISCARD_INDEX_BIO	3
	unsigned int action:2;
	/*
	 * 0 and 1 are related to inflight_bios_ref[],
	 * 2 means index is not assigned.
	 */
#define PLOOP_REF_INDEX_INVALID	2
	unsigned int ref_index:2;
};

struct ploop_iocb {
	struct kiocb iocb;
	struct bio *bio;
	atomic_t count;
};

/* Delta COW private */
struct ploop_cow {
	struct ploop *ploop;
	struct bio *cluster_bio;
	unsigned int dst_cluster;

	struct dm_ploop_endio_hook hook;

	void (*end_fn)(struct ploop *, int, void *);
	void *data; /* Second argument of end_fn */
};

extern struct kmem_cache *piocb_cache;
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

static inline void remap_to_origin(struct ploop *ploop, struct bio *bio)
{
	bio_set_dev(bio, ploop->origin_dev->bdev);
}

static inline void remap_to_cluster(struct ploop *ploop, struct bio *bio,
				    unsigned int cluster)
{
	bio->bi_iter.bi_sector &= ((1 << ploop->cluster_log) - 1);
	bio->bi_iter.bi_sector |= (cluster << ploop->cluster_log);
}

static inline bool whole_cluster(struct ploop *ploop, struct bio *bio)
{
	if (bio_sectors(bio) != (1 << ploop->cluster_log))
		return false;
	/*
	 * There is no sacral meaning in bio_end_sector(),
	 * it's just a suitable and existing primitive.
	 */
	return !(bio_end_sector(bio) & ((1 << ploop->cluster_log) - 1));
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
	bat_clusters = DIV_ROUND_UP(size, 1 << (ploop->cluster_log + 9));

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

	if (dst_cluster == BAT_ENTRY_NONE || level < BAT_LEVEL_TOP)
		return false;
	return true;
}

static inline bool md_page_cluster_is_in_top_delta(struct md_page *md,
						   unsigned int cluster)
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
	    md->bat_levels[cluster] < BAT_LEVEL_TOP)
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

static inline void force_defer_bio_count_inc(struct ploop *ploop)
{
	unsigned long flags;

	write_lock_irqsave(&ploop->bat_rwlock, flags);
	WARN_ON_ONCE(ploop->force_defer_bio_count++ < 0);
	write_unlock_irqrestore(&ploop->bat_rwlock, flags);
}

static inline void force_defer_bio_count_dec(struct ploop *ploop)
{
	unsigned long flags;

	write_lock_irqsave(&ploop->bat_rwlock, flags);
	WARN_ON_ONCE(--ploop->force_defer_bio_count < 0);
	write_unlock_irqrestore(&ploop->bat_rwlock, flags);
}

extern void __track_bio(struct ploop *ploop, struct bio *bio);

static inline void track_bio(struct ploop *ploop, struct bio *bio)
{
	/* See comment in process_tracking_start() about visibility */
	if (unlikely(ploop->tracking_bitmap))
		__track_bio(ploop, bio);
}

extern struct dm_ploop_endio_hook *find_endio_hook_range(struct ploop *ploop,
			struct rb_root *root, unsigned int l, unsigned int r);

static inline struct dm_ploop_endio_hook *find_endio_hook(struct ploop *ploop,
				   struct rb_root *root, unsigned int cluster)
{
	return find_endio_hook_range(ploop, root, cluster, cluster);
}

extern struct md_page * alloc_md_page(unsigned int id);
extern void md_page_insert(struct ploop *ploop, struct md_page *md);
extern void free_md_page(struct md_page *md);
extern void free_md_pages_tree(struct rb_root *root);
extern bool try_update_bat_entry(struct ploop *ploop, unsigned int cluster,
				 u8 level, unsigned int dst_cluster);

extern int ploop_add_delta(struct ploop *ploop, const char *arg);
extern void defer_bio(struct ploop *ploop, struct bio *bio);
extern void defer_bio_list(struct ploop *ploop, struct bio_list *bio_list);
extern void do_ploop_work(struct work_struct *ws);
extern void process_deferred_cmd(struct ploop *ploop,
			struct ploop_index_wb *piwb);
extern int ploop_map(struct dm_target *ti, struct bio *bio);
extern int ploop_endio(struct dm_target *ti, struct bio *bio, blk_status_t *err);
extern int ploop_inflight_bios_ref_switch(struct ploop *ploop, bool killable);
extern struct dm_ploop_endio_hook *find_lk_of_cluster(struct ploop *ploop,
						      unsigned int cluster);
extern void unlink_postponed_backup_endio(struct ploop *ploop,
					  struct bio_list *bio_list,
					  struct dm_ploop_endio_hook *h);

extern int ploop_prepare_reloc_index_wb(struct ploop *, struct ploop_index_wb *,
					unsigned int, unsigned int *);
extern void ploop_reset_bat_update(struct ploop_index_wb *);
extern void ploop_submit_index_wb_sync(struct ploop *, struct ploop_index_wb *);
extern int ploop_message(struct dm_target *ti, unsigned int argc, char **argv,
			 char *result, unsigned int maxlen);
extern int submit_cluster_cow(struct ploop *ploop, unsigned int level,
			      unsigned int cluster, unsigned int dst_cluster,
			      void (*end_fn)(struct ploop *, int, void *), void *data);
extern void restart_delta_cow(struct ploop *ploop);
extern void cancel_discard_bios(struct ploop *ploop);

extern struct bio * alloc_bio_with_pages(struct ploop *ploop);
extern void free_bio_with_pages(struct ploop *ploop, struct bio *bio);
extern void bio_prepare_offsets(struct ploop *, struct bio *, unsigned int);
extern void ploop_free_pb(struct push_backup *pb);
extern void cleanup_backup(struct ploop *ploop);

extern int ploop_read_cluster_sync(struct ploop *, struct bio *, unsigned int);

extern int ploop_read_metadata(struct dm_target *ti, struct ploop *ploop);
extern int ploop_read_delta_metadata(struct ploop *ploop, struct file *file,
				     void **d_hdr);

#endif /* __DM_PLOOP_H */
