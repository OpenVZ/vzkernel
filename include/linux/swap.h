#ifndef _LINUX_SWAP_H
#define _LINUX_SWAP_H

#include <linux/spinlock.h>
#include <linux/linkage.h>
#include <linux/mmzone.h>
#include <linux/list.h>
#include <linux/memcontrol.h>
#include <linux/sched.h>
#include <linux/node.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/atomic.h>
#include <linux/page-flags.h>
#include <asm/page.h>

#include <linux/rh_kabi.h>

struct notifier_block;

struct bio;

struct pagevec;

#define SWAP_FLAG_PREFER	0x8000	/* set if swap priority specified */
#define SWAP_FLAG_PRIO_MASK	0x7fff
#define SWAP_FLAG_PRIO_SHIFT	0
#define SWAP_FLAG_DISCARD	0x10000 /* enable discard for swap */
#define SWAP_FLAG_DISCARD_ONCE	0x20000 /* discard swap area at swapon-time */
#define SWAP_FLAG_DISCARD_PAGES 0x40000 /* discard page-clusters after use */

#define SWAP_FLAGS_VALID	(SWAP_FLAG_PRIO_MASK | SWAP_FLAG_PREFER | \
				 SWAP_FLAG_DISCARD | SWAP_FLAG_DISCARD_ONCE | \
				 SWAP_FLAG_DISCARD_PAGES)
#define SWAP_BATCH 64

static inline int current_is_kswapd(void)
{
	return current->flags & PF_KSWAPD;
}

/*
 * MAX_SWAPFILES defines the maximum number of swaptypes: things which can
 * be swapped to.  The swap type and the offset into that swap type are
 * encoded into pte's and into pgoff_t's in the swapcache.  Using five bits
 * for the type means that the maximum number of swapcache pages is 27 bits
 * on 32-bit-pgoff_t architectures.  And that assumes that the architecture packs
 * the type/offset into the pte as 5/27 as well.
 */
#define MAX_SWAPFILES_SHIFT	5

/*
 * Use some of the swap files numbers for other purposes. This
 * is a convenient way to hook into the VM to trigger special
 * actions on faults.
 */

/*
 * NUMA node memory migration support
 */
#ifdef CONFIG_MIGRATION
#define SWP_MIGRATION_NUM 2
#define SWP_MIGRATION_READ	(MAX_SWAPFILES + SWP_HWPOISON_NUM)
#define SWP_MIGRATION_WRITE	(MAX_SWAPFILES + SWP_HWPOISON_NUM + 1)
#else
#define SWP_MIGRATION_NUM 0
#endif

/*
 * Handling of hardware poisoned pages with memory corruption.
 */
#ifdef CONFIG_MEMORY_FAILURE
#define SWP_HWPOISON_NUM 1
#define SWP_HWPOISON		MAX_SWAPFILES
#else
#define SWP_HWPOISON_NUM 0
#endif

/*
 * HMM (heterogeneous memory management) used when data is in device memory.
 */
#ifdef CONFIG_HMM
#define SWP_HMM_NUM 2
#define SWP_HMM_WRITE	(MAX_SWAPFILES+SWP_MIGRATION_NUM+SWP_HWPOISON_NUM)
#define SWP_HMM_READ	(MAX_SWAPFILES+SWP_MIGRATION_NUM+SWP_HWPOISON_NUM+1)
#else
#define SWP_HMM_NUM 0
#endif

#define MAX_SWAPFILES \
	((1 << MAX_SWAPFILES_SHIFT) - SWP_MIGRATION_NUM - \
	 SWP_HWPOISON_NUM - SWP_HMM_NUM)

/*
 * Magic header for a swap area. The first part of the union is
 * what the swap magic looks like for the old (limited to 128MB)
 * swap area format, the second part of the union adds - in the
 * old reserved area - some extra information. Note that the first
 * kilobyte is reserved for boot loader or disk label stuff...
 *
 * Having the magic at the end of the PAGE_SIZE makes detecting swap
 * areas somewhat tricky on machines that support multiple page sizes.
 * For 2.5 we'll probably want to move the magic to just beyond the
 * bootbits...
 */
union swap_header {
	struct {
		char reserved[PAGE_SIZE - 10];
		char magic[10];			/* SWAP-SPACE or SWAPSPACE2 */
	} magic;
	struct {
		char		bootbits[1024];	/* Space for disklabel etc. */
		__u32		version;
		__u32		last_page;
		__u32		nr_badpages;
		unsigned char	sws_uuid[16];
		unsigned char	sws_volume[16];
		__u32		padding[117];
		__u32		badpages[1];
	} info;
};

 /* A swap entry has to fit into a "unsigned long", as
  * the entry is hidden in the "index" field of the
  * swapper address space.
  */
typedef struct {
	unsigned long val;
} swp_entry_t;

/*
 * current->reclaim_state points to one of these when a task is running
 * memory reclaim
 */
struct reclaim_state {
	unsigned long reclaimed_slab;
};

#ifdef __KERNEL__

struct address_space;
struct sysinfo;
struct writeback_control;
struct zone;

/*
 * A swap extent maps a range of a swapfile's PAGE_SIZE pages onto a range of
 * disk blocks.  A list of swap extents maps the entire swapfile.  (Where the
 * term `swapfile' refers to either a blockdevice or an IS_REG file.  Apart
 * from setup, they're handled identically.
 *
 * We always assume that blocks are of size PAGE_SIZE.
 */
struct swap_extent {
	struct list_head list;
	pgoff_t start_page;
	pgoff_t nr_pages;
	sector_t start_block;
};

/*
 * Max bad pages in the new format..
 */
#define __swapoffset(x) ((unsigned long)&((union swap_header *)0)->x)
#define MAX_SWAP_BADPAGES \
	((__swapoffset(magic.magic) - __swapoffset(info.badpages)) / sizeof(int))

enum {
	SWP_USED	= (1 << 0),	/* is slot in swap_info[] used? */
	SWP_WRITEOK	= (1 << 1),	/* ok to write to this swap?	*/
	SWP_DISCARDABLE = (1 << 2),	/* blkdev support discard */
	SWP_DISCARDING	= (1 << 3),	/* now discarding a free cluster */
	SWP_SOLIDSTATE	= (1 << 4),	/* blkdev seeks are cheap */
	SWP_CONTINUED	= (1 << 5),	/* swap_map has count continuation */
	SWP_BLKDEV	= (1 << 6),	/* its a block device */
	SWP_FILE	= (1 << 7),	/* set after swap_activate success */
	SWP_AREA_DISCARD = (1 << 8),	/* single-time swap area discards */
	SWP_PAGE_DISCARD = (1 << 9),	/* freed swap page-cluster discards */
					/* add others here before... */
	SWP_SCANNING	= (1 << 10),	/* refcount in scan_swap_map */
};

#define SWAP_CLUSTER_MAX 32UL
#define COMPACT_CLUSTER_MAX SWAP_CLUSTER_MAX

/*
 * Ratio between zone->managed_pages and the "gap" that above the per-zone
 * "high_wmark". While balancing nodes, We allow kswapd to shrink zones that
 * do not meet the (high_wmark + gap) watermark, even which already met the
 * high_wmark, in order to provide better per-zone lru behavior. We are ok to
 * spend not more than 1% of the memory for this zone balancing "gap".
 */
#define KSWAPD_ZONE_BALANCE_GAP_RATIO 100

#define SWAP_MAP_MAX	0x3e	/* Max duplication count, in first swap_map */
#define SWAP_MAP_BAD	0x3f	/* Note pageblock is bad, in first swap_map */
#define SWAP_HAS_CACHE	0x40	/* Flag page is cached, in first swap_map */
#define SWAP_CONT_MAX	0x7f	/* Max count, in each swap_map continuation */
#define COUNT_CONTINUED	0x80	/* See swap_map continuation for full count */
#define SWAP_MAP_SHMEM	0xbf	/* Owned by shmem/tmpfs, in first swap_map */

/*
 * We use this to track usage of a cluster. A cluster is a block of swap disk
 * space with SWAPFILE_CLUSTER pages long and naturally aligns in disk. All
 * free clusters are organized into a list. We fetch an entry from the list to
 * get a free cluster.
 *
 * The data field stores next cluster if the cluster is free or cluster usage
 * counter otherwise. The flags field determines if a cluster is free. This is
 * protected by swap_info_struct.lock.
 */
struct swap_cluster_info {
	spinlock_t lock;	/*
				 * Protect swap_cluster_info fields
				 * and swap_info_struct->swap_map
				 * elements correspond to the swap
				 * cluster
				 */
	unsigned int data:24;
	unsigned int flags:8;
};
#define CLUSTER_FLAG_FREE 1 /* This cluster is free */
#define CLUSTER_FLAG_NEXT_NULL 2 /* This cluster has no next cluster */

/*
 * We assign a cluster to each CPU, so each CPU can allocate swap entry from
 * its own cluster and swapout sequentially. The purpose is to optimize swapout
 * throughput.
 */
struct percpu_cluster {
	struct swap_cluster_info index; /* Current cluster index */
	unsigned int next; /* Likely next allocation offset */
};

struct swap_cluster_list {
	struct swap_cluster_info head;
	struct swap_cluster_info tail;
};

/*
 * The in-memory structure used to track swap areas.
 */
struct swap_info_struct {
	unsigned long	flags;		/* SWP_USED etc: see above */
	signed short	prio;		/* swap priority of this type */
	signed char	type;		/* strange name for an index */
	signed char     next;           /* unused: kept for kABI */
	unsigned int	max;		/* extent of the swap_map */
	unsigned char *swap_map;	/* vmalloc'ed array of usage counts */
	unsigned int lowest_bit;	/* index of first free in swap_map */
	unsigned int highest_bit;	/* index of last free in swap_map */
	unsigned int pages;		/* total of usable pages of swap */
	unsigned int inuse_pages;	/* number of those currently in use */
	unsigned int cluster_next;	/* likely index for next allocation */
	unsigned int cluster_nr;	/* countdown to next cluster search */
	RH_KABI_DEPRECATE(unsigned int, lowest_alloc)
	RH_KABI_DEPRECATE(unsigned int, highest_alloc)
	struct swap_extent *curr_swap_extent;
	struct swap_extent first_swap_extent;
	struct block_device *bdev;	/* swap device or bdev of swap file */
	struct file *swap_file;		/* seldom referenced */
	unsigned int old_block_size;	/* seldom referenced */
#ifdef CONFIG_FRONTSWAP
	unsigned long *frontswap_map;	/* frontswap in-use, one bit per page */
	atomic_t frontswap_pages;	/* frontswap pages in-use counter */
#endif
	spinlock_t lock;		/*
					 * protect map scan related fields like
					 * swap_map, lowest_bit, highest_bit,
					 * inuse_pages, cluster_next,
					 * cluster_nr, lowest_alloc,
					 * highest_alloc, free/discard cluster
					 * list. other fields are only changed
					 * at swapon/swapoff, so are protected
					 * by swap_lock. changing flags need
					 * hold this lock and swap_lock. If
					 * both locks need hold, hold swap_lock
					 * first.
					 */
	RH_KABI_EXTEND(struct plist_node list)		/* entry in swap_active_head */
	RH_KABI_EXTEND(struct plist_node avail_lists[MAX_NUMNODES]) /* entry in swap_avail_head */
	RH_KABI_EXTEND(struct swap_cluster_info *cluster_info) /* cluster info. Only for SSD */
	RH_KABI_EXTEND(struct swap_cluster_list free_clusters) /* free clusters list */
	RH_KABI_EXTEND(struct work_struct discard_work) /* discard worker */
	RH_KABI_EXTEND(struct swap_cluster_list discard_clusters) /* discard clusters list */
	RH_KABI_EXTEND(struct percpu_cluster __percpu *percpu_cluster) /* per cpu's swap location */
	RH_KABI_EXTEND(spinlock_t cont_lock) /* protect swap count continuation page list. */
};

#ifdef CONFIG_64BIT
#define SWAP_RA_ORDER_CEILING	5
#else
/* Avoid stack overflow, because we need to save part of page table */
#define SWAP_RA_ORDER_CEILING	3
#define SWAP_RA_PTE_CACHE_SIZE	(1 << SWAP_RA_ORDER_CEILING)
#endif

struct vma_swap_readahead {
	unsigned short win;
	unsigned short offset;
	unsigned short nr_pte;
#ifdef CONFIG_64BIT
	pte_t *ptes;
#else
	pte_t ptes[SWAP_RA_PTE_CACHE_SIZE];
#endif
};

/* linux/mm/workingset.c */
void *workingset_eviction(struct address_space *mapping, struct page *page);
bool workingset_refault(void *shadow);
void workingset_activation(struct page *page);

void workingset_remember_node(struct radix_tree_node *node);
void workingset_forget_node(struct radix_tree_node *node);

static inline unsigned int workingset_node_pages(struct radix_tree_node *node)
{
	return node->count & RADIX_TREE_COUNT_MASK;
}

static inline void workingset_node_pages_inc(struct radix_tree_node *node)
{
	node->count++;
}

static inline void workingset_node_pages_dec(struct radix_tree_node *node)
{
	VM_WARN_ON_ONCE(!workingset_node_pages(node));
	node->count--;
}

static inline unsigned int workingset_node_shadows(struct radix_tree_node *node)
{
	return node->count >> RADIX_TREE_COUNT_SHIFT;
}

static inline void workingset_node_shadows_inc(struct radix_tree_node *node)
{
	node->count += 1U << RADIX_TREE_COUNT_SHIFT;
}

static inline void workingset_node_shadows_dec(struct radix_tree_node *node)
{
	VM_WARN_ON_ONCE(!workingset_node_shadows(node));
	node->count -= 1U << RADIX_TREE_COUNT_SHIFT;
}

/* linux/mm/page_alloc.c */
extern unsigned long totalram_pages;
extern unsigned long totalreserve_pages;
extern unsigned long dirty_balance_reserve;
extern unsigned long nr_free_buffer_pages(void);
extern unsigned long nr_free_pagecache_pages(void);

/* Definition of global_page_state not available yet */
#define nr_free_pages() global_page_state(NR_FREE_PAGES)


/* linux/mm/swap.c */
extern void __lru_cache_add(struct page *);
extern void lru_cache_add(struct page *);
extern void lru_add_page_tail(struct page *page, struct page *page_tail,
			 struct lruvec *lruvec, struct list_head *head);
extern void activate_page(struct page *);
extern void mark_page_accessed(struct page *);
extern void lru_add_drain(void);
extern void lru_add_drain_cpu(int cpu);
extern void lru_add_drain_all(void);
extern void rotate_reclaimable_page(struct page *page);
extern void deactivate_file_page(struct page *page);
extern void deactivate_page(struct page *page);
extern void swap_setup(void);

extern void add_page_to_unevictable_list(struct page *page);

/**
 * lru_cache_add: add a page to the page lists
 * @page: the page to add
 */
static inline void lru_cache_add_anon(struct page *page)
{
	ClearPageActive(page);
	__lru_cache_add(page);
}

static inline void lru_cache_add_file(struct page *page)
{
	ClearPageActive(page);
	__lru_cache_add(page);
}

/* linux/mm/vmscan.c */
extern unsigned long try_to_free_pages(struct zonelist *zonelist, int order,
					gfp_t gfp_mask, nodemask_t *mask);
extern int __isolate_lru_page(struct page *page, isolate_mode_t mode);
extern unsigned long try_to_free_mem_cgroup_pages(struct mem_cgroup *mem,
						  gfp_t gfp_mask, bool noswap);
extern unsigned long mem_cgroup_shrink_node_zone(struct mem_cgroup *mem,
						gfp_t gfp_mask, bool noswap,
						struct zone *zone,
						unsigned long *nr_scanned);
extern unsigned long shrink_all_memory(unsigned long nr_pages);
extern int vm_swappiness;
extern int remove_mapping(struct address_space *mapping, struct page *page);
extern unsigned long vm_total_pages;

#ifdef CONFIG_NUMA
extern int zone_reclaim_mode;
extern int sysctl_min_unmapped_ratio;
extern int sysctl_min_slab_ratio;
extern int zone_reclaim(struct zone *, gfp_t, unsigned int);
#else
#define zone_reclaim_mode 0
static inline int zone_reclaim(struct zone *z, gfp_t mask, unsigned int order)
{
	return 0;
}
#endif

extern int page_evictable(struct page *page);
extern void check_move_unevictable_pages(struct pagevec *pvec);

extern int kswapd_run(int nid);
extern void kswapd_stop(int nid);
#ifdef CONFIG_MEMCG
extern int mem_cgroup_swappiness(struct mem_cgroup *mem);
#else
static inline int mem_cgroup_swappiness(struct mem_cgroup *mem)
{
	return vm_swappiness;
}
#endif
#ifdef CONFIG_MEMCG_SWAP
extern void mem_cgroup_uncharge_swap(swp_entry_t ent);
#else
static inline void mem_cgroup_uncharge_swap(swp_entry_t ent)
{
}
#endif
#ifdef CONFIG_SWAP
/* linux/mm/page_io.c */
extern int swap_readpage(struct page *);
extern int swap_writepage(struct page *page, struct writeback_control *wbc);
extern void end_swap_bio_write(struct bio *bio, int err);
extern int __swap_writepage(struct page *page, struct writeback_control *wbc,
	void (*end_write_func)(struct bio *, int));
extern int swap_set_page_dirty(struct page *page);
extern void end_swap_bio_read(struct bio *bio, int err);

int add_swap_extent(struct swap_info_struct *sis, unsigned long start_page,
		unsigned long nr_pages, sector_t start_block);
int generic_swapfile_activate(struct swap_info_struct *, struct file *,
		sector_t *);

/* linux/mm/swap_state.c */
extern struct backing_dev_info swap_backing_dev_info;
/* One swap address space for each 64M swap space */
#define SWAP_ADDRESS_SPACE_SHIFT	14
#define SWAP_ADDRESS_SPACE_PAGES	(1 << SWAP_ADDRESS_SPACE_SHIFT)
extern struct address_space *swapper_spaces[];
extern bool swap_vma_readahead;
#define swap_address_space(entry)			    \
	(&swapper_spaces[swp_type(entry)][swp_offset(entry) \
		>> SWAP_ADDRESS_SPACE_SHIFT])
extern unsigned long total_swapcache_pages(void);
extern void show_swap_cache_info(void);
extern int add_to_swap(struct page *, struct list_head *list);
extern int add_to_swap_cache(struct page *, swp_entry_t, gfp_t);
extern int __add_to_swap_cache(struct page *page, swp_entry_t entry);
extern void __delete_from_swap_cache(struct page *);
extern void delete_from_swap_cache(struct page *);
extern void free_page_and_swap_cache(struct page *);
extern void free_pages_and_swap_cache(struct page **, int);
extern struct page *lookup_swap_cache(swp_entry_t entry,
				      struct vm_area_struct *vma,
				      unsigned long addr);
extern struct page *read_swap_cache_async(swp_entry_t, gfp_t,
			struct vm_area_struct *vma, unsigned long addr);
extern struct page *__read_swap_cache_async(swp_entry_t, gfp_t,
			struct vm_area_struct *vma, unsigned long addr,
			bool *new_page_allocated);
extern struct page *swapin_readahead(swp_entry_t, gfp_t,
			struct vm_area_struct *vma, unsigned long addr);
extern struct page *do_swap_page_readahead(swp_entry_t fentry, gfp_t gfp_mask,
					   struct vm_fault *vmf);

/* linux/mm/swapfile.c */
extern atomic_long_t nr_swap_pages;
extern long total_swap_pages;
extern atomic_t nr_rotate_swap;
extern bool has_usable_swap(void);

static inline bool swap_use_vma_readahead(void)
{
	return READ_ONCE(swap_vma_readahead) && !atomic_read(&nr_rotate_swap);
}

/* Swap 50% full? Release swapcache more aggressively.. */
static inline bool vm_swap_full(void)
{
	return atomic_long_read(&nr_swap_pages) * 2 < total_swap_pages;
}

static inline long get_nr_swap_pages(void)
{
	return atomic_long_read(&nr_swap_pages);
}

extern void si_swapinfo(struct sysinfo *);
extern swp_entry_t get_swap_page(void);
extern swp_entry_t get_swap_page_of_type(int);
extern int get_swap_pages(int n, swp_entry_t swp_entries[]);
extern int add_swap_count_continuation(swp_entry_t, gfp_t);
extern void swap_shmem_alloc(swp_entry_t);
extern int swap_duplicate(swp_entry_t);
extern int swapcache_prepare(swp_entry_t);
extern void swap_free(swp_entry_t);
extern void swapcache_free(swp_entry_t, struct page *page);
extern void swapcache_free_entries(swp_entry_t *entries, int n);
extern int free_swap_and_cache(swp_entry_t);
extern int swap_type_of(dev_t, sector_t, struct block_device **);
extern unsigned int count_swap_pages(int, int);
extern sector_t map_swap_page(struct page *, struct block_device **);
extern sector_t swapdev_block(int, pgoff_t);
extern int page_swapcount(struct page *);
extern int __swp_swapcount(swp_entry_t entry);
extern struct swap_info_struct *page_swap_info(struct page *);
extern struct swap_info_struct *swp_swap_info(swp_entry_t entry);
extern int reuse_swap_page(struct page *);
extern int try_to_free_swap(struct page *);
struct backing_dev_info;
extern int init_swap_address_space(unsigned int type, unsigned long nr_pages);
extern void exit_swap_address_space(unsigned int type);

#ifdef CONFIG_MEMCG
extern void
mem_cgroup_uncharge_swapcache(struct page *page, swp_entry_t ent, bool swapout);
#else
static inline void
mem_cgroup_uncharge_swapcache(struct page *page, swp_entry_t ent, bool swapout)
{
}
#endif

extern int get_swap_slots(int n, swp_entry_t *slots);
extern void swapcache_free_batch(swp_entry_t *entries, int n);

#else /* CONFIG_SWAP */

#define get_nr_swap_pages()			0L
#define total_swap_pages			0L
#define total_swapcache_pages()			0UL
#define vm_swap_full()				0

#define si_swapinfo(val) \
	do { (val)->freeswap = (val)->totalswap = 0; } while (0)
/* only sparc can not include linux/pagemap.h in this file
 * so leave page_cache_release and release_pages undeclared... */
#define free_page_and_swap_cache(page) \
	page_cache_release(page)
#define free_pages_and_swap_cache(pages, nr) \
	release_pages((pages), (nr), false);

static inline void show_swap_cache_info(void)
{
}

#define free_swap_and_cache(e) (is_migration_entry(e) || is_hmm_entry(e))
#define swapcache_prepare(e) (is_migration_entry(e) || is_hmm_entry(e))

static inline int add_swap_count_continuation(swp_entry_t swp, gfp_t gfp_mask)
{
	return 0;
}

static inline void swap_shmem_alloc(swp_entry_t swp)
{
}

static inline int swap_duplicate(swp_entry_t swp)
{
	return 0;
}

static inline void swap_free(swp_entry_t swp)
{
}

static inline void swapcache_free(swp_entry_t swp, struct page *page)
{
}

static inline struct page *swapin_readahead(swp_entry_t swp, gfp_t gfp_mask,
			struct vm_area_struct *vma, unsigned long addr)
{
	return NULL;
}

static inline bool swap_use_vma_readahead(void)
{
	return false;
}

static inline struct page *do_swap_page_readahead(swp_entry_t fentry,
				gfp_t gfp_mask, struct vm_fault *vmf)
{
	return NULL;
}

static inline int swap_writepage(struct page *p, struct writeback_control *wbc)
{
	return 0;
}

static inline struct page *lookup_swap_cache(swp_entry_t swp,
					     struct vm_area_struct *vma,
					     unsigned long addr)
{
	return NULL;
}

static inline int add_to_swap(struct page *page, struct list_head *list)
{
	return 0;
}

static inline int add_to_swap_cache(struct page *page, swp_entry_t entry,
							gfp_t gfp_mask)
{
	return -1;
}

static inline void __delete_from_swap_cache(struct page *page)
{
}

static inline void delete_from_swap_cache(struct page *page)
{
}

static inline int page_swapcount(struct page *page)
{
	return 0;
}

static inline int __swp_swapcount(swp_entry_t entry)
{
	return 0;
}

#define reuse_swap_page(page)	(page_mapcount(page) == 1)

static inline int try_to_free_swap(struct page *page)
{
	return 0;
}

static inline swp_entry_t get_swap_page(void)
{
	swp_entry_t entry;
	entry.val = 0;
	return entry;
}

static inline void
mem_cgroup_uncharge_swapcache(struct page *page, swp_entry_t ent)
{
}

#endif /* CONFIG_SWAP */
#endif /* __KERNEL__*/
#endif /* _LINUX_SWAP_H */
