/*
 *  include/linux/ploop/ploop.h
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef _LINUX_PLOOP_H_
#define _LINUX_PLOOP_H_

#include <linux/rbtree.h>
#include <linux/timer.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/interrupt.h>
#include <linux/slab.h>

#include "ploop_if.h"
#include "compat.h"

#define PLOOP_NAME_SIZE		64
#define PLOOP_MAX_FORMATS	32
#define PLOOP_DEVICE_MAJOR	182
#define PLOOP_DEVICE_RANGE	(1UL << MINORBITS)
#define PLOOP_PART_SHIFT	4
#define PLOOP_PART_MAX		(1UL << PLOOP_PART_SHIFT)

/* 1. fastpath_reqs is subtracted because they don't consume preq-s
 * 2. typically, entry_qlen and bio_qlen are close to zero */
#define PLOOP_CONGESTED(plo)    (plo->entry_qlen + plo->active_reqs - \
				 plo->fastpath_reqs + plo->bio_qlen)
/* 32 bits for virtual block. Enough. */
typedef u32	cluster_t;
typedef u32	iblock_t;

struct ploop_request;
struct ploop_delta;

enum {
	PLOOP_S_RUNNING,	/* Device is active */
	PLOOP_S_ATTENTION,	/* Device is processing a barrier, everything
				 * is queued to be totally serialized */
	PLOOP_S_EXITING,	/* Exiting */
	PLOOP_S_ABORT,		/* Device is aborted due to unrecoverable
				 * error. Reads are still allowed. */
	PLOOP_S_SYNC,		/* Unplug was requested */
	PLOOP_S_CHANGED,	/* Media changed */
	PLOOP_S_WRITE_CONG,	/* Write direction was congested */
	PLOOP_S_READ_CONG,	/* Read direction was congested */
	PLOOP_S_TRACK,		/* Write tracker is ON */
	PLOOP_S_TRACK_ABORT,	/* Write tracker is aborted */
	PLOOP_S_ENOSPC_EVENT,	/* ENOSPC event happened but but was not
				 * consumed by userspace yet */
	PLOOP_S_CONGESTED,	/* Too many bios submitted to us */
	PLOOP_S_NO_FALLOC_DISCARD, /* Unable to handle discard requests by fallocate */
	PLOOP_S_DISCARD,	/* ploop is ready to handle discard request */
	PLOOP_S_DISCARD_LOADED,	/* A discard request was handled and
				   free blocks loaded */
	PLOOP_S_LOCKED,	        /* ploop is locked by userspace
				   (for minor mgmt only) */
	PLOOP_S_ONCE,	        /* An event (e.g. printk once) happened */
	PLOOP_S_PUSH_BACKUP,	/* Push_backup is in progress */
	PLOOP_S_NULLIFY,	/* Nullifying BAT is in progress */
};

enum {
	PLOOP_F_NORMAL,		/* Default: not yet freezed or unfrozen */
	PLOOP_F_FROZEN,		/* Frozen PLOOP_IOC_FREEZE */
	PLOOP_F_THAWING,	/* thaw_bdev is in progress */
};

struct ploop_snapdata
{
	/* top_delta file reopened read-only. */
	struct file		*file;
};



struct ploop_file
{
	struct list_head	list;

	loff_t		vpos;	/* Position of this chunk in virtual map */
	loff_t		start;	/* Start of data in this file, usually 0 */
	loff_t		length;	/* Length of data in this file */
	loff_t		limit;	/* Maximal size of this file. If it is
				 * exceeded we must switch to the next chunk
				 */
	struct file		*file;	/* File */
	struct address_space	*mapping;
	struct inode		*inode;
	struct extent_map_tree	*em_tree;
	struct block_device	*bdev;
	int flags; /* file flags */
};

/* Real functions are hidden deeply. :-)
 *
 * This struct describes how we do real IO on particular backing file.
 */

enum {
	PLOOP_IO_FSYNC_DELAYED,  /* Must f_op->fsync before FLUSH|FUA */
};

struct ploop_io
{
	struct ploop_device	*plo;

	loff_t		       *size_ptr; /* NULL or points to ploop_mapping */
	loff_t			prealloced_size;
	struct ploop_request   *prealloc_preq;  /* preq who does prealloc */
	loff_t			max_size;	/* Infinity */
	int			n_chunks;	/* 1. */
	struct ploop_file	files;		/* Only 1 file is supported */

	iblock_t		alloc_head;

	struct list_head	fsync_queue;
	struct task_struct	*fsync_thread;
	int			fsync_qlen;
	wait_queue_head_t	fsync_waitq;
	struct timer_list	fsync_timer;

	struct ploop_io_ops	*ops;
	unsigned long		io_state;
	u64                     io_count;
};

struct ploop_io_ops
{
	struct list_head	list;
	unsigned int		id;
	char			*name;
	struct module		*owner;

	void		(*unplug)(struct ploop_io *);
	int		(*congested)(struct ploop_io *, int bits);

	/* Allocate new block, return its index in image.
	 * Data must be initialized to zeros and commited to disk.
	 *
	 * This function is slow and it is used only to allocate
	 * index tables.
	 */
	int	(*alloc)(struct ploop_io *, loff_t pos, loff_t len);

	/* These functions must schedule IO from/to disk.
	 * If it returns 1, this means write is not complete and
	 * preq is added to some internal queue.
	 *
	 * submit() makes IO to already allocated space (preq->iblock)
	 * and must fail when writing to unallocated area.
	 *
	 * submit_alloc() assumes that storage is not allocated and allocates
	 * new area in image.
	 */
	void	(*submit)(struct ploop_io *, struct ploop_request *,
			  unsigned long rw,
			  struct bio_list *sbl, iblock_t iblk, unsigned int size);
	int	(*submit_alloc)(struct ploop_io *, struct ploop_request *,
				struct bio_list *, unsigned int, iblock_t);
	void	(*post_submit)(struct ploop_io *, struct ploop_request *);

	int	(*disable_merge)(struct ploop_io * io, sector_t isector, unsigned int len);
	int	(*fastmap)(struct ploop_io * io, struct bio *orig_bio,
			   struct bio * bio, sector_t isec);

	void	(*read_page)(struct ploop_io * io, struct ploop_request * preq,
			     struct page * page, sector_t sec);
	void	(*write_page)(struct ploop_io * io, struct ploop_request * preq,
			      struct page * page, sector_t sec, unsigned long rw);


	int	(*sync_read)(struct ploop_io * io, struct page * page,
			     unsigned int len, unsigned int off, sector_t sec);
	int	(*sync_write)(struct ploop_io * io, struct page * page,
			      unsigned int len, unsigned int off, sector_t sec);
	int	(*sync_read_many)(struct ploop_io *io, struct page *pages[],
				  unsigned int nr_pages, sector_t sec);

	int	(*init)(struct ploop_io * io);
	void	(*destroy)(struct ploop_io * io);
	int	(*open)(struct ploop_io * io);
	int	(*sync)(struct ploop_io * io);
	int	(*stop)(struct ploop_io * io);
	int	(*prepare_snapshot)(struct ploop_io *, struct ploop_snapdata *);
	int	(*complete_snapshot)(struct ploop_io *, struct ploop_snapdata *);
	int	(*io_prepare_merge)(struct ploop_io *, struct ploop_snapdata *);
	int	(*start_merge)(struct ploop_io *, struct ploop_snapdata *);
	int	(*truncate)(struct ploop_io *, struct file *, __u32 alloc_head);
	void	(*queue_settings)(struct ploop_io *, struct request_queue *q);

	void	(*issue_flush)(struct ploop_io*, struct ploop_request * preq);

	int	(*dump)(struct ploop_io*);

	loff_t  (*i_size_read)(struct ploop_io*);
	fmode_t (*f_mode)(struct ploop_io*);

	int     (*autodetect)(struct ploop_io * io);
};

static inline loff_t generic_i_size_read(struct ploop_io *io)
{
	BUG_ON(!io->files.file);
	BUG_ON(!io->files.inode);

	return i_size_read(io->files.inode);
}
static inline fmode_t generic_f_mode(struct ploop_io *io)
{
	BUG_ON(!io->files.file);

	return io->files.file->f_mode;
}

enum {
	PLOOP_MAP_IDENTICAL,
	PLOOP_MAP_DEAD,
};

#define PLOOP_LRU_BUFFER	8

struct ploop_map
{
	struct ploop_device	*plo;
	struct list_head	delta_list;

	struct rb_root		rb_root;
	unsigned long		flags;
	unsigned long		last_activity;

	unsigned int		pages;
	unsigned int		max_index;

	struct map_node		*lru_buffer[PLOOP_LRU_BUFFER];
	unsigned int		lru_buffer_ptr;

	wait_queue_head_t	destroy_waitq;
};

#define PLOOP_FMT_CAP_DELTA	1
#define PLOOP_FMT_CAP_WRITABLE	2
#define PLOOP_FMT_CAP_IDENTICAL	4

struct ploop_delta_ops
{
	struct list_head	list;
	unsigned int		id;
	char			*name;
	struct module		*owner;

	unsigned int		capability;

	/* Return location of index page */
	int		(*map_index)(struct ploop_delta *, unsigned long index,
				     sector_t *sec);
	void		(*read_index)(struct ploop_delta *, struct ploop_request * preq,
				      struct page * page, sector_t sec);

	/* Allocate new block in delta and write request there.
	 * If request does not cover whole block, this function
	 * must pad with zeros
	 */
	void		(*allocate)(struct ploop_delta *, struct ploop_request *,
				    struct bio_list *sbl, unsigned int size);
	void		(*allocate_complete)(struct ploop_delta *, struct ploop_request *);

	int		(*compose)(struct ploop_delta *, int, struct ploop_ctl_chunk *);
	int		(*open)(struct ploop_delta *);
	void		(*destroy)(struct ploop_delta *);
	int		(*start)(struct ploop_delta *);
	int		(*stop)(struct ploop_delta *);
	int		(*refresh)(struct ploop_delta *);
	int		(*sync)(struct ploop_delta *);
	int		(*prepare_snapshot)(struct ploop_delta *, struct ploop_snapdata *);
	int		(*complete_snapshot)(struct ploop_delta *, struct ploop_snapdata *);
	int		(*fmt_prepare_merge)(struct ploop_delta *, struct ploop_snapdata *);
	int		(*start_merge)(struct ploop_delta *, struct ploop_snapdata *);
	int		(*replace_delta)(struct ploop_delta *);
	int		(*truncate)(struct ploop_delta *, struct file *, __u32 alloc_head);
	int		(*prepare_grow)(struct ploop_delta *, u64 *new_size, int *reloc);
	int		(*complete_grow)(struct ploop_delta *, u64 new_size);
	void		(*add_free_blk)(struct ploop_delta *, struct ploop_request *);
	int		(*dump_bat)(struct ploop_delta *delta, u32 start_cluster,
				    u32 end_cluster, u32 __user *to_addr);
};

/* Virtual image. */
struct ploop_delta
{
	struct list_head	list;

	int			level;		/* Level of delta. 0 is base image */
	unsigned int		cluster_log;	/* In 512=1<<9 byte sectors */
	unsigned int		flags;

	struct ploop_device	*plo;

	struct ploop_io		io;

	void			*priv;

	struct ploop_delta_ops	*ops;

	struct kobject		kobj;

	u64			max_delta_size; /* in sectors */

	void			*holes_bitmap;
};

struct ploop_tunable
{
	int	max_requests;
	int	batch_entry_qlen;
	int	batch_entry_delay;
	int	fsync_max;
	int	fsync_delay;
	int	min_map_pages;
	int	max_map_inactivity;
	int	congestion_high_watermark;
	int	congestion_low_watermark;
	int	max_active_requests;
	int	push_backup_timeout; /* in seconds */
	unsigned int pass_flushes : 1, pass_fuas : 1,
		     congestion_detection : 1,
		     check_zeros : 1,
		     disable_root_threshold : 1,
		     disable_user_threshold : 1,
		     trusted : 1;
};

#define DEFAULT_PLOOP_MAXRQ 256
#define DEFAULT_PLOOP_BATCH_ENTRY_QLEN 32

#define DEFAULT_PLOOP_TUNE \
(struct ploop_tunable) { \
.max_requests = DEFAULT_PLOOP_MAXRQ, \
.batch_entry_qlen = 32, \
.batch_entry_delay = HZ/20, \
.fsync_max = DEFAULT_PLOOP_BATCH_ENTRY_QLEN, \
.fsync_delay = HZ/10, \
.min_map_pages = 32, \
.max_map_inactivity = 10*HZ, \
.congestion_high_watermark = 3*DEFAULT_PLOOP_MAXRQ/4, \
.congestion_low_watermark = DEFAULT_PLOOP_MAXRQ/2, \
.pass_flushes = 1, \
.pass_fuas = 1, \
.check_zeros = 1, \
.max_active_requests = DEFAULT_PLOOP_BATCH_ENTRY_QLEN / 2, \
.push_backup_timeout = 42, }

struct ploop_stats
{
#define __DO(_at)	__u32	_at;
#include "ploop_stat.h"
#undef __DO
};

struct ploop_freeblks_desc;
struct ploop_pushbackup_desc;

struct ploop_device
{
	unsigned long		state;
	spinlock_t		lock;

	struct list_head	free_list;
	struct list_head	entry_queue;
	int			entry_qlen;
	int			read_sync_reqs;
	int			free_qlen; /* len of free_list */
	int			free_qmax; /* max len of free_list */
	int			blockable_reqs; /* depends on userspace tool */
	int			blocked_bios; /* depends on userspace tool */

	struct bio		*bio_head;
	struct bio		*bio_tail;
	struct bio		*bio_sync;
	struct bio_list		bio_discard_list;
	int			bio_discard_qlen;
	int			discard_inflight_reqs;
	int			bio_qlen;
	int			bio_total;

	struct rb_root		entry_tree[2];

	struct list_head	ready_queue;

	struct rb_root		lockout_tree;
	struct rb_root		lockout_pb_tree;

	int			cluster_log;
	int			fmt_version;

	int			active_reqs;
	int			fastpath_reqs;
	int			barrier_reqs;

	struct bio		*cached_bio;

	struct timer_list	mitigation_timer;
	struct timer_list	freeze_timer;

	wait_queue_head_t	waitq;
	wait_queue_head_t	req_waitq;
	wait_queue_head_t	freeze_waitq;
	wait_queue_head_t	event_waitq;
	wait_queue_head_t	pending_waitq;

	struct ploop_map	map;
	struct ploop_map	*trans_map;

	struct ploop_tunable	tune;

	int			index;
	struct mutex		ctl_mutex;
	atomic_t		open_count;
	u64			bd_size;
	struct gendisk		*disk;
	struct block_device	*bdev;
	struct request_queue	*queue;
	struct task_struct	*thread;
	struct block_device	*frozen_bdev;
	int			freeze_state;
	struct rb_node		link;

	/* someone who wants to quiesce state-machine waits
	 * here for signal from state-machine saying that
	 * processing came to PLOOP_REQ_BARRIER request */
	struct completion	*quiesce_comp;

	/* state-machine in 'quiesce' state waits here till
	 * someone call ploop_relax() */
	struct completion	relax_comp;

	/* someone who call ploop_relax() waits here to know
	 * that 'relax' really happened and state-machine is
	 * ready for next ploop_quiesce(). This is important
	 * because someone might call ploop_quiesce() immediately
	 * after ploop_relax() succeeded */
	struct completion	relaxed_comp;

	spinlock_t		track_lock;
	struct rb_root		track_tree;
	sector_t		track_end;
	u32			track_cluster;
	u32			track_ptr;

	u32			merge_ptr;

	atomic_t		maintenance_cnt;
	struct completion	maintenance_comp;
	int			maintenance_type;

	u32			grow_start;
	u32			grow_end;
	u32			grow_relocated;
	u64			grow_new_size;

	spinlock_t		dummy_lock;
	struct mutex		sysfs_mutex;
	struct kobject		kobj;
	struct kobject		*pstat_dir;
	struct kobject		*pstate_dir;
	struct kobject		*ptune_dir;

	struct ploop_stats	st;
	char                    cookie[PLOOP_COOKIE_SIZE];

	struct ploop_freeblks_desc *fbd;
	struct ploop_pushbackup_desc *pbd;
	struct block_device *dm_crypt_bdev;

	unsigned long		locking_state; /* plo locked by userspace */
	unsigned int		fast_path_disabled_count;
	unsigned int		discard_disabled_count;
};

enum
{
	PLOOP_REQ_LOCKOUT,	/* This preq is locking overapping requests */
	PLOOP_REQ_PB_LOCKOUT,	/* This preq is locking overlapping WRITEs */
	PLOOP_REQ_SYNC,
	PLOOP_REQ_BARRIER,
	PLOOP_REQ_UNSTABLE,
	PLOOP_REQ_TRACK,
	PLOOP_REQ_SORTED,
	PLOOP_REQ_TRANS,
	PLOOP_REQ_MERGE,
	PLOOP_REQ_RELOC_A,	/* 'A' stands for allocate() */
	PLOOP_REQ_RELOC_S,	/* 'S' stands for submit() */
	PLOOP_REQ_RELOC_N,	/* 'N' stands for "nullify" */
	PLOOP_REQ_ZERO,
	PLOOP_REQ_DISCARD,
	PLOOP_REQ_RSYNC,
	PLOOP_REQ_KAIO_FSYNC,	/*force image fsync by KAIO module */
	PLOOP_REQ_POST_SUBMIT, /* preq needs post_submit processing */
	PLOOP_REQ_PUSH_BACKUP, /* preq was ACKed by userspace push_backup */
	PLOOP_REQ_FSYNC_DONE,  /* fsync_thread() performed f_op->fsync() */
	PLOOP_REQ_ISSUE_FLUSH, /* preq needs ->issue_flush before completing */
	PLOOP_REQ_BLOCKABLE,  /* preq was accounted in plo->blockable_reqs */
};

#define PLOOP_REQ_MERGE_FL (1 << PLOOP_REQ_MERGE)
#define PLOOP_REQ_RELOC_A_FL (1 << PLOOP_REQ_RELOC_A)
#define PLOOP_REQ_RELOC_S_FL (1 << PLOOP_REQ_RELOC_S)
#define PLOOP_REQ_RELOC_N_FL (1 << PLOOP_REQ_RELOC_N)
#define PLOOP_REQ_DISCARD_FL (1 << PLOOP_REQ_DISCARD)
#define PLOOP_REQ_ZERO_FL (1 << PLOOP_REQ_ZERO)

enum
{
	PLOOP_E_ENTRY,		/* Not yet processed */
	PLOOP_E_COMPLETE,	/* Complete. Maybe, with an error */
	PLOOP_E_RELOC_COMPLETE,	/* Reloc complete. Maybe, with an error */
	PLOOP_E_INDEX_READ,	/* Reading an index page */
	PLOOP_E_TRANS_INDEX_READ,/* Reading a trans index page */
	PLOOP_E_DELTA_READ,	/* Write request reads data from previos delta */
	PLOOP_E_DELTA_COPIED,	/* Data from previos delta was bcopy-ied */
	PLOOP_E_TRANS_DELTA_READ,/* Write request reads data from trans delta */
	PLOOP_E_RELOC_DATA_READ,/* Read user data to relocate */
	PLOOP_E_RELOC_NULLIFY,  /* Zeroing given iblock is in progress */
	PLOOP_E_INDEX_DELAY,	/* Index update is blocked by already queued
				 * index update.
				 */
	PLOOP_E_INDEX_WB,	/* Index writeback is in progress */
	PLOOP_E_DATA_WBI,	/* Data writeback is in progress and index
				 * is not updated.
				 */
	PLOOP_E_ZERO_INDEX,	/* Zeroing index of free block; original request
				   can use .submit on completion */
	PLOOP_E_DELTA_ZERO_INDEX,/* the same but for PLOOP_E_DELTA_READ */
	PLOOP_E_FSYNC_PENDED,   /* INDEX_WB needs io->ops->sync() to proceed */
};

#define BIO_BDEV_REUSED	15	/* io_context is stored in bi_bdev */

struct ploop_request
{
	struct list_head	list;	/* List link.
					 * Req can be on
					 * - free list
					 * - entry queue
					 * - ready queue
					 * - delay_list of another request
					 * nowhere
					 */

	struct ploop_device	*plo;

	cluster_t		req_cluster;
	sector_t		req_sector;
	unsigned int		req_size;
	unsigned int		req_rw;
	unsigned int		req_index_update_rw;
	unsigned long		tstamp;
	struct io_context	*ioc;

	struct bio_list		bl;

	struct bio		*aux_bio;

	atomic_t		io_count;

	unsigned long		state;
	unsigned long		eng_state;
	int			error;

	struct map_node		*map;
	struct map_node		*trans_map;

	iblock_t		iblock;

	/* relocation info */
	union {
		struct {
			iblock_t      src_iblock;
			iblock_t      dst_iblock;
		};
		unsigned long	      ppb_state;
	};
	cluster_t		dst_cluster;
	struct rb_node		reloc_link;

	/* State specific information */
	union {
		/* E_INDEX_READ */
		struct {
			struct page	* tpage;
			int		level;
		} ri;

		/* E_INDEX_WB */
		struct {
			struct page	* tpage;
		} wi;
	} sinfo;

	/* List of requests blocked until completion of this request. */
	struct list_head	delay_list;

	/* Link to tree of "blocking requests". Blocking request
	 * is a request which triggers a kind of a change in image format,
	 * which does not allow to proceed requests to the same area.
	 * F.e. when we do not have mapping in delta and request
	 * requires a copy of data block from previous delta,
	 * this request locks all subseqent requests to the same virtual block
	 * until we allocate and initialize block in delta.
	 */
	struct rb_node		lockout_link;
	struct rb_node		lockout_pb_link;

	u32			track_cluster;

	/* # bytes in tail of image file to prealloc on behalf of this preq */
	loff_t			prealloc_size;

	/* if the engine starts operation on particular io, let's finish
	 * the operation on the same io (see io.ops->post_submit) */
	struct ploop_io	       *eng_io;

	struct user_beancounter *preq_ub;
};

static inline struct ploop_delta * ploop_top_delta(struct ploop_device * plo)
{
	return list_empty(&plo->map.delta_list) ? NULL :
		list_first_entry(&plo->map.delta_list,
				 struct ploop_delta, list);
}

static inline struct ploop_delta * map_top_delta(struct ploop_map * map)
{
	return list_first_entry(&map->delta_list, struct ploop_delta, list);
}

static inline unsigned int cluster_size_in_bytes(struct ploop_device *plo)
{
	return 1 << (plo->cluster_log + 9);
}

static inline unsigned int cluster_size_in_sec(struct ploop_device *plo)
{
	return 1 << (plo->cluster_log);
}

void ploop_complete_io_state(struct ploop_request * preq);
void ploop_fail_request(struct ploop_request * preq, int err);
void ploop_preq_drop(struct ploop_device * plo, struct list_head *drop_list);


static inline int ploop_req_delay_fua_possible(struct ploop_request *preq)
{
	return preq->eng_state == PLOOP_E_DATA_WBI;
}

static inline void ploop_set_dm_crypt_bdev(struct block_device *ploop_bdev,
				struct block_device *bdev)
{
	if (MAJOR(ploop_bdev->bd_dev) == PLOOP_DEVICE_MAJOR) {
		struct ploop_device *plo = ploop_bdev->bd_disk->private_data;
		mutex_lock(&plo->ctl_mutex);
		plo->dm_crypt_bdev = bdev;
		mutex_unlock(&plo->ctl_mutex);
	}
}

static inline struct block_device *__ploop_get_dm_crypt_bdev(
	struct ploop_device *plo)
{
	if (plo->dm_crypt_bdev)
		bdgrab(plo->dm_crypt_bdev);

	return plo->dm_crypt_bdev;
}

static inline struct block_device *ploop_get_dm_crypt_bdev(
				struct ploop_device *plo)
{
	struct block_device *ret;

	mutex_lock(&plo->ctl_mutex);
	ret = __ploop_get_dm_crypt_bdev(plo);
	mutex_unlock(&plo->ctl_mutex);
	return ret;
}

static inline void ploop_req_set_error(struct ploop_request * preq, int err)
{
	if (!preq->error) {
		preq->error = err;
		if (!test_bit(PLOOP_S_ABORT, &preq->plo->state)) {
			if (err != -ENOSPC) {
				printk("ploop_set_error=%d on ploop%d\n",
				       err, preq->plo->index);
				return;
			}
			printk("No space left on device! Either free some "
			       "space on disk or abort ploop%d manually.\n",
				preq->plo->index);
		}
	}
}

#define PLOOP_TRACE_ERROR 1
#define PLOOP_TRACE_ERROR_DUMP_STACK_ON 1

#if PLOOP_TRACE_ERROR_DUMP_STACK_ON
#define PLOOP_TRACE_ERROR_DUMP_STACK()	dump_stack();
#else
#define PLOOP_TRACE_ERROR_DUMP_STACK()
#endif

#if PLOOP_TRACE_ERROR
#define PLOOP_REQ_TRACE_ERROR(preq, err)					\
	do {									\
		if ((err)) {							\
			printk("%s() %d ploop%d set error %d\n",		\
			__FUNCTION__, __LINE__, (preq)->plo->index, (int)(err));\
			PLOOP_TRACE_ERROR_DUMP_STACK();				\
		}								\
	} while (0);
#else
#define PLOOP_REQ_TRACE_ERROR(preq, err)
#endif

#define PLOOP_REQ_SET_ERROR(preq, err)			\
	do {						\
		PLOOP_REQ_TRACE_ERROR(preq, err);	\
		ploop_req_set_error(preq, err);		\
	} while (0);

#define PLOOP_FAIL_REQUEST(preq, err)			\
	do {						\
		PLOOP_REQ_TRACE_ERROR(preq, err);	\
		ploop_fail_request(preq, err);		\
	} while (0);

static inline void ploop_prepare_io_request(struct ploop_request * preq)
{
	atomic_set(&preq->io_count, 1);
}

static inline void ploop_complete_io_request(struct ploop_request * preq)
{
	if (atomic_dec_and_test(&preq->io_count))
		ploop_complete_io_state(preq);
}

static inline void ploop_prepare_tracker(struct ploop_request * preq,
					 sector_t sec)
{
	if (unlikely(test_bit(PLOOP_S_TRACK, &preq->plo->state))) {
		BUG_ON(test_bit(PLOOP_REQ_TRACK, &preq->state));
		set_bit(PLOOP_REQ_TRACK, &preq->state);
		preq->track_cluster = sec >> preq->plo->cluster_log;
	}
}

void ploop_tracker_notify(struct ploop_device *, sector_t sec);

static inline void ploop_acc_ff_in_locked(struct ploop_device *plo,
					  unsigned long rw)
{
	if (unlikely(rw & REQ_FLUSH))
		plo->st.bio_flush_in++;
	if (unlikely(rw & REQ_FUA))
		plo->st.bio_fua_in++;
}
static inline void ploop_acc_ff_in(struct ploop_device *plo,
				   unsigned long rw)
{
	if (unlikely(rw & REQ_FLUSH)) {
		unsigned long flags;
		spin_lock_irqsave(&plo->lock, flags);
		plo->st.bio_flush_in++;
		spin_unlock_irqrestore(&plo->lock, flags);
	}
	if (unlikely(rw & REQ_FUA)) {
		unsigned long flags;
		spin_lock_irqsave(&plo->lock, flags);
		plo->st.bio_fua_in++;
		spin_unlock_irqrestore(&plo->lock, flags);
	}
}
static inline void ploop_acc_ff_out_locked(struct ploop_device *plo,
					   unsigned long rw)
{
	if (unlikely(rw & REQ_FLUSH))
		plo->st.bio_flush_out++;
	if (unlikely(rw & REQ_FUA))
		plo->st.bio_fua_out++;
}
static inline void ploop_acc_ff_out(struct ploop_device *plo,
				    unsigned long rw)
{
	if (unlikely(rw & REQ_FLUSH)) {
		unsigned long flags;
		spin_lock_irqsave(&plo->lock, flags);
		plo->st.bio_flush_out++;
		spin_unlock_irqrestore(&plo->lock, flags);
	}
	if (unlikely(rw & REQ_FUA)) {
		unsigned long flags;
		spin_lock_irqsave(&plo->lock, flags);
		plo->st.bio_fua_out++;
		spin_unlock_irqrestore(&plo->lock, flags);
	}
}
static inline void ploop_acc_flush_skip_locked(struct ploop_device *plo,
					       unsigned long rw)
{
	if (unlikely(rw & REQ_FLUSH))
		plo->st.bio_flush_skip++;
}

static inline void ploop_entry_add(struct ploop_device * plo, struct ploop_request * preq)
{
	list_add_tail(&preq->list, &plo->entry_queue);
	plo->entry_qlen++;
	if (test_bit(PLOOP_REQ_SYNC, &preq->state) && (!(preq->req_rw & WRITE) || (preq->req_rw & (REQ_FLUSH|REQ_FUA)))) {
		__set_bit(PLOOP_REQ_RSYNC, &preq->state);
		plo->read_sync_reqs++;
	}
}

static inline void ploop_entry_qlen_dec(struct ploop_request * preq)
{
	preq->plo->entry_qlen--;
	if (test_bit(PLOOP_REQ_RSYNC, &preq->state)) {
		__clear_bit(PLOOP_REQ_RSYNC, &preq->state);
		preq->plo->read_sync_reqs--;
	}
}

static inline int ploop_map_log(struct ploop_device *plo)
{
	switch (plo->fmt_version) {
	case PLOOP_FMT_V1:
		return plo->cluster_log;
	case PLOOP_FMT_V2:
		return 0;
	default:
		BUG();
	}

	return -1;
}

static inline bool whole_block(struct ploop_device * plo, struct ploop_request *preq)
{
	if (preq->req_size != cluster_size_in_sec(plo))
		return 0;
	return !(preq->req_sector & (cluster_size_in_sec(plo) - 1));
}

static inline void ploop_set_discard_limits(struct ploop_device *plo)
{
	struct request_queue *q = plo->queue;
	/*
	 * In PLOOP_FMT_PLOOP1 format, neighbouring virtual clusters
	 * are not neighbours on backed device, so we expect block
	 * subsystem splits discards in single-cluster requests.
	 */
	q->limits.discard_granularity = cluster_size_in_bytes(plo);
	q->limits.max_discard_sectors = (1 << plo->cluster_log);
}
struct map_node;

int ploop_fastmap(struct ploop_map * map, cluster_t block, iblock_t *result);
void ploop_update_map(struct ploop_map * map, int level, cluster_t block, iblock_t iblk);
void ploop_update_map_hdr(struct ploop_map * map, u8 *hdr, int hdr_size);
void map_release(struct map_node * m);
int ploop_find_map(struct ploop_map * map, struct ploop_request * preq);
int ploop_find_trans_map(struct ploop_map * map, struct ploop_request * preq);
int ploop_check_map(struct ploop_map * map, struct ploop_request * preq);
cluster_t map_get_mn_end(struct map_node *m);
int map_get_index(struct ploop_request * preq, cluster_t block, iblock_t *result);
int trans_map_get_index(struct ploop_request * preq, cluster_t block, iblock_t *result);
int map_index_fault(struct ploop_request * preq);
void map_read_complete(struct ploop_request * preq);
int map_index(struct ploop_delta * delta, struct ploop_request * preq, unsigned long *sec);
struct ploop_delta * map_writable_delta(struct ploop_request * preq);
void map_init(struct ploop_device *, struct ploop_map * map);
void ploop_map_start(struct ploop_map * map, u64 bd_size);
void ploop_map_destroy(struct ploop_map * map);
void ploop_map_remove_delta(struct ploop_map * map, int level);
void ploop_index_wb_proceed(struct ploop_request * preq);
void ploop_index_update(struct ploop_request * preq);
void ploop_index_wb_complete(struct ploop_request * preq);
int __init ploop_map_init(void);
void ploop_map_exit(void);
int ploop_map_dump_bat(struct ploop_delta *delta, u32 start_cluster,
			u32 end_cluster, u32 __user *to_addr);
void ploop_add_req_to_fsync_queue(struct ploop_request * preq);
int ploop_submit_alloc(struct ploop_delta *delta, struct ploop_request *preq,
		       struct bio_list *sbl, unsigned int size, iblock_t iblk);

void ploop_quiesce(struct ploop_device * plo);
void ploop_relax(struct ploop_device * plo);

void track_init(struct ploop_device * plo);
int ploop_tracker_destroy(struct ploop_device *plo, int force);
int ploop_tracker_stop(struct ploop_device * plo, int force);
int ploop_tracker_read(struct ploop_device * plo, unsigned long arg);
int ploop_tracker_setpos(struct ploop_device * plo, unsigned long arg);
int ploop_tracker_init(struct ploop_device * plo, unsigned long arg);


int ploop_add_lockout(struct ploop_request *preq, int try);
void del_lockout(struct ploop_request *preq);

int ploop_io_init(struct ploop_delta * delta, int nchunks, struct ploop_ctl_chunk * pc);
int ploop_io_open(struct ploop_io *);
void ploop_io_destroy(struct ploop_io * io);
void ploop_io_report_fn(struct file * file, char * msg);

int ploop_register_format(struct ploop_delta_ops * ops);
int ploop_register_io(struct ploop_io_ops * ops);
void ploop_unregister_format(struct ploop_delta_ops * ops);
void ploop_unregister_io(struct ploop_io_ops * ops);
void ploop_format_put(struct ploop_delta_ops * ops);

extern struct kobj_type ploop_delta_ktype;
void ploop_sysfs_init(struct ploop_device * plo);
void ploop_sysfs_uninit(struct ploop_device * plo);

void ploop_queue_zero_request(struct ploop_device *plo, struct ploop_request *orig_preq, cluster_t clu);

int ploop_maintenance_wait(struct ploop_device * plo);

extern int max_map_pages;
extern int kaio_backed_ext4;

extern void ploop_msg_once(struct ploop_device *plo, const char *, ...)
	__attribute__ ((format (printf, 2, 3)));

/* Define PLOOP_TRACE to get full trace of ploop state machine.
 */
#undef PLOOP_TRACE


#ifdef PLOOP_TRACE
#define __TRACE(a...)  do { printk(a); } while (0)
#else
#define __TRACE(a...)  do { } while (0)
#endif

#endif /* _LINUX_PLOOP_H_ */
