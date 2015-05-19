#ifndef __PLOOP_IF_H__
#define __PLOOP_IF_H__ 1

#include <linux/ioctl.h>

/* This interface mixes data relevant to delta layer and io layer
 * to one request. It is too simplistic.
 *
 * But this allows to create the whole delta atomically and does
 * not require maintenance of incomplete composition state inside device.
 */

/* Formats of deltas. */

#define PLOOP_FMT_RAW		1
#define PLOOP_FMT_PLOOP1	2

/* PLOOP_FMT_PLOOP1 subversions */
enum {
	PLOOP_FMT_UNDEFINED = 0,
	PLOOP_FMT_V1,
	PLOOP_FMT_V2,
};

/* Delta flags. */
#define PLOOP_FMT_RDONLY	1
#define PLOOP_FMT_FLAGS		1

#define PLOOP_FLAG_FS_SYNC	0x10000000

#define PLOOP_FMT_PREALLOCATED	2

#define PLOOP_FLAG_COOKIE	4
#define PLOOP_COOKIE_SIZE	64

#define PLOOP_FLAG_CLUBLKS	8

/* IO types. */

#define PLOOP_IO_AUTO		0
#define PLOOP_IO_DIRECT		1
#define PLOOP_IO_NFS		2
#define PLOOP_IO_RESERVED	3	/* reserved, do not use */
#define PLOOP_IO_KAIO		4

/*
 * # slots to skip in the very first page of L2 table
 * (they are reserved for format-specific header)
 * Assumptions:
 * 1) sizeof(map_index_t) == sizeof(u32)
 * 2) PLOOP_MAP_OFFSET == sizeof(struct ploop_pvd_header) / sizeof(u32)
 */
#define PLOOP_MAP_OFFSET	16

/*
 * in-kernel ploop implementation assumes that L2[index] can never be
 * equal to this value (this is guaranteed by limitation of bdsize).
 * So, in-kernel ploop may encode L2[index] == 0 by this value and keep
 * zero value as special one meaning "iblock is not allocated yet for
 * given index". User-space may use this value to denote uninitialized
 * slots of L2[] table.
 */
#define PLOOP_ZERO_INDEX	0xFFFFFFFFU

struct ploop_ctl_chunk
{
	__s32	pctl_fd;	/* FD of backing file */
	__u32	pctl_type;	/* IO engine */
	__u32	pctl_flags;	/* Some modifiers, undefined now */
	__u32	pctl_offset;	/* Starting cluster of this chunk in image */

	__u64	pctl_start;	/* Position of data in file.  */
	__u64	pctl_len;	/* Length of data area in file. */
} __attribute__ ((aligned (8)));

struct ploop_ctl
{
	/* Description of delta format */
	__u32	pctl_format;
	__u32	pctl_flags;
	__u32	pctl_cluster_log;
	__u32	pctl_size;

	/* Description of backing files. */
	__u16	pctl_chunks;
	__u8	pctl_level;
	__u8	__mbz1;
	__u32	__mbz2;
	struct ploop_ctl_chunk chunks[0];
} __attribute__ ((aligned (8)));

/* helper for ADD_DELTA */
struct ploop_ctl_delta {
	struct ploop_ctl c;
	struct ploop_ctl_chunk f;
};

struct ploop_truncate_ctl
{
	int	fd;
	__u32	alloc_head;
	__u8	level;
	__u8	__mbz1;
	__u16	__mbz2;
} __attribute__ ((aligned (8)));


/*
 * Before relocation l2[req_cluster] == old_iblk.
 * Then user-space decided to relocate old_iblk to new_iblk.
 * After relocation is done, we need kernel help to update map_node
 * structure for req_cluster (if present). When kernel
 * accomplished this, user-space may safely nullify old_iblk.
 */
struct reloc_map
{
	__u32 req_cluster;
	__u32 iblk;
} __attribute__ ((aligned (8)));

struct ploop_index_update_ctl
{
	__u32	n_maps;
	__u8	level;
	__u8	__mbz1;
	__u16	__mbz2;
	struct reloc_map rmap[0];
} __attribute__ ((aligned (8)));

/*
 * user-space found out that some blocks are not used
 * and reports the list of them to kernel. Onwards,
 * kernel will use them as free blocks instead of
 * alloc_head++ technique.
 */
struct ploop_freeblks_ctl_extent
{
	__u32 clu;
	__u32 iblk;
	__u32 len;

} __attribute__ ((aligned (8)));

struct ploop_freeblks_ctl
{
	__u32	n_extents;
	__u32	alloc_head; /* out */
	__u8	level;
	__u8	__mbz1;
	__u16	__mbz2;
	struct ploop_freeblks_ctl_extent extents[0];
} __attribute__ ((aligned (8)));

struct ploop_relocblks_ctl_extent
{
	__u32 clu;
	__u32 iblk;
	__u32 len;
	__u32 free; /* this extent is also present in freemap */
} __attribute__ ((aligned (8)));

struct ploop_relocblks_ctl
{
	__u32	n_extents;
	__u32	n_scanned;  /* # bytes scanned */
	__u32	alloc_head; /* in, for sanity check */
	__u8	level;
	__u8	__mbz1;
	__u16	__mbz2;
	struct ploop_relocblks_ctl_extent extents[0];
} __attribute__ ((aligned (8)));

struct ploop_balloon_ctl
{
	__u32	mntn_type;     /* see enum above */
	__u32	alloc_head;    /* freezed alloc_head */
	__u8	level;	       /* top-level of ploop device */
	__u8	inflate;       /* inflate/truncate flag */
	__u8	keep_intact;   /* keep mntn state intact */
	__u8	__mbz;
} __attribute__ ((aligned (8)));

struct ploop_getdevice_ctl
{
	__u32	minor;
	__u32	__mbz1;
} __attribute__ ((aligned (8)));

/* maintenance types */
enum {
	PLOOP_MNTN_OFF = 0,  /* no maintenance is in progress */
	PLOOP_MNTN_BALLOON,  /* user-space started ballooning */
	PLOOP_MNTN_FBLOADED, /* list of free-blocks loaded */
	PLOOP_MNTN_SNAPSHOT, /* bdev is freezed due to snapshot */

	PLOOP_MNTN_TRACK,    /* tracking is in progress */
	PLOOP_MNTN_DISCARD,  /* ready to handle discard requests */

	PLOOP_MNTN_NOFAST = 256,
	/* all types below requires fast-path disabled ! */

	PLOOP_MNTN_MERGE,    /* merge is in progress */
	PLOOP_MNTN_GROW,     /* grow is in progress */
	PLOOP_MNTN_RELOC,    /* relocation is in progress */
};

/*
 * This define should be in sync with enum above.
 * NB: PLOOP_MNTN_TRACK is handled separately because
 * READ-requests may go fast-path even while tracking.
 */
#define FAST_PATH_DISABLED(t) (t > PLOOP_MNTN_NOFAST)

#define PLOOPCTLTYPE	'P'

/* Add delta. Device must be offline */
#define PLOOP_IOC_ADD_DELTA	_IOW(PLOOPCTLTYPE, 0, struct ploop_ctl)

/* Close images, free all data, return the device to initial state  */
#define PLOOP_IOC_CLEAR		_IO(PLOOPCTLTYPE, 1)

/* Stop/start device. */
#define PLOOP_IOC_STOP		_IO(PLOOPCTLTYPE, 2)
#define PLOOP_IOC_START		_IO(PLOOPCTLTYPE, 3)

/* Make new snapshot on running device */
#define PLOOP_IOC_SNAPSHOT	_IOW(PLOOPCTLTYPE, 4, struct ploop_ctl)

/* Remove delta. Argument is delta level. */
#define PLOOP_IOC_DEL_DELTA	_IOW(PLOOPCTLTYPE, 5, __u32)

struct ploop_track_extent
{
	__u64	start;
	__u64	end;
};

/* Start tracking of top delta image. */
#define PLOOP_IOC_TRACK_INIT	_IOR(PLOOPCTLTYPE, 6, struct ploop_track_extent)

/* Stop of top delta image. It is responsibility of caller
 * to quiesce the device before stopping tracking. The ioctl
 * will fail if tracking was aborted or if not all dirty bits are read.
 */
#define PLOOP_IOC_TRACK_STOP	_IO(PLOOPCTLTYPE, 7)

/* Abort tracker, clear the state */
#define PLOOP_IOC_TRACK_ABORT	_IO(PLOOPCTLTYPE, 8)

/* User -> ploop : transferred up to this position */
#define PLOOP_IOC_TRACK_SETPOS	_IOW(PLOOPCTLTYPE, 9, __u64)

/* ploop -> user: get modified bits */
#define PLOOP_IOC_TRACK_READ	_IOR(PLOOPCTLTYPE, 10, struct ploop_track_extent)

/* sync cacheable state of deltas to disk */
#define PLOOP_IOC_SYNC		_IO(PLOOPCTLTYPE, 11)

/* Merge top delta to lower one and delete it. */
#define PLOOP_IOC_MERGE		_IO(PLOOPCTLTYPE, 12)

/* Replace alive delta with equivalent one. */
#define PLOOP_IOC_REPLACE_DELTA	_IOW(PLOOPCTLTYPE, 13, struct ploop_ctl)

/* Replace alive delta with equivalent one. */
#define PLOOP_IOC_TRUNCATE	_IOW(PLOOPCTLTYPE, 14, struct ploop_truncate_ctl)

/* Update in-core copy of L2 table */
#define PLOOP_IOC_UPDATE_INDEX  _IOW(PLOOPCTLTYPE, 16, struct ploop_index_update_ctl)

/* Increase size of block device */
#define PLOOP_IOC_GROW		_IOW(PLOOPCTLTYPE, 17, struct ploop_ctl)

/* Inquire current state of free block extents */
#define PLOOP_IOC_FBGET		_IOW(PLOOPCTLTYPE, 18, struct ploop_freeblks_ctl)

/* Start balloning or inquire maintenance_type or flush stale BALLON state */
#define PLOOP_IOC_BALLOON	_IOW(PLOOPCTLTYPE, 19, struct ploop_balloon_ctl)

/* Load free blocks to ploop */
#define PLOOP_IOC_FREEBLKS      _IOW(PLOOPCTLTYPE, 20, struct ploop_freeblks_ctl)

/* Load blocks to relocate and initiate relocation process */
#define PLOOP_IOC_RELOCBLKS     _IOW(PLOOPCTLTYPE, 21, struct ploop_relocblks_ctl)

/* Search ploop_device global tree for first unused minor number */
#define PLOOP_IOC_GETDEVICE    _IOW(PLOOPCTLTYPE, 22, struct ploop_getdevice_ctl)

/* Start handling discard requests */
#define PLOOP_IOC_DISCARD_INIT _IO(PLOOPCTLTYPE, 23)
/* Stop handling discard requests */
#define PLOOP_IOC_DISCARD_FINI _IO(PLOOPCTLTYPE, 24)
/* Wait a discard request */
#define PLOOP_IOC_DISCARD_WAIT _IO(PLOOPCTLTYPE, 25)

/* Drop current state of free block extents */
#define PLOOP_IOC_FBDROP	_IO(PLOOPCTLTYPE, 26)

/* Filter extents with sizes less than arg */
#define PLOOP_IOC_FBFILTER	_IOR(PLOOPCTLTYPE, 27, unsigned long)

/* Set maximum size for the top delta . */
#define PLOOP_IOC_MAX_DELTA_SIZE _IOW(PLOOPCTLTYPE, 28, __u64)

/* Events exposed via /sys/block/ploopN/pstate/event */
#define PLOOP_EVENT_ABORTED	1
#define PLOOP_EVENT_STOPPED	2
#define PLOOP_EVENT_ENOSPC	3

#ifdef __KERNEL__

#define PLOOP_INTERNAL_MAGIC	0x284cd32c
struct ploop_xops
{
	__u32		magic;

	int		(*get_extent)(struct inode *inode, sector_t isec,
				      unsigned int nr, sector_t *start,
				      sector_t *psec, int creat);
};

#define PLOOP_IOC_INTERNAL	_IOR(PLOOPCTLTYPE, 15, struct ploop_xops)

#endif

#endif /* __PLOOP_IF_H__ */
