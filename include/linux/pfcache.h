#ifndef LINUX_PFCACHE_H
#define LINUX_PFCACHE_H

/**
 * include/linux/pfcache
 *
 * Parallels File Cache
 *
 * Copyright (C) 2012. Parallels IP Holdings GmbH.
 * All rights reserved.
 *
 * Author: Konstantin Khlebnikov
 *
 */

#include <linux/types.h>
#include <linux/ioctl.h>

#define FS_IOC_PFCACHE_OPEN	_IO('f', 50)
#define FS_IOC_PFCACHE_CLOSE	_IO('f', 51)
#define FS_IOC_PFCACHE_DUMP	_IO('f', 52)

#define PFCACHE_CSUM_SIZE	20	/* SHA-1 (FIPS 180-1) */

#define PFCACHE_XATTR_NAME	"trusted.pfcache"

/* extendable FS_IOC_PFCACHE_DUMP argument, must be 32/64-bits compatible */
struct pfcache_dump_request {
	__u32	header_size;		/* this struct size */
	__u32	buffer_size;		/* tail buffer size */
	__u64	filter;			/* filter flags */
	__u64	payload;		/* payload flags */
	__u32	offset;			/* skip inodes, after filtering */
	__u8	csum_filter[PFCACHE_CSUM_SIZE];
	/* -- add fields above this line -- */
	__u8	buffer[0];
};

/* to check new fields presence */
#define PFCACHE_DUMP_HAS(req, field)	((req)->header_size >= \
		offsetof(typeof(*(req)), field) + sizeof((req)->field))

/* filter bits, what to skip */
#define PFCACHE_FILTER_WITH_CSUM	0x0001ll
#define PFCACHE_FILTER_WITHOUT_CSUM	0x0002ll
#define PFCACHE_FILTER_WITH_PEER	0x0004ll
#define PFCACHE_FILTER_WITHOUT_PEER	0x0008ll
#define PFCACHE_FILTER_COMPARE_CSUM	0x0010ll /* check csum_filter */
#define PFCACHE_FILTER_MASK		0x001Fll /* all known filters */

/* payload bits, what to dump */
#define PFCACHE_PAYLOAD_CSUM		0x0001ll /* u8[EXT4_DATA_CSUM_SIZE] */
#define PFCACHE_PAYLOAD_FHANDLE		0x0002ll /* struct file_handle */
#define PFCACHE_PAYLOAD_STATE		0x0004ll /* u64 filter-state */
#define PFCACHE_PAYLOAD_FSIZE		0x0008ll /* u64 file size */
#define PFCACHE_PAYLOAD_PAGES		0x0010ll /* u64 page-cache size */
#define PFCACHE_PAYLOAD_MASK		0x001Fll /* all known payloads */

/* MAX_HANDLE_SZ */
#define PFCACHE_FHANDLE_MAX		256

/* see fs/fhandle.c */
#define PFCACHE_FHANDLE_SIZE(ptr)	(*(__u32*)(ptr) + sizeof(__u32) * 2)

/* all payload fields aligned to 8 bytes boundary */
#define PFCACHE_PAYLOAD_MAX_SIZE			\
	(ALIGN(PFCACHE_CSUM_SIZE, sizeof(__u64)) +	\
	 PFCACHE_FHANDLE_MAX +				\
	 sizeof(__u64) * 3)

#endif /* LINUX_PFCACHE_H */
