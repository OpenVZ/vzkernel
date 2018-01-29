/*
 *  include/linux/virtinfo.h
 *
 *  Copyright (c) 2001–2018 Virtuozzo International GmbH.  All rights reserved.
 *
 */

#ifndef __LINUX_VIRTINFO_H
#define __LINUX_VIRTINFO_H

struct sysinfo;
struct ve_struct;

struct meminfo {
        struct sysinfo *si;
        struct ve_struct *ve;	/* for debug only */
        unsigned long pages[NR_LRU_LISTS];
        unsigned long cached, dirty_pages, writeback_pages, shmem;
        unsigned long slab_reclaimable, slab_unreclaimable;
};

#endif /* __LINUX_VIRTINFO_H */
