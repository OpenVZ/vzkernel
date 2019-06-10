/*
 *  include/linux/virtinfo.h
 *
 *  Copyright (c) 2005-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef __LINUX_VIRTINFO_H
#define __LINUX_VIRTINFO_H

#include <linux/kernel.h>
#include <linux/page-flags.h>
#include <linux/notifier.h>
#include <linux/mmzone.h>

struct vnotifier_block
{
	int (*notifier_call)(struct vnotifier_block *self,
			unsigned long, void *, int);
	struct vnotifier_block *next;
	int priority;
};

extern struct semaphore virtinfo_sem;
void __virtinfo_notifier_register(int type, struct vnotifier_block *nb);
void virtinfo_notifier_register(int type, struct vnotifier_block *nb);
void virtinfo_notifier_unregister(int type, struct vnotifier_block *nb);
int virtinfo_notifier_call(int type, unsigned long n, void *data);
int virtinfo_notifier_call_irq(int type, unsigned long n, void *data);

struct page_info {
	unsigned long nr_file_dirty;
	unsigned long nr_writeback;
	unsigned long nr_anon_pages;
	unsigned long nr_file_mapped;
	unsigned long nr_slab_rec;
	unsigned long nr_slab_unrec;
	unsigned long nr_pagetable;
	unsigned long nr_unstable_nfs;
	unsigned long nr_bounce;
	unsigned long nr_writeback_temp;
};

struct sysinfo;
struct user_beancounter;

struct meminfo {
	struct sysinfo *si;
	struct user_beancounter *ub;
	unsigned long meminfo_val;
	unsigned long pages[NR_LRU_LISTS];
	unsigned long cached, dirty_pages, writeback_pages, locked, shmem;
	unsigned long slab_reclaimable, slab_unreclaimable;
	unsigned long available;
};

struct seq_file;

int meminfo_proc_show_ub(struct seq_file *m, void *v,
		struct user_beancounter *ub, unsigned long meminfo_val);

#define VIRTINFO_MEMINFO	0
#define VIRTINFO_SYSINFO	2
#define VIRTINFO_VMSTAT		3
#define VIRTINFO_OOMKILL	4

#define VIRTINFO_IO_ACCOUNT	0
#define VIRTINFO_IO_PREPARE	1
#define VIRTINFO_IO_JOURNAL	2
#define VIRTINFO_IO_READAHEAD	3
#define VIRTINFO_IO_CONGESTION	4
#define VIRTINFO_IO_OP_ACCOUNT	5
#define VIRTINFO_IO_BALANCE_DIRTY	6
#define VIRTINFO_IO_FUSE_REQ	7

enum virt_info_types {
	VITYPE_GENERAL,
	VITYPE_QUOTA,
	VITYPE_IO,

	VIRT_TYPES
};

#endif /* __LINUX_VIRTINFO_H */
