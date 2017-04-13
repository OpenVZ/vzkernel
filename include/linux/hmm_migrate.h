/*
 * Copyright 2013 Red Hat Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Authors: Jérôme Glisse <jglisse@redhat.com>
 */
/*
 * This is heterogeneous memory management (HMM) migration. In a nutshell it
 * provides an alternative to existing migrate code. Migration are done for a
 * range of virtual address space of a proccess. This allow efficient use of
 * DMA engine to perform the actual copy while the struct page migration is
 * handled by HMM code.
 *
 * Another major differences is that allocation of destination memory is under
 * the control of caller of hmm_migrate(), allowing caller to migrate to memory
 * which is not managed by regular mm code (for instance private device memory
 * or reserved memory range).
 *
 * This is intended to help leverage heterogeneous memory on new platform. Each
 * memory having different characteristic (latency, bandwidth, ...). It is also
 * usefull for device driver that want to migrate to their device memory (GPUs
 * are an example of devices which can use this code).
 */
#ifndef _LINUX_HMM_MIGRATE_H
#define _LINUX_HMM_MIGRATE_H

#include <linux/kconfig.h>

#if IS_ENABLED(CONFIG_HMM_MIGRATE)

#include <linux/spinlock.h>
#include <linux/mm_types.h>
#include <linux/highmem.h>
#include <linux/wait.h>
#include <linux/kref.h>
#include <linux/mman.h>
#include <linux/hmm.h>


struct hmm_migrate;


/*
 * While migrating we need to keep track of temporary informations about source
 * or destination page. We store source and destination memory using pfn and as
 * entry in page table like structure. As pfn does not uses all the bits we can
 * take the remaining one as flags (see enum hmm_entry_flags).
 *
 * We define a new type as we do not want migration user to directly access the
 * entry but rather use set of helper functions and macros.
 */

/*
 * HMM_ENTRY_VALID - valid entry
 * HMM_ENTRY_PAGE - entry is pointing to memory back by a struct page
 * HMM_ENTRY_DIRTY - source pte had dirty bit set
 * HMM_ENTRY_ISOLATED - struct page of entry have been isolated from lru list
 * HMM_ENTRY_LOCKED - entry struct page is locked (valid with HMM_ENTRY_PAGE)
 * HMM_ENTRY_MIGRATE - entry can be migrated
 * HMM_ENTRY_READ - source pte had read bit set
 * HMM_ENTRY_WRITE - source pte had write bit set
 */
enum hmm_entry_flags {
	HMM_ENTRY_VALID = 0,
	HMM_ENTRY_PAGE,
	HMM_ENTRY_DIRTY,
	HMM_ENTRY_ISOLATED,
	HMM_ENTRY_LOCKED,
	HMM_ENTRY_MIGRATE,
	HMM_ENTRY_READ,
	HMM_ENTRY_WRITE,
	HMM_ENTRY_MEMCG,
	/* This must be last */
	HMM_ENTRY_PFN_SHIFT
};

#define HMM_ENTRY_FLAG_HELPERS(flag, name)				\
static inline bool hmm_entry_is_##name(gte_t entry)			\
	{ return entry & (1UL << flag); }				\
static inline gte_t hmm_entry_set_##name(gte_t entry)			\
	{ entry |= (1UL << flag); return entry; }			\
static inline gte_t hmm_entry_clear_##name(gte_t entry)			\
	{ entry &= (~(1UL << flag)); return entry; }

HMM_ENTRY_FLAG_HELPERS(HMM_ENTRY_VALID, valid);
HMM_ENTRY_FLAG_HELPERS(HMM_ENTRY_PAGE, page);
HMM_ENTRY_FLAG_HELPERS(HMM_ENTRY_DIRTY, dirty);
HMM_ENTRY_FLAG_HELPERS(HMM_ENTRY_LOCKED, locked);
HMM_ENTRY_FLAG_HELPERS(HMM_ENTRY_MIGRATE, migrate);
HMM_ENTRY_FLAG_HELPERS(HMM_ENTRY_ISOLATED, isolated);
HMM_ENTRY_FLAG_HELPERS(HMM_ENTRY_READ, read);
HMM_ENTRY_FLAG_HELPERS(HMM_ENTRY_WRITE, write);
HMM_ENTRY_FLAG_HELPERS(HMM_ENTRY_MEMCG, memcg);

#define HMM_ENTRY_MIGRATE_MASK ((1UL << HMM_ENTRY_DIRTY) |		\
				(1UL << HMM_ENTRY_LOCKED) |		\
				(1UL << HMM_ENTRY_MIGRATE) |		\
				(1UL << HMM_ENTRY_ISOLATED) |		\
				(1UL << HMM_ENTRY_READ) |		\
				(1UL << HMM_ENTRY_WRITE))

static inline gte_t hmm_entry_from_page(struct page *page)
{
	gte_t entry;

	entry = page_to_pfn(page) << HMM_ENTRY_PFN_SHIFT;
	return hmm_entry_set_valid(hmm_entry_set_page(entry));
}

static inline struct page *hmm_entry_to_page(gte_t entry)
{
	if (!hmm_entry_is_page(entry))
		return NULL;
	return pfn_to_page(entry >> HMM_ENTRY_PFN_SHIFT);
}


/* struct hmm_migrate_ops - HMM migration operations callback
 */
struct hmm_migrate_ops {
	/* copy() - copy memory (by using DMA engine for instance)
	 *
	 * @migrate: pointer to struct hmm_migrate
	 * @vma: virtual memory area struct for the range
	 * Returns: 0 on success, error code otherwise {-ENOMEM, -EIO}
	 *
	 * Called when migrating memory using device DMA engine. Core HMM code
	 * takes care of doing all struct page preparations. Callback only need
	 * to schedule DMA and report successfull copied entry by setting the
	 * HMM_ENTRY_MIGRATE bit on destination gte_t.
	 *
	 * For all successfully copied entry core HMM code will update the CPU
	 * page table accordingly and also properly update struct page for the
	 * source and destination memory. Device driver must also properly set
	 * the dirty bit, if device page table has dirty bit set. This must be
	 * conservative, ie if device does not have dirty bit and could have
	 * written to memory then it must be set unconditionally.
	 *
	 * For fail entry core HMM code will restore CPU pagetable, destination
	 * page must be free through page_free() callback.
	 *
	 * Failures when copying from device umappable memory to regular memory
	 * result in CPU page table being set to invalid entry. CPU access to
	 * such invalid entry trigger SIGBUS for the application.
	 *
	 * Return 0 on success, error value otherwise :
	 * -ENOMEM Not enough memory for performing the operation
	 * -EIO    Some input/output error with the device
	 *
	 * All others return value trigger warning and are transformed to -EIO
	 */
	void (*copy)(struct hmm_migrate *migrate, struct vm_area_struct *vma);

	/* page_alloc() - alloc memory for migration
	 *
	 * @migrate: pointer to struct hmm_migrate
	 * @vma: virtual memory area struct for the range
	 * Returns: number of successfully allocated pages
	 *
	 * Device driver allocate page for destination memory and update the
	 * dst entry accordingly. It must use the src entry array to know if
	 * it must allocate memory or not for given address. The device driver
	 * can also decide to not allocate memory for given page even if the
	 * src entry is valid.
	 *
	 * Return number of successfully allocated pages.
	 */
	void (*page_alloc)(struct hmm_migrate *migrate,
			   struct vm_area_struct *vma);

	/* page_free() - free memory originaly allocated with page_alloc()
	 *
	 * @migrate: pointer to struct hmm_migrate
	 * @start: start address of the range to free
	 * @end: end address of the range to free
	 *
	 * Free unuse source and destination memory. Callback must go through
	 * all source and destination HMM pte and free any of them for which
	 * hmm_entry_none() returns false.
	 *
	 * For regular page (and normal ie not like zero page) call put_page().
	 */
	void (*page_free)(struct hmm_migrate *migrate);
};

/* struct hmm_migrate - per migration structure
 *
 * @list: use for list of active migration of a given mm
 * @hmm: pointer to core HMM struct for the mm migration is taking place
 * @gpt: generic page table where destination memory is track during migration
 * @ops: migration callback operations (see struct hmm_migrate_ops)
 * @private: private pointer (set from hmm_migrate() private argument)
 * @start: virtual start address of the range to copy
 * @end: virtual end address of the range to copy
 * @cpages: number of pages that can be potentialy migrated
 * @kref: reference counter
 * @wait_queue: wait queue for concurrent fault serialization
 *
 * Because concurrent process/thread might fault on migration entry this struct
 * is use to allow them to wait for migration or trigger a migration back to
 * something that is accessible.
 *
 * This structure is reference counted and when hmm_device_migrate_memory()
 * returns some other process/thread might be holding a reference onto it.
 * But no new reference can be taken if destination memory is back by valid
 * struct page. So if it is allocated on stack you must wait for refcount to
 * drop until your are the only one left.
 *
 * It is advice however to allocate this struct as object, you can store a
 * pool of them and recycle them through the release callback (see struct
 * hmm_migrate_ops).
 */
struct hmm_migrate {
	struct list_head		list;
	struct hmm			*hmm;
	struct gpt			*gpt;
	const struct hmm_migrate_ops	*ops;
	void				*private;
	unsigned long			start;
	unsigned long			end;
	unsigned long			cpages;
	struct kref			kref;
	wait_queue_head_t		wait_queue;
};

int hmm_migrate(const struct hmm_migrate_ops *ops,
		struct vm_area_struct *vma,
		unsigned long start,
		unsigned long end,
		struct gpt *gpt,
		void *private);

#endif /* IS_ENABLED(CONFIG_HMM_MIGRATE) */
#endif /* _LINUX_HMM_MIGRATE_H */
