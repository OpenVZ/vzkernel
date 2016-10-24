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
 * HMM provides helpers to help leverage heterogeneous memory ie memory with
 * differents characteristics (latency, bandwidth, ...). The core idea is to
 * migrate virtual address range of a process to different memory. HMM is not
 * involve in policy or decision making of what memory and where to migrate.
 * HMM only provides helpers for the grunt work of migrating memory.
 *
 * Second part of HMM is to provide helpers to mirror a process address space
 * on a device. Here it is about mirroring CPU page table inside device page
 * table and making sure that they keep pointing to same memory for any given
 * virtual address. Bonus feature is allowing migration to device memory that
 * can not be access by CPU.
 */
#ifndef _LINUX_HMM_H
#define _LINUX_HMM_H

#include <linux/kconfig.h>

#if IS_ENABLED(CONFIG_HMM)

#include <linux/mm.h>
#include <linux/gpt.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm_types.h>
#include <linux/highmem.h>
#include <linux/mmu_notifier.h>

struct hmm_mirror;


/* enum hmm_update - type of update
 * @HMM_UPDATE_INVALIDATE: invalidate range (no indication as to why)
 */
enum hmm_update {
	HMM_UPDATE_INVALIDATE,
};


struct hmm {
	struct mm_struct	*mm;
	struct gpt		*gpt;
	struct list_head	migrates;
	struct list_head	mirrors;
	struct kref		kref;
	spinlock_t		lock;
	struct mmu_notifier	mmu_notifier;
	wait_queue_head_t	wait_queue;
	atomic_t		sequence;
	atomic_t		notifier_count;
};

struct hmm *hmm_register(struct mm_struct *mm);
struct hmm *hmm_register_mirror(struct mm_struct *mm,
				struct hmm_mirror *mirror);
void hmm_put(struct hmm *hmm);


typedef int (*hmm_walk_hole_t)(struct vm_area_struct *vma,
			      struct gpt_walk *walk,
			      unsigned long addr,
			      unsigned long end,
			      void *private);

typedef int (*hmm_walk_pte_t)(struct vm_area_struct *vma,
			      struct gpt_walk *walk,
			      unsigned long addr,
			      unsigned long end,
			      spinlock_t *ptl,
			      spinlock_t *gtl,
			      pte_t *ptep,
			      gte_t *gtep,
			      void *private);

typedef int (*hmm_walk_huge_t)(struct vm_area_struct *vma,
			       struct gpt_walk *walk,
			       unsigned long addr,
			       unsigned long end,
			       spinlock_t *ptl,
			       spinlock_t *gtl,
			       struct page *page,
			       pte_t *ptep,
			       gte_t *gtep,
			       void *private);

int hmm_walk(struct vm_area_struct *vma,
	     hmm_walk_hole_t walk_hole,
	     hmm_walk_huge_t walk_huge,
	     hmm_walk_pte_t walk_pte,
	     struct gpt_walk *walk,
	     unsigned long start,
	     unsigned long end,
	     void *private);


static inline bool hmm_get_cookie(struct hmm *hmm, int *cookie)
{
	BUG_ON(!cookie);

	*cookie = atomic_read(&hmm->sequence);
	smp_rmb();
	if (atomic_read(&hmm->notifier_count))
		return false;
	return true;
}

static inline bool hmm_check_cookie(struct hmm *hmm, int cookie)
{
	if (cookie != atomic_read(&hmm->sequence))
		return false;
	return true;
}

static inline void hmm_wait_cookie(struct hmm *hmm)
{
	wait_event(hmm->wait_queue, !atomic_read(&hmm->notifier_count));
}

#endif /* IS_ENABLED(CONFIG_HMM) */
#endif /* _LINUX_HMM_H */
