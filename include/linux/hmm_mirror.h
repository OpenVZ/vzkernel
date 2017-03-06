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
 * This is a heterogeneous memory management (HMM) mirror helpers. This is a
 * set of helpers to mirror a process address space on to a device by keeping
 * CPU page table synchronize with device page table.
 *
 * In conjunction with HMM migrate it allows to migrate regular system memory
 * to device memory (unmappable from CPU point of view). It will handle CPU
 * page fault on such migrated memory by migrating memory back. Migration is
 * otherwise decided by device driver and HMM only provide helpers to achieve
 * that.
 *
 * There are mandatory requirement for the hardware to use this feature :
 *   - mmu supporting at least TASK_SIZE_MAX virtual address space
 *   - support read only page
 *   - support page fault ie hardware must stop execution and wait for kernel
 *     to service fault before resuming execution
 *
 * For optimal behavior hardware should also be able to :
 *   - track dirtyness per page
 *   - track page access
 *
 * Using HMM allows device driver to avoid pining process memory. Moreover HMM
 * allow device driver to be shielded from mm changes.
 */
#ifndef _HMM_MIRROR_H
#define _HMM_MIRROR_H

#include <linux/kconfig.h>

#if IS_ENABLED(CONFIG_HMM_MIRROR)

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/mm_types.h>
#include <linux/mman.h>
#include <linux/kref.h>
#include <linux/hmm_migrate.h>

struct hmm_mirror;


/* struct hmm_mirror_ops - HMM mirror device operations callback
 */
struct hmm_mirror_ops {
	/* update() - update virtual address range of memory
	 *
	 * @mirror: pointer to struct hmm_mirror
	 * @update: update's type (turn read only, unmap, ...)
	 * @start: virtual start address of the range to update
	 * @end: virtual end address of the range to update
	 *
	 * This callback is call when the CPU page table is updated, the device
	 * driver must update device page table accordingly to update's type.
	 *
	 * Device driver callback must wait until device have fully updated its
	 * view for the range. Note we plan to make this asynchronous in later
	 * patches.
	 */
	void (*update)(struct hmm_mirror *mirror,
		       enum hmm_update update,
		       unsigned long start,
		       unsigned long end);
};

/* struct hmm_mirror - mirror struct for a device driver
 *
 * @hmm: pointer to struct hmm (which is unique per mm_struct)
 * @gpt: mirror page table from which the device can fill the device page table
 * @list: for list of mirrors of a given mm
 * @ops: device driver callback for HMM mirror operations
 *
 * Each address space (mm_struct) being mirrored by a device must register one
 * of hmm_mirror struct with HMM. HMM will track list of all mirrors for each
 * mm_struct (or each process).
 */
struct hmm_mirror {
	struct hmm			*hmm;
	const struct hmm_mirror_ops	*ops;
	struct list_head		list;
};

int hmm_mirror_register(struct hmm_mirror *mirror, struct mm_struct *mm);
void hmm_mirror_unregister(struct hmm_mirror *mirror);
int hmm_mirror_range(struct hmm_mirror *mirror,
		     struct vm_area_struct *vma,
		     unsigned long start,
		     unsigned long end,
		     bool write,
		     bool fault);

#endif /* IS_ENABLED(CONFIG_HMM_MIRROR) */
#endif /* _HMM_MIRROR_H */
