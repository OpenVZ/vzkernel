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
 * Refer to include/linux/hmm.h for information about heterogeneous memory
 * management or HMM for short.
 */
#include <linux/mm.h>
#include <linux/hmm.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/mmzone.h>
#include <linux/pagemap.h>
#include <linux/swapops.h>
#include <linux/hugetlb.h>
#include <linux/memremap.h>
#include <linux/mmu_notifier.h>
#include <linux/memory_hotplug.h>

#define PA_SECTION_SIZE (1UL << PA_SECTION_SHIFT)

static const struct mmu_notifier_ops hmm_mmu_notifier_ops;
static bool _hmm_enabled = false;


/*
 * struct hmm - HMM per mm struct
 *
 * @mm: mm struct this HMM struct is bound to
 * @lock: lock protecting ranges list
 * @sequence: we track updates to the CPU page table with a sequence number
 * @ranges: list of range being snapshotted
 * @mirrors: list of mirrors for this mm
 * @mmu_notifier: mmu notifier to track updates to CPU page table
 * @mirrors_sem: read/write semaphore protecting the mirrors list
 */
struct hmm {
	struct mm_struct	*mm;
	spinlock_t		lock;
	atomic_t		sequence;
	struct list_head	ranges;
	struct list_head	mirrors;
	struct mmu_notifier	mmu_notifier;
	struct rw_semaphore	mirrors_sem;
};

/*
 * hmm_register - register HMM against an mm (HMM internal)
 *
 * @mm: mm struct to attach to
 *
 * This is not intended to be used directly by device drivers. It allocates an
 * HMM struct if mm does not have one, and initializes it.
 */
static struct hmm *hmm_register(struct mm_struct *mm)
{
	struct hmm *hmm = READ_ONCE(mm->hmm);
	bool cleanup = false;

	/*
	 * The hmm struct can only be freed once the mm_struct goes away,
	 * hence we should always have pre-allocated an new hmm struct
	 * above.
	 */
	if (hmm)
		return hmm;

	hmm = kmalloc(sizeof(*hmm), GFP_KERNEL);
	if (!hmm)
		return NULL;
	INIT_LIST_HEAD(&hmm->mirrors);
	init_rwsem(&hmm->mirrors_sem);
	atomic_set(&hmm->sequence, 0);
	hmm->mmu_notifier.ops = NULL;
	INIT_LIST_HEAD(&hmm->ranges);
	spin_lock_init(&hmm->lock);
	hmm->mm = mm;

	/*
	 * We should only get here if hold the mmap_sem in write mode ie on
	 * registration of first mirror through hmm_mirror_register()
	 */
	hmm->mmu_notifier.ops = &hmm_mmu_notifier_ops;
	if (__mmu_notifier_register(&hmm->mmu_notifier, mm)) {
		kfree(hmm);
		return NULL;
	}

	spin_lock(&mm->page_table_lock);
	if (!mm->hmm)
		mm->hmm = hmm;
	else
		cleanup = true;
	spin_unlock(&mm->page_table_lock);

	if (cleanup) {
		mmu_notifier_unregister(&hmm->mmu_notifier, mm);
		kfree(hmm);
	}

	return mm->hmm;
}

void hmm_mm_destroy(struct mm_struct *mm)
{
	kfree(mm->hmm);
}

#if IS_ENABLED(CONFIG_HMM_MIRROR)
static void hmm_invalidate_range(struct hmm *hmm,
				 enum hmm_update_type action,
				 unsigned long start,
				 unsigned long end)
{
	struct hmm_mirror *mirror;
	struct hmm_range *range;

	spin_lock(&hmm->lock);
	list_for_each_entry(range, &hmm->ranges, list) {
		unsigned long addr, idx, npages;

		if (end < range->start || start >= range->end)
			continue;

		range->valid = false;
		addr = max(start, range->start);
		idx = (addr - range->start) >> PAGE_SHIFT;
		npages = (min(range->end, end) - addr) >> PAGE_SHIFT;
		memset(&range->pfns[idx], 0, sizeof(*range->pfns) * npages);
	}
	spin_unlock(&hmm->lock);

	down_read(&hmm->mirrors_sem);
	list_for_each_entry(mirror, &hmm->mirrors, list)
		mirror->ops->sync_cpu_device_pagetables(mirror, action,
							start, end);
	up_read(&hmm->mirrors_sem);
}

static void hmm_invalidate_page(struct mmu_notifier *mn,
				struct mm_struct *mm,
				unsigned long addr)
{
	unsigned long start = addr & PAGE_MASK;
	unsigned long end = start + PAGE_SIZE;
	struct hmm *hmm = mm->hmm;

	VM_BUG_ON(!hmm);

	atomic_inc(&hmm->sequence);
	hmm_invalidate_range(mm->hmm, HMM_UPDATE_INVALIDATE, start, end);
}

static void hmm_invalidate_range_start(struct mmu_notifier *mn,
				       struct mm_struct *mm,
				       unsigned long start,
				       unsigned long end)
{
	struct hmm *hmm = mm->hmm;

	VM_BUG_ON(!hmm);

	atomic_inc(&hmm->sequence);
}

static void hmm_invalidate_range_end(struct mmu_notifier *mn,
				     struct mm_struct *mm,
				     unsigned long start,
				     unsigned long end)
{
	struct hmm *hmm = mm->hmm;

	VM_BUG_ON(!hmm);

	hmm_invalidate_range(mm->hmm, HMM_UPDATE_INVALIDATE, start, end);
}

static const struct mmu_notifier_ops hmm_mmu_notifier_ops = {
	.invalidate_page	= hmm_invalidate_page,
	.invalidate_range_start	= hmm_invalidate_range_start,
	.invalidate_range_end	= hmm_invalidate_range_end,
};

/*
 * hmm_mirror_register() - register a mirror against an mm
 *
 * @mirror: new mirror struct to register
 * @mm: mm to register against
 *
 * To start mirroring a process address space, the device driver must register
 * an HMM mirror struct.
 *
 * THE mm->mmap_sem MUST BE HELD IN WRITE MODE !
 */
int hmm_mirror_register(struct hmm_mirror *mirror, struct mm_struct *mm)
{
	/* Sanity check */
	if (!mm || !mirror || !mirror->ops)
		return -EINVAL;

	mirror->hmm = hmm_register(mm);
	if (!mirror->hmm)
		return -ENOMEM;

	down_write(&mirror->hmm->mirrors_sem);
	list_add(&mirror->list, &mirror->hmm->mirrors);
	up_write(&mirror->hmm->mirrors_sem);

	return 0;
}
EXPORT_SYMBOL(hmm_mirror_register);

/*
 * hmm_mirror_unregister() - unregister a mirror
 *
 * @mirror: new mirror struct to register
 *
 * Stop mirroring a process address space, and cleanup.
 */
void hmm_mirror_unregister(struct hmm_mirror *mirror)
{
	struct hmm *hmm = mirror->hmm;

	down_write(&hmm->mirrors_sem);
	list_del(&mirror->list);
	up_write(&hmm->mirrors_sem);
}
EXPORT_SYMBOL(hmm_mirror_unregister);

struct hmm_vma_walk {
	struct hmm_range	*range;
	struct vm_area_struct	*vma;
	unsigned long		last;
	bool			fault;
	bool			block;
	bool			write;
};

static int hmm_vma_do_fault(struct mm_walk *walk,
			    unsigned long addr,
			    hmm_pfn_t *pfn)
{
	unsigned int flags = FAULT_FLAG_ALLOW_RETRY;
	struct hmm_vma_walk *hmm_vma_walk = walk->private;
	struct vm_area_struct *vma = hmm_vma_walk->vma;
	int r;

	flags |= hmm_vma_walk->block ? 0 : FAULT_FLAG_ALLOW_RETRY;
	flags |= hmm_vma_walk->write ? FAULT_FLAG_WRITE : 0;
	r = handle_mm_fault(vma, addr, flags);
	if (r & VM_FAULT_RETRY)
		return -EBUSY;
	if (r & VM_FAULT_ERROR) {
		*pfn = HMM_PFN_ERROR;
		return -EFAULT;
	}

	return -EAGAIN;
}

static void hmm_pfns_special(hmm_pfn_t *pfns,
			     unsigned long addr,
			     unsigned long end)
{
	for (; addr < end; addr += PAGE_SIZE, pfns++)
		*pfns = HMM_PFN_SPECIAL;
}

static int hmm_pfns_bad(hmm_pfn_t *pfns,
			unsigned long addr,
			unsigned long end)
{
	for (; addr < end; addr += PAGE_SIZE, pfns++)
		*pfns = HMM_PFN_ERROR;
	return -EFAULT;
}

static void hmm_pfns_clear(hmm_pfn_t *pfns,
			   unsigned long addr,
			   unsigned long end)
{
	for (; addr < end; addr += PAGE_SIZE, pfns++)
		*pfns = 0;
}

static int hmm_vma_walk_hole(unsigned long addr,
			     unsigned long end,
			     struct mm_walk *walk)
{
	struct hmm_vma_walk *hmm_vma_walk = walk->private;
	struct hmm_range *range = hmm_vma_walk->range;
	hmm_pfn_t *pfns = range->pfns;
	unsigned long i;

	hmm_vma_walk->last = addr;
	i = (addr - range->start) >> PAGE_SHIFT;
	for (; addr < end; addr += PAGE_SIZE, i++) {
		pfns[i] = HMM_PFN_EMPTY;

		if (hmm_vma_walk->fault) {
			int ret;
 
			ret = hmm_vma_do_fault(walk, addr, &pfns[i]);
			if (ret != -EAGAIN)
				return ret;
		}
	}

	return hmm_vma_walk->fault ? -EAGAIN : 0;
}

static int hmm_vma_walk_clear(unsigned long addr,
			      unsigned long end,
			      struct mm_walk *walk)
{
	struct hmm_vma_walk *hmm_vma_walk = walk->private;
	struct hmm_range *range = hmm_vma_walk->range;
	hmm_pfn_t *pfns = range->pfns;
	unsigned long i;

	hmm_vma_walk->last = addr;
	i = (addr - range->start) >> PAGE_SHIFT;
	for (; addr < end; addr += PAGE_SIZE, i++) {
		pfns[i] = 0;
		if (hmm_vma_walk->fault) {
			int ret;
 
			ret = hmm_vma_do_fault(walk, addr, &pfns[i]);
			if (ret != -EAGAIN)
				return ret;
		}
	}

	return hmm_vma_walk->fault ? -EAGAIN : 0;
}

static inline unsigned long hmm_pte_index(unsigned long address)
{
	return (address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
}

static int hmm_vma_walk_pmd(pmd_t *pmdp,
			    unsigned long start,
			    unsigned long end,
			    struct mm_walk *walk)
{
	struct hmm_vma_walk *hmm_vma_walk = walk->private;
	struct vm_area_struct *vma = hmm_vma_walk->vma;
	struct hmm_range *range = hmm_vma_walk->range;
	hmm_pfn_t *pfns = range->pfns;
	unsigned long addr = start, i;
	bool write_fault;
	hmm_pfn_t flag;
	pte_t *ptep;

	i = (addr - range->start) >> PAGE_SHIFT;
	flag = vma->vm_flags & VM_READ ? HMM_PFN_READ : 0;
	write_fault = hmm_vma_walk->fault & hmm_vma_walk->write;

	if (pmd_none(*pmdp))
		return hmm_vma_walk_hole(start, end, walk);

	if (unlikely(pmd_trans_splitting(*pmdp)))
		wait_split_huge_page(vma->anon_vma, pmdp);

	if (pmd_trans_huge(*pmdp)) {
		unsigned long pfn = pmd_pfn(*pmdp) + hmm_pte_index(addr);

		if (write_fault && !pmd_write(*pmdp))
			return hmm_vma_walk_clear(start, end, walk);

		flag |= pmd_write(*pmdp) ? HMM_PFN_WRITE : 0;
		for (; addr < end; addr += PAGE_SIZE, i++, pfn++)
			pfns[i] = hmm_pfn_t_from_pfn(pfn) | flag;
		return 0;
	}

	if (pmd_bad(*pmdp))
		return hmm_pfns_bad(&pfns[i], start, end);

	ptep = pte_offset_map(pmdp, addr);
	for (; addr < end; addr += PAGE_SIZE, ptep++, i++) {
		pte_t pte = *ptep;

		pfns[i] = 0;

		if (pte_none(pte)) {
			pfns[i] = HMM_PFN_EMPTY;
			if (hmm_vma_walk->fault)
				goto fault;
			continue;
		}

		if (!pte_present(pte)) {
			swp_entry_t entry;

			if (!non_swap_entry(entry)) {
				if (hmm_vma_walk->fault)
					goto fault;
				continue;
			}
			entry = pte_to_swp_entry(pte);

			/*
			 * This is a special swap entry, ignore migration, use
			 * device and report anything else as error.
			 */
			if (is_hmm_entry(entry)) {
				pfns[i] = hmm_pfn_t_from_pfn(swp_offset(entry));
				if (is_write_hmm_entry(entry)) {
					pfns[i] |= HMM_PFN_WRITE;
				} else if (write_fault)
					goto fault;
				pfns[i] |= HMM_PFN_DEVICE_UNADDRESSABLE;
				pfns[i] |= flag;
			} else if (is_migration_entry(entry)) {
				if (hmm_vma_walk->fault) {
					pte_unmap(ptep - 1);
					hmm_vma_walk->last = addr;
					migration_entry_wait(vma->vm_mm,
							     pmdp, addr);
					return -EAGAIN;
				}
				continue;
			} else {
				/* Report error for everything else */
				pfns[i] = HMM_PFN_ERROR;
			}
			continue;
		}

		if (write_fault && !pte_write(pte))
			goto fault;
		pfns[i] = hmm_pfn_t_from_pfn(pte_pfn(pte)) | flag;
		pfns[i] |= pte_write(pte) ? HMM_PFN_WRITE : 0;
		continue;

fault:
		pte_unmap(ptep);
		/* Fault all pages in range */
		return hmm_vma_walk_clear(addr, end, walk);
	}
	pte_unmap(ptep - 1);

	return 0;
}

/*
 * hmm_vma_get_pfns() - snapshot CPU page table for a range of virtual addresses
 * @vma: virtual memory area containing the virtual address range
 * @range: used to track snapshot validity
 * @start: range virtual start address (inclusive)
 * @end: range virtual end address (exclusive)
 * @entries: array of hmm_pfn_t: provided by the caller, filled in by function
 * Returns: -EINVAL if invalid argument, -ENOMEM out of memory, 0 success
 *
 * This snapshots the CPU page table for a range of virtual addresses. Snapshot
 * validity is tracked by range struct. See hmm_vma_range_done() for further
 * information.
 *
 * The range struct is initialized here. It tracks the CPU page table, but only
 * if the function returns success (0), in which case the caller must then call
 * hmm_vma_range_done() to stop CPU page table update tracking on this range.
 *
 * NOT CALLING hmm_vma_range_done() IF FUNCTION RETURNS 0 WILL LEAD TO SERIOUS
 * MEMORY CORRUPTION ! YOU HAVE BEEN WARNED !
 */
int hmm_vma_get_pfns(struct vm_area_struct *vma,
		     struct hmm_range *range,
		     unsigned long start,
		     unsigned long end,
		     hmm_pfn_t *pfns)
{
	struct hmm_vma_walk hmm_vma_walk;
	struct mm_walk mm_walk;
	struct hmm *hmm;

	/* FIXME support hugetlb fs */
	if (is_vm_hugetlb_page(vma) || (vma->vm_flags & VM_SPECIAL) ||
			vma_is_dax(vma)) {
		hmm_pfns_special(pfns, start, end);
		return -EINVAL;
	}

	/* Sanity check, this really should not happen ! */
	if (start < vma->vm_start || start >= vma->vm_end)
		return -EINVAL;
	if (end < vma->vm_start || end > vma->vm_end)
		return -EINVAL;

	hmm = hmm_register(vma->vm_mm);
	if (!hmm)
		return -ENOMEM;
	/* Caller must have registered a mirror, via hmm_mirror_register() ! */
	if (!hmm->mmu_notifier.ops)
		return -EINVAL;

	/* Initialize range to track CPU page table update */
	range->start = start;
	range->pfns = pfns;
	range->end = end;
	spin_lock(&hmm->lock);
	range->valid = true;
	list_add_rcu(&range->list, &hmm->ranges);
	spin_unlock(&hmm->lock);

	hmm_vma_walk.vma = vma;
	hmm_vma_walk.fault = false;
	hmm_vma_walk.range = range;

	mm_walk.mm = vma->vm_mm;
	mm_walk.pgd_entry = NULL;
	mm_walk.pud_entry = NULL;
	mm_walk.pte_entry = NULL;
	mm_walk.hugetlb_entry = NULL;
	mm_walk.private = &hmm_vma_walk;
	mm_walk.pmd_entry = hmm_vma_walk_pmd;
	mm_walk.pte_hole = hmm_vma_walk_hole;

	walk_page_range(start, end, &mm_walk);

	return 0;
}
EXPORT_SYMBOL(hmm_vma_get_pfns);

/*
 * hmm_vma_range_done() - stop tracking change to CPU page table over a range
 * @vma: virtual memory area containing the virtual address range
 * @range: range being tracked
 * Returns: false if range data has been invalidated, true otherwise
 *
 * Range struct is used to track updates to the CPU page table after a call to
 * either hmm_vma_get_pfns() or hmm_vma_fault(). Once the device driver is done
 * using the data,  or wants to lock updates to the data it got from those
 * functions, it must call the hmm_vma_range_done() function, which will then
 * stop tracking CPU page table updates.
 *
 * Note that device driver must still implement general CPU page table update
 * tracking either by using hmm_mirror (see hmm_mirror_register()) or by using
 * the mmu_notifier API directly.
 *
 * CPU page table update tracking done through hmm_range is only temporary and
 * to be used while trying to duplicate CPU page table contents for a range of
 * virtual addresses.
 *
 * There are two ways to use this :
 * again:
 *   hmm_vma_get_pfns(vma, range, start, end, pfns); or hmm_vma_fault(...);
 *   trans = device_build_page_table_update_transaction(pfns);
 *   device_page_table_lock();
 *   if (!hmm_vma_range_done(vma, range)) {
 *     device_page_table_unlock();
 *     goto again;
 *   }
 *   device_commit_transaction(trans);
 *   device_page_table_unlock();
 *
 * Or:
 *   hmm_vma_get_pfns(vma, range, start, end, pfns); or hmm_vma_fault(...);
 *   device_page_table_lock();
 *   hmm_vma_range_done(vma, range);
 *   device_update_page_table(pfns);
 *   device_page_table_unlock();
 */
bool hmm_vma_range_done(struct vm_area_struct *vma, struct hmm_range *range)
{
	unsigned long npages = (range->end - range->start) >> PAGE_SHIFT;
	struct hmm *hmm;

	if (range->end <= range->start) {
		BUG();
		return false;
	}

	hmm = hmm_register(vma->vm_mm);
	if (!hmm) {
		memset(range->pfns, 0, sizeof(*range->pfns) * npages);
		return false;
	}

	spin_lock(&hmm->lock);
	list_del_rcu(&range->list);
	spin_unlock(&hmm->lock);

	return range->valid;
}
EXPORT_SYMBOL(hmm_vma_range_done);

/*
 * hmm_vma_fault() - try to fault some address in a virtual address range
 * @vma: virtual memory area containing the virtual address range
 * @range: use to track pfns array content validity
 * @start: fault range virtual start address (inclusive)
 * @end: fault range virtual end address (exclusive)
 * @pfns: array of hmm_pfn_t, only entry with fault flag set will be faulted
 * @write: is it a write fault
 * @block: allow blocking on fault (if true it sleeps and do not drop mmap_sem)
 * Returns: 0 success, error otherwise (-EAGAIN means mmap_sem have been drop)
 *
 * This is similar to a regular CPU page fault except that it will not trigger
 * any memory migration if the memory being faulted is not accessible by CPUs.
 *
 * On error, for one virtual address in the range, the function will set the
 * hmm_pfn_t error flag for the corresponding pfn entry.
 *
 * Expected use pattern:
 * retry:
 *   down_read(&mm->mmap_sem);
 *   // Find vma and address device wants to fault, initialize hmm_pfn_t
 *   // array accordingly
 *   ret = hmm_vma_fault(vma, start, end, pfns, allow_retry);
 *   switch (ret) {
 *   case -EAGAIN:
 *     hmm_vma_range_done(vma, range);
 *     // You might want to rate limit or yield to play nicely, you may
 *     // also commit any valid pfn in the array assuming that you are
 *     // getting true from hmm_vma_range_monitor_end()
 *     goto retry;
 *   case 0:
 *     break;
 *   default:
 *     // Handle error !
 *     up_read(&mm->mmap_sem)
 *     return;
 *   }
 *   // Take device driver lock that serialize device page table update
 *   driver_lock_device_page_table_update();
 *   hmm_vma_range_done(vma, range);
 *   // Commit pfns we got from hmm_vma_fault()
 *   driver_unlock_device_page_table_update();
 *   up_read(&mm->mmap_sem)
 *
 * YOU MUST CALL hmm_vma_range_done() AFTER THIS FUNCTION RETURN SUCCESS (0)
 * BEFORE FREEING THE range struct OR YOU WILL HAVE SERIOUS MEMORY CORRUPTION !
 *
 * YOU HAVE BEEN WARNED !
 */
int hmm_vma_fault(struct vm_area_struct *vma,
		  struct hmm_range *range,
		  unsigned long start,
		  unsigned long end,
		  hmm_pfn_t *pfns,
		  bool write,
		  bool block)
{
	struct hmm_vma_walk hmm_vma_walk;
	struct mm_walk mm_walk;
	struct hmm *hmm;
	int ret;

	/* Sanity check, this really should not happen ! */
	if (start < vma->vm_start || start >= vma->vm_end)
		return -EINVAL;
	if (end < vma->vm_start || end > vma->vm_end)
		return -EINVAL;

	hmm = hmm_register(vma->vm_mm);
	if (!hmm) {
		hmm_pfns_clear(pfns, start, end);
		return -ENOMEM;
	}
	/* Caller must have registered a mirror using hmm_mirror_register() */
	if (!hmm->mmu_notifier.ops)
		return -EINVAL;

	/* Initialize range to track CPU page table update */
	range->start = start;
	range->pfns = pfns;
	range->end = end;
	spin_lock(&hmm->lock);
	range->valid = true;
	list_add_rcu(&range->list, &hmm->ranges);
	spin_unlock(&hmm->lock);

	/* FIXME support hugetlb fs */
	if (is_vm_hugetlb_page(vma) || (vma->vm_flags & VM_SPECIAL) ||
			vma_is_dax(vma)) {
		hmm_pfns_special(pfns, start, end);
		return 0;
	}

	hmm_vma_walk.vma = vma;
	hmm_vma_walk.fault = true;
	hmm_vma_walk.write = write;
	hmm_vma_walk.block = block;
	hmm_vma_walk.range = range;
	hmm_vma_walk.last = range->start;

	mm_walk.mm = vma->vm_mm;
	mm_walk.pgd_entry = NULL;
	mm_walk.pud_entry = NULL;
	mm_walk.pte_entry = NULL;
	mm_walk.hugetlb_entry = NULL;
	mm_walk.private = &hmm_vma_walk;
	mm_walk.pmd_entry = hmm_vma_walk_pmd;
	mm_walk.pte_hole = hmm_vma_walk_hole;

	do {
		ret = walk_page_range(start, end, &mm_walk);
		start = hmm_vma_walk.last;
	} while (ret == -EAGAIN);

	if (ret) {
		unsigned long i;

		i = (hmm_vma_walk.last - range->start) >> PAGE_SHIFT;
		hmm_pfns_clear(&pfns[i], hmm_vma_walk.last, end);
		hmm_vma_range_done(vma, range);
	}
	return ret;
}
EXPORT_SYMBOL(hmm_vma_fault);
#endif /* IS_ENABLED(CONFIG_HMM_MIRROR) */

struct page *hmm_vma_alloc_locked_page(struct vm_area_struct *vma,
				       unsigned long addr)
{
	struct page *page;

	page = alloc_page_vma(GFP_HIGHUSER, vma, addr);
	if (!page)
		return NULL;
	lock_page(page);
	return page;
}
EXPORT_SYMBOL(hmm_vma_alloc_locked_page);


static void hmm_devmem_ref_release(struct percpu_ref *ref)
{
	struct hmm_devmem *devmem;

	devmem = container_of(ref, struct hmm_devmem, ref);
	complete(&devmem->completion);
}

static void hmm_devmem_ref_exit(void *data)
{
	struct percpu_ref *ref = data;
	struct hmm_devmem *devmem;

	devmem = container_of(ref, struct hmm_devmem, ref);
	percpu_ref_exit(ref);
	devm_remove_action(devmem->device, &hmm_devmem_ref_exit, data);
}

static void hmm_devmem_ref_kill(void *data)
{
	struct percpu_ref *ref = data;
	struct hmm_devmem *devmem;

	devmem = container_of(ref, struct hmm_devmem, ref);
	percpu_ref_kill(ref);
	wait_for_completion(&devmem->completion);
	devm_remove_action(devmem->device, &hmm_devmem_ref_kill, data);
}

static int hmm_devmem_fault(struct vm_area_struct *vma,
			    unsigned long addr,
			    struct page *page,
			    unsigned int flags,
			    pmd_t *pmdp)
{
	struct hmm_devmem *devmem = page->pgmap->data;

	return devmem->ops->fault(devmem, vma, addr, page, flags, pmdp);
}

static void hmm_devmem_free(struct page *page, void *data)
{
	struct hmm_devmem *devmem = data;

	page->mapping = NULL;

	devmem->ops->free(devmem, page);
}

static DEFINE_MUTEX(hmm_devmem_lock);
static RADIX_TREE(hmm_devmem_radix, GFP_KERNEL);

static void hmm_devmem_radix_release(struct resource *resource)
{
	resource_size_t key, align_start, align_size, align_end;

	align_start = resource->start & ~(PA_SECTION_SIZE - 1);
	align_size = ALIGN(resource_size(resource), PA_SECTION_SIZE);
	align_end = align_start + align_size - 1;

	mutex_lock(&hmm_devmem_lock);
	for (key = resource->start;
	     key <= resource->end;
	     key += PA_SECTION_SIZE)
		radix_tree_delete(&hmm_devmem_radix, key >> PA_SECTION_SHIFT);
	mutex_unlock(&hmm_devmem_lock);
}

static void hmm_devmem_release(struct device *dev, void *data)
{
	struct hmm_devmem *devmem = data;
	struct resource *resource = devmem->resource;
	unsigned long start_pfn, npages;
	struct zone *zone;
	struct page *page;

	if (percpu_ref_tryget_live(&devmem->ref)) {
		dev_WARN(dev, "%s: page mapping is still live!\n", __func__);
		percpu_ref_put(&devmem->ref);
	}

	/* pages are dead and unused, undo the arch mapping */
	start_pfn = (resource->start & ~(PA_SECTION_SIZE - 1)) >> PAGE_SHIFT;
	npages = ALIGN(resource_size(resource), PA_SECTION_SIZE) >> PAGE_SHIFT;

	page = pfn_to_page(start_pfn);
	zone = page_zone(page);

	__remove_pages(zone, start_pfn, npages, NULL);

	hmm_devmem_radix_release(resource);
}

static struct hmm_devmem *hmm_devmem_find(resource_size_t phys)
{
	WARN_ON_ONCE(!rcu_read_lock_held());

	return radix_tree_lookup(&hmm_devmem_radix, phys >> PA_SECTION_SHIFT);
}

static int hmm_devmem_pages_create(struct hmm_devmem *devmem)
{
	resource_size_t key, align_start, align_size, align_end;
	struct device *device = devmem->device;
	int ret, nid, is_ram;
	unsigned long pfn;

	align_start = devmem->resource->start & ~(PA_SECTION_SIZE - 1);
	align_size = ALIGN(devmem->resource->start +
			   resource_size(devmem->resource),
			   PA_SECTION_SIZE) - align_start;

	is_ram = region_intersects_ram(align_start, align_size);
	if (is_ram == REGION_MIXED) {
		WARN_ONCE(1, "%s attempted on mixed region %pr\n",
				__func__, devmem->resource);
		return -ENXIO;
	}
	if (is_ram == REGION_INTERSECTS)
		return -ENXIO;

	is_ram = region_intersects_pmem(align_start, align_size);
	if (is_ram == REGION_MIXED) {
		WARN_ONCE(1, "%s attempted on mixed region %pr\n",
				__func__, devmem->resource);
		return -ENXIO;
	}
	if (is_ram == REGION_INTERSECTS)
		return -ENXIO;

	devmem->pagemap.type = MEMORY_HMM;
	devmem->pagemap.res = *devmem->resource;
	devmem->pagemap.page_fault = hmm_devmem_fault;
	devmem->pagemap.page_free = hmm_devmem_free;
	devmem->pagemap.dev = devmem->device;
	devmem->pagemap.ref = &devmem->ref;
	devmem->pagemap.data = devmem;

	mutex_lock(&hmm_devmem_lock);
	align_end = align_start + align_size - 1;
	for (key = align_start; key <= align_end; key += PA_SECTION_SIZE) {
		struct hmm_devmem *dup;

		rcu_read_lock();
		dup = hmm_devmem_find(key);
		rcu_read_unlock();
		if (dup) {
			dev_err(device, "%s: collides with mapping for %s\n",
				__func__, dev_name(dup->device));
			mutex_unlock(&hmm_devmem_lock);
			ret = -EBUSY;
			goto error;
		}
		ret = radix_tree_insert(&hmm_devmem_radix,
					key >> PA_SECTION_SHIFT,
					devmem);
		if (ret) {
			dev_err(device, "%s: failed: %d\n", __func__, ret);
			mutex_unlock(&hmm_devmem_lock);
			goto error_radix;
		}
	}
	mutex_unlock(&hmm_devmem_lock);

	nid = dev_to_node(device);
	if (nid < 0)
		nid = numa_mem_id();

	ret = add_pages(nid, align_start, align_size, NULL, true);
	if (ret)
		goto error_radix;

	for (pfn = devmem->pfn_first; pfn < devmem->pfn_last; pfn++) {
		struct page *page = pfn_to_page(pfn);

		/*
		 * ZONE_DEVICE pages union ->lru with a ->pgmap back
		 * pointer.  It is a bug if a ZONE_DEVICE page is ever
		 * freed or placed on a driver-private list. Therefore,
		 * seed the storage with LIST_POISON* values.
		 */
		list_del(&page->lru);
		page->pgmap = &devmem->pagemap;
	}
	return 0;

error_radix:
	hmm_devmem_radix_release(devmem->resource);
error:
	return ret;
}

static int hmm_devmem_match(struct device *dev, void *data, void *match_data)
{
	struct hmm_devmem *devmem = data;

	return devmem->resource == match_data;
}

static void hmm_devmem_pages_remove(struct hmm_devmem *devmem)
{
	devres_release(devmem->device, &hmm_devmem_release,
		       &hmm_devmem_match, devmem->resource);
}

/*
 * hmm_devmem_add() - hotplug ZONE_DEVICE memory for device memory
 *
 * @ops: memory event device driver callback (see struct hmm_devmem_ops)
 * @device: device struct to bind the resource too
 * @size: size in bytes of the device memory to add
 * Returns: pointer to new hmm_devmem struct ERR_PTR otherwise
 *
 * This first finds an empty range of physical address big enough to contain the
 * new resource, and then hotplugs it as ZONE_DEVICE memory, which in turn
 * allocates struct pages. It does not do anything beyond that; all events
 * affecting the memory will go through the various callbacks provided by
 * hmm_devmem_ops struct.
 */
struct hmm_devmem *hmm_devmem_add(const struct hmm_devmem_ops *ops,
				  struct device *device,
				  unsigned long size)
{
	struct hmm_devmem *devmem;
	resource_size_t addr;
	int ret;

	devmem = devres_alloc_node(&hmm_devmem_release, sizeof(*devmem),
				   GFP_KERNEL, dev_to_node(device));
	if (!devmem)
		return ERR_PTR(-ENOMEM);

	init_completion(&devmem->completion);
	devmem->pfn_first = -1UL;
	devmem->pfn_last = -1UL;
	devmem->resource = NULL;
	devmem->device = device;
	devmem->ops = ops;

	ret = percpu_ref_init(&devmem->ref, &hmm_devmem_ref_release,
			      0, GFP_KERNEL);
	if (ret)
		goto error_percpu_ref;

	ret = devm_add_action(device, hmm_devmem_ref_exit, &devmem->ref);
	if (ret)
		goto error_devm_add_action;

	size = ALIGN(size, PA_SECTION_SIZE);
	addr = min((unsigned long)iomem_resource.end,
		   (1UL << MAX_PHYSMEM_BITS) - (128 << 20));
	addr = addr - size + 1UL;

	/*
	 * FIXME add a new helper to quickly walk resource tree and find free
	 * range
	 *
	 * FIXME what about ioport_resource resource ?
	 */
	for (; addr > size && addr >= iomem_resource.start; addr -= size) {
		ret = region_intersects_ram(addr, size);
		if (ret != REGION_DISJOINT)
			continue;

		ret = region_intersects_pmem(addr, size);
		if (ret != REGION_DISJOINT)
			continue;

		devmem->resource = devm_request_mem_region(device, addr, size,
							   dev_name(device));
		if (!devmem->resource) {
			ret = -ENOMEM;
			goto error_no_resource;
		}
		break;
	}
	if (!devmem->resource) {
		ret = -ERANGE;
		goto error_no_resource;
	}

	devmem->pfn_first = devmem->resource->start >> PAGE_SHIFT;
	devmem->pfn_last = devmem->pfn_first +
			   (resource_size(devmem->resource) >> PAGE_SHIFT);

	ret = hmm_devmem_pages_create(devmem);
	if (ret)
		goto error_pages;

	devres_add(device, devmem);

	ret = devm_add_action(device, hmm_devmem_ref_kill, &devmem->ref);
	if (ret) {
		hmm_devmem_remove(devmem);
		return ERR_PTR(ret);
	}

	return devmem;

error_pages:
	devm_release_mem_region(device, devmem->resource->start,
				resource_size(devmem->resource));
error_no_resource:
error_devm_add_action:
	hmm_devmem_ref_kill(&devmem->ref);
	hmm_devmem_ref_exit(&devmem->ref);
error_percpu_ref:
	devres_free(devmem);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL(hmm_devmem_add);

/*
 * hmm_devmem_remove() - remove device memory (kill and free ZONE_DEVICE)
 *
 * @devmem: hmm_devmem struct use to track and manage the ZONE_DEVICE memory
 *
 * This will hot-unplug memory that was hotplugged by hmm_devmem_add on behalf
 * of the device driver. It will free struct page and remove the resource that
 * reserved the physical address range for this device memory.
 */
void hmm_devmem_remove(struct hmm_devmem *devmem)
{
	resource_size_t start, size;
	struct device *device;

	if (!devmem)
		return;

	device = devmem->device;
	start = devmem->resource->start;
	size = resource_size(devmem->resource);

	hmm_devmem_ref_kill(&devmem->ref);
	hmm_devmem_ref_exit(&devmem->ref);
	hmm_devmem_pages_remove(devmem);

	devm_release_mem_region(device, start, size);
}
EXPORT_SYMBOL(hmm_devmem_remove);

/*
 * hmm_devmem_fault_range() - migrate back a virtual range of memory
 *
 * @devmem: hmm_devmem struct use to track and manage the ZONE_DEVICE memory
 * @vma: virtual memory area containing the range to be migrated
 * @ops: migration callback for allocating destination memory and copying
 * @src: array of unsigned long containing source pfns
 * @dst: array of unsigned long containing destination pfns
 * @start: start address of the range to migrate (inclusive)
 * @addr: fault address (must be inside the range)
 * @end: end address of the range to migrate (exclusive)
 * @private: pointer passed back to each of the callback
 * Returns: 0 on success, VM_FAULT_SIGBUS on error
 *
 * This is a wrapper around migrate_vma() which checks the migration status
 * for a given fault address and returns the corresponding page fault handler
 * status. That will be 0 on success, or VM_FAULT_SIGBUS if migration failed
 * for the faulting address.
 *
 * This is a helper intendend to be used by the ZONE_DEVICE fault handler.
 */
int hmm_devmem_fault_range(struct hmm_devmem *devmem,
			   struct vm_area_struct *vma,
			   const struct migrate_vma_ops *ops,
			   unsigned long *src,
			   unsigned long *dst,
			   unsigned long start,
			   unsigned long addr,
			   unsigned long end,
			   void *private)
{
	if (migrate_vma(ops, vma, start, end, src, dst, private))
		return VM_FAULT_SIGBUS;

	if (dst[(addr - start) >> PAGE_SHIFT] & MIGRATE_PFN_ERROR)
		return VM_FAULT_SIGBUS;

	return 0;
}
EXPORT_SYMBOL(hmm_devmem_fault_range);

/*
 * A device driver that wants to handle multiple devices memory through a
 * single fake device can use hmm_device to do so. This is purely a helper
 * and it is not needed to make use of any HMM functionality.
 */
#define HMM_DEVICE_MAX 256

static DECLARE_BITMAP(hmm_device_mask, HMM_DEVICE_MAX);
static DEFINE_SPINLOCK(hmm_device_lock);
static struct class *hmm_device_class;
static dev_t hmm_device_devt;

static void hmm_device_release(struct device *device)
{
	struct hmm_device *hmm_device;

	hmm_device = container_of(device, struct hmm_device, device);
	spin_lock(&hmm_device_lock);
	clear_bit(hmm_device->minor, hmm_device_mask);
	spin_unlock(&hmm_device_lock);

	kfree(hmm_device);
}

struct hmm_device *hmm_device_new(void *drvdata)
{
	struct hmm_device *hmm_device;

	hmm_device = kzalloc(sizeof(*hmm_device), GFP_KERNEL);
	if (!hmm_device)
		return ERR_PTR(-ENOMEM);

	spin_lock(&hmm_device_lock);
	hmm_device->minor = find_first_zero_bit(hmm_device_mask, HMM_DEVICE_MAX);
	if (hmm_device->minor >= HMM_DEVICE_MAX) {
		spin_unlock(&hmm_device_lock);
		kfree(hmm_device);
		return NULL;
	}
	set_bit(hmm_device->minor, hmm_device_mask);
	spin_unlock(&hmm_device_lock);

	dev_set_name(&hmm_device->device, "hmm_device%d", hmm_device->minor);
	hmm_device->device.devt = MKDEV(MAJOR(hmm_device_devt),
					hmm_device->minor);
	hmm_device->device.release = hmm_device_release;
	dev_set_drvdata(&hmm_device->device, drvdata);
	hmm_device->device.class = hmm_device_class;
	device_initialize(&hmm_device->device);

	return hmm_device;
}
EXPORT_SYMBOL(hmm_device_new);

void hmm_device_put(struct hmm_device *hmm_device)
{
	put_device(&hmm_device->device);
}
EXPORT_SYMBOL(hmm_device_put);

static int __init hmm_init(void)
{
	int ret;

	ret = alloc_chrdev_region(&hmm_device_devt, 0,
				  HMM_DEVICE_MAX,
				  "hmm_device");
	if (ret)
		return ret;

	hmm_device_class = class_create(THIS_MODULE, "hmm_device");
	if (IS_ERR(hmm_device_class)) {
		unregister_chrdev_region(hmm_device_devt, HMM_DEVICE_MAX);
		return PTR_ERR(hmm_device_class);
	}
	return 0;
}
device_initcall(hmm_init);

static int __init setup_hmm(char *str)
{
	int ret = 0;

	if (!str)
		goto out;
	if (!strcmp(str, "enable")) {
		_hmm_enabled = true;
		ret = 1;
	}

out:
	if (!ret)
		printk(KERN_WARNING "experimental_hmm= cannot parse, ignored\n");
	return ret;
}
__setup("experimental_hmm=", setup_hmm);
