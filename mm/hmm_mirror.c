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
 * This is the code for heterogeneous memory management (HMM) mirroring. Which
 * provide a common framework to mirror a process address space on to a device.
 *
 * Refer to include/linux/hmm_mirror.h for further informations.
 */
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/hmm_mirror.h>
#include <linux/mmu_notifier.h>


int hmm_mirror_register(struct hmm_mirror *mirror, struct mm_struct *mm)
{
	/* Sanity check */
	if (!mm || !mirror || !mirror->ops)
		return -EINVAL;

	mirror->hmm = hmm_register_mirror(mm, mirror);
	if (!mirror->hmm)
		return -ENOMEM;

	return 0;
}
EXPORT_SYMBOL(hmm_mirror_register);

void hmm_mirror_unregister(struct hmm_mirror *mirror)
{
	struct hmm *hmm = mirror->hmm;

	spin_lock(&hmm->lock);
	list_del_rcu(&mirror->list);
	spin_unlock(&hmm->lock);

	/*
	 * Wait for all active notifier so that it is safe to traverse mirror
	 * list without any lock.
	 */
	wait_event(hmm->wait_queue, !atomic_read(&hmm->notifier_count));

	hmm_put(hmm);
}
EXPORT_SYMBOL(hmm_mirror_unregister);


struct hmm_populate {
	struct hmm_mirror	*mirror;
	unsigned long		start;
	unsigned long		end;
	int			cookie;
	bool			fault;
	bool			write;
};

static bool hmm_populate_init(struct hmm_populate *populate,
			      struct hmm_mirror *mirror,
			      unsigned long start,
			      unsigned long end,
			      bool fault,
			      bool write)
{
	populate->mirror = mirror;
	populate->start = start;
	populate->end = end;
	populate->fault = fault;
	populate->write = write;

	return hmm_get_cookie(mirror->hmm, &populate->cookie);
}

static int hmm_populate_fault(struct vm_area_struct *vma,
			      struct gpt_walk *walk,
			      unsigned long addr,
			      unsigned long end,
			      void *private)
{
	struct hmm_populate *populate = private;
	struct hmm *hmm = populate->mirror->hmm;
	unsigned flags = FAULT_FLAG_ALLOW_RETRY;
	struct mm_struct *mm = hmm->mm;

	BUG_ON(mm != vma->vm_mm);

	if (!populate->fault)
		return 0;

	flags |= (populate->write) ? FAULT_FLAG_WRITE : 0;
	for (; addr < end; addr += PAGE_SIZE) {
		int r;

		r = handle_mm_fault(mm, vma, addr, flags);
		if (r & VM_FAULT_RETRY)
			return -EAGAIN;
		if (r & VM_FAULT_ERROR) {
			if (r & VM_FAULT_OOM)
				return -ENOMEM;
			/* Same error code for all other cases. */
			return -EFAULT;
		}
	}

	up_read(&mm->mmap_sem);
	return -EAGAIN;
}

static int hmm_populate_huge(struct vm_area_struct *vma,
			     struct gpt_walk *walk,
			     unsigned long addr,
			     unsigned long end,
			     spinlock_t *ptl,
			     spinlock_t *gtl,
			     struct page *page,
			     pte_t *ptep,
			     gte_t *gtep,
			     void *private)
{
	/* FIXME support huge page */
	return -EFAULT;
}

static int hmm_populate_pte(struct vm_area_struct *vma,
			    struct gpt_walk *walk,
			    unsigned long addr,
			    unsigned long end,
			    spinlock_t *ptl,
			    spinlock_t *gtl,
			    pte_t *ptep,
			    gte_t *gtep,
			    void *private)
{
	struct hmm_populate *populate = private;
	struct hmm *hmm = populate->mirror->hmm;
	struct mm_struct *mm = hmm->mm;

	BUG_ON(mm != vma->vm_mm);

	if (!populate->fault)
		return 0;

	spin_lock(ptl);
	spin_lock(gtl);
	do {
		unsigned long pfn;
		struct page *page;
		pte_t pte = *ptep;

		if (!hmm_check_cookie(hmm, populate->cookie)) {
			spin_unlock(gtl);
			spin_unlock(ptl);
			up_read(&mm->mmap_sem);
			return -EAGAIN;
		}

		if (!pte_present(pte)) {
			if (hmm_entry_is_valid(*gtep))
				atomic_dec(gpt_walk_gtd_refcount(walk, 0));
			*gtep = 0;
			if (populate->fault)
				goto fault;
			continue;
		}
		if (populate->fault && !pte_write(pte) && populate->write)
			goto fault;

		pfn = pte_pfn(pte);
		page = pfn_to_page(pfn);
		if (hmm_entry_is_valid(*gtep)) {
			BUG_ON(hmm_entry_to_page(*gtep) != page);
			continue;
		}

		*gtep = hmm_entry_from_page(page);
		atomic_inc(gpt_walk_gtd_refcount(walk, 0));
		if (!pte_numa(pte))
			*gtep = hmm_entry_set_read(*gtep);
		if (pte_write(pte))
			*gtep = hmm_entry_set_write(*gtep);
	} while (ptep++, gtep++, addr += PAGE_SIZE, addr != end);
	spin_unlock(gtl);
	spin_unlock(ptl);

	return 0;

fault:
	spin_unlock(gtl);
	spin_unlock(ptl);
	return hmm_populate_fault(vma, walk, addr, end, populate);
}

int hmm_mirror_range(struct hmm_mirror *mirror,
		     struct vm_area_struct *vma,
		     unsigned long start,
		     unsigned long end,
		     bool write,
		     bool fault)
{
	struct hmm_populate populate;
	struct mm_struct *mm;
	struct gpt_walk walk;
	struct hmm *hmm;
	int ret;

	/* Sanity check to catch broken user of HMM */
	start &= PAGE_MASK;
	end &= PAGE_MASK;
	BUG_ON(!mirror);
	BUG_ON(start >= end);
	BUG_ON(vma && vma->vm_mm != mirror->hmm->mm);
	BUG_ON(!rwsem_is_locked(&mirror->hmm->mm->mmap_sem));

	hmm = mirror->hmm;
	mm = hmm->mm;
	gpt_walk_init(&walk, hmm->gpt);

retry:
	/*
	 * We allow to be call without vma set in which case we can adjust the
	 * range. We still check vma in case it is provided and return error if
	 * range is not inside provided vma.
	 */
	if (!vma) {
		vma = find_vma_intersection(mm, start, end);
		if (!vma) {
			ret = -EFAULT;
			goto out;
		}
	}

	if (vma->vm_start > start) {
		ret = -ERANGE;
		goto out;
	}
	/* The end address is not fatal */
	end = min(end, vma->vm_end);

	if (!(vma->vm_flags & VM_READ)) {
		ret = -EPERM;
		goto out;
	}
	if (write && !(vma->vm_flags & VM_WRITE)) {
		ret = -EPERM;
		goto out;
	}
	/* Do not try to mirror special vma */
	if (vma->vm_flags & (VM_IO | VM_PFNMAP)) {
		ret = -EFAULT;
		goto out;
	}

	if (!hmm_populate_init(&populate, mirror, start, end, fault, write)) {
		up_read(&mm->mmap_sem);
		hmm_wait_cookie(hmm);
		down_read(&mm->mmap_sem);
		vma = NULL;
		goto retry;
	}

	ret = hmm_walk(vma, &hmm_populate_fault, &hmm_populate_huge,
		       &hmm_populate_pte, &walk, start, end, &populate);
	if (ret == -EAGAIN) {
		hmm_wait_cookie(hmm);
		down_read(&mm->mmap_sem);
		vma = NULL;
		goto retry;
	}

out:
	gpt_walk_fini(&walk);
	return ret;
}
EXPORT_SYMBOL(hmm_mirror_range);
