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
 * Refer to include/linux/hmm.h for informations about heterogeneous memory
 * management or HMM for short.
 */
#include <linux/mmu_notifier.h>
#include <linux/hmm_mirror.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hmm.h>

static bool _hmm_enabled = false;

static int hmm_gpt_invalidate_range(struct gpt_walk *walk,
				    unsigned long addr,
				    unsigned long end,
				    spinlock_t *gtl,
				    gte_t *gtep,
				    void *private)
{
	spin_lock(gtl);
	for (; addr < end; addr += PAGE_SIZE, gtep++) {
		if (hmm_entry_is_valid(*gtep)) {
			atomic_dec(gpt_walk_gtd_refcount(walk, 0));
			*gtep = 0;
		}
	}
	spin_unlock(gtl);

	return 0;
}

static void hmm_invalidate_range(struct hmm *hmm,
				 enum hmm_update update,
				 unsigned long start,
				 unsigned long end)
{
	struct hmm_mirror *mirror;
	struct gpt_walk walk;

	gpt_walk_init(&walk, hmm->gpt);
	gpt_walk_range(&walk, start, end, &hmm_gpt_invalidate_range, hmm);
	gpt_walk_fini(&walk);

	/*
	 * Mirror being added or remove is a rare event so list traversal isn't
	 * protected by a lock, we rely on simple rules. All list modification
	 * are done using list_add_rcu() and list_del_rcu() under a spinlock to
	 * protect from concurrent addition or removal but not traversal.
	 *
	 * Because hmm_mirror_unregister() wait for all running invalidation to
	 * complete (and thus all list traversal to finish). None of the mirror
	 * struct can be freed from under us while traversing the list and thus
	 * it is safe to dereference their list pointer even if they were just
	 * remove.
	 */
	list_for_each_entry (mirror, &hmm->mirrors, list) {
		mirror->ops->update(mirror, update, start, end);
	}
}

static void hmm_invalidate_page(struct mmu_notifier *mn,
				   struct mm_struct *mm,
				   unsigned long addr)
{
	unsigned long start = addr & PAGE_MASK;
	unsigned long end = start + PAGE_SIZE;
	struct hmm *hmm = mm->hmm;

	VM_BUG_ON(!hmm);

	atomic_inc(&hmm->notifier_count);
	smp_wmb();
	atomic_inc(&hmm->sequence);
	hmm_invalidate_range(mm->hmm, HMM_UPDATE_INVALIDATE, start, end);
	atomic_inc(&hmm->sequence);
	smp_wmb();
	atomic_dec(&hmm->notifier_count);
	wake_up(&hmm->wait_queue);
}

static void hmm_invalidate_range_start(struct mmu_notifier *mn,
				       struct mm_struct *mm,
				       unsigned long start,
				       unsigned long end)
{
	struct hmm *hmm = mm->hmm;

	VM_BUG_ON(!hmm);

	atomic_inc(&hmm->notifier_count);
	smp_wmb();
	atomic_inc(&hmm->sequence);
	hmm_invalidate_range(mm->hmm, HMM_UPDATE_INVALIDATE, start, end);
}

static void hmm_invalidate_range_end(struct mmu_notifier *mn,
				     struct mm_struct *mm,
				     unsigned long start,
				     unsigned long end)
{
	struct hmm *hmm = mm->hmm;

	VM_BUG_ON(!hmm);

	/* Reverse order here because we are getting out of invalidation */
	atomic_inc(&hmm->sequence);
	smp_wmb();
	atomic_dec(&hmm->notifier_count);
	wake_up(&hmm->wait_queue);
}

static const struct mmu_notifier_ops hmm_mmu_notifier_ops = {
	.invalidate_page	= hmm_invalidate_page,
	.invalidate_range_start	= hmm_invalidate_range_start,
	.invalidate_range_end	= hmm_invalidate_range_end,
};


static int hmm_init(struct hmm *hmm, struct mm_struct *mm)
{
	hmm->mm = mm;
	hmm->gpt = NULL;
	kref_init(&hmm->kref);
	spin_lock_init(&hmm->lock);
	hmm->mmu_notifier.ops = NULL;
	INIT_LIST_HEAD(&hmm->mirrors);
	INIT_LIST_HEAD(&hmm->migrates);
	atomic_set(&hmm->sequence, 0);
	atomic_set(&hmm->notifier_count, 0);
	init_waitqueue_head(&hmm->wait_queue);
	return 0;
}

struct hmm *hmm_register_mirror(struct mm_struct *mm,
				struct hmm_mirror *mirror)
{
	struct hmm *hmm;

	if (!_hmm_enabled)
		return NULL;

	spin_lock(&mm->page_table_lock);
again:
	if (!mm->hmm || !kref_get_unless_zero(&mm->hmm->kref)) {
		struct hmm *old;

		old = mm->hmm;
		spin_unlock(&mm->page_table_lock);

		hmm = kmalloc(sizeof(*hmm), GFP_KERNEL);
		if (!hmm)
			return NULL;
		if (hmm_init(hmm, mm)) {
			kfree(hmm);
			return NULL;
		}

		spin_lock(&mm->page_table_lock);
		if (old != mm->hmm) {
			kfree(hmm);
			goto again;
		}
		mm->hmm = hmm;
	} else
		hmm = mm->hmm;
	spin_unlock(&mm->page_table_lock);

	if (hmm && mirror && !hmm->mmu_notifier.ops) {
		hmm->mmu_notifier.ops = &hmm_mmu_notifier_ops;
		if (mmu_notifier_register(&hmm->mmu_notifier, mm)) {
			hmm_put(hmm);
			return NULL;
		}

		spin_lock(&hmm->lock);
		list_add_rcu(&mirror->list, &hmm->mirrors);
		spin_unlock(&hmm->lock);
	}

	if (hmm && mirror && !hmm->gpt) {
		hmm->gpt = gpt_alloc(0, TASK_SIZE,
				     HMM_ENTRY_PFN_SHIFT,
				     HMM_ENTRY_VALID);
		if (!hmm->gpt) {
			hmm_put(hmm);
			return NULL;
		}
	}

	return hmm;
}

struct hmm *hmm_register(struct mm_struct *mm)
{
	return hmm_register_mirror(mm, NULL);
}

static void hmm_release(struct kref *kref)
{
	struct hmm *hmm;

	hmm = container_of(kref, struct hmm, kref);

	if (hmm && hmm->mmu_notifier.ops)
		mmu_notifier_unregister(&hmm->mmu_notifier, hmm->mm);

	if (hmm->gpt) {
		hmm_invalidate_range(hmm, HMM_UPDATE_INVALIDATE, 0, TASK_SIZE);
		gpt_free(hmm->gpt);
	}

	spin_lock(&hmm->mm->page_table_lock);
	if (hmm->mm->hmm == hmm)
		hmm->mm->hmm = NULL;
	spin_unlock(&hmm->mm->page_table_lock);
	kfree(hmm);
}

void hmm_put(struct hmm *hmm)
{
	kref_put(&hmm->kref, &hmm_release);
}


static int hmm_walk_pmd(struct vm_area_struct *vma,
			hmm_walk_hole_t walk_hole,
			hmm_walk_huge_t walk_huge,
			hmm_walk_pte_t walk_pte,
			struct gpt_walk *walk,
			unsigned long addr,
			unsigned long end,
			void *private,
			pud_t *pudp)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long next;
	pmd_t *pmdp;

	/*
	 * As we are holding mmap_sem in read mode we know pmd can't morph into
	 * a huge one so it is safe to map pte and go over them.
	 */
	pmdp = pmd_offset(pudp, addr);
	do {
		spinlock_t *gtl, *ptl;
		unsigned long cend;
		pte_t *ptep;
		gte_t *gtep;
		int ret;

again:
		next = pmd_addr_end(addr, end);

		if (pmd_none(*pmdp)) {
			if (walk_hole) {
				ret = walk_hole(vma, walk, addr,
						next, private);
				if (ret)
					return ret;
			}
			continue;
		}

		/*
		 * TODO support THP, issue lie with mapcount and refcount to
		 * determine if page is pin or not.
		 */
		if (pmd_trans_huge(*pmdp)) {
			if (!pmd_trans_splitting(*pmdp))
				split_huge_page_pmd_mm(mm, addr, pmdp);
			goto again;
		}

		if (pmd_none_or_trans_huge_or_clear_bad(pmdp))
			goto again;

		do {
			gtep = gpt_walk_populate(walk, addr);
			if (!gtep)
				return -ENOMEM;
			gtl = gpt_walk_gtd_lock_ptr(walk, 0);
			cend = min(next, walk->end);

			ptl = pte_lockptr(mm, pmdp);
			ptep = pte_offset_map(pmdp, addr);
			ret = walk_pte(vma, walk, addr, cend, ptl,
				       gtl, ptep, gtep, private);
			pte_unmap(ptep);
			if (ret)
				return ret;

			addr = cend;
			cend = next;
		} while (addr < next);

	} while (pmdp++, addr = next, addr != end);

	return 0;
}

static int hmm_walk_pud(struct vm_area_struct *vma,
			hmm_walk_hole_t walk_hole,
			hmm_walk_huge_t walk_huge,
			hmm_walk_pte_t walk_pte,
			struct gpt_walk *walk,
			unsigned long addr,
			unsigned long end,
			void *private,
			pgd_t *pgdp)
{
	unsigned long next;
	pud_t *pudp;

	pudp = pud_offset(pgdp, addr);
	do {
		int ret;

		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pudp)) {
			if (walk_hole) {
				ret = walk_hole(vma, walk, addr,
						next, private);
				if (ret)
					return ret;
			}
			continue;
		}

		ret = hmm_walk_pmd(vma, walk_hole, walk_huge, walk_pte,
				   walk, addr, next, private, pudp);
		if (ret)
			return ret;

	} while (pudp++, addr = next, addr != end);

	return 0;
}

int hmm_walk(struct vm_area_struct *vma,
	     hmm_walk_hole_t walk_hole,
	     hmm_walk_huge_t walk_huge,
	     hmm_walk_pte_t walk_pte,
	     struct gpt_walk *walk,
	     unsigned long start,
	     unsigned long end,
	     void *private)
{
	unsigned long addr = start, next;
	pgd_t *pgdp;

	pgdp = pgd_offset(vma->vm_mm, addr);
	do {
		int ret;

		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgdp)) {
			if (walk_hole) {
				ret = walk_hole(vma, walk, addr,
						next, private);
				if (ret)
					return ret;
			}
			continue;
		}

		ret = hmm_walk_pud(vma, walk_hole, walk_huge, walk_pte,
				   walk, addr, next, private, pgdp);
		if (ret)
			return ret;

	} while (pgdp++, addr = next, addr != end);

	return 0;
}
EXPORT_SYMBOL(hmm_walk);

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
