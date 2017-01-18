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
 * This is the code for heterogeneous memory management (HMM) migration. Which
 * provide different approach to memory migration than existing migrate.c code.
 *
 * Refer to include/linux/hmm_migrate.h for further informations.
 */
#include <linux/mm.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/hmm_migrate.h>
#include <linux/mmu_notifier.h>
#include <asm/tlbflush.h>

#include "internal.h"


static void hmm_migrate_release(struct kref *kref)
{
	struct hmm_migrate *migrate;
	struct hmm *hmm;

	migrate = container_of(kref, struct hmm_migrate, kref);
	BUG_ON(!list_empty(&migrate->list));
	hmm = migrate->hmm;
	kfree(migrate);
	hmm_put(hmm);
}

static inline bool hmm_migrate_get(struct hmm_migrate *migrate)
{
	return kref_get_unless_zero(&migrate->kref);
}

static inline void hmm_migrate_put(struct hmm_migrate *migrate)
{
	kref_put(&migrate->kref, &hmm_migrate_release);
}


static inline bool hmm_migrate_overlap(struct hmm_migrate *a,
				       struct hmm_migrate *b)
{
	return !(a->start >= b->end || a->end <= b->start);
}

static int hmm_migrate_alloc(struct hmm_migrate **migratep,
			     const struct hmm_migrate_ops *ops,
			     struct vm_area_struct *vma,
			     unsigned long start,
			     unsigned long end,
			     struct gpt *gpt,
			     void *private)
{
	struct hmm_migrate *migrate, *tmp;
	struct mm_struct *mm = vma->vm_mm;
	int ret;

	start &= PAGE_MASK;
	end &= PAGE_MASK;
	if (start >= end)
		return -EINVAL;

	if (gpt && (gpt->valid_bit != HMM_ENTRY_VALID ||
		    gpt->shift != HMM_ENTRY_PFN_SHIFT))
		return -EINVAL;

	migrate = kmalloc(sizeof(*migrate), GFP_KERNEL);
	if (!migrate)
		return -ENOMEM;

	INIT_LIST_HEAD(&migrate->list);
	kref_init(&migrate->kref);
	init_waitqueue_head(&migrate->wait_queue);
	migrate->cpages = 0;
	migrate->ops = ops;
	migrate->start = start;
	migrate->end = end;
	migrate->gpt = gpt;
	migrate->private = private;

	if (!migrate->gpt) {
		migrate->gpt = gpt_alloc(start, end,
					 HMM_ENTRY_PFN_SHIFT,
					 HMM_ENTRY_VALID);
		if (!migrate->gpt) {
			ret = -ENOMEM;
			goto error;
		}
	}

	migrate->hmm = hmm_register(mm);
	if (!migrate->hmm) {
		ret = -EINVAL;
		goto error;
	}

	spin_lock(&migrate->hmm->lock);
	list_for_each_entry (tmp, &migrate->hmm->migrates, list) {
		if (hmm_migrate_overlap(migrate, tmp)) {
			spin_unlock(&migrate->hmm->lock);
			hmm_put(migrate->hmm);
			ret = -EINVAL;
			goto error;
		}
	}
	list_add_tail(&migrate->list, &migrate->hmm->migrates);
	spin_unlock(&migrate->hmm->lock);

	*migratep = migrate;
	return 0;

error:
	if (!gpt && migrate->gpt)
		gpt_free(migrate->gpt);
	kfree(migrate);
	return ret;
}

static void hmm_migrate_fini(struct hmm_migrate *migrate)
{
	spin_lock(&migrate->hmm->lock);
	list_del_init(&migrate->list);
	spin_unlock(&migrate->hmm->lock);

	/* Wake up anyone who might have been waiting. */
	wake_up(&migrate->wait_queue);

	hmm_migrate_put(migrate);
}


static int hmm_migrate_unmap(struct vm_area_struct *vma,
			     struct gpt_walk *walk,
			     unsigned long addr,
			     unsigned long end,
			     spinlock_t *ptl,
			     spinlock_t *gtl,
			     pte_t *ptep,
			     gte_t *gtep,
			     void *private)
{
	struct hmm_migrate *migrate = private;
	struct mm_struct *mm = vma->vm_mm;

	/*
	 * Flush cache even if we don't flush tlb, this for weird CPU arch for
	 * which HMM probably will never be use.
	 */
	flush_cache_range(vma, addr, end);

	spin_lock(ptl);
	spin_lock(gtl);
	arch_enter_lazy_mmu_mode();
	do {
		struct page *spage;
		pte_t pte = *ptep;
		swp_entry_t swap;

		*gtep = 0;

		/*
		 * We clear the PTE but do not flush so potentially a remote
		 * CPU could still be writing to the page. If the entry was
		 * previously clean then the architecture must guarantee that
		 * a clear->dirty transition on a cached TLB entry is written
		 * through and traps if the PTE is unmapped.
		 */
		pte = ptep_get_and_clear(mm, addr, ptep);

		if (!pte_present(pte)) {
			set_pte_at(vma->vm_mm, addr, ptep, pte);
			continue;
		}

		/* FIXME handle zero page, ksm page, THP page, ... */
		spage = vm_normal_page(vma, addr, pte);
		if (!spage || PageCompound(spage) || !PageAnon(spage) ||
		    PageError(spage) || PageKsm(spage)) {
			set_pte_at(vma->vm_mm, addr, ptep, pte);
			continue;
		}

		/* FIXME skip COW pages, we should break COW but leave this for
		 * latter.
		 */
		if (page_mapcount(spage) > 1) {
			set_pte_at(vma->vm_mm, addr, ptep, pte);
			continue;
		}

		/*
		 * Check that page is not pin ie no one did call get_user_pages
		 * (GUP) note that because we did not flush tlb yet then a race
		 * with get_user_pages_fast (GUP_fast) is possible hence why we
		 * perform same check after tlb flush.
		 *
		 * Here this is an anonymous page, for which we expect only one
		 * mapping (we do not want to handle COW page for now).
		 *
		 * Note that if page is not on the LRU list then its reference
		 * count is 2 (1 for CPU page table entry and 1 for whatever
		 * owns the page while not on LRU). We could use PageLRU() to
		 * detect that and still proceed with migration, for now just
		 * skip those pages.
		 */
		/* FIXME how do we want to proceed with COW pages ? */
		if (page_count(spage) != 1) {
			set_pte_at(vma->vm_mm, addr, ptep, pte);
			continue;
		}

		flush_cache_page(vma, addr, page_to_pfn(spage));
		get_page(spage);

		migrate->cpages++;
		atomic_inc(gpt_walk_gtd_refcount(walk, 0));

		*gtep = hmm_entry_set_migrate(*gtep);
		if (!pte_numa(pte))
			*gtep = hmm_entry_set_read(*gtep);
		if (pte_dirty(pte))
			*gtep = hmm_entry_set_dirty(*gtep);
		if (pte_write(pte))
			*gtep = hmm_entry_set_write(*gtep);
		if (trylock_page(spage))
			*gtep = hmm_entry_set_locked(*gtep);

		/*
		 * No tlb flush here, we will flush tlb latter on when we know
		 * for sure we are migrating.
		 */
		swap = make_hmm_entry(page_to_pfn(spage), HMM_SWP_PAGE);
		if (pte_soft_dirty(pte)) {
			pte = swp_entry_to_pte(swap);
			pte = pte_swp_mksoft_dirty(pte);
		} else
			pte = swp_entry_to_pte(swap);
		set_pte_at(vma->vm_mm, addr, ptep, pte);
		hmm_migrate_get(migrate);
		BUG_ON(pte_file(*ptep));

	} while (ptep++, gtep++, addr += PAGE_SIZE, addr != end);
	arch_leave_lazy_mmu_mode();
	spin_unlock(gtl);
	spin_unlock(ptl);

	return 0;
}


static int hmm_migrate_isolate(struct vm_area_struct *vma,
			       struct gpt_walk *walk,
			       unsigned long addr,
			       unsigned long end,
			       spinlock_t *ptl,
			       spinlock_t *gtl,
			       pte_t *ptep,
			       gte_t *gtep,
			       void *private)
{
	struct hmm_migrate *migrate = private;

	if (!migrate->cpages)
		return 0;

	do {
		struct page *spage;
		pte_t pte = *ptep;
		swp_entry_t swap;

		if (pte_present(pte) || pte_file(pte))
			continue;

		swap = pte_to_swp_entry(pte);
		if (!is_hmm_entry(swap) || !hmm_entry_is_migrate(*gtep))
			continue;

		spage = hmm_swp_entry_to_page(swap);
		VM_BUG_ON(!spage);

		if (!hmm_entry_is_locked(*gtep)) {
			/*
			 * If we still can not lock the page then just avoid
			 * migrating it. We do not want to stall on page lock.
			 */
			if (!trylock_page(spage)) {
				*gtep = hmm_entry_clear_migrate(*gtep);
				if (!(--migrate->cpages))
					break;
				continue;
			}
			/* FIXME locking is probably overkill here. */
			spin_lock(gtl);
			*gtep = hmm_entry_set_locked(*gtep);
			spin_unlock(gtl);
		}

		if (isolate_lru_page(spage)) {
			*gtep = hmm_entry_clear_migrate(*gtep);
			if (!(--migrate->cpages))
				break;
			continue;
		}

		/* FIXME locking is probably overkill here. */
		spin_lock(gtl);
		*gtep = hmm_entry_set_isolated(*gtep);
		spin_unlock(gtl);

	} while (ptep++, gtep++, addr += PAGE_SIZE, addr != end);

	return 0;
}


static int hmm_migrate_check(struct vm_area_struct *vma,
			     struct gpt_walk *walk,
			     unsigned long addr,
			     unsigned long end,
			     spinlock_t *ptl,
			     spinlock_t *gtl,
			     pte_t *ptep,
			     gte_t *gtep,
			     void *private)
{
	struct hmm_migrate *migrate = private;

	if (!migrate->cpages)
		return 0;

	do {
		struct page *spage, *dpage;
		struct mem_cgroup *memcg;
		pte_t pte = *ptep;
		swp_entry_t swap;

		if (pte_present(pte) || pte_file(pte))
			continue;

		swap = pte_to_swp_entry(pte);
		if (!is_hmm_entry(swap) || !hmm_entry_is_migrate(*gtep))
			continue;

		spage = hmm_swp_entry_to_page(swap);
		VM_BUG_ON(!spage);

		dpage = hmm_entry_to_page(*gtep);
		if (!dpage) {
			/* FIXME locking is probably overkill here. */
			spin_lock(gtl);
			*gtep = hmm_entry_clear_migrate(*gtep);
			spin_unlock(gtl);
			/*
			 * Do not decrement cpages, assume >page_alloc() forgot
			 * to clear the migrate flag on source entry but didn't
			 * accounted this page in cpages count.
			 *
			 * If it did accounted the page then we are wasting CPU
			 * cycles but nothing bad will happen.
			 */
			continue;
		}

		/*
		 * Here we can no longer race with get_user_pages_fast as tlb
		 * have been flush (-> IPI -> GUP_fast exited).
		 *
		 * Anonymous page only, one refcount for mapping, another one
		 * from isolate_lru_page() and one because we did get_page().
		 */
		/* FIXME THP support require more magic for refcount */
		if (page_count(spage) != 3) {
			/* FIXME locking is probably overkill here. */
			spin_lock(gtl);
			*gtep  = hmm_entry_clear_migrate(*gtep);
			spin_unlock(gtl);
			if (!(--migrate->cpages))
				break;
			continue;
		}

		/* FIXME check dpage is locked or BUG_ON() ? */

		dpage->index = spage->index;
		dpage->mapping = spage->mapping;
		if (PageSwapBacked(spage))
			SetPageSwapBacked(dpage);

		mem_cgroup_prepare_migration(spage, dpage, &memcg);
		dpage->mapping = (void *)memcg;
		*gtep = hmm_entry_set_memcg(*gtep);
	} while (ptep++, gtep++, addr += PAGE_SIZE, addr != end);

	return 0;
}


/* FIXME factor out into common code to share with migrate */
static void migrate_page(struct page *page, struct page *newpage)
{
	int cpupid;

	if (PageError(page))
		SetPageError(newpage);
	if (PageReferenced(page))
		SetPageReferenced(newpage);
	if (PageUptodate(page))
		SetPageUptodate(newpage);
	if (TestClearPageActive(page)) {
		VM_BUG_ON_PAGE(PageUnevictable(page), page);
		SetPageActive(newpage);
	} else if (TestClearPageUnevictable(page))
		SetPageUnevictable(newpage);
	if (PageChecked(page))
		SetPageChecked(newpage);
	if (PageMappedToDisk(page))
		SetPageMappedToDisk(newpage);

	/* Move dirty on pages not done by migrate_page_move_mapping() */
	if (PageDirty(page))
		SetPageDirty(newpage);

	/*
	 * Copy NUMA information to the new page, to prevent over-eager
	 * future migrations of this same page.
	 */
	cpupid = page_cpupid_xchg_last(page, -1);
	page_cpupid_xchg_last(newpage, cpupid);

	ksm_migrate_page(newpage, page);
	/*
	 * Please do not reorder this without considering how mm/ksm.c's
	 * get_ksm_page() depends upon ksm_migrate_page() and PageSwapCache().
	 */
	if (PageSwapCache(page))
		ClearPageSwapCache(page);
	ClearPagePrivate(page);
	set_page_private(page, 0);

	/*
	 * If any waiters have accumulated on the new page then
	 * wake them up.
	 */
	if (PageWriteback(newpage))
		end_page_writeback(newpage);
}

static int hmm_migrate_finalize(struct vm_area_struct *vma,
				struct gpt_walk *walk,
				unsigned long addr,
				unsigned long end,
				spinlock_t *ptl,
				spinlock_t *gtl,
				pte_t *ptep,
				gte_t *gtep,
				void *private)
{
	struct hmm_migrate *migrate = private;

	if (!migrate->cpages)
		return 0;

	/* No need to lock nothing can change from under us */
	do {
		struct page *spage, *dpage;
		pte_t pte = *ptep;
		swp_entry_t swap;

		if (pte_present(pte) || pte_file(pte))
			continue;

		swap = pte_to_swp_entry(pte);
		if (!is_hmm_entry(swap) || !hmm_entry_is_migrate(*gtep))
			continue;

		spage = hmm_swp_entry_to_page(swap);
		VM_BUG_ON(!spage);
		dpage = hmm_entry_to_page(*gtep);
		VM_BUG_ON(!dpage);

		migrate_page(spage, dpage);
	} while (ptep++, gtep++, addr += PAGE_SIZE, addr != end);

	return 0;
}


static int hmm_migrate_cleanup(struct vm_area_struct *vma,
			       struct gpt_walk *walk,
			       unsigned long addr,
			       unsigned long end,
			       spinlock_t *ptl,
			       spinlock_t *gtl,
			       pte_t *ptep,
			       gte_t *gtep,
			       void *private)
{
	spin_lock(ptl);
	spin_lock(gtl);
	arch_enter_lazy_mmu_mode();
	do {
		struct page *spage, *dpage = NULL;
		pte_t pte = *ptep;
		swp_entry_t swap;

		if (pte_present(pte) || pte_file(pte))
			continue;

		swap = pte_to_swp_entry(pte);
		if (!is_hmm_entry(swap))
			continue;
		spage = hmm_swp_entry_to_page(swap);
		VM_BUG_ON(!spage);

		dpage = hmm_entry_to_page(*gtep);
		if (hmm_entry_is_memcg(*gtep)) {
			struct mem_cgroup *memcg;

			memcg = (struct mem_cgroup *)dpage->mapping;
			dpage->mapping = NULL;
			mem_cgroup_end_migration(memcg, spage, dpage,
					         hmm_entry_is_migrate(*gtep));
		}

		if (hmm_entry_is_migrate(*gtep)) {
			VM_BUG_ON(!spage);

			/* Map dst page and do anon_vma dance. */
			page_add_anon_rmap(dpage, vma, addr);
			pte = pte_mkold(mk_pte(dpage, vma->vm_page_prot));
			flush_dcache_page(dpage);
			get_page(dpage);

			/* FIXME handle THP once we support it */
			page_remove_rmap(spage);
			put_page(spage);
		} else
			pte = pte_mkold(mk_pte(spage, vma->vm_page_prot));

		if (hmm_entry_is_write(*gtep))
			pte = maybe_mkwrite(pte, vma);

		if (hmm_entry_is_dirty(*gtep))
			pte = pte_mkdirty(pte);
		if (pte_swp_soft_dirty(*ptep))
			pte = pte_mksoft_dirty(pte);

		/* No need to invalidate - it was non-present before */
		set_pte_at(vma->vm_mm, addr, ptep, pte);
		update_mmu_cache(vma, addr, ptep);

		/* Unlock source page and add it back to lru list */
		if  (hmm_entry_is_locked(*gtep)) {
			*gtep = hmm_entry_clear_locked(*gtep);
			unlock_page(spage);
		}
		if  (hmm_entry_is_isolated(*gtep)) {
			*gtep = hmm_entry_clear_isolated(*gtep);
			/* FIXME put page on list to do putback in bulk */
			spin_unlock(gtl);
			spin_unlock(ptl);
			putback_lru_page(spage);
			spin_lock(ptl);
			spin_lock(gtl);
		}
		put_page(spage);

		/* Same for destination page */
		if (!dpage) {
			atomic_dec(gpt_walk_gtd_refcount(walk, 0));
			*gtep = 0;
			continue;
		}
		unlock_page(dpage);

		/*
		 * FIXME do we want dst page to be added to lru list ?
		 * Some device memory backed by struct page might like
		 * to avoid this. So we likely will want to add a flag
		 * to know if we should add to lru or not.
		 */
		if (hmm_entry_is_migrate(*gtep)) {
			get_page(dpage);
			/* FIXME put page on list to do putback in bulk */
			spin_unlock(gtl);
			spin_unlock(ptl);
			putback_lru_page(dpage);
			spin_lock(ptl);
			spin_lock(gtl);
		}
		put_page(dpage);

		atomic_dec(gpt_walk_gtd_refcount(walk, 0));
		*gtep = 0;

	} while (ptep++, gtep++, addr += PAGE_SIZE, addr != end);
	arch_leave_lazy_mmu_mode();
	spin_unlock(gtl);
	spin_unlock(ptl);

	return 0;
}


/* hmm_migrate() - migrate memory backing a range of virtual address
 * @ops: pointer to migrate operations callback
 * @vma: pointer to vma to which the range belong
 * @start: start address of the range to migrate (inclusive)
 * @end: end address of the range to migrate (exclusive)
 * @gpt: generic page table use during migration to track destination memory
 * @private: pointer to private structure for callback use
 *
 * This function will migrate memory backing a range of virtual address to new
 * memory allocated through a callback pointer in the hmm_migrate struct. Copy
 * is also done through a callback allowing to use DMA engine to copy pages in
 * bulk. This two aspects is what differentiate hmm_migrate from the existing
 * migration code.
 *
 * Moreover it does also allow to migrate (only private anonymous memory for
 * time being) to device private memory unaccesible by the CPU. If CPU try to
 * access the range again it will trigger a migration back to visible CPU
 * memory. Allocation being under the control of the callback provide during
 * the first migration to device memory.
 *
 * WARNING YOU MUST HOLD mmap_sem IN READ MODE AT LEAST WHICH ALSO IMPLY THAT
 * YOU HOLD A PIN ON THE mm struct (mm->mm_users through get_task_mm()).
 *
 * Note current implementation only support subset of private anonymous memory
 * (non special page, non THP, non KSM). Plans is to first support THP/KSM/zero
 * page, then to support share memory and latter to support filesystem.
 *
 * Note gpt can be NULL in which case it will be allocated and free before this
 * function returns.
 */
int hmm_migrate(const struct hmm_migrate_ops *ops,
		struct vm_area_struct *vma,
		unsigned long start,
		unsigned long end,
		struct gpt *gpt,
		void *private)
{
	struct hmm_migrate *migrate;
	struct gpt_walk walk;
	struct mm_struct *mm;
	int ret;

	/* Sanity check */
	if (!vma || !ops)
		return -EINVAL;
	start &= PAGE_MASK;
	end &= PAGE_MASK;
	if (start >= end || start < vma->vm_start || end > vma->vm_end)
		return -ERANGE;
	mm = vma->vm_mm;

	/* Sanity check the vma before trying to allocate a migrate struct */
	if (vma->vm_file)
		return -EINVAL;
	if (is_vm_hugetlb_page(vma))
		return -EINVAL;
	if (unlikely(anon_vma_prepare(vma)))
		return -ENOMEM;

	ret = hmm_migrate_alloc(&migrate, ops, vma, start, end, gpt, private);
	if (ret)
		return ret;

	gpt_walk_init(&walk, migrate->gpt);

	/* First we unmap from our target mm */
	update_hiwater_rss(mm);
	ret = hmm_walk(vma, NULL, NULL, &hmm_migrate_unmap,
		       &walk, start, end, migrate);
	if (ret || !migrate->cpages)
		goto out;

	/* Lock and isolate source pages */
	lru_add_drain();
	ret = hmm_walk(vma, NULL, NULL, &hmm_migrate_isolate,
		       &walk, start, end, migrate);
	if (ret || !migrate->cpages)
		goto out;

	/* Now allocate destination memory */
	ops->page_alloc(migrate, vma);
	if (!migrate->cpages)
		goto cleanup;

	/* We have something to migrate so flush tlb and invalidate */
	mmu_notifier_invalidate_range_start(mm, migrate->start, migrate->end);
	mmu_notifier_invalidate_range(mm, migrate->start, migrate->end);
	mmu_notifier_invalidate_range_end(mm, migrate->start, migrate->end);
	flush_tlb_range(vma, migrate->start, migrate->end);
	clear_tlb_flush_pending(mm);

	/* Perform final checks and preparations before copy */
	ret = hmm_walk(vma, NULL, NULL, &hmm_migrate_check,
		       &walk, start, end, migrate);
	if (ret || !migrate->cpages)
		goto cleanup;

	/*
	 * Time to copy things, callback must set HMM_PTE_MIGRATE on dst entry
	 * successfully copied.
	 */
	ops->copy(migrate, vma);
	if (!migrate->cpages)
		goto cleanup;

	/* Migrate struct page informations */
	ret = hmm_walk(vma, NULL, NULL, &hmm_migrate_finalize,
		       &walk, start, end, migrate);

cleanup:
	ret = hmm_walk(vma, NULL, NULL, &hmm_migrate_cleanup,
		       &walk, start, end, migrate);

	if (ops->page_free)
		ops->page_free(migrate);

out:
	gpt_walk_fini(&walk);
	if (!gpt && migrate->gpt)
		gpt_free(migrate->gpt);
	hmm_migrate_fini(migrate);

	return ret;
}
EXPORT_SYMBOL(hmm_migrate);

static struct hmm_migrate *hmm_migrate_get_from_addr(struct vm_area_struct *vma,
						     unsigned long addr,
						     swp_entry_t entry,
						     pmd_t *pmdp)
{
	struct mm_struct *mm = vma->vm_mm;
	struct hmm_migrate *migrate;
	struct hmm *hmm = mm->hmm;
	spinlock_t *ptl;
	pte_t *ptep;

	ptep = pte_offset_map_lock(mm, pmdp, addr, &ptl);
	if (!is_swap_pte(*ptep)) {
		pte_unmap_unlock(ptep, ptl);
		return NULL;
	}

	if (!pte_same(swp_entry_to_pte(entry), *ptep)) {
		pte_unmap_unlock(ptep, ptl);
		return NULL;
	}

	if (!hmm) {
		pte_unmap_unlock(ptep, ptl);
		return NULL;
	}

	/* The HMM struct can not vanish while there is valid HMM entry */
	spin_lock(&hmm->lock);
	list_for_each_entry (migrate, &hmm->migrates, list) {
		if (addr >= migrate->end || addr < migrate->start)
			continue;

		if (!hmm_migrate_get(migrate))
			migrate = NULL;
		spin_unlock(&hmm->lock);
		pte_unmap_unlock(ptep, ptl);
		return migrate;
	}
	spin_unlock(&hmm->lock);
	pte_unmap_unlock(ptep, ptl);

	return NULL;
}

int hmm_migrate_fault(struct vm_area_struct *vma,
		      unsigned long addr,
		      swp_entry_t entry,
		      pmd_t *pmdp)
{
	struct hmm_migrate *migrate;

	if (!is_hmm_entry(entry))
		return 0;

	if (is_hmm_entry_poisonous(entry))
		return VM_FAULT_SIGBUS;

	migrate = hmm_migrate_get_from_addr(vma, addr, entry, pmdp);
	if (!migrate)
		return 0;

	wait_event(migrate->wait_queue, list_empty(&migrate->list));
	hmm_migrate_put(migrate);
	return 0;
}
