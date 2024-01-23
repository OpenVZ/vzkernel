/*
 * Low-level routines for marking dirty pages of a running system in a
 * bitmap.  Allows memory mirror or migration strategies to be implemented.
 *
 * Copyright (C) 2006, 2010 Stratus Technologies Bermuda Ltd.
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/sched.h>
#include <asm/atomic.h>
#include <asm/mm_track.h>
#include <asm/pgtable.h>
#include <asm/xen/page.h>

/*
 * For memory-tracking purposes, see mm_track.h for details.
 */
struct mm_tracker mm_tracking_struct = {STATIC_KEY_INIT_FALSE, ATOMIC_INIT(0), 0, 0};
EXPORT_SYMBOL_GPL(mm_tracking_struct);

#ifdef CONFIG_MEM_SOFT_DIRTY
struct harvest_clear_refs_private {
	struct vm_area_struct *vma;
};

/* Please remove if the upstream version is backported */
static inline pmd_t pmd_clear_soft_dirty(pmd_t pmd)
{
	return pmd_clear_flags(pmd, _PAGE_SOFT_DIRTY);
}

/* Please remove if the upstream version is backported */
static inline pte_t pte_clear_soft_dirty(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_SOFT_DIRTY);
}

static inline void harvest_clear_soft_dirty(struct vm_area_struct *vma,
					    unsigned long addr, pte_t *pte)
{
	/*
	 * The soft-dirty tracker uses #PF-s to catch writes
	 * to pages, so write-protect the pte as well. See the
	 * Documentation/vm/soft-dirty.txt for full description
	 * of how soft-dirty works.
	 */
	pte_t ptent = *pte;

	if (pte_present(ptent)) {
		ptent = ptep_modify_prot_start(vma->vm_mm, addr, pte);
		ptent = pte_wrprotect(ptent);
		ptent = pte_clear_soft_dirty(ptent);
		ptep_modify_prot_commit(vma->vm_mm, addr, pte, ptent);
	} else if (is_swap_pte(ptent)) {
		ptent = pte_swp_clear_soft_dirty(ptent);
		set_pte_at(vma->vm_mm, addr, pte, ptent);
	} else if (pte_file(ptent)) {
		ptent = pte_file_clear_soft_dirty(ptent);
		set_pte_at(vma->vm_mm, addr, pte, ptent);
	}
}

#if defined(CONFIG_TRANSPARENT_HUGEPAGE)
static void harvest_clear_soft_dirty_pmd(struct vm_area_struct *vma,
					 unsigned long addr, pmd_t *pmdp)
{
	/* mm_track in this call will see soft_dirty pages */
	pmd_t pmd = pmdp_get_and_clear(vma->vm_mm, addr, pmdp);

	pmd = pmd_wrprotect(pmd);
	pmd = pmd_clear_soft_dirty(pmd);

	set_pmd_at(vma->vm_mm, addr, pmdp, pmd);
}
#else
static void harvest_clear_soft_dirty_pmd(struct vm_area_struct *vma,
					 unsigned long addr, pmd_t *pmdp)
{
	do_mm_track_pmd(pmdp);
}
#endif

static int harvest_clear_refs_pte_range(pmd_t *pmd, unsigned long addr,
					unsigned long end, struct mm_walk *walk)
{
	struct harvest_clear_refs_private *cp = walk->private;
	struct vm_area_struct *vma = cp->vma;
	pte_t *pte;

	if (pmd_trans_huge(*pmd)) {
		harvest_clear_soft_dirty_pmd(vma, addr, pmd);
		return 0;
	}

	pte = pte_offset_map(pmd, addr);
	for (; addr != end; pte++, addr += PAGE_SIZE)
		harvest_clear_soft_dirty(vma, addr, pte);

	return 0;
}

static void mm_track_one_hugepage(struct vm_area_struct *vma, pte_t *pte)
{
	struct hstate *h = hstate_vma(vma);
	unsigned long addr, end;

	addr = pte_pfn(*pte) << PAGE_SHIFT;
	end = addr + huge_page_size(h);

	while (addr < end) {
		do_mm_track_phys((void *)addr);
		addr += PAGE_SIZE;
	}
}

static void mm_track_hugepage(struct vm_area_struct *vma)
{
	struct hstate *h = hstate_vma(vma);
	unsigned long hmask = huge_page_mask(h);
	unsigned long addr, next, boundary;
	pte_t *pte;

	addr = vma->vm_start;
	do {
		boundary = (addr & hmask) + huge_page_size(h);
		next = boundary < vma->vm_end ? boundary : vma->vm_end;
		pte = huge_pte_offset(vma->vm_mm, addr & hmask);
		if (pte)
			mm_track_one_hugepage(vma, pte);
	} while (addr = next, addr != vma->vm_end);
}

int  __attribute__ ((__unused__)) harvest_user(void)
{
	struct task_struct *p;
	struct mm_struct *mm;
	struct vm_area_struct *vma;

	for_each_process(p) {
		mm = get_task_mm(p);

		if (mm) {
			struct harvest_clear_refs_private cp;
			struct mm_walk harvest_clear_refs_walk = {
				.pmd_entry = harvest_clear_refs_pte_range,
				.mm = mm,
				.private = &cp,
			};

			for (vma = mm->mmap; vma; vma = vma->vm_next) {
				if (!(vma->vm_flags & VM_SOFTDIRTY))
					continue;
				for (vma = mm->mmap; vma; vma = vma->vm_next) {
					vma->vm_flags &= ~VM_SOFTDIRTY;
					vma_set_page_prot(vma);
				}
				break;
			}

			for (vma = mm->mmap; vma; vma = vma->vm_next) {
				cp.vma = vma;
				if (is_vm_hugetlb_page(vma)) {
					mm_track_hugepage(vma);
					continue;
				}
				if (vma->vm_flags & VM_PFNMAP)
					continue;
				walk_page_range(vma->vm_start, vma->vm_end,
						&harvest_clear_refs_walk);
			}

			mmput(mm);
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(harvest_user);
#endif /* CONFIG_MEM_SOFT_DIRTY */

void do_mm_track_pte(void *val)
{
	pte_t *ptep = (pte_t *)val;
	unsigned long pfn;

	if (!pte_present(*ptep))
		return;

	if (pte_val(*ptep) & _PAGE_USER) {
		if (!(pte_val(*ptep) & _PAGE_SOFT_DIRTY))
			return;
	} else {
		if (!(pte_val(*ptep) & _PAGE_DIRTY))
			return;
	}

	pfn = pte_pfn(*ptep);

	if (pfn >= mm_tracking_struct.bitcnt)
		return;

	if (!test_and_set_bit(pfn, mm_tracking_struct.vector))
		atomic_inc(&mm_tracking_struct.count);
}
EXPORT_SYMBOL_GPL(do_mm_track_pte);

static inline void track_as_pte(void *val)
{
	unsigned long pfn = pte_pfn(*(pte_t *)val);
	if (pfn >= mm_tracking_struct.bitcnt)
		return;

	if (!test_and_set_bit(pfn, mm_tracking_struct.vector))
		atomic_inc(&mm_tracking_struct.count);
}


#define LARGE_PMD_SIZE	(1 << PMD_SHIFT)

void do_mm_track_pmd(void *val)
{
	int i;
	pte_t *pte;
	pmd_t *pmd = (pmd_t *)val;

	if (!pmd_present(*pmd))
		return;

	if (unlikely(pmd_large(*pmd))) {
		/* If we're a hugepage then track all of the
		 * smallpages within that address range
		 */
		unsigned long addr, end;

		if (pmd_val(*pmd) & _PAGE_USER) {
			if (!(pmd_val(*pmd) & _PAGE_SOFT_DIRTY))
				return;
		} else {
			if (!(pmd_val(*pmd) & _PAGE_DIRTY))
				return;
		}

		addr = pmd_pfn(*pmd) << PAGE_SHIFT;
		end = addr + LARGE_PMD_SIZE;

		while (addr < end) {
			do_mm_track_phys((void *)addr);
			addr +=  PAGE_SIZE;
		}
	} else {
		/* Track ourselves, then track any pages
		 * we point to
		 */
		track_as_pte((void *)pmd);

		pte = pte_offset_kernel(pmd, 0);

		for (i = 0; i < PTRS_PER_PTE; i++, pte++)
			do_mm_track_pte(pte);
	}
}
EXPORT_SYMBOL_GPL(do_mm_track_pmd);

#define LARGE_PUD_SIZE (1 << PUD_SHIFT)

void do_mm_track_pud(void *val)
{
	int i;
	pmd_t *pmd;
	pud_t *pud = (pud_t *)val;

	if (!pud_present(*pud))
		return;

	if (unlikely(pud_large(*pud))) {
		/* If we're a hugepage then track all of the
		 * smallpages within that address range
		 */
		unsigned long addr, end;

		if (pud_val(*pud) & _PAGE_USER) {
			if (!(pud_val(*pud) & _PAGE_SOFT_DIRTY))
				return;
		} else {
			if (!(pud_val(*pud) & _PAGE_DIRTY))
				return;
		}

		addr = pud_pfn(*pud) << PAGE_SHIFT;
		end = addr + LARGE_PUD_SIZE;

		while (addr < end) {
			do_mm_track_phys((void *)addr);
			addr += PAGE_SIZE;
		}
	} else {
		/* Track ourselves, then track the next
		 * level down
		 */
		track_as_pte((void *)pud);

		pmd = pmd_offset(pud, 0);

		for (i = 0; i < PTRS_PER_PMD; i++, pmd++)
			do_mm_track_pmd(pmd);
	}
}

void do_mm_track_pgd(void *val)
{
	track_as_pte(val);
}

void do_mm_track_phys(void *val)
{
	unsigned long pfn;

	pfn = (unsigned long)val >> PAGE_SHIFT;

	if (pfn >= mm_tracking_struct.bitcnt)
		return;

	if (!test_and_set_bit(pfn, mm_tracking_struct.vector))
		atomic_inc(&mm_tracking_struct.count);
}
EXPORT_SYMBOL_GPL(do_mm_track_phys);


/*
 * Allocate enough space for the bit vector in the
 * mm_tracking_struct.
 */
int mm_track_init(long num_pages)
{
	mm_tracking_struct.vector = vmalloc((num_pages + 7)/8);
	if (mm_tracking_struct.vector == NULL) {
		printk(KERN_WARNING
		       "%s: failed to allocate bit vector\n", __func__);
		return -ENOMEM;
	}

	mm_tracking_struct.bitcnt = num_pages;

	return 0;
}
EXPORT_SYMBOL_GPL(mm_track_init);

/*
 * Turn off tracking, free the bit vector memory.  This function should
 * ONLY be called with interrupts disabled and all other CPUs quiesced
 */
void mm_track_exit(void)
{
	/*
	 * Inhibit the use of the tracking functions.
	 * This should have already been done, but just in case.
	 */
	if (static_key_enabled(&mm_tracking_struct.active))
		static_key_slow_dec(&mm_tracking_struct.active);
	else
		printk("mm_track_exit: tracking already off??!!\n");
	mm_tracking_struct.bitcnt = 0;

	if (mm_tracking_struct.vector != NULL)
		vfree(mm_tracking_struct.vector);
}
EXPORT_SYMBOL_GPL(mm_track_exit);
