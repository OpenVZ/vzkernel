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
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/atomic.h>
#include <asm/mm_track.h>
#include <asm/pgtable.h>
#include <asm/xen/page.h>

/*
 * For memory-tracking purposes, see mm_track.h for details.
 */
struct mm_tracker mm_tracking_struct = {STATIC_KEY_INIT_FALSE, ATOMIC_INIT(0), 0, 0};
EXPORT_SYMBOL_GPL(mm_tracking_struct);

void do_mm_track_pte(void *val)
{
	pte_t *ptep = (pte_t *)val;
	unsigned long pfn;

	if (!pte_present(*ptep))
		return;

	if (!(pte_val(*ptep) & _PAGE_DIRTY))
		return;

	pfn = pte_pfn(*ptep);

	if (pfn >= mm_tracking_struct.bitcnt)
		return;

	if (!test_and_set_bit(pfn, mm_tracking_struct.vector))
		atomic_inc(&mm_tracking_struct.count);
}

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

		if (!(pte_val(*(pte_t *)val) & _PAGE_DIRTY))
			return;

		addr = pte_pfn(*(pte_t *)val) << PAGE_SHIFT;
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

		/* Treat this as a PTE for purposes of checking
		 * the DIRTY bit...
		 */
		if (!(pte_val(*(pte_t *)val) & _PAGE_DIRTY))
			return;

		addr = pmd_pfn(*(pmd_t *)val) << PAGE_SHIFT;
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
