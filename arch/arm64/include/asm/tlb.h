/*
 * Based on arch/arm/include/asm/tlb.h
 *
 * Copyright (C) 2002 Russell King
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_TLB_H
#define __ASM_TLB_H


#include <asm-generic/tlb.h>

static inline void tlb_flush(struct mmu_gather *tlb)
{
	if (tlb->fullmm) {
		flush_tlb_mm(tlb->mm);
	} else {
		struct vm_area_struct vma = { .vm_mm = tlb->mm, };
		flush_tlb_range(&vma, tlb->start, tlb->end);
	}
}

static inline void __pte_free_tlb(struct mmu_gather *tlb, pgtable_t pte,
				  unsigned long addr)
{
	pgtable_page_dtor(pte);
	tlb_remove_page(tlb, pte);
}

#ifndef CONFIG_ARM64_64K_PAGES
static inline void __pmd_free_tlb(struct mmu_gather *tlb, pmd_t *pmdp,
				  unsigned long addr)
{
	tlb_remove_page(tlb, virt_to_page(pmdp));
}
#endif

#endif
