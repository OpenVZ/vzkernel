#ifndef _ASM_X86_PGTABLE_64_H
#define _ASM_X86_PGTABLE_64_H

#include <linux/const.h>
#include <linux/kaiser.h>
#include <asm/pgtable_64_types.h>

#ifndef __ASSEMBLY__

/*
 * This file contains the functions and defines necessary to modify and use
 * the x86-64 page table tree.
 */
#include <asm/processor.h>
#include <linux/bitops.h>
#include <linux/threads.h>
#include <asm/mm_track.h>

extern pud_t level3_kernel_pgt[512];
extern pud_t level3_ident_pgt[512];
extern pmd_t level2_kernel_pgt[512];
extern pmd_t level2_fixmap_pgt[512];
extern pmd_t level2_ident_pgt[512];
extern pte_t level1_fixmap_pgt[512];
extern pgd_t init_level4_pgt[];

#define swapper_pg_dir init_level4_pgt

extern void paging_init(void);

#define pte_ERROR(e)					\
	pr_err("%s:%d: bad pte %p(%016lx)\n",		\
	       __FILE__, __LINE__, &(e), pte_val(e))
#define pmd_ERROR(e)					\
	pr_err("%s:%d: bad pmd %p(%016lx)\n",		\
	       __FILE__, __LINE__, &(e), pmd_val(e))
#define pud_ERROR(e)					\
	pr_err("%s:%d: bad pud %p(%016lx)\n",		\
	       __FILE__, __LINE__, &(e), pud_val(e))
#define pgd_ERROR(e)					\
	pr_err("%s:%d: bad pgd %p(%016lx)\n",		\
	       __FILE__, __LINE__, &(e), pgd_val(e))

struct mm_struct;

void set_pte_vaddr_pud(pud_t *pud_page, unsigned long vaddr, pte_t new_pte);


static inline void native_pte_clear(struct mm_struct *mm, unsigned long addr,
				    pte_t *ptep)
{
	mm_track_pte(ptep);
	*ptep = native_make_pte(0);
}

static inline void native_set_pte(pte_t *ptep, pte_t pte)
{
	mm_track_pte(ptep);
	*ptep = pte;
}

static inline void native_set_pte_atomic(pte_t *ptep, pte_t pte)
{
	native_set_pte(ptep, pte);
}

static inline void native_set_pmd(pmd_t *pmdp, pmd_t pmd)
{
	mm_track_pmd(pmdp);
	*pmdp = pmd;
}

static inline void native_pmd_clear(pmd_t *pmd)
{
	native_set_pmd(pmd, native_make_pmd(0));
}

static inline pte_t native_ptep_get_and_clear(pte_t *xp)
{
	mm_track_pte(xp);
#ifdef CONFIG_SMP
	return native_make_pte(xchg(&xp->pte, 0));
#else
	/* native_local_ptep_get_and_clear,
	   but duplicated because of cyclic dependency */
	pte_t ret = *xp;
	native_pte_clear(NULL, 0, xp);
	return ret;
#endif
}

static inline pmd_t native_pmdp_get_and_clear(pmd_t *xp)
{
	mm_track_pmd(xp);
#ifdef CONFIG_SMP
	return native_make_pmd(xchg(&xp->pmd, 0));
#else
	/* native_local_pmdp_get_and_clear,
	   but duplicated because of cyclic dependency */
	pmd_t ret = *xp;
	native_pmd_clear(xp);
	return ret;
#endif
}

static inline void native_set_pud(pud_t *pudp, pud_t pud)
{
	mm_track_pud(pudp);
	*pudp = pud;
}

static inline void native_pud_clear(pud_t *pud)
{
	native_set_pud(pud, native_make_pud(0));
}

static inline pud_t native_pudp_get_and_clear(pud_t *xp)
{
#ifdef CONFIG_SMP
	return native_make_pud(xchg(&xp->pud, 0));
#else
	/* native_local_pudp_get_and_clear,
	 * but duplicated because of cyclic dependency
	 */
	pud_t ret = *xp;

	native_pud_clear(xp);
	return ret;
#endif
}

#ifdef CONFIG_KAISER
/*
 * All top-level KAISER page tables are order-1 pages (8k-aligned
 * and 8k in size).  The kernel one is at the beginning 4k and
 * the user (shadow) one is in the last 4k.  To switch between
 * them, you just need to flip the 12th bit in their addresses.
 */
#define KAISER_PGTABLE_SWITCH_BIT	PAGE_SHIFT

/*
 * This generates better code than the inline assembly in
 * __set_bit().
 */
static inline void *ptr_set_bit(void *ptr, int bit)
{
	unsigned long __ptr = (unsigned long)ptr;

	__ptr |= (1<<bit);
	return (void *)__ptr;
}
static inline void *ptr_clear_bit(void *ptr, int bit)
{
	unsigned long __ptr = (unsigned long)ptr;

	__ptr &= ~(1<<bit);
	return (void *)__ptr;
}

static inline pgd_t *kernel_to_shadow_pgdp(pgd_t *pgdp)
{
	return ptr_set_bit(pgdp, KAISER_PGTABLE_SWITCH_BIT);
}
static inline pgd_t *shadow_to_kernel_pgdp(pgd_t *pgdp)
{
	return ptr_clear_bit(pgdp, KAISER_PGTABLE_SWITCH_BIT);
}
#endif /* CONFIG_KAISER */

/*
 * Page table pages are page-aligned.  The lower half of the top
 * level is used for userspace and the top half for the kernel.
 *
 * Returns true for parts of the PGD that map userspace and
 * false for the parts that map the kernel.
 */
static inline bool pgdp_maps_userspace(void *__ptr)
{
	unsigned long ptr = (unsigned long)__ptr;

	return (ptr & ~PAGE_MASK) < (PAGE_SIZE / 2);
}

/*
 * Does this PGD allow access from userspace?
 */
static inline bool pgd_userspace_access(pgd_t pgd)
{
	return pgd.pgd & _PAGE_USER;
}

static inline void kaiser_poison_pgd(pgd_t *pgd)
{
	if (pgd->pgd & _PAGE_PRESENT && __supported_pte_mask & _PAGE_NX)
		pgd->pgd |= _PAGE_NX;
}

static inline void kaiser_unpoison_pgd(pgd_t *pgd)
{
	if (pgd->pgd & _PAGE_PRESENT && __supported_pte_mask & _PAGE_NX)
		pgd->pgd &= ~_PAGE_NX;
}

static inline void kaiser_poison_pgd_atomic(pgd_t *pgd)
{
	BUILD_BUG_ON(_PAGE_NX == 0);
	if (pgd->pgd & _PAGE_PRESENT && __supported_pte_mask & _PAGE_NX)
		set_bit(_PAGE_BIT_NX, &pgd->pgd);
}

static inline void kaiser_unpoison_pgd_atomic(pgd_t *pgd)
{
	if (pgd->pgd & _PAGE_PRESENT && __supported_pte_mask & _PAGE_NX)
		clear_bit(_PAGE_BIT_NX, &pgd->pgd);
}

/*
 * Take a PGD location (pgdp) and a pgd value that needs
 * to be set there.  Populates the shadow and returns
 * the resulting PGD that must be set in the kernel copy
 * of the page tables.
 */
static inline pgd_t kaiser_set_shadow_pgd(pgd_t *pgdp, pgd_t pgd)
{
#ifdef CONFIG_KAISER
	if (pgd_userspace_access(pgd)) {
		if (pgdp_maps_userspace(pgdp)) {
			VM_WARN_ON_ONCE(!is_kaiser_pgd(pgdp));
			/*
			 * The user/shadow page tables get the full
			 * PGD, accessible from userspace:
			 */
			kernel_to_shadow_pgdp(pgdp)->pgd = pgd.pgd;
			/*
			 * For the copy of the pgd that the kernel
			 * uses, make it unusable to userspace.  This
			 * ensures if we get out to userspace with the
			 * wrong CR3 value, userspace will crash
			 * instead of running.
			 */
			if (kaiser_active())
				kaiser_poison_pgd(&pgd);
		}
	} else if (pgd_userspace_access(*pgdp)) {
		/*
		 * We are clearing a _PAGE_USER PGD for which we
		 * presumably populated the shadow.  We must now
		 * clear the shadow PGD entry.
		 */
		if (pgdp_maps_userspace(pgdp)) {
			VM_WARN_ON_ONCE(!is_kaiser_pgd(pgdp));
			kernel_to_shadow_pgdp(pgdp)->pgd = pgd.pgd;
		} else {
			/*
			 * Attempted to clear a _PAGE_USER PGD which
			 * is in the kernel porttion of the address
			 * space.  PGDs are pre-populated and we
			 * never clear them.
			 */
			WARN_ON_ONCE(1);
		}
	} else {
		/*
		 * _PAGE_USER was not set in either the PGD being set
		 * or cleared.  All kernel PGDs should be
		 * pre-populated so this should never happen after
		 * boot.
		 */
		VM_WARN_ON_ONCE(system_state == SYSTEM_RUNNING &&
				is_kaiser_pgd(pgdp));
	}
#endif
	/* return the copy of the PGD we want the kernel to use: */
	return pgd;
}

static inline void native_set_pgd(pgd_t *pgdp, pgd_t pgd)
{
	mm_track_pgd(pgdp);
#ifdef CONFIG_KAISER
	*pgdp = kaiser_set_shadow_pgd(pgdp, pgd);
#else /* CONFIG_KAISER */
	*pgdp = pgd;
#endif
}

static inline void native_pgd_clear(pgd_t *pgd)
{
	native_set_pgd(pgd, native_make_pgd(0));
}

extern void sync_global_pgds(unsigned long start, unsigned long end,
			     int removed);

/*
 * Conversion functions: convert a page and protection to a page entry,
 * and a page entry and page directory to the page they refer to.
 */

/*
 * Level 4 access.
 */
static inline int pgd_large(pgd_t pgd) { return 0; }
#define mk_kernel_pgd(address) __pgd((address) | _KERNPG_TABLE)

/* PUD - Level3 access */

/* PMD  - Level 2 access */
#define pte_to_pgoff(pte) ((pte_val((pte)) & PHYSICAL_PAGE_MASK) >> PAGE_SHIFT)
#define pgoff_to_pte(off) ((pte_t) { .pte = ((off) << PAGE_SHIFT) |	\
					    _PAGE_FILE })
#define PTE_FILE_MAX_BITS __PHYSICAL_MASK_SHIFT

/* PTE - Level 1 access. */

/* x86-64 always has all page tables mapped. */
#define pte_offset_map(dir, address) pte_offset_kernel((dir), (address))
#define pte_unmap(pte) ((void)(pte))/* NOP */

/* Encode and de-code a swap entry */
#if _PAGE_BIT_FILE > _PAGE_BIT_PROTNONE
#error unsupported PTE bit arrangement
#endif

/*
 * Encode and de-code a swap entry
 *
 * |     ...            | 11| 10|  9|8|7|6|5| 4| 3|2|1|0| <- bit number
 * |     ...            |SW3|SW2|SW1|G|L|D|A|CD|WT|U|W|P| <- bit names
 * | OFFSET (14->63) | TYPE (9-13)  |0|X|X|X| X| X|X|X|0| <- swp entry
 *
 * G (8) is aliased and used as a PROT_NONE indicator for
 * !present ptes.  We need to start storing swap entries above
 * there.  We also need to avoid using A and D because of an
 * erratum where they can be incorrectly set by hardware on
 * non-present PTEs.
 */
#define SWP_TYPE_FIRST_BIT (_PAGE_BIT_PROTNONE + 1)
#define SWP_TYPE_BITS	5
/* Place the offset above the type: */
#define SWP_OFFSET_FIRST_BIT (SWP_TYPE_FIRST_BIT + SWP_TYPE_BITS + 1)

#define MAX_SWAPFILES_CHECK() BUILD_BUG_ON(MAX_SWAPFILES_SHIFT > SWP_TYPE_BITS)

#define __swp_type(x)			(((x).val >> (SWP_TYPE_FIRST_BIT)) \
					 & ((1U << SWP_TYPE_BITS) - 1))
#define __swp_offset(x)			((x).val >> SWP_OFFSET_FIRST_BIT)
#define __swp_entry(type, offset)	((swp_entry_t) { \
					 ((type) << (SWP_TYPE_FIRST_BIT)) \
					 | ((offset) << SWP_OFFSET_FIRST_BIT) })
#define __pte_to_swp_entry(pte)		((swp_entry_t) { pte_val((pte)) })
#define __swp_entry_to_pte(x)		((pte_t) { .pte = (x).val })

extern int kern_addr_valid(unsigned long addr);
extern void cleanup_highmap(void);

#define HAVE_ARCH_UNMAPPED_AREA
#define HAVE_ARCH_UNMAPPED_AREA_TOPDOWN

#define pgtable_cache_init()   do { } while (0)
#define check_pgt_cache()      do { } while (0)

#define PAGE_AGP    PAGE_KERNEL_NOCACHE
#define HAVE_PAGE_AGP 1

/* fs/proc/kcore.c */
#define	kc_vaddr_to_offset(v) ((v) & __VIRTUAL_MASK)
#define	kc_offset_to_vaddr(o) ((o) | ~__VIRTUAL_MASK)

#define __HAVE_ARCH_PTE_SAME

#define vmemmap ((struct page *)VMEMMAP_START)

extern void init_extra_mapping_uc(unsigned long phys, unsigned long size);
extern void init_extra_mapping_wb(unsigned long phys, unsigned long size);

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_X86_PGTABLE_64_H */
