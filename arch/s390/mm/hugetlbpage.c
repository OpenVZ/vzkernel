/*
 *  IBM System z Huge TLB Page Support for Kernel.
 *
 *    Copyright IBM Corp. 2007,2020
 *    Author(s): Gerald Schaefer <gerald.schaefer@de.ibm.com>
 */

#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/security.h>

static inline unsigned long __pte_to_rste(pte_t pte)
{
	unsigned long rste;

	/*
	 * Convert encoding		  pte bits	   pmd bits
	 *				.IR...wrdytp	dy..R...I...wr
	 * empty			.10...000000 -> 00..0...1...00
	 * prot-none, clean, old	.11...000001 -> 00..1...1...00
	 * prot-none, clean, young	.11...000101 -> 01..1...1...00
	 * prot-none, dirty, old	.10...001001 -> 10..1...1...00
	 * prot-none, dirty, young	.10...001101 -> 11..1...1...00
	 * read-only, clean, old	.11...010001 -> 00..1...1...01
	 * read-only, clean, young	.01...010101 -> 01..1...0...01
	 * read-only, dirty, old	.11...011001 -> 10..1...1...01
	 * read-only, dirty, young	.01...011101 -> 11..1...0...01
	 * read-write, clean, old	.11...110001 -> 00..0...1...11
	 * read-write, clean, young	.01...110101 -> 01..0...0...11
	 * read-write, dirty, old	.10...111001 -> 10..0...1...11
	 * read-write, dirty, young	.00...111101 -> 11..0...0...11
	 */
	if (pte_present(pte)) {
		rste = pte_val(pte) & PAGE_MASK;
		rste |= (pte_val(pte) & _PAGE_READ) >> 4;
		rste |= (pte_val(pte) & _PAGE_WRITE) >> 4;
		rste |=	(pte_val(pte) & _PAGE_INVALID) >> 5;
		rste |= (pte_val(pte) & _PAGE_PROTECT);
		rste |= (pte_val(pte) & _PAGE_DIRTY) << 10;
		rste |= (pte_val(pte) & _PAGE_YOUNG) << 10;
		rste |= (pte_val(pte) & _PAGE_NOEXEC);
	} else
		rste = _SEGMENT_ENTRY_INVALID;
	return rste;
}

static inline pte_t __rste_to_pte(unsigned long rste)
{
	int present;
	pte_t pte;

	if ((rste & _REGION_ENTRY_TYPE_MASK) == _REGION_ENTRY_TYPE_R3)
		present = pud_present(__pud(rste));
	else
		present = pmd_present(__pmd(rste));

	/*
	 * Convert encoding		   pmd bits	    pte bits
	 *				dy..R...I...wr	  .IR...wrdytp
	 * empty			00..0...1...00 -> .10...001100
	 * prot-none, clean, old	00..0...1...00 -> .10...000001
	 * prot-none, clean, young	01..0...1...00 -> .10...000101
	 * prot-none, dirty, old	10..0...1...00 -> .10...001001
	 * prot-none, dirty, young	11..0...1...00 -> .10...001101
	 * read-only, clean, old	00..1...1...01 -> .11...010001
	 * read-only, clean, young	01..1...1...01 -> .11...010101
	 * read-only, dirty, old	10..1...1...01 -> .11...011001
	 * read-only, dirty, young	11..1...1...01 -> .11...011101
	 * read-write, clean, old	00..0...1...11 -> .10...110001
	 * read-write, clean, young	01..0...1...11 -> .10...110101
	 * read-write, dirty, old	10..0...1...11 -> .10...111001
	 * read-write, dirty, young	11..0...1...11 -> .10...111101
	 */
	if (present) {
		pte_val(pte) = rste & _SEGMENT_ENTRY_ORIGIN_LARGE;
		pte_val(pte) |= _PAGE_LARGE | _PAGE_PRESENT;
		pte_val(pte) |= (rste & _SEGMENT_ENTRY_READ) << 4;
		pte_val(pte) |= (rste & _SEGMENT_ENTRY_WRITE) << 4;
		pte_val(pte) |= (rste & _SEGMENT_ENTRY_INVALID) << 5;
		pte_val(pte) |= (rste & _SEGMENT_ENTRY_PROTECT);
		pte_val(pte) |= (rste & _SEGMENT_ENTRY_DIRTY) >> 10;
		pte_val(pte) |= (rste & _SEGMENT_ENTRY_YOUNG) >> 10;
		pte_val(pte) |= (rste & _SEGMENT_ENTRY_NOEXEC);
	} else
		pte_val(pte) = _PAGE_INVALID;
	return pte;
}

void set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
		     pte_t *ptep, pte_t pte)
{
	unsigned long rste;

	rste = __pte_to_rste(pte);
	if (!MACHINE_HAS_NX)
		rste &= ~_SEGMENT_ENTRY_NOEXEC;

	/* Set correct table type for 2G hugepages */
	if ((pte_val(*ptep) & _REGION_ENTRY_TYPE_MASK) == _REGION_ENTRY_TYPE_R3)
		rste |= _REGION_ENTRY_TYPE_R3 | _REGION3_ENTRY_LARGE;
	else {
		if (!MACHINE_HAS_HPAGE) {
			rste &= ~_SEGMENT_ENTRY_ORIGIN;
			rste |= pte_page(pte)[1].index;
		} else
			rste |= _SEGMENT_ENTRY_LARGE;
	}
	pte_val(*ptep) = rste;
}

pte_t huge_ptep_get(pte_t *ptep)
{
	unsigned long origin, rste;

	rste = pte_val(*ptep);
	if ((pte_val(*ptep) & _REGION_ENTRY_TYPE_MASK) < _REGION_ENTRY_TYPE_R3)
		if (!MACHINE_HAS_HPAGE && pmd_present(__pmd(rste))) {
			origin = rste & _SEGMENT_ENTRY_ORIGIN;
			rste &= ~_SEGMENT_ENTRY_ORIGIN;
			rste |= *(unsigned long *) origin;
			/* Emulated huge ptes are young and dirty by definition */
			rste |= _SEGMENT_ENTRY_YOUNG | _SEGMENT_ENTRY_DIRTY;
		}
	return __rste_to_pte(rste);
}

pte_t huge_ptep_get_and_clear(struct mm_struct *mm,
			      unsigned long addr, pte_t *ptep)
{
	pte_t pte = huge_ptep_get(ptep);
	pmd_t *pmdp = (pmd_t *) ptep;
	pud_t *pudp = (pud_t *) ptep;

	if ((pte_val(*ptep) & _REGION_ENTRY_TYPE_MASK) == _REGION_ENTRY_TYPE_R3) {
		__pudp_idte(addr, pudp);
		pud_val(*pudp) = _REGION3_ENTRY_EMPTY;
	} else {
		if (MACHINE_HAS_IDTE)
			__pmd_idte(addr, pmdp);
		else
			__pmd_csp(pmdp);
		pmd_val(*pmdp) = _SEGMENT_ENTRY_EMPTY;
	}
	return pte;
}

int arch_prepare_hugepage(struct page *page)
{
	unsigned long addr = page_to_phys(page);
	pte_t pte;
	pte_t *ptep;
	int i;

	if (MACHINE_HAS_HPAGE)
		return 0;

	ptep = (pte_t *) pte_alloc_one(&init_mm, addr);
	if (!ptep)
		return -ENOMEM;

	pte_val(pte) = addr;
	for (i = 0; i < PTRS_PER_PTE; i++) {
		set_pte_at(&init_mm, addr + i * PAGE_SIZE, ptep + i, pte);
		pte_val(pte) += PAGE_SIZE;
	}
	page[1].index = (unsigned long) ptep;
	return 0;
}

void arch_release_hugepage(struct page *page)
{
	pte_t *ptep;

	if (MACHINE_HAS_HPAGE)
		return;

	ptep = (pte_t *) page[1].index;
	if (!ptep)
		return;
	clear_table((unsigned long *) ptep, _PAGE_INVALID,
		    PTRS_PER_PTE * sizeof(pte_t));
	page_table_free(&init_mm, (unsigned long *) ptep);
	page[1].index = 0;
}

pte_t *huge_pte_alloc(struct mm_struct *mm,
			unsigned long addr, unsigned long sz)
{
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp = NULL;

	pgdp = pgd_offset(mm, addr);
	pudp = pud_alloc(mm, pgdp, addr);
	if (pudp) {
		if (sz == PUD_SIZE)
			return (pte_t *) pudp;
		else if (sz == PMD_SIZE)
			pmdp = pmd_alloc(mm, pudp, addr);
	}
	return (pte_t *) pmdp;
}

pte_t *huge_pte_offset(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp = NULL;

	pgdp = pgd_offset(mm, addr);
	if (pgd_present(*pgdp)) {
		pudp = pud_offset(pgdp, addr);
		if (pud_present(*pudp)) {
			if (pud_large(*pudp))
				return (pte_t *) pudp;
			pmdp = pmd_offset(pudp, addr);
		}
	}
	return (pte_t *) pmdp;
}

int huge_pmd_unshare(struct mm_struct *mm, unsigned long *addr, pte_t *ptep)
{
	return 0;
}

int pmd_huge(pmd_t pmd)
{
	if (!MACHINE_HAS_HPAGE)
		return 0;

	return !!(pmd_val(pmd) & _SEGMENT_ENTRY_LARGE);
}

int pud_huge(pud_t pud)
{
	return pud_large(pud);
}

struct page *
follow_huge_pud(struct mm_struct *mm, unsigned long address,
		pud_t *pud, int flags)
{
	if (flags & FOLL_GET)
		return NULL;

	return pud_page(*pud) + ((address & ~PUD_MASK) >> PAGE_SHIFT);
}

static __init int setup_hugepagesz(char *opt)
{
	unsigned long size;
	char *string = opt;

	size = memparse(opt, &opt);
	if (MACHINE_HAS_EDAT1 && size == PMD_SIZE) {
		hugetlb_add_hstate(PMD_SHIFT - PAGE_SHIFT);
	} else if (MACHINE_HAS_EDAT2 && size == PUD_SIZE) {
		hugetlb_add_hstate(PUD_SHIFT - PAGE_SHIFT);
	} else {
		pr_err("hugepagesz= specifies an unsupported page size %s\n",
			string);
		return 0;
	}
	return 1;
}
__setup("hugepagesz=", setup_hugepagesz);

static unsigned long hugetlb_get_unmapped_area_bottomup(struct file *file,
		unsigned long addr, unsigned long len,
		unsigned long pgoff, unsigned long flags)
{
	struct hstate *h = hstate_file(file);
	struct vm_unmapped_area_info info;

	info.flags = 0;
	info.length = len;
	info.low_limit = current->mm->mmap_base;
	info.high_limit = TASK_SIZE;
	info.align_mask = PAGE_MASK & ~huge_page_mask(h);
	info.align_offset = 0;
	return vm_unmapped_area(&info);
}

static unsigned long hugetlb_get_unmapped_area_topdown(struct file *file,
		unsigned long addr0, unsigned long len,
		unsigned long pgoff, unsigned long flags)
{
	struct hstate *h = hstate_file(file);
	struct vm_unmapped_area_info info;
	unsigned long addr;

	info.flags = VM_UNMAPPED_AREA_TOPDOWN;
	info.length = len;
	info.low_limit = max(PAGE_SIZE, mmap_min_addr);
	info.high_limit = current->mm->mmap_base;
	info.align_mask = PAGE_MASK & ~huge_page_mask(h);
	info.align_offset = 0;
	addr = vm_unmapped_area(&info);

	/*
	 * A failed mmap() very likely causes application failure,
	 * so fall back to the bottom-up function here. This scenario
	 * can happen with large stack limits and large mmap()
	 * allocations.
	 */
	if (addr & ~PAGE_MASK) {
		VM_BUG_ON(addr != -ENOMEM);
		info.flags = 0;
		info.low_limit = TASK_UNMAPPED_BASE;
		info.high_limit = TASK_SIZE;
		addr = vm_unmapped_area(&info);
	}

	return addr;
}

unsigned long hugetlb_get_unmapped_area(struct file *file, unsigned long addr,
		unsigned long len, unsigned long pgoff, unsigned long flags)
{
	struct hstate *h = hstate_file(file);
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	int rc;

	if (len & ~huge_page_mask(h))
		return -EINVAL;
	if (len > TASK_SIZE - mmap_min_addr)
		return -ENOMEM;

	if (flags & MAP_FIXED) {
		if (prepare_hugepage_range(file, addr, len))
			return -EINVAL;
		goto check_asce_limit;
	}

	if (addr) {
		addr = ALIGN(addr, huge_page_size(h));
		vma = find_vma(mm, addr);
		if (TASK_SIZE - len >= addr && addr >= mmap_min_addr &&
		    (!vma || addr + len <= vm_start_gap(vma)))
			goto check_asce_limit;
	}

	if (mm->get_unmapped_area == arch_get_unmapped_area)
		addr = hugetlb_get_unmapped_area_bottomup(file, addr, len,
				pgoff, flags);
	else
		addr = hugetlb_get_unmapped_area_topdown(file, addr, len,
				pgoff, flags);
	if (addr & ~PAGE_MASK)
		return addr;

check_asce_limit:
	if (addr + len > current->mm->context.asce_limit &&
	    addr + len <= TASK_SIZE) {
		rc = crst_table_upgrade(mm);
		if (rc)
			return (unsigned long) rc;
	}
	return addr;
}
