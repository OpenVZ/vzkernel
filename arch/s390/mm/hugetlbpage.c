/*
 *  IBM System z Huge TLB Page Support for Kernel.
 *
 *    Copyright IBM Corp. 2007,2016
 *    Author(s): Gerald Schaefer <gerald.schaefer@de.ibm.com>
 */

#include <linux/mm.h>
#include <linux/hugetlb.h>

static inline unsigned long __pte_to_rste(pte_t pte)
{
	int none, young, prot;
	unsigned long rste;

	/*
	 * Convert encoding		  pte bits	pmd/pud bits
	 *				.IR...wrdytp	..R...I...y.
	 * empty			.10...000000 -> ..0...1...0.
	 * prot-none, clean, old	.11...000001 -> ..0...1...1.
	 * prot-none, clean, young	.11...000101 -> ..1...1...1.
	 * prot-none, dirty, old	.10...001001 -> ..0...1...1.
	 * prot-none, dirty, young	.10...001101 -> ..1...1...1.
	 * read-only, clean, old	.11...010001 -> ..1...1...0.
	 * read-only, clean, young	.01...010101 -> ..1...0...1.
	 * read-only, dirty, old	.11...011001 -> ..1...1...0.
	 * read-only, dirty, young	.01...011101 -> ..1...0...1.
	 * read-write, clean, old	.11...110001 -> ..0...1...0.
	 * read-write, clean, young	.01...110101 -> ..0...0...1.
	 * read-write, dirty, old	.10...111001 -> ..0...1...0.
	 * read-write, dirty, young	.00...111101 -> ..0...0...1.
	 * Huge ptes are dirty by definition, a clean pte is made dirty
	 * by the conversion.
	 */
	if (pte_present(pte)) {
		rste = pte_val(pte) & PAGE_MASK;
		if (pte_val(pte) & _PAGE_INVALID)
			rste |= _SEGMENT_ENTRY_INVALID;
		none = (pte_val(pte) & _PAGE_PRESENT) &&
			!(pte_val(pte) & _PAGE_READ) &&
			!(pte_val(pte) & _PAGE_WRITE);
		prot = (pte_val(pte) & _PAGE_PROTECT) &&
			!(pte_val(pte) & _PAGE_WRITE);
		young = pte_val(pte) & _PAGE_YOUNG;
		if (none || young)
			rste |= _SEGMENT_ENTRY_YOUNG;
		if (prot || (none && young))
			rste |= _SEGMENT_ENTRY_PROTECT;
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
	 * Convert encoding	pmd/pud bits	  pte bits
	 *			..R...I...y.	.IR...wrdytp
	 * empty		..0...1...0. -> .10...000000
	 * prot-none, old	..0...1...1. -> .10...001001
	 * prot-none, young	..1...1...1. -> .10...001101
	 * read-only, old	..1...1...0. -> .11...011001
	 * read-only, young	..1...0...1. -> .01...011101
	 * read-write, old	..0...1...0. -> .10...111001
	 * read-write, young	..0...0...1. -> .00...111101
	 * Huge ptes are dirty by definition
	 */
	if (present) {
		pte_val(pte) = _PAGE_PRESENT | _PAGE_LARGE | _PAGE_DIRTY |
			       (rste & PAGE_MASK);
		if (rste & _SEGMENT_ENTRY_INVALID)
			pte_val(pte) |= _PAGE_INVALID;
		if (pmd_prot_none(__pmd(rste))) {
			if (rste & _SEGMENT_ENTRY_PROTECT)
				pte_val(pte) |= _PAGE_YOUNG;
		} else {
			pte_val(pte) |= _PAGE_READ;
			if (rste & _SEGMENT_ENTRY_PROTECT)
				pte_val(pte) |= _PAGE_PROTECT;
			else
				pte_val(pte) |= _PAGE_WRITE;
			if (rste & _SEGMENT_ENTRY_YOUNG)
				pte_val(pte) |= _PAGE_YOUNG;
		}
	} else
		pte_val(pte) = _PAGE_INVALID;
	return pte;
}

void set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
		     pte_t *ptep, pte_t pte)
{
	unsigned long rste = __pte_to_rste(pte);

	/* Set correct table type for 2G hugepages */
	if ((pte_val(*ptep) & _REGION_ENTRY_TYPE_MASK) == _REGION_ENTRY_TYPE_R3)
		rste |= _REGION_ENTRY_TYPE_R3 | _REGION3_ENTRY_LARGE;
	else {
		if (!MACHINE_HAS_HPAGE) {
			rste &= ~_SEGMENT_ENTRY_ORIGIN;
			rste |= pte_page(pte)[1].index;
		} else
			rste |= _SEGMENT_ENTRY_LARGE | _SEGMENT_ENTRY_CO;
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
