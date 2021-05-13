/*
 * Lockless get_user_pages_fast for x86
 *
 * Copyright (C) 2008 Nick Piggin
 * Copyright (C) 2008 Novell Inc.
 */
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/memremap.h>

#include <asm/mmu_context.h>
#include <asm/pgtable.h>

/*
 * RHEL-only. Hypervisors overriding pv_mmu_ops.flush_tlb_others need to do
 * static_key_slow_dec(&rh_flush_tlb_others_native)
 */
struct static_key rh_flush_tlb_others_native __read_mostly = STATIC_KEY_INIT_TRUE;
#define rh_flush_tlb_others_IPI_less() (static_key_false(&rh_flush_tlb_others_native))

static inline pte_t gup_get_pte(pte_t *ptep)
{
#ifndef CONFIG_X86_PAE
	return ACCESS_ONCE(*ptep);
#else
	/*
	 * With get_user_pages_fast, we walk down the pagetables without taking
	 * any locks.  For this we would like to load the pointers atomically,
	 * but that is not possible (without expensive cmpxchg8b) on PAE.  What
	 * we do have is the guarantee that a pte will only either go from not
	 * present to present, or present to not present or both -- it will not
	 * switch to a completely different present page without a TLB flush in
	 * between; something that we are blocking by holding interrupts off.
	 *
	 * Setting ptes from not present to present goes:
	 * ptep->pte_high = h;
	 * smp_wmb();
	 * ptep->pte_low = l;
	 *
	 * And present to not present goes:
	 * ptep->pte_low = 0;
	 * smp_wmb();
	 * ptep->pte_high = 0;
	 *
	 * We must ensure here that the load of pte_low sees l iff pte_high
	 * sees h. We load pte_high *after* loading pte_low, which ensures we
	 * don't see an older value of pte_high.  *Then* we recheck pte_low,
	 * which ensures that we haven't picked up a changed pte high. We might
	 * have got rubbish values from pte_low and pte_high, but we are
	 * guaranteed that pte_low will not have the present bit set *unless*
	 * it is 'l'. And get_user_pages_fast only operates on present ptes, so
	 * we're safe.
	 *
	 * gup_get_pte should not be used or copied outside gup.c without being
	 * very careful -- it does not atomically load the pte or anything that
	 * is likely to be useful for you.
	 */
	pte_t pte;

retry:
	pte.pte_low = ptep->pte_low;
	smp_rmb();
	pte.pte_high = ptep->pte_high;
	smp_rmb();
	if (unlikely(pte.pte_low != ptep->pte_low))
		goto retry;

	return pte;
#endif
}

static void undo_dev_pagemap(int *nr, int nr_start, struct page **pages)
{
	while ((*nr) - nr_start) {
		struct page *page = pages[--(*nr)];

		ClearPageReferenced(page);
		put_page(page);
	}
}

/*
 * 'pteval' can come from a pte, pmd or pud.  We only check
 * _PAGE_PRESENT, _PAGE_USER, and _PAGE_RW in here which are the
 * same value on all 3 types.
 */
static inline int pte_allows_gup(unsigned long pteval, int write)
{
	unsigned long need_pte_bits = _PAGE_PRESENT|_PAGE_USER;

	if (write)
		need_pte_bits |= _PAGE_RW;

	if ((pteval & need_pte_bits) != need_pte_bits)
		return 0;

	/* Check memory protection keys permissions. */
	if (!__pkru_allows_pkey(pte_flags_pkey(pteval), write))
		return 0;

	return 1;
}

/*
 * The performance critical leaf functions are made noinline otherwise gcc
 * inlines everything into a single function which results in too much
 * register pressure.
 */
static noinline int gup_pte_range(pmd_t pmd, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	struct dev_pagemap *pgmap = NULL;
	int nr_start = *nr;
	pte_t *ptep;

	ptep = pte_offset_map(&pmd, addr);
	do {
		pte_t pte = gup_get_pte(ptep);
		struct page *page;

		/* Similar to the PMD case, NUMA hinting must take slow path */
		if (pte_numa(pte)) {
			put_dev_pagemap(pgmap);
			pte_unmap(ptep);
			return 0;
		}

		if (!pte_allows_gup(pte_val(pte), write)) {
			put_dev_pagemap(pgmap);
			pte_unmap(ptep);
			return 0;
		}

		if (pte_devmap(pte)) {
			pgmap = get_dev_pagemap(pte_pfn(pte), pgmap);
			if (unlikely(!pgmap)) {
				undo_dev_pagemap(nr, nr_start, pages);
				pte_unmap(ptep);
				return 0;
			}
		} else if (pte_special(pte)) {
			put_dev_pagemap(pgmap);
			pte_unmap(ptep);
			return 0;
		}
		VM_BUG_ON(!pfn_valid(pte_pfn(pte)));
		page = pte_page(pte);

		/*
		 * RHEL-only: upstream has HAVE_GENERIC_GUP and it always does
		 * page_cache_get_speculative() here to ensure serialization
		 * when IPIs are not send on TLB shootdown.
		 */
		if (rh_flush_tlb_others_IPI_less()) {
			if (!try_get_compound_head(page, 1)) {
				put_dev_pagemap(pgmap);
				return 0;
			}
			if (unlikely(pte_val(pte) != pte_val(*ptep))) {
				put_page(page);
				put_dev_pagemap(pgmap);
				return 0;
			}
		} else {
			if (WARN_ON_ONCE(page_ref_count(page) < 0)) {
				put_dev_pagemap(pgmap);
				return 0;
			}
			get_page(page);
		}
		SetPageReferenced(page);
		pages[*nr] = page;
		(*nr)++;

	} while (ptep++, addr += PAGE_SIZE, addr != end);
	if (pgmap)
		put_dev_pagemap(pgmap);
	pte_unmap(ptep - 1);

	return 1;
}

static inline void get_head_page_multiple(struct page *page, int nr)
{
	VM_BUG_ON_PAGE(page != compound_head(page), page);
	VM_BUG_ON_PAGE(page_count(page) == 0, page);

	/*
	 * RHEL note: if this triggers in normal workloads after being
	 * already checked in gup_huge_pud() and gup_huge_pmd(), we
	 * might have to proactively check for overflows. Currently
	 * overflows can only happen with malicious page referencing
	 * workloads (CVE-2019-11487)
	 */
	if (WARN_ON_ONCE(page_ref_count(compound_head(page)) < 0))
		return;
	page_ref_add(page, nr);
	SetPageReferenced(page);
}

static int __gup_device_huge(unsigned long pfn, unsigned long addr,
		unsigned long end, struct page **pages, int *nr)
{
	int nr_start = *nr;
	struct dev_pagemap *pgmap = NULL;

	do {
		struct page *page = pfn_to_page(pfn);

		pgmap = get_dev_pagemap(pfn, pgmap);
		if (unlikely(!pgmap)) {
			undo_dev_pagemap(nr, nr_start, pages);
			return 0;
		}
		SetPageReferenced(page);
		pages[*nr] = page;
		get_page(page);
		(*nr)++;
		pfn++;
	} while (addr += PAGE_SIZE, addr != end);

	if (pgmap)
		put_dev_pagemap(pgmap);
	return 1;
}

static int __gup_device_huge_pmd(pmd_t orig, pmd_t *pmdp, unsigned long addr,
		unsigned long end, struct page **pages, int *nr)
{
	unsigned long fault_pfn;
	int nr_start = *nr;

	fault_pfn = pmd_pfn(orig) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	if (!__gup_device_huge(fault_pfn, addr, end, pages, nr))
		return 0;

	if (unlikely(pmd_val(orig) != pmd_val(*pmdp))) {
		undo_dev_pagemap(nr, nr_start, pages);
		return 0;
	}
	return 1;
}

static int __gup_device_huge_pud(pud_t orig, pud_t *pudp, unsigned long addr,
		unsigned long end, struct page **pages, int *nr)
{
	unsigned long fault_pfn;
	int nr_start = *nr;

	fault_pfn = pud_pfn(orig) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	if (!__gup_device_huge(fault_pfn, addr, end, pages, nr))
		return 0;

	if (unlikely(pud_val(orig) != pud_val(*pudp))) {
		undo_dev_pagemap(nr, nr_start, pages);
		return 0;
	}
	return 1;
}

static noinline int gup_huge_pmd(pmd_t orig, pmd_t *pmdp, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	pte_t pte = *(pte_t *)&orig;
	struct page *head, *page;
	int refs;

	if (!pte_allows_gup(pte_val(pte), write))
		return 0;

	VM_BUG_ON(!pfn_valid(pte_pfn(pte)));
	if (pmd_devmap(orig))
		return __gup_device_huge_pmd(orig, pmdp, addr, end, pages, nr);

	/* hugepages are never "special" */
	VM_BUG_ON(pte_flags(pte) & _PAGE_SPECIAL);

	refs = 0;
	head = pte_page(pte);

	/* RHEL-only. See gup_pte_range() */
	if (rh_flush_tlb_others_IPI_less()) {
		head = try_get_compound_head(head, 1);
		if (!head)
			return 0;
		if (unlikely(pte_val(pte) != pte_val(*(pte_t *)&orig))) {
			put_page(head);
			return 0;
		}

		/* Don't take ref to the head page twice */
		refs--;
	} else {
		if (WARN_ON_ONCE(page_ref_count(head) < 0))
			return 0;
	}

	page = head + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
	do {
		VM_BUG_ON_PAGE(compound_head(page) != head, page);
		pages[*nr] = page;
		if (PageTail(page))
			get_huge_page_tail(page);
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);
	get_head_page_multiple(head, refs);

	return 1;
}

static int gup_pmd_range(pud_t pud, unsigned long addr, unsigned long end,
		int write, struct page **pages, int *nr)
{
	unsigned long next;
	pmd_t *pmdp;

	pmdp = pmd_offset(&pud, addr);
	do {
		pmd_t pmd = *pmdp;

		next = pmd_addr_end(addr, end);
		/*
		 * The pmd_trans_splitting() check below explains why
		 * pmdp_splitting_flush has to flush the tlb, to stop
		 * this gup-fast code from running while we set the
		 * splitting bit in the pmd. Returning zero will take
		 * the slow path that will call wait_split_huge_page()
		 * if the pmd is still in splitting state. gup-fast
		 * can't because it has irq disabled and
		 * wait_split_huge_page() would never return as the
		 * tlb flush IPI wouldn't run.
		 */
		if (pmd_none(pmd) || pmd_trans_splitting(pmd))
			return 0;
		if (unlikely(pmd_large(pmd) || !pmd_present(pmd))) {
			/*
			 * NUMA hinting faults need to be handled in the GUP
			 * slowpath for accounting purposes and so that they
			 * can be serialised against THP migration.
			 */
			if (pmd_numa(pmd))
				return 0;
			if (!gup_huge_pmd(pmd, pmdp, addr, next, write,
				pages, nr))
				return 0;
		} else {
			if (!gup_pte_range(pmd, addr, next, write, pages, nr))
				return 0;
		}
	} while (pmdp++, addr = next, addr != end);

	return 1;
}

static noinline int gup_huge_pud(pud_t orig, pud_t *pudp, unsigned long addr,
		unsigned long end, int write, struct page **pages, int *nr)
{
	pte_t pte = *(pte_t *)&orig;
	struct page *head, *page;
	int refs;

	if (!pte_allows_gup(pte_val(pte), write))
		return 0;

	VM_BUG_ON(!pfn_valid(pte_pfn(pte)));
	if (pud_devmap(orig))
		return __gup_device_huge_pud(orig, pudp, addr, end, pages, nr);

	/* hugepages are never "special" */
	VM_BUG_ON(pte_flags(pte) & _PAGE_SPECIAL);

	refs = 0;
	head = pte_page(pte);

	/* RHEL-only. See gup_pte_range() */
	if (rh_flush_tlb_others_IPI_less()) {
		head = try_get_compound_head(head, 1);
		if (!head)
			return 0;
		if (unlikely(pte_val(pte) != pte_val(*(pte_t *)&orig))) {
			put_page(head);
			return 0;
		}

		/* Don't take ref to the head page twice */
		refs--;
	} else {
		if (WARN_ON_ONCE(page_ref_count(head) < 0))
			return 0;
	}

	page = head + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
	do {
		VM_BUG_ON_PAGE(compound_head(page) != head, page);
		pages[*nr] = page;
		if (PageTail(page))
			get_huge_page_tail(page);
		(*nr)++;
		page++;
		refs++;
	} while (addr += PAGE_SIZE, addr != end);
	get_head_page_multiple(head, refs);

	return 1;
}

static int gup_pud_range(pgd_t pgd, unsigned long addr, unsigned long end,
			int write, struct page **pages, int *nr)
{
	unsigned long next;
	pud_t *pudp;

	pudp = pud_offset(&pgd, addr);
	do {
		pud_t pud = *pudp;

		next = pud_addr_end(addr, end);
		if (pud_none(pud))
			return 0;
		if (unlikely(pud_large(pud))) {
			if (!gup_huge_pud(pud, pudp, addr, next, write,
					  pages, nr))
				return 0;
		} else {
			if (!gup_pmd_range(pud, addr, next, write, pages, nr))
				return 0;
		}
	} while (pudp++, addr = next, addr != end);

	return 1;
}

/*
 * Like get_user_pages_fast() except its IRQ-safe in that it won't fall
 * back to the regular GUP.
 */
int __get_user_pages_fast(unsigned long start, int nr_pages, int write,
			  struct page **pages)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr, len, end;
	unsigned long next;
	unsigned long flags;
	pgd_t *pgdp;
	int nr = 0;

	start &= PAGE_MASK;
	addr = start;
	len = (unsigned long) nr_pages << PAGE_SHIFT;
	end = start + len;
	if (unlikely(!access_ok(write ? VERIFY_WRITE : VERIFY_READ,
					(void __user *)start, len)))
		return 0;

	/*
	 * XXX: batch / limit 'nr', to avoid large irq off latency
	 * needs some instrumenting to determine the common sizes used by
	 * important workloads (eg. DB2), and whether limiting the batch size
	 * will decrease performance.
	 *
	 * It seems like we're in the clear for the moment. Direct-IO is
	 * the main guy that batches up lots of get_user_pages, and even
	 * they are limited to 64-at-a-time which is not so many.
	 */
	/*
	 * This doesn't prevent pagetable teardown, but does prevent
	 * the pagetables and pages from being freed on x86.
	 *
	 * So long as we atomically load page table pointers versus teardown
	 * (which we do on x86, with the above PAE exception), we can follow the
	 * address down to the the page and take a ref on it.
	 */
	local_irq_save(flags);
	pgdp = pgd_offset(mm, addr);
	do {
		pgd_t pgd = *pgdp;

		next = pgd_addr_end(addr, end);
		if (pgd_none(pgd))
			break;
		if (!gup_pud_range(pgd, addr, next, write, pages, &nr))
			break;
	} while (pgdp++, addr = next, addr != end);
	local_irq_restore(flags);

	return nr;
}

/**
 * get_user_pages_fast() - pin user pages in memory
 * @start:	starting user address
 * @nr_pages:	number of pages from start to pin
 * @write:	whether pages will be written to
 * @pages:	array that receives pointers to the pages pinned.
 * 		Should be at least nr_pages long.
 *
 * Attempt to pin user pages in memory without taking mm->mmap_sem.
 * If not successful, it will fall back to taking the lock and
 * calling get_user_pages().
 *
 * Returns number of pages pinned. This may be fewer than the number
 * requested. If nr_pages is 0 or negative, returns 0. If no pages
 * were pinned, returns -errno.
 */
int get_user_pages_fast(unsigned long start, int nr_pages, int write,
			struct page **pages)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr, len, end;
	unsigned long next;
	pgd_t *pgdp;
	int nr = 0;

	start &= PAGE_MASK;
	addr = start;
	len = (unsigned long) nr_pages << PAGE_SHIFT;

	end = start + len;
	if (end < start)
		goto slow_irqon;

#ifdef CONFIG_X86_64
	if (end >> __VIRTUAL_MASK_SHIFT)
		goto slow_irqon;
#endif

	/*
	 * XXX: batch / limit 'nr', to avoid large irq off latency
	 * needs some instrumenting to determine the common sizes used by
	 * important workloads (eg. DB2), and whether limiting the batch size
	 * will decrease performance.
	 *
	 * It seems like we're in the clear for the moment. Direct-IO is
	 * the main guy that batches up lots of get_user_pages, and even
	 * they are limited to 64-at-a-time which is not so many.
	 */
	/*
	 * This doesn't prevent pagetable teardown, but does prevent
	 * the pagetables and pages from being freed on x86.
	 *
	 * So long as we atomically load page table pointers versus teardown
	 * (which we do on x86, with the above PAE exception), we can follow the
	 * address down to the the page and take a ref on it.
	 */
	local_irq_disable();
	pgdp = pgd_offset(mm, addr);
	do {
		pgd_t pgd = *pgdp;

		next = pgd_addr_end(addr, end);
		if (pgd_none(pgd))
			goto slow;
		if (!gup_pud_range(pgd, addr, next, write, pages, &nr))
			goto slow;
	} while (pgdp++, addr = next, addr != end);
	local_irq_enable();

	VM_BUG_ON(nr != (end - start) >> PAGE_SHIFT);
	return nr;

	{
		int ret;

slow:
		local_irq_enable();
slow_irqon:
		/* Try to get the remaining pages with get_user_pages */
		start += nr << PAGE_SHIFT;
		pages += nr;

		ret = get_user_pages_unlocked(current, mm, start,
					      (end - start) >> PAGE_SHIFT,
					      write, 0, pages);

		/* Have to be a bit careful with return values */
		if (nr > 0) {
			if (ret < 0)
				ret = nr;
			else
				ret += nr;
		}

		return ret;
	}
}
