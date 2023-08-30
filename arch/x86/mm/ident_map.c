/*
 * Helper routines for building identity mapping page tables. This is
 * included by both the compressed kernel and the regular kernel.
 */

static void ident_pmd_init(struct x86_mapping_info *info, pmd_t *pmd_page,
			   unsigned long addr, unsigned long end)
{
	addr &= PMD_MASK;
	for (; addr < end; addr += PMD_SIZE) {
		pmd_t *pmd = pmd_page + pmd_index(addr);

		if (pmd_present(*pmd))
			continue;

		set_pmd(pmd, __pmd((addr - info->offset) | info->page_flag));
	}
}

static int ident_pud_init(struct x86_mapping_info *info, pud_t *pud_page,
			  unsigned long addr, unsigned long end)
{
	unsigned long next;

	for (; addr < end; addr = next) {
		pud_t *pud = pud_page + pud_index(addr);
		pmd_t *pmd;

		next = (addr & PUD_MASK) + PUD_SIZE;
		if (next > end)
			next = end;

		if (info->direct_gbpages) {
			pud_t pudval;

			if (pud_present(*pud))
				continue;

			addr &= PUD_MASK;
			pudval = __pud((addr - info->offset) | info->page_flag);
			set_pud(pud, pudval);
			continue;
		}

		if (pud_present(*pud)) {
			pmd = pmd_offset(pud, 0);
			ident_pmd_init(info, pmd, addr, next);
			continue;
		}
		pmd = (pmd_t *)info->alloc_pgt_page(info->context);
		if (!pmd)
			return -ENOMEM;
		ident_pmd_init(info, pmd, addr, next);
		set_pud(pud, __pud(__pa(pmd) | info->kernpg_flag));
	}

	return 0;
}

int kernel_ident_mapping_init(struct x86_mapping_info *info, pgd_t *pgd_page,
			      unsigned long pstart, unsigned long pend)
{
	unsigned long addr = pstart + info->offset;
	unsigned long end = pend + info->offset;
	unsigned long next;
	int result;

	/* Set the default pagetable flags if not supplied */
	if (!info->kernpg_flag)
		info->kernpg_flag = _KERNPG_TABLE;

	for (; addr < end; addr = next) {
		pgd_t *pgd = pgd_page + pgd_index(addr);
		pud_t *pud;

		next = (addr & PGDIR_MASK) + PGDIR_SIZE;
		if (next > end)
			next = end;

		if (pgd_present(*pgd)) {
			pud = pud_offset(pgd, 0);
			result = ident_pud_init(info, pud, addr, next);
			if (result)
				return result;
			continue;
		}

		pud = (pud_t *)info->alloc_pgt_page(info->context);
		if (!pud)
			return -ENOMEM;
		result = ident_pud_init(info, pud, addr, next);
		if (result)
			return result;
		set_pgd(pgd, __pgd(__pa(pud) | info->kernpg_flag));
	}

	return 0;
}
