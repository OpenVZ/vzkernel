/*
 * Re-map IO memory to kernel address space so that we can access it.
 * This is needed for high PCI addresses that aren't mapped in the
 * 640k-1MB IO memory area on PC's
 *
 * (C) Copyright 1995 1996 Linus Torvalds
 */

#include <linux/bootmem.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mmiotrace.h>
#include <linux/mem_encrypt.h>
#include <linux/efi.h>

#include <asm/cacheflush.h>
#include <asm/e820.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/pgalloc.h>
#include <asm/pat.h>
#include <asm/setup.h>

#include "physaddr.h"

/*
 * Fix up the linear direct mapping of the kernel to avoid cache attribute
 * conflicts.
 */
int ioremap_change_attr(unsigned long vaddr, unsigned long size,
			enum page_cache_mode pcm)
{
	unsigned long nrpages = size >> PAGE_SHIFT;
	int err;

	switch (pcm) {
	case _PAGE_CACHE_MODE_UC:
	default:
		err = _set_memory_uc(vaddr, nrpages);
		break;
	case _PAGE_CACHE_MODE_WC:
		err = _set_memory_wc(vaddr, nrpages);
		break;
	case _PAGE_CACHE_MODE_WB:
		err = _set_memory_wb(vaddr, nrpages);
		break;
	}

	return err;
}

static int __ioremap_check_ram(unsigned long start_pfn, unsigned long nr_pages,
			       void *arg)
{
	unsigned long i;

	for (i = 0; i < nr_pages; ++i)
		if (pfn_valid(start_pfn + i) &&
		    !PageReserved(pfn_to_page(start_pfn + i)))
			return 1;

	return 0;
}

/*
 * Remap an arbitrary physical address space into the kernel virtual
 * address space. It transparently creates kernel huge I/O mapping when
 * the physical address is aligned by a huge page size (1GB or 2MB) and
 * the requested size is at least the huge page size.
 *
 * NOTE: MTRRs can override PAT memory types with a 4KB granularity.
 * Therefore, the mapping code falls back to use a smaller page toward 4KB
 * when a mapping range is covered by non-WB type of MTRRs.
 *
 * NOTE! We need to allow non-page-aligned mappings too: we will obviously
 * have to convert them into an offset in a page-aligned mapping, but the
 * caller shouldn't need to know that small detail.
 */
static void __iomem *__ioremap_caller(resource_size_t phys_addr,
		unsigned long size, enum page_cache_mode pcm, void *caller)
{
	unsigned long offset, vaddr;
	resource_size_t pfn, last_pfn, last_addr;
	const resource_size_t unaligned_phys_addr = phys_addr;
	const unsigned long unaligned_size = size;
	struct vm_struct *area;
	enum page_cache_mode new_pcm;
	pgprot_t prot;
	int retval;
	void __iomem *ret_addr;

	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (!size || last_addr < phys_addr)
		return NULL;

	if (!phys_addr_valid(phys_addr)) {
		printk(KERN_WARNING "ioremap: invalid physical address %llx\n",
		       (unsigned long long)phys_addr);
		WARN_ON_ONCE(1);
		return NULL;
	}

	/*
	 * Don't allow anybody to remap normal RAM that we're using..
	 */
	pfn      = phys_addr >> PAGE_SHIFT;
	last_pfn = last_addr >> PAGE_SHIFT;
	if (walk_system_ram_range(pfn, last_pfn - pfn + 1, NULL,
					  __ioremap_check_ram) == 1) {
		WARN_ONCE(1, "ioremap on RAM at 0x%llx - 0x%llx\n",
					phys_addr, last_addr);
		return NULL;
	}

	/*
	 * Mappings have to be page-aligned
	 */
	offset = phys_addr & ~PAGE_MASK;
	phys_addr &= PHYSICAL_PAGE_MASK;
	size = PAGE_ALIGN(last_addr+1) - phys_addr;

	retval = reserve_memtype(phys_addr, (u64)phys_addr + size,
						pcm, &new_pcm);
	if (retval) {
		printk(KERN_ERR "ioremap reserve_memtype failed %d\n", retval);
		return NULL;
	}

	if (pcm != new_pcm) {
		if (!is_new_memtype_allowed(phys_addr, size, pcm, new_pcm)) {
			printk(KERN_ERR
		"ioremap error for 0x%llx-0x%llx, requested 0x%x, got 0x%x\n",
				(unsigned long long)phys_addr,
				(unsigned long long)(phys_addr + size),
				pcm, new_pcm);
			goto err_free_memtype;
		}
		pcm = new_pcm;
	}

	prot = PAGE_KERNEL_IO;
	switch (pcm) {
	case _PAGE_CACHE_MODE_UC:
	default:
		prot = __pgprot(pgprot_val(prot) |
				cachemode2protval(_PAGE_CACHE_MODE_UC));
		break;
	case _PAGE_CACHE_MODE_UC_MINUS:
		prot = __pgprot(pgprot_val(prot) |
				cachemode2protval(_PAGE_CACHE_MODE_UC_MINUS));
		break;
	case _PAGE_CACHE_MODE_WC:
		prot = __pgprot(pgprot_val(prot) |
				cachemode2protval(_PAGE_CACHE_MODE_WC));
		break;
	case _PAGE_CACHE_MODE_WB:
		break;
	}

	/*
	 * Ok, go for it..
	 */
	area = get_vm_area_caller(size, VM_IOREMAP, caller);
	if (!area)
		goto err_free_memtype;
	area->phys_addr = phys_addr;
	vaddr = (unsigned long) area->addr;

	if (kernel_map_sync_memtype(phys_addr, size, pcm))
		goto err_free_area;

	if (ioremap_page_range(vaddr, vaddr + size, phys_addr, prot))
		goto err_free_area;

	ret_addr = (void __iomem *) (vaddr + offset);
	mmiotrace_ioremap(unaligned_phys_addr, unaligned_size, ret_addr);

	/*
	 * Check if the request spans more than any BAR in the iomem resource
	 * tree.
	 */
	if (iomem_map_sanity_check(unaligned_phys_addr, unaligned_size))
		pr_warn("caller %pS mapping multiple BARs\n", caller);

	return ret_addr;
err_free_area:
	free_vm_area(area);
err_free_memtype:
	free_memtype(phys_addr, phys_addr + size);
	return NULL;
}

/**
 * ioremap_nocache     -   map bus memory into CPU space
 * @phys_addr:    bus address of the memory
 * @size:      size of the resource to map
 *
 * ioremap_nocache performs a platform specific sequence of operations to
 * make bus memory CPU accessible via the readb/readw/readl/writeb/
 * writew/writel functions and the other mmio helpers. The returned
 * address is not guaranteed to be usable directly as a virtual
 * address.
 *
 * This version of ioremap ensures that the memory is marked uncachable
 * on the CPU as well as honouring existing caching rules from things like
 * the PCI bus. Note that there are other caches and buffers on many
 * busses. In particular driver authors should read up on PCI writes
 *
 * It's useful if some control registers are in such an area and
 * write combining or read caching is not desirable:
 *
 * Must be freed with iounmap.
 */
void __iomem *ioremap_nocache(resource_size_t phys_addr, unsigned long size)
{
	/*
	 * Ideally, this should be:
	 *	pat_enabled ? _PAGE_CACHE_MODE_UC : _PAGE_CACHE_MODE_UC_MINUS;
	 *
	 * Till we fix all X drivers to use ioremap_wc(), we will use
	 * UC MINUS.
	 */
	enum page_cache_mode pcm = _PAGE_CACHE_MODE_UC_MINUS;

	return __ioremap_caller(phys_addr, size, pcm,
				__builtin_return_address(0));
}
EXPORT_SYMBOL(ioremap_nocache);

/**
 * ioremap_wc	-	map memory into CPU space write combined
 * @phys_addr:	bus address of the memory
 * @size:	size of the resource to map
 *
 * This version of ioremap ensures that the memory is marked write combining.
 * Write combining allows faster writes to some hardware devices.
 *
 * Must be freed with iounmap.
 */
void __iomem *ioremap_wc(resource_size_t phys_addr, unsigned long size)
{
	if (pat_enabled)
		return __ioremap_caller(phys_addr, size, _PAGE_CACHE_MODE_WC,
					__builtin_return_address(0));
	else
		return ioremap_nocache(phys_addr, size);
}
EXPORT_SYMBOL(ioremap_wc);

void __iomem *ioremap_cache(resource_size_t phys_addr, unsigned long size)
{
	return __ioremap_caller(phys_addr, size, _PAGE_CACHE_MODE_WB,
				__builtin_return_address(0));
}
EXPORT_SYMBOL(ioremap_cache);

void __iomem *ioremap_prot(resource_size_t phys_addr, unsigned long size,
				unsigned long prot_val)
{
	return __ioremap_caller(phys_addr, size,
				pgprot2cachemode(__pgprot(prot_val)),
				__builtin_return_address(0));
}
EXPORT_SYMBOL(ioremap_prot);

/**
 * iounmap - Free a IO remapping
 * @addr: virtual address from ioremap_*
 *
 * Caller must ensure there is only one unmapping for the same pointer.
 */
void iounmap(volatile void __iomem *addr)
{
	struct vm_struct *p, *o;

	if ((void __force *)addr <= high_memory)
		return;

	/*
	 * The PCI/ISA range special-casing was removed from __ioremap()
	 * so this check, in theory, can be removed. However, there are
	 * cases where iounmap() is called for addresses not obtained via
	 * ioremap() (vga16fb for example). Add a warning so that these
	 * cases can be caught and fixed.
	 */
	if ((void __force *)addr >= phys_to_virt(ISA_START_ADDRESS) &&
	    (void __force *)addr < phys_to_virt(ISA_END_ADDRESS)) {
		WARN(1, "iounmap() called for ISA range not obtained using ioremap()\n");
		return;
	}

	addr = (volatile void __iomem *)
		(PAGE_MASK & (unsigned long __force)addr);

	mmiotrace_iounmap(addr);

	/* Use the vm area unlocked, assuming the caller
	   ensures there isn't another iounmap for the same address
	   in parallel. Reuse of the virtual address is prevented by
	   leaving it in the global lists until we're done with it.
	   cpa takes care of the direct mappings. */
	p = find_vm_area((void __force *)addr);

	if (!p) {
		printk(KERN_ERR "iounmap: bad address %p\n", addr);
		dump_stack();
		return;
	}

	free_memtype(p->phys_addr, p->phys_addr + get_vm_area_size(p));

	/* Finally remove it */
	o = remove_vm_area((void __force *)addr);
	BUG_ON(p != o || o == NULL);
	kfree(p);
}
EXPORT_SYMBOL(iounmap);

int arch_ioremap_pud_supported(void)
{
#ifdef CONFIG_X86_64
	return cpu_has_gbpages;
#else
	return 0;
#endif
}

int arch_ioremap_pmd_supported(void)
{
	return cpu_has_pse;
}

/*
 * Convert a physical pointer to a virtual kernel pointer for /dev/mem
 * access
 */
void *xlate_dev_mem_ptr(unsigned long phys)
{
	unsigned long start  = phys &  PAGE_MASK;
	unsigned long offset = phys & ~PAGE_MASK;
	void *vaddr;

	/* memremap() maps if RAM, otherwise falls back to ioremap() */
	vaddr = memremap(start, PAGE_SIZE, MEMREMAP_WB);

	/* Only add the offset on success and return NULL if memremap() failed */
	if (vaddr)
		vaddr += offset;

	return vaddr;
}

void unxlate_dev_mem_ptr(unsigned long phys, void *addr)
{
	memunmap((void *)((unsigned long)addr & PAGE_MASK));
}

/*
 * Examine the physical address to determine if it is an area of memory
 * that should be mapped decrypted.  If the memory is not part of the
 * kernel usable area it was accessed and created decrypted, so these
 * areas should be mapped decrypted. And since the encryption key can
 * change across reboots, persistent memory should also be mapped
 * decrypted.
 */
static bool memremap_should_map_decrypted(resource_size_t phys_addr,
					  unsigned long size)
{
	int is_pmem;

	/*
	 * Check if the address is part of a persistent memory region.
	 * This check covers areas added by E820, EFI and ACPI.
	 */
	is_pmem = region_intersects_pmem(phys_addr, size);
	if (is_pmem != REGION_DISJOINT)
		return true;

	/*
	 * Check if the non-volatile attribute is set for an EFI
	 * reserved area.
	 */
	if (efi_enabled(EFI_BOOT)) {
		switch (efi_mem_type(phys_addr)) {
		case EFI_RESERVED_TYPE:
			if (efi_mem_attributes(phys_addr) & EFI_MEMORY_NV)
				return true;
			break;
		case -EINVAL:
			return true;
		default:
			break;
		}
	}

	/* Check if the address is outside kernel usable area */
	switch (e820__get_entry_type(phys_addr, phys_addr + size - 1)) {
	case E820_RESERVED:
	case E820_ACPI:
	case E820_NVS:
	case E820_UNUSABLE:
	case E820_PRAM:
		return true;
	default:
		break;
	}

	return false;
}

/*
 * Examine the physical address to determine if it is EFI data. Check
 * it against the boot params structure and EFI tables and memory types.
 */
static bool memremap_is_efi_data(resource_size_t phys_addr,
				 unsigned long size)
{
	u64 paddr;

	/* Check if the address is part of EFI boot/runtime data */
	if (!efi_enabled(EFI_BOOT))
		return false;

	paddr = boot_params.efi_info.efi_memmap_hi;
	paddr <<= 32;
	paddr |= boot_params.efi_info.efi_memmap;
	if (phys_addr == paddr)
		return true;

	paddr = boot_params.efi_info.efi_systab_hi;
	paddr <<= 32;
	paddr |= boot_params.efi_info.efi_systab;
	if (phys_addr == paddr)
		return true;

	if (efi_is_table_address(phys_addr))
		return true;

	switch (efi_mem_type(phys_addr)) {
	case EFI_BOOT_SERVICES_DATA:
	case EFI_RUNTIME_SERVICES_DATA:
		return true;
	default:
		break;
	}

	return false;
}

/*
 * Examine the physical address to determine if it is boot data by checking
 * it against the boot params setup_data chain.
 */
static bool memremap_is_setup_data(resource_size_t phys_addr,
				   unsigned long size)
{
	struct setup_data *data;
	u64 paddr, paddr_next;

	paddr = boot_params.hdr.setup_data;
	while (paddr) {
		unsigned int len;

		if (phys_addr == paddr)
			return true;

		data = memremap(paddr, sizeof(*data),
				MEMREMAP_WB | MEMREMAP_DEC);

		paddr_next = data->next;
		len = data->len;

		memunmap(data);

		if ((phys_addr > paddr) && (phys_addr < (paddr + len)))
			return true;

		paddr = paddr_next;
	}

	return false;
}

/*
 * Examine the physical address to determine if it is boot data by checking
 * it against the boot params setup_data chain (early boot version).
 */
static bool __init early_memremap_is_setup_data(resource_size_t phys_addr,
						unsigned long size)
{
	struct setup_data *data;
	u64 paddr, paddr_next;

	paddr = boot_params.hdr.setup_data;
	while (paddr) {
		unsigned int len;

		if (phys_addr == paddr)
			return true;

		data = early_memremap_decrypted(paddr, sizeof(*data));

		paddr_next = data->next;
		len = data->len;

		early_memunmap(data, sizeof(*data));

		if ((phys_addr > paddr) && (phys_addr < (paddr + len)))
			return true;

		paddr = paddr_next;
	}

	return false;
}

/*
 * Architecture function to determine if RAM remap is allowed. By default, a
 * RAM remap will map the data as encrypted. Determine if a RAM remap should
 * not be done so that the data will be mapped decrypted.
 */
bool arch_memremap_can_ram_remap(resource_size_t phys_addr, unsigned long size,
				 unsigned long flags)
{
	if (!sme_active())
		return true;

	if (flags & MEMREMAP_ENC)
		return true;

	if (flags & MEMREMAP_DEC)
		return false;

	if (memremap_is_setup_data(phys_addr, size) ||
	    memremap_is_efi_data(phys_addr, size) ||
	    memremap_should_map_decrypted(phys_addr, size))
		return false;

	return true;
}

/*
 * Architecture override of __weak function to adjust the protection attributes
 * used when remapping memory. By default, early_memremap() will map the data
 * as encrypted. Determine if an encrypted mapping should not be done and set
 * the appropriate protection attributes.
 */
pgprot_t __init early_memremap_pgprot_adjust(resource_size_t phys_addr,
					     unsigned long size,
					     pgprot_t prot)
{
	if (!sme_active())
		return prot;

	if (early_memremap_is_setup_data(phys_addr, size) ||
	    memremap_is_efi_data(phys_addr, size) ||
	    memremap_should_map_decrypted(phys_addr, size))
		prot = pgprot_decrypted(prot);
	else
		prot = pgprot_encrypted(prot);

	return prot;
}

bool phys_mem_access_encrypted(unsigned long phys_addr, unsigned long size)
{
	return arch_memremap_can_ram_remap(phys_addr, size, 0);
}

#ifdef CONFIG_ARCH_USE_MEMREMAP_PROT

static void __init __iomem *
__early_ioremap(resource_size_t phys_addr, unsigned long size, pgprot_t prot);

void __init *
early_memremap_prot(resource_size_t phys_addr, unsigned long size,
		    unsigned long prot_val)
{
	return (__force void *)__early_ioremap(phys_addr, size,
					       __pgprot(prot_val));
}

/* Remap memory with encryption */
void __init *early_memremap_encrypted(resource_size_t phys_addr,
				      unsigned long size)
{
	return early_memremap_prot(phys_addr, size, __PAGE_KERNEL_ENC);
}

/*
 * Remap memory with encryption and write-protected - cannot be called
 * before pat_init() is called
 */
void __init *early_memremap_encrypted_wp(resource_size_t phys_addr,
					 unsigned long size)
{
	/* Be sure the write-protect PAT entry is set for write-protect */
	if (__pte2cachemode_tbl[_PAGE_CACHE_MODE_WP] != _PAGE_CACHE_MODE_WP)
		return NULL;

	return early_memremap_prot(phys_addr, size, __PAGE_KERNEL_ENC_WP);
}

/* Remap memory without encryption */
void __init *early_memremap_decrypted(resource_size_t phys_addr,
				      unsigned long size)
{
	return early_memremap_prot(phys_addr, size, __PAGE_KERNEL_NOENC);
}

/*
 * Remap memory without encryption and write-protected - cannot be called
 * before pat_init() is called
 */
void __init *early_memremap_decrypted_wp(resource_size_t phys_addr,
					 unsigned long size)
{
	/* Be sure the write-protect PAT entry is set for write-protect */
	if (__pte2cachemode_tbl[_PAGE_CACHE_MODE_WP] != _PAGE_CACHE_MODE_WP)
		return NULL;

	return early_memremap_prot(phys_addr, size, __PAGE_KERNEL_NOENC_WP);
}
#endif	/* CONFIG_ARCH_USE_MEMREMAP_PROT */

static int __initdata early_ioremap_debug;

static int __init early_ioremap_debug_setup(char *str)
{
	early_ioremap_debug = 1;

	return 0;
}
early_param("early_ioremap_debug", early_ioremap_debug_setup);

static __initdata int after_paging_init;
static pte_t bm_pte[PAGE_SIZE/sizeof(pte_t)] __page_aligned_bss;

static inline pmd_t * __init early_ioremap_pmd(unsigned long addr)
{
	/* Don't assume we're using swapper_pg_dir at this point */
	pgd_t *base = __va(read_cr3_pa());
	pgd_t *pgd = &base[pgd_index(addr)];
	pud_t *pud = pud_offset(pgd, addr);
	pmd_t *pmd = pmd_offset(pud, addr);

	return pmd;
}

static inline pte_t * __init early_ioremap_pte(unsigned long addr)
{
	return &bm_pte[pte_index(addr)];
}

bool __init is_early_ioremap_ptep(pte_t *ptep)
{
	return ptep >= &bm_pte[0] && ptep < &bm_pte[PAGE_SIZE/sizeof(pte_t)];
}

static unsigned long slot_virt[FIX_BTMAPS_SLOTS] __initdata;

void __init early_ioremap_init(void)
{
	pmd_t *pmd;
	int i;

	if (early_ioremap_debug)
		printk(KERN_INFO "early_ioremap_init()\n");

	for (i = 0; i < FIX_BTMAPS_SLOTS; i++)
		slot_virt[i] = __fix_to_virt(FIX_BTMAP_BEGIN - NR_FIX_BTMAPS*i);

	pmd = early_ioremap_pmd(fix_to_virt(FIX_BTMAP_BEGIN));
	memset(bm_pte, 0, sizeof(bm_pte));
	pmd_populate_kernel(&init_mm, pmd, bm_pte);

	/*
	 * The boot-ioremap range spans multiple pmds, for which
	 * we are not prepared:
	 */
#define __FIXADDR_TOP (-PAGE_SIZE)
	BUILD_BUG_ON((__fix_to_virt(FIX_BTMAP_BEGIN) >> PMD_SHIFT)
		     != (__fix_to_virt(FIX_BTMAP_END) >> PMD_SHIFT));
#undef __FIXADDR_TOP
	if (pmd != early_ioremap_pmd(fix_to_virt(FIX_BTMAP_END))) {
		WARN_ON(1);
		printk(KERN_WARNING "pmd %p != %p\n",
		       pmd, early_ioremap_pmd(fix_to_virt(FIX_BTMAP_END)));
		printk(KERN_WARNING "fix_to_virt(FIX_BTMAP_BEGIN): %08lx\n",
			fix_to_virt(FIX_BTMAP_BEGIN));
		printk(KERN_WARNING "fix_to_virt(FIX_BTMAP_END):   %08lx\n",
			fix_to_virt(FIX_BTMAP_END));

		printk(KERN_WARNING "FIX_BTMAP_END:       %d\n", FIX_BTMAP_END);
		printk(KERN_WARNING "FIX_BTMAP_BEGIN:     %d\n",
		       FIX_BTMAP_BEGIN);
	}
}

void __init early_ioremap_reset(void)
{
	after_paging_init = 1;
}

static void __init __early_set_fixmap(enum fixed_addresses idx,
				      phys_addr_t phys, pgprot_t flags)
{
	unsigned long addr = __fix_to_virt(idx);
	pte_t *pte;

	if (idx >= __end_of_fixed_addresses) {
		BUG();
		return;
	}
	pte = early_ioremap_pte(addr);

	if (pgprot_val(flags))
		set_pte(pte, pfn_pte(phys >> PAGE_SHIFT, flags));
	else
		pte_clear(&init_mm, addr, pte);
	__flush_tlb_one(addr);
}

static inline void __init early_set_fixmap(enum fixed_addresses idx,
					   phys_addr_t phys, pgprot_t prot)
{
	if (after_paging_init)
		__set_fixmap(idx, phys, prot);
	else
		__early_set_fixmap(idx, phys, prot);
}

static inline void __init early_clear_fixmap(enum fixed_addresses idx)
{
	if (after_paging_init)
		clear_fixmap(idx);
	else
		__early_set_fixmap(idx, 0, __pgprot(0));
}

static void __iomem *prev_map[FIX_BTMAPS_SLOTS] __initdata;
static unsigned long prev_size[FIX_BTMAPS_SLOTS] __initdata;

void __init fixup_early_ioremap(void)
{
	int i;

	for (i = 0; i < FIX_BTMAPS_SLOTS; i++) {
		if (prev_map[i]) {
			WARN_ON(1);
			break;
		}
	}

	early_ioremap_init();
}

static int __init check_early_ioremap_leak(void)
{
	int count = 0;
	int i;

	for (i = 0; i < FIX_BTMAPS_SLOTS; i++)
		if (prev_map[i])
			count++;

	if (!count)
		return 0;
	WARN(1, KERN_WARNING
	       "Debug warning: early ioremap leak of %d areas detected.\n",
		count);
	printk(KERN_WARNING
		"please boot with early_ioremap_debug and report the dmesg.\n");

	return 1;
}
late_initcall(check_early_ioremap_leak);

static void __init __iomem *
__early_ioremap(resource_size_t phys_addr, unsigned long size, pgprot_t prot)
{
	unsigned long offset;
	resource_size_t last_addr;
	unsigned int nrpages;
	enum fixed_addresses idx0, idx;
	int i, slot;

	WARN_ON(system_state != SYSTEM_BOOTING);

	slot = -1;
	for (i = 0; i < FIX_BTMAPS_SLOTS; i++) {
		if (!prev_map[i]) {
			slot = i;
			break;
		}
	}

	if (slot < 0) {
		printk(KERN_INFO "early_iomap(%08llx, %08lx) not found slot\n",
			 (u64)phys_addr, size);
		WARN_ON(1);
		return NULL;
	}

	if (early_ioremap_debug) {
		printk(KERN_INFO "early_ioremap(%08llx, %08lx) [%d] => ",
		       (u64)phys_addr, size, slot);
		dump_stack();
	}

	/* Don't allow wraparound or zero size */
	last_addr = phys_addr + size - 1;
	if (!size || last_addr < phys_addr) {
		WARN_ON(1);
		return NULL;
	}

	prev_size[slot] = size;
	/*
	 * Mappings have to be page-aligned
	 */
	offset = phys_addr & ~PAGE_MASK;
	phys_addr &= PAGE_MASK;
	size = PAGE_ALIGN(last_addr + 1) - phys_addr;

	/*
	 * Mappings have to fit in the FIX_BTMAP area.
	 */
	nrpages = size >> PAGE_SHIFT;
	if (nrpages > NR_FIX_BTMAPS) {
		WARN_ON(1);
		return NULL;
	}

	/*
	 * Ok, go for it..
	 */
	idx0 = FIX_BTMAP_BEGIN - NR_FIX_BTMAPS*slot;
	idx = idx0;
	while (nrpages > 0) {
		early_set_fixmap(idx, phys_addr, prot);
		phys_addr += PAGE_SIZE;
		--idx;
		--nrpages;
	}
	if (early_ioremap_debug)
		printk(KERN_CONT "%08lx + %08lx\n", offset, slot_virt[slot]);

	prev_map[slot] = (void __iomem *)(offset + slot_virt[slot]);
	return prev_map[slot];
}

/* Remap an IO device */
void __init __iomem *
early_ioremap(resource_size_t phys_addr, unsigned long size)
{
	return __early_ioremap(phys_addr, size, PAGE_KERNEL_IO);
}

/* Remap memory */
void __init *early_memremap(resource_size_t phys_addr, unsigned long size)
{
	pgprot_t prot = early_memremap_pgprot_adjust(phys_addr, size,
						     PAGE_KERNEL);

	return (__force void *)__early_ioremap(phys_addr, size, prot);
}

void __init early_iounmap(void __iomem *addr, unsigned long size)
{
	unsigned long virt_addr;
	unsigned long offset;
	unsigned int nrpages;
	enum fixed_addresses idx;
	int i, slot;

	slot = -1;
	for (i = 0; i < FIX_BTMAPS_SLOTS; i++) {
		if (prev_map[i] == addr) {
			slot = i;
			break;
		}
	}

	if (slot < 0) {
		printk(KERN_INFO "early_iounmap(%p, %08lx) not found slot\n",
			 addr, size);
		WARN_ON(1);
		return;
	}

	if (prev_size[slot] != size) {
		printk(KERN_INFO "early_iounmap(%p, %08lx) [%d] size not consistent %08lx\n",
			 addr, size, slot, prev_size[slot]);
		WARN_ON(1);
		return;
	}

	if (early_ioremap_debug) {
		printk(KERN_INFO "early_iounmap(%p, %08lx) [%d]\n", addr,
		       size, slot);
		dump_stack();
	}

	virt_addr = (unsigned long)addr;
	if (virt_addr < fix_to_virt(FIX_BTMAP_BEGIN)) {
		WARN_ON(1);
		return;
	}
	offset = virt_addr & ~PAGE_MASK;
	nrpages = PAGE_ALIGN(offset + size) >> PAGE_SHIFT;

	idx = FIX_BTMAP_BEGIN - NR_FIX_BTMAPS*slot;
	while (nrpages > 0) {
		early_clear_fixmap(idx);
		--idx;
		--nrpages;
	}
	prev_map[slot] = NULL;
}

void __init early_memunmap(void *addr, unsigned long size)
{
	early_iounmap((__force void __iomem *)addr, size);
}
