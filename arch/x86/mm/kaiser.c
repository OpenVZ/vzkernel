/*
 * Copyright(c) 2017 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * This code is based in part on work published here:
 *
 *	https://github.com/IAIK/KAISER
 *
 * The original work was written by and and signed off by for the Linux
 * kernel by:
 *
 *   Signed-off-by: Richard Fellner <richard.fellner@student.tugraz.at>
 *   Signed-off-by: Moritz Lipp <moritz.lipp@iaik.tugraz.at>
 *   Signed-off-by: Daniel Gruss <daniel.gruss@iaik.tugraz.at>
 *   Signed-off-by: Michael Schwarz <michael.schwarz@iaik.tugraz.at>
 *
 * Major changes to the original code by: Dave Hansen <dave.hansen@intel.com>
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/stop_machine.h>
#include <linux/cpu.h>

#include <asm/kaiser.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>
#include <asm/kvmclock.h>
#include <asm/cmpxchg.h>

#define KAISER_WALK_ATOMIC  0x1

static pteval_t kaiser_pte_mask __read_mostly = ~(_PAGE_NX | _PAGE_GLOBAL);

/*
 * We need a two-stage enable/disable.  One (kaiser_enabled) to stop
 * the ongoing work that keeps KAISER from being disabled (like PGD
 * poisoning) and another (kaiser_asm_do_switch) that we set when it
 * is completely safe to run without doing KAISER switches.
 */
int kaiser_enabled __read_mostly;

/*
 * The flag that captures the command line "nopti" option.
 *  0 - auto
 * -1 - disabled
 */
static int kpti_force_enabled __read_mostly;

/*
 * At runtime, the only things we map are some things for CPU
 * hotplug, and stacks for new processes.  No two CPUs will ever
 * be populating the same addresses, so we only need to ensure
 * that we protect between two CPUs trying to allocate and
 * populate the same page table page.
 *
 * Only take this lock when doing a set_p[4um]d(), but it is not
 * needed for doing a set_pte().  We assume that only the *owner*
 * of a given allocation will be doing this for _their_
 * allocation.
 *
 * This ensures that once a system has been running for a while
 * and there have been stacks all over and these page tables
 * are fully populated, there will be no further acquisitions of
 * this lock.
 */
static DEFINE_SPINLOCK(shadow_table_allocation_lock);

/*
 * This is only for walking kernel addresses.  We use it to help
 * recreate the "shadow" page tables which are used while we are in
 * userspace.
 *
 * This can be called on any kernel memory addresses and will work
 * with any page sizes and any types: normal linear map memory,
 * vmalloc(), even kmap().
 *
 * Note: this is only used when mapping new *kernel* entries into
 * the user/shadow page tables.  It is never used for userspace
 * addresses.
 *
 * Returns -1 on error.
 */
static inline unsigned long get_pa_from_kernel_map(unsigned long vaddr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	/* We should only be asked to walk kernel addresses */
	if (vaddr < PAGE_OFFSET) {
		WARN_ON_ONCE(1);
		return -1;
	}

	pgd = pgd_offset_k(vaddr);
	/*
	 * We made all the kernel PGDs present in kaiser_init().
	 * We expect them to stay that way.
	 */
	if (pgd_none(*pgd)) {
		WARN_ON_ONCE(1);
		return -1;
	}
	/*
	 * PGDs are either 512GB or 128TB on all x86_64
	 * configurations.  We don't handle these.
	 */
	BUILD_BUG_ON(pgd_large(*pgd) != 0);

	pud = pud_offset(pgd, vaddr);
	if (pud_none(*pud)) {
		WARN_ON_ONCE(1);
		return -1;
	}

	if (pud_large(*pud))
		return (pud_pfn(*pud) << PAGE_SHIFT) | (vaddr & ~PUD_PAGE_MASK);

	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd)) {
		WARN_ON_ONCE(1);
		return -1;
	}

	if (pmd_large(*pmd))
		return (pmd_pfn(*pmd) << PAGE_SHIFT) | (vaddr & ~PMD_PAGE_MASK);

	pte = pte_offset_kernel(pmd, vaddr);
	if (pte_none(*pte)) {
		WARN_ON_ONCE(1);
		return -1;
	}

	return (pte_pfn(*pte) << PAGE_SHIFT) | (vaddr & ~PAGE_MASK);
}

/*
 * Walk the shadow copy of the page tables (optionally) trying to
 * allocate page table pages on the way down.  Does not support
 * large pages since the data we are mapping is (generally) not
 * large enough or aligned to 2MB.
 *
 * Note: this is only used when mapping *new* kernel data into the
 * user/shadow page tables.  It is never used for userspace data.
 *
 * Returns a pointer to a PTE on success, or NULL on failure.
 */
static pte_t *kaiser_shadow_pagetable_walk(unsigned long address,
					   unsigned long flags)
{
	pte_t *pte;
	pmd_t *pmd;
	pud_t *pud;
	pgd_t *pgd = kernel_to_shadow_pgdp(pgd_offset_k(address));
	gfp_t gfp = (GFP_KERNEL | __GFP_NOTRACK | __GFP_ZERO);

	if (flags & KAISER_WALK_ATOMIC) {
		gfp &= ~GFP_KERNEL;
		gfp |= GFP_ATOMIC;
	}

	if (address < PAGE_OFFSET) {
		WARN_ONCE(1, "attempt to walk user address\n");
		return NULL;
	}

	if (pgd_none(*pgd)) {
		WARN_ONCE(1, "All shadow pgds should have been populated\n");
		return NULL;
	}
	BUILD_BUG_ON(pgd_large(*pgd) != 0);

	pud = pud_offset(pgd, address);
	/* The shadow page tables do not use large mappings: */
	if (pud_large(*pud)) {
		WARN_ON(1);
		return NULL;
	}
	if (pud_none(*pud)) {
		unsigned long new_pmd_page = __get_free_page(gfp);
		if (!new_pmd_page)
			return NULL;

		spin_lock(&shadow_table_allocation_lock);
		if (pud_none(*pud))
			set_pud(pud, __pud(_PAGE_TABLE | __pa(new_pmd_page)));
		else
			free_page(new_pmd_page);
		spin_unlock(&shadow_table_allocation_lock);
	}

	pmd = pmd_offset(pud, address);
	/* The shadow page tables do not use large mappings: */
	if (pmd_large(*pmd)) {
		WARN_ON(1);
		return NULL;
	}
	if (pmd_none(*pmd)) {
		unsigned long new_pte_page = __get_free_page(gfp);
		if (!new_pte_page)
			return NULL;

		spin_lock(&shadow_table_allocation_lock);
		if (pmd_none(*pmd))
			set_pmd(pmd, __pmd(_PAGE_TABLE  | __pa(new_pte_page)));
		else
			free_page(new_pte_page);
		spin_unlock(&shadow_table_allocation_lock);
	}

	pte = pte_offset_kernel(pmd, address);
	if (pte_flags(*pte) & _PAGE_USER) {
		WARN_ONCE(1, "attempt to walk to user pte\n");
		return NULL;
	}
	return pte;
}

/*
 * Given a kernel address, @__start_addr, copy that mapping into
 * the user (shadow) page tables.  This may need to allocate page
 * table pages.
 */
int kaiser_add_user_map(const void *__start_addr, unsigned long size,
			unsigned long flags)
{
	unsigned long start_addr = (unsigned long)__start_addr;
	unsigned long address = start_addr & PAGE_MASK;
	unsigned long end_addr = PAGE_ALIGN(start_addr + size);
	unsigned long target_address;
	pte_t *pte;

	/* Clear not supported bits */
	flags &= kaiser_pte_mask;

	for (; address < end_addr; address += PAGE_SIZE) {
		target_address = get_pa_from_kernel_map(address);
		if (target_address == -1)
			return -EIO;

		pte = kaiser_shadow_pagetable_walk(address, false);
		/*
		 * Errors come from either -ENOMEM for a page
		 * table page, or something screwy that did a
		 * WARN_ON().  Just return -ENOMEM.
		 */
		if (!pte)
			return -ENOMEM;
		if (pte_none(*pte)) {
			set_pte(pte, __pte(flags | target_address));
		} else {
			pte_t tmp;
			/*
			 * Make a fake, temporary PTE that mimics the
			 * one we would have created.
			 */
			set_pte(&tmp, __pte(flags | target_address));
			/*
			 * Warn if the pte that would have been
			 * created is different from the one that
			 * was there previously.  In other words,
			 * we allow the same PTE value to be set,
			 * but not changed.
			 */
			WARN_ON_ONCE(!pte_same(*pte, tmp));
		}
	}
	return 0;
}

int kaiser_add_user_map_ptrs(const void *__start_addr,
			     const void *__end_addr,
			     unsigned long flags)
{
	return kaiser_add_user_map(__start_addr,
				   __end_addr - __start_addr,
				   flags);
}

/*
 * Ensure that the top level of the (shadow) page tables are
 * entirely populated.  This ensures that all processes that get
 * forked have the same entries.  This way, we do not have to
 * ever go set up new entries in older processes.
 *
 * Note: we never free these, so there are no updates to them
 * after this.
 */
static void __init kaiser_init_all_pgds(void)
{
	pgd_t *pgd;
	int i;

	if (__supported_pte_mask & _PAGE_NX)
		kaiser_pte_mask |= _PAGE_NX;
	if (boot_cpu_has(X86_FEATURE_PGE))
		kaiser_pte_mask |= _PAGE_GLOBAL;

	pgd = kernel_to_shadow_pgdp(pgd_offset_k(0UL));
	for (i = PTRS_PER_PGD / 2; i < PTRS_PER_PGD; i++) {
		/*
		 * Each PGD entry moves up PGDIR_SIZE bytes through
		 * the address space, so get the first virtual
		 * address mapped by PGD #i:
		 */
		unsigned long addr = i * PGDIR_SIZE;
		pud_t *pud = pud_alloc_one(&init_mm, addr);
		if (!pud) {
			WARN_ON(1);
			break;
		}
		set_pgd(pgd + i, __pgd(_PAGE_TABLE | __pa(pud)));
	}
}

/*
 * Page table allocations called by kaiser_add_user_map() can
 * theoretically fail, but are very unlikely to fail in early boot.
 * This would at least output a warning before crashing.
 *
 * Do the checking and warning in a macro to make it more readable and
 * preserve line numbers in the warning message that you would not get
 * with an inline.
 */
#define kaiser_add_user_map_early(__start, __size, __flags)	\
do {								\
	int __ret = kaiser_add_user_map((__start), (__size),	\
					(__flags));		\
	WARN_ON(__ret);						\
} while (0)

#define kaiser_add_user_map_ptrs_early(__start, __end, __flags) do {	\
	int __ret = kaiser_add_user_map_ptrs((__start), (__end),	\
					     (__flags));		\
	WARN_ON(__ret);							\
} while (0)

static void kaiser_enable_pcp(bool enable)
{
	int cpu, val = 0;
	if (enable) {
		val = KAISER_PCP_ENABLED;
		if (boot_cpu_has(X86_FEATURE_PCID))
			val |= KAISER_PCP_PCID;
	}
	for_each_possible_cpu(cpu)
		WRITE_ONCE(per_cpu(kaiser_enabled_pcp, cpu), val);
}

extern char __per_cpu_user_mapped_start[], __per_cpu_user_mapped_end[];

void kaiser_add_mapping_cpu_entry(int cpu)
{
	/* includes the entry stack */
	void *percpu_vaddr = __per_cpu_user_mapped_start +
		per_cpu_offset(cpu);
	unsigned long percpu_sz = __per_cpu_user_mapped_end -
		__per_cpu_user_mapped_start;
	kaiser_add_user_map_early(percpu_vaddr, percpu_sz,
				  __PAGE_KERNEL | _PAGE_GLOBAL);
}

static bool is_xen_pv_domain(void)
{
#ifdef CONFIG_XEN
	return xen_pv_domain();
#else
	return false;
#endif
}

static int __init force_nokpti(char *arg)
{
	kpti_force_enabled = -1;
	return 0;
}
early_param("nopti", force_nokpti);

/*
 * If anything in here fails, we will likely die on one of the
 * first kernel->user transitions and init will die.  But, we
 * will have most of the kernel up by then and should be able to
 * get a clean warning out of it.  If we BUG_ON() here, we run
 * the risk of being before we have good console output.
 *
 * When KAISER is enabled, we remove _PAGE_GLOBAL from all of the
 * kernel PTE permissions.  This ensures that the TLB entries for
 * the kernel are not available when in userspace.  However, for
 * the pages that are available to userspace *anyway*, we might as
 * well continue to map them _PAGE_GLOBAL and enjoy the potential
 * performance advantages.
 */
void __init kaiser_init(void)
{
	int cpu, idx;
	extern enum { EMULATE, NATIVE, NONE } vsyscall_mode;
	kaiser_init_all_pgds();

	for_each_possible_cpu(cpu)
		kaiser_add_mapping_cpu_entry(cpu);

	kaiser_add_user_map_ptrs_early(__entry_text_start, __entry_text_end,
				       __PAGE_KERNEL_RX | _PAGE_GLOBAL);

	/* the fixed map address of the idt_table */
	kaiser_add_user_map_early((void *)idt_descr.address,
				  sizeof(gate_desc) * NR_VECTORS,
				  __PAGE_KERNEL_RO | _PAGE_GLOBAL);

	kaiser_add_user_map_early(&debug_idt_table,
				  sizeof(gate_desc) * NR_VECTORS,
				  __PAGE_KERNEL | _PAGE_GLOBAL);

	kaiser_add_user_map_early(&trace_idt_table,
				  sizeof(gate_desc) * NR_VECTORS,
				  __PAGE_KERNEL | _PAGE_GLOBAL);

	kaiser_add_user_map_ptrs_early(__kprobes_text_start,
				       __kprobes_text_end,
				       __PAGE_KERNEL_RX | _PAGE_GLOBAL);

	/*
	 * .irqentry.text helps us identify code that runs before
	 * we get a chance to call entering_irq().  This includes
	 * the interrupt entry assembly plus the first C function
	 * that gets called.  KAISER does not need the C code
	 * mapped.  We just use the .irqentry.text section as-is
	 * to avoid having to carve out a new section for the
	 * assembly only.
	 */
	kaiser_add_user_map_ptrs_early(__irqentry_text_start,
				       __irqentry_text_end,
				       __PAGE_KERNEL_RX | _PAGE_GLOBAL);

	kaiser_add_user_map_early((void *)VVAR_ADDRESS, PAGE_SIZE,
				  __PAGE_KERNEL_VVAR | _PAGE_GLOBAL);
	kaiser_add_user_map_early((void *)VSYSCALL_START, PAGE_SIZE,
				  vsyscall_mode == NATIVE
				  ? __PAGE_KERNEL_VSYSCALL | _PAGE_GLOBAL
				  : __PAGE_KERNEL_VVAR | _PAGE_GLOBAL);
#ifdef CONFIG_PARAVIRT_CLOCK
	for (idx = 0; kvm_clock.archdata.vclock_mode == VCLOCK_PVCLOCK &&
		     idx <= (PVCLOCK_FIXMAP_END-PVCLOCK_FIXMAP_BEGIN); idx++) {
		kaiser_add_user_map_early((void *)__fix_to_virt(PVCLOCK_FIXMAP_BEGIN + idx),
					  PAGE_SIZE,
					  __PAGE_KERNEL_VVAR | _PAGE_GLOBAL);
	}
#endif

	if (is_xen_pv_domain()) {
		pr_info("x86/pti: Xen PV detected, disabling "
			"PTI protection\n");
	} else if (!cpu_mitigations_off() && ((kpti_force_enabled > 0) ||
		   (boot_cpu_has_bug(X86_BUG_CPU_MELTDOWN) &&
		   !kpti_force_enabled))) {
		pr_info("x86/pti: Unmapping kernel while in userspace\n");
		kaiser_enable_pcp(true);
		kaiser_enabled = 1;
	}
}

int kaiser_add_mapping(unsigned long addr, unsigned long size,
		       unsigned long flags)
{
	return kaiser_add_user_map((const void *)addr, size, flags);
}

void kaiser_remove_mapping(unsigned long start, unsigned long size)
{
	unsigned long addr;

	/* The shadow page tables always use small pages: */
	for (addr = start; addr < start + size; addr += PAGE_SIZE) {
		/*
		 * Do an "atomic" walk in case this got called from an atomic
		 * context.  This should not do any allocations because we
		 * should only be walking things that are known to be mapped.
		 */
		pte_t *pte = kaiser_shadow_pagetable_walk(addr, KAISER_WALK_ATOMIC);

		/*
		 * We are removing a mapping that should
		 * exist.  WARN if it was not there:
		 */
		if (!pte) {
			WARN_ON_ONCE(1);
			continue;
		}

		pte_clear(&init_mm, addr, pte);
	}
	/*
	 * This ensures that the TLB entries used to map this data are
	 * no longer usable on *this* CPU.  We theoretically want to
	 * flush the entries on all CPUs here, but that's too
	 * expensive right now: this is called to unmap process
	 * stacks in the exit() path.
	 *
	  This can change if we get to the point where this is not
	 * in a remotely hot path, like only called via write_ldt().
	 *
	 * Note: we could probably also just invalidate the individual
	 * addresses to take care of *this* PCID and then do a
	 * tlb_flush_shared_nonglobals() to ensure that all other
	 * PCIDs get flushed before being used again.
	 */
	__native_flush_tlb_global();
}

static ssize_t kaiser_enabled_read_file(struct file *file, char __user *user_buf,
			     size_t count, loff_t *ppos)
{
	char buf[32];
	unsigned int len;

	len = sprintf(buf, "%d\n", kaiser_enabled);
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

enum poison {
	KAISER_POISON,
	KAISER_UNPOISON
};
void kaiser_poison_pgds(enum poison do_poison);

enum {
	FIRST_STOP_MACHINE_INIT,
	FIRST_STOP_MACHINE_START,
	FIRST_STOP_MACHINE_END,
};
static int first_stop_machine;
static int kaiser_stop_machine(void *data)
{
	bool enable = !!*(unsigned int *)data;
	int first;

	first = cmpxchg(&first_stop_machine, FIRST_STOP_MACHINE_INIT,
			FIRST_STOP_MACHINE_START);
	if (first == FIRST_STOP_MACHINE_INIT) {
		/* Tell the assembly code to start/stop switching CR3. */
		kaiser_enable_pcp(enable);
		kaiser_poison_pgds(enable ? KAISER_POISON : KAISER_UNPOISON);
		smp_wmb();
		WRITE_ONCE(first_stop_machine, FIRST_STOP_MACHINE_END);
	} else {
		do {
			cpu_relax();
		} while (READ_ONCE(first_stop_machine) !=
			 FIRST_STOP_MACHINE_END);
		smp_rmb();
	}
	__flush_tlb_all();

	return 0;
}

static ssize_t kaiser_enabled_write_file(struct file *file,
		 const char __user *user_buf, size_t count, loff_t *ppos)
{
	char buf[32];
	ssize_t len;
	unsigned int enable;
	ssize_t err;
	static DEFINE_MUTEX(enable_mutex);

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtouint(buf, 0, &enable))
		return -EINVAL;

	if (enable > 1)
		return -EINVAL;

	mutex_lock(&enable_mutex);
	if (kaiser_enabled == enable)
		goto out_unlock;

	first_stop_machine = FIRST_STOP_MACHINE_INIT;
	get_online_cpus();
	err = __stop_machine(kaiser_stop_machine, &enable, cpu_online_mask);
	put_online_cpus();
	if (err) {
		VM_WARN_ON(1);
		count = err;
	} else
		kaiser_enabled = enable;

out_unlock:
	mutex_unlock(&enable_mutex);
	return count;
}

static const struct file_operations fops_kaiser_enabled = {
	.read = kaiser_enabled_read_file,
	.write = kaiser_enabled_write_file,
	.llseek = default_llseek,
};

static int __init create_kpti_enabled(void)
{
	if (!xen_pv_domain() && !sme_active())
		debugfs_create_file("pti_enabled", S_IRUSR | S_IWUSR,
				    arch_debugfs_dir, NULL, &fops_kaiser_enabled);
	return 0;
}
late_initcall(create_kpti_enabled);

void kaiser_poison_pgd_page(pgd_t *pgd_page, enum poison do_poison)
{
	int i = 0;

	for (i = 0; i < PTRS_PER_PGD; i++) {
		pgd_t *pgd = &pgd_page[i];

		/* Stop once we hit kernel addresses: */
		if (!pgdp_maps_userspace(pgd))
			break;

		if (do_poison == KAISER_POISON)
			kaiser_poison_pgd_atomic(pgd);
		else
			kaiser_unpoison_pgd_atomic(pgd);
	}

}

void kaiser_poison_pgds(enum poison do_poison)
{
	struct page *page;

	spin_lock(&pgd_lock);
	list_for_each_entry(page, &pgd_list, lru) {
		pgd_t *pgd = (pgd_t *)page_address(page);
		kaiser_poison_pgd_page(pgd, do_poison);
	}
	spin_unlock(&pgd_lock);
}

/*
 * Won't compile inline in pgtable headers, where it has to be called
 * from. This is only called in a slow path unless DEBUG_VM=y so it's
 * not a concern.
 */
bool is_kaiser_pgd(pgd_t *pgd)
{
	return (pgd >= init_mm.pgd && pgd < init_mm.pgd + PTRS_PER_PGD) ||
		!list_empty(&virt_to_page(pgd)->lru);
}
