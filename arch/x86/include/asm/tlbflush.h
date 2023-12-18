#ifndef _ASM_X86_TLBFLUSH_H
#define _ASM_X86_TLBFLUSH_H

#include <linux/mm.h>
#include <linux/sched.h>

#include <asm/processor.h>
#include <asm/cpufeature.h>
#include <asm/special_insns.h>

#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#else
#define __flush_tlb() __native_flush_tlb()
#define __flush_tlb_global() __native_flush_tlb_global()
#define __flush_tlb_single(addr) __native_flush_tlb_single(addr)
#endif

static inline void __invpcid(unsigned long pcid, unsigned long addr,
			     unsigned long type)
{
	struct { u64 d[2]; } desc = { { pcid, addr } };

	/*
	 * The memory clobber is because the whole point is to invalidate
	 * stale TLB entries and, especially if we're flushing global
	 * mappings, we don't want the compiler to reorder any subsequent
	 * memory accesses before the TLB flush.
	 *
	 * The hex opcode is invpcid (%ecx), %eax in 32-bit mode and
	 * invpcid (%rcx), %rax in long mode.
	 */
	asm volatile (".byte 0x66, 0x0f, 0x38, 0x82, 0x01"
		      : : "m" (desc), "a" (type), "c" (&desc) : "memory");
}

#define INVPCID_TYPE_INDIV_ADDR		0
#define INVPCID_TYPE_SINGLE_CTXT	1
#define INVPCID_TYPE_ALL_INCL_GLOBAL	2
#define INVPCID_TYPE_ALL_NON_GLOBAL	3

/* Flush all mappings for a given pcid and addr, not including globals. */
static inline void invpcid_flush_one(unsigned long pcid,
				     unsigned long addr)
{
	__invpcid(pcid, addr, INVPCID_TYPE_INDIV_ADDR);
}

/* Flush all mappings for a given PCID, not including globals. */
static inline void invpcid_flush_single_context(unsigned long pcid)
{
	__invpcid(pcid, 0, INVPCID_TYPE_SINGLE_CTXT);
}

/* Flush all mappings, including globals, for all PCIDs. */
static inline void invpcid_flush_all(void)
{
	__invpcid(0, 0, INVPCID_TYPE_ALL_INCL_GLOBAL);
}

/* Flush all mappings for all PCIDs except globals. */
static inline void invpcid_flush_all_nonglobals(void)
{
	__invpcid(0, 0, INVPCID_TYPE_ALL_NON_GLOBAL);
}

#ifdef CONFIG_PAGE_TABLE_ISOLATION

/*
 * RHEL7 Only
 */
#ifdef CONFIG_EFI
/*
 * Test whether this is the EFI pgd_t CR3 value used for EFI runtime services
 */
static inline bool is_efi_pgd_cr3(unsigned long cr3)
{
	extern unsigned long efi_pgd_cr3;
	return cr3 == efi_pgd_cr3;
}
#else

static inline bool is_efi_pgd_cr3(unsigned long cr3)
{
	return false;
}
#endif

static __always_inline void __load_cr3(unsigned long cr3)
{
	if (static_cpu_has(X86_FEATURE_PCID) && kaiser_active()) {
		unsigned long shadow_cr3;
		VM_WARN_ON(cr3 & KAISER_SHADOW_PCID_ASID);
		VM_WARN_ON(cr3 & (1<<KAISER_PGTABLE_SWITCH_BIT));
		VM_WARN_ON(cr3 & X86_CR3_PCID_NOFLUSH);

		if (this_cpu_has(X86_FEATURE_INVPCID_SINGLE)) {
			invpcid_flush_single_context(KAISER_SHADOW_PCID_ASID);
			write_cr3(cr3);
			return;
		}

		/*
		 * RHEL7 Only
		 * The EFI pgd, which maps UEFI runtime services code and data
		 * in addition to kernel space but no userspace, does not have
		 * a shadow pgd. This exclusion is "RHEL7 Only" because the
		 * subsequent performance optimization for processors with the
		 * PCID feature but without INVPCID_SINGLE is also RHEL7 only.
		 */
		if (is_efi_pgd_cr3(cr3)) {
			write_cr3(cr3);
			return;
		}

		shadow_cr3 = cr3 | (1<<KAISER_PGTABLE_SWITCH_BIT) |
			KAISER_SHADOW_PCID_ASID;
		asm volatile("\tjmp 1f\n\t"
			     "2:\n\t"
			     ".section .entry.text, \"ax\"\n\t"
			     "1:\n\t"
			     "pushf\n\t"
			     "cli\n\t"
			     "movq %0, %%cr3\n\t"
			     "movq %1, %%cr3\n\t"
			     "popf\n\t"
			     "jmp 2b\n\t"
			     ".previous" : :
			     "r" (shadow_cr3), "r" (cr3) :
			     "memory");
	} else
		write_cr3(cr3);
}
#else /* CONFIG_PAGE_TABLE_ISOLATION */
static __always_inline void __load_cr3(unsigned long cr3)
{
	write_cr3(cr3);
}
#endif /* CONFIG_PAGE_TABLE_ISOLATION */

static inline void __native_flush_tlb(void)
{
	if (!static_cpu_has(X86_FEATURE_INVPCID)) {
		__load_cr3(native_read_cr3());
		return;
	}
	/*
	 * Note, this works with CR4.PCIDE=0 or 1.
	 */
	invpcid_flush_all_nonglobals();
}

static inline void __native_flush_tlb_global_irq_disabled(void)
{
	unsigned long cr4;

	cr4 = native_read_cr4();
	/*
	 * This function is only called on systems that support X86_CR4_PGE
	 * and where we expect X86_CR4_PGE to be set.  Warn if we are called
	 * without PGE set.
	 */
	WARN_ON_ONCE(!(cr4 & X86_CR4_PGE));

	/*
	 * Architecturally, any _change_ to X86_CR4_PGE will fully flush
	 * all entries.  Make sure that we _change_ the bit, regardless of
	 * whether we had X86_CR4_PGE set in the first place.
	 *
	 * Note that just toggling PGE *also* flushes all entries from all
	 * PCIDs, regardless of the state of X86_CR4_PCIDE.
	 */
	native_write_cr4(cr4 ^ X86_CR4_PGE);

	/* Put original CR4 value back: */
	native_write_cr4(cr4);
}

static inline void __native_flush_tlb_global(void)
{
	unsigned long flags;

	if (static_cpu_has(X86_FEATURE_INVPCID)) {
		/*
		 * Using INVPCID is considerably faster than a pair of writes
		 * to CR4 sandwiched inside an IRQ flag save/restore.
		 *
		 * Note, this works with CR4.PCIDE=0 or 1.
		 */
		invpcid_flush_all();
		return;
	}

	/*
	 * Read-modify-write to CR4 - protect it from preemption and
	 * from interrupts. (Use the raw variant because this code can
	 * be called from deep inside debugging code.)
	 */
	raw_local_irq_save(flags);

	__native_flush_tlb_global_irq_disabled();

	raw_local_irq_restore(flags);
}

static inline void __native_flush_tlb_single(unsigned long addr)
{
#ifdef CONFIG_PAGE_TABLE_ISOLATION
	unsigned long cr3, shadow_cr3;

	/* Flush the address out of both PCIDs. */
	/*
	 * An optimization here might be to determine addresses
	 * that are only kernel-mapped and only flush the kernel
	 * ASID.  But, userspace flushes are probably much more
	 * important performance-wise.
	 *
	 * Make sure to do only a single invpcid when KAISER is
	 * disabled and we have only a single ASID.
	 */
	if (static_cpu_has(X86_FEATURE_PCID) && kaiser_active()) {
		/*
		 * Some platforms #GP if we call invpcid(type=1/2) before
		 * CR4.PCIDE=1.  Just call invpcid in the case we are called
		 * early.
		 */
		if (this_cpu_has(X86_FEATURE_INVPCID_SINGLE)) {
			invpcid_flush_one(KAISER_SHADOW_PCID_ASID, addr);
			invpcid_flush_one(0, addr);
			return;
		}

		cr3 = native_read_cr3();
		VM_WARN_ON(cr3 & KAISER_SHADOW_PCID_ASID);
		VM_WARN_ON(cr3 & (1<<KAISER_PGTABLE_SWITCH_BIT));
		VM_WARN_ON(cr3 & X86_CR3_PCID_NOFLUSH);
		cr3 |= X86_CR3_PCID_NOFLUSH;
		shadow_cr3 = cr3 | (1<<KAISER_PGTABLE_SWITCH_BIT) |
			KAISER_SHADOW_PCID_ASID;
		asm volatile("\tjmp 1f\n\t"
			     "2:\n\t"
			     ".section .entry.text, \"ax\"\n\t"
			     "1:\n\t"
			     "pushf\n\t"
			     "cli\n\t"
			     "movq %0, %%cr3\n\t"
			     "invlpg (%2)\n\t"
			     "movq %1, %%cr3\n\t"
			     "popf\n\t"
			     "invlpg (%2)\n\t"
			     "jmp 2b\n\t"
			     ".previous" : :
			     "r" (shadow_cr3), "r" (cr3), "r" (addr) :
			     "memory");
	} else
#endif
		asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}

static inline void __flush_tlb_all(void)
{
	if (cpu_has_pge)
		__flush_tlb_global();
	else
		__flush_tlb();
}

static inline void __flush_tlb_one(unsigned long addr)
{
		__flush_tlb_single(addr);
}

#define TLB_FLUSH_ALL	-1UL

/*
 * TLB flushing:
 *
 *  - flush_tlb_all() flushes all processes TLBs
 *  - flush_tlb_mm(mm) flushes the specified mm context TLB's
 *  - flush_tlb_page(vma, vmaddr) flushes one page
 *  - flush_tlb_range(vma, start, end) flushes a range of pages
 *  - flush_tlb_kernel_range(start, end) flushes a range of kernel pages
 *  - flush_tlb_others(cpumask, mm, start, end) flushes TLBs on other cpus
 *
 * ..but the i386 has somewhat limited tlb flushing capabilities,
 * and page-granular flushes are available only on i486 and up.
 */

#ifndef CONFIG_SMP

#define flush_tlb() __flush_tlb()
#define flush_tlb_all() __flush_tlb_all()
#define local_flush_tlb() __flush_tlb()

static inline void flush_tlb_mm(struct mm_struct *mm)
{
	if (mm == current->active_mm)
		__flush_tlb();
}

static inline void flush_tlb_page(struct vm_area_struct *vma,
				  unsigned long addr)
{
	if (vma->vm_mm == current->active_mm)
		__flush_tlb_one(addr);
}

static inline void flush_tlb_range(struct vm_area_struct *vma,
				   unsigned long start, unsigned long end)
{
	if (vma->vm_mm == current->active_mm)
		__flush_tlb();
}

static inline void flush_tlb_mm_range(struct mm_struct *mm,
	   unsigned long start, unsigned long end, unsigned long vmflag)
{
	if (mm == current->active_mm)
		__flush_tlb();
}

static inline void native_flush_tlb_others(const struct cpumask *cpumask,
					   struct mm_struct *mm,
					   unsigned long start,
					   unsigned long end)
{
}

static inline void reset_lazy_tlbstate(void)
{
}

static inline void flush_tlb_kernel_range(unsigned long start,
					  unsigned long end)
{
	flush_tlb_all();
}

#else  /* SMP */

#include <asm/smp.h>

#define local_flush_tlb() __flush_tlb()

#define flush_tlb_mm(mm)	flush_tlb_mm_range(mm, 0UL, TLB_FLUSH_ALL, 0UL)

#define flush_tlb_range(vma, start, end)	\
		flush_tlb_mm_range(vma->vm_mm, start, end, vma->vm_flags)

extern void flush_tlb_all(void);
extern void flush_tlb_page(struct vm_area_struct *, unsigned long);
extern void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
				unsigned long end, unsigned long vmflag);
extern void flush_tlb_kernel_range(unsigned long start, unsigned long end);

void native_flush_tlb_others(const struct cpumask *cpumask,
				struct mm_struct *mm,
				unsigned long start, unsigned long end);

#define TLBSTATE_OK	1
#define TLBSTATE_LAZY	2

struct tlb_state {
	struct mm_struct *active_mm;
	int state;
};
DECLARE_PER_CPU_SHARED_ALIGNED(struct tlb_state, cpu_tlbstate);

static inline void reset_lazy_tlbstate(void)
{
	this_cpu_write(cpu_tlbstate.state, 0);
	this_cpu_write(cpu_tlbstate.active_mm, &init_mm);
}

#endif	/* SMP */

/* Not inlined due to inc_irq_stat not being defined yet */
#define flush_tlb_local() {		\
	inc_irq_stat(irq_tlb_count);	\
	local_flush_tlb();		\
}

#ifndef CONFIG_PARAVIRT
#define flush_tlb_others(mask, mm, start, end)	\
	native_flush_tlb_others(mask, mm, start, end)
#endif

#endif /* _ASM_X86_TLBFLUSH_H */
