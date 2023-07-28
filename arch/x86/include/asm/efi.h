#ifndef _ASM_X86_EFI_H
#define _ASM_X86_EFI_H

#include <asm/i387.h>
#include <asm/pgtable.h>
#include <asm/processor-flags.h>
#include <asm/tlb.h>
#include <asm/spec_ctrl.h>
#include <asm/mmu_context.h>

/*
 * We map the EFI regions needed for runtime services non-contiguously,
 * with preserved alignment on virtual addresses starting from -4G down
 * for a total max space of 64G. This way, we provide for stable runtime
 * services addresses across kernels so that a kexec'd kernel can still
 * use them.
 *
 * This is the main reason why we're doing stable VA mappings for RT
 * services.
 *
 * This flag is used in conjuction with a chicken bit called
 * "efi=old_map" which can be used as a fallback to the old runtime
 * services mapping method in case there's some b0rkage with a
 * particular EFI implementation (haha, it is hard to hold up the
 * sarcasm here...).
 */
#define EFI_OLD_MEMMAP		EFI_ARCH_1

#define EFI32_LOADER_SIGNATURE	"EL32"
#define EFI64_LOADER_SIGNATURE	"EL64"

#define ARCH_EFI_IRQ_FLAGS_MASK	X86_EFLAGS_IF

#ifdef CONFIG_X86_32

extern unsigned long asmlinkage efi_call_phys(void *, ...);

#define arch_efi_call_virt_setup()					\
{(									\
	bool ibrs_on;							\
	kernel_fpu_begin();						\
	ibrs_on = unprotected_firmware_begin();				\
	ibrs_on;							\
)}

#define arch_efi_call_virt_teardown(ibrs_on)				\
{(									\
	unprotected_firmware_end(ibrs_on);				\
	kernel_fpu_end();						\
)}


/*
 * Wrap all the virtual calls in a way that forces the parameters on the stack.
 */
#define arch_efi_call_virt(p, f, args...)				\
({									\
	((efi_##f##_t __attribute__((regparm(0)))*) p->f)(args);	\
})

#define efi_ioremap(addr, size, type, attr)	ioremap_cache(addr, size)

#else /* !CONFIG_X86_32 */

#define EFI_LOADER_SIGNATURE	"EL64"

extern u64 asmlinkage efi_call(void *fp, ...);

#define efi_call_phys(f, args...)		efi_call((f), args)

/*
 * struct efi_scratch - Scratch space used while switching to/from efi_mm
 * @phys_stack: stack used during EFI Mixed Mode
 * @prev_mm:    store/restore stolen mm_struct while switching to/from efi_mm
 * @cpu_tlbstate: store/restore the previous TLB state (for lazy flushes)
 */
struct efi_scratch {
	u64			phys_stack;
	struct mm_struct	*prev_mm;
	int			cpu_tlbstate;
} __packed;

/*
 * RHEL7: switch_mm() will prematurely flip the cpu_tlbstate back to
 * TLBSTATE_OK for the kernel thread servicing EFI stubs, which can
 * potentially trigger the assertion at leave_mm(), if the work queued
 * to run after the EFI thunk happens to initiate a TLB flush (i.e.:
 * if a flush worker is queued after the efivarsfs read/write work).
 *
 * OTOH, we cannot blindly make the cpu re-enter lazy_tlb state on
 * every call to efi_switch_mm(), as it might also cause issues for
 * the thread running under efi_mm when it's mapped and operated on.
 *
 * In order to address these two diametral corner cases, we need to
 * save the CPU current TLBSTATE before calling efi_switch_mm(&efi_mm),
 * and restore its value after calling efi_switch_mm(efi_scratch.prev_mm);
 */
#define EFI_SAVE_CPU_TLBSTATE()						\
({									\
	efi_scratch.cpu_tlbstate = this_cpu_read(cpu_tlbstate.state);	\
})

#define EFI_RESTORE_CPU_TLBSTATE()					\
({									\
	this_cpu_write(cpu_tlbstate.state, efi_scratch.cpu_tlbstate);	\
})

#define arch_efi_call_virt_setup()					\
({									\
	bool ibrs_on;							\
	efi_sync_low_kernel_mappings();					\
	preempt_disable();						\
	ibrs_on = unprotected_firmware_begin();				\
									\
	if (!efi_enabled(EFI_OLD_MEMMAP)) {				\
		EFI_SAVE_CPU_TLBSTATE();				\
		efi_switch_mm(&efi_mm);					\
	}								\
	ibrs_on;							\
})

#define arch_efi_call_virt(p, f, args...)				\
	efi_call((void *)p->f, args)					\

#define arch_efi_call_virt_teardown(ibrs_on)				\
({									\
	if (!efi_enabled(EFI_OLD_MEMMAP)) {				\
		efi_switch_mm(efi_scratch.prev_mm);			\
		EFI_RESTORE_CPU_TLBSTATE();				\
	}								\
	unprotected_firmware_end(ibrs_on);				\
	preempt_enable();						\
})

extern void __iomem *__init efi_ioremap(unsigned long addr, unsigned long size,
					u32 type, u64 attribute);

#endif /* CONFIG_X86_32 */

extern int add_efi_memmap;
extern struct efi_scratch efi_scratch;
extern void __init efi_set_executable(efi_memory_desc_t *md, bool executable);
extern int __init efi_memblock_x86_reserve_range(void);
extern pgd_t * __init efi_call_phys_prolog(void);
extern void __init efi_call_phys_epilog(pgd_t *save_pgd);
extern void __init efi_unmap_memmap(void);
extern void __init efi_memory_uc(u64 addr, unsigned long size);
extern void __init efi_map_region(efi_memory_desc_t *md);
extern void __init efi_map_region_fixed(efi_memory_desc_t *md);
extern void efi_sync_low_kernel_mappings(void);
extern int __init efi_alloc_page_tables(void);
extern int __init efi_setup_page_tables(unsigned long pa_memmap, unsigned num_pages);
extern void __init old_map_region(efi_memory_desc_t *md);
extern void __init efi_dump_pagetable(void);
extern void __init efi_apply_memmap_quirks(void);
extern int __init efi_reuse_config(u64 tables, int nr_tables);
extern void efi_delete_dummy_variable(void);
extern void efi_switch_mm(struct mm_struct *mm);
extern void efi_recover_from_page_fault(unsigned long phys_addr);

struct efi_setup_data {
	u64 fw_vendor;
	u64 runtime;
	u64 tables;
	u64 smbios;
	u64 reserved[8];
};

extern u64 efi_setup;

#ifdef CONFIG_EFI

static inline bool efi_is_native(void)
{
	return IS_ENABLED(CONFIG_X86_64) == efi_enabled(EFI_64BIT);
}

static inline bool efi_runtime_supported(void)
{
	if (efi_is_native())
		return true;

	if (IS_ENABLED(CONFIG_EFI_MIXED) && !efi_enabled(EFI_OLD_MEMMAP))
		return true;

	return false;
}

extern struct console early_efi_console;

extern void parse_efi_setup(u64 phys_addr, u32 data_len);

#ifdef CONFIG_EFI_MIXED
extern void efi_thunk_runtime_setup(void);
extern efi_status_t efi_thunk_set_virtual_address_map(
	void *phys_set_virtual_address_map,
	unsigned long memory_map_size,
	unsigned long descriptor_size,
	u32 descriptor_version,
	efi_memory_desc_t *virtual_map);
#else
static inline void efi_thunk_runtime_setup(void) {}
static inline efi_status_t efi_thunk_set_virtual_address_map(
	void *phys_set_virtual_address_map,
	unsigned long memory_map_size,
	unsigned long descriptor_size,
	u32 descriptor_version,
	efi_memory_desc_t *virtual_map)
{
	return EFI_SUCCESS;
}
#endif /* CONFIG_EFI_MIXED */
#else
static inline void parse_efi_setup(u64 phys_addr, u32 data_len) {}
#endif /* CONFIG_EFI */

#endif /* _ASM_X86_EFI_H */
