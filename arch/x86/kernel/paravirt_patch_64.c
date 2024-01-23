#include <asm/paravirt.h>
#include <asm/asm-offsets.h>
#include <asm/processor.h>
#include <asm/cpufeature.h>
#include <linux/stringify.h>

DEF_NATIVE(pv_irq_ops, irq_disable, "cli");
DEF_NATIVE(pv_irq_ops, irq_enable, "sti");
DEF_NATIVE(pv_irq_ops, restore_fl, "pushq %rdi; popfq");
DEF_NATIVE(pv_irq_ops, save_fl, "pushfq; popq %rax");
DEF_NATIVE(pv_cpu_ops, iret, "iretq");
DEF_NATIVE(pv_mmu_ops, read_cr2, "movq %cr2, %rax");
DEF_NATIVE(pv_mmu_ops, read_cr3, "movq %cr3, %rax");
DEF_NATIVE(pv_mmu_ops, write_cr3, "movq %rdi, %cr3");
DEF_NATIVE(pv_mmu_ops, flush_tlb_single, "invlpg (%rdi)");
DEF_NATIVE(pv_cpu_ops, clts, "clts");
DEF_NATIVE(pv_cpu_ops, wbinvd, "wbinvd");

DEF_NATIVE(pv_cpu_ops, irq_enable_sysexit, "swapgs; sti; sysexit");
DEF_NATIVE(pv_cpu_ops, usergs_sysret64, "swapgs; sysretq");
DEF_NATIVE(pv_cpu_ops, usergs_sysret32, "swapgs; sysretl");
DEF_NATIVE(pv_cpu_ops, swapgs, "swapgs");

DEF_NATIVE(, mov32, "mov %edi, %eax");
DEF_NATIVE(, mov64, "mov %rdi, %rax");

#if defined(CONFIG_PARAVIRT_SPINLOCKS) && defined(CONFIG_QUEUED_SPINLOCKS)
DEF_NATIVE(pv_lock_ops, queued_spin_unlock, "movb $0, (%rdi)");
DEF_NATIVE(pv_lock_ops, unlock_kick, "nop");
#endif

unsigned paravirt_patch_ident_32(void *insnbuf, unsigned len)
{
	return paravirt_patch_insns(insnbuf, len,
				    start__mov32, end__mov32);
}

unsigned paravirt_patch_ident_64(void *insnbuf, unsigned len)
{
	return paravirt_patch_insns(insnbuf, len,
				    start__mov64, end__mov64);
}

extern bool pv_is_native_spin_unlock(void);

unsigned native_patch(u8 type, u16 clobbers, void *ibuf,
		      unsigned long addr, unsigned len)
{
	const unsigned char *start, *end;
	unsigned ret;

#define PATCH_SITE(ops, x)					\
		case PARAVIRT_PATCH(ops.x):			\
			start = start_##ops##_##x;		\
			end = end_##ops##_##x;			\
			goto patch_site
	switch(type) {
		PATCH_SITE(pv_irq_ops, restore_fl);
		PATCH_SITE(pv_irq_ops, save_fl);
		PATCH_SITE(pv_irq_ops, irq_enable);
		PATCH_SITE(pv_irq_ops, irq_disable);
		PATCH_SITE(pv_cpu_ops, iret);
		PATCH_SITE(pv_cpu_ops, irq_enable_sysexit);
		PATCH_SITE(pv_cpu_ops, usergs_sysret32);
		PATCH_SITE(pv_cpu_ops, usergs_sysret64);
		PATCH_SITE(pv_cpu_ops, swapgs);
		PATCH_SITE(pv_mmu_ops, read_cr2);
		PATCH_SITE(pv_mmu_ops, read_cr3);
		PATCH_SITE(pv_mmu_ops, write_cr3);
		PATCH_SITE(pv_cpu_ops, clts);
		case PARAVIRT_PATCH(pv_mmu_ops.flush_tlb_single):
			if (!boot_cpu_has(X86_FEATURE_PCID)) {
				start = start_pv_mmu_ops_flush_tlb_single;
				end   = end_pv_mmu_ops_flush_tlb_single;
				goto patch_site;
			} else {
				goto patch_default;
			}
		PATCH_SITE(pv_cpu_ops, wbinvd);
#if defined(CONFIG_PARAVIRT_SPINLOCKS) && defined(CONFIG_QUEUED_SPINLOCKS)
		case PARAVIRT_PATCH(pv_lock_ops.unlock_kick):
			if (pv_is_native_spin_unlock()) {
				start = start_pv_lock_ops_unlock_kick;
				end   = end_pv_lock_ops_unlock_kick;
				goto patch_site;
			} else {
				goto patch_default;
			}

		case PARAVIRT_PATCH(pv_lock_ops.queued_spin_unlock):
			if (pv_is_native_spin_unlock()) {
				start = start_pv_lock_ops_queued_spin_unlock;
				end   = end_pv_lock_ops_queued_spin_unlock;
				goto patch_site;
			}
#endif

patch_default:
	default:
		ret = paravirt_patch_default(type, clobbers, ibuf, addr, len);
		break;

patch_site:
		ret = paravirt_patch_insns(ibuf, len, start, end);
		break;
	}
#undef PATCH_SITE
	return ret;
}
