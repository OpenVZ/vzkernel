/*
 *  S390 version
 *
 *  Derived from "include/asm-i386/mmu_context.h"
 */

#ifndef __S390_MMU_CONTEXT_H
#define __S390_MMU_CONTEXT_H

#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/tlbflush.h>
#include <asm/ctl_reg.h>

static inline int init_new_context(struct task_struct *tsk,
				   struct mm_struct *mm)
{
	atomic_set(&mm->context.attach_count, 0);
	mm->context.flush_mm = 0;
	mm->context.has_pgste = 0;
	switch (mm->context.asce_limit) {
	case 1UL << 42:
		/*
		 * forked 3-level task, fall through to set new asce with new
		 * mm->pgd
		 */
	case 0:
		/* context created by exec, set asce limit to 4TB */
		mm->context.asce = __pa(mm->pgd) | _ASCE_TABLE_LENGTH |
				   _ASCE_USER_BITS;
#ifdef CONFIG_64BIT
		mm->context.asce |= _ASCE_TYPE_REGION3;
#endif
		mm->context.asce_limit = STACK_TOP_MAX;
		break;
	case 1UL << 53:
		/* forked 4-level task, set new asce with new mm->pgd */
		mm->context.asce = __pa(mm->pgd) | _ASCE_TABLE_LENGTH |
				   _ASCE_USER_BITS | _ASCE_TYPE_REGION2;
		break;
	case 1UL << 31:
		/* forked 2-level compat task, set new asce with new mm->pgd */
		mm->context.asce = __pa(mm->pgd) | _ASCE_TABLE_LENGTH |
				   _ASCE_USER_BITS | _ASCE_TYPE_SEGMENT;
	}
	crst_table_init((unsigned long *) mm->pgd, pgd_entry_type(mm));
	return 0;
}

#define destroy_context(mm)             do { } while (0)

static inline void update_primary_asce(struct task_struct *tsk)
{
	unsigned long asce;

	__ctl_store(asce, 1, 1);
	if (asce != S390_lowcore.kernel_asce)
		__ctl_load(S390_lowcore.kernel_asce, 1, 1);
	set_tsk_thread_flag(tsk, TIF_ASCE);
}

static inline void update_mm(struct mm_struct *mm, struct task_struct *tsk)
{
	S390_lowcore.user_asce = mm->context.asce;
	set_fs(current->thread.mm_segment);
	update_primary_asce(tsk);
}

static inline void switch_mm(struct mm_struct *prev, struct mm_struct *next,
			     struct task_struct *tsk)
{
	cpumask_set_cpu(smp_processor_id(), mm_cpumask(next));
	update_mm(next, tsk);
	atomic_dec(&prev->context.attach_count);
	WARN_ON(atomic_read(&prev->context.attach_count) < 0);
	atomic_inc(&next->context.attach_count);
	/* Check for TLBs not flushed yet */
	__tlb_flush_mm_lazy(next);
}

#define enter_lazy_tlb(mm,tsk)	do { } while (0)
#define deactivate_mm(tsk,mm)	do { } while (0)

static inline void activate_mm(struct mm_struct *prev,
                               struct mm_struct *next)
{
        switch_mm(prev, next, current);
}

static inline void arch_dup_mmap(struct mm_struct *oldmm,
				 struct mm_struct *mm)
{
}

static inline void arch_exit_mmap(struct mm_struct *mm)
{
}

static inline void arch_unmap(struct mm_struct *mm,
			struct vm_area_struct *vma,
			unsigned long start, unsigned long end)
{
}

static inline void arch_bprm_mm_init(struct mm_struct *mm,
				     struct vm_area_struct *vma)
{
}

static inline bool arch_vma_access_permitted(struct vm_area_struct *vma,
		bool write, bool execute, bool foreign)
{
	/* by default, allow everything */
	return true;
}

static inline bool arch_pte_access_permitted(pte_t pte, bool write)
{
	/* by default, allow everything */
	return true;
}
#endif /* __S390_MMU_CONTEXT_H */
