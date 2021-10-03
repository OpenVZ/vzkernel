#ifndef _LINUX_SCHED_MM_H
#define _LINUX_SCHED_MM_H

#include <linux/sched.h>
#include <linux/sync_core.h>

/*
 * This has to be called after a get_task_mm()/mmget_not_zero()
 * followed by taking the mmap_sem for writing before modifying the
 * vmas or anything the coredump pretends not to change from under it.
 *
 * It also has to be called when mmgrab() is used in the context of
 * the process, but then the mm_count refcount is transferred outside
 * the context of the process to run down_write() on that pinned mm.
 *
 * NOTE: find_extend_vma() called from GUP context is the only place
 * that can modify the "mm" (notably the vm_start/end) under mmap_sem
 * for reading and outside the context of the process, so it is also
 * the only case that holds the mmap_sem for reading that must call
 * this function. Generally if the mmap_sem is hold for reading
 * there's no need of this check after get_task_mm()/mmget_not_zero().
 *
 * This function can be obsoleted and the check can be removed, after
 * the coredump code will hold the mmap_sem for writing before
 * invoking the ->core_dump methods.
 */
static inline bool mmget_still_valid(struct mm_struct *mm)
{
	return likely(!mm->core_state);
}

#ifdef CONFIG_MEMBARRIER
enum {
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_READY		= (1U << 0),
	MEMBARRIER_STATE_PRIVATE_EXPEDITED			= (1U << 1),
	MEMBARRIER_STATE_GLOBAL_EXPEDITED_READY			= (1U << 2),
	MEMBARRIER_STATE_GLOBAL_EXPEDITED			= (1U << 3),
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY	= (1U << 4),
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE		= (1U << 5),
};

enum {
	MEMBARRIER_FLAG_SYNC_CORE				= (1U << 0),
};

#ifdef CONFIG_ARCH_HAS_MEMBARRIER_CALLBACKS
#include <asm/membarrier.h>
#endif

static inline void membarrier_mm_sync_core_before_usermode(struct mm_struct *mm)
{
	if (likely(!(atomic_read(&mm->membarrier_state) &
		     MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE)))
		return;
	sync_core_before_usermode();
}

static inline void membarrier_execve(struct task_struct *t)
{
	atomic_set(&t->mm->membarrier_state, 0);
}
#else
#ifdef CONFIG_ARCH_HAS_MEMBARRIER_CALLBACKS
static inline void membarrier_arch_switch_mm(struct mm_struct *prev,
					     struct mm_struct *next,
					     struct task_struct *tsk)
{
}
#endif
static inline void membarrier_execve(struct task_struct *t)
{
}
static inline void membarrier_mm_sync_core_before_usermode(struct mm_struct *mm)
{
}
#endif

#endif /* _LINUX_SCHED_MM_H */
