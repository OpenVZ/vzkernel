#ifndef _LINUX_SCHED_MM_H
#define _LINUX_SCHED_MM_H

#include <linux/sched.h>
#include <linux/sync_core.h>

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
