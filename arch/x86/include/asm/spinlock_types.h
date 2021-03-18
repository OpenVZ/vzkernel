#ifndef _ASM_X86_SPINLOCK_TYPES_H
#define _ASM_X86_SPINLOCK_TYPES_H

#include <linux/types.h>

/* Increment the ticket by 2, to leave a bit free for pvspinlock */
#define __TICKET_LOCK_INC	2
#ifdef CONFIG_PARAVIRT_SPINLOCKS
#define TICKET_SLOWPATH_FLAG   ((__ticket_t)1)
#else
#define TICKET_SLOWPATH_FLAG   ((__ticket_t)0)
#endif

#if (CONFIG_NR_CPUS < (256 / __TICKET_LOCK_INC))
typedef u8  __ticket_t;
typedef u16 __ticketpair_t;
#else
typedef u16 __ticket_t;
typedef u32 __ticketpair_t;
#endif

#define TICKET_LOCK_INC	((__ticket_t)__TICKET_LOCK_INC)

#define TICKET_SHIFT	(sizeof(__ticket_t) * 8)

#ifdef CONFIG_QUEUED_SPINLOCKS
#include <asm-generic/qspinlock_types.h>
#else
typedef struct arch_spinlock {
	union {
		__ticketpair_t head_tail;
		struct __raw_tickets {
			__ticket_t head, tail;
		} tickets;
	};
} arch_spinlock_t;

#define __ARCH_SPIN_LOCK_UNLOCKED	{ { 0 } }
#endif /* CONFIG_QUEUED_SPINLOCKS */

#include <asm/rwlock.h>
#ifdef CONFIG_QUEUE_RWLOCK
#include <asm-generic/qrwlock_types.h>
#endif

#endif /* _ASM_X86_SPINLOCK_TYPES_H */
