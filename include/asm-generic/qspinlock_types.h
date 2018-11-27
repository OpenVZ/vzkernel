/*
 * Queued spinlock
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * (C) Copyright 2013-2015 Hewlett-Packard Development Company, L.P.
 *
 * Authors: Waiman Long <waiman.long@hp.com>
 */
#ifndef __ASM_GENERIC_QSPINLOCK_TYPES_H
#define __ASM_GENERIC_QSPINLOCK_TYPES_H

/*
 * Including atomic.h with PARAVIRT on will cause compilation errors because
 * of recursive header file incluson via paravirt_types.h. So don't include
 * it if PARAVIRT is on.
 */
#ifndef CONFIG_PARAVIRT
#include <linux/types.h>
#include <linux/atomic.h>
#endif

/*
 * Maintain the same kABI signature as the ticket lock.
 */
typedef u16 __ticket_t;
#ifndef __GENKSYMS__
typedef struct qspinlock {
	atomic_t	val;
} arch_spinlock_t;
#else
typedef u32 __ticketpair_t;

typedef struct arch_spinlock {
	union {
		__ticketpair_t	head_tail;
		struct __raw_tickets {
			__ticket_t head, tail;
		} tickets;
	};
} arch_spinlock_t;
#endif

/*
 * Initializier
 */
#define	__ARCH_SPIN_LOCK_UNLOCKED	{ ATOMIC_INIT(0) }

/*
 * Bitfields in the atomic value:
 *
 * When NR_CPUS <= 8K
 *  0- 7: locked byte
 *     8: pending
 *  9-15: not used
 * 16-18: tail index (*2 + 1)
 * 19-31: tail cpu
 *
 * When NR_CPUS > 8K
 *  0- 7: locked byte
 *     8: pending
 *  9-11: tail index (*2 + 1)
 * 12-31: tail cpu
 */
#define	_Q_SET_MASK(type)	(((1U << _Q_ ## type ## _BITS) - 1)\
				      << _Q_ ## type ## _OFFSET)
#define _Q_LOCKED_OFFSET	0
#define _Q_LOCKED_BITS		8
#define _Q_LOCKED_MASK		_Q_SET_MASK(LOCKED)

#define _Q_PENDING_OFFSET	(_Q_LOCKED_OFFSET + _Q_LOCKED_BITS)
#if CONFIG_NR_CPUS <= (1U << 13)
#define _Q_PENDING_BITS		8
#else
#define _Q_PENDING_BITS		1
#endif
#define _Q_PENDING_MASK		_Q_SET_MASK(PENDING)

#define _Q_TAIL_IDX_OFFSET	(_Q_PENDING_OFFSET + _Q_PENDING_BITS)
#define _Q_TAIL_IDX_BITS	3
#define _Q_TAIL_IDX_MASK	_Q_SET_MASK(TAIL_IDX)

#define _Q_TAIL_CPU_OFFSET	(_Q_TAIL_IDX_OFFSET + _Q_TAIL_IDX_BITS)
#define _Q_TAIL_CPU_BITS	(32 - _Q_TAIL_CPU_OFFSET)
#define _Q_TAIL_CPU_MASK	_Q_SET_MASK(TAIL_CPU)

#define _Q_TAIL_OFFSET		_Q_TAIL_IDX_OFFSET
#define _Q_TAIL_MASK		(_Q_TAIL_IDX_MASK | _Q_TAIL_CPU_MASK)

#define _Q_LOCKED_VAL		(1U << _Q_LOCKED_OFFSET)
#define _Q_PENDING_VAL		(1U << _Q_PENDING_OFFSET)

/*
 * Special code to handle ticket unlock code which adds 2 to _Q_LOCKED_VAL.
 */
#define _Q_UNLOCKED_BIT		2
#define _Q_UNLOCKED_VAL		3

#endif /* __ASM_GENERIC_QSPINLOCK_TYPES_H */
