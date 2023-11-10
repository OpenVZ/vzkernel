#ifndef __ASM_SPINLOCK_TYPES_H
#define __ASM_SPINLOCK_TYPES_H

#ifndef __LINUX_SPINLOCK_TYPES_H
# error "please don't include this file directly"
#endif

#include <linux/rh_kabi.h>

typedef struct {
	RH_KABI_REPLACE(volatile unsigned int owner_cpu, unsigned int lock)
} __attribute__ ((aligned (4))) arch_spinlock_t;

#define __ARCH_SPIN_LOCK_UNLOCKED { .lock = 0, }

typedef struct {
	RH_KABI_REPLACE(volatile unsigned int lock, unsigned int lock)
} arch_rwlock_t;

#define __ARCH_RW_LOCK_UNLOCKED		{ .lock = 0 }

#endif
