/*
 * Copyright IBM Corp. 1999, 2009
 *
 * Author(s): Martin Schwidefsky <schwidefsky@de.ibm.com>
 */

#ifndef __ASM_CTL_REG_H
#define __ASM_CTL_REG_H

#include <linux/bug.h>

#ifdef CONFIG_64BIT

#define __ctl_load(array, low, high) ({				\
	typedef struct { char _[sizeof(array)]; } addrtype;	\
	asm volatile(						\
		"	lctlg	%1,%2,%0\n"			\
		: : "Q" (*(addrtype *)(&array)),		\
		    "i" (low), "i" (high));			\
	})

#define __ctl_store(array, low, high) ({			\
	typedef struct { char _[sizeof(array)]; } addrtype;	\
	asm volatile(						\
		"	stctg	%1,%2,%0\n"			\
		: "=Q" (*(addrtype *)(&array))			\
		: "i" (low), "i" (high));			\
	})

#else /* CONFIG_64BIT */

#define __ctl_load(array, low, high) ({				\
	typedef struct { char _[sizeof(array)]; } addrtype;	\
	asm volatile(						\
		"	lctl	%1,%2,%0\n"			\
		: : "Q" (*(addrtype *)(&array)),		\
		    "i" (low), "i" (high));			\
})

#define __ctl_store(array, low, high) ({			\
	typedef struct { char _[sizeof(array)]; } addrtype;	\
	asm volatile(						\
		"	stctl	%1,%2,%0\n"			\
		: "=Q" (*(addrtype *)(&array))			\
		: "i" (low), "i" (high));			\
	})

#endif /* CONFIG_64BIT */

#define __ctl_set_bit(cr, bit) ({	\
	unsigned long __dummy;		\
	__ctl_store(__dummy, cr, cr);	\
	__dummy |= 1UL << (bit);	\
	__ctl_load(__dummy, cr, cr);	\
})

#define __ctl_clear_bit(cr, bit) ({	\
	unsigned long __dummy;		\
	__ctl_store(__dummy, cr, cr);	\
	__dummy &= ~(1UL << (bit));	\
	__ctl_load(__dummy, cr, cr);	\
})

union ctlreg0 {
	unsigned long val;
	struct {
#ifdef CONFIG_64BIT
		unsigned long	   : 32;
#endif
		unsigned long	   : 3;
		unsigned long lap  : 1; /* Low-address-protection control */
		unsigned long	   : 4;
		unsigned long edat : 1; /* Enhanced-DAT-enablement control */
		unsigned long	   : 4;
		unsigned long afp  : 1; /* AFP-register control */
		unsigned long vx   : 1; /* Vector enablement control */
		unsigned long	   : 17;
	};
};

#ifdef CONFIG_SMP

extern void smp_ctl_set_bit(int cr, int bit);
extern void smp_ctl_clear_bit(int cr, int bit);
#define ctl_set_bit(cr, bit) smp_ctl_set_bit(cr, bit)
#define ctl_clear_bit(cr, bit) smp_ctl_clear_bit(cr, bit)

#else

#define ctl_set_bit(cr, bit) __ctl_set_bit(cr, bit)
#define ctl_clear_bit(cr, bit) __ctl_clear_bit(cr, bit)

#endif /* CONFIG_SMP */

#endif /* __ASM_CTL_REG_H */
