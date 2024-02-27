/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_POWERPC_ARCHRANDOM_H
#define _ASM_POWERPC_ARCHRANDOM_H

static inline size_t __must_check arch_get_random_longs(unsigned long *v, size_t max_longs)
{
	return 0;
}

size_t __must_check arch_get_random_seed_longs(unsigned long *v, size_t max_longs);

#ifdef CONFIG_PPC_POWERNV
int powernv_hwrng_present(void);
int powernv_get_random_long(unsigned long *v);
int powernv_get_random_real_mode(unsigned long *v);
#else
static inline int powernv_hwrng_present(void) { return 0; }
static inline int powernv_get_random_real_mode(unsigned long *v) { return 0; }
#endif

#endif /* _ASM_POWERPC_ARCHRANDOM_H */
