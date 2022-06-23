/*
 * Generate definitions needed by the preprocessor.
 * This code generates raw asm output which is post-processed
 * to extract and format the required data.
 */

#define __GENERATING_BOUNDS_H
/* Include headers that define the enum constants of interest */
#include <linux/page-flags.h>
#include <linux/mmzone.h>
#include <linux/kbuild.h>
#include <linux/page_cgroup.h>
#include <linux/log2.h>
#include <linux/spinlock.h>

void foo(void)
{
	/* The enum constants to put into include/generated/bounds.h */
	DEFINE(NR_PAGEFLAGS, __NR_PAGEFLAGS);
	DEFINE(MAX_NR_ZONES, __MAX_NR_ZONES);
	DEFINE(NR_PCG_FLAGS, __NR_PCG_FLAGS);
#ifdef CONFIG_SMP
	DEFINE(NR_CPUS_BITS, ilog2(CONFIG_NR_CPUS));
#endif
	DEFINE(BLOATED_SPINLOCKS, sizeof(spinlock_t) > sizeof(int));
	/* End of constants */
}
