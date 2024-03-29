/*
 * Flexible mmap layout support
 *
 * Based on code by Ingo Molnar and Andi Kleen, copyrighted
 * as follows:
 *
 * Copyright 2003-2009 Red Hat Inc.
 * All Rights Reserved.
 * Copyright 2005 Andi Kleen, SUSE Labs.
 * Copyright 2007 Jiri Kosina, SUSE Labs.
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/personality.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <asm/elf.h>

struct __read_mostly va_alignment va_align = {
	.flags = -1,
};

static inline unsigned long tasksize_32bit(void)
{
	return IA32_PAGE_OFFSET;
}

static unsigned long stack_maxrandom_size(unsigned long task_size)
{
	unsigned long max = 0;
	if ((current->flags & PF_RANDOMIZE) &&
		!(current->personality & ADDR_NO_RANDOMIZE)) {
		max = (-1UL) & __STACK_RND_MASK(task_size == tasksize_32bit());
		max <<= PAGE_SHIFT;
	}

	return max;
}

#ifdef CONFIG_COMPAT
# define mmap32_rnd_bits  8
# define mmap64_rnd_bits  28
#else
# define mmap32_rnd_bits  28
# define mmap64_rnd_bits  28
#endif

#define SIZE_128M    (128 * 1024 * 1024UL)

static int mmap_is_legacy(void)
{
	if (current->personality & ADDR_COMPAT_LAYOUT)
		return 1;

	if (rlimit(RLIMIT_STACK) == RLIM_INFINITY)
		return 1;

	return sysctl_legacy_va_layout;
}

static unsigned long arch_rnd(unsigned int rndbits)
{
	return ((unsigned long)get_random_int() &
			((1UL << rndbits) - 1)) << PAGE_SHIFT;
}

unsigned long arch_mmap_rnd(void)
{
	return arch_rnd(mmap_is_ia32() ? mmap32_rnd_bits : mmap64_rnd_bits);
}

static unsigned long mmap_base(unsigned long rnd, unsigned long task_size)
{
	unsigned long gap = rlimit(RLIMIT_STACK);
	unsigned long gap_min, gap_max;

	/*
	 * Top of mmap area (just below the process stack).
	 * Leave an at least ~128 MB hole with possible stack randomization.
	 */
	gap_min = SIZE_128M + stack_maxrandom_size(task_size);
	gap_max = (task_size / 6) * 5;

	if (gap < gap_min)
		gap = gap_min;
	else if (gap > gap_max)
		gap = gap_max;

	return PAGE_ALIGN(task_size - gap - rnd);
}

static unsigned long mmap_legacy_base(unsigned long rnd,
				      unsigned long task_size)
{
	return __TASK_UNMAPPED_BASE(task_size) + rnd;
}

/*
 * This function, called very early during the creation of a new
 * process VM image, sets up which VM layout function to use:
 */
void arch_pick_mmap_layout(struct mm_struct *mm)
{
	unsigned long random_factor = 0UL;

	if (current->flags & PF_RANDOMIZE)
		random_factor = arch_mmap_rnd();

	mm->mmap_legacy_base = mmap_legacy_base(random_factor, TASK_SIZE);

	if (mmap_is_legacy()) {
		mm->mmap_base = mm->mmap_legacy_base;
		mm->get_unmapped_area = arch_get_unmapped_area;
		mm->unmap_area = arch_unmap_area;
	} else {
		mm->mmap_base = mmap_base(random_factor, TASK_SIZE);
		mm->get_unmapped_area = arch_get_unmapped_area_topdown;
		mm->unmap_area = arch_unmap_area_topdown;
	}
}

/*
 * Only allow root to set high MMIO mappings to PROT_NONE.
 * This prevents an unpriv. user to set them to PROT_NONE and invert
 * them, then pointing to valid memory for L1TF speculation.
 *
 * Note: for locked down kernels may want to disable the root override.
 */
bool pfn_modify_allowed(unsigned long pfn, pgprot_t prot)
{
	if (!boot_cpu_has_bug(X86_BUG_L1TF))
		return true;
	if (!__pte_needs_invert(pgprot_val(prot)))
		return true;
	/* If it's real memory always allow */
	if (pfn_valid(pfn))
		return true;
	if (pfn > l1tf_pfn_limit() && !capable(CAP_SYS_ADMIN))
		return false;
	return true;
}
