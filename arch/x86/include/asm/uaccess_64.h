/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_UACCESS_64_H
#define _ASM_X86_UACCESS_64_H

/*
 * User space memory access functions
 */
#include <linux/compiler.h>
#include <linux/lockdep.h>
#include <linux/kasan-checks.h>
#include <asm/alternative.h>
#include <asm/cpufeatures.h>
#include <asm/page.h>

#ifdef CONFIG_ADDRESS_MASKING
/*
 * Mask out tag bits from the address.
 */
static inline unsigned long __untagged_addr(unsigned long addr)
{
	/*
	 * Refer tlbstate_untag_mask directly to avoid RIP-relative relocation
	 * in alternative instructions. The relocation gets wrong when gets
	 * copied to the target place.
	 */
	asm (ALTERNATIVE("",
			 "and %%gs:tlbstate_untag_mask, %[addr]\n\t", X86_FEATURE_LAM)
	     : [addr] "+r" (addr) : "m" (tlbstate_untag_mask));

	return addr;
}

#define untagged_addr(addr)	({					\
	unsigned long __addr = (__force unsigned long)(addr);		\
	(__force __typeof__(addr))__untagged_addr(__addr);		\
})

static inline unsigned long __untagged_addr_remote(struct mm_struct *mm,
						   unsigned long addr)
{
	mmap_assert_locked(mm);
	return addr & (mm)->context.untag_mask;
}

#define untagged_addr_remote(mm, addr)	({				\
	unsigned long __addr = (__force unsigned long)(addr);		\
	(__force __typeof__(addr))__untagged_addr_remote(mm, __addr);	\
})

#endif

/*
 * On x86-64, we may have tag bits in the user pointer. Rather than
 * mask them off, just change the rules for __access_ok().
 *
 * Make the rule be that 'ptr+size' must not overflow, and must not
 * have the high bit set. Compilers generally understand about
 * unsigned overflow and the CF bit and generate reasonable code for
 * this. Although it looks like the combination confuses at least
 * clang (and instead of just doing an "add" followed by a test of
 * SF and CF, you'll see that unnecessary comparison).
 *
 * For the common case of small sizes that can be checked at compile
 * time, don't even bother with the addition, and just check that the
 * base pointer is ok.
 */
static inline bool __access_ok(const void __user *ptr, unsigned long size)
{
	if (__builtin_constant_p(size <= PAGE_SIZE) && size <= PAGE_SIZE) {
		return (long)ptr >= 0;
	} else {
		unsigned long sum = size + (unsigned long)ptr;
		return (long) sum >= 0 && sum >= (unsigned long)ptr;
	}
}
#define __access_ok __access_ok

/*
 * Copy To/From Userspace
 */

/* Handles exceptions in both to and from, but doesn't do access_ok */
__must_check unsigned long
copy_user_enhanced_fast_string(void *to, const void *from, unsigned len);
__must_check unsigned long
copy_user_generic_string(void *to, const void *from, unsigned len);
__must_check unsigned long
copy_user_generic_unrolled(void *to, const void *from, unsigned len);

static __always_inline __must_check unsigned long
copy_user_generic(void *to, const void *from, unsigned len)
{
	unsigned ret;

	/*
	 * If CPU has ERMS feature, use copy_user_enhanced_fast_string.
	 * Otherwise, if CPU has rep_good feature, use copy_user_generic_string.
	 * Otherwise, use copy_user_generic_unrolled.
	 */
	alternative_call_2(copy_user_generic_unrolled,
			 copy_user_generic_string,
			 X86_FEATURE_REP_GOOD,
			 copy_user_enhanced_fast_string,
			 X86_FEATURE_ERMS,
			 ASM_OUTPUT2("=a" (ret), "=D" (to), "=S" (from),
				     "=d" (len)),
			 "1" (to), "2" (from), "3" (len)
			 : "memory", "rcx", "r8", "r9", "r10", "r11");
	return ret;
}

static __always_inline __must_check unsigned long
raw_copy_from_user(void *dst, const void __user *src, unsigned long size)
{
	return copy_user_generic(dst, (__force void *)src, size);
}

static __always_inline __must_check unsigned long
raw_copy_to_user(void __user *dst, const void *src, unsigned long size)
{
	return copy_user_generic((__force void *)dst, src, size);
}

extern long __copy_user_nocache(void *dst, const void __user *src,
				unsigned size, int zerorest);

extern long __copy_user_flushcache(void *dst, const void __user *src, unsigned size);
extern void memcpy_page_flushcache(char *to, struct page *page, size_t offset,
			   size_t len);

static inline int
__copy_from_user_inatomic_nocache(void *dst, const void __user *src,
				  unsigned size)
{
	kasan_check_write(dst, size);
	return __copy_user_nocache(dst, src, size, 0);
}

static inline int
__copy_from_user_flushcache(void *dst, const void __user *src, unsigned size)
{
	kasan_check_write(dst, size);
	return __copy_user_flushcache(dst, src, size);
}

/*
 * Zero Userspace.
 */

__must_check unsigned long
clear_user_original(void __user *addr, unsigned long len);
__must_check unsigned long
clear_user_rep_good(void __user *addr, unsigned long len);
__must_check unsigned long
clear_user_erms(void __user *addr, unsigned long len);

static __always_inline __must_check unsigned long __clear_user(void __user *addr, unsigned long size)
{
	might_fault();
	stac();

	/*
	 * No memory constraint because it doesn't change any memory gcc
	 * knows about.
	 */
	asm volatile(
		"1:\n\t"
		ALTERNATIVE_3("rep stosb",
			      "call clear_user_erms",	  ALT_NOT(X86_FEATURE_FSRM),
			      "call clear_user_rep_good", ALT_NOT(X86_FEATURE_ERMS),
			      "call clear_user_original", ALT_NOT(X86_FEATURE_REP_GOOD))
		"2:\n"
	       _ASM_EXTABLE_UA(1b, 2b)
	       : "+c" (size), "+D" (addr), ASM_CALL_CONSTRAINT
	       : "a" (0)
		/* rep_good clobbers %rdx */
	       : "rdx");

	clac();

	return size;
}

static __always_inline unsigned long clear_user(void __user *to, unsigned long n)
{
	if (__access_ok(to, n))
		return __clear_user(to, n);
	return n;
}
#endif /* _ASM_X86_UACCESS_64_H */
