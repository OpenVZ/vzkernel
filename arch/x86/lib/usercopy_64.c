/* 
 * User address space access functions.
 *
 * Copyright 1997 Andi Kleen <ak@muc.de>
 * Copyright 1997 Linus Torvalds
 * Copyright 2002 Andi Kleen <ak@suse.de>
 */
#include <linux/module.h>
#include <asm/uaccess.h>
#include <linux/highmem.h>

/*
 * Zero Userspace
 */

unsigned long __clear_user(void __user *addr, unsigned long size)
{
	long __d0;
	might_fault();
	/* no memory constraint because it doesn't change any memory gcc knows
	   about */
	stac();
	asm volatile(
		"	testq  %[size8],%[size8]\n"
		"	jz     4f\n"
		"0:	movq %[zero],(%[dst])\n"
		"	addq   %[eight],%[dst]\n"
		"	decl %%ecx ; jnz   0b\n"
		"4:	movq  %[size1],%%rcx\n"
		"	testl %%ecx,%%ecx\n"
		"	jz     2f\n"
		"1:	movb   %b[zero],(%[dst])\n"
		"	incq   %[dst]\n"
		"	decl %%ecx ; jnz  1b\n"
		"2:\n"
		".section .fixup,\"ax\"\n"
		"3:	lea 0(%[size1],%[size8],8),%[size8]\n"
		"	jmp 2b\n"
		".previous\n"
		_ASM_EXTABLE(0b,3b)
		_ASM_EXTABLE(1b,2b)
		: [size8] "=&c"(size), [dst] "=&D" (__d0)
		: [size1] "r"(size & 7), "[size8]" (size / 8), "[dst]"(addr),
		  [zero] "r" (0UL), [eight] "r" (8UL));
	clac();
	return size;
}
EXPORT_SYMBOL(__clear_user);

unsigned long clear_user(void __user *to, unsigned long n)
{
	if (access_ok(VERIFY_WRITE, to, n))
		return __clear_user(to, n);
	return n;
}
EXPORT_SYMBOL(clear_user);

unsigned long copy_in_user(void __user *to, const void __user *from, unsigned len)
{
	if (access_ok(VERIFY_WRITE, to, len) && access_ok(VERIFY_READ, from, len)) { 
		return copy_user_generic((__force void *)to, (__force void *)from, len);
	} 
	return len;		
}
EXPORT_SYMBOL(copy_in_user);

/*
 * Try to copy last bytes and clear the rest if needed.
 * Since protection fault in copy_from/to_user is not a normal situation,
 * it is not necessary to optimize tail handling.
 */
unsigned long
copy_user_handle_tail(char *to, char *from, unsigned len, unsigned zerorest)
{
	char c;
	unsigned zero_len;

	for (; len; --len, to++) {
		if (__get_user_nocheck(c, from++, sizeof(char)))
			break;
		if (__put_user_nocheck(c, to, sizeof(char)))
			break;
	}

	for (c = 0, zero_len = len; zerorest && zero_len; --zero_len)
		if (__put_user_nocheck(c, to++, sizeof(char)))
			break;
	clac();
	return len;
}

/*
 * Similar to copy_user_handle_tail, probe for the write fault point,
 * but reuse __memcpy_mcsafe in case a new read error is encountered.
 * clac() is handled in _copy_to_iter_mcsafe().
 */
__visible unsigned long
mcsafe_handle_tail(char *to, char *from, unsigned len)
{
	for (; len; --len, to++, from++) {
		/*
		 * Call the assembly routine back directly since
		 * memcpy_mcsafe() may silently fallback to memcpy.
		 */
		unsigned long rem = __memcpy_mcsafe(to, from, 1);

		if (rem)
			break;
	}
	return len;
}

#ifdef CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE
/**
 * clean_cache_range - write back a cache range with CLWB
 * @vaddr:	virtual start address
 * @size:	number of bytes to write back
 *
 * Write back a cache range using the CLWB (cache line write back)
 * instruction. Note that @size is internally rounded up to be cache
 * line size aligned.
 */
static void clean_cache_range(void *addr, size_t size)
{
	u16 x86_clflush_size = boot_cpu_data.x86_clflush_size;
	unsigned long clflush_mask = x86_clflush_size - 1;
	void *vend = addr + size;
	void *p;

	for (p = (void *)((unsigned long)addr & ~clflush_mask);
	     p < vend; p += x86_clflush_size)
		clwb(p);
}

void arch_wb_cache_pmem(void *addr, size_t size)
{
	clean_cache_range(addr, size);
}
EXPORT_SYMBOL_GPL(arch_wb_cache_pmem);

long __copy_user_flushcache(void *dst, const void __user *src, unsigned size)
{
	unsigned long flushed, dest = (unsigned long) dst;
	long rc = __copy_user_nocache(dst, src, size, 0);

	/*
	 * __copy_user_nocache() uses non-temporal stores for the bulk
	 * of the transfer, but we need to manually flush if the
	 * transfer is unaligned. A cached memory copy is used when
	 * destination or size is not naturally aligned. That is:
	 *   - Require 8-byte alignment when size is 8 bytes or larger.
	 *   - Require 4-byte alignment when size is 4 bytes.
	 */
	if (size < 8) {
		if (!IS_ALIGNED(dest, 4) || size != 4)
			clean_cache_range(dst, 1);
	} else {
		if (!IS_ALIGNED(dest, 8)) {
			dest = ALIGN(dest, boot_cpu_data.x86_clflush_size);
			clean_cache_range(dst, 1);
		}

		flushed = dest - (unsigned long) dst;
		if (size > flushed && !IS_ALIGNED(size - flushed, 8))
			clean_cache_range(dst + size - 1, 1);
	}

	return rc;
}

void memcpy_flushcache(void *_dst, const void *_src, size_t size)
{
	unsigned long dest = (unsigned long) _dst;
	unsigned long source = (unsigned long) _src;

	/* cache copy and flush to align dest */
	if (!IS_ALIGNED(dest, 8)) {
		unsigned len = min_t(unsigned, size, ALIGN(dest, 8) - dest);

		memcpy((void *) dest, (void *) source, len);
		clean_cache_range((void *) dest, len);
		dest += len;
		source += len;
		size -= len;
		if (!size)
			return;
	}

	/* 4x8 movnti loop */
	while (size >= 32) {
		asm("movq    (%0), %%r8\n"
		    "movq   8(%0), %%r9\n"
		    "movq  16(%0), %%r10\n"
		    "movq  24(%0), %%r11\n"
		    "movnti  %%r8,   (%1)\n"
		    "movnti  %%r9,  8(%1)\n"
		    "movnti %%r10, 16(%1)\n"
		    "movnti %%r11, 24(%1)\n"
		    :: "r" (source), "r" (dest)
		    : "memory", "r8", "r9", "r10", "r11");
		dest += 32;
		source += 32;
		size -= 32;
	}

	/* 1x8 movnti loop */
	while (size >= 8) {
		asm("movq    (%0), %%r8\n"
		    "movnti  %%r8,   (%1)\n"
		    :: "r" (source), "r" (dest)
		    : "memory", "r8");
		dest += 8;
		source += 8;
		size -= 8;
	}

	/* 1x4 movnti loop */
	while (size >= 4) {
		asm("movl    (%0), %%r8d\n"
		    "movnti  %%r8d,   (%1)\n"
		    :: "r" (source), "r" (dest)
		    : "memory", "r8");
		dest += 4;
		source += 4;
		size -= 4;
	}

	/* cache copy for remaining bytes */
	if (size) {
		memcpy((void *) dest, (void *) source, size);
		clean_cache_range((void *) dest, size);
	}
}
EXPORT_SYMBOL_GPL(memcpy_flushcache);

void memcpy_page_flushcache(char *to, struct page *page, size_t offset,
		size_t len)
{
	char *from = kmap_atomic(page);

	memcpy_flushcache(to, from + offset, len);
	kunmap_atomic(from);
}
#endif
