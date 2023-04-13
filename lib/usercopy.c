#include <linux/export.h>
#include <linux/bug.h>
#include <linux/uaccess.h>
#include <linux/vz_bitops.h>

void copy_from_user_overflow(void)
{
	WARN(1, "Buffer overflow detected!\n");
}
EXPORT_SYMBOL(copy_from_user_overflow);

/*
 * The "unsafe" user accesses aren't really "unsafe", but the naming
 * is a big fat warning: you have to not only do the access_ok()
 * checking before using them, but you have to surround them with the
 * user_access_begin/end() pair.
 */
static __must_check inline bool user_access_begin(const void __user *ptr, size_t len)
{
	if (unlikely(!access_ok(0,ptr,len)))
		return 0;
	__uaccess_begin();
	return 1;
}
#define user_access_end()      __uaccess_end()

#define unsafe_get_user(x, ptr)                                                \
({                                                                             \
	 int __gu_err;                                                           \
	 unsigned long __gu_val;                                                 \
	 __get_user_size(__gu_val, (ptr), sizeof(*(ptr)), __gu_err, -EFAULT);    \
	 (x) = (__force __typeof__(*(ptr)))__gu_val;                             \
	 __builtin_expect(__gu_err, 0);                                          \
 })

/**
 * check_zeroed_user: check if a userspace buffer only contains zero bytes
 * @from: Source address, in userspace.
 * @size: Size of buffer.
 *
 * This is effectively shorthand for "memchr_inv(from, 0, size) == NULL" for
 * userspace addresses (and is more efficient because we don't care where the
 * first non-zero byte is).
 *
 * Returns:
 *  * 0: There were non-zero bytes present in the buffer.
 *  * 1: The buffer was full of zero bytes.
 *  * -EFAULT: access to userspace failed.
 */
int check_zeroed_user(const void __user *from, size_t size)
{
	unsigned long val;
	uintptr_t align = (uintptr_t) from % sizeof(unsigned long);

	if (unlikely(size == 0))
		return 1;

	from -= align;
	size += align;

	if (!user_access_begin(from, size))
		return -EFAULT;

	unsafe_get_user(val, (unsigned long __user *) from);
	if (align)
		val &= ~aligned_byte_mask(align);

	while (size > sizeof(unsigned long)) {
		if (unlikely(val))
			goto done;

		from += sizeof(unsigned long);
		size -= sizeof(unsigned long);

		unsafe_get_user(val, (unsigned long __user *) from);
	}

	if (size < sizeof(unsigned long))
		val &= aligned_byte_mask(size);

done:
	user_access_end();
	return (val == 0);
}
EXPORT_SYMBOL(check_zeroed_user);
