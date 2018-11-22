/*
 * rh_kabi.h - Red Hat kABI abstraction header
 *
 * Copyright (c) 2014 Don Zickus
 * Copyright (c) 2015-2017 Jiri Benc
 * Copyright (c) 2015 Sabrina Dubroca, Hannes Frederic Sowa
 * Copyright (c) 2016-2018 Prarit Bhargava
 * Copyright (c) 2017 Paolo Abeni, Larry Woodman
 *
 * This file is released under the GPLv2.
 * See the file COPYING for more details.
 *
 * These kabi macros hide the changes from the kabi checker and from the
 * process that computes the exported symbols' checksums.
 * They have 2 variants: one (defined under __GENKSYMS__) used when
 * generating the checksums, and the other used when building the kernel's
 * binaries.
 *
 * The use of these macros does not guarantee that the usage and modification
 * of code is correct.  As with all Red Hat only changes, an engineer must
 * explain why the use of the macro is valid in the patch containing the
 * changes.
 *
 */

#ifndef _LINUX_RH_KABI_H
#define _LINUX_RH_KABI_H

#include <linux/compiler.h>
#include <linux/stringify.h>

/*
 * RH_KABI_CONST
 *   Adds a new const modifier to a function parameter preserving the old
 *   checksum.
 *
 * RH_KABI_DEPRECATE
 *   Mark the element as deprecated and make it unusable by modules while
 *   preserving kABI checksums.
 *
 * RH_KABI_DEPRECATE_FN
 *   Mark the function pointer as deprecated and make it unusable by modules
 *   while preserving kABI checksums.
 *
 * RH_KABI_EXTEND
 *   Simple macro for adding a new element to a struct.
 *
 *   Warning: only use if a hole exists for _all_ arches.  Use pahole to verify.
 *
 * RH_KABI_FILL_HOLE
 *   Simple macro for filling a hole in a struct.
 *
 * RH_KABI_RENAME
 *   Simple macro for renaming an element without changing its type.  This
 *   macro can be used in bitfields, for example.
 *
 *   NOTE: does not include the final ';'
 *
 * RH_KABI_REPLACE
 *   Simple replacement of _orig with a union of _orig and _new.
 *
 *   The RH_KABI_REPLACE* macros attempt to add the ability to use the '_new'
 *   element while preserving size alignment with the '_orig' element.
 *
 *   The #ifdef __GENKSYMS__ preserves the kABI agreement, while the anonymous
 *   union structure preserves the size alignment (assuming the '_new' element
 *   is not bigger than the '_orig' element).
 *
 * RH_KABI_REPLACE_UNSAFE
 *   Unsafe version of RH_KABI_REPLACE.  Only use for typedefs.
 *
 * RH_KABI_FORCE_CHANGE
 *   Force change of the symbol checksum.  The argument of the macro is a
 *   version for cases we need to do this more than once.
 *
 *   This macro does the opposite: it changes the symbol checksum without
 *   actually changing anything about the exported symbol.  It is useful for
 *   symbols that are not whitelisted, we're changing them in an
 *   incompatible way and want to prevent 3rd party modules to silently
 *   corrupt memory.  Instead, by changing the symbol checksum, such modules
 *   won't be loaded by the kernel.  This macro should only be used as a
 *   last resort when all other KABI workarounds have failed.
 * RH_KABI_EXCLUDE
 *   Exclude the element from checksum generation.  Any such element is
 *   considered not to be part of the kABI whitelist and may be changed at
 *   will.  Note however that it's the responsibility of the developer
 *   changing the element to ensure 3rd party drivers using this element
 *   won't panic, for example by not allowing them to be loaded.  That can
 *   be achieved by changing another, non-whitelisted symbol they use,
 *   either by nature of the change or by using RH_KABI_FORCE_CHANGE.
 *
 *   Also note that any change to the element must preserve its size. Change
 *   of the size is not allowed and would constitute a silent kABI breakage.
 *   Beware that the RH_KABI_EXCLUDE macro does not do any size checks.
 *
 * NOTE
 *   Don't use ';' after these macros as it messes up the kABI checker by
 *   changing what the resulting token string looks like.  Instead let this
 *   macro add the ';' so it can be properly hidden from the kABI checker
 *   (mainly for RH_KABI_EXTEND, but applied to all macros for uniformity).
 *
 */
#ifdef __GENKSYMS__

# define RH_KABI_CONST
# define RH_KABI_EXTEND(_new)
# define RH_KABI_FILL_HOLE(_new)
# define RH_KABI_FORCE_CHANGE(ver)		__attribute__((rh_kabi_change ## ver))
# define RH_KABI_RENAME(_orig, _new)		_orig

# define _RH_KABI_DEPRECATE(_type, _orig)	_type _orig
# define _RH_KABI_DEPRECATE_FN(_type, _orig, _args...)	_type (*_orig)(_args)
# define _RH_KABI_REPLACE(_orig, _new)		_orig
# define _RH_KABI_REPLACE_UNSAFE(_orig, _new)	_orig
# define _RH_KABI_EXCLUDE(_elem)

#else

# define RH_KABI_ALIGN_WARNING ".  Disable CONFIG_RH_KABI_SIZE_ALIGN_CHECKS if debugging."

# define RH_KABI_CONST				const
# define RH_KABI_EXTEND(_new)			_new;
# define RH_KABI_FILL_HOLE(_new)		_new;
# define RH_KABI_FORCE_CHANGE(ver)
# define RH_KABI_RENAME(_orig, _new)		_new


#if IS_BUILTIN(CONFIG_RH_KABI_SIZE_ALIGN_CHECKS)
# define __RH_KABI_CHECK_SIZE_ALIGN(_orig, _new)			\
	union {								\
		_Static_assert(sizeof(struct{_new;}) <= sizeof(struct{_orig;}), \
			       __FILE__ ":" __stringify(__LINE__) ": "  __stringify(_new) " is larger than " __stringify(_orig) RH_KABI_ALIGN_WARNING); \
		_Static_assert(__alignof__(struct{_new;}) <= __alignof__(struct{_orig;}), \
			       __FILE__ ":" __stringify(__LINE__) ": "  __stringify(_orig) " is not aligned the same as " __stringify(_new) RH_KABI_ALIGN_WARNING); \
	}
#else
# define __RH_KABI_CHECK_SIZE_ALIGN(_orig, _new)
#endif

# define _RH_KABI_DEPRECATE(_type, _orig)	_type rh_reserved_##_orig
# define _RH_KABI_DEPRECATE_FN(_type, _orig, _args...)  \
	_type (* rh_reserved_##_orig)(_args)
# define _RH_KABI_REPLACE(_orig, _new)			  \
	union {						  \
		_new;					  \
		struct {				  \
			_orig;				  \
		} __UNIQUE_ID(rh_kabi_hide);		  \
		__RH_KABI_CHECK_SIZE_ALIGN(_orig, _new);  \
	}
# define _RH_KABI_REPLACE_UNSAFE(_orig, _new)	_new

# define _RH_KABI_EXCLUDE(_elem)		_elem

#endif /* __GENKSYMS__ */

/* semicolon added wrappers for the RH_KABI_REPLACE macros */
# define RH_KABI_DEPRECATE(_type, _orig)	_RH_KABI_DEPRECATE(_type, _orig);
# define RH_KABI_DEPRECATE_FN(_type, _orig, _args...)  \
	_RH_KABI_DEPRECATE_FN(_type, _orig, _args);
# define RH_KABI_REPLACE(_orig, _new)		_RH_KABI_REPLACE(_orig, _new);
# define RH_KABI_REPLACE_UNSAFE(_orig, _new)	_RH_KABI_REPLACE_UNSAFE(_orig, _new);
/*
 * Macro for breaking up a random element into two smaller chunks using an
 * anonymous struct inside an anonymous union.
 */
# define RH_KABI_REPLACE2(orig, _new1, _new2)	RH_KABI_REPLACE(orig, struct{ _new1; _new2;})

# define RH_KABI_RESERVE(n)		_RH_KABI_RESERVE(n);
/*
 * Simple wrappers to replace standard Red Hat reserved elements.
 */
# define RH_KABI_USE(n, _new)		RH_KABI_REPLACE(_RH_KABI_RESERVE(n), _new)
/*
 * Macros for breaking up a reserved element into two smaller chunks using
 * an anonymous struct inside an anonymous union.
 */
# define RH_KABI_USE2(n, _new1, _new2)	RH_KABI_REPLACE(_RH_KABI_RESERVE(n), struct{ _new1; _new2; })

/*
 * We tried to standardize on Red Hat reserved names.  These wrappers
 * leverage those common names making it easier to read and find in the
 * code.
 */
# define _RH_KABI_RESERVE(n)		unsigned long rh_reserved##n

#define RH_KABI_EXCLUDE(_elem)		_RH_KABI_EXCLUDE(_elem);

#endif /* _LINUX_RH_KABI_H */
