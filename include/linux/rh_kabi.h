/*
 * rh_kabi.h - Red Hat kabi abstraction header
 *
 * Copyright (c) 2014 Don Zickus
 *
 * This file is released under the GPLv2.
 * See the file COPYING for more details.
 */

#ifndef _LINUX_RH_KABI_H
#define _LINUX_RH_KABI_H

#include <linux/compiler.h>
#include <linux/stringify.h>

/*
 * The RH_KABI_REPLACE* macros attempt to add the ability to use the '_new'
 * element while preserving size alignment and kabi agreement with the '_orig'
 * element.
 *
 * The #ifdef __GENKSYMS__ preserves the kabi agreement, while the anonymous
 * union structure preserves the size alignment (assuming the '_new' element is
 * not bigger than the '_orig' element).
 *
 * RH_KABI_REPLACE - simple replacement of _orig with a union of _orig and _new
 * RH_KABI_DEPRECATE - mark the element as deprecated and make it unusable
 *		       by modules while preserving kABI checksums
 * RH_KABI_DEPRECATE_FN - mark the function pointer as deprecated and make it
 * 			  unusable by modules while preserving kABI checksums
 *
 * RH_KABI_EXTEND - simple macro for adding a new element to a struct while
 *                  preserving the kabi agreement (by wrapping with GENKSYMS).
 * RH_KABI_FILL_HOLE - simple macro for filling a hole in a struct while
 *                     preserving the kabi agreement (by wrapping with GENKSYMS).
 * RH_KABI_RENAME - simple macro for renaming an element without changing its type
 *                  while preserving thi kabi agreement (by wrapping with GENKSYMS).
 *                  This macro can be used in bitfields, for example.
 *                  NOTE: does not include the final ';'
 * RH_KABI_REPLACE_UNSAFE - unsafe version of RH_KABI_REPLACE. Only use for typedefs.
 *
 * NOTE NOTE NOTE
 * Don't use ';' after these macros as it messes up the kabi checker by
 * changing what the resulting token string looks like.
 * Instead let this macro add the ';' so it can be properly hidden from
 * the kabi checker (mainly for RH_KABI_EXTEND, but applied to all macros for
 * uniformity).
 * NOTE NOTE NOTE
 *
 * RH_KABI_CONST - adds a new const modifier to a function parameter
 *		   preserving the old checksum
 *
 * This macro does the opposite: it changes the symbol checksum without
 * actually changing anything about the exported symbol. It is useful for
 * symbols that are not whitelisted, we're changing them in an incompatible
 * way and want to prevent 3rd party modules to silently corrupt memory.
 * Instead, by changing the symbol checksum, such modules won't be loaded by
 * the kernel. This macro should only be used as a last resort when all other
 * KABI workarounds have failed.
 *
 * RH_KABI_FORCE_CHANGE - Force change of the symbol checksum. The argument
 *			  of the macro is a version for cases we need to do
 *			  this more than once.
 */
#ifdef __GENKSYMS__

# define _RH_KABI_REPLACE(_orig, _new)		_orig
# define _RH_KABI_REPLACE_UNSAFE(_orig, _new)	_orig
# define _RH_KABI_DEPRECATE(_type, _orig)	_type _orig
# define _RH_KABI_DEPRECATE_FN(_type, _orig, _args...)	_type (*_orig)(_args)

# define RH_KABI_EXTEND(_new)
# define RH_KABI_FILL_HOLE(_new)
# define RH_KABI_RENAME(_orig, _new)		_orig

# define RH_KABI_CONST

# define RH_KABI_FORCE_CHANGE(ver)		__attribute__((rh_kabi_change ## ver))

#else

#define RH_KABI_ALIGN_WARNING ".  Disable CONFIG_RH_KABI_SIZE_ALIGN_CHECKS if debugging."

#if IS_BUILTIN(CONFIG_RH_KABI_SIZE_ALIGN_CHECKS)
#define __RH_KABI_CHECK_SIZE_ALIGN(_orig, _new)				\
	union {								\
		_Static_assert(sizeof(struct{_new;}) <= sizeof(struct{_orig;}), \
			       __FILE__ ":" __stringify(__LINE__) ": "  __stringify(_new) " is larger than " __stringify(_orig) RH_KABI_ALIGN_WARNING); \
		_Static_assert(__alignof__(struct{_new;}) <= __alignof__(struct{_orig;}), \
			       __FILE__ ":" __stringify(__LINE__) ": "  __stringify(_orig) " is not aligned the same as " __stringify(_new) RH_KABI_ALIGN_WARNING); \
	}
#else
#define __RH_KABI_CHECK_SIZE_ALIGN(_orig, _new)
#endif

# define _RH_KABI_REPLACE(_orig, _new)			\
	union {						\
		_new;					\
		struct {				\
			_orig;				\
		} __UNIQUE_ID(rh_kabi_hide);		\
		__RH_KABI_CHECK_SIZE_ALIGN(_orig, _new);	\
	}

#define _RH_KABI_REPLACE_UNSAFE(_orig, _new)	_new

# define _RH_KABI_DEPRECATE(_type, _orig)	_type rh_reserved_##_orig
# define _RH_KABI_DEPRECATE_FN(_type, _orig, _args...) \
	_type (* rh_reserved_##_orig)(_args)

# define RH_KABI_EXTEND(_new)         		_new;

/* Warning, only use if a hole exists for _all_ arches. Use pahole to verify */
# define RH_KABI_FILL_HOLE(_new)       	_new;
# define RH_KABI_RENAME(_orig, _new)		_new

# define RH_KABI_CONST				const

# define RH_KABI_FORCE_CHANGE(ver)

#endif /* __GENKSYMS__ */

/* colon added wrappers for the RH_KABI_REPLACE macros */
#define RH_KABI_REPLACE(_orig, _new)		_RH_KABI_REPLACE(_orig, _new);
#define RH_KABI_REPLACE_UNSAFE(_orig, _new)	_RH_KABI_REPLACE_UNSAFE(_orig, _new);
#define RH_KABI_DEPRECATE(_type, _orig)		_RH_KABI_DEPRECATE(_type, _orig);
#define RH_KABI_DEPRECATE_FN(_type, _orig, _args...) \
	_RH_KABI_DEPRECATE_FN(_type, _orig, _args);

/*
 * We tried to standardize on Red Hat reserved names.  These wrappers leverage
 * those common names making it easier to read and find in the code.
 */
#define _RH_KABI_RESERVE(n)		unsigned long rh_reserved##n
#define _RH_KABI_RESERVE_P(n)		void (*rh_reserved##n)(void)
#define RH_KABI_RESERVE(n)		_RH_KABI_RESERVE(n);
#define RH_KABI_RESERVE_P(n)		_RH_KABI_RESERVE_P(n);

/*
 * Simple wrappers to replace standard Red Hat reserved elements.
 */
#define RH_KABI_USE(n, _new)		RH_KABI_REPLACE(_RH_KABI_RESERVE(n), _new)
#define RH_KABI_USE_P(n, _new)		RH_KABI_REPLACE(_RH_KABI_RESERVE_P(n), _new)

/*
 * Macros for breaking up a reserved element into two smaller chunks using an
 * anonymous struct inside an anonymous union.
 */
#define RH_KABI_USE2(n, _new1, _new2)	RH_KABI_REPLACE(_RH_KABI_RESERVE(n), struct{ _new1; _new2; })
#define RH_KABI_USE2_P(n, _new1, _new2)	RH_KABI_REPLACE(_RH_KABI_RESERVE_P(n), struct{ _new1; _new2;})

/*
 * Macro for breaking up a random element into two smaller chunks using an anonymous
 * struct inside an anonymous union.
 */
#define RH_KABI_REPLACE2(orig, _new1, _new2)	RH_KABI_REPLACE(orig, struct{ _new1; _new2;})

#endif /* _LINUX_RH_KABI_H */
