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
 * RH_KABI_CHANGE_TYPE - replacement of _orig with _new of the same name but
 *                       different type.  This causes problems with a union
 *                       so append a '1' to the _orig name to avoid name
 *                       collision.  Assumption here is _orig will not be used
 *                       anymore.
 * RH_KABI_REPLACE_P - replacement of _orig pointer with _new pointer.  Pointers
 *                     don't work with anonymous unions and their sizes don't
 *                     change, so just do a straightforward replacement.
 * RH_KABI_DEPRECATE - mark the element as deprecated and make it unusable
 *		       by modules while preserving kABI checksums
 *
 * RH_KABI_EXTEND - simple macro for adding a new element to a struct while
 *                  preserving the kabi agreement (by wrapping with GENKSYMS).
 * RH_KABI_FILL_HOLE - simple macro for filling a hole in a struct while
 *                     preserving the kabi agreement (by wrapping with GENKSYMS).
 *
 * NOTE NOTE NOTE
 * Don't use ';' after these macros as it messes up the kabi checker by
 * changing what the resulting token string looks like.
 * Instead let this macro add the ';' so it can be properly hidden from
 * the kabi checker (mainly for RH_KABI_EXTEND, but applied to all macros for
 * uniformity).
 * NOTE NOTE NOTE
 */
#ifdef __GENKSYMS__

# define _RH_KABI_REPLACE(_orig, _new)		_orig
# define _RH_KABI_CHANGE_TYPE(_orig, _new)	_orig
# define _RH_KABI_REPLACE_P(_orig, _new)	_orig
# define _RH_KABI_DEPRECATE(_type, _orig)	_type _orig

# define RH_KABI_EXTEND(_new)
# define RH_KABI_FILL_HOLE(_new)

#else

# define _RH_KABI_REPLACE(_orig, _new)		\
	union {					\
		_new;				\
		_orig;				\
	}
# define _RH_KABI_CHANGE_TYPE(_orig, _new)	\
	union {					\
		_new;				\
		_orig##1;			\
	}
# define _RH_KABI_REPLACE_P(_orig, _new)	_new

# define _RH_KABI_DEPRECATE(_type, _orig)	_type rh_reserved_##_orig

# define RH_KABI_EXTEND(_new)         		_new;

/* Warning, only use if a hole exists for _all_ arches. Use pahole to verify */
# define RH_KABI_FILL_HOLE(_new)       	_new;

#endif /* __GENKSYMS__ */

/* colon added wrappers for the RH_KABI_REPLACE macros */
#define RH_KABI_REPLACE(_orig, _new)		_RH_KABI_REPLACE(_orig, _new);
#define RH_KABI_CHANGE_TYPE(_orig, _new)	_RH_KABI_CHANGE_TYPE(_orig, _new);
#define RH_KABI_REPLACE_P(_orig, _new)		_RH_KABI_REPLACE_P(_orig, _new);
#define RH_KABI_DEPRECATE(_type, _orig)		_RH_KABI_DEPRECATE(_type, _orig);

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
#define RH_KABI_USE_P(n, _new)		RH_KABI_REPLACE_P(_RH_KABI_RESERVE_P(n), _new)

/*
 * Macro for breaking up a reserved element into two smaller chunks using an
 * anonymous struct inside an anonymous union.
 */
#define RH_KABI_USE2(n, _new1, _new2)	RH_KABI_REPLACE(_RH_KABI_RESERVE(n), struct{ _new1; _new2; })

#endif /* _LINUX_RH_KABI_H */
