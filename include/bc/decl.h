/*
 *  include/bc/decl.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __BC_DECL_H_
#define __BC_DECL_H_

#ifdef __KERNEL__

/*
 * Naming convension:
 * ub_<section|object>_<operation>
 */

#ifdef CONFIG_BEANCOUNTERS

#define UB_DECLARE_FUNC(ret_type, decl)	extern ret_type decl;
#define UB_DECLARE_VOID_FUNC(decl)	extern void decl;

#else /* CONFIG_BEANCOUNTERS */

#define UB_DECLARE_FUNC(ret_type, decl)		\
	static inline ret_type decl		\
	{					\
		return (ret_type)0;		\
	}
#define UB_DECLARE_VOID_FUNC(decl)		\
	static inline void decl			\
	{					\
	}

#endif /* CONFIG_BEANCOUNTERS */
#endif

#endif
