/*
 *  include/bc/kmem.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __UB_SLAB_H_
#define __UB_SLAB_H_

#include <bc/beancounter.h>
#include <bc/decl.h>

struct mm_struct;
struct kmem_cache;

static inline struct user_beancounter *slab_ub(void *obj) { return &ub0; }

struct user_beancounter;
static inline void slab_walk_ub(struct user_beancounter *ub,
		void (*show)(const char *name, int count, void *v), void *v) { }

static inline void slab_obj_walk(struct kmem_cache *c, void (*f)(void *)) { }

#endif /* __UB_SLAB_H_ */
