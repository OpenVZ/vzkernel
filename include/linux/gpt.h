/*
 * Copyright 2016 Red Hat Inc.
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
 * Authors: Jérôme Glisse <jglisse@redhat.com>
 */
/*
 * Generic page table structure with adjustable depth. This is unlike regular
 * CPU page table use on many architecture. It is more like radix tree but it
 * uses full pages and offers more bits for flags per entry.
 *
 * Note that resizing it (increase its depth) is something relatively easy to
 * add in case someone cares.
 *
 * Note that we use the private field of root struct page to store the number
 * of levels as well as the pfn_shift values. Moreover we use _mapcount field
 * to count number of valid entry inside each directory.
 */
#ifndef _LINUX_GPT_H
#define _LINUX_GPT_H

#include <linux/mm_types.h>
#include <linux/spinlock.h>
#include <linux/gfp.h>

#ifdef CONFIG_HIGHMEM64G
#define gte_t uint64_t
#else /* CONFIG_HIGHMEM64G */
#define gte_t unsigned long
#endif /* CONFIG_HIGHMEM64G */

/* 6 level on 64 bits arch with PAGE_SHIFT=12 means 66bits of address space */
#define GPT_MAX_LEVEL 6


struct gpt {
	unsigned long		start;
	unsigned long		end;
	unsigned long		*gdp;
	atomic_t		refcount;
	spinlock_t		lock;
	uint8_t			nlevels;
	uint8_t			shift;
	uint8_t			valid_bit;
};

struct gpt *gpt_alloc(unsigned long start,
		      unsigned long end,
		      uint8_t shift,
		      uint8_t valid_bit);
void gpt_free(struct gpt *gpt);


struct gpt_walk {
	struct gpt		*gpt;
	unsigned long		start;
	unsigned long		end;
	struct page		*gtd[GPT_MAX_LEVEL];
	gte_t			*gte[GPT_MAX_LEVEL];
};

void gpt_walk_init(struct gpt_walk *walk, struct gpt *gpt);
void gpt_walk_fini(struct gpt_walk *walk);
gte_t *gpt_walk_gtep_from_addr(struct gpt_walk *walk, unsigned long addr);
gte_t *gpt_walk_populate(struct gpt_walk *walk, unsigned long addr);
void gpt_walk_prune(struct gpt_walk *walk,
		    unsigned long start,
		    unsigned long end);

typedef int (*gpt_walk_cb_t)(struct gpt_walk *walk,
			     unsigned long addr,
			     unsigned long end,
			     spinlock_t *gtl,
			     gte_t *gtep,
			     void *private);

int gpt_walk_range(struct gpt_walk *walk,
		   unsigned long start,
		   unsigned long end,
		   gpt_walk_cb_t cb,
		   void *private);


/* gpt_walk_gtd_refcount - pointer to atomic use to count valid directory entry
 * @walk: walk structure from which to extract directory level
 * @level: level for the refcount (0 is the lowest level)
 * Returns: pointer to refcount atomic or NULL if directory level is empty
 *
 * To know when we can prune (free) a directory we count number of valid entry
 * and this for all directory levels.
 */
static inline atomic_t *gpt_walk_gtd_refcount(struct gpt_walk *walk,
					      unsigned level)
{
	BUG_ON(level > walk->gpt->nlevels);

	if (walk->gpt->nlevels && (level < walk->gpt->nlevels)) {
		if (walk->gtd[level])
			return &walk->gtd[level]->_mapcount;
		return NULL;
	}
	return &walk->gpt->refcount;
}

/* gpt_walk_gtd_lock_ptr - spinlock pointer for given directory level
 * @walk: walk structure with current directory hierarchy
 * @level: level to lock (0 is the lowest level and gpt->nlevels the highest)
 * Returns: spinlock pointer for given level, NULL if directory level is empty
 *
 * To provide fine granularity locking to generic page table we use the struct
 * page spinlock. This helper just provide a pointer to the appropriate lock
 * for a given directory level.
 */
static inline spinlock_t *gpt_walk_gtd_lock_ptr(struct gpt_walk *walk,
						unsigned level)
{
	BUG_ON(level > walk->gpt->nlevels);

	if (walk->gpt->nlevels && (level < walk->gpt->nlevels)) {
		if (walk->gtd[level])
			return ptlock_ptr(walk->gtd[level]);
		return NULL;
	}
	return &walk->gpt->lock;
}

#endif /* _LINUX_GPT_H */
