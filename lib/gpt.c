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
 * Generic page table structure with adjustable depth. For details refer to
 * include/linux/gpt.h
 */
#include <linux/mm.h>
#include <linux/gpt.h>
#include <linux/slab.h>
#include <linux/highmem.h>

#ifdef CONFIG_HIGHMEM64G
/* Some arch do not define MAX_PHYSMEM_BITS */
#ifndef MAX_PHYSMEM_BITS
#define MAX_PHYSMEM_BITS 36
#endif /* MAX_PHYSMEM_BITS */
#define GTE_SHIFT 3
#define GTE_BITS 64
/* GPT_GTD_SHIFT - Shift for one directory level index */
#else /* CONFIG_HIGHMEM64G */
/* Some arch do not define MAX_PHYSMEM_BITS */
#ifndef MAX_PHYSMEM_BITS
#define MAX_PHYSMEM_BITS BITS_PER_LONG
#endif /* MAX_PHYSMEM_BITS */
#if BITS_PER_LONG == 32
#define GTE_SHIFT 2
#define GTE_BITS 32
#else /* This must be 64 McFly ! */
#define GTE_SHIFT 3
#define GTE_BITS 64
#endif
#endif /* CONFIG_HIGHMEM64G */

#define GPT_DEFAULT_GFP (GFP_KERNEL | __GFP_ZERO | __GFP_HIGHMEM)


/*
 * GPT_PFN_BITS - Number of bits require to store any valid pfn value
 * GPT_PFN_MASK - Mask for pfn value
 *
 * This means that there is (BITS_PER_LONG - GPT_PFN_BITS) bits that can be use
 * in anyway by the end user of GPT struct.
 */
#define GPT_PFN_BITS (MAX_PHYSMEM_BITS - PAGE_SHIFT)
#define GPT_PFN_MASK ((1UL << GPT_PFN_BITS) - 1)

/*
 * GPT_GTD_SHIFT - Shift for one directory level index
 * GPT_GTE_PER_GTD - Number of page table entry in one directory level
 */
#define GTD_SHIFT (PAGE_SHIFT - GTE_SHIFT)
#define GTE_PER_GTD (1UL << GTD_SHIFT)
#define GTD_MASK (GTE_PER_GTD - 1)


struct gpt *gpt_alloc(unsigned long start,
		      unsigned long end,
		      uint8_t shift,
		      uint8_t valid_bit)
{
	unsigned long ngd, tmp;
	struct gpt *gpt;

	/* Sanity checks */
	start &= PAGE_MASK;
	end &= PAGE_MASK;
	BUG_ON(start >= end);
	BUG_ON(valid_bit >= shift);
	BUG_ON((GTE_BITS - shift) < GPT_PFN_BITS);

	gpt = kmalloc(sizeof(*gpt), GFP_KERNEL);
	if (!gpt)
		return NULL;

	gpt->start = start;
	gpt->end = end;
	gpt->nlevels = 0;
	gpt->shift = shift;
	gpt->valid_bit = valid_bit;
	spin_lock_init(&gpt->lock);
	atomic_set(&gpt->refcount, 0);

	ngd = (end - start) >> PAGE_SHIFT;
	tmp = (ngd) >> GTD_SHIFT;
	while (tmp) {
		ngd = tmp;
		tmp = tmp >> GTD_SHIFT;
		gpt->nlevels++;
	}
	BUG_ON(gpt->nlevels >= GPT_MAX_LEVEL);

	gpt->gdp = kzalloc(ngd * sizeof(gte_t), GFP_KERNEL);
	if (!gpt->gdp) {
		kfree(gpt);
		return NULL;
	}

	return gpt;
}
EXPORT_SYMBOL(gpt_alloc);

void gpt_free(struct gpt *gpt)
{
	struct gpt_walk walk;

	if (!gpt)
		return;

	gpt_walk_init(&walk, gpt);
	gpt_walk_prune(&walk, gpt->start, gpt->end);
	gpt_walk_fini(&walk);

	kfree(gpt->gdp);
	kfree(gpt);
}
EXPORT_SYMBOL(gpt_free);


static inline unsigned long gte_to_pfn(struct gpt_walk *walk, gte_t gte)
{
	return (unsigned long)(gte >> walk->gpt->shift) & GPT_PFN_MASK;
}

static inline struct page *gte_to_page(struct gpt_walk *walk, gte_t gte)
{
	if (!(gte & (1UL << walk->gpt->valid_bit)))
		return NULL;
	return pfn_to_page(gte_to_pfn(walk, gte));
}

static inline unsigned gpt_index(struct gpt_walk *walk,
				 unsigned long addr,
				 unsigned level)
{
	unsigned shift;

	shift = GTD_SHIFT * level + PAGE_SHIFT;
	return ((addr - walk->gpt->start) >> shift) & GTD_MASK;
}

static inline unsigned long gpt_level_start(struct gpt_walk *walk,
					    unsigned long addr,
					    unsigned level)
{
	unsigned long mask;
	unsigned shift;

	shift = GTD_SHIFT * (level + 1) + PAGE_SHIFT;
	mask = ~((1UL << shift) - 1);
	return ((addr - walk->gpt->start) & mask) + walk->gpt->start;
}

static inline unsigned long gpt_level_end(struct gpt_walk *walk,
					  unsigned long addr,
					  unsigned level)
{
	unsigned long mask;
	unsigned shift;

	shift = GTD_SHIFT * (level + 1) + PAGE_SHIFT;
	mask = (1UL << shift) - 1;
	return ((addr - walk->gpt->start) | mask) + walk->gpt->start + 1;
}


/* gpt_walk_init() - Init gpt walk structure
 * @walk: walk structure to initialize
 */
void gpt_walk_init(struct gpt_walk *walk, struct gpt *gpt)
{
	unsigned level;

	BUG_ON(!gpt);

	walk->gpt = gpt;
	walk->gtd[walk->gpt->nlevels] = NULL;
	walk->gte[walk->gpt->nlevels] = gpt->gdp;
	walk->start = gpt->start;
	walk->end = gpt->end;

	for (level = 0; level < walk->gpt->nlevels; level++) {
		walk->gtd[level] = NULL;
		walk->gte[level] = NULL;
	}
}
EXPORT_SYMBOL(gpt_walk_init);

/* gpt_walk_fini() - Finalize gpt walk structure
 * @walk: walk structure to finalize
 *
 * This unmap any mapped directory.
 */
void gpt_walk_fini(struct gpt_walk *walk)
{
	unsigned level;

	for (level = 0; level < walk->gpt->nlevels; ++level) {
		if (!walk->gtd[level])
			continue;
		kunmap(walk->gtd[level]);
		atomic_dec(gpt_walk_gtd_refcount(walk, level));
		walk->gtd[level] = NULL;
		walk->gte[level] = NULL;
	}
	walk->start = walk->gpt->start;
	walk->end = walk->gpt->end;
}
EXPORT_SYMBOL(gpt_walk_fini);

/* gpt_walk_gtep_from_addr() - Get entry pointer for a given address
 * @walk: walk structure use to walk generic page table
 * @addr: address of interest
 * Returns: NULL if address is not in range of if there is no directory
 *
 * This will return pointer to page table entry if a directory exist for the
 * given address.
 */
gte_t *gpt_walk_gtep_from_addr(struct gpt_walk *walk, unsigned long addr)
{
	unsigned l;

	if (addr < walk->gpt->start || addr >= walk->gpt->end)
		return NULL;

again:
	if (walk->gte[0] && addr >= walk->start && addr < walk->end)
		return &walk->gte[0][gpt_index(walk, addr, 0)];

	for (l = 0; l < walk->gpt->nlevels; l++) {
		if (!walk->gtd[l])
			continue;

		if (addr >= walk->start && addr < walk->end)
			break;

		kunmap(walk->gtd[l]);
		atomic_dec(gpt_walk_gtd_refcount(walk, l));
		walk->gtd[l] = NULL;
		walk->gte[l] = NULL;
		/* Compute start and end address of upper level */
		walk->start = gpt_level_start(walk, walk->start, l + 1);
		walk->end = gpt_level_end(walk, walk->start, l + 1);
	}

	for (; l; l--) {
		unsigned idx;
		atomic_t *refcount;

		idx = gpt_index(walk, addr, l);
		spin_lock(gpt_walk_gtd_lock_ptr(walk, l));
		walk->gtd[l - 1] = gte_to_page(walk, walk->gte[l][idx]);
		refcount = gpt_walk_gtd_refcount(walk, l - 1);
		if (refcount)
			atomic_inc(refcount);
		else
			walk->gtd[l - 1] = NULL;
		spin_unlock(gpt_walk_gtd_lock_ptr(walk, l));
		if (!walk->gtd[l- 1])
			return NULL;

		walk->gte[l - 1] = kmap(walk->gtd[l - 1]);

		/* Compute start and end address of lower level */
		walk->start = gpt_level_start(walk, addr, l - 1);
		walk->end = gpt_level_end(walk, addr, l - 1);
	}

	/* At this point all gtd levels are mapped */
	goto again;
}
EXPORT_SYMBOL(gpt_walk_gtep_from_addr);

/* gpt_populate() - Populate page table directory tree for given address
 * @walk: walk structure use to walk generic page table
 * @addr: address of interest
 * Returns: NULL if nothing to populate (locking error) directory entry pointer
 *
 * This will populate all directory levels that are missing for a given address
 * and it returns a pointer to lowest directory level.
 */
gte_t *gpt_walk_populate(struct gpt_walk *walk, unsigned long addr)
{
	unsigned idx;
	gte_t *gtep;
	int level;

	if ((gtep = gpt_walk_gtep_from_addr(walk, addr)))
		return gtep;

	for (level = walk->gpt->nlevels - 1; level >= 0; level--) {
		unsigned long pfn;

		if (walk->gtd[level])
			continue;

		walk->gtd[level] = alloc_page(GPT_DEFAULT_GFP);
		if (!walk->gtd[level])
			return NULL;
		if (!ptlock_init(walk->gtd[level])) {
			__free_page(walk->gtd[level]);
			walk->gtd[level] = NULL;
			return NULL;
		}
		pfn = page_to_pfn(walk->gtd[level]);

		/* Initialize new directory */
		atomic_set(&walk->gtd[level]->_mapcount, 1);

		/* Compute start and end address of current level */
		walk->start = gpt_level_start(walk, addr, level);
		walk->end = gpt_level_end(walk, addr, level);
		walk->gte[level] = kmap(walk->gtd[level]);

		/* Set directory entry in upper level */
		idx = gpt_index(walk, addr, level + 1);
		atomic_inc(gpt_walk_gtd_refcount(walk, level + 1));
		spin_lock(gpt_walk_gtd_lock_ptr(walk, level + 1));
		walk->gte[level + 1][idx] = pfn << walk->gpt->shift;
		walk->gte[level + 1][idx] |= 1UL << walk->gpt->valid_bit;
		spin_unlock(gpt_walk_gtd_lock_ptr(walk, level + 1));
	}

	idx = gpt_index(walk, addr, 0);
	return &walk->gte[0][idx];
}
EXPORT_SYMBOL(gpt_walk_populate);

/* gpt_page_reset() - Reset struct page fields use by gpt to sane value
 * @page: page that is being prune from directory tree and needs reset
 *
 * We use few fields inside the struct page to store informations for each of
 * directory in the tree. We need to reset some of those fields to sane value
 * so that core mm does not freaks out when we free a directory page.
 *
 * This should be call by the prune callback provided to gpt_prune() when it
 * decides to free a directory level. Default callback, gpt_prune_default(),
 * properly call this function.
 */
static inline void gpt_page_reset(struct page *page)
{
	atomic_set(&page->_mapcount, -1);
}

/* gpt_prune() - Prune page table directory tree for given address range
 * @walk: walk structure use to walk generic page table
 * @start: range start address
 * @end: range end address
 *
 * This will prune the directory tree for the given address range. Any empty
 * directory will be free.
 *
 * WARNING YOU ARE RESPONSIBLE FOR LOCKING IN RESPECT TO CONCURRENT PAGE TABLE
 * PRUNING OR POPULATING !
 */
void gpt_walk_prune(struct gpt_walk *walk,
		    unsigned long start,
		    unsigned long end)
{
	unsigned long addr;

	start &= PAGE_MASK;
	end &= PAGE_MASK;
	BUG_ON(start >= end);

	for (addr = start; addr < end;) {
		unsigned long next;
		unsigned l;

		next = min(end, gpt_level_end(walk, addr, 0));
		gpt_walk_gtep_from_addr(walk, addr);
		for (l = 0; l < walk->gpt->nlevels; l++) {
			unsigned idx;

			if (!walk->gtd[l]) {
				next = min(end, gpt_level_end(walk, addr, l));
				continue;
			}

			if (atomic_read(gpt_walk_gtd_refcount(walk, l)) != 1)
				break;

			/* First unmap end update walk structure */
			kunmap(walk->gtd[l]);
			walk->gtd[l] = NULL;
			walk->gte[l] = NULL;

			/* Pointer to directory entry in the upper level */
			idx = gpt_index(walk, walk->start, l + 1);
			spin_lock(gpt_walk_gtd_lock_ptr(walk, l + 1));
			walk->gte[l + 1][idx] = 0;
			spin_unlock(gpt_walk_gtd_lock_ptr(walk, l + 1));
			atomic_dec(gpt_walk_gtd_refcount(walk, l + 1));

			/* The next address is end address of current level */
			next = min(end, walk->end);

			/* Start and end address are now for the upper level */
			walk->start = gpt_level_start(walk, addr, l + 1);
			walk->end = gpt_level_end(walk, addr, l + 1);
		}
		addr = next;
	}
}
EXPORT_SYMBOL(gpt_walk_prune);

int gpt_walk_range(struct gpt_walk *walk,
		   unsigned long start,
		   unsigned long end,
		   gpt_walk_cb_t cb,
		   void *private)
{
	unsigned long addr;

	for (addr = start; addr < end;) {
		unsigned long next;
		spinlock_t *gtl;
		gte_t *gtep;
		int ret;

		gtep = gpt_walk_gtep_from_addr(walk, addr);
		if (!gtep) {
			unsigned l;

			for (l = 0; l < walk->gpt->nlevels; l++) {
				if (walk->gtd[l])
					break;
				addr = min(end, gpt_level_end(walk, addr, l));
			}
			continue;
		}

		next = min(end, gpt_level_end(walk, addr, 0));
		gtl = gpt_walk_gtd_lock_ptr(walk, 0);
		ret = cb(walk, addr, next, gtl, gtep, private);
		if (ret)
			return ret;
		addr = next;
	}

	return 0;
}
EXPORT_SYMBOL(gpt_walk_range);
