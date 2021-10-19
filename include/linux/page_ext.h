/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_PAGE_EXT_H
#define __LINUX_PAGE_EXT_H

#include <linux/types.h>
#include <linux/stacktrace.h>
#include <linux/stackdepot.h>
#include <linux/page_owner.h>

struct pglist_data;
struct page_ext_operations {
	size_t offset;
	size_t size;
	bool (*need)(void);
	void (*init)(void);
};

#ifdef CONFIG_PAGE_EXTENSION

enum page_ext_flags {
	PAGE_EXT_OWNER,
	PAGE_EXT_OWNER_ALLOCATED,
#if defined(CONFIG_IDLE_PAGE_TRACKING) && !defined(CONFIG_64BIT)
	PAGE_EXT_YOUNG,
	PAGE_EXT_IDLE,
#endif
};

/*
 * Page Extension can be considered as an extended mem_map.
 * A page_ext page is associated with every page descriptor. The
 * page_ext helps us add more information about the page.
 * All page_ext are allocated at boot or memory hotplug event,
 * then the page_ext for pfn always exists.
 */
struct page_ext {
	unsigned long flags;
};

extern unsigned long page_ext_size;
extern void pgdat_page_ext_init(struct pglist_data *pgdat);

#ifdef CONFIG_SPARSEMEM
static inline void page_ext_init_flatmem(void)
{
}
extern void page_ext_init(void);
static inline void page_ext_init_flatmem_late(void)
{
}
#else
extern void page_ext_init_flatmem(void);
extern void page_ext_init_flatmem_late(void);
static inline void page_ext_init(void)
{
}
#endif

struct page_ext *lookup_page_ext(const struct page *page);

static inline struct page_ext *page_ext_next(struct page_ext *curr)
{
	void *next = curr;
	next += page_ext_size;
	return next;
}

extern void _reset_page_vzext(struct page *page, unsigned int order);
extern void _split_page_vzext(struct page *page, unsigned int nr);
extern void _copy_page_vzext(struct page *oldpage, struct page *newpage);

static inline void reset_page_ext(struct page *page, unsigned int order)
{
	_reset_page_owner(page, order);
	_reset_page_vzext(page, order);
}

static inline void split_page_ext(struct page *page, unsigned int nr)
{
	_split_page_owner(page, nr);
	_split_page_vzext(page, nr);
}

static inline void copy_page_ext(struct page *oldpage, struct page *newpage)
{
	_copy_page_owner(oldpage, newpage);
	_copy_page_vzext(oldpage, newpage);
}

#else /* !CONFIG_PAGE_EXTENSION */
struct page_ext;

static inline void pgdat_page_ext_init(struct pglist_data *pgdat)
{
}

static inline struct page_ext *lookup_page_ext(const struct page *page)
{
	return NULL;
}

static inline void page_ext_init(void)
{
}

static inline void page_ext_init_flatmem_late(void)
{
}

static inline void page_ext_init_flatmem(void)
{
}

static inline void reset_page_ext(struct page *page, unsigned int order)
{
}

static inline void split_page_ext(struct page *page, unsigned int order)
{
}

static inline void copy_page_ext(struct page *oldpage, struct page *newpage)
{
}

#endif /* CONFIG_PAGE_EXTENSION */
#endif /* __LINUX_PAGE_EXT_H */
