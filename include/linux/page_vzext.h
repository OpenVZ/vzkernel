/*
 *  mm/page_vzext.c
 *
 *  Copyright (c) 2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef __LINUX_PAGE_VZEXT_H
#define __LINUX_PAGE_VZEXT_H

#include <linux/page_ext.h>

extern struct page_ext_operations page_vzext_ops;

extern void _reset_page_vzext(struct page *page, unsigned int order);
extern void _split_page_vzext(struct page *page, unsigned int order);
extern void _copy_page_vzext(struct page *oldpage, struct page *newpage);

struct page_vzext {
	unsigned long vzflags;
};

static inline struct page_vzext *get_page_vzext(struct page *page)
{
	struct page_ext *page_ext = lookup_page_ext(page);

	if (unlikely(!page_ext))
		return NULL;

	return (void *)page_ext + page_vzext_ops.offset;
}

#endif /* __LINUX_PAGE_VZEXT_H */
