/*
 *  mm/page_vzext.c
 *
 *  Copyright (c) 2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/memblock.h>
#include <linux/stacktrace.h>
#include <linux/page_vzext.h>
#include <linux/jump_label.h>
#include <linux/migrate.h>

#include "internal.h"

static bool need_page_vzext(void)
{
	return true;
}

struct page_ext_operations page_vzext_ops = {
	.size = sizeof(struct page_vzext),
	.need = need_page_vzext,
};

static inline struct page_vzext *get_page_ext_vzext(struct page_ext *page_ext)
{
	return (void *)page_ext + page_vzext_ops.offset;
}

void _reset_page_vzext(struct page *page, unsigned int order)
{
	/* TODO: write universal code for page deinitialization */
}

void _split_page_vzext(struct page *page, unsigned int nr)
{
	int i;
	struct page_ext *page_ext = lookup_page_ext(page);
	struct page_vzext *page_vzext;

	if (unlikely(!page_ext))
		return;

	page_vzext = get_page_ext_vzext(page_ext);
	for (i = 1; i < nr; i++)
		_copy_page_vzext(page, page + i);
}

void _copy_page_vzext(struct page *oldpage, struct page *newpage)
{
	struct page_ext *old_ext = lookup_page_ext(oldpage);
	struct page_ext *new_ext = lookup_page_ext(newpage);
	struct page_vzext *old_page_vzext, *new_page_vzext;

	if (unlikely(!old_ext || !new_ext))
		return;

	old_page_vzext = get_page_ext_vzext(old_ext);
	new_page_vzext = get_page_ext_vzext(new_ext);

	/* TODO: add callbacks to handle separate vzext in different helpers */
	new_page_vzext->vzflags = old_page_vzext->vzflags;
}
