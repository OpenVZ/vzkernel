/*
 *  include/linux/page_vzflags.h
 *
 *  Copyright (c) 2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef __LINUX_PAGE_VZFLAGS_H
#define __LINUX_PAGE_VZFLAGS_H

#include <linux/page_vzext.h>
#include <linux/page-flags.h>

enum vzpageflags {
	PGVZ_pagecache,
};

#define TESTVZPAGEFLAG(uname, lname)				\
static __always_inline int PageVz##uname(struct page *page)		\
	{ return get_page_vzext(page) && test_bit(PGVZ_##lname, &get_page_vzext(page)->vzflags); }

#define SETVZPAGEFLAG(uname, lname)				\
static __always_inline void SetVzPage##uname(struct page *page)		\
	{ if (get_page_vzext(page)) set_bit(PGVZ_##lname, &get_page_vzext(page)->vzflags); }

#define CLEARVZPAGEFLAG(uname, lname)				\
static __always_inline void ClearVzPage##uname(struct page *page)		\
	{ if (get_page_vzext(page)) clear_bit(PGVZ_##lname, &get_page_vzext(page)->vzflags); }

#define VZPAGEFLAG(uname, lname)					\
	TESTVZPAGEFLAG(uname, lname)				\
	SETVZPAGEFLAG(uname, lname)				\
	CLEARVZPAGEFLAG(uname, lname)

VZPAGEFLAG(PageCache, pagecache)

#endif /* __LINUX_PAGE_VZFLAGS_H */
