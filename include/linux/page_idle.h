#ifndef _LINUX_MM_PAGE_IDLE_H
#define _LINUX_MM_PAGE_IDLE_H

#include <linux/page-flags.h>

#ifdef CONFIG_IDLE_PAGE_TRACKING

static inline bool page_is_young(struct page *page)
{
	return PageYoung(page);
}

static inline void set_page_young(struct page *page)
{
	SetPageYoung(page);
}

static inline bool test_and_clear_page_young(struct page *page)
{
	return TestClearPageYoung(page);
}

static inline bool page_is_idle(struct page *page)
{
	return PageIdle(page);
}

static inline void set_page_idle(struct page *page)
{
	SetPageIdle(page);
}

static inline void clear_page_idle(struct page *page)
{
	ClearPageIdle(page);
}

#else /* !CONFIG_IDLE_PAGE_TRACKING */

static inline bool page_is_young(struct page *page)
{
	return false;
}

static inline void set_page_young(struct page *page)
{
}

static inline bool test_and_clear_page_young(struct page *page)
{
	return false;
}

static inline bool page_is_idle(struct page *page)
{
	return false;
}

static inline void set_page_idle(struct page *page)
{
}

static inline void clear_page_idle(struct page *page)
{
}

#endif /* CONFIG_IDLE_PAGE_TRACKING */

#endif /* _LINUX_MM_PAGE_IDLE_H */
