#ifndef __LINUX_PAGE_OWNER_H
#define __LINUX_PAGE_OWNER_H

#include <linux/jump_label.h>

#ifdef CONFIG_PAGE_OWNER
extern bool page_owner_disabled;
extern struct static_key page_owner_inited;
extern struct page_ext_operations page_owner_ops;

extern void __reset_page_owner(struct page *page, unsigned int order);
extern void __set_page_owner(struct page *page,
			unsigned int order, gfp_t gfp_mask);
extern gfp_t __get_page_owner_gfp(struct page *page);

static inline void reset_page_owner(struct page *page, unsigned int order)
{
	if (static_key_false(&page_owner_inited))
		__reset_page_owner(page, order);
}

static inline void set_page_owner(struct page *page,
			unsigned int order, gfp_t gfp_mask)
{
	if (static_key_false(&page_owner_inited))
		__set_page_owner(page, order, gfp_mask);
}

static inline gfp_t get_page_owner_gfp(struct page *page)
{
	if (static_key_false(&page_owner_inited))
		return __get_page_owner_gfp(page);
	else
		return 0;
}
#else
static inline void reset_page_owner(struct page *page, unsigned int order)
{
}
static inline void set_page_owner(struct page *page,
			unsigned int order, gfp_t gfp_mask)
{
}
static inline gfp_t get_page_owner_gfp(struct page *page)
{
	return 0;
}

#endif /* CONFIG_PAGE_OWNER */
#endif /* __LINUX_PAGE_OWNER_H */
