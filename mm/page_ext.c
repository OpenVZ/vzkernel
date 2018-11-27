#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/bootmem.h>
#include <linux/page_ext.h>
#include <linux/page_cgroup.h>
#include <linux/memory.h>
#include <linux/vmalloc.h>
#include <linux/kmemleak.h>

/*
 * struct page extension
 *
 * This is the feature to manage memory for extended data per page.
 */

static struct page_ext_operations *page_ext_ops[] = {
	&debug_guardpage_ops,
#ifdef CONFIG_PAGE_POISONING
	&page_poisoning_ops,
#endif
};

void __init invoke_page_ext_init_callbacks(void)
{
	int i;
	int entries = ARRAY_SIZE(page_ext_ops);

	for (i = 0; i < entries; i++) {
		if (page_ext_ops[i]->init)
			page_ext_ops[i]->init();
	}
}

struct page_ext *lookup_page_ext(struct page *page)
{
	struct page_cgroup *pc = lookup_page_cgroup(page);

	return &pc->ext;
}
