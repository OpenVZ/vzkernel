#include <linux/bootmem.h>
#include <linux/compiler.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ksm.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/kernel-page-flags.h>
#include <asm/uaccess.h>
#include "internal.h"

#define KPMSIZE sizeof(u64)
#define KPMMASK (KPMSIZE - 1)
#define KPMBITS (KPMSIZE * BITS_PER_BYTE)

/* /proc/kpagecount - an array exposing page counts
 *
 * Each entry is a u64 representing the corresponding
 * physical page count.
 */
static ssize_t kpagecount_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	u64 __user *out = (u64 __user *)buf;
	struct page *ppage;
	unsigned long src = *ppos;
	unsigned long pfn;
	ssize_t ret = 0;
	u64 pcount;

	pfn = src / KPMSIZE;
	count = min_t(size_t, count, (max_pfn * KPMSIZE) - src);
	if (src & KPMMASK || count & KPMMASK)
		return -EINVAL;

	while (count > 0) {
		if (pfn_valid(pfn))
			ppage = pfn_to_page(pfn);
		else
			ppage = NULL;
		if (!ppage || PageSlab(ppage))
			pcount = 0;
		else
			pcount = page_mapcount(ppage);

		if (put_user(pcount, out)) {
			ret = -EFAULT;
			break;
		}

		pfn++;
		out++;
		count -= KPMSIZE;
	}

	*ppos += (char __user *)out - buf;
	if (!ret)
		ret = (char __user *)out - buf;
	return ret;
}

static const struct file_operations proc_kpagecount_operations = {
	.llseek = mem_lseek,
	.read = kpagecount_read,
};

/* /proc/kpageflags - an array exposing page flags
 *
 * Each entry is a u64 representing the corresponding
 * physical page flags.
 */

static inline u64 kpf_copy_bit(u64 kflags, int ubit, int kbit)
{
	return ((kflags >> kbit) & 1) << ubit;
}

u64 stable_page_flags(struct page *page)
{
	u64 k;
	u64 u;

	/*
	 * pseudo flag: KPF_NOPAGE
	 * it differentiates a memory hole from a page with no flags
	 */
	if (!page)
		return 1 << KPF_NOPAGE;

	k = page->flags;
	u = 0;

	/*
	 * pseudo flags for the well known (anonymous) memory mapped pages
	 *
	 * Note that page->_mapcount is overloaded in SLOB/SLUB/SLQB, so the
	 * simple test in page_mapped() is not enough.
	 */
	if (!PageSlab(page) && page_mapped(page))
		u |= 1 << KPF_MMAP;
	if (PageAnon(page))
		u |= 1 << KPF_ANON;
	if (PageKsm(page))
		u |= 1 << KPF_KSM;

	/*
	 * compound pages: export both head/tail info
	 * they together define a compound page's start/end pos and order
	 */
	if (PageHead(page))
		u |= 1 << KPF_COMPOUND_HEAD;
	if (PageTail(page))
		u |= 1 << KPF_COMPOUND_TAIL;
	if (PageHuge(page))
		u |= 1 << KPF_HUGE;
	/*
	 * PageTransCompound can be true for non-huge compound pages (slab
	 * pages or pages allocated by drivers with __GFP_COMP) because it
	 * just checks PG_head/PG_tail, so we need to check PageLRU/PageAnon
	 * to make sure a given page is a thp, not a non-huge compound page.
	 */
	else if (PageTransCompound(page) && (PageLRU(compound_head(page)) ||
					     PageAnon(compound_head(page))))
		u |= 1 << KPF_THP;

	/*
	 * Caveats on high order pages: page->_count will only be set
	 * -1 on the head page; SLUB/SLQB do the same for PG_slab;
	 * SLOB won't set PG_slab at all on compound pages.
	 */
	if (PageBuddy(page))
		u |= 1 << KPF_BUDDY;

	u |= kpf_copy_bit(k, KPF_LOCKED,	PG_locked);

	u |= kpf_copy_bit(k, KPF_SLAB,		PG_slab);

	u |= kpf_copy_bit(k, KPF_ERROR,		PG_error);
	u |= kpf_copy_bit(k, KPF_DIRTY,		PG_dirty);
	u |= kpf_copy_bit(k, KPF_UPTODATE,	PG_uptodate);
	u |= kpf_copy_bit(k, KPF_WRITEBACK,	PG_writeback);

	u |= kpf_copy_bit(k, KPF_LRU,		PG_lru);
	u |= kpf_copy_bit(k, KPF_REFERENCED,	PG_referenced);
	u |= kpf_copy_bit(k, KPF_ACTIVE,	PG_active);
	u |= kpf_copy_bit(k, KPF_RECLAIM,	PG_reclaim);

	u |= kpf_copy_bit(k, KPF_SWAPCACHE,	PG_swapcache);
	u |= kpf_copy_bit(k, KPF_SWAPBACKED,	PG_swapbacked);

	u |= kpf_copy_bit(k, KPF_UNEVICTABLE,	PG_unevictable);
	u |= kpf_copy_bit(k, KPF_MLOCKED,	PG_mlocked);

#ifdef CONFIG_MEMORY_FAILURE
	u |= kpf_copy_bit(k, KPF_HWPOISON,	PG_hwpoison);
#endif

#ifdef CONFIG_ARCH_USES_PG_UNCACHED
	u |= kpf_copy_bit(k, KPF_UNCACHED,	PG_uncached);
#endif

	u |= kpf_copy_bit(k, KPF_RESERVED,	PG_reserved);
	u |= kpf_copy_bit(k, KPF_MAPPEDTODISK,	PG_mappedtodisk);
	u |= kpf_copy_bit(k, KPF_PRIVATE,	PG_private);
	u |= kpf_copy_bit(k, KPF_PRIVATE_2,	PG_private_2);
	u |= kpf_copy_bit(k, KPF_OWNER_PRIVATE,	PG_owner_priv_1);
	u |= kpf_copy_bit(k, KPF_ARCH,		PG_arch_1);

	return u;
};

static ssize_t kpageflags_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	u64 __user *out = (u64 __user *)buf;
	struct page *ppage;
	unsigned long src = *ppos;
	unsigned long pfn;
	ssize_t ret = 0;

	pfn = src / KPMSIZE;
	count = min_t(unsigned long, count, (max_pfn * KPMSIZE) - src);
	if (src & KPMMASK || count & KPMMASK)
		return -EINVAL;

	while (count > 0) {
		if (pfn_valid(pfn))
			ppage = pfn_to_page(pfn);
		else
			ppage = NULL;

		if (put_user(stable_page_flags(ppage), out)) {
			ret = -EFAULT;
			break;
		}

		pfn++;
		out++;
		count -= KPMSIZE;
	}

	*ppos += (char __user *)out - buf;
	if (!ret)
		ret = (char __user *)out - buf;
	return ret;
}

static const struct file_operations proc_kpageflags_operations = {
	.llseek = mem_lseek,
	.read = kpageflags_read,
};

#ifdef CONFIG_MEMCG
static ssize_t kpagecgroup_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	u64 __user *out = (u64 __user *)buf;
	struct page *ppage;
	unsigned long src = *ppos;
	unsigned long pfn;
	ssize_t ret = 0;
	u64 ino;

	pfn = src / KPMSIZE;
	count = min_t(unsigned long, count, (max_pfn * KPMSIZE) - src);
	if (src & KPMMASK || count & KPMMASK)
		return -EINVAL;

	while (count > 0) {
		if (pfn_valid(pfn))
			ppage = pfn_to_page(pfn);
		else
			ppage = NULL;

		if (ppage)
			ino = page_cgroup_ino(ppage);
		else
			ino = 0;

		if (put_user(ino, out)) {
			ret = -EFAULT;
			break;
		}

		pfn++;
		out++;
		count -= KPMSIZE;
	}

	*ppos += (char __user *)out - buf;
	if (!ret)
		ret = (char __user *)out - buf;
	return ret;
}

static const struct file_operations proc_kpagecgroup_operations = {
	.llseek = mem_lseek,
	.read = kpagecgroup_read,
};
#endif /* CONFIG_MEMCG */

#ifdef CONFIG_IDLE_PAGE_TRACKING
/*
 * Idle page tracking only considers user memory pages, for other types of
 * pages the idle flag is always unset and an attempt to set it is silently
 * ignored.
 *
 * We treat a page as a user memory page if it is on an LRU list, because it is
 * always safe to pass such a page to page_referenced(), which is essential for
 * idle page tracking. With such an indicator of user pages we can skip
 * isolated pages, but since there are not usually many of them, it will hardly
 * affect the overall result.
 *
 * This function tries to get a user memory page by pfn as described above.
 */
static struct page *kpageidle_get_page(unsigned long pfn)
{
	struct page *page;
	struct zone *zone;

	if (!pfn_valid(pfn))
		return NULL;

	page = pfn_to_page(pfn);
	if (!page || !PageLRU(page))
		return NULL;
	if (!get_page_unless_zero(page))
		return NULL;

	zone = page_zone(page);
	spin_lock_irq(&zone->lru_lock);
	if (unlikely(!PageLRU(page))) {
		put_page(page);
		page = NULL;
	}
	spin_unlock_irq(&zone->lru_lock);
	return page;
}

/*
 * This function calls page_referenced() to clear the referenced bit for all
 * mappings to a page. Since the latter also clears the page idle flag if the
 * page was referenced, it can be used to update the idle flag of a page.
 */
static void kpageidle_clear_pte_refs(struct page *page)
{
	unsigned long dummy;

	if (page_referenced(page, 0, NULL, &dummy))
		/*
		 * We cleared the referenced bit in a mapping to this page. To
		 * avoid interference with the reclaimer, mark it young so that
		 * the next call to page_referenced() will also return > 0 (see
		 * page_referenced_one())
		 */
		set_page_young(page);
}

static ssize_t kpageidle_read(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos)
{
	u64 __user *out = (u64 __user *)buf;
	struct page *page;
	unsigned long pfn, end_pfn;
	ssize_t ret = 0;
	u64 idle_bitmap = 0;
	int bit;

	if (*ppos & KPMMASK || count & KPMMASK)
		return -EINVAL;

	pfn = *ppos * BITS_PER_BYTE;
	if (pfn >= max_pfn)
		return 0;

	end_pfn = pfn + count * BITS_PER_BYTE;
	if (end_pfn > max_pfn)
		end_pfn = ALIGN(max_pfn, KPMBITS);

	for (; pfn < end_pfn; pfn++) {
		bit = pfn % KPMBITS;
		page = kpageidle_get_page(pfn);
		if (page) {
			if (page_is_idle(page)) {
				/*
				 * The page might have been referenced via a
				 * pte, in which case it is not idle. Clear
				 * refs and recheck.
				 */
				kpageidle_clear_pte_refs(page);
				if (page_is_idle(page))
					idle_bitmap |= 1ULL << bit;
			}
			put_page(page);
		}
		if (bit == KPMBITS - 1) {
			if (put_user(idle_bitmap, out)) {
				ret = -EFAULT;
				break;
			}
			idle_bitmap = 0;
			out++;
		}
	}

	*ppos += (char __user *)out - buf;
	if (!ret)
		ret = (char __user *)out - buf;
	return ret;
}

static ssize_t kpageidle_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	const u64 __user *in = (const u64 __user *)buf;
	struct page *page;
	unsigned long pfn, end_pfn;
	ssize_t ret = 0;
	u64 idle_bitmap = 0;
	int bit;

	if (*ppos & KPMMASK || count & KPMMASK)
		return -EINVAL;

	pfn = *ppos * BITS_PER_BYTE;
	if (pfn >= max_pfn)
		return -ENXIO;

	end_pfn = pfn + count * BITS_PER_BYTE;
	if (end_pfn > max_pfn)
		end_pfn = ALIGN(max_pfn, KPMBITS);

	for (; pfn < end_pfn; pfn++) {
		bit = pfn % KPMBITS;
		if (bit == 0) {
			if (get_user(idle_bitmap, in)) {
				ret = -EFAULT;
				break;
			}
			in++;
		}
		if (idle_bitmap >> bit & 1) {
			page = kpageidle_get_page(pfn);
			if (page) {
				kpageidle_clear_pte_refs(page);
				set_page_idle(page);
				put_page(page);
			}
		}
	}

	*ppos += (const char __user *)in - buf;
	if (!ret)
		ret = (const char __user *)in - buf;
	return ret;
}

static const struct file_operations proc_kpageidle_operations = {
	.llseek = mem_lseek,
	.read = kpageidle_read,
	.write = kpageidle_write,
};
#endif /* CONFIG_IDLE_PAGE_TRACKING */

static int __init proc_page_init(void)
{
	proc_create("kpagecount", S_IRUSR, NULL, &proc_kpagecount_operations);
	proc_create("kpageflags", S_IRUSR, NULL, &proc_kpageflags_operations);
#ifdef CONFIG_MEMCG
	proc_create("kpagecgroup", S_IRUSR, NULL, &proc_kpagecgroup_operations);
#endif
#ifdef CONFIG_IDLE_PAGE_TRACKING
	proc_create("kpageidle", S_IRUSR | S_IWUSR, NULL,
		    &proc_kpageidle_operations);
#endif
	return 0;
}
module_init(proc_page_init);
