#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>

/* These functions compensate for nice features, which are present
 * in new kernels and absent in 2.6.18.
 */

static int _add_to_page_cache_lru(struct page *page, struct address_space *mapping,
				  pgoff_t offset, gfp_t gfp_mask)
{
	int ret = add_to_page_cache(page, mapping, offset, gfp_mask);
	if (ret == 0) {
		struct pagevec lru_pvec;
		pagevec_init(&lru_pvec, 0);

		page_cache_get(page);
		if (!pagevec_add(&lru_pvec, page))
			__pagevec_lru_add(&lru_pvec);
		pagevec_lru_add(&lru_pvec);
	}
	return ret;
}


static struct page *
__grab_cache_page(struct address_space *mapping, pgoff_t index)
{
	int status;
	struct page *page;
repeat:
	page = find_lock_page(mapping, index);
	if (likely(page))
		return page;

	page = page_cache_alloc(mapping);
	if (!page)
		return NULL;
	status = _add_to_page_cache_lru(page, mapping, index, mapping_gfp_mask(mapping));
	if (unlikely(status)) {
		page_cache_release(page);
		if (status == -EEXIST)
			goto repeat;
		return NULL;
	}
	return page;
}


int pagecache_write_begin(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata)
{
	const struct address_space_operations *aops = mapping->a_ops;

	int ret;
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	unsigned offset = pos & (PAGE_CACHE_SIZE - 1);
	struct inode *inode = mapping->host;
	struct page *page;

	page = __grab_cache_page(mapping, index);
	*pagep = page;
	if (!page)
		return -ENOMEM;

	ret = aops->prepare_write(file, page, offset, offset+len);
	if (ret) {
		unlock_page(page);
		page_cache_release(page);
		if (pos + len > inode->i_size)
			vmtruncate(inode, inode->i_size);
	}
	return ret;
}

int pagecache_write_end(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata)
{
	const struct address_space_operations *aops = mapping->a_ops;
	int ret;

	unsigned offset = pos & (PAGE_CACHE_SIZE - 1);
	struct inode *inode = mapping->host;

	flush_dcache_page(page);
	ret = aops->commit_write(file, page, offset, offset+len);
	unlock_page(page);
#if 0
	/* Not really, we are not interested. */
	mark_page_accessed(page);
#endif
	page_cache_release(page);

	if (ret < 0) {
		if (pos + len > inode->i_size)
			vmtruncate(inode, inode->i_size);
	} else if (ret > 0)
		ret = min_t(size_t, copied, ret);
	else
		ret = copied;

	return ret;
}

#endif
