/*
 *  mm/iov-iter.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/hardirq.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/bio.h>

static size_t __iovec_copy_to_user_inatomic(char *vaddr,
			const struct iovec *iov, size_t base, size_t bytes)
{
	size_t copied = 0, left = 0;

	while (bytes) {
		char __user *buf = iov->iov_base + base;
		int copy = min(bytes, iov->iov_len - base);

		base = 0;
		left = __copy_to_user_inatomic(buf, vaddr, copy);
		copied += copy;
		bytes -= copy;
		vaddr += copy;
		iov++;

		if (unlikely(left))
			break;
	}
	return copied - left;
}

/*
 * Copy as much as we can into the page and return the number of bytes which
 * were sucessfully copied.  If a fault is encountered then return the number of
 * bytes which were copied.
 */
static size_t ii_iovec_copy_to_user_atomic(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	struct iovec *iov = (struct iovec *)i->data;
	char *kaddr;
	size_t copied;

	kaddr = kmap_atomic(page);
	if (likely(i->nr_segs == 1)) {
		int left;
		char __user *buf = iov->iov_base + i->iov_offset;
		left = __copy_to_user_inatomic(buf, kaddr + offset, bytes);
		copied = bytes - left;
	} else {
		copied = __iovec_copy_to_user_inatomic(kaddr + offset,
						iov, i->iov_offset, bytes);
	}
	kunmap_atomic(kaddr);

	return copied;
}

/*
 * This has the same sideeffects and return value as
 * ii_iovec_copy_to_user_atomic().
 * The difference is that it attempts to resolve faults.
 * Page must not be locked.
 */
static size_t ii_iovec_copy_to_user(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	struct iovec *iov = (struct iovec *)i->data;
	char *kaddr;
	size_t copied;

	kaddr = kmap(page);
	if (likely(i->nr_segs == 1)) {
		int left;
		char __user *buf = iov->iov_base + i->iov_offset;
		left = copy_to_user(buf, kaddr + offset, bytes);
		copied = bytes - left;
	} else {
		copied = __iovec_copy_to_user_inatomic(kaddr + offset,
						iov, i->iov_offset, bytes);
	}
	kunmap(page);
	return copied;
}


static size_t __iovec_copy_from_user_inatomic(char *vaddr,
			const struct iovec *iov, size_t base, size_t bytes)
{
	size_t copied = 0, left = 0;

	while (bytes) {
		char __user *buf = iov->iov_base + base;
		int copy = min(bytes, iov->iov_len - base);

		base = 0;
		left = __copy_from_user_inatomic(vaddr, buf, copy);
		copied += copy;
		bytes -= copy;
		vaddr += copy;
		iov++;

		if (unlikely(left))
			break;
	}
	return copied - left;
}

/*
 * Copy as much as we can into the page and return the number of bytes which
 * were sucessfully copied.  If a fault is encountered then return the number of
 * bytes which were copied.
 */
static size_t ii_iovec_copy_from_user_atomic(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	struct iovec *iov = (struct iovec *)i->data;
	char *kaddr;
	size_t copied;

	kaddr = kmap_atomic(page);
	if (likely(i->nr_segs == 1)) {
		int left;
		char __user *buf = iov->iov_base + i->iov_offset;
		left = __copy_from_user_inatomic(kaddr + offset, buf, bytes);
		copied = bytes - left;
	} else {
		copied = __iovec_copy_from_user_inatomic(kaddr + offset,
						iov, i->iov_offset, bytes);
	}
	kunmap_atomic(kaddr);

	return copied;
}
EXPORT_SYMBOL(iov_iter_copy_from_user_atomic);

/*
 * This has the same sideeffects and return value as
 * ii_iovec_copy_from_user_atomic().
 * The difference is that it attempts to resolve faults.
 * Page must not be locked.
 */
static size_t ii_iovec_copy_from_user(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	struct iovec *iov = (struct iovec *)i->data;
	char *kaddr;
	size_t copied;

	kaddr = kmap(page);
	if (likely(i->nr_segs == 1)) {
		int left;
		char __user *buf = iov->iov_base + i->iov_offset;
		left = __copy_from_user(kaddr + offset, buf, bytes);
		copied = bytes - left;
	} else {
		copied = __iovec_copy_from_user_inatomic(kaddr + offset,
						iov, i->iov_offset, bytes);
	}
	kunmap(page);
	return copied;
}

static void ii_iovec_advance(struct iov_iter *i, size_t bytes)
{
	BUG_ON(i->count < bytes);

	if (likely(i->nr_segs == 1)) {
		i->iov_offset += bytes;
		i->count -= bytes;
	} else {
		struct iovec *iov = (struct iovec *)i->data;
		size_t base = i->iov_offset;
		unsigned long nr_segs = i->nr_segs;

		/*
		 * The !iov->iov_len check ensures we skip over unlikely
		 * zero-length segments (without overruning the iovec).
		 */
		while (bytes || unlikely(i->count && !iov->iov_len)) {
			int copy;

			copy = min(bytes, iov->iov_len - base);
			BUG_ON(!i->count || i->count < copy);
			i->count -= copy;
			bytes -= copy;
			base += copy;
			if (iov->iov_len == base) {
				iov++;
				nr_segs--;
				base = 0;
			}
		}
		i->data = (unsigned long)iov;
		i->iov_offset = base;
		i->nr_segs = nr_segs;
	}
}

/*
 * Fault in the first iovec of the given iov_iter, to a maximum length
 * of bytes. Returns 0 on success, or non-zero if the memory could not be
 * accessed (ie. because it is an invalid address).
 *
 * writev-intensive code may want this to prefault several iovecs -- that
 * would be possible (callers must not rely on the fact that _only_ the
 * first iovec will be faulted with the current implementation).
 */
static int ii_iovec_fault_in_readable(struct iov_iter *i, size_t bytes)
{
	struct iovec *iov = (struct iovec *)i->data;
	char __user *buf = iov->iov_base + i->iov_offset;
	bytes = min(bytes, iov->iov_len - i->iov_offset);
	return fault_in_pages_readable(buf, bytes);
}

/*
 * Return the count of just the current iov_iter segment.
 */
static size_t ii_iovec_single_seg_count(const struct iov_iter *i)
{
	struct iovec *iov = (struct iovec *)i->data;
	if (i->nr_segs == 1)
		return i->count;
	else
		return min(i->count, iov->iov_len - i->iov_offset);
}

static void *ii_iovec_kmap_atomic(const struct iov_iter *i, void **bp,
				  size_t *len)
{
	struct iovec *iov = (struct iovec *)i->data;

	*bp = iov->iov_base + i->iov_offset;
	*len = min(i->count, iov->iov_len - i->iov_offset);

	return NULL;
}

static struct page *ii_iovec_kmap(const struct iov_iter *i, void **bp,
				  size_t *len)
{
	struct iovec *iov = (struct iovec *)i->data;

	*bp = iov->iov_base + i->iov_offset;
	*len = min(i->count, iov->iov_len - i->iov_offset);

	return NULL;
}

static struct page *ii_iovec_get_page(const struct iov_iter *i, size_t *off,
				      size_t *len)
{
	return NULL;
}

static int ii_iovec_shorten(struct iov_iter *i, size_t count)
{
	struct iovec *iov = (struct iovec *)i->data;
	i->nr_segs = iov_shorten(iov, i->nr_segs, count);
	return 0;
}

struct iov_iter_ops ii_iovec_ops = {
	.ii_copy_to_user_atomic = ii_iovec_copy_to_user_atomic,
	.ii_copy_to_user = ii_iovec_copy_to_user,
	.ii_copy_from_user_atomic = ii_iovec_copy_from_user_atomic,
	.ii_copy_from_user = ii_iovec_copy_from_user,
	.ii_advance = ii_iovec_advance,
	.ii_fault_in_readable = ii_iovec_fault_in_readable,
	.ii_single_seg_count = ii_iovec_single_seg_count,
	.ii_shorten = ii_iovec_shorten,
	.ii_kmap_atomic = ii_iovec_kmap_atomic,
	.ii_kmap = ii_iovec_kmap,
	.ii_get_page = ii_iovec_get_page,

};
EXPORT_SYMBOL(ii_iovec_ops);

/*
 * Copy as much as we can into the page and return the number of bytes which
 * were sucessfully copied.  If a fault is encountered then return the number of
 * bytes which were copied.
 */
static size_t ii_plain_copy_to_user_atomic(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	char *buf = (void *)i->data + i->iov_offset;
	size_t copied;
	int left;
	char *kaddr;

	BUG_ON(!in_atomic());
	kaddr = kmap_atomic(page);
	left = __copy_to_user_inatomic(buf, kaddr + offset, bytes);
	copied = bytes - left;
	kunmap_atomic(kaddr);

	return copied;
}

/*
 * This has the same sideeffects and return value as
 * ii_plain_copy_to_user_atomic().
 * The difference is that it attempts to resolve faults.
 * Page must not be locked.
 */
static size_t ii_plain_copy_to_user(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	char *buf =  (void *)i->data + i->iov_offset;
	int left;
	char *kaddr;
	size_t copied;

	kaddr = kmap(page);
	left = copy_to_user(buf, kaddr + offset, bytes);
	copied = bytes - left;
	kunmap(page);

	return copied;
}

/*
 * Copy as much as we can into the page and return the number of bytes which
 * were sucessfully copied.  If a fault is encountered then return the number of
 * bytes which were copied.
 */
static size_t ii_plain_copy_from_user_atomic(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	char *buf = (void *)i->data + i->iov_offset;
	char *kaddr;
	size_t copied;
	int left;

	BUG_ON(!in_atomic());
	kaddr = kmap_atomic(page);
	left = __copy_from_user_inatomic(kaddr + offset, buf, bytes);
	copied = bytes - left;
	kunmap_atomic(kaddr);

	return copied;
}

/*
 * This has the same sideeffects and return value as
 * ii_plain_copy_from_user_atomic().
 * The difference is that it attempts to resolve faults.
 * Page must not be locked.
 */
static size_t ii_plain_copy_from_user(struct page *page,
		struct iov_iter *i, unsigned long offset, size_t bytes)
{
	char *buf = (void *)i->data + i->iov_offset;
	char *kaddr;
	size_t copied;
	int left;

	kaddr = kmap(page);
	left = __copy_from_user(kaddr + offset, buf, bytes);
	copied = bytes - left;
	kunmap(page);
	return copied;
}

static void ii_plain_advance(struct iov_iter *i, size_t bytes)
{
	BUG_ON(i->count < bytes);

	BUG_ON(i->nr_segs != 1);

	i->iov_offset += bytes;
	i->count -= bytes;
}

static int ii_plain_fault_in_readable(struct iov_iter *i, size_t bytes)
{
	return 0;
}

static size_t ii_plain_single_seg_count(const struct iov_iter *i)
{
	return i->count;
}

static int ii_plain_shorten(struct iov_iter *i, size_t count)
{
	return 0;
}

static void *ii_plain_kmap_atomic(const struct iov_iter *i, void **bp,
				  size_t *len)
{
	*bp = (void *)i->data + i->iov_offset;
	*len = i->count;

	return NULL;
}

static struct page *ii_plain_kmap(const struct iov_iter *i, void **bp,
				  size_t *len)
{
	*bp = (void *)i->data + i->iov_offset;
	*len = i->count;

	return NULL;
}

static struct page *ii_plain_get_page(const struct iov_iter *i, size_t *off,
				      size_t *len)
{
	return NULL;
}

struct iov_iter_ops ii_plain_ops = {
	.ii_copy_to_user_atomic = ii_plain_copy_to_user_atomic,
	.ii_copy_to_user = ii_plain_copy_to_user,
	.ii_copy_from_user_atomic = ii_plain_copy_from_user_atomic,
	.ii_copy_from_user = ii_plain_copy_from_user,
	.ii_advance = ii_plain_advance,
	.ii_fault_in_readable = ii_plain_fault_in_readable,
	.ii_single_seg_count = ii_plain_single_seg_count,
	.ii_shorten = ii_plain_shorten,
	.ii_kmap_atomic = ii_plain_kmap_atomic,
	.ii_kmap = ii_plain_kmap,
	.ii_get_page = ii_plain_get_page,
};
EXPORT_SYMBOL(ii_plain_ops);

/*
 * As an easily verifiable first pass, we implement all the methods that
 * copy data to and from bvec pages with one function.  We implement it
 * all with kmap_atomic().
 */

static void *ii_bvec_kmap_atomic(const struct iov_iter *iter, void **bp,
				 size_t *len)
{
	struct bio_vec *bvec = (struct bio_vec *)iter->data;
	void *map;

	BUG_ON(iter->iov_offset >= bvec->bv_len);

	map = kmap_atomic(bvec->bv_page);
	*bp = map + bvec->bv_offset + iter->iov_offset;
	*len = min(iter->count, bvec->bv_len - iter->iov_offset);

	return map;
}

static struct page *ii_bvec_kmap(const struct iov_iter *iter, void **bp,
				 size_t *len)
{
	struct bio_vec *bvec = (struct bio_vec *)iter->data;
	void *map;

	BUG_ON(iter->iov_offset >= bvec->bv_len);

	map = kmap(bvec->bv_page);
	*bp = map + bvec->bv_offset + iter->iov_offset;
	*len = min(iter->count, bvec->bv_len - iter->iov_offset);

	return bvec->bv_page;
}

/*
 * Common check that it is sage to pin page with get_page()/put_page()
 * it page is pinnable then page can be subject zerocopy sendpage and others
 */
static bool get_page_is_safe(struct page *page)
{
	/* It is not safe to increment page count on pages with count == 0 */
	return (page_count(page) > 0 && !PageSlab(page));
}

static struct page *ii_bvec_get_page(const struct iov_iter *iter, size_t *off,
				     size_t *len)
{
	struct bio_vec *bvec = (struct bio_vec *)iter->data;

	if (!get_page_is_safe(bvec->bv_page))
		return NULL;

	*off = bvec->bv_offset + iter->iov_offset;
	*len = min(iter->count, bvec->bv_len - iter->iov_offset);
	get_page(bvec->bv_page);

	return bvec->bv_page;
}

static size_t bvec_copy_tofrom_page(struct iov_iter *iter, struct page *page,
				    unsigned long page_offset, size_t bytes,
				    int topage)
{
	struct bio_vec *bvec = (struct bio_vec *)iter->data;
	size_t bvec_offset = iter->iov_offset;
	size_t remaining = bytes;
	void *bvec_map;
	void *page_map;
	size_t copy;

	page_map = kmap_atomic(page);

	BUG_ON(bytes > iter->count);
	while (remaining) {
		BUG_ON(bvec->bv_len == 0);
		BUG_ON(bvec_offset >= bvec->bv_len);
		copy = min(remaining, bvec->bv_len - bvec_offset);
		bvec_map = kmap_atomic(bvec->bv_page);
		if (topage)
			memcpy(page_map + page_offset,
			       bvec_map + bvec->bv_offset + bvec_offset,
			       copy);
		else
			memcpy(bvec_map + bvec->bv_offset + bvec_offset,
			       page_map + page_offset,
			       copy);
		kunmap_atomic(bvec_map);
		remaining -= copy;
		bvec_offset += copy;
		page_offset += copy;
		if (bvec_offset == bvec->bv_len) {
			bvec_offset = 0;
			bvec++;
		}
	}

	kunmap_atomic(page_map);

	return bytes;
}

size_t ii_bvec_copy_to_user_atomic(struct page *page, struct iov_iter *i,
				   unsigned long offset, size_t bytes)
{
	return bvec_copy_tofrom_page(i, page, offset, bytes, 0);
}
size_t ii_bvec_copy_to_user(struct page *page, struct iov_iter *i,
				   unsigned long offset, size_t bytes)
{
	return bvec_copy_tofrom_page(i, page, offset, bytes, 0);
}
size_t ii_bvec_copy_from_user_atomic(struct page *page, struct iov_iter *i,
				     unsigned long offset, size_t bytes)
{
	return bvec_copy_tofrom_page(i, page, offset, bytes, 1);
}
size_t ii_bvec_copy_from_user(struct page *page, struct iov_iter *i,
			      unsigned long offset, size_t bytes)
{
	return bvec_copy_tofrom_page(i, page, offset, bytes, 1);
}

/*
 * bio_vecs have a stricter structure than iovecs that might have
 * come from userspace.  There are no zero length bio_vec elements.
 */
void ii_bvec_advance(struct iov_iter *i, size_t bytes)
{
	struct bio_vec *bvec = (struct bio_vec *)i->data;
	size_t offset = i->iov_offset;
	size_t delta;

	BUG_ON(i->count < bytes);
	while (bytes) {
		BUG_ON(bvec->bv_len == 0);
		BUG_ON(bvec->bv_len <= offset);
		delta = min(bytes, bvec->bv_len - offset);
		offset += delta;
		i->count -= delta;
		bytes -= delta;
		if (offset == bvec->bv_len) {
			bvec++;
			offset = 0;
		}
	}

	i->data = (unsigned long)bvec;
	i->iov_offset = offset;
}

/*
 * pages pointed to by bio_vecs are always pinned.
 */
int ii_bvec_fault_in_readable(struct iov_iter *i, size_t bytes)
{
	return 0;
}

size_t ii_bvec_single_seg_count(const struct iov_iter *i)
{
	const struct bio_vec *bvec = (struct bio_vec *)i->data;
	if (i->nr_segs == 1)
		return i->count;
	else
		return min(i->count, bvec->bv_len - i->iov_offset);
}

static int ii_bvec_shorten(struct iov_iter *i, size_t count)
{
	return -EINVAL;
}

struct iov_iter_ops ii_bvec_ops = {
	.ii_copy_to_user_atomic = ii_bvec_copy_to_user_atomic,
	.ii_copy_to_user = ii_bvec_copy_to_user,
	.ii_copy_from_user_atomic = ii_bvec_copy_from_user_atomic,
	.ii_copy_from_user = ii_bvec_copy_from_user,
	.ii_advance = ii_bvec_advance,
	.ii_fault_in_readable = ii_bvec_fault_in_readable,
	.ii_single_seg_count = ii_bvec_single_seg_count,
	.ii_shorten = ii_bvec_shorten,
	.ii_kmap_atomic = ii_bvec_kmap_atomic,
	.ii_kmap = ii_bvec_kmap,
	.ii_get_page = ii_bvec_get_page,

};
EXPORT_SYMBOL(ii_bvec_ops);

/* Functions to get on with single page */

static void *ii_page_kmap_atomic(const struct iov_iter *iter, void **bp,
				 size_t *len)
{
	struct page *page = (struct page *)iter->data;
	void *map;

	BUG_ON(iter->iov_offset >= PAGE_SIZE);
	map = kmap_atomic(page);
	*bp = map + iter->iov_offset;
	*len = iter->count;
	return map;
}

static struct page *ii_page_kmap(const struct iov_iter *iter, void **bp,
				 size_t *len)
{
	struct page *page = (struct page *)iter->data;
	void *map;

	BUG_ON(iter->iov_offset >= PAGE_SIZE);
	map = kmap(page);
	*bp = map + iter->iov_offset;
	*len = iter->count;
	return page;
}

static struct page *ii_page_get_page(const struct iov_iter *iter, size_t *off,
				     size_t *len)
{
	struct page *page = (struct page *)iter->data;

	if (!get_page_is_safe(page))
		return NULL;

	*off = iter->iov_offset;
	*len = iter->count;
	get_page(page);

	return page;
}

static size_t page_copy_tofrom_page(struct iov_iter *iter, struct page *page,
				    unsigned long page_offset, size_t bytes,
				    int topage)
{
	struct page *ipage = (struct page *)iter->data;
	size_t ipage_offset = iter->iov_offset;
	void *ipage_map;
	void *page_map;

	BUG_ON(bytes > iter->count);
	BUG_ON(bytes > PAGE_SIZE - ipage_offset);
	BUG_ON(ipage_offset >= PAGE_SIZE);

	page_map = kmap_atomic(page);
	ipage_map = kmap_atomic(ipage);

	if (topage)
		memcpy(page_map + page_offset,
		       ipage_map + ipage_offset,
		       bytes);
	else
		memcpy(ipage_map + ipage_offset,
		       page_map + page_offset,
		       bytes);

	kunmap_atomic(ipage_map);
	kunmap_atomic(page_map);

	return bytes;
}

size_t ii_page_copy_to_user_atomic(struct page *page, struct iov_iter *i,
				   unsigned long offset, size_t bytes)
{
	return page_copy_tofrom_page(i, page, offset, bytes, 0);
}
size_t ii_page_copy_to_user(struct page *page, struct iov_iter *i,
				   unsigned long offset, size_t bytes)
{
	return page_copy_tofrom_page(i, page, offset, bytes, 0);
}
size_t ii_page_copy_from_user_atomic(struct page *page, struct iov_iter *i,
				     unsigned long offset, size_t bytes)
{
	return page_copy_tofrom_page(i, page, offset, bytes, 1);
}
size_t ii_page_copy_from_user(struct page *page, struct iov_iter *i,
			      unsigned long offset, size_t bytes)
{
	return page_copy_tofrom_page(i, page, offset, bytes, 1);
}

void ii_page_advance(struct iov_iter *i, size_t bytes)
{
	BUG_ON(i->count < bytes);
	BUG_ON(i->iov_offset >= PAGE_SIZE);
	BUG_ON(bytes > PAGE_SIZE - i->iov_offset);

	i->iov_offset += bytes;
	i->count      -= bytes;
}

/*
 * pages pointed to by bio_vecs are always pinned.
 */
int ii_page_fault_in_readable(struct iov_iter *i, size_t bytes)
{
	return 0;
}

size_t ii_page_single_seg_count(const struct iov_iter *i)
{
	BUG_ON(i->nr_segs != 1);

	return i->count;
}

static int ii_page_shorten(struct iov_iter *i, size_t count)
{
	return -EINVAL;
}

struct iov_iter_ops ii_page_ops = {
	.ii_copy_to_user_atomic = ii_page_copy_to_user_atomic,
	.ii_copy_to_user = ii_page_copy_to_user,
	.ii_copy_from_user_atomic = ii_page_copy_from_user_atomic,
	.ii_copy_from_user = ii_page_copy_from_user,
	.ii_advance = ii_page_advance,
	.ii_fault_in_readable = ii_page_fault_in_readable,
	.ii_single_seg_count = ii_page_single_seg_count,
	.ii_shorten = ii_page_shorten,
	.ii_kmap_atomic = ii_page_kmap_atomic,
	.ii_kmap = ii_page_kmap,
	.ii_get_page = ii_page_get_page,

};
EXPORT_SYMBOL(ii_page_ops);

static inline size_t ii_bad_copy_to_user_atomic(struct page *p,
						struct iov_iter *i,
						unsigned long off, size_t cnt)
{
	BUG();
	return 0;
}
static inline size_t ii_bad_copy_to_user(struct page *p, struct iov_iter *i,
					 unsigned long off, size_t c)
{
	BUG();
	return 0;
}

static inline size_t ii_bad_copy_from_user_atomic(struct page *p,
						  struct iov_iter *i,
						  unsigned long off, size_t c)
{
	BUG();
	return 0;
}

static inline size_t ii_bad_copy_from_user(struct page *p, struct iov_iter *i,
					   unsigned long off, size_t c)
{
	BUG();
	return 0;
}

static inline void ii_bad_advance(struct iov_iter *i, size_t c)
{
	BUG();
}

static inline int ii_bad_fault_in_readable(struct iov_iter *i, size_t c)
{
	BUG();
	return 0;
}

static inline size_t ii_bad_single_seg_count(const struct iov_iter *i)
{
	BUG();
	return 0;
}

static inline int ii_bad_shorten(struct iov_iter *i, size_t c)
{
	BUG();
	return 0;
}

static inline void *ii_bad_kmap_atomic(const struct iov_iter *i, void **bp,
				       size_t *len)
{
	BUG();
	return NULL;
}

static inline struct page *ii_bad_kmap(const struct iov_iter *i, void **bp,
				       size_t *len)
{
	BUG();
	return NULL;
}

static inline struct page *ii_bad_get_page(const struct iov_iter *i, size_t *o,
					   size_t *c)
{
	BUG();
	return NULL;
}

struct iov_iter_ops ii_bad_ops = {
	.ii_copy_to_user_atomic = ii_bad_copy_to_user_atomic,
	.ii_copy_to_user = ii_bad_copy_to_user,
	.ii_copy_from_user_atomic = ii_bad_copy_from_user_atomic,
	.ii_copy_from_user = ii_bad_copy_from_user,
	.ii_advance = ii_bad_advance,
	.ii_fault_in_readable = ii_bad_fault_in_readable,
	.ii_single_seg_count = ii_bad_single_seg_count,
	.ii_shorten = ii_bad_shorten,
	.ii_kmap_atomic = ii_bad_kmap_atomic,
	.ii_kmap = ii_bad_kmap,
	.ii_get_page = ii_bad_get_page,
};
EXPORT_SYMBOL(ii_bad_ops);

static unsigned long alignment_bvec(struct iov_iter *i)
{
	struct bio_vec *bvec = iov_iter_bvec(i);
	unsigned long res;
	size_t size = i->count;
	size_t n;

	if (!size)
		return 0;

	res = bvec->bv_offset + i->iov_offset;
	n = bvec->bv_len - i->iov_offset;
	if (n >= size)
		return res | size;
	size -= n;
	res |= n;
	while (size > (++bvec)->bv_len) {
		res |= bvec->bv_offset | bvec->bv_len;
		size -= bvec->bv_len;
	}
	res |= bvec->bv_offset | size;
	return res;
}

static unsigned long alignment_iovec(const struct iov_iter *i)
{
	const struct iovec *iov = iov_iter_iovec(i);
	unsigned long res;
	size_t size = i->count;
	size_t n;

	if (!size)
		return 0;

	res = (unsigned long)iov->iov_base + i->iov_offset;
	n = iov->iov_len - i->iov_offset;
	if (n >= size)
		return res | size;
	size -= n;
	res |= n;
	while (size > (++iov)->iov_len) {
		res |= (unsigned long)iov->iov_base | iov->iov_len;
		size -= iov->iov_len;
	}
	res |= (unsigned long)iov->iov_base | size;
	return res;
}

unsigned long iov_iter_alignment(struct iov_iter *i)
{
	if (iov_iter_has_bvec(i))
		return alignment_bvec(i);
	else
		return alignment_iovec(i);
}
EXPORT_SYMBOL(iov_iter_alignment);

static ssize_t get_pages_bvec(struct iov_iter *i,
		struct page **pages, size_t maxsize,
		size_t *start)
{
	struct bio_vec *bvec = iov_iter_bvec(i);
	size_t len = bvec->bv_len - i->iov_offset;
	if (len > i->count)
		len = i->count;
	if (len > maxsize)
		len = maxsize;
	*start = bvec->bv_offset + i->iov_offset;

	get_page(*pages = bvec->bv_page);

	return len;
}

static ssize_t get_pages_iovec(struct iov_iter *i,
		struct page **pages, size_t maxsize,
		size_t *start, int rw)
{
	size_t offset = i->iov_offset;
	const struct iovec *iov = iov_iter_iovec(i);
	size_t len;
	unsigned long addr;
	int n;
	int res;

	len = iov->iov_len - offset;
	if (len > i->count)
		len = i->count;
	if (len > maxsize)
		len = maxsize;
	addr = (unsigned long)iov->iov_base + offset;
	len += *start = addr & (PAGE_SIZE - 1);
	addr &= ~(PAGE_SIZE - 1);
	n = (len + PAGE_SIZE - 1) / PAGE_SIZE;
	res = get_user_pages_fast(addr, n, (rw & WRITE) != WRITE, pages);
	if (unlikely(res < 0))
		return res;
	return (res == n ? len : res * PAGE_SIZE) - *start;
}

ssize_t iov_iter_get_pages(struct iov_iter *i,
			   struct page **pages, size_t maxsize,
			   size_t *start, int rw)
{
	if (iov_iter_has_bvec(i))
		return get_pages_bvec(i, pages, maxsize, start);
	else
		return get_pages_iovec(i, pages, maxsize, start, rw);
}
EXPORT_SYMBOL(iov_iter_get_pages);

static int iov_iter_npages_bvec(struct iov_iter *i, int maxpages)
{
	size_t offset = i->iov_offset;
	size_t size = i->count;
	struct bio_vec *bvec = iov_iter_bvec(i);
	int npages = 0;
	int n;

	for (n = 0; size && n < i->nr_segs; n++, bvec++) {
		size_t len = bvec->bv_len - offset;
		offset = 0;
		if (unlikely(!len))	/* empty segment */
			continue;
		if (len > size)
			len = size;
		npages++;
		if (npages >= maxpages)	/* don't bother going further */
			return maxpages;
		size -= len;
		offset = 0;
	}
	return min(npages, maxpages);
}

static int iov_iter_npages_iovec(const struct iov_iter *i, int maxpages)
{
	size_t offset = i->iov_offset;
	size_t size = i->count;
	const struct iovec *iov = iov_iter_iovec(i);
	int npages = 0;
	int n;

	for (n = 0; size && n < i->nr_segs; n++, iov++) {
		unsigned long addr = (unsigned long)iov->iov_base + offset;
		size_t len = iov->iov_len - offset;
		offset = 0;
		if (unlikely(!len))	/* empty segment */
			continue;
		if (len > size)
			len = size;
		npages += (addr + len + PAGE_SIZE - 1) / PAGE_SIZE
			  - addr / PAGE_SIZE;
		if (npages >= maxpages)	/* don't bother going further */
			return maxpages;
		size -= len;
		offset = 0;
	}
	return min(npages, maxpages);
}

int iov_iter_npages(struct iov_iter *i, int maxpages)
{
	if (iov_iter_has_bvec(i))
		return iov_iter_npages_bvec(i, maxpages);
	else
		return iov_iter_npages_iovec(i, maxpages);
}
EXPORT_SYMBOL(iov_iter_npages);
