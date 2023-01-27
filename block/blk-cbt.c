/*
 *  block/blk-cbt.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>
#include <linux/log2.h>
#include <linux/math.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>

#define CBT_MAX_EXTENTS	512
#define NR_PAGES(bits)		DIV_ROUND_UP((bits), PAGE_SIZE*8)
#define BITS_PER_PAGE		(1UL << (PAGE_SHIFT + 3))

#define CBT_PAGE_MISSED (struct page *)(0x1)
#define CBT_PAGE(cbt, idx) (cbt->map[idx] == CBT_PAGE_MISSED ? \
			    NULL : cbt->map[idx])

static __cacheline_aligned_in_smp DEFINE_MUTEX(cbt_mutex);

struct cbt_extent{
	blkcnt_t start;
	blkcnt_t len;
};

struct cbt_info {
	__u8 	 uuid[16];
	struct request_queue *queue;
	blkcnt_t block_max;
	blkcnt_t block_bits;
	unsigned long flags;

	struct rcu_head rcu;
	unsigned int count;
	struct cbt_extent __percpu *cache;
	struct page **map;

	struct page **snp_map;
	blkcnt_t snp_block_max;

	spinlock_t lock;
};


enum CBT_FLAGS
{
	CBT_ERROR = 0,
	CBT_DEAD  = 1,
	CBT_NOCACHE  = 2,
};
static void cbt_release_callback(struct rcu_head *head);
static void cbt_flush_cache(struct cbt_info *cbt);

static inline void spin_lock_page(struct page *page)
{
	while(!trylock_page(page))
		cpu_relax();
}

static void set_bits(void *bm, int cur, int len, bool is_set)
{
	__u32 *addr;
	__u32 pattern = is_set? 0xffffffff : 0;

	len = cur + len;
	while (cur < len) {
		if ((cur & 31) == 0 && (len - cur) >= 32) {
			/* fast path: set whole word at once */
			addr = bm + (cur >> 3);

			*addr = pattern;
			cur += 32;
			continue;
		}
		if (is_set)
			set_bit(cur, bm);
		else
			clear_bit(cur, bm);
		cur++;
	}
}

/*
 * Return values:
 * 0 if OK,
 * -EAGAIN if cbt was updated,
 * -EBADF if cbt is dead,
 * -ENOMEM if alloc_page failed.
 */
static int cbt_page_alloc(struct cbt_info  **cbt_pp, unsigned long idx,
			  int in_rcu)
{
	struct cbt_info	 *cbt = *cbt_pp;
	struct page *page;

	/* Page not allocated yet. Synchronization required */
	spin_lock_irq(&cbt->lock);
	if (likely(!test_bit(CBT_DEAD, &cbt->flags))) {
		cbt->count++;
	} else {
		struct cbt_info *new = rcu_dereference(cbt->queue->cbt);

		spin_unlock_irq(&cbt->lock);
		/* was cbt updated ? */
		if (new != cbt) {
			*cbt_pp = new;
			return -EAGAIN;
		} else {
			return -EBADF;
		}
	}
	spin_unlock_irq(&cbt->lock);
	if (in_rcu)
		rcu_read_unlock();
	page = alloc_page(GFP_NOIO|__GFP_ZERO);
	if (in_rcu)
		rcu_read_lock();
	spin_lock_irq(&cbt->lock);
	if (unlikely(!--(cbt->count) && test_bit(CBT_DEAD, &cbt->flags))) {
		spin_unlock_irq(&cbt->lock);
		call_rcu(&cbt->rcu, &cbt_release_callback);
		if (page)
			__free_page(page);
		return -EBADF;
	}
	if (unlikely(!page)) {
		set_bit(CBT_ERROR, &cbt->flags);
		spin_unlock_irq(&cbt->lock);
		return -ENOMEM;
	}

	if (likely(CBT_PAGE(cbt, idx) == NULL))
		cbt->map[idx] = page;
	else
		__free_page(page);

	page = NULL;
	spin_unlock_irq(&cbt->lock);

	return 0;
}

static int __blk_cbt_set(struct cbt_info  *cbt, blkcnt_t block,
			 blkcnt_t count, bool in_rcu, bool set,
			 unsigned long *pages_missed,
			 unsigned long *idx_first)
{
	struct page *page;

	if (unlikely(block + count > cbt->block_max)) {
		printk("WARN: %s eof access block:%lld, len: %lld, max:%lld\n",
		       __FUNCTION__, (unsigned long long) block,
		       (unsigned long long)count,
		       (unsigned long long)cbt->block_max);
		set_bit(CBT_ERROR, &cbt->flags);
		return -EINVAL;
	}

	while(count) {
		unsigned long idx = block >> (PAGE_SHIFT + 3);
		unsigned long off = block & (BITS_PER_PAGE -1);
		unsigned long len = min_t(unsigned long, BITS_PER_PAGE - off,
					  count);
		int ret;
		unsigned long flags;

		page = CBT_PAGE(cbt, idx);
		if (page) {
			local_irq_save(flags);
			spin_lock_page(page);
			set_bits(page_address(page), off, len, set);
			unlock_page(page);
			local_irq_restore(flags);
			count -= len;
			block += len;
			continue;
		} else if (pages_missed) {
			(*pages_missed)++;
			if (!*idx_first)
				*idx_first = idx;
			cbt->map[idx] = CBT_PAGE_MISSED;
			count -= len;
			block += len;
			continue;
		}  else {
			if (!set) {
				/* Nothing to do */
				count -= len;
				block += len;
				continue;
			}
		}

		ret = cbt_page_alloc(&cbt, idx, in_rcu);
		if (ret == -EAGAIN) /* new cbt */
			continue;
		else if (ret == -EBADF) /* dead cbt */
			break;
		else if (ret)
			return ret;
	}
	return (pages_missed && *pages_missed) ? -EAGAIN : 0;
}

static void blk_cbt_add(struct request_queue *q, blkcnt_t start, blkcnt_t len)
{
	struct cbt_info *cbt;
	struct cbt_extent *ex;
	struct cbt_extent old;
	blkcnt_t end;
	/* Check per-cpu cache */

	rcu_read_lock();
	cbt = rcu_dereference(q->cbt);
	if (unlikely(!cbt))
		goto out_rcu;

	if (unlikely(test_bit(CBT_ERROR, &cbt->flags)))
		goto out_rcu;
	end = DIV_ROUND_UP(start + len, 1 << cbt->block_bits);
	start >>= cbt->block_bits;
	len = end - start;
	if (unlikely(test_bit(CBT_NOCACHE, &cbt->flags))) {
		__blk_cbt_set(cbt, start, len, 1, 1, NULL, NULL);
		goto out_rcu;
	}
	local_irq_disable();
	ex = this_cpu_ptr(cbt->cache);
	if (ex->start + ex->len == start) {
		ex->len += len;
		local_irq_enable();
		goto out_rcu;
	}
	old = *ex;
	ex->start = start;
	ex->len = len;
	local_irq_enable();

	if (likely(old.len))
		__blk_cbt_set(cbt, old.start, old.len, 1, 1, NULL, NULL);
out_rcu:
	rcu_read_unlock();
}

inline void blk_cbt_bio_queue(struct request_queue *q, struct bio *bio)
{
	if (!q->cbt || bio_data_dir(bio) == READ || !bio->bi_iter.bi_size)
		return;

	blk_cbt_add(q, bio->bi_iter.bi_sector << 9, bio->bi_iter.bi_size);
}

static struct cbt_info* do_cbt_alloc(struct request_queue *q, __u8 *uuid,
				     loff_t size, loff_t blocksize)
{
	struct cbt_info *cbt;

	cbt = kzalloc(sizeof(*cbt), GFP_KERNEL);
	if (!cbt)
		return ERR_PTR(-ENOMEM);

	cbt->block_bits = ilog2(blocksize);
	cbt->block_max  = DIV_ROUND_UP(size, blocksize);
	spin_lock_init(&cbt->lock);
	memcpy(cbt->uuid, uuid, sizeof(cbt->uuid));
	cbt->cache = alloc_percpu(struct cbt_extent);
	if (!cbt->cache)
		goto err_cbt;

	cbt->map = vmalloc(NR_PAGES(cbt->block_max) * sizeof(void*));
	if (!cbt->map)
		goto err_pcpu;

	memset(cbt->map, 0, NR_PAGES(cbt->block_max) * sizeof(void*));
	cbt->queue = q;
	return cbt;
err_pcpu:
	free_percpu(cbt->cache);
err_cbt:
	kfree(cbt);
	return ERR_PTR(-ENOMEM);
}

static void free_map(struct page **map, unsigned long npages)
{
	unsigned long i;

	for (i = 0; i < npages; i++)
		if (map[i])
			__free_page(map[i]);
	vfree(map);
}

static unsigned long map_required_size(struct page **map, unsigned long block_max)
{
	unsigned long bit, page, npages = NR_PAGES(block_max);

	for (page = npages - 1; page != ULONG_MAX; page--) {
		if (map[page])
			break;
	}
	if (page == ULONG_MAX)
		return 0;

	bit = find_last_bit(page_address(map[page]), PAGE_SIZE);
	if (bit >= PAGE_SIZE)
		bit = 0; /* Not found */
	else
		bit++;

	return DIV_ROUND_UP(bit, 8) + page * PAGE_SIZE;
}

static int copy_cbt_to_user(struct page **map, unsigned long size,
			    unsigned long to_size, void *user_addr)
{
        unsigned long i, bytes, npages = DIV_ROUND_UP(size, PAGE_SIZE);

	if (size > to_size)
		return -EFBIG;

        for (i = 0; i < npages; i++) {
                struct page *page = map[i] ? : ZERO_PAGE(0);

		if (i != npages - 1)
			bytes = PAGE_SIZE;
		else
			bytes = size % PAGE_SIZE;

                if (copy_to_user(user_addr, page_address(page), bytes))
                        return -EFAULT;

                user_addr += bytes;
        }

	/* Zero the rest of memory passed by user */
        npages = DIV_ROUND_UP(to_size, PAGE_SIZE);
	for (; i < npages; i++) {
                struct page *page = ZERO_PAGE(0);

		if (i != npages - 1)
			bytes = PAGE_SIZE;
		else
			bytes = to_size % PAGE_SIZE;

                if (copy_to_user(user_addr, page_address(page), bytes))
                        return -EFAULT;

                user_addr += bytes;
	}

        return 0;
}

static int blk_cbt_snap_create(struct request_queue *q, __u8 *uuid,
			       struct blk_user_cbt_snap_create __user *arg)
{
	unsigned long size;
	long npages, i;
	__u64 to_addr, to_size;
	struct cbt_info *cbt;
	struct page **map;
	int ret;

	if (copy_from_user(&to_addr, &arg->addr, sizeof(to_addr)) ||
	    copy_from_user(&to_size, &arg->size, sizeof(to_size)) ||
	    (unsigned long)to_addr != to_addr ||
	    (unsigned long)to_size != to_size)
		return -EFAULT;

	mutex_lock(&cbt_mutex);
	cbt = q->cbt;

	if (!cbt) {
		mutex_unlock(&cbt_mutex);
		return -ENOENT;
	}

	BUG_ON(!cbt->map);
	BUG_ON(!cbt->block_max);

	if (!uuid || memcmp(uuid, cbt->uuid, sizeof(cbt->uuid))) {
		mutex_unlock(&cbt_mutex);
		return -EINVAL;
	}

	if (cbt->snp_map) {
		mutex_unlock(&cbt_mutex);
		return -EBUSY;
	}

	cbt_flush_cache(cbt);

	size = map_required_size(cbt->map, cbt->block_max);
	if (to_size < size) {
		mutex_unlock(&cbt_mutex);
		return -EFBIG;
	}

	npages = NR_PAGES(cbt->block_max);
	map = vmalloc(npages * sizeof(void*));
	if (!map)
		goto fail;

	memset(map, 0, npages * sizeof(void*));

	for (i = 0; i < npages; i++) {
		struct page *page = cbt->map[i];

		BUG_ON(page == CBT_PAGE_MISSED);

		if (page) {
			map[i] = alloc_page(GFP_KERNEL|__GFP_ZERO);
			if (!map[i])
				goto fail_pages;

			spin_lock_page(page);
			memcpy(page_address(map[i]), page_address(page),
			       PAGE_SIZE);
			memset(page_address(page), 0, PAGE_SIZE);
			unlock_page(page);
		}
	}

	cbt->snp_map = map;
	cbt->snp_block_max = cbt->block_max;
	ret = copy_cbt_to_user(map, size, to_size, (void *)to_addr);

	mutex_unlock(&cbt_mutex);
	return ret;

fail_pages:
	while (--i >= 0) {
		if (map[i])
			__free_page(map[i]);
	}
fail:
	vfree(map);
	mutex_unlock(&cbt_mutex);
	return -ENOMEM;
}

static int blk_cbt_snap_drop(struct request_queue *q, __u8 *uuid)
{
	struct cbt_info *cbt;
	unsigned long npages;
	struct page **map;
	int ret;

	mutex_lock(&cbt_mutex);
	cbt = q->cbt;

	ret = -ENOENT;
	if (!cbt)
		goto out;

	BUG_ON(!cbt->map);
	BUG_ON(!cbt->block_max);

	ret = -EINVAL;
	if (!uuid || memcmp(uuid, cbt->uuid, sizeof(cbt->uuid)))
		goto out;

	ret = -ENODEV;
	map = cbt->snp_map;
	if (!map)
		goto out;
	cbt->snp_map = NULL;
	npages = NR_PAGES(cbt->snp_block_max);
	cbt->snp_block_max = 0;
	ret = 0;
out:
	mutex_unlock(&cbt_mutex);
	if (ret == 0)
		free_map(map, npages);
	return ret;
}

static void blk_cbt_page_merge(struct page *pg_from, struct page *pg_to)
{
	u32 *from = page_address(pg_from);
	u32 *to = page_address(pg_to);
	u32 *fin = to + PAGE_SIZE/sizeof(*to);

	while (to < fin) {
		*to |= *from;
		to++;
		from++;
	}
}

static int blk_cbt_snap_merge_back(struct request_queue *q, __u8 *uuid)
{
	struct cbt_info *cbt;
	blkcnt_t block_max;
	struct page **map;
	unsigned long i;
	int ret;

	mutex_lock(&cbt_mutex);
	cbt = q->cbt;

	ret = -ENOENT;
	if (!cbt)
		goto out;

	BUG_ON(!cbt->map);
	BUG_ON(!cbt->block_max);

	ret = -EINVAL;
	if (!uuid || memcmp(uuid, cbt->uuid, sizeof(cbt->uuid)))
		goto out;

	map = cbt->snp_map;
	block_max = cbt->snp_block_max;
	ret = -ENODEV;
	if (!map)
		goto out;
	ret = -ESTALE;
	if (block_max != cbt->block_max)
		goto out;

	for (i = 0; i < NR_PAGES(cbt->block_max); i++) {
		struct page *page_main = cbt->map[i];
		struct page *page_addon = map[i];

		BUG_ON(page_main == CBT_PAGE_MISSED);
		BUG_ON(page_addon == CBT_PAGE_MISSED);

		if (!page_addon)
			continue;

		if (!page_main) {
			ret = -ENOMEM;
			if (cbt_page_alloc(&cbt, i, 0))
				goto out;

			page_main = cbt->map[i];
			BUG_ON(page_main == NULL);
			BUG_ON(page_main == CBT_PAGE_MISSED);
		}

		spin_lock_page(page_main);
		blk_cbt_page_merge(page_addon, page_main);
		unlock_page(page_main);
	}

	cbt->snp_map = NULL;
	cbt->snp_block_max = 0;
	ret = 0;
out:
	mutex_unlock(&cbt_mutex);
	if (ret == 0)
		free_map(map, NR_PAGES(block_max));
	return ret;
}

void blk_cbt_update_size(struct block_device *bdev)
{
	struct request_queue *q;
	struct cbt_info *new, *cbt;
	unsigned long to_cpy, idx;
	unsigned bsz;
	loff_t new_sz = i_size_read(bdev->bd_inode);
	int in_use = 0;

	if (!bdev->bd_disk || !bdev_get_queue(bdev))
		return;

	q = bdev_get_queue(bdev);
	mutex_lock(&cbt_mutex);
	cbt = q->cbt;
	if (!cbt) {
		mutex_unlock(&cbt_mutex);
		return;
	}
	bsz = 1 << cbt->block_bits;
	if (DIV_ROUND_UP(new_sz, bsz) <= cbt->block_max)
		goto err_mtx;

	new = do_cbt_alloc(q, cbt->uuid, new_sz, bsz);
	if (IS_ERR(new)) {
		set_bit(CBT_ERROR, &cbt->flags);
		goto err_mtx;
	}
	to_cpy = NR_PAGES(cbt->block_max);
	set_bit(CBT_NOCACHE, &cbt->flags);
	cbt_flush_cache(cbt);
	spin_lock_irq(&cbt->lock);
	set_bit(CBT_DEAD, &cbt->flags);
	for (idx = 0; idx < to_cpy; idx++){
		new->map[idx] = cbt->map[idx];
		if (CBT_PAGE(new, idx))
			get_page(CBT_PAGE(new, idx));
	}
	rcu_assign_pointer(q->cbt, new);
	in_use = cbt->count;
	spin_unlock(&cbt->lock);
	if (!in_use)
		call_rcu(&cbt->rcu, &cbt_release_callback);
err_mtx:
	mutex_unlock(&cbt_mutex);


}

static int cbt_ioc_init(struct block_device *bdev, struct blk_user_cbt_info __user *ucbt_ioc)
{
	struct request_queue *q;
	struct blk_user_cbt_info ci;
	struct cbt_info *cbt;
	int ret = 0;

	if (copy_from_user(&ci, ucbt_ioc, sizeof(ci)))
		return -EFAULT;

	if (!is_power_of_2(ci.ci_blksize))
		return -EINVAL;

	q = bdev_get_queue(bdev);
	mutex_lock(&cbt_mutex);
	if (q->cbt) {
		ret = -EBUSY;
		goto err_mtx;
	}
	cbt = do_cbt_alloc(q, ci.ci_uuid, i_size_read(bdev->bd_inode), ci.ci_blksize);
	if (IS_ERR(cbt))
		ret = PTR_ERR(cbt);
	else
		rcu_assign_pointer(q->cbt, cbt);
err_mtx:
	mutex_unlock(&cbt_mutex);
	return ret;
}

static void cbt_release_callback(struct rcu_head *head)
{
	struct cbt_info *cbt;
	int nr_pages, i;

	cbt = container_of(head, struct cbt_info, rcu);
	nr_pages = NR_PAGES(cbt->block_max);
	for (i = 0; i < nr_pages; i++)
		if (CBT_PAGE(cbt, i))
			__free_page(CBT_PAGE(cbt, i));
	vfree(cbt->map);

	if (cbt->snp_map) {
		nr_pages = NR_PAGES(cbt->snp_block_max);
		free_map(cbt->snp_map, nr_pages);
	}

	free_percpu(cbt->cache);
	kfree(cbt);
}

void blk_cbt_release(struct request_queue *q)
{
	struct cbt_info *cbt;
	int in_use = 0;

	cbt = q->cbt;
	if (!cbt)
		return;
	spin_lock(&cbt->lock);
	set_bit(CBT_DEAD, &cbt->flags);
	rcu_assign_pointer(q->cbt, NULL);
	in_use = cbt->count;
	spin_unlock(&cbt->lock);
	if (!in_use)
		call_rcu(&cbt->rcu, &cbt_release_callback);
}

static int cbt_ioc_stop(struct block_device *bdev)
{
	struct request_queue *q;

	mutex_lock(&cbt_mutex);
	q = bdev_get_queue(bdev);
	if(!q->cbt) {
		mutex_unlock(&cbt_mutex);
		return -EINVAL;
	}
	blk_cbt_release(q);
	mutex_unlock(&cbt_mutex);
	return 0;
}

struct flush_ctx {
	struct cbt_info *cbt;
	unsigned long pages_missed;
	unsigned long idx_first;
};

static inline void __cbt_flush_cpu_cache(void *ptr)
{
	struct flush_ctx *ctx = (struct flush_ctx *)ptr;
	struct cbt_info *cbt = ctx->cbt;
	struct cbt_extent *ex = this_cpu_ptr(cbt->cache);

	if (ex->len) {
		int ret = __blk_cbt_set(cbt, ex->start, ex->len, 0, 1,
					&ctx->pages_missed,
					&ctx->idx_first);
		if (!ret) {
			ex->start += ex->len;
			ex->len = 0;
		}
	}
}

static void cbt_flush_cache(struct cbt_info *cbt)
{
	for (;;) {
		struct flush_ctx ctx;
		unsigned long i;
try_again:
		ctx.cbt = cbt;
		ctx.pages_missed = 0;
		ctx.idx_first = 0;

		on_each_cpu(__cbt_flush_cpu_cache, &ctx, 1);

		if (likely(!ctx.pages_missed))
			return;

		for (i = ctx.idx_first; i < NR_PAGES(cbt->block_max); i++) {
			int ret;

			if (cbt->map[i] != CBT_PAGE_MISSED)
				continue;

			ret = cbt_page_alloc(&cbt, i, 0);
			if (ret == -EAGAIN) /* new cbt */
				goto try_again;
			else if (ret) /* dead cbt or alloc_page failed */
				return;

			/* cbt_page_alloc succeeded ... */
			if (!--ctx.pages_missed)
				break;
		}
	}
}

static void cbt_find_next_extent(struct cbt_info *cbt, blkcnt_t block, struct cbt_extent *ex)
{
	unsigned long off, off2, idx;
	struct page *page;
	bool found = 0;

	ex->start = cbt->block_max;
	ex->len = 0;

	idx = block >> (PAGE_SHIFT + 3);
	while (block < cbt->block_max) {
		off = block & (BITS_PER_PAGE -1);
		page = CBT_PAGE(cbt, idx);
		if (!page) {
			if (found)
				break;
			goto next;
		}
		spin_lock_page(page);
		/* Find extent start */
		if (!found) {
			ex->start = find_next_bit(page_address(page), BITS_PER_PAGE, off);
			if (ex->start != BITS_PER_PAGE) {
				off = ex->start;
				ex->start += idx << (PAGE_SHIFT + 3);
				found = 1;
			} else {
				unlock_page(page);
				goto next;
			}
		}
		if (found) {
			off2 = find_next_zero_bit(page_address(page), BITS_PER_PAGE, off);
			ex->len += off2 - off;
			if (off2 != BITS_PER_PAGE) {
				unlock_page(page);
				break;
			}
		}
		unlock_page(page);
	next:
		idx++;
		block = idx << (PAGE_SHIFT + 3);
		continue;
	}
}

static int cbt_ioc_get(struct block_device *bdev, struct blk_user_cbt_info __user *ucbt_ioc)
{
	struct request_queue *q;
	struct blk_user_cbt_info ci;
	struct blk_user_cbt_extent __user *cur_u_ex;
	struct blk_user_cbt_extent        *cur_ex, *cur_ex_base;
	struct cbt_info *cbt;
	struct cbt_extent ex;
	blkcnt_t block , end;
	int ret = 0;

	if (copy_from_user(&ci, ucbt_ioc, sizeof(ci)))
		return -EFAULT;
	if (ci.ci_flags &  ~CI_FLAG_ONCE)
		return -EINVAL;
	if (ci.ci_extent_count > CBT_MAX_EXTENTS)
		return -EINVAL;

	cur_u_ex = (struct blk_user_cbt_extent __user*)
		((char *)ucbt_ioc + sizeof(struct blk_user_cbt_info));

	if (ci.ci_extent_count != 0 &&
	    !access_ok(cur_u_ex,
		       ci.ci_extent_count * sizeof(struct blk_user_cbt_extent))){
		return -EFAULT;
	}

	cur_ex_base = cur_ex = kzalloc(ci.ci_extent_count * sizeof(*cur_ex),
				       GFP_KERNEL);
	if (!cur_ex_base)
		return -ENOMEM;

	ret = -EINVAL;
	q = bdev_get_queue(bdev);
	mutex_lock(&cbt_mutex);
	cbt = q->cbt;
	if (!cbt ||
	    (ci.ci_start >> cbt->block_bits) > cbt->block_max)
		goto ioc_get_failed;

	ret = -EIO;
	if (test_bit(CBT_ERROR, &cbt->flags))
		goto ioc_get_failed;
	cbt_flush_cache(cbt);

	memcpy(&ci.ci_uuid, cbt->uuid, sizeof(cbt->uuid));
	ci.ci_blksize = 1UL << cbt->block_bits;
	block = ci.ci_start >> cbt->block_bits;
	end = (ci.ci_start + ci.ci_length) >> cbt->block_bits;
	if (end > cbt->block_max)
		end = cbt->block_max;

	ci.ci_mapped_extents = 0;
	while (ci.ci_mapped_extents < ci.ci_extent_count) {
		cbt_find_next_extent(cbt, block, &ex);
		if (!ex.len || ex.start > end)
			break;
		cur_ex->ce_physical = ex.start << cbt->block_bits;
		cur_ex->ce_length = ex.len << cbt->block_bits;

		if (ci.ci_flags & CI_FLAG_ONCE)
			__blk_cbt_set(cbt, ex.start, ex.len, 0, 0, NULL, NULL);
		cur_ex++;
		ci.ci_mapped_extents++;
		block = ex.start + ex.len;
	}
	mutex_unlock(&cbt_mutex);

	ret = 0;
	if (ci.ci_mapped_extents &&
	    copy_to_user(cur_u_ex, cur_ex_base,
			 sizeof(*cur_ex_base) * ci.ci_mapped_extents))
		ret = -EFAULT;
	if (!ret && copy_to_user(ucbt_ioc, &ci, sizeof(ci)))
		ret = -EFAULT;

	kfree(cur_ex_base);
	return ret;

ioc_get_failed:
	mutex_unlock(&cbt_mutex);
	kfree(cur_ex_base);
	return ret;
}

static int cbt_ioc_set(struct block_device *bdev, struct blk_user_cbt_info __user *ucbt_ioc, bool set)
{
	struct request_queue *q = bdev_get_queue(bdev);
	struct cbt_info *cbt;
	struct blk_user_cbt_info ci;
	struct blk_user_cbt_extent __user *cur_u_ex;
	struct blk_user_cbt_extent *cur_ex, *cur_ex_base, *end;
	int ret = 0;

	if (copy_from_user(&ci, ucbt_ioc, sizeof(ci)))
		return -EFAULT;
	if (ci.ci_extent_count > CBT_MAX_EXTENTS)
		return -EINVAL;
	if (ci.ci_extent_count < ci.ci_mapped_extents)
		return -EINVAL;

	cur_u_ex = (struct blk_user_cbt_extent __user*)
		((char *)ucbt_ioc + sizeof(struct blk_user_cbt_info));
	if (!access_ok(cur_u_ex,
		       ci.ci_mapped_extents * sizeof(struct blk_user_cbt_extent)))
		return -EFAULT;

	cur_ex_base = cur_ex = kzalloc(ci.ci_mapped_extents * sizeof(*cur_ex),
				       GFP_KERNEL);
	if (!cur_ex_base)
		return -ENOMEM;
	end = cur_ex_base + ci.ci_mapped_extents;

	if (copy_from_user(cur_ex_base, cur_u_ex,
			   sizeof(*cur_ex_base) * ci.ci_mapped_extents)) {
		kfree(cur_ex_base);
		return -EFAULT;
	}

	ret = -EINVAL;
	mutex_lock(&cbt_mutex);
	cbt = q->cbt;
	if (!cbt)
		goto ioc_set_failed;

	if (ci.ci_flags & CI_FLAG_NEW_UUID)
		memcpy(cbt->uuid, &ci.ci_uuid, sizeof(ci.ci_uuid));
	else if (memcmp(cbt->uuid, &ci.ci_uuid, sizeof(ci.ci_uuid)))
		goto ioc_set_failed;

	ret = -EIO;
	if (test_bit(CBT_ERROR, &cbt->flags))
		goto ioc_set_failed;

	/* Do not care about pcpu caches on set, only in case of clear */
	if (!set)
		cbt_flush_cache(cbt);

	ret = 0;
	while (cur_ex < end) {
		struct cbt_extent ex;

		ex.start  = cur_ex->ce_physical >> cbt->block_bits;
		ex.len  = DIV_ROUND_UP(cur_ex->ce_length, 1 << cbt->block_bits);
		if (ex.start > q->cbt->block_max ||
		    ex.start + ex.len > q->cbt->block_max ||
		    ex.len == 0) {
			ret = -EINVAL;
			break;
		}
		ret = __blk_cbt_set(cbt, ex.start, ex.len, 0, set, NULL, NULL);
		if (ret)
			break;
		cur_ex++;
	}
	mutex_unlock(&cbt_mutex);
	kfree(cur_ex_base);
	return ret;

ioc_set_failed:
	mutex_unlock(&cbt_mutex);
	kfree(cur_ex_base);
	return ret;
}

static int cbt_ioc_misc(struct block_device *bdev, void __user *arg)
{
	struct request_queue *q = bdev_get_queue(bdev);
	struct blk_user_cbt_misc_info cmi;

	if (copy_from_user(&cmi, arg, sizeof(cmi)))
		return -EFAULT;

	switch (cmi.action) {
	case CBT_SNAP_CREATE:
		return blk_cbt_snap_create(q, cmi.uuid, arg);
	case CBT_SNAP_DROP:
		return blk_cbt_snap_drop(q, cmi.uuid);
	case CBT_SNAP_MERGE_BACK:
		return blk_cbt_snap_merge_back(q, cmi.uuid);
	default:
		return -ENOTSUPP;
	}

	return 0;
}

int blk_cbt_ioctl(struct block_device *bdev, unsigned cmd, char __user *arg)
{
	struct blk_user_cbt_info __user *ucbt_ioc;

	ucbt_ioc = (struct blk_user_cbt_info __user *) arg;

	if (cmd == BLKCBTGET)
		return cbt_ioc_get(bdev, ucbt_ioc);

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	switch(cmd) {
	case BLKCBTSTART:
		return cbt_ioc_init(bdev, ucbt_ioc);
	case BLKCBTSTOP:
		return cbt_ioc_stop(bdev);
	case BLKCBTSET:
		return cbt_ioc_set(bdev, ucbt_ioc, 1);
	case BLKCBTCLR:
		return cbt_ioc_set(bdev, ucbt_ioc, 0);
	case BLKCBTMISC:
		return cbt_ioc_misc(bdev, arg);
	default:
		BUG();
	}
	return -ENOTTY;
}
