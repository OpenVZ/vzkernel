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
#include <asm/atomic.h>
#include <asm/uaccess.h>

#define CBT_MAX_EXTENTS	(UINT_MAX / sizeof(struct blk_user_cbt_extent))
#define NR_PAGES(bits) (((bits) + PAGE_SIZE*8 - 1) / (PAGE_SIZE*8))
#define BITS_PER_PAGE		(1UL << (PAGE_SHIFT + 3))

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
	if (unlikely(!cbt->count-- && test_bit(CBT_DEAD, &cbt->flags))) {
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
	cbt->map[idx] = page;
	page = NULL;
	spin_unlock_irq(&cbt->lock);

	return 0;
}

static int __blk_cbt_set(struct cbt_info  *cbt, blkcnt_t block,
			  blkcnt_t count, bool in_rcu, bool set)
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

		page = cbt->map[idx];
		if (page) {
			spin_lock_page(page);
			set_bits(page_address(page), off, len, set);
			unlock_page(page);
			count -= len;
			block += len;
			continue;
		} else {
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
	return 0;
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
	end = (start + len + (1 << cbt->block_bits) -1) >> cbt->block_bits;
	start >>= cbt->block_bits;
	len = end - start;
	if (unlikely(test_bit(CBT_NOCACHE, &cbt->flags))) {
		__blk_cbt_set(cbt, start, len, 1, 1);
		goto out_rcu;
	}
	ex = this_cpu_ptr(cbt->cache);
	if (ex->start + ex->len == start) {
		ex->len += len;
		goto out_rcu;
	}
	old = *ex;
	ex->start = start;
	ex->len = len;

	if (likely(old.len))
		__blk_cbt_set(cbt, old.start, old.len, 1, 1);
out_rcu:
	rcu_read_unlock();
}

inline void blk_cbt_bio_queue(struct request_queue *q, struct bio *bio)
{
	if (!q->cbt || bio_data_dir(bio) == READ || !bio->bi_size)
		return;

	blk_cbt_add(q, bio->bi_sector << 9, bio->bi_size);
}

static struct cbt_info* do_cbt_alloc(struct request_queue *q, __u8 *uuid,
				     loff_t size, loff_t blocksize)
{
	struct cbt_info *cbt;
	struct cbt_extent *ex;
	int i;


	cbt = kzalloc(sizeof(*cbt), GFP_KERNEL);
	if (!cbt)
		return ERR_PTR(-ENOMEM);

	cbt->block_bits = ilog2(blocksize);
	cbt->block_max  = (size + blocksize) >> cbt->block_bits;
	spin_lock_init(&cbt->lock);
	memcpy(cbt->uuid, uuid, sizeof(cbt->uuid));
	cbt->cache = alloc_percpu(struct cbt_extent);
	if (!cbt->cache)
		goto err_cbt;

	for_each_possible_cpu(i) {
		ex = per_cpu_ptr(cbt->cache, i);
		memset(ex, 0, sizeof (*ex));
	}

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
	if ((new_sz + bsz) >> cbt->block_bits <= cbt->block_max)
		goto err_mtx;

	new = do_cbt_alloc(q, cbt->uuid, new_sz, bsz);
	if (IS_ERR(new)) {
		set_bit(CBT_ERROR, &cbt->flags);
		goto err_mtx;
	}
	to_cpy = NR_PAGES(new->block_max);
	set_bit(CBT_NOCACHE, &cbt->flags);
	cbt_flush_cache(cbt);
	spin_lock_irq(&cbt->lock);
	set_bit(CBT_DEAD, &cbt->flags);
	for (idx = 0; idx < to_cpy; idx++){
		new->map[idx] = cbt->map[idx];
		if (new->map[idx])
			get_page(new->map[idx]);
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

	if (((ci.ci_blksize -1) & ci.ci_blksize))
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
		if (cbt->map[i])
			__free_page(cbt->map[i]);

	vfree(cbt->map);
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
	if (in_use)
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

static inline void __cbt_flush_cpu_cache(void *ptr)
{
	struct cbt_info *cbt = (struct cbt_info *) ptr;
	struct cbt_extent *ex = this_cpu_ptr(cbt->cache);

	if (ex->len) {
		__blk_cbt_set(cbt, ex->start, ex->len, 0, 1);
		ex->start += ex->len;
		ex->len = 0;
	}
}

static void cbt_flush_cache(struct cbt_info *cbt)
{
	on_each_cpu(__cbt_flush_cpu_cache, cbt, 1);
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
		page = cbt->map[idx];
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
	struct blk_user_cbt_extent u_ex;
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
	    !access_ok(VERIFY_WRITE, cur_u_ex,
		       ci.ci_extent_count * sizeof(struct blk_user_cbt_extent))){
		return -EFAULT;
	}
	q = bdev_get_queue(bdev);
	mutex_lock(&cbt_mutex);
	cbt = q->cbt;
	if (!cbt) {
		mutex_unlock(&cbt_mutex);
		return -EINVAL;
	}
	if ((ci.ci_start >> cbt->block_bits) > cbt->block_max) {
		mutex_unlock(&cbt_mutex);
		return -EINVAL;
	}
	if (test_bit(CBT_ERROR, &cbt->flags)) {
		mutex_unlock(&cbt_mutex);
		return -EIO;
	}
	cbt_flush_cache(cbt);

	memcpy(&ci.ci_uuid, cbt->uuid, sizeof(cbt->uuid));
	ci.ci_blksize = 1UL << cbt->block_bits;
	block = ci.ci_start >> cbt->block_bits;
	end = (ci.ci_start + ci.ci_length) >> cbt->block_bits;
	if (end > cbt->block_max)
		end = cbt->block_max;

	while (ci.ci_mapped_extents < ci.ci_extent_count) {
		cbt_find_next_extent(cbt, block, &ex);
		if (!ex.len || ex.start > end) {
			ret = 0;
			break;
		}
		u_ex.ce_physical = ex.start << cbt->block_bits;
		u_ex.ce_length = ex.len << cbt->block_bits;
		if (copy_to_user(cur_u_ex, &u_ex, sizeof(u_ex))) {
			ret = -EFAULT;
			break;
		}
		if (ci.ci_flags & CI_FLAG_ONCE)
			__blk_cbt_set(cbt, ex.start, ex.len, 0, 0);
		cur_u_ex++;
		ci.ci_mapped_extents++;
		block = ex.start + ex.len;
	}
	mutex_unlock(&cbt_mutex);
	if (!ret && copy_to_user(ucbt_ioc, &ci, sizeof(ci)))
		ret = -EFAULT;

	return ret;
}

static int cbt_ioc_set(struct block_device *bdev, struct blk_user_cbt_info __user *ucbt_ioc, bool set)
{
	struct request_queue *q = bdev_get_queue(bdev);
	struct cbt_info *cbt;
	struct blk_user_cbt_info ci;
	struct blk_user_cbt_extent __user u_ex, *cur_u_ex, *end;
	int ret = 0;

	if (copy_from_user(&ci, ucbt_ioc, sizeof(ci)))
		return -EFAULT;
	if (ci.ci_extent_count > CBT_MAX_EXTENTS)
		return -EINVAL;
	if (ci.ci_extent_count < ci.ci_mapped_extents)
		return -EINVAL;

	cur_u_ex = (struct blk_user_cbt_extent __user*)
		((char *)ucbt_ioc + sizeof(struct blk_user_cbt_info));
	end = cur_u_ex + ci.ci_mapped_extents;
	if (!access_ok(VERIFY_READ, cur_u_ex,
		       ci.ci_mapped_extents * sizeof(struct blk_user_cbt_extent)))
		return -EFAULT;

	mutex_lock(&cbt_mutex);
	cbt = q->cbt;
	if (!cbt) {
		mutex_unlock(&cbt_mutex);
		return -EINVAL;
	}
	if (ci.ci_flags & CI_FLAG_NEW_UUID)
		memcpy(cbt->uuid, &ci.ci_uuid, sizeof(ci.ci_uuid));
	else if (memcmp(cbt->uuid, &ci.ci_uuid, sizeof(ci.ci_uuid))) {
			mutex_unlock(&cbt_mutex);
			return -EINVAL;
	}
	if (test_bit(CBT_ERROR, &cbt->flags)) {
		mutex_unlock(&cbt_mutex);
		return -EIO;
	}

	/* Do not care about pcpu caches on set, only in case of clear */
	if (!set)
		cbt_flush_cache(cbt);

	while (cur_u_ex < end) {
		struct cbt_extent ex;

		if (copy_from_user(&u_ex, cur_u_ex, sizeof(u_ex))) {
			ret = -EFAULT;
			break;
		}
		ex.start  = u_ex.ce_physical >> cbt->block_bits;
		ex.len  = (u_ex.ce_length + (1 << cbt->block_bits) -1) >> cbt->block_bits;
		if (ex.start > q->cbt->block_max ||
		    ex.start + ex.len > q->cbt->block_max ||
		    ex.len == 0) {
			ret = -EINVAL;
			break;
		}
		ret = __blk_cbt_set(cbt, ex.start, ex.len, 0, set);
		if (ret)
			break;
		cur_u_ex++;
	}
	mutex_unlock(&cbt_mutex);
	return ret;
}

int blk_cbt_ioctl(struct block_device *bdev, unsigned cmd, char __user *arg)
{
	struct blk_user_cbt_info __user *ucbt_ioc = (struct blk_user_cbt_info __user *) arg;

	switch(cmd) {
	case BLKCBTSTART:
		if (!capable(CAP_SYS_ADMIN))
			return -EACCES;
		return cbt_ioc_init(bdev, ucbt_ioc);
	case BLKCBTSTOP:
		if (!capable(CAP_SYS_ADMIN))
			return -EACCES;

		return cbt_ioc_stop(bdev);
	case BLKCBTGET:
		return cbt_ioc_get(bdev, ucbt_ioc);
	case BLKCBTSET:
		if (!capable(CAP_SYS_ADMIN))
			return -EACCES;

		return cbt_ioc_set(bdev, ucbt_ioc, 1);
	case BLKCBTCLR:
		if (!capable(CAP_SYS_ADMIN))
			return -EACCES;

		return cbt_ioc_set(bdev, ucbt_ioc, 0);
	default:
		BUG();
	}
	return -ENOTTY;
}
