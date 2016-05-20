/*
 *	An async IO implementation for Linux
 *	Written by Benjamin LaHaise <bcrl@kvack.org>
 *
 *	Implements an efficient asynchronous io interface.
 *
 *	Copyright 2000, 2001, 2002 Red Hat, Inc.  All Rights Reserved.
 *
 *	See ../COPYING for licensing terms.
 */
#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/aio_abi.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/backing-dev.h>
#include <linux/uio.h>

#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mmu_context.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/aio.h>
#include <linux/ve.h>
#include <linux/highmem.h>
#include <linux/workqueue.h>
#include <linux/security.h>
#include <linux/eventfd.h>
#include <linux/blkdev.h>
#include <linux/compat.h>
#include <linux/migrate.h>
#include <linux/ramfs.h>
#include <linux/mount.h>

#include <asm/kmap_types.h>
#include <asm/uaccess.h>

#define AIO_RING_MAGIC			0xa10a10a1
#define AIO_RING_COMPAT_FEATURES	1
#define AIO_RING_INCOMPAT_FEATURES	0
struct aio_ring {
	unsigned	id;	/* kernel internal index number */
	unsigned	nr;	/* number of io_events */
	unsigned	head;	/* Written to by userland or under ring_lock
				 * mutex by aio_read_events_ring(). */
	unsigned	tail;

	unsigned	magic;
	unsigned	compat_features;
	unsigned	incompat_features;
	unsigned	header_length;	/* size of aio_ring */


	struct io_event		io_events[0];
}; /* 128 bytes + ring size */

#define AIO_RING_PAGES	8

struct kioctx {
	atomic_t		users;
	atomic_t		dead;

	/* This needs improving */
	unsigned long		user_id;
	struct hlist_node	list;

	/*
	 * This is what userspace passed to io_setup(), it's not used for
	 * anything but counting against the global max_reqs quota.
	 *
	 * The real limit is nr_events - 1, which will be larger (see
	 * aio_setup_ring())
	 */
	unsigned		max_reqs;

	/* Size of ringbuffer, in units of struct io_event */
	unsigned		nr_events;

	unsigned long		mmap_base;
	unsigned long		mmap_size;

	struct page		**ring_pages;
	long			nr_pages;

	struct rcu_head		rcu_head;
	struct work_struct	rcu_work;

	struct {
		atomic_t	reqs_active; /* tracks an io request from the
					      * time it's allocated until the
					      * time the corresponding io_event
					      * is consumed by userspace */
	} ____cacheline_aligned_in_smp;

	struct {
		spinlock_t	ctx_lock;
		struct list_head active_reqs;	/* used for cancellation */
	} ____cacheline_aligned_in_smp;

	struct {
		struct mutex	ring_lock;
		wait_queue_head_t wait;
	} ____cacheline_aligned_in_smp;

	/*
	 * signals when all in-flight requests are done
	 */
	struct completion *requests_done;

	struct {
		unsigned	tail;
		unsigned	completed_events;
		spinlock_t	completion_lock;
	} ____cacheline_aligned_in_smp;

	struct page		*internal_pages[AIO_RING_PAGES];
	struct file		*aio_ring_file;
	struct ve_struct	*ve;
};

static struct kmem_cache	*kiocb_cachep;
static struct kmem_cache	*kioctx_cachep;

static struct vfsmount *aio_mnt;

static const struct file_operations_extend aio_ring_fops;
static const struct address_space_operations aio_ctx_aops;

static void user_update_reqs_active(struct kioctx *ctx);
static void update_reqs_active(struct kioctx *ctx, unsigned head, unsigned tail);

/* Backing dev info for aio fs.
 * -no dirty page accounting or writeback happens
 */
static struct backing_dev_info aio_fs_backing_dev_info = {
	.name           = "aiofs",
	.state          = 0,
	.capabilities   = BDI_CAP_NO_ACCT_AND_WRITEBACK | BDI_CAP_MAP_COPY,
};

static struct file *aio_private_file(struct kioctx *ctx, loff_t nr_pages)
{
	struct qstr this = QSTR_INIT("[aio]", 5);
	struct file *file;
	struct path path;
	struct inode *inode = alloc_anon_inode(aio_mnt->mnt_sb);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	inode->i_mapping->a_ops = &aio_ctx_aops;
	inode->i_mapping->private_data = ctx;
	inode->i_mapping->backing_dev_info = &aio_fs_backing_dev_info;
	inode->i_size = PAGE_SIZE * nr_pages;

	path.dentry = d_alloc_pseudo(aio_mnt->mnt_sb, &this);
	if (!path.dentry) {
		iput(inode);
		return ERR_PTR(-ENOMEM);
	}
	path.mnt = mntget(aio_mnt);

	d_instantiate(path.dentry, inode);
	file = alloc_file(&path, FMODE_READ | FMODE_WRITE, &aio_ring_fops.kabi_fops);
	if (IS_ERR(file)) {
		path_put(&path);
		return file;
	}

	file->f_flags = O_RDWR;
	file->private_data = ctx;
	return file;
}

static struct dentry *aio_mount(struct file_system_type *fs_type,
				int flags, const char *dev_name, void *data)
{
	static const struct dentry_operations ops = {
		.d_dname	= simple_dname,
	};
	return mount_pseudo(fs_type, "aio:", NULL, &ops, 0xa10a10a1);
}

/* aio_setup
 *	Creates the slab caches used by the aio routines, panic on
 *	failure as this is done early during the boot sequence.
 */
static int __init aio_setup(void)
{
	static struct file_system_type aio_fs = {
		.name		= "aio",
		.mount		= aio_mount,
		.kill_sb	= kill_anon_super,
	};

	if (register_fo_extend(&aio_ring_fops) != 0)
		WARN(1, "Failed to register extended file operations.");

	aio_mnt = kern_mount(&aio_fs);
	if (IS_ERR(aio_mnt))
		panic("Failed to create aio fs mount.");

	if (bdi_init(&aio_fs_backing_dev_info))
		panic("Failed to init aio fs backing dev info.");

	kiocb_cachep = KMEM_CACHE(kiocb, SLAB_HWCACHE_ALIGN|SLAB_PANIC);
	kioctx_cachep = KMEM_CACHE(kioctx,SLAB_HWCACHE_ALIGN|SLAB_PANIC);

	pr_debug("sizeof(struct page) = %zu\n", sizeof(struct page));

	return 0;
}
__initcall(aio_setup);

static void put_aio_ring_file(struct kioctx *ctx)
{
	struct file *aio_ring_file = ctx->aio_ring_file;
	if (aio_ring_file) {
		truncate_setsize(aio_ring_file->f_inode, 0);

		/* Prevent further access to the kioctx from migratepages */
		spin_lock(&aio_ring_file->f_inode->i_mapping->private_lock);
		aio_ring_file->f_inode->i_mapping->private_data = NULL;
		ctx->aio_ring_file = NULL;
		spin_unlock(&aio_ring_file->f_inode->i_mapping->private_lock);

		fput(aio_ring_file);
	}
}

static void aio_free_ring(struct kioctx *ctx)
{
	int i;

	/* Disconnect the kiotx from the ring file.  This prevents future
	 * accesses to the kioctx from page migration.
	 */
	put_aio_ring_file(ctx);

	for (i = 0; i < ctx->nr_pages; i++) {
		struct page *page;
		pr_debug("pid(%d) [%d] page->count=%d\n", current->pid, i,
				page_count(ctx->ring_pages[i]));
		page = ctx->ring_pages[i];
		if (!page)
			continue;
		ctx->ring_pages[i] = NULL;
		put_page(page);
	}

	if (ctx->ring_pages && ctx->ring_pages != ctx->internal_pages)
		kfree(ctx->ring_pages);
}

static int aio_ring_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_flags |= VM_DONTEXPAND;
	vma->vm_ops = &generic_file_vm_ops;
	return 0;
}

static void aio_ring_remap(struct file *file, struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	struct kioctx *ctx;

	spin_lock(&mm->ioctx_lock);
	rcu_read_lock();
	hlist_for_each_entry_rcu(ctx, &mm->ioctx_list, list) {
		if (ctx->aio_ring_file == file) {
			struct aio_ring *ring = kmap_atomic(ctx->ring_pages[0]);
			ring->id = ctx->user_id = ctx->mmap_base = vma->vm_start;
			kunmap_atomic(ring);
			break;
		}
	}
	rcu_read_unlock();
	spin_unlock(&mm->ioctx_lock);
}

static const struct file_operations_extend aio_ring_fops = {
	.kabi_fops = {
		.mmap = aio_ring_mmap,
	},
	.mremap = aio_ring_remap,
};

#if IS_ENABLED(CONFIG_MIGRATION)
static int aio_migratepage(struct address_space *mapping, struct page *new,
			struct page *old, enum migrate_mode mode)
{
	struct kioctx *ctx;
	unsigned long flags;
	pgoff_t idx;
	int rc;

	/*
	 * We cannot support the _NO_COPY case here, because copy needs to
	 * happen under the ctx->completion_lock. That does not work with the
	 * migration workflow of MIGRATE_SYNC_NO_COPY.
	 */
	if (mode == MIGRATE_SYNC_NO_COPY)
		return -EINVAL;

	rc = 0;

	/* mapping->private_lock here protects against the kioctx teardown.  */
	spin_lock(&mapping->private_lock);
	ctx = mapping->private_data;
	if (!ctx) {
		rc = -EINVAL;
		goto out;
	}

	/* The ring_lock mutex.  The prevents aio_read_events() from writing
	 * to the ring's head, and prevents page migration from mucking in
	 * a partially initialized kiotx.
	 */
	if (!mutex_trylock(&ctx->ring_lock)) {
		rc = -EAGAIN;
		goto out;
	}

	idx = old->index;
	if (idx < (pgoff_t)ctx->nr_pages) {
		/* Make sure the old page hasn't already been changed */
		if (ctx->ring_pages[idx] != old)
			rc = -EAGAIN;
	} else
		rc = -EINVAL;

	if (rc != 0)
		goto out_unlock;

	/* Writeback must be complete */
	BUG_ON(PageWriteback(old));
	get_page(new);

	rc = migrate_page_move_mapping(mapping, new, old, NULL, mode, 1);
	if (rc != MIGRATEPAGE_SUCCESS) {
		put_page(new);
		goto out_unlock;
	}

	/* Take completion_lock to prevent other writes to the ring buffer
	 * while the old page is copied to the new.  This prevents new
	 * events from being lost.
	 */
	spin_lock_irqsave(&ctx->completion_lock, flags);
	migrate_page_copy(new, old);
	BUG_ON(ctx->ring_pages[idx] != old);
	ctx->ring_pages[idx] = new;
	spin_unlock_irqrestore(&ctx->completion_lock, flags);

	/* The old page is no longer accessible. */
	put_page(old);

out_unlock:
	mutex_unlock(&ctx->ring_lock);
out:
	spin_unlock(&mapping->private_lock);
	return rc;
}
#endif

static const struct address_space_operations aio_ctx_aops = {
	.set_page_dirty = __set_page_dirty_no_writeback,
#if IS_ENABLED(CONFIG_MIGRATION)
	.migratepage	= aio_migratepage,
#endif
};

static int aio_setup_ring(struct kioctx *ctx)
{
	struct aio_ring *ring;
	unsigned nr_events = ctx->max_reqs;
	struct mm_struct *mm = current->mm;
	unsigned long size, unused;
	int nr_pages;
	int i;
	struct file *file;

	/* Compensate for the ring buffer's head/tail overlap entry */
	nr_events += 2;	/* 1 is required, 2 for good luck */

	size = sizeof(struct aio_ring);
	size += sizeof(struct io_event) * nr_events;

	nr_pages = PFN_UP(size);
	if (nr_pages < 0)
		return -EINVAL;

	file = aio_private_file(ctx, nr_pages);
	if (IS_ERR(file)) {
		ctx->aio_ring_file = NULL;
		return -ENOMEM;
	}

	ctx->aio_ring_file = file;
	nr_events = (PAGE_SIZE * nr_pages - sizeof(struct aio_ring))
			/ sizeof(struct io_event);

	ctx->ring_pages = ctx->internal_pages;
	if (nr_pages > AIO_RING_PAGES) {
		ctx->ring_pages = kcalloc(nr_pages, sizeof(struct page *),
					  GFP_KERNEL);
		if (!ctx->ring_pages) {
			put_aio_ring_file(ctx);
			return -ENOMEM;
		}
	}

	for (i = 0; i < nr_pages; i++) {
		struct page *page;
		page = find_or_create_page(file->f_inode->i_mapping,
					   i, GFP_HIGHUSER | __GFP_ZERO);
		if (!page)
			break;
		pr_debug("pid(%d) page[%d]->count=%d\n",
			 current->pid, i, page_count(page));
		SetPageUptodate(page);
		unlock_page(page);

		ctx->ring_pages[i] = page;
	}
	ctx->nr_pages = i;

	if (unlikely(i != nr_pages)) {
		aio_free_ring(ctx);
		return -ENOMEM;
	}

	ctx->mmap_size = nr_pages * PAGE_SIZE;
	pr_debug("attempting mmap of %lu bytes\n", ctx->mmap_size);

	down_write(&mm->mmap_sem);
	ctx->mmap_base = do_mmap_pgoff(ctx->aio_ring_file, 0, ctx->mmap_size,
				       PROT_READ | PROT_WRITE,
				       MAP_SHARED, 0, &unused, NULL);
	up_write(&mm->mmap_sem);
	if (IS_ERR((void *)ctx->mmap_base)) {
		ctx->mmap_size = 0;
		aio_free_ring(ctx);
		return -ENOMEM;
	}

	pr_debug("mmap address: 0x%08lx\n", ctx->mmap_base);

	ctx->user_id = ctx->mmap_base;
	ctx->nr_events = nr_events; /* trusted copy */

	ring = kmap_atomic(ctx->ring_pages[0]);
	ring->nr = nr_events;	/* user copy */
	ring->id = ctx->user_id;
	ring->head = ring->tail = 0;
	ring->magic = AIO_RING_MAGIC;
	ring->compat_features = AIO_RING_COMPAT_FEATURES;
	ring->incompat_features = AIO_RING_INCOMPAT_FEATURES;
	ring->header_length = sizeof(struct aio_ring);
	kunmap_atomic(ring);
	flush_dcache_page(ctx->ring_pages[0]);

	return 0;
}

#define AIO_EVENTS_PER_PAGE	(PAGE_SIZE / sizeof(struct io_event))
#define AIO_EVENTS_FIRST_PAGE	((PAGE_SIZE - sizeof(struct aio_ring)) / sizeof(struct io_event))
#define AIO_EVENTS_OFFSET	(AIO_EVENTS_PER_PAGE - AIO_EVENTS_FIRST_PAGE)

void kiocb_set_cancel_fn(struct kiocb *req, kiocb_cancel_fn *cancel)
{
	struct kioctx *ctx = req->ki_ctx;
	unsigned long flags;

	spin_lock_irqsave(&ctx->ctx_lock, flags);

	if (!req->ki_list.next)
		list_add(&req->ki_list, &ctx->active_reqs);

	req->ki_cancel = cancel;

	spin_unlock_irqrestore(&ctx->ctx_lock, flags);
}
EXPORT_SYMBOL(kiocb_set_cancel_fn);

static int kiocb_cancel(struct kioctx *ctx, struct kiocb *kiocb,
			struct io_event *res)
{
	kiocb_cancel_fn *old, *cancel;
	int ret = -EINVAL;

	/*
	 * Don't want to set kiocb->ki_cancel = KIOCB_CANCELLED unless it
	 * actually has a cancel function, hence the cmpxchg()
	 */

	cancel = ACCESS_ONCE(kiocb->ki_cancel);
	do {
		if (!cancel || cancel == KIOCB_CANCELLED)
			return ret;

		old = cancel;
		cancel = cmpxchg(&kiocb->ki_cancel, old, KIOCB_CANCELLED);
	} while (cancel != old);

	atomic_inc(&kiocb->ki_users);
	spin_unlock_irq(&ctx->ctx_lock);

	memset(res, 0, sizeof(*res));
	res->obj = (u64)(unsigned long)kiocb->ki_obj.user;
	res->data = kiocb->ki_user_data;
	ret = cancel(kiocb, res);

	spin_lock_irq(&ctx->ctx_lock);

	return ret;
}

static void free_ioctx_rcu(struct rcu_head *head)
{
	struct kioctx *ctx = container_of(head, struct kioctx, rcu_head);
	struct ve_struct *ve = ctx->ve;

	put_ve(ve);
	kmem_cache_free(kioctx_cachep, ctx);
}

/*
 * When this function runs, the kioctx has been removed from the "hash table"
 * and ctx->users has dropped to 0, so we know no more kiocbs can be submitted -
 * now it's safe to cancel any that need to be.
 */
static void free_ioctx(struct kioctx *ctx)
{
	struct aio_ring *ring;
	struct io_event res;
	struct kiocb *req;
	unsigned head, avail;

	spin_lock_irq(&ctx->ctx_lock);

	while (!list_empty(&ctx->active_reqs)) {
		req = list_first_entry(&ctx->active_reqs,
				       struct kiocb, ki_list);

		list_del_init(&req->ki_list);
		kiocb_cancel(ctx, req, &res);
	}

	spin_unlock_irq(&ctx->ctx_lock);

	ring = kmap_atomic(ctx->ring_pages[0]);
	head = ring->head;
	kunmap_atomic(ring);

	while (atomic_read(&ctx->reqs_active) > 0) {
		user_update_reqs_active(ctx);
		avail = (head <= ctx->tail ? ctx->tail : ctx->nr_events) - head;
		head += avail;
		head %= ctx->nr_events;
		atomic_sub(avail, &ctx->reqs_active);

		wait_event(ctx->wait,
				head != ctx->tail ||
				atomic_read(&ctx->reqs_active) <= 0);
	}

	WARN_ON(atomic_read(&ctx->reqs_active) < 0);

	aio_free_ring(ctx);

	/* At this point we know that there are no any in-flight requests */
	if (ctx->requests_done)
		complete(ctx->requests_done);

	pr_debug("freeing %p\n", ctx);

	/*
	 * Here the call_rcu() is between the wait_event() for reqs_active to
	 * hit 0, and freeing the ioctx.
	 *
	 * aio_complete() decrements reqs_active, but it has to touch the ioctx
	 * after to issue a wakeup so we use rcu.
	 */
	call_rcu(&ctx->rcu_head, free_ioctx_rcu);
}

static void put_ioctx(struct kioctx *ctx)
{
	if (unlikely(atomic_dec_and_test(&ctx->users)))
		free_ioctx(ctx);
}

/* ioctx_alloc
 *	Allocates and initializes an ioctx.  Returns an ERR_PTR if it failed.
 */
static struct kioctx *ioctx_alloc(unsigned nr_events)
{
	struct mm_struct *mm = current->mm;
	struct kioctx *ctx;
	struct ve_struct *ve = get_exec_env();
	int err = -ENOMEM;

	/* Kernel since e1bdd5f27a5b do this, and criu is tuned on that */
	nr_events *= 2;

	/* Prevent overflows */
	if ((nr_events > (0x10000000U / sizeof(struct io_event))) ||
	    (nr_events > (0x10000000U / sizeof(struct kiocb)))) {
		pr_debug("ENOMEM: nr_events too high\n");
		return ERR_PTR(-EINVAL);
	}

	if (!nr_events || (unsigned long)nr_events > ve->aio_max_nr)
		return ERR_PTR(-EAGAIN);

	ctx = kmem_cache_zalloc(kioctx_cachep, GFP_KERNEL);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->max_reqs = nr_events;
	ctx->ve = get_ve(ve);

	spin_lock_init(&ctx->ctx_lock);
	spin_lock_init(&ctx->completion_lock);
	mutex_init(&ctx->ring_lock);
	/* Protect against page migration throughout kioctx setup by keeping
	 * the ring_lock mutex held until setup is complete. */
	mutex_lock(&ctx->ring_lock);

	init_waitqueue_head(&ctx->wait);

	INIT_LIST_HEAD(&ctx->active_reqs);

	atomic_set(&ctx->users, 2);
	atomic_set(&ctx->dead, 0);

	err = aio_setup_ring(ctx);
	if (err < 0)
		goto out_freectx;

	/* limit the number of system wide aios */
	spin_lock(&ve->aio_nr_lock);
	if (ve->aio_nr + ctx->nr_events > ve->aio_max_nr ||
	    ve->aio_nr + ctx->nr_events < ve->aio_nr) {
		spin_unlock(&ve->aio_nr_lock);
		goto out_cleanup;
	}
	ve->aio_nr += ctx->nr_events;
	spin_unlock(&ve->aio_nr_lock);

	/* now link into global list. */
	spin_lock(&mm->ioctx_lock);
	hlist_add_head_rcu(&ctx->list, &mm->ioctx_list);
	spin_unlock(&mm->ioctx_lock);

	/* Release the ring_lock mutex now that all setup is complete. */
	mutex_unlock(&ctx->ring_lock);

	pr_debug("allocated ioctx %p[%ld]: mm=%p mask=0x%x\n",
		 ctx, ctx->user_id, mm, ctx->nr_events);
	return ctx;

out_cleanup:
	err = -EAGAIN;
	atomic_set(&ctx->dead, 1);
	if (ctx->mmap_size)
		vm_munmap(ctx->mmap_base, ctx->mmap_size);
	aio_free_ring(ctx);
out_freectx:
	put_ve(ctx->ve);
	mutex_unlock(&ctx->ring_lock);
	put_aio_ring_file(ctx);
	kmem_cache_free(kioctx_cachep, ctx);
	pr_debug("error allocating ioctx %d\n", err);
	return ERR_PTR(err);
}

static void kill_ioctx_work(struct work_struct *work)
{
	struct kioctx *ctx = container_of(work, struct kioctx, rcu_work);

	wake_up_all(&ctx->wait);
	put_ioctx(ctx);
}

static void kill_ioctx_rcu(struct rcu_head *head)
{
	struct kioctx *ctx = container_of(head, struct kioctx, rcu_head);

	INIT_WORK(&ctx->rcu_work, kill_ioctx_work);
	schedule_work(&ctx->rcu_work);
}

/* kill_ioctx
 *	Cancels all outstanding aio requests on an aio context.  Used
 *	when the processes owning a context have all exited to encourage
 *	the rapid destruction of the kioctx.
 */
static int kill_ioctx(struct mm_struct *mm, struct kioctx *ctx,
		struct completion *requests_done)
{
	if (!atomic_xchg(&ctx->dead, 1)) {
		struct ve_struct *ve = ctx->ve;

		spin_lock(&mm->ioctx_lock);
		hlist_del_rcu(&ctx->list);
		spin_unlock(&mm->ioctx_lock);

		/*
		 * It'd be more correct to do this in free_ioctx(), after all
		 * the outstanding kiocbs have finished - but by then io_destroy
		 * has already returned, so io_setup() could potentially return
		 * -EAGAIN with no ioctxs actually in use (as far as userspace
		 *  could tell).
		 */
		spin_lock(&ve->aio_nr_lock);
		BUG_ON(ve->aio_nr - ctx->nr_events > ve->aio_nr);
		ve->aio_nr -= ctx->nr_events;
		spin_unlock(&ve->aio_nr_lock);

		if (ctx->mmap_size)
			vm_munmap(ctx->mmap_base, ctx->mmap_size);

		ctx->requests_done = requests_done;

		/* Between hlist_del_rcu() and dropping the initial ref */
		call_rcu(&ctx->rcu_head, kill_ioctx_rcu);
		return 0;
	}

	return -EINVAL;
}

/* wait_on_sync_kiocb:
 *	Waits on the given sync kiocb to complete.
 */
ssize_t wait_on_sync_kiocb(struct kiocb *iocb)
{
	while (atomic_read(&iocb->ki_users)) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (!atomic_read(&iocb->ki_users))
			break;
		io_schedule();
	}
	__set_current_state(TASK_RUNNING);
	return iocb->ki_user_data;
}
EXPORT_SYMBOL(wait_on_sync_kiocb);

/*
 * exit_aio: called when the last user of mm goes away.  At this point, there is
 * no way for any new requests to be submited or any of the io_* syscalls to be
 * called on the context.
 *
 * There may be outstanding kiocbs, but free_ioctx() will explicitly wait on
 * them.
 */
void exit_aio(struct mm_struct *mm)
{
	struct kioctx *ctx;
	struct hlist_node *n;
	struct completion requests_done =
		COMPLETION_INITIALIZER_ONSTACK(requests_done);

	hlist_for_each_entry_safe(ctx, n, &mm->ioctx_list, list) {
		if (1 != atomic_read(&ctx->users))
			printk(KERN_DEBUG
				"exit_aio:ioctx still alive: %d %d %d\n",
				atomic_read(&ctx->users),
				atomic_read(&ctx->dead),
				atomic_read(&ctx->reqs_active));
		/*
		 * We don't need to bother with munmap() here -
		 * exit_mmap(mm) is coming and it'll unmap everything.
		 * Since aio_free_ring() uses non-zero ->mmap_size
		 * as indicator that it needs to unmap the area,
		 * just set it to 0; aio_free_ring() is the only
		 * place that uses ->mmap_size, so it's safe.
		 */
		ctx->mmap_size = 0;
		kill_ioctx(mm, ctx, &requests_done);

		/* Wait until all IO for the context are done. */
		wait_for_completion(&requests_done);
	}
}

/* update_reqs_active
 *     Updates the reqs_active counter used for tracking the number of
 *     outstanding requests and its complement, the number of free slots
 *     in the completion ring.  This can be called from aio_complete()
 *     (to optimistically updates reqs_active) or from aio_get_req()
 *     (the we're out of events case).  It must be called holding
 *     ctx->completion_lock.
 */
static void update_reqs_active(struct kioctx *ctx, unsigned head, unsigned tail)
{
	unsigned events_in_ring, completed;

	/* Clamp head since userland can write to it. */
	head %= ctx->nr_events;
	if (head <= tail)
		events_in_ring = tail - head;
	else
		events_in_ring = ctx->nr_events - (head - tail);

	completed = ctx->completed_events;
	if (events_in_ring < completed)
		completed -= events_in_ring;
	else
		completed = 0;

	if (!completed)
		return;

	ctx->completed_events -= completed;
	atomic_sub(completed, &ctx->reqs_active);
}

static void user_update_reqs_active(struct kioctx *ctx)
{
	spin_lock_irq(&ctx->completion_lock);
	if (ctx->completed_events) {
		struct aio_ring *ring;
		unsigned head;

		/* Access of ring->head may race with aio_read_events_ring()
		 * here, but that's okay since whether we read the old version
		 * or the new version, and either will be valid.  The important
		 * part is that head cannot pass tail since we prevent
		 * aio_complete() from updating tail by holding
		 * ctx->completion_lock.  Even if head is invalid, the check
		 * against ctx->completed_events below will make sure we do the
		 * safe/right thing.
		 */
		ring = kmap_atomic(ctx->ring_pages[0]);
		head = ring->head;
		kunmap_atomic(ring);

		update_reqs_active(ctx, head, ctx->tail);
	}

	spin_unlock_irq(&ctx->completion_lock);
}


/* aio_get_req
 *	Allocate a slot for an aio request.  Increments the ki_users count
 * of the kioctx so that the kioctx stays around until all requests are
 * complete.  Returns NULL if no requests are free.
 *
 * Returns with kiocb->ki_users set to 2.  The io submit code path holds
 * an extra reference while submitting the i/o.
 * This prevents races between the aio code path referencing the
 * req (after submitting it) and aio_complete() freeing the req.
 */
static inline struct kiocb *aio_get_req(struct kioctx *ctx)
{
	struct kiocb *req;

	if (atomic_read(&ctx->reqs_active) >= ctx->nr_events - 1) {
		user_update_reqs_active(ctx);
		if (atomic_read(&ctx->reqs_active) >= ctx->nr_events - 1)
			return NULL;
	}

	if (atomic_inc_return(&ctx->reqs_active) > ctx->nr_events - 1)
		goto out_put;

	req = kmem_cache_alloc(kiocb_cachep, GFP_KERNEL|__GFP_ZERO);
	if (unlikely(!req))
		goto out_put;

	atomic_set(&req->ki_users, 2);
	req->ki_ctx = ctx;

	return req;
out_put:
	atomic_dec(&ctx->reqs_active);
	return NULL;
}

static void kiocb_free(struct kiocb *req)
{
	if (req->ki_filp)
		fput(req->ki_filp);
	if (req->ki_eventfd != NULL)
		eventfd_ctx_put(req->ki_eventfd);
	if (req->ki_dtor)
		req->ki_dtor(req);
	if (req->ki_iovec != &req->ki_inline_vec)
		kfree(req->ki_iovec);
	kmem_cache_free(kiocb_cachep, req);
}

void aio_put_req(struct kiocb *req)
{
	if (atomic_dec_and_test(&req->ki_users))
		kiocb_free(req);
}
EXPORT_SYMBOL(aio_put_req);

static struct kioctx *lookup_ioctx(unsigned long ctx_id)
{
	struct mm_struct *mm = current->mm;
	struct kioctx *ctx, *ret = NULL;

	rcu_read_lock();

	hlist_for_each_entry_rcu(ctx, &mm->ioctx_list, list) {
		if (ctx->user_id == ctx_id) {
			atomic_inc(&ctx->users);
			ret = ctx;
			break;
		}
	}

	rcu_read_unlock();
	return ret;
}

/* aio_complete
 *	Called when the io request on the given iocb is complete.
 */
void aio_complete(struct kiocb *iocb, long res, long res2)
{
	struct kioctx	*ctx = iocb->ki_ctx;
	struct aio_ring	*ring;
	struct io_event	*ev_page, *event;
	unsigned tail, pos, head;
	unsigned long	flags;

	/*
	 * Special case handling for sync iocbs:
	 *  - events go directly into the iocb for fast handling
	 *  - the sync task with the iocb in its stack holds the single iocb
	 *    ref, no other paths have a way to get another ref
	 *  - the sync task helpfully left a reference to itself in the iocb
	 */
	if (is_sync_kiocb(iocb)) {
		BUG_ON(atomic_read(&iocb->ki_users) != 1);
		iocb->ki_user_data = res;
		atomic_set(&iocb->ki_users, 0);
		wake_up_process(iocb->ki_obj.tsk);
		return;
	} else if (is_kernel_kiocb(iocb)) {
		iocb->ki_obj.complete(iocb->ki_user_data, res);
		aio_kernel_free(iocb);
		return;
	}

	/*
	 * Take rcu_read_lock() in case the kioctx is being destroyed, as we
	 * need to issue a wakeup after decrementing reqs_active.
	 */
	rcu_read_lock();

	if (iocb->ki_list.next) {
		unsigned long flags;

		spin_lock_irqsave(&ctx->ctx_lock, flags);
		list_del(&iocb->ki_list);
		spin_unlock_irqrestore(&ctx->ctx_lock, flags);
	}

	/*
	 * cancelled requests don't get events, userland was given one
	 * when the event got cancelled.
	 */
	if (unlikely(xchg(&iocb->ki_cancel,
			  KIOCB_CANCELLED) == KIOCB_CANCELLED)) {
		atomic_dec(&ctx->reqs_active);
		/* Still need the wake_up in case free_ioctx is waiting */
		goto put_rq;
	}

	/*
	 * Add a completion event to the ring buffer. Must be done holding
	 * ctx->ctx_lock to prevent other code from messing with the tail
	 * pointer since we might be called from irq context.
	 */
	spin_lock_irqsave(&ctx->completion_lock, flags);

	tail = ctx->tail;
	pos = tail + AIO_EVENTS_OFFSET;

	if (++tail >= ctx->nr_events)
		tail = 0;

	ev_page = kmap_atomic(ctx->ring_pages[pos / AIO_EVENTS_PER_PAGE]);
	event = ev_page + pos % AIO_EVENTS_PER_PAGE;

	event->obj = (u64)(unsigned long)iocb->ki_obj.user;
	event->data = iocb->ki_user_data;
	event->res = res;
	event->res2 = res2;

	kunmap_atomic(ev_page);
	flush_dcache_page(ctx->ring_pages[pos / AIO_EVENTS_PER_PAGE]);

	pr_debug("%p[%u]: %p: %p %Lx %lx %lx\n",
		 ctx, tail, iocb, iocb->ki_obj.user, iocb->ki_user_data,
		 res, res2);

	/* after flagging the request as done, we
	 * must never even look at it again
	 */
	smp_wmb();	/* make event visible before updating tail */

	ctx->tail = tail;

	ring = kmap_atomic(ctx->ring_pages[0]);
	head = ring->head;
	ring->tail = tail;
	kunmap_atomic(ring);
	flush_dcache_page(ctx->ring_pages[0]);

	ctx->completed_events++;
	/*
	 * It doesn't make sense to call update_reqs_active for this
	 * particular completion, b/c userspace hasn't had a chance
	 * to reap it yet.  So only call update_reqs_active if some
	 * other completion came in earlier.
	 */
	if (ctx->completed_events > 1)
		update_reqs_active(ctx, head, tail);
	spin_unlock_irqrestore(&ctx->completion_lock, flags);

	pr_debug("added to ring %p at [%u]\n", iocb, tail);

	/*
	 * Check if the user asked us to deliver the result through an
	 * eventfd. The eventfd_signal() function is safe to be called
	 * from IRQ context.
	 */
	if (iocb->ki_eventfd != NULL)
		eventfd_signal(iocb->ki_eventfd, 1);

put_rq:
	/* everything turned out well, dispose of the aiocb. */
	aio_put_req(iocb);

	/*
	 * We have to order our ring_info tail store above and test
	 * of the wait list below outside the wait lock.  This is
	 * like in wake_up_bit() where clearing a bit has to be
	 * ordered with the unlocked test.
	 */
	smp_mb();

	if (waitqueue_active(&ctx->wait))
		wake_up(&ctx->wait);

	rcu_read_unlock();
}
EXPORT_SYMBOL(aio_complete);

/* aio_read_events
 *	Pull an event off of the ioctx's event ring.  Returns the number of
 *	events fetched
 */
static long aio_read_events_ring(struct kioctx *ctx,
				 struct io_event __user *event, long nr)
{
	struct aio_ring *ring;
	unsigned head, tail, pos;
	long ret = 0;
	int copy_ret;

	mutex_lock(&ctx->ring_lock);

	/* Access to ->ring_pages here is protected by ctx->ring_lock. */
	ring = kmap_atomic(ctx->ring_pages[0]);
	head = ring->head;
	tail = ring->tail;
	kunmap_atomic(ring);

	/*
	 * Ensure that once we've read the current tail pointer, that
	 * we also see the events that were stored up to the tail.
	 */
	smp_rmb();

	pr_debug("h%u t%u m%u\n", head, tail, ctx->nr_events);

	if (head == tail)
		goto out;

	head %= ctx->nr_events;
	tail %= ctx->nr_events;

	while (ret < nr) {
		long avail;
		struct io_event *ev;
		struct page *page;

		avail = (head <= tail ? tail : ctx->nr_events) - head;
		if (head == tail)
			break;

		avail = min(avail, nr - ret);
		avail = min_t(long, avail, AIO_EVENTS_PER_PAGE -
			    ((head + AIO_EVENTS_OFFSET) % AIO_EVENTS_PER_PAGE));

		pos = head + AIO_EVENTS_OFFSET;
		page = ctx->ring_pages[pos / AIO_EVENTS_PER_PAGE];
		pos %= AIO_EVENTS_PER_PAGE;

		ev = kmap(page);
		copy_ret = copy_to_user(event + ret, ev + pos,
					sizeof(*ev) * avail);
		kunmap(page);

		if (unlikely(copy_ret)) {
			ret = -EFAULT;
			goto out;
		}

		ret += avail;
		head += avail;
		head %= ctx->nr_events;
	}

	ring = kmap_atomic(ctx->ring_pages[0]);
	ring->head = head;
	kunmap_atomic(ring);
	flush_dcache_page(ctx->ring_pages[0]);

	pr_debug("%li  h%u t%u\n", ret, head, tail);

out:
	mutex_unlock(&ctx->ring_lock);

	return ret;
}

static bool aio_read_events(struct kioctx *ctx, long min_nr, long nr,
			    struct io_event __user *event, long *i)
{
	long ret = aio_read_events_ring(ctx, event + *i, nr - *i);

	if (ret > 0)
		*i += ret;

	if (unlikely(atomic_read(&ctx->dead)))
		ret = -EINVAL;

	if (!*i)
		*i = ret;

	return ret < 0 || *i >= min_nr;
}

static long read_events(struct kioctx *ctx, long min_nr, long nr,
			struct io_event __user *event,
			struct timespec __user *timeout)
{
	ktime_t until = { .tv64 = KTIME_MAX };
	long ret = 0;

	if (timeout) {
		struct timespec	ts;

		if (unlikely(copy_from_user(&ts, timeout, sizeof(ts))))
			return -EFAULT;

		until = timespec_to_ktime(ts);
	}

	/*
	 * Note that aio_read_events() is being called as the conditional - i.e.
	 * we're calling it after prepare_to_wait() has set task state to
	 * TASK_INTERRUPTIBLE.
	 *
	 * But aio_read_events() can block, and if it blocks it's going to flip
	 * the task state back to TASK_RUNNING.
	 *
	 * This should be ok, provided it doesn't flip the state back to
	 * TASK_RUNNING and return 0 too much - that causes us to spin. That
	 * will only happen if the mutex_lock() call blocks, and we then find
	 * the ringbuffer empty. So in practice we should be ok, but it's
	 * something to be aware of when touching this code.
	 */
	if (until.tv64 == 0)
		aio_read_events(ctx, min_nr, nr, event, &ret);
	else
		wait_event_interruptible_hrtimeout(ctx->wait,
				aio_read_events(ctx, min_nr, nr, event, &ret),
				until);

	if (!ret && signal_pending(current))
		ret = -EINTR;

	return ret;
}

/* sys_io_setup:
 *	Create an aio_context capable of receiving at least nr_events.
 *	ctxp must not point to an aio_context that already exists, and
 *	must be initialized to 0 prior to the call.  On successful
 *	creation of the aio_context, *ctxp is filled in with the resulting 
 *	handle.  May fail with -EINVAL if *ctxp is not initialized,
 *	if the specified nr_events exceeds internal limits.  May fail 
 *	with -EAGAIN if the specified nr_events exceeds the user's limit 
 *	of available events.  May fail with -ENOMEM if insufficient kernel
 *	resources are available.  May fail with -EFAULT if an invalid
 *	pointer is passed for ctxp.  Will fail with -ENOSYS if not
 *	implemented.
 */
SYSCALL_DEFINE2(io_setup, unsigned, nr_events, aio_context_t __user *, ctxp)
{
	struct kioctx *ioctx = NULL;
	unsigned long ctx;
	long ret;

	ret = get_user(ctx, ctxp);
	if (unlikely(ret))
		goto out;

	ret = -EINVAL;
	if (unlikely(ctx || nr_events == 0)) {
		pr_debug("EINVAL: io_setup: ctx %lu nr_events %u\n",
		         ctx, nr_events);
		goto out;
	}

	ioctx = ioctx_alloc(nr_events);
	ret = PTR_ERR(ioctx);
	if (!IS_ERR(ioctx)) {
		ret = put_user(ioctx->user_id, ctxp);
		if (ret)
			kill_ioctx(current->mm, ioctx, NULL);
		put_ioctx(ioctx);
	}

out:
	return ret;
}

/* sys_io_destroy:
 *	Destroy the aio_context specified.  May cancel any outstanding 
 *	AIOs and block on completion.  Will fail with -ENOSYS if not
 *	implemented.  May fail with -EINVAL if the context pointed to
 *	is invalid.
 */
SYSCALL_DEFINE1(io_destroy, aio_context_t, ctx)
{
	struct kioctx *ioctx = lookup_ioctx(ctx);
	if (likely(NULL != ioctx)) {
		struct completion requests_done =
			COMPLETION_INITIALIZER_ONSTACK(requests_done);
		int ret;

		/* Pass requests_done to kill_ioctx() where it can be set
		 * in a thread-safe way. If we try to set it here then we have
		 * a race condition if two io_destroy() called simultaneously.
		 */
		ret = kill_ioctx(current->mm, ioctx, &requests_done);
		put_ioctx(ioctx);

		/* Wait until all IO for the context are done. Otherwise kernel
		 * keep using user-space buffers even if user thinks the context
		 * is destroyed.
		 */
		if (!ret)
			wait_for_completion(&requests_done);

		return ret;
	}
	pr_debug("EINVAL: io_destroy: invalid context id\n");
	return -EINVAL;
}

static void aio_advance_iovec(struct kiocb *iocb, ssize_t ret)
{
	struct iovec *iov = &iocb->ki_iovec[iocb->ki_cur_seg];

	BUG_ON(ret <= 0);

	while (iocb->ki_cur_seg < iocb->ki_nr_segs && ret > 0) {
		ssize_t this = min((ssize_t)iov->iov_len, ret);
		iov->iov_base += this;
		iov->iov_len -= this;
		iocb->ki_left -= this;
		ret -= this;
		if (iov->iov_len == 0) {
			iocb->ki_cur_seg++;
			iov++;
		}
	}

	/* the caller should not have done more io than what fit in
	 * the remaining iovecs */
	BUG_ON(ret > 0 && iocb->ki_left == 0);
}

typedef ssize_t (aio_rw_op)(struct kiocb *, const struct iovec *,
			    unsigned long, loff_t);

static ssize_t aio_rw_vect_retry(struct kiocb *iocb, int rw, aio_rw_op *rw_op)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t ret = 0;

	/* This matches the pread()/pwrite() logic */
	if (iocb->ki_pos < 0)
		return -EINVAL;

	if (rw == WRITE)
		file_start_write(file);
	do {
		ret = rw_op(iocb, &iocb->ki_iovec[iocb->ki_cur_seg],
			    iocb->ki_nr_segs - iocb->ki_cur_seg,
			    iocb->ki_pos);
		if (ret > 0)
			aio_advance_iovec(iocb, ret);

	/* retry all partial writes.  retry partial reads as long as its a
	 * regular file. */
	} while (ret > 0 && iocb->ki_left > 0 &&
		 (rw == WRITE ||
		  (!S_ISFIFO(inode->i_mode) && !S_ISSOCK(inode->i_mode))));
	if (rw == WRITE)
		file_end_write(file);

	/* This means we must have transferred all that we could */
	/* No need to retry anymore */
	if ((ret == 0) || (iocb->ki_left == 0))
		ret = iocb->ki_nbytes - iocb->ki_left;

	/* If we managed to write some out we return that, rather than
	 * the eventual error. */
	if (rw == WRITE
	    && ret < 0 && ret != -EIOCBQUEUED
	    && iocb->ki_nbytes - iocb->ki_left)
		ret = iocb->ki_nbytes - iocb->ki_left;

	return ret;
}

static ssize_t aio_setup_vectored_rw(int rw, struct kiocb *kiocb, bool compat)
{
	ssize_t ret;

	kiocb->ki_nr_segs = kiocb->ki_nbytes;

#ifdef CONFIG_COMPAT
	if (compat)
		ret = compat_rw_copy_check_uvector(rw,
				(struct compat_iovec __user *)kiocb->ki_buf,
				kiocb->ki_nr_segs, 1, &kiocb->ki_inline_vec,
				&kiocb->ki_iovec);
	else
#endif
		ret = rw_copy_check_uvector(rw,
				(struct iovec __user *)kiocb->ki_buf,
				kiocb->ki_nr_segs, 1, &kiocb->ki_inline_vec,
				&kiocb->ki_iovec);
	if (ret < 0)
		return ret;

	/* ki_nbytes now reflect bytes instead of segs */
	kiocb->ki_nbytes = ret;
	return 0;
}

static ssize_t aio_setup_single_vector(int rw, struct kiocb *kiocb)
{
	size_t len = kiocb->ki_nbytes;

	if (len > MAX_RW_COUNT)
		len = MAX_RW_COUNT;

	if (unlikely(!access_ok(!rw, kiocb->ki_buf, len)))
		return -EFAULT;

	kiocb->ki_iovec = &kiocb->ki_inline_vec;
	kiocb->ki_iovec->iov_base = kiocb->ki_buf;
	kiocb->ki_iovec->iov_len = len;
	kiocb->ki_nr_segs = 1;
	return 0;
}

static ssize_t aio_read_iter(struct kiocb *iocb)
{
	struct file *file = iocb->ki_filp;
	ssize_t ret;

	if (unlikely(!is_kernel_kiocb(iocb)))
		return -EINVAL;

	if (unlikely(!(file->f_mode & FMODE_READ)))
		return -EBADF;

	ret = security_file_permission(file, MAY_READ);
	if (unlikely(ret))
		return ret;

	if (!file->f_op->read_iter)
		return -EINVAL;

	return file->f_op->read_iter(iocb, iocb->ki_iter, iocb->ki_pos);
}

static ssize_t aio_write_iter(struct kiocb *iocb)
{
	struct file *file = iocb->ki_filp;
	ssize_t ret;

	if (unlikely(!is_kernel_kiocb(iocb)))
		return -EINVAL;

	if (unlikely(!(file->f_mode & FMODE_WRITE)))
		return -EBADF;

	ret = security_file_permission(file, MAY_WRITE);
	if (unlikely(ret))
		return ret;

	if (!file->f_op->write_iter)
		return -EINVAL;

	file_start_write(file);
	ret = file->f_op->write_iter(iocb, iocb->ki_iter, iocb->ki_pos);
	file_end_write(file);
	return ret;
}

/*
 * aio_setup_iocb:
 *	Performs the initial checks and aio retry method
 *	setup for the kiocb at the time of io submission.
 */
static ssize_t aio_run_iocb(struct kiocb *req, bool compat)
{
	struct file *file = req->ki_filp;
	ssize_t ret;
	int rw;
	fmode_t mode;
	aio_rw_op *rw_op;

	switch (req->ki_opcode) {
	case IOCB_CMD_PREAD:
	case IOCB_CMD_PREADV:
		mode	= FMODE_READ;
		rw	= READ;
		rw_op	= file->f_op->aio_read;
		goto rw_common;

	case IOCB_CMD_PWRITE:
	case IOCB_CMD_PWRITEV:
		mode	= FMODE_WRITE;
		rw	= WRITE;
		rw_op	= file->f_op->aio_write;
		goto rw_common;
rw_common:
		if (unlikely(!(file->f_mode & mode)))
			return -EBADF;

		if (!rw_op)
			return -EINVAL;

		ret = (req->ki_opcode == IOCB_CMD_PREADV ||
		       req->ki_opcode == IOCB_CMD_PWRITEV)
			? aio_setup_vectored_rw(rw, req, compat)
			: aio_setup_single_vector(rw, req);
		if (ret)
			return ret;

		ret = rw_verify_area(rw, file, &req->ki_pos, req->ki_nbytes);
		if (ret < 0)
			return ret;

		req->ki_nbytes = ret;
		req->ki_left = ret;

		ret = aio_rw_vect_retry(req, rw, rw_op);
		break;

	case IOCB_CMD_READ_ITER:
		ret = aio_read_iter(req);
		break;

	case IOCB_CMD_WRITE_ITER:
		ret = aio_write_iter(req);
		break;

	case IOCB_CMD_FDSYNC:
		if (!file->f_op->aio_fsync)
			return -EINVAL;

		ret = file->f_op->aio_fsync(req, 1);
		break;

	case IOCB_CMD_FSYNC:
		if (!file->f_op->aio_fsync)
			return -EINVAL;

		ret = file->f_op->aio_fsync(req, 0);
		break;

	default:
		pr_debug("EINVAL: no operation provided\n");
		return -EINVAL;
	}

	if (ret != -EIOCBQUEUED) {
		/*
		 * There's no easy way to restart the syscall since other AIO's
		 * may be already running. Just fail this IO with EINTR.
		 */
		if (unlikely(ret == -ERESTARTSYS || ret == -ERESTARTNOINTR ||
			     ret == -ERESTARTNOHAND ||
			     ret == -ERESTART_RESTARTBLOCK))
			ret = -EINTR;
		aio_complete(req, ret, 0);
	}

	return 0;
}

/*
 * This allocates an iocb that will be used to submit and track completion of
 * an IO that is issued from kernel space.
 *
 * The caller is expected to call the appropriate aio_kernel_init_() functions
 * and then call aio_kernel_submit().  From that point forward progress is
 * guaranteed by the file system aio method.  Eventually the caller's
 * completion callback will be called.
 *
 * These iocbs are special.  They don't have a context, we don't limit the
 * number pending, they can't be canceled, and can't be retried.  In the short
 * term callers need to be careful not to call operations which might retry by
 * only calling new ops which never add retry support.  In the long term
 * retry-based AIO should be removed.
 */
struct kiocb *aio_kernel_alloc(gfp_t gfp)
{
	struct kiocb *iocb = kzalloc(sizeof(struct kiocb), gfp);
	if (iocb)
		iocb->ki_ctx = (void *)-1;
	return iocb;
}
EXPORT_SYMBOL_GPL(aio_kernel_alloc);

void aio_kernel_free(struct kiocb *iocb)
{
	kfree(iocb);
}
EXPORT_SYMBOL_GPL(aio_kernel_free);

/*
 * The iter count must be set before calling here.  Some filesystems uses
 * iocb->ki_left as an indicator of the size of an IO.
 */
void aio_kernel_init_iter(struct kiocb *iocb, struct file *filp,
			  unsigned short op, struct iov_iter *iter, loff_t off)
{
	iocb->ki_filp = filp;
	iocb->ki_iter = iter;
	iocb->ki_opcode = op;
	iocb->ki_pos = off;
	iocb->ki_nbytes = iov_iter_count(iter);
	iocb->ki_left = iocb->ki_nbytes;
}
EXPORT_SYMBOL_GPL(aio_kernel_init_iter);

void aio_kernel_init_callback(struct kiocb *iocb,
			      void (*complete)(u64 user_data, long res),
			      u64 user_data)
{
	iocb->ki_obj.complete = complete;
	iocb->ki_user_data = user_data;
}
EXPORT_SYMBOL_GPL(aio_kernel_init_callback);

/*
 * The iocb is our responsibility once this is called.  The caller must not
 * reference it.  This comes from aio_setup_iocb() modifying the iocb.
 *
 * Callers must be prepared for their iocb completion callback to be called the
 * moment they enter this function.  The completion callback may be called from
 * any context.
 *
 * Returns: 0: the iocb completion callback will be called with the op result
 * negative errno: the operation was not submitted and the iocb was freed
 */
int aio_kernel_submit(struct kiocb *iocb)
{
	int ret;

	BUG_ON(!is_kernel_kiocb(iocb));
	BUG_ON(!iocb->ki_obj.complete);
	BUG_ON(!iocb->ki_filp);

	ret = aio_run_iocb(iocb, 0);

	if (ret)
		aio_kernel_free(iocb);

	return ret;
}
EXPORT_SYMBOL_GPL(aio_kernel_submit);

static int io_submit_one(struct kioctx *ctx, struct iocb __user *user_iocb,
			 struct iocb *iocb, bool compat)
{
	struct kiocb *req;
	ssize_t ret;

	/* enforce forwards compatibility on users */
	if (unlikely(iocb->aio_reserved1 || iocb->aio_reserved2)) {
		pr_debug("EINVAL: reserve field set\n");
		return -EINVAL;
	}

	/* prevent overflows */
	if (unlikely(
	    (iocb->aio_buf != (unsigned long)iocb->aio_buf) ||
	    (iocb->aio_nbytes != (size_t)iocb->aio_nbytes) ||
	    ((ssize_t)iocb->aio_nbytes < 0)
	   )) {
		pr_debug("EINVAL: io_submit: overflow check\n");
		return -EINVAL;
	}

	req = aio_get_req(ctx);
	if (unlikely(!req))
		return -EAGAIN;

	req->ki_filp = fget(iocb->aio_fildes);
	if (unlikely(!req->ki_filp)) {
		ret = -EBADF;
		goto out_put_req;
	}

	if (iocb->aio_flags & IOCB_FLAG_RESFD) {
		/*
		 * If the IOCB_FLAG_RESFD flag of aio_flags is set, get an
		 * instance of the file* now. The file descriptor must be
		 * an eventfd() fd, and will be signaled for each completed
		 * event using the eventfd_signal() function.
		 */
		req->ki_eventfd = eventfd_ctx_fdget((int) iocb->aio_resfd);
		if (IS_ERR(req->ki_eventfd)) {
			ret = PTR_ERR(req->ki_eventfd);
			req->ki_eventfd = NULL;
			goto out_put_req;
		}
	}

	ret = put_user(KIOCB_KEY, &user_iocb->aio_key);
	if (unlikely(ret)) {
		pr_debug("EFAULT: aio_key\n");
		goto out_put_req;
	}

	req->ki_obj.user = user_iocb;
	req->ki_user_data = iocb->aio_data;
	req->ki_pos = iocb->aio_offset;

	req->ki_buf = (char __user *)(unsigned long)iocb->aio_buf;
	req->ki_left = req->ki_nbytes = iocb->aio_nbytes;
	req->ki_opcode = iocb->aio_lio_opcode;

	ret = aio_run_iocb(req, compat);
	if (ret)
		goto out_put_req;

	aio_put_req(req);	/* drop extra ref to req */
	return 0;
out_put_req:
	atomic_dec(&ctx->reqs_active);
	aio_put_req(req);	/* drop extra ref to req */
	aio_put_req(req);	/* drop i/o ref to req */
	return ret;
}

long do_io_submit(aio_context_t ctx_id, long nr,
		  struct iocb __user *__user *iocbpp, bool compat)
{
	struct kioctx *ctx;
	long ret = 0;
	int i = 0;
	struct blk_plug plug;

	if (unlikely(nr < 0))
		return -EINVAL;

	if (unlikely(nr > LONG_MAX/sizeof(*iocbpp)))
		nr = LONG_MAX/sizeof(*iocbpp);

	if (unlikely(!access_ok(VERIFY_READ, iocbpp, (nr*sizeof(*iocbpp)))))
		return -EFAULT;

	ctx = lookup_ioctx(ctx_id);
	if (unlikely(!ctx)) {
		pr_debug("EINVAL: invalid context id\n");
		return -EINVAL;
	}

	blk_start_plug(&plug);

	/*
	 * AKPM: should this return a partial result if some of the IOs were
	 * successfully submitted?
	 */
	for (i=0; i<nr; i++) {
		struct iocb __user *user_iocb;
		struct iocb tmp;

		if (unlikely(__get_user(user_iocb, iocbpp + i))) {
			ret = -EFAULT;
			break;
		}

		if (unlikely(copy_from_user(&tmp, user_iocb, sizeof(tmp)))) {
			ret = -EFAULT;
			break;
		}

		ret = io_submit_one(ctx, user_iocb, &tmp, compat);
		if (ret)
			break;
	}
	blk_finish_plug(&plug);

	put_ioctx(ctx);
	return i ? i : ret;
}

/* sys_io_submit:
 *	Queue the nr iocbs pointed to by iocbpp for processing.  Returns
 *	the number of iocbs queued.  May return -EINVAL if the aio_context
 *	specified by ctx_id is invalid, if nr is < 0, if the iocb at
 *	*iocbpp[0] is not properly initialized, if the operation specified
 *	is invalid for the file descriptor in the iocb.  May fail with
 *	-EFAULT if any of the data structures point to invalid data.  May
 *	fail with -EBADF if the file descriptor specified in the first
 *	iocb is invalid.  May fail with -EAGAIN if insufficient resources
 *	are available to queue any iocbs.  Will return 0 if nr is 0.  Will
 *	fail with -ENOSYS if not implemented.
 */
SYSCALL_DEFINE3(io_submit, aio_context_t, ctx_id, long, nr,
		struct iocb __user * __user *, iocbpp)
{
	return do_io_submit(ctx_id, nr, iocbpp, 0);
}

/* lookup_kiocb
 *	Finds a given iocb for cancellation.
 */
static struct kiocb *lookup_kiocb(struct kioctx *ctx, struct iocb __user *iocb,
				  u32 key)
{
	struct list_head *pos;

	assert_spin_locked(&ctx->ctx_lock);

	if (key != KIOCB_KEY)
		return NULL;

	/* TODO: use a hash or array, this sucks. */
	list_for_each(pos, &ctx->active_reqs) {
		struct kiocb *kiocb = list_kiocb(pos);
		if (kiocb->ki_obj.user == iocb)
			return kiocb;
	}
	return NULL;
}

/* sys_io_cancel:
 *	Attempts to cancel an iocb previously passed to io_submit.  If
 *	the operation is successfully cancelled, the resulting event is
 *	copied into the memory pointed to by result without being placed
 *	into the completion queue and 0 is returned.  May fail with
 *	-EFAULT if any of the data structures pointed to are invalid.
 *	May fail with -EINVAL if aio_context specified by ctx_id is
 *	invalid.  May fail with -EAGAIN if the iocb specified was not
 *	cancelled.  Will fail with -ENOSYS if not implemented.
 */
SYSCALL_DEFINE3(io_cancel, aio_context_t, ctx_id, struct iocb __user *, iocb,
		struct io_event __user *, result)
{
	struct io_event res;
	struct kioctx *ctx;
	struct kiocb *kiocb;
	u32 key;
	int ret;

	ret = get_user(key, &iocb->aio_key);
	if (unlikely(ret))
		return -EFAULT;

	ctx = lookup_ioctx(ctx_id);
	if (unlikely(!ctx))
		return -EINVAL;

	spin_lock_irq(&ctx->ctx_lock);

	kiocb = lookup_kiocb(ctx, iocb, key);
	if (kiocb)
		ret = kiocb_cancel(ctx, kiocb, &res);
	else
		ret = -EINVAL;

	spin_unlock_irq(&ctx->ctx_lock);

	if (!ret) {
		/* Cancellation succeeded -- copy the result
		 * into the user's buffer.
		 */
		if (copy_to_user(result, &res, sizeof(res)))
			ret = -EFAULT;
	}

	put_ioctx(ctx);

	return ret;
}

/* io_getevents:
 *	Attempts to read at least min_nr events and up to nr events from
 *	the completion queue for the aio_context specified by ctx_id. If
 *	it succeeds, the number of read events is returned. May fail with
 *	-EINVAL if ctx_id is invalid, if min_nr is out of range, if nr is
 *	out of range, if timeout is out of range.  May fail with -EFAULT
 *	if any of the memory specified is invalid.  May return 0 or
 *	< min_nr if the timeout specified by timeout has elapsed
 *	before sufficient events are available, where timeout == NULL
 *	specifies an infinite timeout. Note that the timeout pointed to by
 *	timeout is relative.  Will fail with -ENOSYS if not implemented.
 */
SYSCALL_DEFINE5(io_getevents, aio_context_t, ctx_id,
		long, min_nr,
		long, nr,
		struct io_event __user *, events,
		struct timespec __user *, timeout)
{
	struct kioctx *ioctx = lookup_ioctx(ctx_id);
	long ret = -EINVAL;

	if (likely(ioctx)) {
		if (likely(min_nr <= nr && min_nr >= 0))
			ret = read_events(ioctx, min_nr, nr, events, timeout);
		put_ioctx(ioctx);
	}
	return ret;
}
