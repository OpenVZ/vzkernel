// SPDX-License-Identifier: GPL-2.0-only

/*
 *  drivers/md/dm-ploop-target.c
 *
 *  Copyright (c) 2020-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include "dm.h"
#include <linux/buffer_head.h>
#include <linux/rbtree.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uio.h>
#include "dm-ploop.h"

#define DM_MSG_PREFIX "ploop"

bool ignore_signature_disk_in_use = false; /* For development purposes */
module_param(ignore_signature_disk_in_use, bool, 0444);
MODULE_PARM_DESC(ignore_signature_disk_in_use,
                "Does not check for SIGNATURE_DISK_IN_USE");

static struct kmem_cache *prq_cache;
static struct kmem_cache *pio_cache;
struct kmem_cache *cow_cache;

static void ploop_aio_do_completion(struct pio *pio)
{
	if (!atomic_dec_and_test(&pio->aio_ref))
		return;
	pio->complete(pio);
}

static void ploop_aio_complete(struct kiocb *iocb, long ret)
{
	struct pio *pio;

	pio = container_of(iocb, struct pio, iocb);

	WARN_ON_ONCE(ret > INT_MAX);
	pio->ret = (int)ret;
	ploop_aio_do_completion(pio);
}

void ploop_call_rw_iter(struct file *file, loff_t pos, unsigned rw,
			struct iov_iter *iter, struct pio *pio)
{
	struct kiocb *iocb = &pio->iocb;
	int ret;

	iocb->ki_pos = pos;
	iocb->ki_filp = file;
	iocb->ki_complete = ploop_aio_complete;
	iocb->ki_flags = IOCB_DIRECT;
	iocb->ki_ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0);

	atomic_set(&pio->aio_ref, 2);

	if (rw == WRITE)
		ret = call_write_iter(file, iocb, iter);
	else
		ret = call_read_iter(file, iocb, iter);

	ploop_aio_do_completion(pio);

	if (ret != -EIOCBQUEUED)
		iocb->ki_complete(iocb, ret);
}

int ploop_rw_page_sync(unsigned rw, struct file *file,
		       u64 index, struct page *page)
{
	struct bio_vec *bvec, bvec_on_stack;
	struct iov_iter iter;
	ssize_t ret;
	loff_t pos;

	BUG_ON(rw != READ && rw != WRITE);

	bvec = &bvec_on_stack;
	bvec->bv_page = page;
	bvec->bv_len = PAGE_SIZE;
	bvec->bv_offset = 0;

	iov_iter_bvec(&iter, rw, bvec, 1, PAGE_SIZE);
	pos = index << PAGE_SHIFT;

	if (rw == READ)
		ret = vfs_iter_read(file, &iter, &pos, 0);
	else
		ret = vfs_iter_write(file, &iter, &pos, 0);

	if (ret == PAGE_SIZE)
		ret = 0;
	else if (ret >= 0)
		ret = -ENODATA;

	return ret;
}

static void inflight_bios_ref_exit0(struct percpu_ref *ref)
{
	struct ploop *ploop = container_of(ref, struct ploop,
					   inflight_bios_ref[0]);
	complete(&ploop->inflight_bios_ref_comp);
}

static void inflight_bios_ref_exit1(struct percpu_ref *ref)
{
	struct ploop *ploop = container_of(ref, struct ploop,
					   inflight_bios_ref[1]);
	complete(&ploop->inflight_bios_ref_comp);
}

void free_md_pages_tree(struct rb_root *root)
{
	struct rb_node *node;
	struct md_page *md;

	while ((node = root->rb_node) != NULL) {
		md = rb_entry(node, struct md_page, node);
		rb_erase(node, root);
		ploop_free_md_page(md);
	}
}

static bool ploop_has_pending_activity(struct ploop *ploop)
{
	bool has = false;
	int i;

	spin_lock_irq(&ploop->deferred_lock);
	for (i = 0; i < PLOOP_LIST_COUNT; i++)
		has |= !list_empty(&ploop->pios[i]);
	spin_unlock_irq(&ploop->deferred_lock);

	return has;
}

static bool ploop_empty_htable(struct hlist_head head[])
{
	int i;

	for (i = 0; i < PLOOP_HASH_TABLE_SIZE; i++)
		if (!hlist_empty(&head[i]))
			return false;

	return true;
}

static void ploop_destroy(struct ploop *ploop)
{
	int i;

	if (ploop->wq) {
		flush_workqueue(ploop->wq);
		destroy_workqueue(ploop->wq);
		WARN_ON_ONCE(ploop_has_pending_activity(ploop));
	}
	for (i = 0; i < 2; i++)
		percpu_ref_exit(&ploop->inflight_bios_ref[i]);
	/* Nobody uses it after destroy_workqueue() */
	while (ploop->nr_deltas-- > 0) {
		if (ploop->deltas[ploop->nr_deltas].file)
			fput(ploop->deltas[ploop->nr_deltas].file);
	}
	WARN_ON(!ploop_empty_htable(ploop->exclusive_pios));
	WARN_ON(!ploop_empty_htable(ploop->inflight_pios));
	kfree(ploop->inflight_pios);
	kfree(ploop->exclusive_pios);
	mempool_destroy(ploop->pio_pool);
	mempool_destroy(ploop->prq_pool);
	kfree(ploop->deltas);
	kvfree(ploop->holes_bitmap);
	kvfree(ploop->tracking_bitmap);
	free_md_pages_tree(&ploop->bat_entries);
	kfree(ploop);
}

static struct file * get_delta_file(int fd)
{
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-ENOENT);
	if (!(file->f_mode & FMODE_READ)) {
		fput(file);
		return ERR_PTR(-EBADF);
	}

	return file;
}

static int check_top_delta(struct ploop *ploop, struct file *file)
{
	struct dm_target *ti = ploop->ti;
	struct page *page = NULL;
	fmode_t mode;
	int ret;

	mode = dm_table_get_mode(ti->table);
	mode &= (FMODE_READ|FMODE_WRITE);

	ret = -EACCES;
        if (mode & ~(file->f_mode & (FMODE_READ|FMODE_WRITE)))
		goto out;

	/* Prealloc a page to read hdr */
	ret = -ENOMEM;
	page = alloc_page(GFP_KERNEL);
	if (!page)
		goto out;

	ret = ploop_rw_page_sync(READ, file, 0, page);
	if (ret < 0)
		goto out;

	ret = ploop_setup_metadata(ploop, page);
	if (ret)
		goto out;

	ret = prealloc_md_pages(&ploop->bat_entries, 0, ploop->nr_bat_entries);
	if (ret)
		goto out;
out:
	if (page)
		put_page(page);
	return ret;
}

static int ploop_add_deltas_stack(struct ploop *ploop, char **argv, int argc)
{
	struct ploop_delta *deltas;
	int i, delta_fd, ret;
	struct file *file;
	const char *arg;
	bool is_raw;

	ret = -EINVAL;
	if (argc < 1)
		goto out;
	if (argc > BAT_LEVEL_MAX - 1)
		goto out;

	ret = -ENOMEM;
	deltas = kcalloc(argc, sizeof(*deltas), GFP_KERNEL);
	if (!deltas)
		goto out;
	ploop->deltas = deltas;
	ploop->nr_deltas = argc;

	for (i = argc - 1; i >= 0; i--) {
		ret = -EINVAL;
		arg = argv[i];
		is_raw = false;
		if (strncmp(arg, "raw@", 4) == 0) {
			if (i != 0)
				goto out;
			arg += 4;
			is_raw = true;
		}
		if (kstrtos32(arg, 10, &delta_fd) < 0)
			goto out;

		file = get_delta_file(delta_fd);
		if (IS_ERR(file)) {
			ret = PTR_ERR(file);
			goto out;
		}

		if (i == argc - 1) { /* Top delta */
			ret = check_top_delta(ploop, file);
			if (ret)
				goto err_fput;
		}

		ret = ploop_add_delta(ploop, i, file, is_raw);
		if (ret < 0)
			goto err_fput;
	}

	ret = 0;
out:
	return ret;
err_fput:
	fput(file);
	goto out;
}

#define EAT_ARG(argc, argv)					\
	do {							\
		BUILD_BUG_ON(sizeof(argc) != sizeof(int));	\
		argc--;						\
		argv++;						\
	} while (0);
/*
 * <data dev>
 */
static int ploop_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	percpu_ref_func_t *release;
	struct ploop *ploop;
	unsigned int flags;
	int i, ret;

	if (argc < 2)
		return -EINVAL;

	ploop = kzalloc(sizeof(*ploop), GFP_KERNEL);
	if (!ploop)
		return -ENOMEM;

	ploop->prq_pool = mempool_create_slab_pool(PLOOP_PRQ_POOL_SIZE,
						   prq_cache);
	ploop->pio_pool = mempool_create_slab_pool(PLOOP_PIO_POOL_SIZE,
						   pio_cache);
	ploop->exclusive_pios = kcalloc(PLOOP_HASH_TABLE_SIZE,
					sizeof(struct hlist_head),
					GFP_KERNEL);
	ploop->inflight_pios = kcalloc(PLOOP_HASH_TABLE_SIZE,
					sizeof(struct hlist_head),
					GFP_KERNEL);
	if (!ploop->prq_pool || !ploop->pio_pool ||
	    !ploop->exclusive_pios || !ploop->inflight_pios) {
		ret = -ENOMEM;
		goto err;
	}

	rwlock_init(&ploop->bat_rwlock);
	spin_lock_init(&ploop->err_status_lock);
	init_rwsem(&ploop->ctl_rwsem);
	init_waitqueue_head(&ploop->service_wq);
	spin_lock_init(&ploop->inflight_lock);
	spin_lock_init(&ploop->deferred_lock);

	INIT_LIST_HEAD(&ploop->suspended_pios);

	for (i = 0; i < PLOOP_LIST_COUNT; i++)
		INIT_LIST_HEAD(&ploop->pios[i]);

	INIT_LIST_HEAD(&ploop->resubmit_pios);
	INIT_LIST_HEAD(&ploop->enospc_pios);
	INIT_LIST_HEAD(&ploop->cluster_lk_list);
	INIT_LIST_HEAD(&ploop->wb_batch_list);
	ploop->bat_entries = RB_ROOT;
	timer_setup(&ploop->enospc_timer, ploop_enospc_timer, 0);

	INIT_WORK(&ploop->worker, do_ploop_work);
	INIT_WORK(&ploop->fsync_worker, do_ploop_fsync_work);
	INIT_WORK(&ploop->event_work, ploop_event_work);
	init_completion(&ploop->inflight_bios_ref_comp);

	for (i = 0; i < 2; i++) {
		release = i ? inflight_bios_ref_exit1 : inflight_bios_ref_exit0;
		if (percpu_ref_init(&ploop->inflight_bios_ref[i], release,
				    PERCPU_REF_ALLOW_REINIT, GFP_KERNEL)) {
			ret = -ENOMEM;
			goto err;
		}
	}

	flags = WQ_MEM_RECLAIM|WQ_HIGHPRI|WQ_UNBOUND;
	ploop->wq = alloc_workqueue("dm-" DM_MSG_PREFIX, flags, 0);
	if (!ploop->wq) {
		ret = -ENOMEM;
		goto err;
	}

	ti->private = ploop;
	ploop->ti = ti;

	if (kstrtou32(argv[0], 10, &ploop->cluster_log) < 0) {
		ret = -EINVAL;
		ti->error = "could not parse cluster_log";
		goto err;
	}
	EAT_ARG(argc, argv);
	ret = dm_set_target_max_io_len(ti, CLU_TO_SEC(ploop, 1));
	if (ret) {
		ti->error = "could not set max_io_len";
		goto err;
	}

	ret = -EINVAL;
	/* Optional parameters */
	while (argc > 0) {
		if (strcmp(argv[0], "falloc_new_clu") == 0) {
			ploop->falloc_new_clu = true;
			EAT_ARG(argc, argv);
			continue;
		}
		if (strncmp(argv[0], "off=", 4) == 0) {
			if (kstrtou64(argv[0] + 4, 10, &ploop->skip_off) < 0)
				goto err;
			EAT_ARG(argc, argv);
			continue;
		}
		break;
	}

	if (argc <= 0)
		goto err;

	ret = ploop_add_deltas_stack(ploop, &argv[0], argc);
	if (ret)
		goto err;

	ti->num_flush_bios = 1;
	ti->flush_supported = true;
	ti->num_discard_bios = 1;
	ti->discards_supported = true;
	return 0;

err:
	ploop_destroy(ploop);
	return ret;
}

static void ploop_dtr(struct dm_target *ti)
{
	ploop_destroy(ti->private);
}

static void ploop_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct ploop *ploop = ti->private;

	limits->max_discard_sectors = CLU_TO_SEC(ploop, 1);
	limits->max_hw_discard_sectors = CLU_TO_SEC(ploop, 1);
	limits->discard_granularity = CLU_SIZE(ploop);
	limits->discard_alignment = 0;
	limits->discard_misaligned = 0;
}

static void ploop_status(struct dm_target *ti, status_type_t type,
			 unsigned int status_flags, char *result,
			 unsigned int maxlen)
{
	struct ploop *ploop = ti->private;
	char stat[32] = { 0 }, *p = stat;
	ssize_t sz = 0;

	down_read(&ploop->ctl_rwsem);
	if (ploop->falloc_new_clu)
		p += sprintf(p, "f");
	if (ploop->tracking_bitmap)
		p += sprintf(p, "t");
	if (READ_ONCE(ploop->noresume))
		p += sprintf(p, "n");
	if (READ_ONCE(ploop->event_enospc))
		p += sprintf(p, "s");
	if (p == stat)
		p += sprintf(p, "o");
	if (ploop->skip_off)
		p += sprintf(p, " off=%llu", ploop->skip_off);
	up_read(&ploop->ctl_rwsem);

	BUG_ON(p - stat >= sizeof(stat));
	DMEMIT("%u v2 %u %s", ploop->nr_deltas, (u32)CLU_TO_SEC(ploop, 1), stat);
}

static void ploop_set_wants_suspend(struct dm_target *ti, bool wants)
{
	struct ploop *ploop = ti->private;

	spin_lock_irq(&ploop->deferred_lock);
	ploop->wants_suspend = wants;
	spin_unlock_irq(&ploop->deferred_lock);
}
static void ploop_set_suspended(struct dm_target *ti, bool suspended)
{
	struct ploop *ploop = ti->private;

	down_write(&ploop->ctl_rwsem);
	ploop->suspended = suspended;
	up_write(&ploop->ctl_rwsem);
}

static void ploop_presuspend(struct dm_target *ti)
{
	struct ploop *ploop = ti->private;
	/*
	 * For pending enospc requests. Otherwise,
	 * we may never be able to suspend this target.
	 */
	ploop_set_wants_suspend(ti, true);
	flush_work(&ploop->event_work);
	del_timer_sync(&ploop->enospc_timer);
	ploop_enospc_timer(&ploop->enospc_timer);
}
static void ploop_presuspend_undo(struct dm_target *ti)
{
	ploop_set_wants_suspend(ti, false);
}
static void ploop_postsuspend(struct dm_target *ti)
{
	ploop_set_suspended(ti, true);
}
static int ploop_preresume(struct dm_target *ti)
{
	struct ploop *ploop = ti->private;
	int ret = 0;

	down_read(&ploop->ctl_rwsem);
	if (ploop->noresume)
		ret = -EAGAIN;
	up_read(&ploop->ctl_rwsem);

	if (ret == 0) {
		/*
		 * We are singleton target. There will be
		 * no more reasons to break resume.
		 */
		ploop_set_suspended(ti, false);
		ploop_set_wants_suspend(ti, false);
	}
	return ret;
}

/*----------------------------------------------------------------*/

static struct target_type ploop_target = {
	.name = "ploop",
	.version = {1, 0, 0},
	.features = DM_TARGET_SINGLETON,
	.module = THIS_MODULE,
	.ctr = ploop_ctr,
	.dtr = ploop_dtr,
	.message = ploop_message,
	.io_hints = ploop_io_hints,
	.presuspend = ploop_presuspend,
	.presuspend_undo = ploop_presuspend_undo,
	.postsuspend = ploop_postsuspend,
	.preresume = ploop_preresume,
	.clone_and_map_rq = ploop_clone_and_map,
	.status = ploop_status,
};

static int __init dm_ploop_init(void)
{
	int r = -ENOMEM;

	/* This saves some memory in comparison with kmalloc memcache */
	prq_cache = kmem_cache_create("ploop-prq", sizeof(struct ploop_rq) +
				      sizeof(struct pio), 0, 0, NULL);
	pio_cache = kmem_cache_create("ploop-pio", sizeof(struct pio),
				      0, 0, NULL);
	cow_cache = kmem_cache_create("ploop-cow", sizeof(struct ploop_cow),
				      0, 0, NULL);
	if (!prq_cache || !pio_cache || !cow_cache)
		goto err;

	r = dm_register_target(&ploop_target);
	if (r) {
		DMERR("ploop target registration failed: %d", r);
		goto err;
	}

	return 0;
err:
	kmem_cache_destroy(prq_cache);
	kmem_cache_destroy(pio_cache);
	kmem_cache_destroy(cow_cache);
	return r;
}

static void __exit dm_ploop_exit(void)
{
	dm_unregister_target(&ploop_target);
	kmem_cache_destroy(prq_cache);
	kmem_cache_destroy(pio_cache);
	kmem_cache_destroy(cow_cache);
}

module_init(dm_ploop_init);
module_exit(dm_ploop_exit);

MODULE_AUTHOR("Kirill Tkhai <ktkhai@virtuozzo.com>");
MODULE_LICENSE("GPL");
