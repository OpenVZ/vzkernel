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

struct kmem_cache *piocb_cache;
struct kmem_cache *cow_cache;

static void ploop_aio_do_completion(struct pio *pio)
{
	if (!atomic_dec_and_test(&pio->aio_ref))
		return;
	pio->complete(pio);
}

static void ploop_aio_complete(struct kiocb *iocb, long ret, long ret2)
{
	struct pio *pio;

	pio = container_of(iocb, struct pio, iocb);

	WARN_ON_ONCE(ret > INT_MAX);
	pio->ret = (int)ret;
	ploop_aio_do_completion(pio);
}

void call_rw_iter(struct file *file, loff_t pos, unsigned rw,
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
		iocb->ki_complete(iocb, ret, 0);
}

int rw_page_sync(unsigned rw, struct file *file,
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
		free_md_page(md);
	}
}

/* This is called on final device destroy */
static void ploop_flush_workqueue(struct ploop *ploop)
{
	char *argv[1] = {"try_preflush"};
	bool again = true;

	while (again) {
		flush_workqueue(ploop->wq);
		/*
		 * Normally, ploop_message("try_preflush") returns 0 or 1.
		 * In case of underlining bdev is hung, this finishes with
		 * error by timeout, and our caller (.dtr) never completes.
		 */
		again = ploop_message(ploop->ti, 1, argv, NULL, 0);
	}
}

static void ploop_destroy(struct ploop *ploop)
{
	int i;

	if (ploop->pb) {
		cleanup_backup(ploop);
		ploop_free_pb(ploop->pb);
	}
	if (ploop->wq) {
		ploop_flush_workqueue(ploop);
		destroy_workqueue(ploop->wq);
	}
	for (i = 0; i < 2; i++)
		percpu_ref_exit(&ploop->inflight_bios_ref[i]);
	/* Nobody uses it after destroy_workqueue() */
	while (ploop->nr_deltas-- > 0) {
		if (ploop->deltas[ploop->nr_deltas].file)
			fput(ploop->deltas[ploop->nr_deltas].file);
	}
	WARN_ON(!RB_EMPTY_ROOT(&ploop->exclusive_bios_rbtree));
	WARN_ON(!RB_EMPTY_ROOT(&ploop->inflight_bios_rbtree));
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

	ret = rw_page_sync(READ, file, 0, page);
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

	ret = -EINVAL;
	for (i = argc - 1; i >= 0; i--) {
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
/*
 * <data dev>
 */
static int ploop_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	percpu_ref_func_t *release;
	struct ploop *ploop;
	int i, ret;

	if (argc < 2)
		return -EINVAL;

	ploop = kzalloc(sizeof(*ploop), GFP_KERNEL);
	if (!ploop) {
		ti->error = "Error allocating ploop structure";
		return -ENOMEM;
	}

	rwlock_init(&ploop->bat_rwlock);
	init_rwsem(&ploop->ctl_rwsem);
	spin_lock_init(&ploop->deferred_lock);
	spin_lock_init(&ploop->pb_lock);

	INIT_LIST_HEAD(&ploop->deferred_pios);
	INIT_LIST_HEAD(&ploop->flush_pios);
	INIT_LIST_HEAD(&ploop->discard_pios);
	INIT_LIST_HEAD(&ploop->cluster_lk_list);
	INIT_LIST_HEAD(&ploop->delta_cow_action_list);
	atomic_set(&ploop->nr_discard_bios, 0);
	ploop->bat_entries = RB_ROOT;
	ploop->exclusive_bios_rbtree = RB_ROOT;
	ploop->inflight_bios_rbtree = RB_ROOT;

	INIT_WORK(&ploop->worker, do_ploop_work);
	INIT_WORK(&ploop->fsync_worker, do_ploop_fsync_work);
	init_completion(&ploop->inflight_bios_ref_comp);

	for (i = 0; i < 2; i++) {
		release = i ? inflight_bios_ref_exit1 : inflight_bios_ref_exit0;
		if (percpu_ref_init(&ploop->inflight_bios_ref[i], release,
				    PERCPU_REF_ALLOW_REINIT, GFP_KERNEL)) {
			ret = -ENOMEM;
			ti->error = "could not alloc percpu_ref";
			goto err;
		}
	}

	ti->private = ploop;
	ploop->ti = ti;

	if (kstrtou32(argv[0], 10, &ploop->cluster_log) < 0) {
		ret = -EINVAL;
		ti->error = "could not parse cluster_log";
		goto err;
	}
	ret = dm_set_target_max_io_len(ti, 1 << ploop->cluster_log);
	if (ret) {
		ti->error = "could not set max_io_len";
		goto err;
	}

	ploop->wq = alloc_ordered_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!ploop->wq) {
		ti->error = "could not create workqueue for metadata object";
		ret = -ENOMEM;
		goto err;
	}

	ret = ploop_add_deltas_stack(ploop, &argv[1], argc - 1);
	if (ret)
		goto err;

	ti->per_io_data_size = ploop_per_io_data_size();
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
	unsigned int cluster_log = ploop->cluster_log;

	limits->max_discard_sectors = 1 << cluster_log;
	limits->max_hw_discard_sectors = 1 << cluster_log;
	limits->discard_granularity = CLU_SIZE(ploop);
	limits->discard_alignment = 0;
	limits->discard_misaligned = 0;
}

static void ploop_status(struct dm_target *ti, status_type_t type,
			 unsigned int status_flags, char *result,
			 unsigned int maxlen)
{
	struct ploop *ploop = ti->private;
	char stat[16] = { 0 }, *p = stat;
	ssize_t sz = 0;

	read_lock_irq(&ploop->bat_rwlock);
	if (ploop->tracking_bitmap)
		p += sprintf(p, "t");
	if (READ_ONCE(ploop->noresume))
		p += sprintf(p, "n");
	if (ploop->pb) {
		if (ploop->pb->alive)
			p += sprintf(p, "b");
		else
			p += sprintf(p, "B");
	}
	if (p == stat)
		p += sprintf(p, "o");
	BUG_ON(p - stat >= sizeof(stat));
	DMEMIT("%u v2 %u %s", ploop->nr_deltas,
		1 << ploop->cluster_log, stat);
	read_unlock_irq(&ploop->bat_rwlock);
}

static int ploop_preresume(struct dm_target *ti)
{
	struct ploop *ploop = ti->private;
	int ret = 0;

	down_read(&ploop->ctl_rwsem);
	if (ploop->noresume)
		ret = -EAGAIN;
	up_read(&ploop->ctl_rwsem);
	return ret;
}

/*----------------------------------------------------------------*/

static struct target_type ploop_target = {
	.name = "ploop",
	.version = {1, 0, 0},
	.features = DM_TARGET_SINGLETON|DM_TARGET_IMMUTABLE,
	.module = THIS_MODULE,
	.ctr = ploop_ctr,
	.dtr = ploop_dtr,
	.message = ploop_message,
	.io_hints = ploop_io_hints,
	.preresume = ploop_preresume,
	.clone_and_map_rq = ploop_clone_and_map,
	.status = ploop_status,
};

static int __init dm_ploop_init(void)
{
	int r = -ENOMEM;

	piocb_cache = kmem_cache_create("ploop-iocb", sizeof(struct ploop_iocb),
					0, 0, NULL);
	cow_cache = kmem_cache_create("ploop-cow", sizeof(struct ploop_cow),
				      0, 0, NULL);
	if (!piocb_cache || !cow_cache)
		goto err;

	r = dm_register_target(&ploop_target);
	if (r) {
		DMERR("ploop target registration failed: %d", r);
		goto err;
	}

	return 0;
err:
	kmem_cache_destroy(piocb_cache);
	kmem_cache_destroy(cow_cache);
	return r;
}

static void __exit dm_ploop_exit(void)
{
	dm_unregister_target(&ploop_target);
	kmem_cache_destroy(cow_cache);
	kmem_cache_destroy(piocb_cache);
}

module_init(dm_ploop_init);
module_exit(dm_ploop_exit);

MODULE_AUTHOR("Kirill Tkhai <ktkhai@virtuozzo.com>");
MODULE_LICENSE("GPL");
