// SPDX-License-Identifier: GPL-2.0-only

/*
 *  drivers/md/dm-ploop-target.c
 *
 *  Copyright (c) 2020-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include "dm.h"
#include <linux/buffer_head.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "dm-ploop.h"

#define DM_MSG_PREFIX "ploop"

struct kmem_cache *piocb_cache;

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

static void ploop_flush_workqueue(struct ploop *ploop)
{
	bool again = true;

	while (again) {
		flush_workqueue(ploop->wq);

		spin_lock_irq(&ploop->deferred_lock);
		again = ploop->deferred_cmd || !bio_list_empty(&ploop->deferred_bios);
		spin_unlock_irq(&ploop->deferred_lock);
		if (again)
			schedule_timeout(HZ);
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
	if (ploop->origin_dev) {
		WARN_ON(blkdev_issue_flush(ploop->origin_dev->bdev, GFP_NOIO, NULL));
		dm_put_device(ploop->ti, ploop->origin_dev);
	}

	for (i = 0; i < 2; i++)
		percpu_ref_exit(&ploop->inflight_bios_ref[i]);
	/* Nobody uses it after destroy_workqueue() */
	while (ploop->nr_deltas-- > 0)
		fput(ploop->deltas[ploop->nr_deltas].file);
	WARN_ON(!RB_EMPTY_ROOT(&ploop->exclusive_bios_rbtree));
	WARN_ON(!RB_EMPTY_ROOT(&ploop->inflight_bios_rbtree));
	kfree(ploop->deltas);
	kvfree(ploop->bat_levels);
	kvfree(ploop->holes_bitmap);
	kvfree(ploop->tracking_bitmap);
	vfree(ploop->hdr);
	kfree(ploop);
}

static int ploop_check_origin_dev(struct dm_target *ti, struct ploop *ploop)
{
	struct block_device *bdev = ploop->origin_dev->bdev;
	int r;

	if (bdev->bd_block_size < PAGE_SIZE) {
		ti->error = "Origin dev has too small block size";
		return -EINVAL;
	}

	r = ploop_read_metadata(ti, ploop);
	if (r) {
		ti->error = "Can't read ploop header";
		return r;
	}

	return 0;
}

/*
 * <data dev>
 */
static int ploop_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	percpu_ref_func_t *release;
	struct ploop *ploop;
	int i, ret;

	if (argc < 1)
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

	bio_list_init(&ploop->deferred_bios);
	bio_list_init(&ploop->discard_bios);
	INIT_LIST_HEAD(&ploop->cluster_lk_list);
	bio_list_init(&ploop->delta_cow_action_list);
	atomic_set(&ploop->nr_discard_bios, 0);

	INIT_WORK(&ploop->worker, do_ploop_work);

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

	/*
	 * We do not add FMODE_EXCL, because further open_table_device()
	 * unconditionally adds it. See call stack.
	 */
	ret = dm_get_device(ti, argv[1], dm_table_get_mode(ti->table),
			    &ploop->origin_dev);
	if (ret) {
		ti->error = "Error opening origin device";
		goto err;
	}

	ret = ploop_check_origin_dev(ti, ploop);
	if (ret) {
		/* ploop_check_origin_dev() assigns ti->error */
		goto err;
	}

	ret = dm_set_target_max_io_len(ti, 1 << ploop->cluster_log);
	if (ret) {
		ti->error = "could not set max_io_len";
		goto err;
	}

	ret = -ENOMEM;

	ploop->wq = alloc_ordered_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!ploop->wq) {
		ti->error = "could not create workqueue for metadata object";
		goto err;
	}

	ploop->exclusive_bios_rbtree = RB_ROOT;
	ploop->inflight_bios_rbtree = RB_ROOT;
	ret = -EINVAL;
	for (i = 2; i < argc; i++) {
                ret = ploop_add_delta(ploop, argv[i]);
		if (ret < 0)
			goto err;
	}

	ti->per_io_data_size = sizeof(struct dm_ploop_endio_hook);
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

	/* TODO: take into account the origin_dev */
	limits->max_discard_sectors = 1 << cluster_log;
	limits->max_hw_discard_sectors = 1 << cluster_log;
	limits->discard_granularity = 1 << (cluster_log + SECTOR_SHIFT);
	limits->discard_alignment = 0;
	limits->discard_misaligned = 0;
}

static sector_t get_dev_size(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

static int ploop_iterate_devices(struct dm_target *ti,
				 iterate_devices_callout_fn fn, void *data)
{
	struct ploop *ploop = ti->private;
	sector_t size;

	size = get_dev_size(ploop->origin_dev);

	return fn(ti, ploop->origin_dev, 0, size, data);
}

static void ploop_postsuspend(struct dm_target *ti)
{
	struct ploop *ploop = ti->private;

	ploop_flush_workqueue(ploop);

	blkdev_issue_flush(ploop->origin_dev->bdev, GFP_NOIO, NULL);
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
	if (ploop->noresume)
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
	DMEMIT("%s %u v2 %u %s", ploop->origin_dev->name, ploop->nr_deltas,
		1 << ploop->cluster_log, stat);
	read_unlock_irq(&ploop->bat_rwlock);
}

static int ploop_preresume(struct dm_target *ti)
{
	struct ploop *ploop = ti->private;
	int ret = 0;

	if (READ_ONCE(ploop->noresume))
		ret = -EAGAIN;
	return ret;
}

/*----------------------------------------------------------------*/

static struct target_type ploop_target = {
	.name = "ploop",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = ploop_ctr,
	.dtr = ploop_dtr,
	.map = ploop_map,
	.end_io = ploop_endio,
	.message = ploop_message,
	.io_hints = ploop_io_hints,
	.iterate_devices = ploop_iterate_devices,
	.postsuspend = ploop_postsuspend,
	.preresume = ploop_preresume,
	.status = ploop_status,
};

static int __init dm_ploop_init(void)
{
	int r;

	r = dm_register_target(&ploop_target);
	if (r) {
		DMERR("ploop target registration failed: %d", r);
		return r;
	}

	piocb_cache = kmem_cache_create("ploop-iocb", sizeof(struct ploop_iocb),
					0, 0, NULL);
	if (!piocb_cache) {
		dm_unregister_target(&ploop_target);
		return -ENOMEM;
	}

	return 0;
}

static void __exit dm_ploop_exit(void)
{
	kmem_cache_destroy(piocb_cache);
	dm_unregister_target(&ploop_target);
}

module_init(dm_ploop_init);
module_exit(dm_ploop_exit);

MODULE_AUTHOR("Kirill Tkhai <ktkhai@virtuozzo.com>");
MODULE_LICENSE("GPL");
