// SPDX-License-Identifier: GPL-2.0-only

/*
 *  drivers/md/dm-tracking.c
 *
 *  Copyright (c) 2020-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include "dm.h"
#include "dm-rq.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/ctype.h>
#include <linux/dm-io.h>
#include <linux/blk-mq.h>


#define DM_MSG_PREFIX "dm-tracking"

struct dm_tracking {
	struct dm_target *ti;
	struct dm_dev *origin_dev;

	u32 clu_size;
	u64 nr_clus;

	u64 cursor;
	void *bitmap;

	spinlock_t lock;
	struct mutex ctl_mutex;
};

struct treq {
	sector_t pos;
	u32 bytes;
};

static sector_t get_dev_size(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

static void track_rq_clus(struct dm_tracking *dmt, struct treq *treq)
{
	loff_t off = to_bytes(treq->pos);
	u64 start_clu, end_clu, clu;

	start_clu = off / dmt->clu_size;
	end_clu = (off + treq->bytes - 1) / dmt->clu_size;

	for (clu = start_clu; clu <= end_clu; clu++) {
		set_bit(clu, dmt->bitmap);
		if (clu == U64_MAX)
			break;
	}
}

static int dmt_clone_and_map(struct dm_target *ti, struct request *rq,
			     union map_info *map_context,
			     struct request **__clone)

{
	struct dm_tracking *dmt = ti->private;
	struct block_device *bdev = dmt->origin_dev->bdev;
	struct treq *treq = NULL;
	struct request_queue *q;
	struct request *clone;

	map_context->ptr = NULL;
	if (blk_rq_bytes(rq) && op_is_write(req_op(rq))) {
		treq = kmalloc(sizeof(*treq), GFP_ATOMIC);
		if (!treq)
			return DM_MAPIO_REQUEUE;
		treq->pos = blk_rq_pos(rq);
		treq->bytes = blk_rq_bytes(rq);
		map_context->ptr = treq;
	}

	q = bdev_get_queue(bdev);
	clone = blk_mq_alloc_request(q, rq->cmd_flags | REQ_NOMERGE,
				BLK_MQ_REQ_NOWAIT);
	if (IS_ERR(clone)) {
		kfree(treq);
		/* EBUSY, ENODEV or EWOULDBLOCK: requeue */
		if (blk_queue_dying(q))
			return DM_MAPIO_DELAY_REQUEUE;
		return DM_MAPIO_REQUEUE;
	}

	clone->bio = clone->biotail = NULL;
	clone->cmd_flags |= REQ_FAILFAST_TRANSPORT;
	*__clone = clone;
	return DM_MAPIO_REMAPPED;
}

static void dmt_release_clone(struct request *clone,
			      union map_info *map_context)
{
	if (unlikely(map_context)) {
		struct treq *treq = map_context->ptr;
		kfree(treq);
	}

	blk_mq_free_request(clone);
}

static int dmt_end_io(struct dm_target *ti, struct request *clone,
		      blk_status_t error, union map_info *map_context)
{
	struct treq *treq = map_context->ptr;
	struct dm_tracking *dmt = ti->private;

	if (treq) {
		spin_lock_irq(&dmt->lock);
		if (dmt->bitmap)
			track_rq_clus(dmt, treq);
		spin_unlock_irq(&dmt->lock);
		kfree(treq);
	}

	return DM_ENDIO_DONE;
}

static void dmt_destroy(struct dm_tracking *dmt)
{
	if (dmt->origin_dev)
		dm_put_device(dmt->ti, dmt->origin_dev);

	kvfree(dmt->bitmap);
	kfree(dmt);
}

/*
 * <cluster size> <data dev>
 */
static int dmt_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct dm_tracking *dmt;
	u64 origin_secs;
	u32 sectors;
	int ret;

	if (argc != 2 || ti->begin != 0)
		return -EINVAL;

	ret = -ENOMEM;
	dmt = kzalloc(sizeof(*dmt), GFP_KERNEL);
	if (!dmt)
		goto err;

	mutex_init(&dmt->ctl_mutex);

	ti->private = dmt;
	dmt->ti = ti;

	if (kstrtou32(argv[0], 10, &sectors) < 0) {
		ret = -EINVAL;
		ti->error = "could not parse cluster size";
		goto err;
	}
	dmt->clu_size = to_bytes(sectors);
	dmt->nr_clus = DIV_ROUND_UP(ti->len, sectors);

	/*
	 * We do not add FMODE_EXCL, because further open_table_device()
	 * unconditionally adds it. See call stack.
	 */
	ret = dm_get_device(ti, argv[1], dm_table_get_mode(ti->table),
			    &dmt->origin_dev);
	if (ret) {
		ti->error = "Error opening origin device";
		goto err;
	}

	origin_secs = get_dev_size(dmt->origin_dev);
	if (origin_secs < ti->len) {
		ret = -EBADSLT;
		ti->error = "Origin device is too small";
		goto err;
	}

	ti->num_flush_bios = 1;
	ti->flush_supported = true;
	ti->num_discard_bios = 1;
	ti->discards_supported = true;
	return 0;
err:
	if (dmt)
		dmt_destroy(dmt);
	return ret;
}

static void dmt_dtr(struct dm_target *ti)
{
	dmt_destroy(ti->private);
}

static int tracking_clear(struct dm_tracking *dmt, u64 clu)
{
	spin_lock_irq(&dmt->lock);
	clear_bit(clu, dmt->bitmap);
	spin_unlock_irq(&dmt->lock);
	return 0;
}

static int tracking_get_next(struct dm_tracking *dmt, char *result,
			     unsigned int maxlen)
{
	unsigned int i, sz = 0, nr_clus = dmt->nr_clus, prev = dmt->cursor;
	void *bitmap = dmt->bitmap;
	int ret = 0;

	if (WARN_ON_ONCE(prev > nr_clus - 1))
		prev = 0;

	spin_lock_irq(&dmt->lock);
	i = find_next_bit(bitmap, nr_clus, prev + 1);
	if (i < nr_clus)
		goto found;
	i = find_first_bit(bitmap, prev + 1);
	if (i >= prev + 1)
		goto unlock;
found:
	ret = (DMEMIT("%u\n", i)) ? 1 : 0;
	if (ret)
		clear_bit(i, bitmap);
unlock:
	spin_unlock_irq(&dmt->lock);
	if (ret > 0)
		dmt->cursor = i;
	return ret;
}

static int dmt_cmd(struct dm_tracking *dmt, const char *suffix,
		   int argc, char *argv[],
		   char *result, unsigned int maxlen)
{
	unsigned int nr_clus, size;
	void *bitmap = NULL;
	u64 val;

	if (!strcmp(suffix, "clear")) {
		if (argc != 1 || kstrtou64(argv[0], 10, &val) < 0 ||
		    val >= dmt->nr_clus)
			return -EINVAL;
		if (!dmt->bitmap)
			return -ENOENT;
		return tracking_clear(dmt, val);
	}

	if (argc != 0)
		return -EINVAL;

	if (!strcmp(suffix, "get_next")) {
		if (!dmt->bitmap)
			return -ENOENT;
		return tracking_get_next(dmt, result, maxlen);
	}

	if (!strcmp(suffix, "start")) {
		if (dmt->bitmap)
			return -EEXIST;
		nr_clus = dmt->nr_clus;

		size = DIV_ROUND_UP(nr_clus, 8 * sizeof(unsigned long));
		size *= sizeof(unsigned long);
		bitmap = kvzalloc(size, GFP_KERNEL);
		if (!bitmap)
			return -ENOMEM;
		dmt->cursor = nr_clus - 1;

		spin_lock_irq(&dmt->lock);
		dmt->bitmap = bitmap;
		spin_unlock_irq(&dmt->lock);
		return 0;
	} else if (!strcmp(suffix, "stop")) {
		if (!dmt->bitmap)
			return -ENOENT;

		spin_lock_irq(&dmt->lock);
		swap(dmt->bitmap, bitmap);
		spin_unlock_irq(&dmt->lock);
		kvfree(bitmap);
		return 0;
	}

	return -ENOTSUPP;
}

static int dmt_message(struct dm_target *ti, unsigned int argc, char **argv,
		       char *result, unsigned int maxlen)
{
	struct dm_tracking *dmt = ti->private;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	mutex_lock(&dmt->ctl_mutex);
	ret = -EINVAL;
	if (argc < 1)
		goto unlock;
	ret = -ENOTSUPP;
	if (strncmp(argv[0], "tracking_", 9))
		goto unlock;
	ret = dmt_cmd(dmt, argv[0] + 9, argc - 1,
		      &argv[1], result, maxlen);
unlock:
	mutex_unlock(&dmt->ctl_mutex);

	return ret;
}

static int dmt_iterate_devices(struct dm_target *ti,
			       iterate_devices_callout_fn fn, void *data)
{
	struct dm_tracking *dmt = ti->private;
	sector_t size;

	size = get_dev_size(dmt->origin_dev);

	return fn(ti, dmt->origin_dev, 0, size, data);
}

static void dmt_status(struct dm_target *ti, status_type_t type,
		       unsigned int status_flags, char *result,
		       unsigned int maxlen)
{
	struct dm_tracking *dmt = ti->private;
	const char *status = "inactive";
	ssize_t sz = 0;

	spin_lock_irq(&dmt->lock);
	if (dmt->bitmap)
		status = "active";
	DMEMIT("%s %llu %s", dmt->origin_dev->name,
	       to_sector(dmt->clu_size), status);
	spin_unlock_irq(&dmt->lock);
}

static struct target_type dmt_target = {
	.name = "tracking",
	.version = {1, 0, 0},
	.features = DM_TARGET_SINGLETON,
	.module = THIS_MODULE,
	.ctr = dmt_ctr,
	.dtr = dmt_dtr,
	.clone_and_map_rq = dmt_clone_and_map,
	.release_clone_rq = dmt_release_clone,
	.rq_end_io = dmt_end_io,
	.message = dmt_message,
	.iterate_devices = dmt_iterate_devices,
	.status = dmt_status,
};

static int __init dmt_init(void)
{
	return dm_register_target(&dmt_target);
}

static void __exit dmt_exit(void)
{
	dm_unregister_target(&dmt_target);
}

module_init(dmt_init);
module_exit(dmt_exit);

MODULE_AUTHOR("Kirill Tkhai <ktkhai@virtuozzo.com>");
MODULE_LICENSE("GPL v2");
