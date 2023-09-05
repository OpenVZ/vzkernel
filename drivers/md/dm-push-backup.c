// SPDX-License-Identifier: GPL-2.0-only

/*
 *  drivers/md/dm-push-backup.c
 *
 *  Copyright (c) 2020-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include "dm.h"
#include "dm-rq.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/ctype.h>
#include <linux/dm-io.h>
#include <linux/blk-mq.h>


#define DM_MSG_PREFIX "push-backup"

#define PB_HASH_TABLE_BITS 5
#define PB_HASH_TABLE_SIZE (1 << PB_HASH_TABLE_BITS)
#define PUSH_BACKUP_POOL_SIZE 128

static struct kmem_cache *pbio_cache;

static inline struct hlist_head *pb_htable_slot(struct hlist_head head[], u32 clu)
{
        return &head[hash_32(clu, PB_HASH_TABLE_BITS)];
}

struct pb_bio {
	struct request *rq;
	struct hlist_node hlist_node;
	u64 start_clu;
	u64 end_clu;
	u64 key_clu; /* Cluster, we are waiting at the moment */
	struct list_head list;
};

struct push_backup {
	struct dm_target *ti;
	struct dm_dev *origin_dev;
	mempool_t *pbio_pool;
	u64 clu_size;
	u64 nr_clus;

	bool alive;
	void *map;
	u64 map_bits;
	void *pending_map;
	struct hlist_head *pending_htable;

	struct list_head pending;
	s32 nr_delayed;

	u64 timeout_in_jiffies;
	u64 deadline_jiffies;
	struct timer_list deadline_timer;

	spinlock_t lock;
	struct bio_list deferred_bios;

	struct wait_queue_head waitq;
	struct workqueue_struct *wq;
	struct work_struct worker;

	struct rw_semaphore ctl_rwsem;
};

static u64 pbio_first_required_for_backup_clu(struct push_backup *pb, struct pb_bio *pbio)
{
	u64 clu;

	for (clu = pbio->start_clu; clu <= pbio->end_clu; clu++)
		if (test_bit(clu, pb->map))
			return clu;
	return U64_MAX;
}
static u64 last_required_for_backup_clu(struct push_backup *pb, u64 start_clu, u64 end_clu)
{
	u64 clu;

	for (clu = end_clu; clu >= start_clu; clu--) {
		if (test_bit(clu, pb->map))
			return clu;
		if (clu == 0)
			break;
	}
	return U64_MAX;
}
static u64 pbio_last_required_for_backup_clu(struct push_backup *pb, struct pb_bio *pbio)
{
	return last_required_for_backup_clu(pb, pbio->start_clu, pbio->end_clu);
}

static void init_pb_bio(struct pb_bio *pbio)
{
	INIT_HLIST_NODE(&pbio->hlist_node);
	INIT_LIST_HEAD(&pbio->list);
}

static void calc_bio_clusters(struct push_backup *pb, struct request *rq,
			      u64 *start_clu, u64 *end_clu)
{
	loff_t off = to_bytes(blk_rq_pos(rq));

	*start_clu = off / pb->clu_size;
	*end_clu = (off + blk_rq_bytes(rq) - 1) / pb->clu_size;
}

static int setup_if_required_for_backup(struct push_backup *pb,
					struct request *rq,
					struct pb_bio **ret_pbio)
{
	u64 start_clu, end_clu, key;
	struct pb_bio *pbio;

	calc_bio_clusters(pb, rq, &start_clu, &end_clu);

	key = last_required_for_backup_clu(pb, start_clu, end_clu);
	if (key != U64_MAX) {
		pbio = mempool_alloc(pb->pbio_pool, GFP_ATOMIC);
		if (!pbio)
			return -ENOMEM;
		init_pb_bio(pbio);
		pbio->rq = rq;
		pbio->start_clu = start_clu;
		pbio->end_clu = end_clu;
		pbio->key_clu = key;
		*ret_pbio = pbio;
		return 1;
	}
	return 0;
}

static void update_pending_map(struct push_backup *pb, struct pb_bio *pbio)
{
	u64 clu;

	for (clu = pbio->start_clu; clu <= pbio->end_clu; clu++)
		if (test_bit(clu, pb->map))
			set_bit(clu, pb->pending_map);
}

static void link_pending_pbio(struct push_backup *pb, struct pb_bio *pbio)
{
	struct hlist_head *slot = pb_htable_slot(pb->pending_htable, pbio->key_clu);

	hlist_add_head(&pbio->hlist_node, slot);
	list_add_tail(&pbio->list, &pb->pending);
}

static void unlink_pending_pbio(struct push_backup *pb, struct pb_bio *pbio)
{
	hlist_del_init(&pbio->hlist_node);
	list_del_init(&pbio->list);
}

static void relink_pending_pbio(struct push_backup *pb, struct pb_bio *pbio, u64 key)
{
	struct hlist_head *slot = pb_htable_slot(pb->pending_htable, key);

	hlist_del_init(&pbio->hlist_node);
	pbio->key_clu = key;
	hlist_add_head(&pbio->hlist_node, slot);
}

static struct pb_bio *find_pending_pbio(struct push_backup *pb, u64 clu)
{
	struct hlist_head *slot = pb_htable_slot(pb->pending_htable, clu);
	struct pb_bio *pbio;

	hlist_for_each_entry(pbio, slot, hlist_node)
		if (pbio->key_clu == clu)
			return pbio;

	return NULL;
}

static void unlink_postponed_backup_pbio(struct push_backup *pb,
					 struct list_head *pbio_list,
					 struct pb_bio *pbio)
{
	lockdep_assert_held(&pb->lock);

	unlink_pending_pbio(pb, pbio);
	pb->nr_delayed -= 1;

	list_add_tail(&pbio->list, pbio_list);
}

static void resubmit_pbios(struct push_backup *pb, struct list_head *list)
{
	struct pb_bio *pbio;

	while ((pbio = list_first_entry_or_null(list, struct pb_bio, list)) != NULL) {
		list_del_init(&pbio->list);
		dm_requeue_original_rq(pbio->rq);
		mempool_free(pbio, pb->pbio_pool);
	}
}

static void cleanup_backup(struct push_backup *pb)
{
	struct hlist_node *tmp;
	LIST_HEAD(pbio_list);
	struct pb_bio *pbio;
	int i;

	spin_lock_irq(&pb->lock);
	pb->alive = false;

	for (i = 0; i < PB_HASH_TABLE_SIZE && pb->nr_delayed; i++) {
		hlist_for_each_entry_safe(pbio, tmp, &pb->pending_htable[i], hlist_node)
			unlink_postponed_backup_pbio(pb, &pbio_list, pbio);
	}

	WARN_ON_ONCE(pb->nr_delayed);
	spin_unlock_irq(&pb->lock);

	wake_up_interruptible(&pb->waitq); /* pb->alive = false */

	if (!list_empty(&pbio_list))
		resubmit_pbios(pb, &pbio_list);
}

static void do_pb_work(struct work_struct *ws)
{
	struct push_backup *pb = container_of(ws, struct push_backup, worker);

	cleanup_backup(pb);
}

static void pb_timer_func(struct timer_list *timer)
{
	struct push_backup *pb = from_timer(pb, timer, deadline_timer);
	u64 deadline, now = get_jiffies_64();
	unsigned long flags;

	spin_lock_irqsave(&pb->lock, flags);
	deadline = pb->deadline_jiffies;
	spin_unlock_irqrestore(&pb->lock, flags);

	if (unlikely(time_before64(now, deadline)))
		mod_timer(timer, deadline - now + 1);
	else
		queue_work(pb->wq, &pb->worker);
}

static int postpone_if_required_for_backup(struct push_backup *pb,
					   struct request *rq)
{
	bool queue_timer = false;
	struct pb_bio *pbio;
	unsigned long flags;
	int ret = 0;

	rcu_read_lock(); /* See push_backup_stop() */
	spin_lock_irqsave(&pb->lock, flags);
	if (!pb->alive)
		goto unlock;
	ret = setup_if_required_for_backup(pb, rq, &pbio);
	if (ret <= 0)
		goto unlock;

	update_pending_map(pb, pbio);
	link_pending_pbio(pb, pbio);

	ret = 1;
	pb->nr_delayed += 1;
	if (pb->nr_delayed == 1) {
		pb->deadline_jiffies = get_jiffies_64() + pb->timeout_in_jiffies;
		queue_timer = true;
	}
unlock:
	spin_unlock_irqrestore(&pb->lock, flags);

	if (queue_timer)
		mod_timer(&pb->deadline_timer, pb->timeout_in_jiffies + 1);
	rcu_read_unlock();

	if (queue_timer)
		wake_up_interruptible(&pb->waitq);

	return ret;
}

static int pb_clone_and_map(struct dm_target *ti, struct request *rq,
				   union map_info *map_context,
				   struct request **__clone)

{
	struct push_backup *pb = ti->private;
	struct block_device *bdev = pb->origin_dev->bdev;
	struct request_queue *q;
	struct request *clone;
	int ret;

	if (blk_rq_bytes(rq) && op_is_write(req_op(rq))) {
		ret = postpone_if_required_for_backup(pb, rq);
		if (ret < 0) /* ENOMEM */
			return DM_MAPIO_REQUEUE;
		if (ret > 0) /* Postponed */
			return DM_MAPIO_SUBMITTED;
	}

	q = bdev_get_queue(bdev);
	clone = blk_mq_alloc_request(q, rq->cmd_flags | REQ_NOMERGE,
				BLK_MQ_REQ_NOWAIT);
	if (IS_ERR(clone)) {
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

static void pb_release_clone(struct request *clone,
			     union map_info *map_context)
{
	blk_mq_free_request(clone);
}

static bool msg_wants_down_write(const char *cmd)
{
	if (!strcmp(cmd, "push_backup_start") ||
	    !strcmp(cmd, "push_backup_stop"))
		return true;

	return false;
}

static int setup_pb(struct push_backup *pb, void __user *mask, int timeout)
{
	u64 i, map_bits, clus = pb->nr_clus;
	void *map, *pending_map;
	size_t size;

	pb->deadline_jiffies = S64_MAX;
	pb->timeout_in_jiffies = timeout * HZ;

	size = DIV_ROUND_UP(clus, 8);
	size = ALIGN(size, sizeof(unsigned long));

	map = kvzalloc(size, GFP_KERNEL);
	pending_map = kvzalloc(size, GFP_KERNEL);
	if (!map || !pending_map)
		goto err;

	if (!mask) {
		/* Full backup */
		memset(map, 0xff, clus / 8);
		for (i = round_down(clus, 8); i < clus; i++)
			set_bit(i, map);
	} else {
		/* Partial backup */
		size = DIV_ROUND_UP(clus, 8);
		if (copy_from_user(map, mask, size))
			goto err;
	}

	map_bits = bitmap_weight(map, clus);

	spin_lock_irq(&pb->lock);
	pb->map = map;
	pb->map_bits = map_bits;
	pb->pending_map = pending_map;
	pb->alive = true;
	spin_unlock_irq(&pb->lock);
	return 0;
err:
	kvfree(map);
	kvfree(pending_map);
	return -EFAULT;
}

static int push_backup_start(struct push_backup *pb, u64 timeout,
			     void __user *mask)
{
	if (pb->alive)
		return -EEXIST;
	if (timeout == 0 || timeout >= 60UL * 60 * 5)
		return -EINVAL;
	return setup_pb(pb, mask, timeout);
}

static int push_backup_stop(struct push_backup *pb,
			    char *result, unsigned int maxlen)
{
	void *map = NULL, *pending_map = NULL;

	if (!pb->map)
		return -EBADF;
	cleanup_backup(pb);

	/* Wait postpone_if_required_for_backup() starts timer */
	synchronize_rcu();
	del_timer_sync(&pb->deadline_timer);
	flush_workqueue(pb->wq);

	spin_lock_irq(&pb->lock);
	swap(pb->map, map);
	swap(pb->pending_map, pending_map);
	pb->timeout_in_jiffies = 0;
	spin_unlock_irq(&pb->lock);
	kvfree(map);
	kvfree(pending_map);
	return 0;
}

static int push_backup_read(struct push_backup *pb,
			    char *result, unsigned int maxlen)
{
	unsigned int left, right, sz = 0;
	struct pb_bio *pbio;
	int ret;

	if (!pb)
		return -EBADF;
	if (!pb->map)
		return -ESTALE;
again:
	if (wait_event_interruptible(pb->waitq,
				     !list_empty_careful(&pb->pending) ||
				     !pb->alive || !pb->map_bits))
		return -EINTR;

	spin_lock_irq(&pb->lock);
	ret = -ESTALE;
	if (!pb->alive)
		goto unlock;
	ret = 0;
	if (!pb->map_bits)
		goto unlock;
	pbio = list_first_entry_or_null(&pb->pending, typeof(*pbio), list);
	if (unlikely(!pbio)) {
		spin_unlock_irq(&pb->lock);
		goto again;
	}

	ret = -EBADMSG;
	left = pbio_first_required_for_backup_clu(pb, pbio);
	if (WARN_ON_ONCE(left == U64_MAX))
		goto unlock;

	right = find_next_zero_bit(pb->pending_map, pb->nr_clus, left + 1);
	if (right < pb->nr_clus)
		right -= 1;
	else
		right = pb->nr_clus - 1;

	DMEMIT("%u:%u", left, right - left + 1);
	ret = 1;
unlock:
	spin_unlock_irq(&pb->lock);
	return ret;
}

static int push_backup_write(struct push_backup *pb,
			     unsigned int clu, unsigned int nr)
{
	u64 i, key, nr_clus = pb->nr_clus;
	bool finished, has_more = false;
	LIST_HEAD(pbio_list);
	struct pb_bio *pbio;

	if (!pb)
		return -EBADF;
	if (clu >= nr_clus || nr > nr_clus - clu)
		return -E2BIG;
	if (!pb->map)
		return -ESTALE;

	spin_lock_irq(&pb->lock);
	if (!pb->alive) {
		spin_unlock_irq(&pb->lock);
		return -ESTALE;
	}

	for (i = clu; i < clu + nr; i++) {
		if (test_bit(i, pb->map)) {
			clear_bit(i, pb->map);
			clear_bit(i, pb->pending_map);
			pb->map_bits--;
		}
	}

	finished = (pb->map_bits == 0);

	for (i = clu; i < clu + nr; i++) {
		while (1) {
			pbio = find_pending_pbio(pb, i);
			if (!pbio)
				break;
			key = pbio_last_required_for_backup_clu(pb, pbio);
			if (key != U64_MAX) {
				/*
				 * There is one or more clusters-to-backup
				 * required for this bio. Wait for them.
				 * Userspace possible backups clusters
				 * from smallest to biggest, so we use
				 * last clu as key.
				 */
				relink_pending_pbio(pb, pbio, key);
				continue;
			}
			/*
			 * All clusters of this bios were backuped or
			 * they are not needed for backup.
			 */
			unlink_postponed_backup_pbio(pb, &pbio_list, pbio);
		}
	}

	has_more = (pb->nr_delayed != 0);
	if (has_more)
		pb->deadline_jiffies = get_jiffies_64() + pb->timeout_in_jiffies;
	else
		pb->deadline_jiffies = S64_MAX;
	spin_unlock_irq(&pb->lock);

	if (finished)
		wake_up_interruptible(&pb->waitq);

	if (!list_empty(&pbio_list)) {
		resubmit_pbios(pb, &pbio_list);
		if (has_more)
			mod_timer(&pb->deadline_timer, pb->timeout_in_jiffies + 1);
	}

	return 0;
}

static int push_backup_statistics(struct push_backup *pb, char *result,
				  unsigned int maxlen)
{
	unsigned int sz = 0;
	s64 expires;

	spin_lock_irq(&pb->lock);
	expires = pb->timeout_in_jiffies;
	if (pb->alive) {
		if (pb->deadline_jiffies != S64_MAX)
			expires = pb->deadline_jiffies - jiffies_64;
	} else if (pb->map) {
		expires = pb->deadline_jiffies - jiffies_64;
	}
	DMEMIT("nr_remaining_clus=%llu\n", pb->map_bits);
	DMEMIT("nr_delayed_bios=%d\n", pb->nr_delayed);
	DMEMIT("expires_in=%lld\n", expires / HZ);
	spin_unlock_irq(&pb->lock);
	return 1;
}

static int pb_message(struct dm_target *ti, unsigned int argc, char **argv,
		      char *result, unsigned int maxlen)
{
	struct push_backup *pb = ti->private;
	int ret = -EPERM;
	u64 val, val2;
	bool write;

	if (!capable(CAP_SYS_ADMIN))
		goto out;

	ret = -EINVAL;
	if (argc < 1)
		goto out;

	if (!strcmp(argv[0], "push_backup_stop")) {
		if (argc != 1)
			goto out;

		if (!pb->map)
			return -EBADF;

		pb->alive = false;
		wake_up_interruptible(&pb->waitq); /* pb->alive = false */
	}

	write = msg_wants_down_write(argv[0]);
	if (write)
		ret = down_write_killable(&pb->ctl_rwsem);
	else
		ret = down_read_killable(&pb->ctl_rwsem);
	if (unlikely(ret))
		goto out;

	if (!strcmp(argv[0], "push_backup_start")) {
		if (argc < 2 || argc > 3)
			goto unlock;
		if (kstrtou64(argv[1], 10, &val) < 0)
			goto unlock;
		val2 = 0;
		if (argc == 3 && kstrtou64(argv[2], 10, &val2) < 0)
			goto unlock;
		ret = push_backup_start(pb, val, (void *)val2);
	} else if (!strcmp(argv[0], "push_backup_stop")) {
		ret = push_backup_stop(pb, result, maxlen);
	} else if (!strcmp(argv[0], "push_backup_read")) {
		if (argc != 1)
			goto unlock;
		ret = push_backup_read(pb, result, maxlen);
	} else if (!strcmp(argv[0], "push_backup_write")) {
		if (argc != 2 || sscanf(argv[1], "%llu:%llu", &val, &val2) != 2)
			goto unlock;
		ret = push_backup_write(pb, val, val2);
	} else if (!strcmp(argv[0], "push_backup_statistics")) {
		ret = push_backup_statistics(pb, result, maxlen);
	} else {
		ret = -ENOTSUPP;
	}

unlock:
	if (write)
		up_write(&pb->ctl_rwsem);
	else
		up_read(&pb->ctl_rwsem);
out:
	return ret;
}
static void pb_destroy(struct push_backup *pb)
{
	WARN_ON_ONCE(pb->nr_delayed);

	del_timer_sync(&pb->deadline_timer);
	if (pb->wq)
		destroy_workqueue(pb->wq);
	kvfree(pb->map); /* Is's not zero if stop was not called */
	kvfree(pb->pending_map);
	kvfree(pb->pending_htable);
	mempool_destroy(pb->pbio_pool);
	if (pb->origin_dev)
		dm_put_device(pb->ti, pb->origin_dev);
	kfree(pb);
}

/*
 * <cluster size> <data dev>
 */
static int pb_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct push_backup *pb;
	u32 sectors;
	int ret;

	if (argc < 2 || ti->begin != 0)
		return -EINVAL;

	ret = -ENOMEM;
	pb = kzalloc(sizeof(*pb), GFP_KERNEL);
	if (!pb)
		goto err;

	pb->pbio_pool = mempool_create_slab_pool(PUSH_BACKUP_POOL_SIZE,
						 pbio_cache);
        pb->pending_htable = kcalloc(PB_HASH_TABLE_SIZE,
				     sizeof(struct hlist_head),
				     GFP_KERNEL);
	if (!pb->pbio_pool || !pb->pending_htable)
		goto err;

	spin_lock_init(&pb->lock);
	init_rwsem(&pb->ctl_rwsem);
	bio_list_init(&pb->deferred_bios);
	INIT_LIST_HEAD(&pb->pending);
	timer_setup(&pb->deadline_timer, pb_timer_func, 0);

	init_waitqueue_head(&pb->waitq);
	INIT_WORK(&pb->worker, do_pb_work);

	ti->private = pb;
	pb->ti = ti;

	if (kstrtou32(argv[0], 10, &sectors) < 0) {
		ret = -EINVAL;
		ti->error = "could not parse cluster size";
		goto err;
	}
	pb->clu_size = to_bytes(sectors);
	pb->nr_clus = DIV_ROUND_UP(ti->len, sectors);

	/*
	 * We do not add FMODE_EXCL, because further open_table_device()
	 * unconditionally adds it. See call stack.
	 */
	ret = dm_get_device(ti, argv[1], dm_table_get_mode(ti->table),
			    &pb->origin_dev);
	if (ret) {
		ti->error = "Error opening origin device";
		goto err;
	}

	pb->wq = alloc_ordered_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM);
	if (!pb->wq) {
		ti->error = "could not create workqueue for metadata object";
		goto err;
	}

	ti->num_flush_bios = 1;
	ti->flush_supported = true;
	ti->num_discard_bios = 1;
	ti->discards_supported = true;
	return 0;
err:
	if (pb)
		pb_destroy(pb);
	return ret;
}

static void pb_dtr(struct dm_target *ti)
{
	pb_destroy(ti->private);
}

static sector_t get_dev_size(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

static int pb_iterate_devices(struct dm_target *ti,
			      iterate_devices_callout_fn fn, void *data)
{
	struct push_backup *pb = ti->private;
	sector_t size;

	size = get_dev_size(pb->origin_dev);

	return fn(ti, pb->origin_dev, 0, size, data);
}

static void pb_status(struct dm_target *ti, status_type_t type,
		      unsigned int status_flags, char *result,
		      unsigned int maxlen)
{
	struct push_backup *pb = ti->private;
	const char *status = "inactive";
	ssize_t sz = 0;

	spin_lock_irq(&pb->lock);
	if (pb->alive)
		status = "active";
	else if (pb->map)
		status = "expired";
	DMEMIT("%s %llu %llu %s", pb->origin_dev->name, to_sector(pb->clu_size),
				  pb->timeout_in_jiffies / HZ, status);
	spin_unlock_irq(&pb->lock);
}

static loff_t pb_llseek_hole(struct dm_target *ti, loff_t offset,
			      int whence)
{
	struct push_backup *pb = ti->private;
	struct block_device *bdev = pb->origin_dev->bdev;

	if (!bdev->bd_disk->fops->llseek_hole)
		return -EINVAL;
	return bdev->bd_disk->fops->llseek_hole(bdev, offset, whence);
}

static struct target_type pb_target = {
	.name = "push_backup",
	.version = {1, 0, 0},
	.features = DM_TARGET_SINGLETON,
	.module = THIS_MODULE,
	.ctr = pb_ctr,
	.dtr = pb_dtr,
	.clone_and_map_rq = pb_clone_and_map,
	.release_clone_rq = pb_release_clone,
	.message = pb_message,
	.iterate_devices = pb_iterate_devices,
	.status = pb_status,
	.llseek_hole = pb_llseek_hole,
};

static int __init dm_pb_init(void)
{
	int r;

	pbio_cache = kmem_cache_create("pb_bio", sizeof(struct pb_bio), 0, 0, NULL);
	if (!pbio_cache)
		return -ENOMEM;

	r = dm_register_target(&pb_target);
	if (r) {
		DMERR("pb target registration failed: %d", r);
		goto err;
	}
out:
	return r;
err:
	kmem_cache_destroy(pbio_cache);
	goto out;
}

static void __exit dm_pb_exit(void)
{
	dm_unregister_target(&pb_target);
	kmem_cache_destroy(pbio_cache);
}

module_init(dm_pb_init);
module_exit(dm_pb_exit);

MODULE_AUTHOR("Kirill Tkhai <ktkhai@virtuozzo.com>");
MODULE_LICENSE("GPL v2");
