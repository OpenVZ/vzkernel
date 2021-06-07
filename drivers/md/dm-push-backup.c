// SPDX-License-Identifier: GPL-2.0-only

/*
 *  drivers/md/dm-push-backup.c
 *
 *  Copyright (c) 2020-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include "dm.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/ctype.h>
#include <linux/dm-io.h>
#include <linux/rbtree.h>


#define DM_MSG_PREFIX "push-backup"

struct pb_bio {
	struct rb_node node;
	struct bio_list chain_bio_list;
	u64 clu;
	struct list_head list;
};

struct push_backup {
	struct dm_target *ti;
	struct dm_dev *origin_dev;
	u64 cluster_size;
	u64 nr_clus;

	u8 uuid[33];
	bool alive;
	void *ppb_map;
	u64 ppb_map_bits;

	struct rb_root rb_root;
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

static struct pb_bio *bio_to_pbio(struct bio *bio)
{
	return dm_per_bio_data(bio, sizeof(struct pb_bio));
}

static struct bio *pbio_to_bio(struct pb_bio *pbio)
{
	return dm_bio_from_per_bio_data(pbio, sizeof(*pbio));
}

static inline void remap_to_origin(struct push_backup *pb, struct bio *bio)
{
	bio_set_dev(bio, pb->origin_dev->bdev);
}

static int pb_bio_cluster(struct push_backup *pb, struct bio *bio, u64 *clu)
{
	loff_t off = to_bytes(bio->bi_iter.bi_sector);
	u64 start_clu, end_clu;

	start_clu = off / pb->cluster_size;
	end_clu = (off + bio->bi_iter.bi_size - 1) / pb->cluster_size;

	if (unlikely(start_clu != end_clu))
		return -EIO;

	*clu = start_clu;
	return 0;
}

static void link_node_pbio(struct rb_root *root, struct pb_bio *new, u64 clu)
{
	struct rb_node *parent, **node = &root->rb_node;
	struct pb_bio *pbio;

	BUG_ON(!RB_EMPTY_NODE(&new->node));
	parent = NULL;

	while (*node) {
		pbio = rb_entry(*node, struct pb_bio, node);
		parent = *node;
		if (clu < pbio->clu)
			node = &parent->rb_left;
		else if (clu > pbio->clu)
			node = &parent->rb_right;
		else
			BUG();
	}

	new->clu = clu;
	rb_link_node(&new->node, parent, node);
	rb_insert_color(&new->node, root);
}

static void unlink_node_pbio(struct rb_root *root, struct pb_bio *pbio)
{
	BUG_ON(RB_EMPTY_NODE(&pbio->node));

	rb_erase(&pbio->node, root);
	RB_CLEAR_NODE(&pbio->node);
}

static struct pb_bio *find_node_pbio_range(struct rb_root *root,
					   u64 left, u64 right)
{
	struct rb_node *node = root->rb_node;
	struct pb_bio *h;

	while (node) {
		h = rb_entry(node, struct pb_bio, node);
		if (right < h->clu)
			node = node->rb_left;
		else if (left > h->clu)
			node = node->rb_right;
		else
			return h;
	}

	return NULL;
}

static struct pb_bio *find_node_pbio(struct rb_root *root, u64 clu)
{
	return find_node_pbio_range(root, clu, clu);
}

static void unlink_postponed_backup_pbio(struct push_backup *pb,
					 struct bio_list *bio_list,
					 struct pb_bio *pbio)
{
	struct bio *bio;

	lockdep_assert_held(&pb->lock);

	unlink_node_pbio(&pb->rb_root, pbio);
	bio = pbio_to_bio(pbio);
	bio_list_add(bio_list, bio);

	pb->nr_delayed -= (1 + bio_list_size(&pbio->chain_bio_list));

	/* Unlink chain from @pbio and link to bio_list */
	bio_list_merge(bio_list, &pbio->chain_bio_list);
	bio_list_init(&pbio->chain_bio_list);

	/* Unlink from pb->pending */
	list_del_init(&pbio->list);
}

static void resubmit_bios(struct push_backup *pb, struct bio_list *bl)
{
	struct bio *bio;

	while ((bio = bio_list_pop(bl)) != NULL) {
		remap_to_origin(pb, bio);
		generic_make_request(bio);
	}
}

static void cleanup_backup(struct push_backup *pb)
{
	struct bio_list bio_list = BIO_EMPTY_LIST;
	struct rb_node *node;
	struct pb_bio *pbio;

	spin_lock_irq(&pb->lock);
	pb->alive = false;

	while ((node = pb->rb_root.rb_node) != NULL) {
		pbio = rb_entry(node, struct pb_bio, node);
		unlink_postponed_backup_pbio(pb, &bio_list, pbio);
	}

	WARN_ON_ONCE(pb->nr_delayed);
	spin_unlock_irq(&pb->lock);

	wake_up_interruptible(&pb->waitq); /* pb->alive = false */

	if (!bio_list_empty(&bio_list))
		resubmit_bios(pb, &bio_list);
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

static bool postpone_if_required_for_backup(struct push_backup *pb,
					  struct bio *bio, u64 clu)
{
	bool first = false, queue_timer = false, postpone = false;
	struct pb_bio *pbio;
	unsigned long flags;

	rcu_read_lock(); /* See push_backup_stop() */
	spin_lock_irqsave(&pb->lock, flags);
	if (likely(!pb->alive) || !test_bit(clu, pb->ppb_map))
		goto unlock;

	postpone = true;
	pb->nr_delayed += 1;

	pbio = find_node_pbio(&pb->rb_root, clu);
	if (pbio) {
		bio_list_add(&pbio->chain_bio_list, bio);
		goto unlock;
	}

	if (RB_EMPTY_ROOT(&pb->rb_root)) {
		pb->deadline_jiffies = get_jiffies_64() + pb->timeout_in_jiffies;
		queue_timer = true;
	}

	pbio = bio_to_pbio(bio);
	link_node_pbio(&pb->rb_root, pbio, clu);
	first = list_empty(&pb->pending);
	list_add_tail(&pbio->list, &pb->pending);
unlock:
	spin_unlock_irqrestore(&pb->lock, flags);

	if (queue_timer)
		mod_timer(&pb->deadline_timer, pb->timeout_in_jiffies + 1);
	rcu_read_unlock();

	if (first)
		wake_up_interruptible(&pb->waitq);

	return postpone;
}

static void init_pb_bio(struct bio *bio)
{
	struct pb_bio *pbio = bio_to_pbio(bio);

	bio_list_init(&pbio->chain_bio_list);
	pbio->clu = UINT_MAX;
	INIT_LIST_HEAD(&pbio->list);
	RB_CLEAR_NODE(&pbio->node);
}

static int pb_map(struct dm_target *ti, struct bio *bio)
{
	struct push_backup *pb = ti->private;
	u64 clu;

	init_pb_bio(bio);

	if (bio_sectors(bio) && op_is_write(bio->bi_opf)) {
		if (pb_bio_cluster(pb, bio, &clu))
			return DM_MAPIO_KILL;

		if (postpone_if_required_for_backup(pb, bio, clu))
			return DM_MAPIO_SUBMITTED;
	}

	remap_to_origin(pb, bio);
	return DM_MAPIO_REMAPPED;
}

static bool msg_wants_down_read(const char *cmd)
{
	if (!strcmp(cmd, "push_backup_get_uuid") ||
	    !strcmp(cmd, "push_backup_read") ||
	    !strcmp(cmd, "push_backup_write"))
		return true;

	return false;
}

static int setup_pb(struct push_backup *pb, char *uuid,
		    void __user *mask, int timeout)
{
	u64 i, map_bits, clus = pb->nr_clus;
	size_t size;
	void *map;

	snprintf(pb->uuid, sizeof(pb->uuid), "%s", uuid);
	pb->deadline_jiffies = S64_MAX;
	pb->timeout_in_jiffies = timeout * HZ;

	size = DIV_ROUND_UP(clus, 8);

	map = kvzalloc(size, GFP_KERNEL);
        if (!map)
		return -ENOMEM;

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
        pb->ppb_map = map;
	pb->ppb_map_bits = map_bits;
	pb->alive = true;
	spin_unlock_irq(&pb->lock);
	return 0;
err:
	kvfree(map);
	return -EFAULT;
}

static int push_backup_start(struct push_backup *pb, char *uuid,
			     void __user *mask, u64 timeout)
{
	char *p = uuid;

	if (pb->alive)
		return -EEXIST;
	if (timeout == 0 || timeout >= 60UL * 60 * 5)
		return -EINVAL;
	/*
	 * There is no a problem in case of not suspended for the device.
	 * But this means userspace collects wrong backup. Warn it here.
	 * Since the device is suspended, we do not care about inflight bios.
	 */
	if (!dm_suspended(pb->ti))
		return -EBUSY;
	/* Check UUID */
	while (*p) {
		if (!isxdigit(*p))
			return -EINVAL;
		p++;
	}
	if (p != uuid + sizeof(pb->uuid) - 1)
		return -EINVAL;

	return setup_pb(pb, uuid, mask, timeout);
}

static int push_backup_stop(struct push_backup *pb, char *uuid,
			    char *result, unsigned int maxlen)
{
	void *map = NULL;

        if (!pb->ppb_map)
                return -EBADF;
        if (strcmp(pb->uuid, uuid))
                return -EINVAL;

	cleanup_backup(pb);

	/* Wait postpone_if_required_for_backup() starts timer */
	synchronize_rcu();
	del_timer_sync(&pb->deadline_timer);
	flush_workqueue(pb->wq);

	spin_lock_irq(&pb->lock);
	swap(pb->ppb_map, map);
	pb->timeout_in_jiffies = 0;
	spin_unlock_irq(&pb->lock);
	kvfree(map);
	return 0;
}

static int push_backup_get_uuid(struct push_backup *pb, char *result,
				unsigned int maxlen)
{
	unsigned int sz = 0;

	if (pb->ppb_map)
		DMEMIT("%s", pb->uuid);
	else
		result[0] = '\0';
	return 1;
}

static int push_backup_read(struct push_backup *pb, char *uuid,
			  char *result, unsigned int maxlen)
{
	unsigned int left, right, sz = 0;
	struct pb_bio *pbio, *orig_pbio;
	struct rb_node *node;
	int ret;

	if (!pb)
		return -EBADF;
	if (strcmp(uuid, pb->uuid))
		return -EINVAL;
	if (!pb->ppb_map)
		return -ESTALE;
again:
	if (wait_event_interruptible(pb->waitq, !list_empty_careful(&pb->pending) ||
						!pb->alive || !pb->ppb_map_bits))
		return -EINTR;

	spin_lock_irq(&pb->lock);
	ret = -ESTALE;
	if (!pb->alive)
		goto unlock;
	ret = 0;
	if (!pb->ppb_map_bits)
		goto unlock;
	pbio = orig_pbio = list_first_entry_or_null(&pb->pending, typeof(*pbio), list);
	if (unlikely(!pbio)) {
		spin_unlock_irq(&pb->lock);
		goto again;
	}
	list_del_init(&pbio->list);

	left = right = pbio->clu;
	while ((node = rb_prev(&pbio->node)) != NULL) {
		pbio = rb_entry(node, struct pb_bio, node);
		if (pbio->clu + 1 != left || list_empty(&pbio->list))
			break;
		list_del_init(&pbio->list);
		left = pbio->clu;
	}

	pbio = orig_pbio;
	while ((node = rb_next(&pbio->node)) != NULL) {
		pbio = rb_entry(node, struct pb_bio, node);
		if (pbio->clu - 1 != right || list_empty(&pbio->list))
			break;
		list_del_init(&pbio->list);
		right = pbio->clu;
	}

	DMEMIT("%u:%u", left, right - left + 1);
	ret = 1;
unlock:
	spin_unlock_irq(&pb->lock);
	return ret;
}

static int push_backup_write(struct push_backup *pb, char *uuid,
			     unsigned int clu, unsigned int nr)
{
	struct bio_list bio_list = BIO_EMPTY_LIST;
	bool finished, has_more = false;
	u64 i, nr_clus = pb->nr_clus;
	struct pb_bio *pbio;

	if (!pb)
		return -EBADF;
	if (strcmp(uuid, pb->uuid) || !nr)
		return -EINVAL;
	if (clu >= nr_clus || nr > nr_clus - clu)
		return -E2BIG;
	if (!pb->ppb_map)
		return -ESTALE;

	spin_lock_irq(&pb->lock);
	if (!pb->alive) {
		spin_unlock_irq(&pb->lock);
		return -ESTALE;
	}

	for (i = clu; i < clu + nr; i++)
		clear_bit(i, pb->ppb_map);
	pb->ppb_map_bits -= nr;
	finished = (pb->ppb_map_bits == 0);

	for (i = 0; i < nr; i++) {
		pbio = find_node_pbio_range(&pb->rb_root, clu,
					    clu + nr - 1);
		if (!pbio)
			break;
		unlink_postponed_backup_pbio(pb, &bio_list, pbio);
	}

	has_more = !RB_EMPTY_ROOT(&pb->rb_root);
	if (has_more)
		pb->deadline_jiffies = get_jiffies_64() + pb->timeout_in_jiffies;
	else
		pb->deadline_jiffies = S64_MAX;
	spin_unlock_irq(&pb->lock);

	if (finished)
		wake_up_interruptible(&pb->waitq);

	if (!bio_list_empty(&bio_list)) {
		resubmit_bios(pb, &bio_list);
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
	} else if (pb->ppb_map) {
		expires = pb->deadline_jiffies - jiffies_64;
	}
	DMEMIT("nr_remaining_clus=%llu\n", pb->ppb_map_bits);
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
	bool read;

	if (!capable(CAP_SYS_ADMIN))
		goto out;

	ret = -EINVAL;
	if (argc < 1)
		goto out;

	read = msg_wants_down_read(argv[0]);
	if (read)
		down_read(&pb->ctl_rwsem);
	else
		down_write(&pb->ctl_rwsem);

	if (!strcmp(argv[0], "push_backup_start")) {
		if (argc != 4 || kstrtou64(argv[2], 10, &val) < 0 ||
				 kstrtou64(argv[3], 10, &val2) < 0)
			goto unlock;
		ret = push_backup_start(pb, argv[1], (void *)val, val2);
	} else if (!strcmp(argv[0], "push_backup_stop")) {
		if (argc != 2)
			goto unlock;
		ret = push_backup_stop(pb, argv[1], result, maxlen);
	} else if (!strcmp(argv[0], "push_backup_get_uuid")) {
		if (argc != 1)
			goto unlock;
		ret = push_backup_get_uuid(pb, result, maxlen);
	} else if (!strcmp(argv[0], "push_backup_read")) {
		if (argc != 2)
			goto unlock;
		ret = push_backup_read(pb, argv[1], result, maxlen);
	} else if (!strcmp(argv[0], "push_backup_write")) {
		if (argc != 3 || sscanf(argv[2], "%llu:%llu", &val, &val2) != 2)
			goto unlock;
		ret = push_backup_write(pb, argv[1], val, val2);
	} else if (!strcmp(argv[0], "push_backup_statistics")){
		ret = push_backup_statistics(pb, result, maxlen);
	} else {
		ret = -ENOTSUPP;
	}

unlock:
	if (read)
		up_read(&pb->ctl_rwsem);
	else
		up_write(&pb->ctl_rwsem);
out:
	return ret;
}
static void pb_destroy(struct push_backup *pb)
{
	WARN_ON_ONCE(pb->rb_root.rb_node != NULL);

	del_timer_sync(&pb->deadline_timer);
	if (pb->wq)
		destroy_workqueue(pb->wq);
	if (pb->ppb_map) /* stop was not called */
		kvfree(pb->ppb_map);
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

	pb = kzalloc(sizeof(*pb), GFP_KERNEL);
	if (!pb) {
		ti->error = "Error allocating pb structure";
		return -ENOMEM;
	}

	spin_lock_init(&pb->lock);
	init_rwsem(&pb->ctl_rwsem);
	bio_list_init(&pb->deferred_bios);
	pb->rb_root = RB_ROOT;
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
	pb->cluster_size = to_bytes(sectors);
	pb->nr_clus = DIV_ROUND_UP(ti->len, sectors);
	/*
	 * TODO: we may avoid splitting bio by cluster size.
	 * Tree search, read, write, etc should be changed.
	 */
	ret = dm_set_target_max_io_len(ti, sectors);
	if (ret) {
		ti->error = "could not set max_io_len";
		goto err;
	}

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

	ti->per_io_data_size = sizeof(struct pb_bio);
	ti->num_flush_bios = 1;
	ti->flush_supported = true;
	ti->num_discard_bios = 1;
	ti->discards_supported = true;
	return 0;

err:
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
	else if (pb->ppb_map)
		status = "expired";
	DMEMIT("%s %llu %llu %s", pb->origin_dev->name, to_sector(pb->cluster_size),
				  pb->timeout_in_jiffies / HZ, status);
	spin_unlock_irq(&pb->lock);
}

/*----------------------------------------------------------------*/

static struct target_type pb_target = {
	.name = "push_backup",
	.version = {1, 0, 0},
	.features = DM_TARGET_SINGLETON|DM_TARGET_IMMUTABLE,
	.module = THIS_MODULE,
	.ctr = pb_ctr,
	.dtr = pb_dtr,
	.map = pb_map,
	.message = pb_message,
	.iterate_devices = pb_iterate_devices,
	.status = pb_status,
};

static int __init dm_pb_init(void)
{
	int r = -ENOMEM;

	r = dm_register_target(&pb_target);
	if (r)
		DMERR("pb target registration failed: %d", r);

	return r;
}

static void __exit dm_pb_exit(void)
{
	dm_unregister_target(&pb_target);
}

module_init(dm_pb_init);
module_exit(dm_pb_exit);

MODULE_AUTHOR("Kirill Tkhai <ktkhai@virtuozzo.com>");
MODULE_LICENSE("GPL v2");
