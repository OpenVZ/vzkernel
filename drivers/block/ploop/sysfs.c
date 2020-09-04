/*
 *  drivers/block/ploop/sysfs.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/interrupt.h>
#include <linux/buffer_head.h>
#include <linux/kthread.h>
#include <asm/uaccess.h>

#include <linux/ploop/ploop.h>
#include "push_backup.h"

struct delta_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct ploop_delta *, char *);
	ssize_t (*store)(struct ploop_delta *, const char *, size_t);
};

static ssize_t
delta_attr_show(struct kobject *kobj, struct attribute *attr, char *page)
{
	struct delta_sysfs_entry *entry = container_of(attr, struct delta_sysfs_entry, attr);
	struct ploop_delta *delta = container_of(kobj, struct ploop_delta, kobj);

	if (!entry->show)
		return -EIO;
	return entry->show(delta, page);
}

static ssize_t
delta_attr_store(struct kobject *kobj, struct attribute *attr,
		 const char *page, size_t length)
{
	struct delta_sysfs_entry *entry = container_of(attr, struct delta_sysfs_entry, attr);
	struct ploop_delta *delta = container_of(kobj, struct ploop_delta, kobj);

	if (!entry->store)
		return -EIO;

	return entry->store(delta, page, length);
}


static struct sysfs_ops delta_sysfs_ops = {
	.show	= delta_attr_show,
	.store	= delta_attr_store,
};

static void release_delta(struct kobject *kobj)
{
	struct ploop_delta *delta = container_of(kobj, struct ploop_delta, kobj);

	if (delta->ops)
		ploop_format_put(delta->ops);
	module_put(THIS_MODULE);
	kfree(delta);
}

static ssize_t
delta_var_show(unsigned int var, char *page)
{
	return sprintf(page, "%d\n", var);
}

static ssize_t
delta_string_show(char * str, char *page)
{
	return sprintf(page, "%s\n", str);
}

static ssize_t delta_level_show(struct ploop_delta *delta, char *page)
{
	return delta_var_show(delta->level, page);
}

static ssize_t delta_image_show(struct ploop_delta *delta, char *page)
{
	char * res;
	int len = -ENOENT;

	mutex_lock(&delta->plo->sysfs_mutex);
	if (delta->io.files.file) {
		res = d_path(&delta->io.files.file->f_path, page, PAGE_SIZE-1);
		len = PTR_ERR(res);
		if (!IS_ERR(res)) {
			len = strlen(res);
			if (res != page)
				memmove(page, res, len);
			page[len] = '\n';
			len++;
		}
	}
	mutex_unlock(&delta->plo->sysfs_mutex);
	return len;
}

static ssize_t delta_image_info_show(struct ploop_delta *delta, char *page)
{
	int len = -ENOENT;

	mutex_lock(&delta->plo->sysfs_mutex);
	if (delta->io.files.file) {
		struct inode *inode = file_inode(delta->io.files.file);
		len = snprintf(page, PAGE_SIZE, "ino:%lu\nsdev:%u:%u\n",
				inode->i_ino,
				MAJOR(inode->i_sb->s_dev),
				MINOR(inode->i_sb->s_dev));
	}
	mutex_unlock(&delta->plo->sysfs_mutex);
	return len;
}

static ssize_t delta_format_show(struct ploop_delta *delta, char *page)
{
	return delta_string_show(delta->ops->name, page);
}

static ssize_t delta_io_show(struct ploop_delta *delta, char *page)
{
	return delta_string_show(delta->io.ops->name, page);
}

static ssize_t delta_ro_show(struct ploop_delta *delta, char *page)
{
	return sprintf(page, "%d\n", !!(delta->flags & PLOOP_FMT_RDONLY));
}

static ssize_t delta_trans_show(struct ploop_delta *delta, char *page)
{
	struct ploop_device * plo = delta->plo;
	int trans = 0;

	mutex_lock(&delta->plo->sysfs_mutex);
	if (plo->trans_map && map_top_delta(plo->trans_map) == delta)
		trans = 1;
	mutex_unlock(&delta->plo->sysfs_mutex);
	return sprintf(page, "%d\n", trans);
}

static ssize_t delta_dump(struct ploop_delta *delta, char *page)
{
	int ret = delta->io.ops->dump ? delta->io.ops->dump(&delta->io) : -1;
	return sprintf(page, "%d\n", ret);
}

static struct delta_sysfs_entry delta_level_entry = {
	.attr = {.name = "level", .mode = S_IRUGO },
	.show = delta_level_show,
	.store = NULL,
};

static struct delta_sysfs_entry delta_image_entry = {
	.attr = {.name = "image", .mode = S_IRUGO },
	.show = delta_image_show,
	.store = NULL,
};

static struct delta_sysfs_entry delta_image_info_entry = {
	.attr = {.name = "image_info", .mode = S_IRUGO },
	.show = delta_image_info_show,
	.store = NULL,
};

static struct delta_sysfs_entry delta_format_entry = {
	.attr = {.name = "format", .mode = S_IRUGO },
	.show = delta_format_show,
	.store = NULL,
};

static struct delta_sysfs_entry delta_io_entry = {
	.attr = {.name = "io", .mode = S_IRUGO },
	.show = delta_io_show,
	.store = NULL,
};

static struct delta_sysfs_entry delta_ro_entry = {
	.attr = {.name = "ro", .mode = S_IRUGO },
	.show = delta_ro_show,
	.store = NULL,
};

static struct delta_sysfs_entry delta_trans_entry = {
	.attr = {.name = "transparent", .mode = S_IRUGO },
	.show = delta_trans_show,
	.store = NULL,
};

static struct delta_sysfs_entry delta_dump_entry = {
	.attr = {.name = "dump", .mode = S_IRUGO },
	.show = delta_dump,
};

static struct attribute *default_attrs[] = {
	&delta_level_entry.attr,
	&delta_image_entry.attr,
	&delta_image_info_entry.attr,
	&delta_format_entry.attr,
	&delta_io_entry.attr,
	&delta_ro_entry.attr,
	&delta_trans_entry.attr,
	&delta_dump_entry.attr,
	NULL,
};

struct kobj_type ploop_delta_ktype = {
	.sysfs_ops	= &delta_sysfs_ops,
	.default_attrs	= default_attrs,
	.release	= release_delta,
};


static struct {
#define __DO(_at)	struct attribute _at;
#include <linux/ploop/ploop_stat.h>
#undef __DO
} _attr_arr = {
#define __DO(_at)	._at = { .name = __stringify(_at), .mode = S_IRUGO|S_IWUSR, },
#include <linux/ploop/ploop_stat.h>
#undef __DO
};

static struct attribute *stats_attributes[] = {
#define __DO(_at) &_attr_arr._at,
#include <linux/ploop/ploop_stat.h>
#undef __DO
	NULL
};

static const struct attribute_group stats_group = {
	.attrs = stats_attributes,
};



#define to_disk(obj) dev_to_disk(container_of(obj,struct device,kobj))

static ssize_t pstat_show(struct kobject *kobj, struct attribute *attr,
			  char *page)
{
	struct gendisk *disk = to_disk(kobj->parent);
	struct ploop_device * plo = disk->private_data;
	int n;

	n = attr - (struct attribute *)&_attr_arr;

	return sprintf(page, "%u\n", ((u32*)&plo->st)[n]);
}

static ssize_t pstat_store(struct kobject * kobj, struct attribute * attr,
			   const char *page, size_t count)
{
	struct gendisk *disk = to_disk(kobj->parent);
	struct ploop_device * plo = disk->private_data;
	char *p = (char *) page;
	unsigned long var;
	int n;

	var = simple_strtoul(p, &p, 10);

	n = attr - (struct attribute *)&_attr_arr;
	((u32*)&plo->st)[n] = var;
	return count;
}

static u32 show_block_size(struct ploop_device * plo)
{
	return cluster_size_in_sec(plo);
}

static u32 show_fmt_version(struct ploop_device * plo)
{
	return plo->fmt_version;
}

static u32 show_total_bios(struct ploop_device * plo)
{
	return plo->bio_total;
}

static u32 show_queued_bios(struct ploop_device * plo)
{
	return plo->bio_qlen;
}

static u32 show_discard_bios(struct ploop_device * plo)
{
	return plo->bio_discard_qlen;
}

static u32 show_discard_inflight_bios(struct ploop_device * plo)
{
	return plo->discard_inflight_reqs;
}

static u32 show_active_reqs(struct ploop_device * plo)
{
	return plo->active_reqs;
}

static u32 show_entry_read_sync_reqs(struct ploop_device * plo)
{
	return plo->read_sync_reqs;
}

static u32 show_entry_reqs(struct ploop_device * plo)
{
	return plo->entry_qlen;
}

static u32 show_barrier_reqs(struct ploop_device * plo)
{
	return plo->barrier_reqs;
}

static u32 show_fsync_reqs(struct ploop_device * plo)
{
	u32 qlen = 0;
	mutex_lock(&plo->sysfs_mutex);
	if (!list_empty(&plo->map.delta_list))
		qlen = ploop_top_delta(plo)->io.fsync_qlen;
	mutex_unlock(&plo->sysfs_mutex);
	return qlen;
}

static u32 show_fastpath_reqs(struct ploop_device * plo)
{
	return plo->fastpath_reqs;
}

static u32 show_map_pages(struct ploop_device * plo)
{
	return plo->map.pages;
}

static u32 show_running(struct ploop_device * plo)
{
	return test_bit(PLOOP_S_RUNNING, &plo->state);
}

static u32 show_locked(struct ploop_device * plo)
{
	return test_bit(PLOOP_S_LOCKED, &plo->locking_state);
}

static u32 show_aborted(struct ploop_device * plo)
{
	return test_bit(PLOOP_S_ABORT, &plo->state);
}

static int store_aborted(struct ploop_device * plo, u32 val)
{
	printk(KERN_INFO "ploop: Force %s aborted state for ploop%d\n",
	       val ? "set" : "clear", plo->index);

	if (val)
		set_bit(PLOOP_S_ABORT, &plo->state);
	else
		clear_bit(PLOOP_S_ABORT, &plo->state);
	return 0;
}

static u32 show_discard_granularity(struct ploop_device * plo)
{
	return plo->queue->limits.discard_granularity;
}

static int store_discard_granularity(struct ploop_device *plo, u32 val)
{
	struct ploop_delta *delta;
	struct request_queue *q;
	struct inode *inode;
	int ret = 0;

	mutex_lock(&plo->ctl_mutex);
	if (test_bit(PLOOP_S_RUNNING, &plo->state)) {
		ret = -EBUSY;
		goto unlock;
	}

	q = plo->queue;
	if (val == q->limits.discard_granularity)
		goto unlock;

	delta = ploop_top_delta(plo);
	if (!delta) {
		ret = -ENODEV;
		goto unlock;
	}

	if (val == cluster_size_in_bytes(plo)) {
		ploop_set_discard_limits(plo);
		plo->force_split_discard_reqs = false;
		goto unlock;
	}

	inode = delta->io.files.inode;
	if (val != inode->i_sb->s_blocksize) {
		ret = -EINVAL;
		goto unlock;
	}

	q->limits.discard_granularity = val;
	/*
	 * There is no a way to force block engine to split a request
	 * to fit a single cluster, when discard granuality is 4K
	 * (inherited from fs block size in blk_queue_stack_limits()).
	 * So, ploop_make_request() splits them.
	 */
	plo->force_split_discard_reqs = true;
	/*
	 * Why not (1 << io->plo->cluster_log)?
	 * Someone may want to clear indexes in case of a request
	 * is big enough to fit the whole cluster.
	 * In case of max_discard_sectors is 1 cluster, a request
	 * for [cluster_start - 4K, cluster_start + cluster_size)
	 * at block level will be splitted in two requests:
	 *
	 * [cluster_start - 4K, cluster_start + cluster_size - 4K)
	 * [cluster_start + cluster_size - 4K, cluster_start + cluster_size)
	 *
	 * Then, ploop_make_request() splits the first of them in two
	 * to fit a single cluster, so all three requests will be smaller
	 * then 1 cluster, and no index will be cleared.
	 *
	 * Note, this does not solve a problem, when a request covers
	 * 3 clusters: [cluster_start - 4K, cluster_start + 2 * cluster_size],
	 * so the third cluster's index will remain. This will require
	 * unlimited max_discard_sectors and splitting every request
	 * in ploop_make_request(). We don't want that in that context.
	 *
	 * But even in current view, this makes indexes to be cleared
	 * more frequently, and index-clearing code will be tested better.
	 *
	 * Anyway, in general this may be an excess functionality.
	 * If it's so, it will be dropped later.
	 */
	q->limits.max_discard_sectors = (1 << plo->cluster_log) * 2 - 1;

unlock:
	mutex_unlock(&plo->ctl_mutex);
	return ret;
}

static u32 show_discard_alignment(struct ploop_device * plo)
{
	return plo->queue->limits.discard_alignment;
}

static u32 show_discard_zeroes_data(struct ploop_device * plo)
{
	return plo->queue->limits.discard_zeroes_data;
}

static int store_discard_zeroes_data(struct ploop_device * plo, u32 val)
{
	plo->queue->limits.discard_zeroes_data = !!val;
	return 0;
}

static u32 show_top(struct ploop_device * plo)
{
	int top = -1;

	mutex_lock(&plo->sysfs_mutex);
	if (!list_empty(&plo->map.delta_list))
		top = ploop_top_delta(plo)->level;
	if (plo->trans_map)
		top++;
	mutex_unlock(&plo->sysfs_mutex);
	return (u32)top;
}

static inline u32 get_event_locked(struct ploop_device * plo)
{
	if (test_and_clear_bit(PLOOP_S_ENOSPC_EVENT, &plo->state))
		return PLOOP_EVENT_ENOSPC;
	else if (test_bit(PLOOP_S_ABORT, &plo->state))
		return PLOOP_EVENT_ABORTED;
	else if (!test_bit(PLOOP_S_RUNNING, &plo->state))
		return PLOOP_EVENT_STOPPED;

	return 0;
}

static u32 show_event(struct ploop_device * plo)
{
	u32 ret;

	DEFINE_WAIT(_wait);
	spin_lock_irq(&plo->lock);

	ret = get_event_locked(plo);
	if (ret) {
		spin_unlock_irq(&plo->lock);
		return ret;
	}

	prepare_to_wait(&plo->event_waitq, &_wait, TASK_INTERRUPTIBLE);
	spin_unlock_irq(&plo->lock);
	schedule();
	spin_lock_irq(&plo->lock);
	finish_wait(&plo->event_waitq, &_wait);

	ret = get_event_locked(plo);

	spin_unlock_irq(&plo->lock);
	return ret;
}

static u32 show_open_count(struct ploop_device * plo)
{
	return atomic_read(&plo->open_count);
}

static ssize_t print_cookie(struct ploop_device * plo, char * page)
{
	return sprintf(page, "%s\n", plo->cookie);
}

static ssize_t print_push_backup_uuid(struct ploop_device * plo, char * page)
{
	__u8 uuid[16];
	int err;

	mutex_lock(&plo->sysfs_mutex);
	err = ploop_pb_get_uuid(plo->pbd, uuid);
	mutex_unlock(&plo->sysfs_mutex);

	page[0] = '\0';
	if (err)
		return 0;

	return snprintf(page, PAGE_SIZE, "%pUB\n", uuid);
}

static u32 show_free_reqs(struct ploop_device * plo)
{
	return plo->free_qlen;
}

static u32 show_free_qmax(struct ploop_device * plo)
{
	return plo->free_qmax;
}

static u32 show_blockable_reqs(struct ploop_device * plo)
{
	return plo->blockable_reqs;
}

static u32 show_blocked_bios(struct ploop_device * plo)
{
	return plo->blocked_bios;
}

static u32 show_freeze_state(struct ploop_device * plo)
{
	return plo->freeze_state;
}

static u32 show_discard_mode(struct ploop_device *plo)
{
	/*
	 * 0 - discard disabled (not implemented)
	 * 1 - maintaince mode-based discard
	 * 2 - hole-based discard
	 * 3 - move-tail-block discard (not implemented)
	 */
	return test_bit(PLOOP_S_NO_FALLOC_DISCARD, &plo->state) ? 1 : 2;
}

#define _TUNE_U32(_name)				\
static u32 show_##_name(struct ploop_device * plo)	\
{							\
	return plo->tune._name;				\
}							\
							\
static int store_##_name(struct ploop_device * plo, u32 val) \
{							\
	plo->tune._name = val;				\
	return 0;					\
}

#define _TUNE_JIFFIES(_name)				\
static u32 show_##_name(struct ploop_device * plo)	\
{							\
	return (plo->tune._name * 1000) / HZ;		\
}							\
							\
static int store_##_name(struct ploop_device * plo, u32 val) \
{							\
	plo->tune._name = (val * HZ) / 1000;		\
	return 0;					\
}

#define _TUNE_BOOL	_TUNE_U32

_TUNE_U32(max_requests);
_TUNE_U32(batch_entry_qlen);
_TUNE_JIFFIES(batch_entry_delay);
_TUNE_U32(fsync_max);
_TUNE_JIFFIES(fsync_delay);
_TUNE_BOOL(pass_flushes);
_TUNE_BOOL(pass_fuas);
_TUNE_BOOL(congestion_detection);
_TUNE_BOOL(check_zeros);
_TUNE_U32(min_map_pages);
_TUNE_JIFFIES(max_map_inactivity);
_TUNE_BOOL(disable_root_threshold);
_TUNE_BOOL(disable_user_threshold);
_TUNE_U32(congestion_high_watermark);
_TUNE_U32(congestion_low_watermark);
_TUNE_U32(max_active_requests);
_TUNE_U32(push_backup_timeout);
_TUNE_BOOL(trusted);


struct pattr_sysfs_entry {
	struct attribute attr;
	u32 (*show)(struct ploop_device *);
	int (*store)(struct ploop_device *, __u32 val);
	ssize_t (*print)(struct ploop_device *, char *page);
};

#define _A(_name) \
&((struct pattr_sysfs_entry){ .attr = { .name = __stringify(_name), .mode = S_IRUGO }, .show = show_##_name, }).attr

#define _A2(_name) \
&((struct pattr_sysfs_entry){ .attr = { .name = __stringify(_name), .mode = S_IRUGO|S_IWUSR }, .show = show_##_name, .store = store_##_name, }).attr

#define _A3(_name)							\
&((struct pattr_sysfs_entry){ .attr = { .name = __stringify(_name), .mode = S_IRUGO }, .print = print_##_name, }).attr

static struct attribute *state_attributes[] = {
	_A(block_size),
	_A(fmt_version),
	_A(total_bios),
	_A(queued_bios),
	_A(discard_bios),
	_A(discard_inflight_bios),
	_A(active_reqs),
	_A(entry_reqs),
	_A(entry_read_sync_reqs),
	_A(barrier_reqs),
	_A(fastpath_reqs),
	_A(fsync_reqs),
	_A(map_pages),
	_A(running),
	_A(locked),
	_A2(aborted),
	_A(top),
	_A(event),
	_A3(cookie),
	_A3(push_backup_uuid),
	_A(open_count),
	_A(free_reqs),
	_A(free_qmax),
	_A(blockable_reqs),
	_A(blocked_bios),
	_A(freeze_state),
	_A(discard_mode),
	NULL
};

static struct attribute *tune_attributes[] = {
	_A2(max_requests),
	_A2(batch_entry_qlen),
	_A2(batch_entry_delay),
	_A2(fsync_max),
	_A2(fsync_delay),
	_A2(min_map_pages),
	_A2(max_map_inactivity),
	_A2(pass_flushes),
	_A2(pass_fuas),
	_A2(congestion_detection),
	_A2(check_zeros),
	_A2(disable_root_threshold),
	_A2(disable_user_threshold),
	_A2(congestion_high_watermark),
	_A2(congestion_low_watermark),
	_A2(max_active_requests),
	_A2(push_backup_timeout),
	_A2(discard_granularity),
	_A(discard_alignment),
	_A2(discard_zeroes_data),
	_A2(trusted),
	NULL
};

static const struct attribute_group state_group = {
	.attrs = state_attributes,
};

static const struct attribute_group tune_group = {
	.attrs = tune_attributes,
};

static ssize_t
pattr_show(struct kobject *kobj, struct attribute *attr, char *page)
{
	struct pattr_sysfs_entry *entry = container_of(attr, struct pattr_sysfs_entry, attr);
	struct gendisk *disk = to_disk(kobj->parent);
	struct ploop_device * plo = disk->private_data;
	u32 val;

	if (entry->print)
		return entry->print(plo, page);

	if (!entry->show)
		return -EIO;
	val = entry->show(plo);
	return sprintf(page, "%u\n", val);
}

static ssize_t
pattr_store(struct kobject *kobj, struct attribute *attr,
	    const char *page, size_t length)
{
	struct pattr_sysfs_entry *entry = container_of(attr, struct pattr_sysfs_entry, attr);
	struct gendisk *disk = to_disk(kobj->parent);
	struct ploop_device * plo = disk->private_data;
	char *p = (char *) page;
	unsigned long var;
	int err;

	if (!entry->store)
		return -EIO;

	var = simple_strtoul(p, &p, 10);

	err = entry->store(plo, var);
	return err ? : length;
}

static struct sysfs_ops pattr_sysfs_ops = {
	.show	= &pattr_show,
	.store	= &pattr_store,
};

static struct sysfs_ops pstat_sysfs_ops = {
	.show	= &pstat_show,
	.store	= &pstat_store,
};

static void pattr_release(struct kobject *kobj)
{
	kfree(kobj);
}

static struct kobj_type pattr_ktype = {
	.release	= pattr_release,
	.sysfs_ops	= &pattr_sysfs_ops,
};

static struct kobj_type pstat_ktype = {
	.release	= pattr_release,
	.sysfs_ops	= &pstat_sysfs_ops,
};

struct kobject *kobject_add_attr(struct gendisk *gd, const char *name,
				 struct kobj_type * type)
{
	struct kobject *k;
	int err;
	struct kobject * parent = &disk_to_dev(gd)->kobj;

	k = kzalloc(sizeof(*k), GFP_KERNEL);
	if (!k)
		return NULL;

	kobject_init(k, type);

	err = kobject_add(k, parent, "%s", name);
	if (err) {
		kobject_put(k);
		return NULL;
	}
	return k;
}

void ploop_sysfs_init(struct ploop_device * plo)
{
	plo->pstat_dir = kobject_add_attr(plo->disk, "pstat", &pstat_ktype);
	if (plo->pstat_dir) {
		if (sysfs_create_group(plo->pstat_dir, &stats_group))
			printk("ploop: were not able to create pstat dir\n");
	}
	plo->pstate_dir = kobject_add_attr(plo->disk, "pstate", &pattr_ktype);
	if (plo->pstate_dir) {
		if (sysfs_create_group(plo->pstate_dir, &state_group))
			printk("ploop: were not able to create pstate dir\n");
	}
	plo->ptune_dir = kobject_add_attr(plo->disk, "ptune", &pattr_ktype);
	if (plo->ptune_dir) {
		if (sysfs_create_group(plo->ptune_dir, &tune_group))
			printk("ploop: were not able to create ptune dir\n");
	}

	if (kobject_add(&plo->kobj, kobject_get(&disk_to_dev(plo->disk)->kobj), "%s", "pdelta"))
		printk("ploop: were not able to create pdelta dir\n");
}

void ploop_sysfs_uninit(struct ploop_device * plo)
{
	if (plo->pstat_dir) {
		sysfs_remove_group(plo->pstat_dir, &stats_group);
		kobject_del(plo->pstat_dir);
		kobject_put(plo->pstat_dir);
		plo->pstat_dir = NULL;
	}
	if (plo->pstate_dir) {
		sysfs_remove_group(plo->pstate_dir, &state_group);
		kobject_del(plo->pstate_dir);
		kobject_put(plo->pstate_dir);
		plo->pstate_dir = NULL;
	}
	if (plo->ptune_dir) {
		sysfs_remove_group(plo->ptune_dir, &tune_group);
		kobject_del(plo->ptune_dir);
		kobject_put(plo->ptune_dir);
		plo->ptune_dir = NULL;
	}
	kobject_del(&plo->kobj);

	kobject_put(&disk_to_dev(plo->disk)->kobj);
}
