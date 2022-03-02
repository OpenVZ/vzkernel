// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2021 Virtuozzo International GmbH. All rights reserved.
 */
#include <linux/prandom.h>
#include <linux/uio.h>

#include "dm.h"
#include "dm-qcow2.h"

static bool kernel_sets_dirty_bit; /* false */;
module_param(kernel_sets_dirty_bit, bool, 0444);
MODULE_PARM_DESC(kernel_sets_dirty_bit,
		"Dirty bit is set by kernel, not by userspace");

static struct kmem_cache *qrq_cache;

static void qcow2_set_service_operations(struct dm_target *ti, bool allowed)
{
	struct qcow2_target *tgt = to_qcow2_target(ti);

	mutex_lock(&tgt->ctl_mutex);
	tgt->service_operations_allowed = allowed;
	mutex_unlock(&tgt->ctl_mutex);
}
static void qcow2_set_wants_suspend(struct dm_target *ti, bool wants)
{
	struct qcow2_target *tgt = to_qcow2_target(ti);

	spin_lock_irq(&tgt->event_lock);
	tgt->wants_suspend = wants;
	spin_unlock_irq(&tgt->event_lock);
}

static int rw_pages_sync(unsigned int rw, struct qcow2 *qcow2,
			 u64 index, struct page *pages[], int nr)
{
	struct bio_vec *bvec, bvec_on_stack;
	ssize_t size = nr * PAGE_SIZE, ret;
	struct iov_iter iter;
	loff_t from, pos;
	int i;

	if (rw != READ && rw != WRITE)
		return -EINVAL;

	bvec = &bvec_on_stack;
	if (nr != 1)
		bvec = kmalloc(nr * sizeof(*bvec), GFP_NOIO);
	if (!bvec)
		return -ENOMEM;

	for (i = 0; i < nr; i++) {
		bvec[i].bv_page = pages[i];
		bvec[i].bv_len = PAGE_SIZE;
		bvec[i].bv_offset = 0;
	}

	iov_iter_bvec(&iter, rw, bvec, nr, size);
	pos = from = index << PAGE_SHIFT;

	if (rw == READ)
		ret = vfs_iter_read(qcow2->file, &iter, &pos, 0);
	else
		ret = vfs_iter_write(qcow2->file, &iter, &pos, 0);

	if (ret == size) {
		ret = 0;
	} else if (ret > 0 && pos == qcow2->file_size &&
		 from + size - qcow2->file_size < PAGE_SIZE) {
		/* Read near EOF? */
		zero_fill_page_from(pages[nr-1], ret % PAGE_SIZE);
		ret = 0;
	} else if (ret >= 0) {
		ret = -ENODATA;
	}

	if (bvec != &bvec_on_stack)
		kfree(bvec);
	return ret;
}

int rw_page_sync(unsigned int rw, struct qcow2 *qcow2,
		 u64 index, struct page *page)
{
	struct page *pages[] = {page};

	return rw_pages_sync(rw, qcow2, index, pages, 1);
}

static bool should_fail_rw(struct qcow2 *qcow2)
{
	u32 fault_injection = data_race(qcow2->fault_injection);

	if (likely(!fault_injection))
		return false;
	if (fault_injection < prandom_u32() % (100 * QCOW2_FAULT_RATIO))
		return false;
	return true;
}

static void qcow2_aio_do_completion(struct qio *qio)
{
	if (!atomic_dec_and_test(&qio->aio_ref))
		return;
	qio->complete(qio);
}

static void qcow2_aio_complete(struct kiocb *iocb, long ret, long ret2)
{
	struct qio *qio = container_of(iocb, struct qio, iocb);

	WARN_ON_ONCE(ret > INT_MAX);
	qio->ret = (int)ret;
	qcow2_aio_do_completion(qio);
}

void call_rw_iter(struct qcow2 *qcow2, loff_t pos, unsigned int rw,
		  struct iov_iter *iter, struct qio *qio)
{
	struct kiocb *iocb = &qio->iocb;
	struct file *file = qcow2->file;
	int ret;

	iocb->ki_pos = pos;
	iocb->ki_filp = file;
	iocb->ki_complete = qcow2_aio_complete;
	iocb->ki_flags = IOCB_DIRECT;
	iocb->ki_ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0);

	atomic_set(&qio->aio_ref, 2);

	if (unlikely(should_fail_rw(qcow2)))
		ret = -EIO;
	else if (rw == WRITE)
		ret = call_write_iter(file, iocb, iter);
	else
		ret = call_read_iter(file, iocb, iter);

	qcow2_aio_do_completion(qio);

	if (ret != -EIOCBQUEUED)
		iocb->ki_complete(iocb, ret, 0);
}

void free_md_page(struct md_page *md)
{
	WARN_ON_ONCE(md->wbd || md->lockd);
	put_page(md->page);
	kfree(md);
}

static void free_md_pages_tree(struct rb_root *root)
{
	struct rb_node *node;
	struct md_page *md;

	while ((node = root->rb_node) != NULL) {
		md = rb_entry(node, struct md_page, node);
		rb_erase(node, root);
		free_md_page(md);
	}
}

/* This flushes activity remaining after qios endio (delayed md pages wb */
void flush_deferred_activity(struct qcow2_target *tgt, struct qcow2 *qcow2)
{
	struct rb_node *node;
	struct md_page *md;
	int i;

	/*
	 * We need second iteration, since revert_clusters_alloc()
	 * may start timer again after failed wb.
	 */
	for (i = 0; i < 2; i++) {
		del_timer_sync(&qcow2->slow_wb_timer);
		slow_wb_timer_fn(&qcow2->slow_wb_timer);
		/* Start md writeback */
		flush_workqueue(tgt->wq);
		/* Wait AIO of md wb */
		qcow2_inflight_ref_switch(tgt);
	}

	spin_lock_irq(&qcow2->md_pages_lock);
	for (node = rb_first(&qcow2->md_pages);
	     node; node = rb_next(node)) {
		md = rb_entry(node, struct md_page, node);
		/* FIXME: call md_make_dirty() and try once again? */
		if (md->status & MD_WRITEBACK_ERROR) {
			pr_err("qcow2: Failed to write dirty pages\n");
			tgt->md_writeback_error = true;
			break;
		}
	}
	spin_unlock_irq(&qcow2->md_pages_lock);
}

static void flush_deferred_activity_all(struct qcow2_target *tgt)
{
	struct qcow2 *qcow2 = tgt->top;

	while (qcow2) {
		flush_deferred_activity(tgt, qcow2);
		qcow2 = qcow2->lower;
	}
}
static void free_md_pages_all(struct qcow2_target *tgt)
{
	struct qcow2 *qcow2 = tgt->top;

	while (qcow2) {
		free_md_pages_tree(&qcow2->md_pages);
		qcow2 = qcow2->lower;
	}
}

void qcow2_destroy(struct qcow2 *qcow2)
{
	int i;

	for (i = 0; i < QLIST_COUNT; i++)
		WARN(!list_empty(&qcow2->qios[i]),
		     "qcow2: list %d is not empty", i);

	WARN_ON(!list_empty(&qcow2->paused_qios) ||
		!list_empty(&qcow2->wb_batch_list) ||
		!list_empty(&qcow2->slow_wb_batch_list) ||
		timer_pending(&qcow2->slow_wb_timer));

	free_md_pages_tree(&qcow2->md_pages);
	if (qcow2->file)
		fput(qcow2->file);

	kfree(qcow2);
}

static void qcow2_tgt_destroy(struct qcow2_target *tgt)
{
	struct qcow2 *lower, *qcow2 = tgt->top;
	unsigned int i;

	if (tgt->wq) {
		/*
		 * All activity from DM bios are already done,
		 * since DM waits them. Complete our deferred:
		 */
		flush_deferred_activity_all(tgt);
		/* Now kill the queue */
		destroy_workqueue(tgt->wq);
	}

	mempool_destroy(tgt->qio_pool);
	mempool_destroy(tgt->qrq_pool);

	for (i = 0; i < 2; i++)
		percpu_ref_exit(&tgt->inflight_ref[i]);

	while (qcow2) {
		lower = qcow2->lower;
		qcow2_destroy(qcow2);
		qcow2 = lower;
	}

	kfree(tgt);
}

static struct md_page *__md_page_find(struct qcow2 *qcow2, unsigned int id)
{
	struct rb_node *node = qcow2->md_pages.rb_node;
	struct md_page *md;

	lockdep_assert_held(&qcow2->md_pages_lock);

	while (node) {
		md = rb_entry(node, struct md_page, node);
		if (id < md->id)
			node = node->rb_left;
		else if (id > md->id)
			node = node->rb_right;
		else
			return md;
	}

	return NULL;
}

static struct md_page *md_page_find(struct qcow2 *qcow2, unsigned int id)
{
	struct md_page *md;

	spin_lock_irq(&qcow2->md_pages_lock);
	md = __md_page_find(qcow2, id);
	spin_unlock_irq(&qcow2->md_pages_lock);
	return md;
}

/*
 * This returns md if it's found and up to date, or NULL.
 * @qio is zeroed if it's postponed.
 */
struct md_page *md_page_find_or_postpone(struct qcow2 *qcow2, unsigned int id,
					 struct qio **qio)
{
	struct md_page *md;

	spin_lock_irq(&qcow2->md_pages_lock);
	md = __md_page_find(qcow2, id);
	if (md && !(md->status & MD_UPTODATE)) {
		if (qio) {
			list_add_tail(&(*qio)->link, &md->wait_list);
			*qio = NULL;
		}
		md = NULL;
	}
	spin_unlock_irq(&qcow2->md_pages_lock);

	return md;
}

static void md_page_insert(struct qcow2 *qcow2, struct md_page *new_md)
{
	struct rb_root *root = &qcow2->md_pages;
	unsigned int new_id = new_md->id;
	struct rb_node *parent, **node;
	struct md_page *md;

	lockdep_assert_held(&qcow2->md_pages_lock);
	node = &root->rb_node;
	parent = NULL;

	while (*node) {
		parent = *node;
		md = rb_entry(*node, struct md_page, node);
		if (new_id < md->id)
			node = &parent->rb_left;
		else if (new_id > md->id)
			node = &parent->rb_right;
		else
			BUG();
	}

	rb_link_node(&new_md->node, parent, node);
	rb_insert_color(&new_md->node, root);
}

void md_page_erase(struct qcow2 *qcow2, struct md_page *md)
{
	lockdep_assert_held(&qcow2->md_pages_lock);
	rb_erase(&md->node, &qcow2->md_pages);
}

struct md_page *md_page_renumber(struct qcow2 *qcow2, unsigned int id,
						      unsigned int new_id)
{
	struct md_page *md;

	lockdep_assert_held(&qcow2->md_pages_lock);
	md = __md_page_find(qcow2, id);
	if (md) {
		WARN_ON_ONCE(!list_empty(&md->wait_list));
		md_page_erase(qcow2, md);
		md->id = new_id;
		md_page_insert(qcow2, md);
	}
	return md;
}

void zero_fill_page_from(struct page *page, unsigned int from)
{
	void *addr = kmap_atomic(page);

	memset(addr + from, 0, PAGE_SIZE - from);
	kunmap_atomic(addr);
}

int alloc_and_insert_md_page(struct qcow2 *qcow2, u64 index, struct md_page **md)
{
	int ret = -ENOMEM;

	*md = kmalloc(sizeof(**md), GFP_KERNEL);
	if (!*md)
		return -ENOMEM;
	(*md)->page = alloc_page(GFP_KERNEL);
	if (!(*md)->page)
		goto err_kfree;

	(*md)->id = index;
	(*md)->status = 0;
	(*md)->wbd = NULL;
	(*md)->lockd = NULL;
	atomic_set(&(*md)->wpc_readers, 0);
	(*md)->wpc_noread_count = 0;
	INIT_LIST_HEAD(&(*md)->wait_list);
	INIT_LIST_HEAD(&(*md)->wpc_readers_wait_list);
	INIT_LIST_HEAD(&(*md)->wb_link);

	spin_lock_irq(&qcow2->md_pages_lock);
	md_page_insert(qcow2, *md);
	spin_unlock_irq(&qcow2->md_pages_lock);
	return 0;

err_kfree:
	kfree(*md);
	return ret;
}

static void inflight_ref_exit0(struct percpu_ref *ref)
{
	struct qcow2_target *tgt = container_of(ref, struct qcow2_target,
						inflight_ref[0]);
	complete(&tgt->inflight_ref_comp);
}

static void inflight_ref_exit1(struct percpu_ref *ref)
{
	struct qcow2_target *tgt = container_of(ref, struct qcow2_target,
						inflight_ref[1]);
	complete(&tgt->inflight_ref_comp);
}

void ploop_enospc_timer(struct timer_list *timer)
{
	struct qcow2_target *tgt = from_timer(tgt, timer, enospc_timer);
	unsigned long flags;
	LIST_HEAD(list);

	spin_lock_irqsave(&tgt->event_lock, flags);
	list_splice_init(&tgt->enospc_qios, &list);
	spin_unlock_irqrestore(&tgt->event_lock, flags);

	submit_embedded_qios(tgt, &list);
}

static void qcow2_event_work(struct work_struct *ws)
{
	struct qcow2_target *tgt = container_of(ws, struct qcow2_target, event_work);

	dm_table_event(tgt->ti->table);
}

static struct qcow2_target *alloc_qcow2_target(struct dm_target *ti)
{
	percpu_ref_func_t *release;
	struct qcow2_target *tgt;
	unsigned int i, flags;

	tgt = kzalloc(sizeof(*tgt), GFP_KERNEL);
	if (!tgt)
		return NULL;
	tgt->qrq_pool = mempool_create_slab_pool(QCOW2_QRQ_POOL_SIZE,
						 qrq_cache);
	tgt->qio_pool = mempool_create_kmalloc_pool(MIN_QIOS,
						    sizeof(struct qio));
	if (!tgt->qrq_pool || !tgt->qio_pool) {
		ti->error = "Can't create mempool";
		goto out_target;
	}

	flags = WQ_MEM_RECLAIM|WQ_HIGHPRI|WQ_UNBOUND;
	tgt->wq = alloc_workqueue("dm-" DM_MSG_PREFIX, flags, 0);
	if (!tgt->wq) {
		ti->error = "Can't create workqueue";
		goto out_pool;
	}

	for (i = 0; i < 2; i++) {
		release = i ? inflight_ref_exit1 : inflight_ref_exit0;
		if (percpu_ref_init(&tgt->inflight_ref[i], release,
				    PERCPU_REF_ALLOW_REINIT, GFP_KERNEL)) {
			if (i)
				percpu_ref_exit(&tgt->inflight_ref[0]);
			ti->error = "could not alloc percpu_ref";
			goto out_wq;
		}
	}

	init_completion(&tgt->inflight_ref_comp);
	spin_lock_init(&tgt->event_lock);
	mutex_init(&tgt->ctl_mutex);
	init_waitqueue_head(&tgt->service_wq);
	INIT_WORK(&tgt->event_work, qcow2_event_work);
	INIT_LIST_HEAD(&tgt->enospc_qios);
	timer_setup(&tgt->enospc_timer, ploop_enospc_timer, 0);
	ti->private = tgt;
	tgt->ti = ti;
	qcow2_set_service_operations(ti, false);

	return tgt;
out_wq:
	destroy_workqueue(tgt->wq);
out_pool:
	mempool_destroy(tgt->qio_pool);
	mempool_destroy(tgt->qrq_pool);
out_target:
	kfree(tgt);
	return NULL;
}

static int qcow2_check_convert_hdr(struct dm_target *ti,
				   struct QCowHeader *raw_hdr,
				   struct QCowHeader *hdr,
				   u64 min_len, u64 max_len)
{
	bool ext_l2, is_ro;
	u32 clu_size;

	hdr->magic = cpu_to_be32(raw_hdr->magic);
	hdr->version = be32_to_cpu(raw_hdr->version);
	hdr->cluster_bits = be32_to_cpu(raw_hdr->cluster_bits);
	hdr->size = be64_to_cpu(raw_hdr->size);
	/*
	 * In this driver we never check userspace passed correct backing
	 * file fd, since it's impossible: here can be name of a symlink.
	 */
	hdr->backing_file_offset = be64_to_cpu(raw_hdr->backing_file_offset);
	hdr->backing_file_size = be32_to_cpu(raw_hdr->backing_file_size);
	hdr->crypt_method = be32_to_cpu(raw_hdr->crypt_method);
	hdr->l1_size = be32_to_cpu(raw_hdr->l1_size);
	hdr->l1_table_offset = be64_to_cpu(raw_hdr->l1_table_offset);
	hdr->refcount_table_offset = be64_to_cpu(raw_hdr->refcount_table_offset);
	hdr->refcount_table_clusters = be32_to_cpu(raw_hdr->refcount_table_clusters);
	hdr->nb_snapshots = be32_to_cpu(raw_hdr->nb_snapshots);
	hdr->snapshots_offset = be64_to_cpu(raw_hdr->snapshots_offset);

	clu_size = 1 << hdr->cluster_bits;
	if (hdr->size < min_len || hdr->size > max_len ||
	    /* Note, we do not extend L1 table: */
	    (u64)hdr->l1_size * clu_size / sizeof(u64) * clu_size < min_len)
		return -EBADSLT;

	if (hdr->magic != QCOW_MAGIC || hdr->version < 2 || hdr->version > 3 ||
	    (hdr->l1_table_offset & (clu_size - 1)) ||
	    hdr->cluster_bits < 9 || hdr->cluster_bits > 21 ||
	    (hdr->refcount_table_offset & (clu_size - 1)))
		return -EINVAL;

	if (hdr->crypt_method != 0)
		return -EOPNOTSUPP;

	hdr->refcount_order = 4;

	if (hdr->version == 2)
		return 0;

	hdr->incompatible_features = be64_to_cpu(raw_hdr->incompatible_features);
	hdr->autoclear_features = be64_to_cpu(raw_hdr->autoclear_features);
	hdr->refcount_order = be32_to_cpu(raw_hdr->refcount_order);
	hdr->header_length = be32_to_cpu(raw_hdr->header_length);

	is_ro = !(dm_table_get_mode(ti->table) & FMODE_WRITE);

//	if (!is_ro && kernel_sets_dirty_bit !=
//	    !(hdr->incompatible_features & INCOMPATIBLE_FEATURES_DIRTY_BIT))
//		return kernel_sets_dirty_bit ? -EUCLEAN : -ENOLCK;
	if (hdr->incompatible_features &
	    ~(INCOMPATIBLE_FEATURES_EXTL2_BIT|INCOMPATIBLE_FEATURES_DIRTY_BIT))
		return -EOPNOTSUPP;
	ext_l2 = hdr->incompatible_features & INCOMPATIBLE_FEATURES_EXTL2_BIT;

	if (hdr->refcount_order > 6 || (ext_l2 && hdr->cluster_bits < 14))
		return -EINVAL;

	if (hdr->header_length < offsetof(struct QCowHeader, compression_type))
		return -EINVAL;

	if (hdr->header_length < offsetof(struct QCowHeader, padding))
		return 0;

	hdr->compression_type = (u8)raw_hdr->compression_type;
	if (hdr->compression_type != (u8)0)
		return -EOPNOTSUPP;

	return 0;
}

void calc_cached_parameters(struct qcow2 *qcow2, struct QCowHeader *hdr)
{
	s64 clu_size, reftable_clus = hdr->refcount_table_clusters;
	loff_t pos, tmp, max;

	qcow2->clu_size = clu_size = 1 << hdr->cluster_bits;
	qcow2->ext_l2 = hdr->incompatible_features & INCOMPATIBLE_FEATURES_EXTL2_BIT;
	if (qcow2->ext_l2)
		qcow2->subclu_size = clu_size / 32;
	qcow2->l2_entries = clu_size / (sizeof(u64) * (1 + qcow2->ext_l2));
	qcow2->refblock_bits = 1 << hdr->refcount_order;
	qcow2->refblock_entries = clu_size * 8 / qcow2->refblock_bits;
	pos = div64_s64(PAGE_SIZE * 8ULL, qcow2->refblock_bits) * clu_size;
	qcow2->r2_page_covered_file_size = pos;
	max = round_down(LLONG_MAX, clu_size);
	tmp = div64_s64(reftable_clus * qcow2->refblock_entries, sizeof(u64));
	if (div64_s64(max, (u64)clu_size * clu_size) >= tmp) {
		tmp = div64_s64(reftable_clus * clu_size, sizeof(u64));
		pos = tmp * qcow2->refblock_entries * clu_size;
	} else {
		pos = max;
	}
	qcow2->reftable_max_file_size = pos;
}

int qcow2_set_image_file_features(struct qcow2 *qcow2, bool dirty)
{
	u64 dirty_mask = cpu_to_be64(INCOMPATIBLE_FEATURES_DIRTY_BIT);
	struct QCowHeader *raw_hdr;
	struct md_page *md;
	bool is_ro;

	if (qcow2->hdr.version ==  2)
		return 0;

	is_ro = !(dm_table_get_mode(qcow2->tgt->ti->table) & FMODE_WRITE);
	if (is_ro)
		return 0;

	md = md_page_find(qcow2, 0);
	if (WARN_ON_ONCE(!md || !(md->status & MD_UPTODATE)))
		return -EIO;

	raw_hdr = kmap(md->page);
	qcow2->hdr.autoclear_features = raw_hdr->autoclear_features = 0;
	if (kernel_sets_dirty_bit) {
		if (dirty)
			raw_hdr->incompatible_features |= dirty_mask;
		else
			raw_hdr->incompatible_features &= ~dirty_mask;
	}
	kunmap(md->page);

	return rw_page_sync(WRITE, qcow2, md->id, md->page);
}

static struct qcow2 *qcow2_alloc_delta(struct qcow2_target *tgt, struct qcow2 *upper)
{
	struct qcow2 *qcow2;
	int i;

	qcow2 = kzalloc(sizeof(*qcow2), GFP_KERNEL);
	if (!qcow2)
		return ERR_PTR(-ENOMEM);
	qcow2->tgt = tgt;

	for (i = 0; i < QLIST_COUNT; i++)
		INIT_LIST_HEAD(&qcow2->qios[i]);
	INIT_LIST_HEAD(&qcow2->resubmit_qios);
	INIT_LIST_HEAD(&qcow2->paused_qios);
	INIT_LIST_HEAD(&qcow2->wb_batch_list);
	INIT_LIST_HEAD(&qcow2->slow_wb_batch_list);
	spin_lock_init(&qcow2->deferred_lock);
	spin_lock_init(&qcow2->md_pages_lock);
	timer_setup(&qcow2->slow_wb_timer, slow_wb_timer_fn, 0);
	INIT_WORK(&qcow2->worker, do_qcow2_work);
	INIT_WORK(&qcow2->fsync_worker, do_qcow2_fsync_work);

	if (upper)
		upper->lower = qcow2;
	else /* Top delta */
		tgt->top = qcow2;

	return qcow2;
}

static int qcow2_attach_file(struct dm_target *ti, struct qcow2_target *tgt,
			     struct qcow2 *qcow2, int fd)
{
	struct file *file;
	fmode_t mode;

	file = qcow2->file = fget(fd);
	if (!file) /* In case of further errors, cleanup is made by caller */
		return -ENOENT;

	if (!S_ISREG(file_inode(file)->i_mode))
		return -EINVAL;

	mode = tgt->top != qcow2 ? FMODE_READ : dm_table_get_mode(ti->table);
	mode &= (FMODE_READ|FMODE_WRITE);
	if (mode & ~(file->f_mode & (FMODE_READ|FMODE_WRITE)))
		return -EACCES;

	return 0;
}

static int qcow2_parse_header(struct dm_target *ti, struct qcow2 *qcow2,
			      struct qcow2 *upper, bool is_bottom)
{
	struct QCowHeader *raw_hdr, *hdr = &qcow2->hdr;
	loff_t min_len, max_len, new_size;
	struct file *file = qcow2->file;
	struct md_page *md;
	int ret;

	qcow2->file_size = i_size_read(file_inode(file));
	if ((file->f_mode & FMODE_WRITE) && (qcow2->file_size & ~PAGE_MASK)) {
		new_size = PAGE_ALIGN(qcow2->file_size);
		ret = qcow2_truncate_safe(file, new_size);
		if (ret) {
			pr_err("qcow2: Can't truncate file\n");
			return ret;
		} /* See md_page_read_complete() */
		qcow2->file_size = new_size;
	}
	qcow2->file_preallocated_area_start = qcow2->file_size;

	ret = alloc_and_insert_md_page(qcow2, 0, &md);
	if (ret)
		return ret;
	ret = rw_page_sync(READ, qcow2, md->id, md->page);
	if (ret)
		return ret;
	md->status |= MD_UPTODATE;

	raw_hdr = kmap(md->page);
	min_len = to_bytes(ti->len);
	max_len = LLONG_MAX;
	if (upper) {
		min_len = PAGE_SIZE;
		max_len = upper->hdr.size;
	}
	ret = qcow2_check_convert_hdr(ti, raw_hdr, hdr, min_len, max_len);
	kunmap(md->page);
	if (ret < 0)
		goto out;

	calc_cached_parameters(qcow2, hdr);
	ret = -EOPNOTSUPP;
	if (qcow2->clu_size < PAGE_SIZE ||
	    (qcow2->ext_l2 && qcow2->clu_size < PAGE_SIZE * 32))
		goto out;
	ret = -EXDEV;
	if (upper && (upper->clu_size != qcow2->clu_size ||
		      upper->ext_l2 != qcow2->ext_l2))
		goto out; /* This is not supported yet */
	ret = -ENOENT;
	if (is_bottom && qcow2->hdr.backing_file_offset)
		goto out;
	qcow2->free_cluster_search_pos = qcow2->clu_size * 1;

	ret = -EFBIG;
	if (qcow2->reftable_max_file_size < qcow2->file_size)
		goto out;
	ret = 0;
out:
	return ret;
}

static int qcow2_parse_metadata(struct dm_target *ti, struct qcow2_target *tgt)
{
	unsigned int i, nr_images = tgt->top->img_id + 1;
	struct qcow2 *qcow2, *upper = NULL;
	int ret;

	qcow2 = top_qcow2_protected(ti);
	for (i = 0; i < nr_images; i++) {
		ret = -ENOENT;
		if (!qcow2)
			goto out;

		ret = qcow2_parse_header(ti, qcow2, upper, i == nr_images - 1);
		if (ret)
			goto out;

		upper = qcow2;
		qcow2 = qcow2->lower;
	}

	ret = 0;
out:
	if (ret)
		pr_err("dm-qcow2: Can't parse metadata\n");
	return ret;
}

static int qcow2_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct qcow2 *qcow2, *upper = NULL;
	struct qcow2_target *tgt;
	int i, fd, ret;

	if (argc < 1 || ti->begin != 0)
		return -EINVAL;

	tgt = alloc_qcow2_target(ti);
	if (!tgt)
		return -ENOMEM;
	/*
	 * Userspace passes deltas in bottom, ..., top order,
	 * but we attach it vise versa: from top to bottom.
	 */
	for (i = argc - 1; i >= 0; i--) {
		ret = -EINVAL;
		if (kstrtos32(argv[i], 10, &fd) < 0) {
			ti->error = "Wrong fd";
			goto err;
		}

		qcow2 = qcow2_alloc_delta(tgt, upper);
		if (IS_ERR(qcow2)) {
			ret = PTR_ERR(qcow2);
			goto err;
		}
		qcow2->img_id = i;

		ret = qcow2_attach_file(ti, tgt, qcow2, fd);
		if (ret) {
			ti->error = "Error attaching file";
			goto err;
		}

		upper = qcow2;
	}

	ret = qcow2_parse_metadata(ti, tgt);
	if (ret)
		goto err;

	ti->flush_supported = true;
	ti->num_flush_bios = 1;
	ti->discards_supported = true;
	ti->num_discard_bios = 1;
	return 0;
err:
	qcow2_tgt_destroy(tgt);
	return ret;
}

static void qcow2_dtr(struct dm_target *ti)
{
	struct qcow2_target *tgt = to_qcow2_target(ti);

	qcow2_tgt_destroy(tgt);
}

static void qcow2_truncate_preallocations(struct dm_target *ti)
{
	struct qcow2_target *tgt = to_qcow2_target(ti);
	struct qcow2 *qcow2 = top_qcow2_protected(ti);
	loff_t end = qcow2->file_preallocated_area_start;
	int ret;

	if (!(dm_table_get_mode(ti->table) & FMODE_WRITE))
		return;
	if (end == qcow2->file_size)
		return;

	ret = qcow2_truncate_safe(qcow2->file, end);
	if (ret) {
		pr_err("dm-qcow2: Can't truncate preallocations\n");
		tgt->truncate_error = true;
		return;
	}

	qcow2->file_preallocated_area_start = end;
	qcow2->file_size = end;
}

static void qcow2_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct qcow2 *qcow2 = top_qcow2_protected(ti);
	unsigned int block_size = 512;
	struct super_block *sb;

	sb = file_inode(qcow2->file)->i_sb;
	if (sb->s_bdev)
		block_size = bdev_logical_block_size(sb->s_bdev);
	/*
	 * Even if this is less than discard_granularity of bdev,
	 * we can free a block on filesystem.
	 */
	limits->discard_granularity = sb->s_blocksize;
	limits->max_discard_sectors = to_sector(qcow2->clu_size);

	limits->logical_block_size = block_size;
	limits->physical_block_size = block_size;

	blk_limits_io_min(limits, block_size);
	blk_limits_io_opt(limits, qcow2->clu_size);
}

static void qcow2_status(struct dm_target *ti, status_type_t type,
			 unsigned int status_flags, char *result,
			 unsigned int maxlen)
{
	struct qcow2_target *tgt = to_qcow2_target(ti);
	struct QCowHeader *hdr;
	unsigned int sz = 0;
	struct qcow2 *qcow2;
	u8 ref_index;

	qcow2 = qcow2_ref_inc(tgt, &ref_index);
	hdr = &qcow2->hdr;
	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;
	case STATUSTYPE_TABLE:
		DMEMIT("%u v%u %llu", qcow2->img_id + 1, hdr->version,
				      to_sector(qcow2->clu_size));
		break;
	case STATUSTYPE_IMA:
		result[0] = '\0';
		break;
	}
	qcow2_ref_dec(tgt, ref_index);
}

static void qcow2_presuspend(struct dm_target *ti)
{
	struct qcow2_target *tgt = to_qcow2_target(ti);

	qcow2_set_service_operations(ti, false);
	qcow2_set_wants_suspend(ti, true);
	del_timer_sync(&tgt->enospc_timer);
	ploop_enospc_timer(&tgt->enospc_timer);
}
static void qcow2_presuspend_undo(struct dm_target *ti)
{
	qcow2_set_wants_suspend(ti, false);
	qcow2_set_service_operations(ti, true);
}
static void qcow2_postsuspend(struct dm_target *ti)
{
	struct qcow2 *qcow2 = top_qcow2_protected(ti);
	int ret;

	flush_deferred_activity_all(to_qcow2_target(ti));
	qcow2_truncate_preallocations(ti);

	if (dm_table_get_mode(ti->table) & FMODE_WRITE) {
		ret = qcow2_set_image_file_features(qcow2, false);
		if (ret)
			pr_err("qcow2: Can't set features\n");
	}
}
static int qcow2_preresume(struct dm_target *ti)
{
	struct qcow2_target *tgt = to_qcow2_target(ti);
	int ret = 0;

	if (qcow2_wants_check(tgt)) {
		pr_err("qcow2: image check and target reload are required\n");
		return -EIO;
	}

	free_md_pages_all(tgt);
	/*
	 * Reading metadata here allows userspace to modify images
	 * of suspended device without reloading target. We also
	 * want to do this in .ctr to break device creation early
	 * if images are not valid.
	 */
	ret = qcow2_parse_metadata(ti, tgt);
	if (ret)
		return ret;
	/*
	 * Despite .preresume has no undo, our target is singleton,
	 * so we can set features uncoditionally here.
	 */
	if (dm_table_get_mode(ti->table) & FMODE_WRITE) {
		ret = qcow2_set_image_file_features(tgt->top, true);
		if (ret)
			pr_err("qcow2: Can't set features\n");
	}
	if (!ret)
		qcow2_set_wants_suspend(ti, false);

	return ret;
}
static void qcow2_resume(struct dm_target *ti)
{
	qcow2_set_service_operations(ti, true);
}

static struct target_type qcow2_target = {
	.name = "qcow2",
	.version = {1, 0, 0},
	.features = DM_TARGET_SINGLETON,
	.module = THIS_MODULE,
	.ctr = qcow2_ctr,
	.dtr = qcow2_dtr,
	.io_hints = qcow2_io_hints,
	.status = qcow2_status,
	.presuspend = qcow2_presuspend,
	.presuspend_undo = qcow2_presuspend_undo,
	.postsuspend = qcow2_postsuspend,
	.preresume = qcow2_preresume,
	.resume = qcow2_resume,
	.clone_and_map_rq = qcow2_clone_and_map,
	.message = qcow2_message,
};

static int __init dm_qcow2_init(void)
{
	int ret;

	qrq_cache = kmem_cache_create("qcow2-qrq", sizeof(struct qcow2_rq) +
				      sizeof(struct qio), 0, 0, NULL);
	if (!qrq_cache)
		return -ENOMEM;

	ret = dm_register_target(&qcow2_target);
	if (ret)
		kmem_cache_destroy(qrq_cache);

	return ret;
}

static void __exit dm_qcow2_exit(void)
{
	dm_unregister_target(&qcow2_target);
	kmem_cache_destroy(qrq_cache);
}

module_init(dm_qcow2_init);
module_exit(dm_qcow2_exit);

MODULE_DESCRIPTION("QCOW2 block device driver");
MODULE_AUTHOR("Kirill Tkhai <ktkhai@virtuozzo.com>");
MODULE_LICENSE("GPL");
