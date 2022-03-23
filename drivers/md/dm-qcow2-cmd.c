// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 2021 Virtuozzo International GmbH. All rights reserved.
 */
#include <linux/device-mapper.h>
#include <linux/sched/signal.h>
#include <linux/file.h>
#include "dm-qcow2.h"

#define SERVICE_QIOS_MAX 64

static int qcow2_get_errors(struct qcow2_target *tgt, char *result,
			    unsigned int maxlen)
{
	bool wants_check = qcow2_wants_check(tgt);
	unsigned int sz = 0;
	int ret;

	ret = DMEMIT("wants_check=%d\nmd_writeback_error=%d\ntruncate_error=%d\n",
		      wants_check, tgt->md_writeback_error, tgt->truncate_error);

	return ret ? 1 : 0;
}

int qcow2_inflight_ref_switch(struct qcow2_target *tgt)
{
	struct completion *comp = &tgt->inflight_ref_comp;
	u8 ref_index = tgt->inflight_ref_index;

	tgt->inflight_ref_index = !ref_index;

	percpu_ref_kill(&tgt->inflight_ref[ref_index]);
	wait_for_completion(comp);

	percpu_ref_reinit(&tgt->inflight_ref[ref_index]);
	reinit_completion(comp);
	return 0;
}

static void service_qio_endio(struct qcow2_target *tgt, struct qio *qio,
			      void *data, blk_status_t status)
{
	blk_status_t *status_ptr = data;

	if (unlikely(status)) {
		WRITE_ONCE(*status_ptr, status);
		smp_wmb(); /* Pairs with smp_rmb() in qcow2_service_iter() */
	}

	atomic_dec(&tgt->service_qios);
	wake_up(&tgt->service_wq);
}

static int qcow2_service_iter(struct qcow2_target *tgt, struct qcow2 *qcow2,
			      loff_t end, loff_t step, u8 qio_flags)
{
	static blk_status_t service_status;
	struct bio_vec bvec = {0};
	struct qio *qio;
	int ret = 0;
	loff_t pos;

	WRITE_ONCE(service_status, BLK_STS_OK);

	for (pos = 0; pos < end; pos += step) {
		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		qio = alloc_qio(tgt->qio_pool, true);
		if (!qio) {
			ret = -ENOMEM;
			break;
		}

		/* See fake_merge_qio() and fake_l1cow_qio() */
		init_qio(qio, REQ_OP_WRITE, qcow2);
		qio->flags |= qio_flags|QIO_FREE_ON_ENDIO_FL;
		qio->bi_io_vec = &bvec;
		qio->bi_iter.bi_sector = to_sector(pos);
		qio->bi_iter.bi_size = 0;
		qio->bi_iter.bi_idx = 0;
		qio->bi_iter.bi_bvec_done = 0;
		qio->endio_cb = service_qio_endio;
		qio->endio_cb_data = &service_status;

		dispatch_qios(qcow2, qio, NULL);
		if (atomic_inc_return(&tgt->service_qios) == SERVICE_QIOS_MAX) {
			wait_event(tgt->service_wq,
				   atomic_read(&tgt->service_qios) < SERVICE_QIOS_MAX);
		}

		if (unlikely(READ_ONCE(service_status)))
			break;
	}

	wait_event(tgt->service_wq, !atomic_read(&tgt->service_qios));
	if (!ret) {
		smp_rmb(); /* Pairs with smp_wmb() in service_qio_endio() */
		ret = blk_status_to_errno(READ_ONCE(service_status));
	}

	return ret;
}

static int qcow2_merge_common(struct qcow2_target *tgt)
{
	struct qcow2 *qcow2 = tgt->top, *lower = qcow2->lower;
	u32 clu_size = qcow2->clu_size;
	loff_t end = lower->hdr.size;

	return qcow2_service_iter(tgt, qcow2, end, clu_size, QIO_IS_MERGE_FL);
}

/*
 * Forward merge is a simple COW simulation in every clu.
 * After that, all mapped clus from lower delta become
 * mapped in top delta. Then, userspace may remove lower
 * delta from the deltas stack (and it also has to update
 * backing file name in top delta's metadata).
 */
static int qcow2_merge_forward(struct qcow2_target *tgt)
{
	return -ENOTTY; /* TODO */
}

static int qcow2_break_l1cow(struct qcow2_target *tgt)
{
	struct qcow2 *qcow2 = tgt->top;
	loff_t end = qcow2->hdr.size;
	loff_t step = (u64)qcow2->l2_entries * qcow2->clu_size;

	return qcow2_service_iter(tgt, qcow2, end, step, QIO_IS_L1COW_FL);
}

static void set_backward_merge_in_process(struct qcow2_target *tgt,
				     struct qcow2 *qcow2, bool set)
{
	LIST_HEAD(list);

	/*
	 * To avoid race between allocations and COWS
	 * we completely stop queueing qios and wait
	 * for pending qios. Lock is for visability.
	 */
	spin_lock_irq(&qcow2->deferred_lock);
	qcow2->pause_submitting_qios = true;
	spin_unlock_irq(&qcow2->deferred_lock);
	qcow2_inflight_ref_switch(tgt);

	/* queue is stopped */
	spin_lock_irq(&qcow2->deferred_lock);
	WARN_ON_ONCE(qcow2->backward_merge_in_process == set);
	qcow2->backward_merge_in_process = set;
	qcow2->pause_submitting_qios = false;
	list_splice_init(&qcow2->paused_qios, &list);
	spin_unlock_irq(&qcow2->deferred_lock);

	submit_embedded_qios(tgt, &list);
}

static int qcow2_merge_backward(struct qcow2_target *tgt)
{
	struct qcow2 *qcow2 = tgt->top, *lower = qcow2->lower;
	int ret, ret2;

	ret = -ENOENT;
	if (!lower)
		goto out;
	ret = -EACCES;
	if (!(lower->file->f_mode & FMODE_WRITE))
		goto out;
	ret = -EOPNOTSUPP;
	if (qcow2->clu_size != lower->clu_size)
		goto out;
	ret = -EBADSLT;
	if (lower->hdr.size < qcow2->hdr.size)
		goto out;
	/*
	 * Break all COW clus at L1 level. Otherwise, later
	 * there would be problems with unusing them:
	 * we'd have to freeze IO going to all data clusters
	 * under every L1 entry related to several snapshots.
	 */
	ret = qcow2_break_l1cow(tgt);
	if (ret) {
		pr_err("dm-qcow2: Can't break L1 COW\n");
		goto out;
	}

	ret = qcow2_set_image_file_features(lower, true);
	if (ret) {
		pr_err("dm-qcow2: Can't set dirty bit\n");
		goto out;
	}
	set_backward_merge_in_process(tgt, qcow2, true);

	/* Start merge */
	ret = qcow2_merge_common(tgt);
	if (ret) {
		set_backward_merge_in_process(tgt, qcow2, false);
		ret2 = qcow2_set_image_file_features(lower, false);
		if (ret2 < 0)
			pr_err("dm-qcow2: Can't unuse lower (%d)\n", ret2);
		goto out;
	}
	tgt->top = lower;
	smp_wmb(); /* Pairs with qcow2_ref_inc() */
	qcow2_inflight_ref_switch(tgt); /* Pending qios */
	flush_deferred_activity(tgt, qcow2); /* Delayed md pages */
	qcow2->lower = NULL;

	ret2 = qcow2_set_image_file_features(qcow2, false);
	if (ret2 < 0)
		pr_err("dm-qcow2: Can't unuse merged img (%d)\n", ret2);
	qcow2_destroy(qcow2);
out:
	return ret;
}

static struct qcow2 *qcow2_get_img(struct qcow2_target *tgt, u32 img_id, u8 *ref_index)
{
	struct qcow2 *qcow2;

	qcow2 = qcow2_ref_inc(tgt, ref_index);

	while (qcow2->img_id > img_id)
		qcow2 = qcow2->lower;

	if (qcow2->img_id != img_id) {
		qcow2_ref_dec(tgt, *ref_index);
		return NULL;
	}
	return qcow2;
}

static int qcow2_get_img_fd(struct qcow2_target *tgt, u32 img_id,
			    char *result, unsigned int maxlen)
{
	struct qcow2 *qcow2;
	unsigned int sz = 0;
	u8 ref_index;
	int fd, ret;

	qcow2 = qcow2_get_img(tgt, img_id, &ref_index);
	if (!qcow2) {
		result[0] = 0; /* empty output */
		return 1;
	}

	ret = fd = get_unused_fd_flags(0);
	if (fd < 0)
		goto out_ref_dec;

	if (DMEMIT("%d\n", fd) == 0) {
		/* Not enough space in @result */
		ret = 0;
		put_unused_fd(fd);
		goto out_ref_dec;
	}

	ret = 1;
	fd_install(fd, get_file(qcow2->file));
out_ref_dec:
	qcow2_ref_dec(tgt, ref_index);
	return ret;
}

static int qcow2_get_img_name(struct qcow2_target *tgt, u32 img_id,
			      char *result, unsigned int maxlen)
{
	struct qcow2 *qcow2;
	u8 ref_index;
	char *p;
	int ret;

	qcow2 = qcow2_get_img(tgt, img_id, &ref_index);
	if (!qcow2) {
		result[0] = 0; /* empty output */
		return 1;
	}

	p = file_path(qcow2->file, result, maxlen - 1);
	if (IS_ERR(p)) {
		ret = PTR_ERR(p);
		if (PTR_ERR(p) == -ENAMETOOLONG)
			ret = 0; /* dm should pass bigger buffer */
		goto out_ref_dec;
	}

	ret = strlen(p);
	memmove(result, p, ret);
	result[ret] = 0;
	ret = 1;
out_ref_dec:
	qcow2_ref_dec(tgt, ref_index);
	return ret;
}

static int qcow2_set_fault_injection(struct qcow2_target *tgt,
				     u32 img_id, u32 ratio)
{
	struct qcow2 *qcow2;
	u8 ref_index;

	if (ratio > 100 * QCOW2_FAULT_RATIO)
		return -EINVAL;

	qcow2 = qcow2_get_img(tgt, img_id, &ref_index);
	if (!qcow2)
		return -ENOENT;

	qcow2->fault_injection = ratio; /* Unlocked */
	qcow2_ref_dec(tgt, ref_index);
	return 0;
}

static int qcow2_get_event(struct qcow2_target *tgt, char *result, unsigned int maxlen)
{
	unsigned int sz = 0;
	int ret = 0;

	spin_lock_irq(&tgt->event_lock);
	if (tgt->event_enospc) {
		ret = (DMEMIT("event_ENOSPC\n")) ? 1 : 0;
		if (ret)
			tgt->event_enospc = false;
	}
	spin_unlock_irq(&tgt->event_lock);

	return ret;
}

int qcow2_message(struct dm_target *ti, unsigned int argc, char **argv,
		  char *result, unsigned int maxlen)
{
	struct qcow2_target *tgt = to_qcow2_target(ti);
	int ret = -EPERM;
	u32 val, val2;

	if (!capable(CAP_SYS_ADMIN))
		goto out;

	ret = -EINVAL;
	if (argc < 1)
		goto out;

	if (!strcmp(argv[0], "get_img_fd")) {
		if (argc != 2 || kstrtou32(argv[1], 10, &val)) {
			ret = -EINVAL;
			goto out;
		}
		ret = qcow2_get_img_fd(tgt, val, result, maxlen);
		goto out;
	} else if (!strcmp(argv[0], "get_img_name")) {
		if (argc != 2 || kstrtou32(argv[1], 10, &val)) {
			ret = -EINVAL;
			goto out;
		}
		ret = qcow2_get_img_name(tgt, val, result, maxlen);
		goto out;
	} else if (!strcmp(argv[0], "set_fault_injection")) {
		if (argc != 3 || kstrtou32(argv[1], 10, &val) ||
				 kstrtou32(argv[2], 10, &val2)) {
			ret = -EINVAL;
			goto out;
		}
		ret = qcow2_set_fault_injection(tgt, val, val2);
		goto out;
	} else if (!strcmp(argv[0], "get_event")) {
		if (argc != 1) {
			ret = -EINVAL;
			goto out;
		}
		ret = qcow2_get_event(tgt, result, maxlen);
		goto out;
	}

	ret = mutex_lock_killable(&tgt->ctl_mutex);
	if (ret)
		goto out;

	if (!strcmp(argv[0], "get_errors")) {
		ret = qcow2_get_errors(tgt, result, maxlen);
	} else if (!tgt->service_operations_allowed) {
		ret = -EBUSY; /* Suspended */
		/* Service operations goes below: */
	} else if (!strcmp(argv[0], "merge_forward")) {
		ret = qcow2_merge_forward(tgt);
	} else if (!strcmp(argv[0], "merge_backward")) {
		ret = qcow2_merge_backward(tgt);
	} else {
		ret = -ENOTTY;
	}

	mutex_unlock(&tgt->ctl_mutex);
out:
	return ret;
}
