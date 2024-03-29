/*
 * Block multiqueue core code
 *
 * Copyright (C) 2013-2014 Jens Axboe
 * Copyright (C) 2013-2014 Christoph Hellwig
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/kmemleak.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/smp.h>
#include <linux/llist.h>
#include <linux/list_sort.h>
#include <linux/cpu.h>
#include <linux/cache.h>
#include <linux/sched/sysctl.h>
#include <linux/delay.h>
#include <linux/crash_dump.h>

#include <trace/events/block.h>

#include <linux/blk-mq.h>
#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-mq-tag.h"
#include "blk-mq-sched.h"
#include "blk-stat.h"

static DEFINE_MUTEX(all_q_mutex);
static LIST_HEAD(all_q_list);

static void blk_mq_poll_stats_start(struct request_queue *q);
static void blk_mq_poll_stats_fn(struct blk_stat_callback *cb);

/*
 * Check if any of the ctx's have pending work in this hardware queue
 */
static bool blk_mq_hctx_has_pending(struct blk_mq_hw_ctx *hctx)
{
	return !list_empty_careful(&hctx->dispatch) ||
		sbitmap_any_bit_set(&hctx->ctx_map) ||
			blk_mq_sched_has_work(hctx);
}

/*
 * Mark this ctx as having pending work in this hardware queue
 */
static void blk_mq_hctx_mark_pending(struct blk_mq_hw_ctx *hctx,
				     struct blk_mq_ctx *ctx)
{
	if (!sbitmap_test_bit(&hctx->ctx_map, ctx->index_hw))
		sbitmap_set_bit(&hctx->ctx_map, ctx->index_hw);
}

static void blk_mq_hctx_clear_pending(struct blk_mq_hw_ctx *hctx,
				      struct blk_mq_ctx *ctx)
{
	sbitmap_clear_bit(&hctx->ctx_map, ctx->index_hw);
}

struct mq_inflight {
	struct hd_struct *part;
	unsigned int *inflight;
};

static void blk_mq_check_inflight(struct blk_mq_hw_ctx *hctx,
				  struct request *rq, void *priv,
				  bool reserved)
{
	struct mq_inflight *mi = priv;

	if (!blk_mq_request_started(rq))
		return;

	/*
	 * index[0] counts the specific partition that was asked
	 * for. index[1] counts the ones that are active on the
	 * whole device, so increment that if mi->part is indeed
	 * a partition, and not a whole device.
	 */
	if (rq->part == mi->part)
		mi->inflight[0]++;
	if (mi->part->partno)
		mi->inflight[1]++;
}

void blk_mq_in_flight(struct request_queue *q, struct hd_struct *part,
		      unsigned int inflight[2])
{
	struct mq_inflight mi = { .part = part, .inflight = inflight, };

	inflight[0] = inflight[1] = 0;
	blk_mq_queue_tag_busy_iter(q, blk_mq_check_inflight, &mi);
}

static void blk_mq_check_inflight_rw(struct blk_mq_hw_ctx *hctx,
				     struct request *rq, void *priv,
				     bool reserved)
{
	struct mq_inflight *mi = priv;

	if (!blk_mq_request_started(rq))
		return;

	if (rq->part == mi->part)
		mi->inflight[rq_data_dir(rq)]++;
}

void blk_mq_in_flight_rw(struct request_queue *q, struct hd_struct *part,
			 unsigned int inflight[2])
{
	struct mq_inflight mi = { .part = part, .inflight = inflight, };

	inflight[0] = inflight[1] = 0;
	blk_mq_queue_tag_busy_iter(q, blk_mq_check_inflight_rw, &mi);
}

void blk_freeze_queue_start(struct request_queue *q)
{
	mutex_lock(&q->mq_freeze_lock);
	if (atomic_inc_return(&q->mq_freeze_depth) == 1) {
		percpu_ref_kill(&q->q_usage_counter);
		mutex_unlock(&q->mq_freeze_lock);
		if (q->mq_ops)
			blk_mq_run_hw_queues(q, false);
	} else {
		mutex_unlock(&q->mq_freeze_lock);
	}
}
EXPORT_SYMBOL_GPL(blk_freeze_queue_start);

void blk_mq_freeze_queue_wait(struct request_queue *q)
{
	wait_event(q->mq_freeze_wq, percpu_ref_is_zero(&q->q_usage_counter));
}
EXPORT_SYMBOL_GPL(blk_mq_freeze_queue_wait);

int blk_mq_freeze_queue_wait_timeout(struct request_queue *q,
				     unsigned long timeout)
{
	return wait_event_timeout(q->mq_freeze_wq,
					percpu_ref_is_zero(&q->q_usage_counter),
					timeout);
}
EXPORT_SYMBOL_GPL(blk_mq_freeze_queue_wait_timeout);

/*
 * Guarantee no request is in use, so we can change any data structure of
 * the queue afterward.
 */
void blk_freeze_queue(struct request_queue *q)
{
	/*
	 * In the !blk_mq case we are only calling this to kill the
	 * q_usage_counter, otherwise this increases the freeze depth
	 * and waits for it to return to zero.  For this reason there is
	 * no blk_unfreeze_queue(), and blk_freeze_queue() is not
	 * exported to drivers as the only user for unfreeze is blk_mq.
	 */
	blk_freeze_queue_start(q);
	if (!q->mq_ops)
		blk_drain_queue(q);
	blk_mq_freeze_queue_wait(q);
}

void blk_mq_freeze_queue(struct request_queue *q)
{
	/*
	 * ...just an alias to keep freeze and unfreeze actions balanced
	 * in the blk_mq_* namespace
	 */
	blk_freeze_queue(q);
}
EXPORT_SYMBOL_GPL(blk_mq_freeze_queue);

void blk_mq_unfreeze_queue(struct request_queue *q)
{
	int freeze_depth;

	mutex_lock(&q->mq_freeze_lock);
	freeze_depth = atomic_dec_return(&q->mq_freeze_depth);
	WARN_ON_ONCE(freeze_depth < 0);
	if (!freeze_depth) {
		percpu_ref_reinit(&q->q_usage_counter);
		wake_up_all(&q->mq_freeze_wq);
	}
	mutex_unlock(&q->mq_freeze_lock);
}
EXPORT_SYMBOL_GPL(blk_mq_unfreeze_queue);

/*
 * FIXME: replace the scsi_internal_device_*block_nowait() calls in the
 * mpt3sas driver such that this function can be removed.
 */
void blk_mq_quiesce_queue_nowait(struct request_queue *q)
{
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	queue_flag_set(QUEUE_FLAG_QUIESCED, q);
	spin_unlock_irqrestore(q->queue_lock, flags);
}
EXPORT_SYMBOL_GPL(blk_mq_quiesce_queue_nowait);

/**
 * blk_mq_quiesce_queue() - wait until all ongoing dispatches have finished
 * @q: request queue.
 *
 * Note: this function does not prevent that the struct request end_io()
 * callback function is invoked. Once this function is returned, we make
 * sure no dispatch can happen until the queue is unquiesced via
 * blk_mq_unquiesce_queue().
 */
void blk_mq_quiesce_queue(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned int i;
	bool rcu = false;

	blk_mq_quiesce_queue_nowait(q);

	queue_for_each_hw_ctx(q, hctx, i) {
		if (hctx->flags & BLK_MQ_F_BLOCKING)
			synchronize_srcu(&hctx->queue_rq_srcu);
		else
			rcu = true;
	}
	if (rcu)
		synchronize_rcu();
}
EXPORT_SYMBOL_GPL(blk_mq_quiesce_queue);

/*
 * blk_mq_unquiesce_queue() - counterpart of blk_mq_quiesce_queue()
 * @q: request queue.
 *
 * This function recovers queue into the state before quiescing
 * which is done by blk_mq_quiesce_queue.
 */
void blk_mq_unquiesce_queue(struct request_queue *q)
{
	unsigned long flags;

	spin_lock_irqsave(q->queue_lock, flags);
	queue_flag_clear(QUEUE_FLAG_QUIESCED, q);
	spin_unlock_irqrestore(q->queue_lock, flags);

	/* dispatch requests which are inserted during quiescing */
	blk_mq_run_hw_queues(q, true);
}
EXPORT_SYMBOL_GPL(blk_mq_unquiesce_queue);

void blk_mq_wake_waiters(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned int i;

	queue_for_each_hw_ctx(q, hctx, i)
		if (blk_mq_hw_queue_mapped(hctx))
			blk_mq_tag_wakeup_all(hctx->tags, true);
}

bool blk_mq_can_queue(struct blk_mq_hw_ctx *hctx)
{
	return blk_mq_has_free_tags(hctx->tags);
}
EXPORT_SYMBOL(blk_mq_can_queue);

void blk_mq_rq_ctx_init(struct request_queue *q, struct blk_mq_ctx *ctx,
			struct request *rq, unsigned int rw_flags)
{
	if (blk_queue_io_stat(q))
		rw_flags |= REQ_IO_STAT;

	INIT_LIST_HEAD(&rq->queuelist);
	/* csd/requeue_work/fifo_time is initialized before use */
	rq->q = q;
	rq->mq_ctx = ctx;
	rq->cmd_flags |= rw_flags;
	/* do not touch atomic flags, it needs atomic ops against the timer */
	rq->cpu = -1;
	INIT_HLIST_NODE(&rq->hash);
	RB_CLEAR_NODE(&rq->rb_node);
	rq->rq_disk = NULL;
	rq->part = NULL;
	rq->start_time = jiffies;
#ifdef CONFIG_BLK_CGROUP
	rq->rl = NULL;
	set_start_time_ns(rq);
	rq->io_start_time_ns = 0;
#endif
	rq->nr_phys_segments = 0;
#if defined(CONFIG_BLK_DEV_INTEGRITY)
	rq->nr_integrity_segments = 0;
#endif
	rq->special = NULL;
	/* tag was already set */
	rq->errors = 0;

	rq->cmd = rq->__cmd;

	rq->extra_len = 0;
	rq->sense_len = 0;
	rq->resid_len = 0;
	rq->sense = NULL;

	INIT_LIST_HEAD(&rq->timeout_list);
	rq->timeout = 0;

	rq->end_io = NULL;
	rq->end_io_data = NULL;
	rq->next_rq = NULL;

	ctx->rq_dispatched[rw_is_sync(rw_flags)]++;
}
EXPORT_SYMBOL_GPL(blk_mq_rq_ctx_init);

struct request *__blk_mq_alloc_request(struct blk_mq_alloc_data *data, int rw)
{
	struct request *rq;
	unsigned int tag;

	tag = blk_mq_get_tag(data);
	if (tag != BLK_MQ_TAG_FAIL) {
		struct blk_mq_tags *tags = blk_mq_tags_from_data(data);

		rq = tags->static_rqs[tag];

		if (data->flags & BLK_MQ_REQ_INTERNAL) {
			rq->tag = -1;
			__rq_aux(rq, data->q)->internal_tag = tag;
		} else {
			if (blk_mq_tag_busy(data->hctx)) {
				rq->cmd_flags = REQ_MQ_INFLIGHT;
				atomic_inc(&data->hctx->nr_active);
			}
			rq->tag = tag;
			__rq_aux(rq, data->q)->internal_tag = -1;
			data->hctx->tags->rqs[rq->tag] = rq;
		}

		blk_mq_rq_ctx_init(data->q, data->ctx, rq, rw);
		if (data->flags & BLK_MQ_REQ_PREEMPT)
			rq->cmd_flags |= REQ_PREEMPT;

		return rq;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(__blk_mq_alloc_request);

struct request *blk_mq_alloc_request(struct request_queue *q, int rw,
		unsigned int flags)
{
	struct blk_mq_alloc_data alloc_data = { .flags = flags };
	struct request *rq;
	int ret;

	ret = blk_queue_enter(q, flags);
	if (ret)
		return ERR_PTR(ret);

	rq = blk_mq_sched_get_request(q, NULL, rw, &alloc_data);

	blk_mq_put_ctx(alloc_data.ctx);
	blk_queue_exit(q);

	if (!rq)
		return ERR_PTR(-EWOULDBLOCK);
	return rq;
}
EXPORT_SYMBOL(blk_mq_alloc_request);

struct request *blk_mq_alloc_request_hctx(struct request_queue *q, int rw,
		unsigned int flags, unsigned int hctx_idx)
{
	struct blk_mq_alloc_data alloc_data = { .flags = flags };
	struct request *rq;
	unsigned int cpu;
	int ret;

	/*
	 * If the tag allocator sleeps we could get an allocation for a
	 * different hardware context.  No need to complicate the low level
	 * allocator for this for the rare use case of a command tied to
	 * a specific queue.
	 */
	if (WARN_ON_ONCE(!(flags & BLK_MQ_REQ_NOWAIT)))
		return ERR_PTR(-EINVAL);

	if (hctx_idx >= q->nr_hw_queues)
		return ERR_PTR(-EIO);

	ret = blk_queue_enter(q, flags);
	if (ret)
		return ERR_PTR(ret);

	/*
	 * Check if the hardware context is actually mapped to anything.
	 * If not tell the caller that it should skip this queue.
	 */
	alloc_data.hctx = q->queue_hw_ctx[hctx_idx];
	if (!blk_mq_hw_queue_mapped(alloc_data.hctx)) {
		blk_queue_exit(q);
		return ERR_PTR(-EXDEV);
	}
	cpu = cpumask_first(alloc_data.hctx->cpumask);
	alloc_data.ctx = __blk_mq_get_ctx(q, cpu);

	rq = blk_mq_sched_get_request(q, NULL, rw, &alloc_data);

	blk_queue_exit(q);

	if (!rq)
		return ERR_PTR(-EWOULDBLOCK);

	return rq;
}
EXPORT_SYMBOL_GPL(blk_mq_alloc_request_hctx);

static void
blk_mq_sched_completed_request(struct request *rq)
{
	struct elevator_queue *e = rq->q->elevator;

	if (e && e->aux->ops.mq.completed_request)
		e->aux->ops.mq.completed_request(rq);
}

void __blk_mq_finish_request(struct blk_mq_hw_ctx *hctx, struct blk_mq_ctx *ctx,
			     struct request *rq)
{
	const int sched_tag = rq_aux(rq)->internal_tag;
	struct request_queue *q = rq->q;

	if (rq->cmd_flags & REQ_MQ_INFLIGHT)
		atomic_dec(&hctx->nr_active);
	rq->cmd_flags = 0;

	clear_bit(REQ_ATOM_STARTED, &rq->atomic_flags);
	if (rq->tag != -1)
		blk_mq_put_tag(hctx, hctx->tags, ctx, rq->tag);
	if (sched_tag != -1)
		blk_mq_put_tag(hctx, hctx->sched_tags, ctx, sched_tag);
	blk_mq_sched_restart(hctx);
	blk_queue_exit(q);
}

static void blk_mq_finish_hctx_request(struct blk_mq_hw_ctx *hctx,
				       struct request *rq)
{
	struct blk_mq_ctx *ctx = rq->mq_ctx;

	ctx->rq_completed[rq_is_sync(rq)]++;
	__blk_mq_finish_request(hctx, ctx, rq);
}
EXPORT_SYMBOL_GPL(blk_mq_finish_request);

void blk_mq_finish_request(struct request *rq)
{
	blk_mq_finish_hctx_request(blk_mq_map_queue(rq->q, rq->mq_ctx->cpu), rq);
 }

void blk_mq_free_request(struct request *rq)
{
	blk_mq_sched_put_request(rq);
}
EXPORT_SYMBOL_GPL(blk_mq_free_request);

inline void __blk_mq_end_request(struct request *rq, int error)
{
	blk_account_io_done(rq);

	if (rq->end_io) {
		rq->end_io(rq, error);
	} else {
		if (unlikely(blk_bidi_rq(rq)))
			blk_mq_free_request(rq->next_rq);
		blk_mq_free_request(rq);
	}
}
EXPORT_SYMBOL(__blk_mq_end_request);

void blk_mq_end_request(struct request *rq, int error)
{
	if (blk_update_request(rq, error, blk_rq_bytes(rq)))
		BUG();
	__blk_mq_end_request(rq, error);
}
EXPORT_SYMBOL(blk_mq_end_request);

static void __blk_mq_complete_request_remote(void *data)
{
	struct request *rq = data;

	rq->q->softirq_done_fn(rq);
}

static void blk_mq_ipi_complete_request(struct request *rq)
{
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	bool shared = false;
	int cpu;

	/*
	 * Most of single queue controllers, there is only one irq vector
	 * for handling IO completion, and the only irq's affinity is set
	 * as all possible CPUs. On most of ARCHs, this affinity means the
	 * irq is handled on one specific CPU.
	 *
	 * So complete IO reqeust in softirq context in case of single queue
	 * for not degrading IO performance by irqsoff latency.
	 */
	if (rq->q->nr_hw_queues == 1) {
		__blk_complete_request(rq);
		return;
	}

	if (!test_bit(QUEUE_FLAG_SAME_COMP, &rq->q->queue_flags)) {
		rq->q->softirq_done_fn(rq);
		return;
	}

	cpu = get_cpu();
	if (!test_bit(QUEUE_FLAG_SAME_FORCE, &rq->q->queue_flags))
		shared = cpus_share_cache(cpu, ctx->cpu);

	if (cpu != ctx->cpu && !shared && cpu_online(ctx->cpu)) {
		rq->csd.func = __blk_mq_complete_request_remote;
		rq->csd.info = rq;
		rq->csd.flags = 0;
		smp_call_function_single_async(ctx->cpu, &rq->csd);
	} else {
		rq->q->softirq_done_fn(rq);
	}
	put_cpu();
}

static void blk_mq_stat_add(struct request *rq)
{
	if (rq->cmd_flags & REQ_STATS) {
		blk_mq_poll_stats_start(rq->q);
		blk_stat_add(rq);
	}
}

static void __blk_mq_complete_request(struct request *rq)
{
	struct request_queue *q = rq->q;

	if (rq_aux(rq)->internal_tag != -1)
		blk_mq_sched_completed_request(rq);

	blk_mq_stat_add(rq);

	if (!q->softirq_done_fn)
		blk_mq_end_request(rq, rq->errors);
	else
		blk_mq_ipi_complete_request(rq);
}

static void hctx_unlock(struct blk_mq_hw_ctx *hctx, int srcu_idx)
	__releases(hctx->srcu)
{
	if (!(hctx->flags & BLK_MQ_F_BLOCKING))
		rcu_read_unlock();
	else
		srcu_read_unlock(&hctx->queue_rq_srcu, srcu_idx);
}

static void hctx_lock(struct blk_mq_hw_ctx *hctx, int *srcu_idx)
	__acquires(hctx->srcu)
{
	if (!(hctx->flags & BLK_MQ_F_BLOCKING)) {
		/* shut up gcc false positive */
		*srcu_idx = 0;
		rcu_read_lock();
	} else
		*srcu_idx = srcu_read_lock(&hctx->queue_rq_srcu);
}

/**
 * blk_mq_complete_request - end I/O on a request
 * @rq:		the request being processed
 *
 * Description:
 *	Ends all I/O on a request. It does not handle partial completions.
 *	The actual completion happens out-of-order, through a IPI handler.
 **/
void blk_mq_complete_request(struct request *rq, int error)
{
	struct request_queue *q = rq->q;

	if (unlikely(blk_should_fake_timeout(q)))
		return;
	if (!blk_mark_rq_complete(rq)) {
		rq->errors = error;
		__blk_mq_complete_request(rq);
	}
}
EXPORT_SYMBOL(blk_mq_complete_request);

int blk_mq_request_started(struct request *rq)
{
	return test_bit(REQ_ATOM_STARTED, &rq->atomic_flags);
}
EXPORT_SYMBOL_GPL(blk_mq_request_started);

int blk_mq_request_completed(struct request *rq)
{
	return test_bit(REQ_ATOM_COMPLETE, &rq->atomic_flags);
}
EXPORT_SYMBOL_GPL(blk_mq_request_completed);


/*
 * This API is for implementing same timeout handling for drivers compared
 * with upstream kernel without backporting big & kabi-breaking blk-mq
 * & dirver timeout handling re-work.
 *
 * Driver can call this API to mark the timed-out request as not-completed,
 * then handle it same with other in-flight requests.
 */
void blk_mq_clear_rq_complete(struct request *rq)
{
	blk_clear_rq_complete(rq);
}
EXPORT_SYMBOL_GPL(blk_mq_clear_rq_complete);

void blk_mq_start_request(struct request *rq)
{
	struct request_queue *q = rq->q;

	blk_mq_sched_started_request(rq);

	trace_block_rq_issue(q, rq);

	rq->resid_len = blk_rq_bytes(rq);
	if (unlikely(blk_bidi_rq(rq)))
		rq->next_rq->resid_len = blk_rq_bytes(rq->next_rq);

	if (test_bit(QUEUE_FLAG_STATS, &q->queue_flags)) {
		blk_stat_set_issue_time(&rq_aux(rq)->issue_stat);
		rq->cmd_flags |= REQ_STATS;
	}

	blk_add_timer(rq);

	/*
	 * Ensure that ->deadline is visible before set the started
	 * flag and clear the completed flag.
	 */
	smp_mb__before_atomic();

	/*
	 * Mark us as started and clear complete. Complete might have been
	 * set if requeue raced with timeout, which then marked it as
	 * complete. So be sure to clear complete again when we start
	 * the request, otherwise we'll ignore the completion event.
	 */
	if (!test_bit(REQ_ATOM_STARTED, &rq->atomic_flags))
		set_bit(REQ_ATOM_STARTED, &rq->atomic_flags);
	if (test_bit(REQ_ATOM_COMPLETE, &rq->atomic_flags))
		clear_bit(REQ_ATOM_COMPLETE, &rq->atomic_flags);

	if (q->dma_drain_size && blk_rq_bytes(rq)) {
		/*
		 * Make sure space for the drain appears.  We know we can do
		 * this because max_hw_segments has been adjusted to be one
		 * fewer than the device can handle.
		 */
		rq->nr_phys_segments++;
	}
}
EXPORT_SYMBOL(blk_mq_start_request);

/*
 * When we reach here because queue is busy, REQ_ATOM_COMPLETE
 * flag isn't set yet, so there may be race with timeout hanlder,
 * but given rq->deadline is just set in .queue_rq() under
 * this situation, the race won't be possible in reality because
 * rq->timeout should be set as big enough to cover the window
 * between blk_mq_start_request() called from .queue_rq() and
 * clearing REQ_ATOM_STARTED here.
 */
static void __blk_mq_requeue_request(struct request *rq)
{
	struct request_queue *q = rq->q;

	blk_mq_put_driver_tag(rq);

	trace_block_rq_requeue(q, rq);

	if (test_and_clear_bit(REQ_ATOM_STARTED, &rq->atomic_flags)) {
		if (q->dma_drain_size && blk_rq_bytes(rq))
			rq->nr_phys_segments--;
	}
}

void blk_mq_requeue_request(struct request *rq, bool kick_requeue_list)
{
	__blk_mq_requeue_request(rq);

	/* this request will be re-inserted to io scheduler queue */
	blk_mq_sched_requeue_request(rq);

	BUG_ON(blk_queued_rq(rq));
	blk_mq_add_to_requeue_list(rq, true, kick_requeue_list);
}
EXPORT_SYMBOL(blk_mq_requeue_request);

static void blk_mq_requeue_work(struct work_struct *work)
{
	struct request_queue *q =
		container_of(work, struct request_queue, requeue_work.work);
	LIST_HEAD(rq_list);
	struct request *rq, *next;
	unsigned long flags;

	spin_lock_irqsave(&q->requeue_lock, flags);
	list_splice_init(&q->requeue_list, &rq_list);
	spin_unlock_irqrestore(&q->requeue_lock, flags);

	list_for_each_entry_safe(rq, next, &rq_list, queuelist) {
		if (!(rq->cmd_flags & (REQ_SOFTBARRIER | REQ_DONTPREP)))
			continue;

		rq->cmd_flags &= ~REQ_SOFTBARRIER;
		list_del_init(&rq->queuelist);
		/*
		 * If RQF_DONTPREP, rq has contained some driver specific
		 * data, so insert it to hctx dispatch list to avoid any
		 * merge.
		 */
		if (rq->cmd_flags & REQ_DONTPREP)
			blk_mq_request_bypass_insert(rq, false);
		else
			blk_mq_sched_insert_request(rq, true, false, false);
	}

	while (!list_empty(&rq_list)) {
		rq = list_entry(rq_list.next, struct request, queuelist);
		list_del_init(&rq->queuelist);
		blk_mq_sched_insert_request(rq, false, false, false);
	}

	blk_mq_run_hw_queues(q, false);
}

void blk_mq_add_to_requeue_list(struct request *rq, bool at_head,
				bool kick_requeue_list)
{
	struct request_queue *q = rq->q;
	unsigned long flags;

	/*
	 * We abuse this flag that is otherwise used by the I/O scheduler to
	 * request head insertation from the workqueue.
	 */
	BUG_ON(rq->cmd_flags & REQ_SOFTBARRIER);

	spin_lock_irqsave(&q->requeue_lock, flags);
	if (at_head) {
		rq->cmd_flags |= REQ_SOFTBARRIER;
		list_add(&rq->queuelist, &q->requeue_list);
	} else {
		list_add_tail(&rq->queuelist, &q->requeue_list);
	}
	spin_unlock_irqrestore(&q->requeue_lock, flags);

	if (kick_requeue_list)
		blk_mq_kick_requeue_list(q);
}
EXPORT_SYMBOL(blk_mq_add_to_requeue_list);

void blk_mq_kick_requeue_list(struct request_queue *q)
{
	kblockd_mod_delayed_work_on(WORK_CPU_UNBOUND, &q->requeue_work, 0);
}
EXPORT_SYMBOL(blk_mq_kick_requeue_list);

void blk_mq_delay_kick_requeue_list(struct request_queue *q,
				    unsigned long msecs)
{
	kblockd_schedule_delayed_work(&q->requeue_work,
				      msecs_to_jiffies(msecs));
}
EXPORT_SYMBOL(blk_mq_delay_kick_requeue_list);

struct request *blk_mq_tag_to_rq(struct blk_mq_tags *tags, unsigned int tag)
{
	if (tag < tags->nr_tags)
		return tags->rqs[tag];

	return NULL;
}
EXPORT_SYMBOL(blk_mq_tag_to_rq);

struct blk_mq_timeout_data {
	unsigned long next;
	unsigned int next_set;
};

void blk_mq_rq_timed_out(struct request *req, bool reserved)
{
	const struct blk_mq_ops *ops = req->q->mq_ops;
	enum blk_eh_timer_return ret = BLK_EH_RESET_TIMER;

	/*
	 * We know that complete is set at this point. If STARTED isn't set
	 * anymore, then the request isn't active and the "timeout" should
	 * just be ignored. This can happen due to the bitflag ordering.
	 * Timeout first checks if STARTED is set, and if it is, assumes
	 * the request is active. But if we race with completion, then
	 * we both flags will get cleared. So check here again, and ignore
	 * a timeout event with a request that isn't active.
	 */
	if (!test_bit(REQ_ATOM_STARTED, &req->atomic_flags))
		return;

	if (ops->timeout) {
		req->cmd_flags |= REQ_TIMEOUT;
		ret = ops->timeout(req, reserved);
		req->cmd_flags &= ~REQ_TIMEOUT;
	}

	switch (ret) {
	case BLK_EH_HANDLED:
		__blk_mq_complete_request(req);
		break;
	case BLK_EH_RESET_TIMER:
		blk_add_timer(req);
		blk_clear_rq_complete(req);
		break;
	case BLK_EH_NOT_HANDLED:
		break;
	default:
		printk(KERN_ERR "block: bad eh return: %d\n", ret);
		break;
	}
}

static void blk_mq_check_expired(struct blk_mq_hw_ctx *hctx,
		struct request *rq, void *priv, bool reserved)
{
	struct blk_mq_timeout_data *data = priv;

	if (!test_bit(REQ_ATOM_STARTED, &rq->atomic_flags))
		return;

	/*
	 * The rq being checked may have been freed and reallocated
	 * out already here, we avoid this race by checking rq->deadline
	 * and REQ_ATOM_COMPLETE flag together:
	 *
	 * - if rq->deadline is observed as new value because of
	 *   reusing, the rq won't be timed out because of timing.
	 * - if rq->deadline is observed as previous value,
	 *   REQ_ATOM_COMPLETE flag won't be cleared in reuse path
	 *   because we put a barrier between setting rq->deadline
	 *   and clearing the flag in blk_mq_start_request(), so
	 *   this rq won't be timed out too.
	 */
	if (time_after_eq(jiffies, rq->deadline)) {
		if (!blk_mark_rq_complete(rq))
			blk_mq_rq_timed_out(rq, reserved);
	} else if (!data->next_set || time_after(data->next, rq->deadline)) {
		data->next = rq->deadline;
		data->next_set = 1;
	}
}

static void blk_mq_timeout_work(struct work_struct *work)
{
	struct request_queue *q =
		container_of(work, struct request_queue, timeout_work);
	struct blk_mq_timeout_data data = {
		.next		= 0,
		.next_set	= 0,
	};
	int i;

	/* A deadlock might occur if a request is stuck requiring a
	 * timeout at the same time a queue freeze is waiting
	 * completion, since the timeout code would not be able to
	 * acquire the queue reference here.
	 *
	 * That's why we don't use blk_queue_enter here; instead, we use
	 * percpu_ref_tryget directly, because we need to be able to
	 * obtain a reference even in the short window between the queue
	 * starting to freeze, by dropping the first reference in
	 * blk_freeze_queue_start, and the moment the last request is
	 * consumed, marked by the instant q_usage_counter reaches
	 * zero.
	 */
	if (!percpu_ref_tryget(&q->q_usage_counter))
		return;

	blk_mq_queue_tag_busy_iter(q, blk_mq_check_expired, &data);

	if (data.next_set) {
		data.next = blk_rq_timeout(round_jiffies_up(data.next));
		mod_timer(&q->timeout, data.next);
	} else {
		struct blk_mq_hw_ctx *hctx;

		queue_for_each_hw_ctx(q, hctx, i) {
			/* the hctx may be unmapped, so check it here */
			if (blk_mq_hw_queue_mapped(hctx))
				blk_mq_tag_idle(hctx);
		}
	}
	blk_queue_exit(q);
}

/*
 * Reverse check our software queue for entries that we could potentially
 * merge with. Currently includes a hand-wavy stop count of 8, to not spend
 * too much time checking for merges.
 */
static bool blk_mq_attempt_merge(struct request_queue *q,
				 struct blk_mq_ctx *ctx, struct bio *bio)
{
	struct request *rq;
	int checked = 8;

	list_for_each_entry_reverse(rq, &ctx->rq_list, queuelist) {
		int el_ret;

		if (!checked--)
			break;

		if (!blk_rq_merge_ok(rq, bio))
			continue;

		el_ret = blk_try_merge(rq, bio);
		if (el_ret == ELEVATOR_NO_MERGE)
			continue;

		if (!blk_mq_sched_allow_merge(q, rq, bio))
			break;

		if (el_ret == ELEVATOR_BACK_MERGE) {
			if (bio_attempt_back_merge(q, rq, bio)) {
				ctx->rq_merged++;
				return true;
			}
			break;
		} else if (el_ret == ELEVATOR_FRONT_MERGE) {
			if (bio_attempt_front_merge(q, rq, bio)) {
				ctx->rq_merged++;
				return true;
			}
			break;
		}
	}

	return false;
}

struct flush_busy_ctx_data {
	struct blk_mq_hw_ctx *hctx;
	struct list_head *list;
};

static bool flush_busy_ctx(struct sbitmap *sb, unsigned int bitnr, void *data)
{
	struct flush_busy_ctx_data *flush_data = data;
	struct blk_mq_hw_ctx *hctx = flush_data->hctx;
	struct blk_mq_ctx *ctx = hctx->ctxs[bitnr];

	spin_lock(&ctx->lock);
	list_splice_tail_init(&ctx->rq_list, flush_data->list);
	sbitmap_clear_bit(sb, bitnr);
	spin_unlock(&ctx->lock);
	return true;
}

/*
 * Process software queues that have been marked busy, splicing them
 * to the for-dispatch
 */
void blk_mq_flush_busy_ctxs(struct blk_mq_hw_ctx *hctx, struct list_head *list)
{
	struct flush_busy_ctx_data data = {
		.hctx = hctx,
		.list = list,
	};

	sbitmap_for_each_set(&hctx->ctx_map, flush_busy_ctx, &data);
}
EXPORT_SYMBOL_GPL(blk_mq_flush_busy_ctxs);

struct dispatch_rq_data {
	struct blk_mq_hw_ctx *hctx;
	struct request *rq;
};

static bool dispatch_rq_from_ctx(struct sbitmap *sb, unsigned int bitnr,
		void *data)
{
	struct dispatch_rq_data *dispatch_data = data;
	struct blk_mq_hw_ctx *hctx = dispatch_data->hctx;
	struct blk_mq_ctx *ctx = hctx->ctxs[bitnr];

	spin_lock(&ctx->lock);
	if (unlikely(!list_empty(&ctx->rq_list))) {
		dispatch_data->rq = list_entry_rq(ctx->rq_list.next);
		list_del_init(&dispatch_data->rq->queuelist);
		if (list_empty(&ctx->rq_list))
			sbitmap_clear_bit(sb, bitnr);
	}
	spin_unlock(&ctx->lock);

	return !dispatch_data->rq;
}

struct request *blk_mq_dequeue_from_ctx(struct blk_mq_hw_ctx *hctx,
					struct blk_mq_ctx *start)
{
	unsigned off = start ? start->index_hw : 0;
	struct dispatch_rq_data data = {
		.hctx = hctx,
		.rq   = NULL,
	};

	__sbitmap_for_each_set(&hctx->ctx_map, off,
			       dispatch_rq_from_ctx, &data);

	return data.rq;
}

static inline unsigned int queued_to_index(unsigned int queued)
{
	if (!queued)
		return 0;

	return min(BLK_MQ_MAX_DISPATCH_ORDER - 1, ilog2(queued) + 1);
}

bool blk_mq_get_driver_tag(struct request *rq, struct blk_mq_hw_ctx **hctx,
			   bool wait)
{
	struct blk_mq_alloc_data data = {
		.q = rq->q,
		.hctx = blk_mq_map_queue(rq->q, rq->mq_ctx->cpu),
		.flags = wait ? 0 : BLK_MQ_REQ_NOWAIT,
	};

	if (rq->tag != -1)
		goto done;

	if (blk_mq_tag_is_reserved(data.hctx->sched_tags, rq_aux(rq)->internal_tag))
		data.flags |= BLK_MQ_REQ_RESERVED;

	rq->tag = blk_mq_get_tag(&data);
	if (rq->tag >= 0) {
		if (blk_mq_tag_busy(data.hctx)) {
			rq->cmd_flags |= REQ_MQ_INFLIGHT;
			atomic_inc(&data.hctx->nr_active);
		}
		data.hctx->tags->rqs[rq->tag] = rq;
	}

done:
	if (hctx)
		*hctx = data.hctx;
	return rq->tag != -1;
}

static int blk_mq_dispatch_wake(wait_queue_t *wait, unsigned mode,
				int flags, void *key)
{
	struct blk_mq_hw_ctx *hctx;

	hctx = container_of(wait, struct blk_mq_hw_ctx, dispatch_wait);

	list_del_init(&wait->task_list);
	blk_mq_run_hw_queue(hctx, true);
	return 1;
}

/*
 * Mark us waiting for a tag. For shared tags, this involves hooking us into
 * the tag wakeups. For non-shared tags, we can simply mark us nedeing a
 * restart. For both caes, take care to check the condition again after
 * marking us as waiting.
 */
static bool blk_mq_mark_tag_wait(struct blk_mq_hw_ctx **hctx,
				 struct request *rq)
{
	struct blk_mq_hw_ctx *this_hctx = *hctx;
	struct sbq_wait_state *ws;
	wait_queue_t *wait;
	bool ret;

	if (!(this_hctx->flags & BLK_MQ_F_TAG_SHARED)) {
		if (!test_bit(BLK_MQ_S_SCHED_RESTART, &this_hctx->state))
			set_bit(BLK_MQ_S_SCHED_RESTART, &this_hctx->state);
		/*
		 * It's possible that a tag was freed in the window between the
		 * allocation failure and adding the hardware queue to the wait
		 * queue.
		 *
		 * Don't clear RESTART here, someone else could have set it.
		 * At most this will cost an extra queue run.
		 */
		return blk_mq_get_driver_tag(rq, hctx, false);
	}

	wait = &this_hctx->dispatch_wait;
	if (!list_empty_careful(&wait->task_list))
		return false;

	spin_lock(&this_hctx->lock);
	if (!list_empty(&wait->task_list)) {
		spin_unlock(&this_hctx->lock);
		return false;
	}

	ws = bt_wait_ptr(&this_hctx->tags->bitmap_tags, this_hctx);
	add_wait_queue(&ws->wait, wait);

	/*
	 * It's possible that a tag was freed in the window between the
	 * allocation failure and adding the hardware queue to the wait
	 * queue.
	 */
	ret = blk_mq_get_driver_tag(rq, hctx, false);

	if (!ret) {
		spin_unlock(&this_hctx->lock);
		return false;
	}

	/*
	 * We got a tag, remove ourselves from the wait queue to ensure
	 * someone else gets the wakeup.
	 */
	spin_lock_irq(&ws->wait.lock);
	list_del_init(&wait->task_list);
	spin_unlock_irq(&ws->wait.lock);
	spin_unlock(&this_hctx->lock);

	return true;
}

#define BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT  8
#define BLK_MQ_DISPATCH_BUSY_EWMA_FACTOR  4
/*
 * Update dispatch busy with the Exponential Weighted Moving Average(EWMA):
 * - EWMA is one simple way to compute running average value
 * - weight(7/8 and 1/8) is applied so that it can decrease exponentially
 * - take 4 as factor for avoiding to get too small(0) result, and this
 *   factor doesn't matter because EWMA decreases exponentially
 */
static void blk_mq_update_dispatch_busy(struct blk_mq_hw_ctx *hctx, bool busy)
{
	unsigned int ewma;

	if (hctx->queue->elevator)
		return;

	ewma = hctx->dispatch_busy;

	if (!ewma && !busy)
		return;

	ewma *= BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT - 1;
	if (busy)
		ewma += 1 << BLK_MQ_DISPATCH_BUSY_EWMA_FACTOR;
	ewma /= BLK_MQ_DISPATCH_BUSY_EWMA_WEIGHT;

	hctx->dispatch_busy = ewma;
}

#define BLK_MQ_RESOURCE_DELAY	3		/* ms units */

/*
 * Returns true if we did some work AND can potentially do more.
 */
bool blk_mq_dispatch_rq_list(struct request_queue *q, struct list_head *list,
			     bool got_budget)
{
	struct blk_mq_hw_ctx *hctx;
	bool no_tag = false;
	struct request *rq, *nxt;
	LIST_HEAD(driver_list);
	struct list_head *dptr;
	int errors, queued, ret = BLK_MQ_RQ_QUEUE_OK;

	if (list_empty(list))
		return false;

	WARN_ON(!list_is_singular(list) && got_budget);

	/*
	 * Start off with dptr being NULL, so we start the first request
	 * immediately, even if we have more pending.
	 */
	dptr = NULL;

	/*
	 * Now process all the entries, sending them to the driver.
	 */
	errors = queued = 0;
	do {
		struct blk_mq_queue_data bd;

		rq = list_first_entry(list, struct request, queuelist);

		hctx = blk_mq_map_queue(rq->q, rq->mq_ctx->cpu);
		if (!got_budget && !blk_mq_get_dispatch_budget(hctx)) {
			blk_mq_put_driver_tag(rq);
			break;
		}

		if (!blk_mq_get_driver_tag(rq, NULL, false)) {
			/*
			 * The initial allocation attempt failed, so we need to
			 * rerun the hardware queue when a tag is freed. The
			 * waitqueue takes care of that. If the queue is run
			 * before we add this entry back on the dispatch list,
			 * we'll re-run it below.
			 */
			if (!blk_mq_mark_tag_wait(&hctx, rq)) {
				blk_mq_put_dispatch_budget(hctx);
				/*
				 * For non-shared tags, the RESTART check
				 * will suffice.
				 */
				if (hctx->flags & BLK_MQ_F_TAG_SHARED)
					no_tag = true;
				break;
			}
		}

		list_del_init(&rq->queuelist);

		bd.rq = rq;
		bd.list = dptr;

		/*
		 * Flag last if we have no more requests, or if we have more
		 * but can't assign a driver tag to it.
		 */
		if (list_empty(list))
			bd.last = true;
		else {
			nxt = list_first_entry(list, struct request, queuelist);
			bd.last = !blk_mq_get_driver_tag(nxt, NULL, false);
		}

		ret = q->mq_ops->queue_rq(hctx, &bd);
		switch (ret) {
		case BLK_MQ_RQ_QUEUE_OK:
			queued++;
			break;
		case BLK_MQ_RQ_QUEUE_BUSY:
		case BLK_MQ_RQ_QUEUE_DEV_BUSY:
			/*
			 * If an I/O scheduler has been configured and we got a
			 * driver tag for the next request already, free it again.
			 */
			if (!list_empty(list)) {
				nxt = list_first_entry(list, struct request, queuelist);
				blk_mq_put_driver_tag(nxt);
			}
			list_add(&rq->queuelist, list);
			__blk_mq_requeue_request(rq);
			break;
		default:
			pr_err("blk-mq: bad return on queue: %d\n", ret);
		case BLK_MQ_RQ_QUEUE_ERROR:
			errors++;
			rq->errors = -EIO;
			blk_mq_end_request(rq, rq->errors);
			break;
		}

		if (ret == BLK_MQ_RQ_QUEUE_BUSY || ret == BLK_MQ_RQ_QUEUE_DEV_BUSY)
			break;

		/*
		 * We've done the first request. If we have more than 1
		 * left in the list, set dptr to defer issue.
		 */
		if (!dptr && list->next != list->prev)
			dptr = &driver_list;
	} while (!list_empty(list));

	hctx->dispatched[queued_to_index(queued)]++;

	/*
	 * Any items that need requeuing? Stuff them into hctx->dispatch,
	 * that is where we will continue on next queue run.
	 */
	if (!list_empty(list)) {
		bool needs_restart;

		spin_lock(&hctx->lock);
		list_splice_init(list, &hctx->dispatch);
		spin_unlock(&hctx->lock);

		/*
		 * the queue is expected stopped with BLK_MQ_RQ_QUEUE_BUSY, but
		 * it's possible the queue is stopped and restarted again
		 * before this. Queue restart will dispatch requests. And since
		 * requests in rq_list aren't added into hctx->dispatch yet,
		 * the requests in rq_list might get lost.
		 *
		 * blk_mq_run_hw_queue() already checks the STOPPED bit
		 *
		 * If RESTART or TAG_WAITING is set, then let completion restart
		 * the queue instead of potentially looping here.
		 *
		 * If 'no_tag' is set, that means that we failed getting
		 * a driver tag with an I/O scheduler attached. If our dispatch
		 * waitqueue is no longer active, ensure that we run the queue
		 * AFTER adding our entries back to the list.
		 *
		 * If driver returns BLK_MQ_RQ_QUEUE_BUSY and SCHED_RESTART
		 * bit is set, run queue after a delay to avoid IO stalls
		 * that could otherwise occur if the queue is idle.
		 */
		needs_restart = blk_mq_sched_needs_restart(hctx);
		if (!needs_restart ||
		    (no_tag && list_empty_careful(&hctx->dispatch_wait.task_list)))
			blk_mq_run_hw_queue(hctx, true);
		else if (needs_restart && (ret == BLK_MQ_RQ_QUEUE_BUSY))
			blk_mq_delay_run_hw_queue(hctx, BLK_MQ_RESOURCE_DELAY);

		blk_mq_update_dispatch_busy(hctx, true);
		return false;
	} else
		blk_mq_update_dispatch_busy(hctx, false);

	/*
	 * If the host/device is unable to accept more work, inform the
	 * caller of that.
	 */
	if (ret == BLK_MQ_RQ_QUEUE_BUSY || ret == BLK_MQ_RQ_QUEUE_DEV_BUSY)
		return false;

	return (queued + errors) != 0;
}

static void __blk_mq_run_hw_queue(struct blk_mq_hw_ctx *hctx)
{
	int srcu_idx;

	WARN_ON(!cpumask_test_cpu(raw_smp_processor_id(), hctx->cpumask) &&
		cpu_online(hctx->next_cpu));

	might_sleep_if(hctx->flags & BLK_MQ_F_BLOCKING);

	hctx_lock(hctx, &srcu_idx);
	blk_mq_sched_dispatch_requests(hctx);
	hctx_unlock(hctx, srcu_idx);
}

/*
 * It'd be great if the workqueue API had a way to pass
 * in a mask and had some smarts for more clever placement.
 * For now we just round-robin here, switching for every
 * BLK_MQ_CPU_WORK_BATCH queued items.
 */
static int blk_mq_hctx_next_cpu(struct blk_mq_hw_ctx *hctx)
{
	if (hctx->queue->nr_hw_queues == 1)
		return WORK_CPU_UNBOUND;

	if (--hctx->next_cpu_batch <= 0) {
		int next_cpu;

		next_cpu = cpumask_next(hctx->next_cpu, hctx->cpumask);
		if (next_cpu >= nr_cpu_ids)
			next_cpu = cpumask_first(hctx->cpumask);

		hctx->next_cpu = next_cpu;
		hctx->next_cpu_batch = BLK_MQ_CPU_WORK_BATCH;
	}

	return hctx->next_cpu;
}

static void __blk_mq_delay_run_hw_queue(struct blk_mq_hw_ctx *hctx, bool async,
					unsigned long msecs)
{
	if (unlikely(blk_mq_hctx_stopped(hctx) ||
		     !blk_mq_hw_queue_mapped(hctx)))
		return;

	if (!async && !(hctx->flags & BLK_MQ_F_BLOCKING)) {
		int cpu = get_cpu();
		if (cpumask_test_cpu(cpu, hctx->cpumask)) {
			__blk_mq_run_hw_queue(hctx);
			put_cpu();
			return;
		}

		put_cpu();
	}

	kblockd_mod_delayed_work_on(blk_mq_hctx_next_cpu(hctx), &hctx->run_work,
				    msecs_to_jiffies(msecs));
}

void blk_mq_delay_run_hw_queue(struct blk_mq_hw_ctx *hctx, unsigned long msecs)
{
	__blk_mq_delay_run_hw_queue(hctx, true, msecs);
}
EXPORT_SYMBOL(blk_mq_delay_run_hw_queue);

bool blk_mq_run_hw_queue(struct blk_mq_hw_ctx *hctx, bool async)
{
	int srcu_idx;
	bool need_run;

	/*
	 * When queue is quiesced, we may be switching io scheduler, or
	 * updating nr_hw_queues, or other things, and we can't run queue
	 * any more, even __blk_mq_hctx_has_pending() can't be called safely.
	 *
	 * And queue will be rerun in blk_mq_unquiesce_queue() if it is
	 * quiesced.
	 */
	hctx_lock(hctx, &srcu_idx);
	need_run = !blk_queue_quiesced(hctx->queue) &&
		blk_mq_hctx_has_pending(hctx);
	hctx_unlock(hctx, srcu_idx);

	if (need_run) {
		__blk_mq_delay_run_hw_queue(hctx, async, 0);
		return true;
	}

	return false;
}
EXPORT_SYMBOL(blk_mq_run_hw_queue);

void blk_mq_run_hw_queues(struct request_queue *q, bool async)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i) {
		if (blk_mq_hctx_stopped(hctx))
			continue;

		blk_mq_run_hw_queue(hctx, async);
	}
}
EXPORT_SYMBOL(blk_mq_run_hw_queues);

/**
 * blk_mq_queue_stopped() - check whether one or more hctxs have been stopped
 * @q: request queue.
 *
 * The caller is responsible for serializing this function against
 * blk_mq_{start,stop}_hw_queue().
 */
bool blk_mq_queue_stopped(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i)
		if (blk_mq_hctx_stopped(hctx))
			return true;

	return false;
}
EXPORT_SYMBOL(blk_mq_queue_stopped);

/*
 * This function is often used for pausing .queue_rq() by driver when
 * there isn't enough resource or some conditions aren't satisfied, and
 * BLK_MQ_RQ_QUEUE_BUSY is usually returned.
 *
 * We do not guarantee that dispatch can be drained or blocked
 * after blk_mq_stop_hw_queue() returns. Please use
 * blk_mq_quiesce_queue() for that requirement.
 */
void blk_mq_stop_hw_queue(struct blk_mq_hw_ctx *hctx)
{
	cancel_delayed_work(&hctx->run_work);
	cancel_delayed_work(&hctx->delay_work);
	set_bit(BLK_MQ_S_STOPPED, &hctx->state);
}
EXPORT_SYMBOL(blk_mq_stop_hw_queue);

/*
 * This function is often used for pausing .queue_rq() by driver when
 * there isn't enough resource or some conditions aren't satisfied, and
 * BLK_MQ_RQ_QUEUE_BUSY is usually returned.
 *
 * We do not guarantee that dispatch can be drained or blocked
 * after blk_mq_stop_hw_queues() returns. Please use
 * blk_mq_quiesce_queue() for that requirement.
 */
void blk_mq_stop_hw_queues(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i)
		blk_mq_stop_hw_queue(hctx);
}
EXPORT_SYMBOL(blk_mq_stop_hw_queues);

void blk_mq_start_hw_queue(struct blk_mq_hw_ctx *hctx)
{
	clear_bit(BLK_MQ_S_STOPPED, &hctx->state);

	blk_mq_run_hw_queue(hctx, false);
}
EXPORT_SYMBOL(blk_mq_start_hw_queue);

void blk_mq_start_hw_queues(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i)
		blk_mq_start_hw_queue(hctx);
}
EXPORT_SYMBOL(blk_mq_start_hw_queues);

void blk_mq_start_stopped_hw_queues(struct request_queue *q, bool async)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i) {
		if (!blk_mq_hctx_stopped(hctx))
			continue;

		clear_bit(BLK_MQ_S_STOPPED, &hctx->state);
		blk_mq_run_hw_queue(hctx, async);
	}
}
EXPORT_SYMBOL(blk_mq_start_stopped_hw_queues);

static void blk_mq_run_work_fn(struct work_struct *work)
{
	struct blk_mq_hw_ctx *hctx;

	hctx = container_of(work, struct blk_mq_hw_ctx, run_work.work);

	__blk_mq_run_hw_queue(hctx);
}

static void blk_mq_delay_work_fn(struct work_struct *work)
{
	struct blk_mq_hw_ctx *hctx;

	hctx = container_of(work, struct blk_mq_hw_ctx, delay_work.work);

	if (test_and_clear_bit(BLK_MQ_S_STOPPED, &hctx->state))
		__blk_mq_run_hw_queue(hctx);
}

static inline void __blk_mq_insert_req_list(struct blk_mq_hw_ctx *hctx,
					    struct request *rq,
					    bool at_head)
{
	struct blk_mq_ctx *ctx = rq->mq_ctx;

	trace_block_rq_insert(hctx->queue, rq);

	if (at_head)
		list_add(&rq->queuelist, &ctx->rq_list);
	else
		list_add_tail(&rq->queuelist, &ctx->rq_list);
}

void __blk_mq_insert_request(struct blk_mq_hw_ctx *hctx, struct request *rq,
			     bool at_head)
{
	struct blk_mq_ctx *ctx = rq->mq_ctx;

	__blk_mq_insert_req_list(hctx, rq, at_head);
	blk_mq_hctx_mark_pending(hctx, ctx);
}

/*
 * Should only be used carefully, when the caller knows we want to
 * bypass a potential IO scheduler on the target device.
 */
void blk_mq_request_bypass_insert(struct request *rq, bool run_queue)
{
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(rq->q, ctx->cpu);

	spin_lock(&hctx->lock);
	list_add_tail(&rq->queuelist, &hctx->dispatch);
	spin_unlock(&hctx->lock);

	if (run_queue)
		blk_mq_run_hw_queue(hctx, false);
}

void blk_mq_insert_requests(struct blk_mq_hw_ctx *hctx, struct blk_mq_ctx *ctx,
			    struct list_head *list)

{
	struct request *rq;

	/*
	 * preemption doesn't flush plug list, so it's possible ctx->cpu is
	 * offline now
	 */
	list_for_each_entry(rq, list, queuelist) {
		BUG_ON(rq->mq_ctx != ctx);
		trace_block_rq_insert(hctx->queue, rq);
	}

	spin_lock(&ctx->lock);
	list_splice_tail_init(list, &ctx->rq_list);
	blk_mq_hctx_mark_pending(hctx, ctx);
	spin_unlock(&ctx->lock);
}

static int plug_ctx_cmp(void *priv, struct list_head *a, struct list_head *b)
{
	struct request *rqa = container_of(a, struct request, queuelist);
	struct request *rqb = container_of(b, struct request, queuelist);

	return !(rqa->mq_ctx < rqb->mq_ctx ||
		 (rqa->mq_ctx == rqb->mq_ctx &&
		  blk_rq_pos(rqa) < blk_rq_pos(rqb)));
}

void blk_mq_flush_plug_list(struct blk_plug *plug, bool from_schedule)
{
	struct blk_mq_ctx *this_ctx;
	struct request_queue *this_q;
	struct request *rq;
	LIST_HEAD(list);
	LIST_HEAD(ctx_list);
	unsigned int depth;

	list_splice_init(&plug->mq_list, &list);

	list_sort(NULL, &list, plug_ctx_cmp);

	this_q = NULL;
	this_ctx = NULL;
	depth = 0;

	while (!list_empty(&list)) {
		rq = list_entry_rq(list.next);
		list_del_init(&rq->queuelist);
		BUG_ON(!rq->q);
		if (rq->mq_ctx != this_ctx) {
			if (this_ctx) {
				trace_block_unplug(this_q, depth, from_schedule);
				blk_mq_sched_insert_requests(this_q, this_ctx,
								&ctx_list,
								from_schedule);
			}

			this_ctx = rq->mq_ctx;
			this_q = rq->q;
			depth = 0;
		}

		depth++;
		list_add_tail(&rq->queuelist, &ctx_list);
	}

	/*
	 * If 'this_ctx' is set, we know we have entries to complete
	 * on 'ctx_list'. Do those.
	 */
	if (this_ctx) {
		trace_block_unplug(this_q, depth, from_schedule);
		blk_mq_sched_insert_requests(this_q, this_ctx, &ctx_list,
						from_schedule);
	}
}

static void blk_mq_bio_to_request(struct request *rq, struct bio *bio)
{
	init_request_from_bio(rq, bio);

	if (blk_do_io_stat(rq))
		blk_account_io_start(rq, true);
}

static inline bool hctx_allow_merges(struct blk_mq_hw_ctx *hctx)
{
	return (hctx->flags & BLK_MQ_F_SHOULD_MERGE) &&
		!blk_queue_nomerges(hctx->queue);
}

/* attempt to merge bio into current sw queue */
static inline bool blk_mq_merge_bio(struct request_queue *q, struct bio *bio)
{
	bool ret = false;
	struct blk_mq_ctx *ctx = blk_mq_get_ctx(q);
	struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(q, ctx->cpu);

	if (hctx_allow_merges(hctx) && bio_mergeable(bio) &&
			!list_empty_careful(&ctx->rq_list)) {
		spin_lock(&ctx->lock);
		ret = blk_mq_attempt_merge(q, ctx, bio);
		spin_unlock(&ctx->lock);
	}

	blk_mq_put_ctx(ctx);
	return ret;
}

static inline void blk_mq_queue_io(struct blk_mq_hw_ctx *hctx,
				   struct blk_mq_ctx *ctx,
				   struct request *rq)
{
	spin_lock(&ctx->lock);
	__blk_mq_insert_request(hctx, rq, false);
	spin_unlock(&ctx->lock);
}

static int __blk_mq_issue_directly(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
	struct request_queue *q = rq->q;
	struct blk_mq_queue_data bd = {
		.rq = rq,
		.list = NULL,
		.last = true,
	};
	int ret;

	/*
	 * For OK queue, we are done. For error, caller may kill it.
	 * Any other error (busy), just add it to our list as we
	 * previously would have done.
	 */
	ret = q->mq_ops->queue_rq(hctx, &bd);
	switch (ret) {
	case BLK_MQ_RQ_QUEUE_OK:
		blk_mq_update_dispatch_busy(hctx, false);
		break;
	case BLK_MQ_RQ_QUEUE_BUSY:
	case BLK_MQ_RQ_QUEUE_DEV_BUSY:
		blk_mq_update_dispatch_busy(hctx, true);
		__blk_mq_requeue_request(rq);
		break;
	default:
		blk_mq_update_dispatch_busy(hctx, false);
		break;
	}

	return ret;
}

static int __blk_mq_try_issue_directly(struct blk_mq_hw_ctx *hctx,
						struct request *rq,
						bool bypass_insert)
{
	struct request_queue *q = rq->q;
	bool run_queue = true;

	/*
	 * RCU or SRCU read lock is needed before checking quiesced flag.
	 *
	 * When queue is stopped or quiesced, ignore 'bypass_insert' from
	 * blk_mq_request_issue_directly(), and return BLK_STS_OK to caller,
	 * and avoid driver to try to dispatch again.
	 */
	if (blk_mq_hctx_stopped(hctx) || blk_queue_quiesced(q)) {
		run_queue = false;
		bypass_insert = false;
		goto insert;
	}

	if (q->elevator && !bypass_insert)
		goto insert;

	if (!blk_mq_get_dispatch_budget(hctx))
		goto insert;

	if (!blk_mq_get_driver_tag(rq, NULL, false)) {
		blk_mq_put_dispatch_budget(hctx);
		goto insert;
	}

	return __blk_mq_issue_directly(hctx, rq);
insert:
	if (bypass_insert)
		return BLK_MQ_RQ_QUEUE_BUSY;

	blk_mq_request_bypass_insert(rq, run_queue);
	return BLK_MQ_RQ_QUEUE_OK;
}

static void blk_mq_try_issue_directly(struct blk_mq_hw_ctx *hctx,
				      struct request *rq)
{
	int ret;
	int srcu_idx;

	might_sleep_if(hctx->flags & BLK_MQ_F_BLOCKING);
	hctx_lock(hctx, &srcu_idx);
	ret = __blk_mq_try_issue_directly(hctx, rq, false);
	if (ret == BLK_MQ_RQ_QUEUE_BUSY || ret == BLK_MQ_RQ_QUEUE_DEV_BUSY)
		blk_mq_request_bypass_insert(rq, true);
	else if (ret != BLK_MQ_RQ_QUEUE_OK)
		blk_mq_end_request(rq, ret);

	hctx_unlock(hctx, srcu_idx);
}

int blk_mq_request_issue_directly(struct request *rq)
{
	int ret;
	int srcu_idx;
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(rq->q, ctx->cpu);

	hctx_lock(hctx, &srcu_idx);
	ret = __blk_mq_try_issue_directly(hctx, rq, true);
	hctx_unlock(hctx, srcu_idx);

	return ret;
}

void blk_mq_try_issue_list_directly(struct blk_mq_hw_ctx *hctx,
		struct list_head *list)
{
	while (!list_empty(list)) {
		int ret;
		struct request *rq = list_first_entry(list, struct request,
				queuelist);

		list_del_init(&rq->queuelist);
		ret = blk_mq_request_issue_directly(rq);
		if (ret != BLK_MQ_RQ_QUEUE_OK) {
			if (ret == BLK_MQ_RQ_QUEUE_BUSY ||
					ret == BLK_MQ_RQ_QUEUE_DEV_BUSY) {
				blk_mq_request_bypass_insert(rq,
							list_empty(list));
				break;
			}
			blk_mq_end_request(rq, ret);
		}
	}
}

static void blk_mq_make_request(struct request_queue *q, struct bio *bio)
{
	const int is_sync = rw_is_sync(bio->bi_rw);
	const int is_flush_fua = bio->bi_rw & (REQ_FLUSH | REQ_FUA);
	struct blk_mq_alloc_data data = { .flags = 0 };
	struct request *rq;
	unsigned int request_count = 0;
	struct blk_plug *plug;
	struct request *same_queue_rq = NULL;

	blk_queue_bounce(q, &bio);

	if (bio_integrity_enabled(bio) && bio_integrity_prep(bio)) {
		bio_endio(bio, -EIO);
		return;
	}

	if (!is_flush_fua && !blk_queue_nomerges(q) &&
	    blk_attempt_plug_merge(q, bio, &request_count, &same_queue_rq))
		return;

	if (blk_mq_sched_bio_merge(q, bio))
		return;

	if (blk_mq_merge_bio(q, bio))
		return;

	trace_block_getrq(q, bio, bio->bi_rw);

	rq = blk_mq_sched_get_request(q, bio, bio->bi_rw, &data);
	if (unlikely(!rq))
		return;

	plug = current->plug;
	if (unlikely(is_flush_fua)) {
		blk_mq_put_ctx(data.ctx);
		blk_mq_bio_to_request(rq, bio);

		/* bypass scheduler for flush rq */
		blk_insert_flush(rq);
		blk_mq_run_hw_queue(data.hctx, true);
	} else if (plug && q->nr_hw_queues == 1) {
		struct request *last = NULL;

		blk_mq_put_ctx(data.ctx);
		blk_mq_bio_to_request(rq, bio);

		/*
		 * @request_count may become stale because of schedule
		 * out, so check the list again.
		 */
		if (list_empty(&plug->mq_list))
			request_count = 0;
		else if (blk_queue_nomerges(q))
			request_count = blk_plug_queued_count(q);

		if (!request_count)
			trace_block_plug(q);
		else
			last = list_entry_rq(plug->mq_list.prev);

		if (request_count >= BLK_MAX_REQUEST_COUNT || (last &&
		    blk_rq_bytes(last) >= BLK_PLUG_FLUSH_SIZE)) {
			blk_flush_plug_list(plug, false);
			trace_block_plug(q);
		}

		list_add_tail(&rq->queuelist, &plug->mq_list);
	} else if (plug && !blk_queue_nomerges(q)) {
		blk_mq_bio_to_request(rq, bio);

		/*
		 * We do limited plugging. If the bio can be merged, do that.
		 * Otherwise the existing request in the plug list will be
		 * issued. So the plug list will have one request at most
		 * The plug list might get flushed before this. If that happens,
		 * the plug list is empty, and same_queue_rq is invalid.
		 */
		if (list_empty(&plug->mq_list))
			same_queue_rq = NULL;
		if (same_queue_rq)
			list_del_init(&same_queue_rq->queuelist);
		list_add_tail(&rq->queuelist, &plug->mq_list);

		blk_mq_put_ctx(data.ctx);

		if (same_queue_rq) {
			data.hctx = blk_mq_map_queue(q,
					same_queue_rq->mq_ctx->cpu);
			blk_mq_try_issue_directly(data.hctx, same_queue_rq);
		}
	} else if ((q->nr_hw_queues > 1 && is_sync) || (!q->elevator &&
			!data.hctx->dispatch_busy)) {
		blk_mq_put_ctx(data.ctx);
		blk_mq_bio_to_request(rq, bio);
		blk_mq_try_issue_directly(data.hctx, rq);
	} else if (q->elevator) {
		blk_mq_put_ctx(data.ctx);
		blk_mq_bio_to_request(rq, bio);
		blk_mq_sched_insert_request(rq, false, true, true);
	} else {
		blk_mq_put_ctx(data.ctx);
		blk_mq_bio_to_request(rq, bio);
		blk_mq_queue_io(data.hctx, data.ctx, rq);
		blk_mq_run_hw_queue(data.hctx, true);
	}
}

void blk_mq_free_rqs(struct blk_mq_tag_set *set, struct blk_mq_tags *tags,
		     unsigned int hctx_idx)
{
	struct page *page;

	if (tags->rqs && set->ops->exit_request) {
		int i;

		for (i = 0; i < tags->nr_tags; i++) {
			struct request *rq = tags->static_rqs[i];

			if (!rq)
				continue;
			set->ops->exit_request(set, rq, hctx_idx);
			tags->static_rqs[i] = NULL;
		}
	}

	while (!list_empty(&tags->page_list)) {
		page = list_first_entry(&tags->page_list, struct page, lru);
		list_del_init(&page->lru);
		/*
		 * Remove kmemleak object previously allocated in
		 * blk_mq_init_rq_map().
		 */
		kmemleak_free(page_address(page));
		__free_pages(page, page->private);
	}
}

void blk_mq_free_rq_map(struct blk_mq_tags *tags)
{
	kfree(tags->rqs);
	tags->rqs = NULL;
	kfree(tags->static_rqs);
	tags->static_rqs = NULL;

	blk_mq_free_tags(tags);
}

struct blk_mq_tags *blk_mq_alloc_rq_map(struct blk_mq_tag_set *set,
					unsigned int hctx_idx,
					unsigned int nr_tags,
					unsigned int reserved_tags)
{
	struct blk_mq_tags *tags;

	tags = blk_mq_init_tags(nr_tags, reserved_tags,
				set->numa_node,
				BLK_MQ_FLAG_TO_ALLOC_POLICY(set->flags));
	if (!tags)
		return NULL;

	tags->rqs = kzalloc_node(nr_tags * sizeof(struct request *),
				 GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY,
				 set->numa_node);
	if (!tags->rqs) {
		blk_mq_free_tags(tags);
		return NULL;
	}

	tags->static_rqs = kzalloc_node(nr_tags * sizeof(struct request *),
				 GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY,
				 set->numa_node);
	if (!tags->static_rqs) {
		kfree(tags->rqs);
		blk_mq_free_tags(tags);
		return NULL;
	}

	return tags;
}

static size_t order_to_size(unsigned int order)
{
	return (size_t)PAGE_SIZE << order;
}

int blk_mq_alloc_rqs(struct blk_mq_tag_set *set, struct blk_mq_tags *tags,
		     unsigned int hctx_idx, unsigned int depth)
{
	unsigned int i, j, entries_per_page, max_order = 4;
	size_t rq_size, left;

	INIT_LIST_HEAD(&tags->page_list);

	/*
	 * rq_size is the size of the request plus driver payload, rounded
	 * to the cacheline size
	 */
	rq_size = round_up(sizeof(struct request) + set->cmd_size +
			   sizeof(struct request_aux), cache_line_size());
	left = rq_size * depth;

	for (i = 0; i < depth; ) {
		int this_order = max_order;
		struct page *page;
		int to_do;
		void *p;

		while (this_order && left < order_to_size(this_order - 1))
			this_order--;

		do {
			page = alloc_pages_node(set->numa_node,
				GFP_NOIO | __GFP_NOWARN | __GFP_NORETRY | __GFP_ZERO,
				this_order);
			if (page)
				break;
			if (!this_order--)
				break;
			if (order_to_size(this_order) < rq_size)
				break;
		} while (1);

		if (!page)
			goto fail;

		page->private = this_order;
		list_add_tail(&page->lru, &tags->page_list);

		p = page_address(page);
		/*
		 * Allow kmemleak to scan these pages as they contain pointers
		 * to additional allocations like via ops->init_request().
		 */
		kmemleak_alloc(p, order_to_size(this_order), 1, GFP_NOIO);
		entries_per_page = order_to_size(this_order) / rq_size;
		to_do = min(entries_per_page, depth - i);
		left -= to_do * rq_size;
		for (j = 0; j < to_do; j++) {
			struct request *rq = p;

			tags->static_rqs[i] = rq;
			if (set->ops->init_request) {
				if (set->ops->init_request(set, rq, hctx_idx,
						set->numa_node)) {
					tags->static_rqs[i] = NULL;
					goto fail;
				}
			}

			p += rq_size;
			i++;
		}
	}
	return 0;

fail:
	blk_mq_free_rqs(set, tags, hctx_idx);
	return -ENOMEM;
}

/*
 * 'cpu' is going away. splice any existing rq_list entries from this
 * software queue to the hw queue dispatch list, and ensure that it
 * gets run.
 */
static int blk_mq_hctx_cpu_offline(struct blk_mq_hw_ctx *hctx, int cpu)
{
	struct blk_mq_ctx *ctx;
	LIST_HEAD(tmp);

	ctx = __blk_mq_get_ctx(hctx->queue, cpu);

	spin_lock(&ctx->lock);
	if (!list_empty(&ctx->rq_list)) {
		list_splice_init(&ctx->rq_list, &tmp);
		blk_mq_hctx_clear_pending(hctx, ctx);
	}
	spin_unlock(&ctx->lock);

	if (list_empty(&tmp))
		return NOTIFY_OK;

	spin_lock(&hctx->lock);
	list_splice_tail_init(&tmp, &hctx->dispatch);
	spin_unlock(&hctx->lock);

	blk_mq_run_hw_queue(hctx, true);
	return NOTIFY_OK;
}

static int blk_mq_hctx_notify(void *data, unsigned long action,
			      unsigned int cpu)
{
	struct blk_mq_hw_ctx *hctx = data;

	if (action == CPU_DEAD || action == CPU_DEAD_FROZEN)
		return blk_mq_hctx_cpu_offline(hctx, cpu);

	/*
	 * In case of CPU online, tags may be reallocated
	 * in blk_mq_map_swqueue() after mapping is updated.
	 */

	return NOTIFY_OK;
}

/* hctx->ctxs will be freed in queue's release handler */
static void blk_mq_exit_hctx(struct request_queue *q,
		struct blk_mq_tag_set *set,
		struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	blk_mq_debugfs_unregister_hctx(hctx);

	if (blk_mq_hw_queue_mapped(hctx))
		blk_mq_tag_idle(hctx);

	if (set->ops->exit_request)
		set->ops->exit_request(set, hctx->fq->flush_rq, hctx_idx);

	blk_mq_sched_exit_hctx(q, hctx, hctx_idx);

	if (set->ops->exit_hctx)
		set->ops->exit_hctx(hctx, hctx_idx);

	if (hctx->flags & BLK_MQ_F_BLOCKING)
		cleanup_srcu_struct(&hctx->queue_rq_srcu);

	blk_mq_unregister_cpu_notifier(&hctx->cpu_notifier);
	blk_free_flush_queue(hctx->fq);
	sbitmap_free(&hctx->ctx_map);
}

static void blk_mq_exit_hw_queues(struct request_queue *q,
		struct blk_mq_tag_set *set, int nr_queue)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned int i;

	queue_for_each_hw_ctx(q, hctx, i) {
		if (i == nr_queue)
			break;
		blk_mq_exit_hctx(q, set, hctx, i);
	}
}

static void blk_mq_free_hw_queues(struct request_queue *q,
		struct blk_mq_tag_set *set)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned int i;

	queue_for_each_hw_ctx(q, hctx, i)
		free_cpumask_var(hctx->cpumask);
}

static int blk_mq_init_hctx(struct request_queue *q,
		struct blk_mq_tag_set *set,
		struct blk_mq_hw_ctx *hctx, unsigned hctx_idx)
{
	int node;

	node = hctx->numa_node;
	if (node == NUMA_NO_NODE)
		node = hctx->numa_node = set->numa_node;

	INIT_DELAYED_WORK(&hctx->run_work, blk_mq_run_work_fn);
	INIT_DELAYED_WORK(&hctx->delay_work, blk_mq_delay_work_fn);
	spin_lock_init(&hctx->lock);
	INIT_LIST_HEAD(&hctx->dispatch);
	hctx->queue = q;
	hctx->queue_num = hctx_idx;
	hctx->flags = set->flags & ~BLK_MQ_F_TAG_SHARED;

	blk_mq_init_cpu_notifier(&hctx->cpu_notifier,
					blk_mq_hctx_notify, hctx);
	blk_mq_register_cpu_notifier(&hctx->cpu_notifier);

	hctx->tags = set->tags[hctx_idx];

	/*
	 * Allocate space for all possible cpus to avoid allocation at
	 * runtime
	 */
	hctx->ctxs = kmalloc_node(nr_cpu_ids * sizeof(void *),
					GFP_KERNEL, node);
	if (!hctx->ctxs)
		goto unregister_cpu_notifier;

	if (sbitmap_init_node(&hctx->ctx_map, nr_cpu_ids, ilog2(8), GFP_KERNEL,
			      node))
		goto free_ctxs;

	hctx->nr_ctx = 0;

	init_waitqueue_func_entry(&hctx->dispatch_wait, blk_mq_dispatch_wake);
	INIT_LIST_HEAD(&hctx->dispatch_wait.task_list);

	if (set->ops->init_hctx &&
	    set->ops->init_hctx(hctx, set->driver_data, hctx_idx))
		goto free_bitmap;

	if (blk_mq_sched_init_hctx(q, hctx, hctx_idx))
		goto exit_hctx;

	hctx->fq = blk_alloc_flush_queue(q, hctx->numa_node, set->cmd_size +
			sizeof(struct request_aux));
	if (!hctx->fq)
		goto sched_exit_hctx;

	if (set->ops->init_request &&
	    set->ops->init_request(set, hctx->fq->flush_rq, hctx_idx,
				   node))
		goto free_fq;

	if (hctx->flags & BLK_MQ_F_BLOCKING)
		init_srcu_struct(&hctx->queue_rq_srcu);

	blk_mq_debugfs_register_hctx(q, hctx);

	return 0;

 free_fq:
	kfree(hctx->fq);
 sched_exit_hctx:
	blk_mq_sched_exit_hctx(q, hctx, hctx_idx);
 exit_hctx:
	if (set->ops->exit_hctx)
		set->ops->exit_hctx(hctx, hctx_idx);
 free_bitmap:
	sbitmap_free(&hctx->ctx_map);
 free_ctxs:
	kfree(hctx->ctxs);
 unregister_cpu_notifier:
	blk_mq_unregister_cpu_notifier(&hctx->cpu_notifier);

	return -1;
}

static void blk_mq_init_cpu_queues(struct request_queue *q,
				   unsigned int nr_hw_queues)
{
	unsigned int i;

	for_each_possible_cpu(i) {
		struct blk_mq_ctx *__ctx = per_cpu_ptr(q->queue_ctx, i);
		struct blk_mq_hw_ctx *hctx;

		memset(__ctx, 0, sizeof(*__ctx));
		__ctx->cpu = i;
		spin_lock_init(&__ctx->lock);
		INIT_LIST_HEAD(&__ctx->rq_list);
		__ctx->queue = q;

		/* If the cpu isn't online, the cpu is mapped to first hctx */
		if (!cpu_online(i))
			continue;

		hctx = blk_mq_map_queue(q, i);

		/*
		 * Set local node, IFF we have more than one hw queue. If
		 * not, we remain on the home node of the device
		 */
		if (nr_hw_queues > 1 && hctx->numa_node == NUMA_NO_NODE)
			hctx->numa_node = local_memory_node(cpu_to_node(i));
	}
}

static bool __blk_mq_alloc_rq_map(struct blk_mq_tag_set *set, int hctx_idx)
{
	int ret = 0;

	set->tags[hctx_idx] = blk_mq_alloc_rq_map(set, hctx_idx,
					set->queue_depth, set->reserved_tags);
	if (!set->tags[hctx_idx])
		return false;

	ret = blk_mq_alloc_rqs(set, set->tags[hctx_idx], hctx_idx,
				set->queue_depth);
	if (!ret)
		return true;

	blk_mq_free_rq_map(set->tags[hctx_idx]);
	set->tags[hctx_idx] = NULL;
	return false;
}

static void blk_mq_free_map_and_requests(struct blk_mq_tag_set *set,
					 unsigned int hctx_idx)
{
	if (set->tags[hctx_idx]) {
		blk_mq_free_rqs(set, set->tags[hctx_idx], hctx_idx);
		blk_mq_free_rq_map(set->tags[hctx_idx]);
		set->tags[hctx_idx] = NULL;
	}
}

static void blk_mq_map_swqueue(struct request_queue *q,
			       const struct cpumask *online_mask)
{
	unsigned int i, hctx_idx;
	struct blk_mq_hw_ctx *hctx;
	struct blk_mq_ctx *ctx;
	struct blk_mq_tag_set *set = q->tag_set;

	/*
	 * Avoid others reading imcomplete hctx->cpumask through sysfs
	 */
	mutex_lock(&q->sysfs_lock);

	queue_for_each_hw_ctx(q, hctx, i) {
		cpumask_clear(hctx->cpumask);
		hctx->nr_ctx = 0;
	}

	/*
	 * Map software to hardware queues
	 */
	for_each_possible_cpu(i) {
		/* If the cpu isn't online, the cpu is mapped to first hctx */
		if (!cpumask_test_cpu(i, online_mask))
			continue;

		hctx_idx = q->mq_map[i];
		/* unmapped hw queue can be remapped after CPU topo changed */
		if (!set->tags[hctx_idx] &&
		    !__blk_mq_alloc_rq_map(set, hctx_idx)) {
			/*
			 * If tags initialization fail for some hctx,
			 * that hctx won't be brought online.  In this
			 * case, remap the current ctx to hctx[0] which
			 * is guaranteed to always have tags allocated
			 */
			q->mq_map[i] = 0;
		}

		ctx = per_cpu_ptr(q->queue_ctx, i);
		hctx = blk_mq_map_queue(q, i);

		cpumask_set_cpu(i, hctx->cpumask);
		ctx->index_hw = hctx->nr_ctx;
		hctx->ctxs[hctx->nr_ctx++] = ctx;
	}

	mutex_unlock(&q->sysfs_lock);

	queue_for_each_hw_ctx(q, hctx, i) {
		/*
		 * If no software queues are mapped to this hardware queue,
		 * disable it and free the request entries.
		 */
		if (!hctx->nr_ctx) {
			/* Never unmap queue 0.  We need it as a
			 * fallback in case of a new remap fails
			 * allocation
			 */
			if (i && set->tags[i])
				blk_mq_free_map_and_requests(set, i);

			hctx->tags = NULL;
			continue;
		}

		hctx->tags = set->tags[i];
		WARN_ON(!hctx->tags);

		/*
		 * Set the map size to the number of mapped software queues.
		 * This is more accurate and more efficient than looping
		 * over all possibly mapped software queues.
		 */
		sbitmap_resize(&hctx->ctx_map, hctx->nr_ctx);

		/*
		 * Initialize batch roundrobin counts
		 */
		hctx->next_cpu = cpumask_first(hctx->cpumask);
		hctx->next_cpu_batch = BLK_MQ_CPU_WORK_BATCH;
	}
}

/*
 * Caller needs to ensure that we're either frozen/quiesced, or that
 * the queue isn't live yet.
 */
static void queue_set_hctx_shared(struct request_queue *q, bool shared)
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i) {
		if (shared) {
			if (test_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state))
				atomic_inc(&q->shared_hctx_restart);
			hctx->flags |= BLK_MQ_F_TAG_SHARED;
		} else {
			if (test_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state))
				atomic_dec(&q->shared_hctx_restart);
			hctx->flags &= ~BLK_MQ_F_TAG_SHARED;
		}
	}
}

static void blk_mq_update_tag_set_depth(struct blk_mq_tag_set *set,
					bool shared)
{
	struct request_queue *q;

	lockdep_assert_held(&set->tag_list_lock);

	list_for_each_entry(q, &set->tag_list, tag_set_list) {
		blk_mq_freeze_queue(q);
		queue_set_hctx_shared(q, shared);
		blk_mq_unfreeze_queue(q);
	}
}

static void blk_mq_del_queue_tag_set(struct request_queue *q)
{
	struct blk_mq_tag_set *set = q->tag_set;

	mutex_lock(&set->tag_list_lock);
	list_del_rcu(&q->tag_set_list);
	if (list_is_singular(&set->tag_list)) {
		/* just transitioned to unshared */
		set->flags &= ~BLK_MQ_F_TAG_SHARED;
		/* update existing queue */
		blk_mq_update_tag_set_depth(set, false);
	}
	mutex_unlock(&set->tag_list_lock);
	synchronize_rcu();
	INIT_LIST_HEAD(&q->tag_set_list);
}

static void blk_mq_add_queue_tag_set(struct blk_mq_tag_set *set,
				     struct request_queue *q)
{
	q->tag_set = set;

	mutex_lock(&set->tag_list_lock);

	/* Check to see if we're transitioning to shared (from 1 to 2 queues). */
	if (!list_empty(&set->tag_list) && !(set->flags & BLK_MQ_F_TAG_SHARED)) {
		set->flags |= BLK_MQ_F_TAG_SHARED;
		/* update existing queue */
		blk_mq_update_tag_set_depth(set, true);
	}
	if (set->flags & BLK_MQ_F_TAG_SHARED)
		queue_set_hctx_shared(q, true);
	list_add_tail_rcu(&q->tag_set_list, &set->tag_list);

	mutex_unlock(&set->tag_list_lock);
}

/*
 * It is the actual release handler for mq, but we do it from
 * request queue's release handler for avoiding use-after-free
 * and headache because q->mq_kobj shouldn't have been introduced,
 * but we can't group ctx/kctx kobj without it.
 */
void blk_mq_release(struct request_queue *q)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned int i;

	/* hctx kobj stays in hctx */
	queue_for_each_hw_ctx(q, hctx, i) {
		if (!hctx)
			continue;
		kfree(hctx->ctxs);
		kfree(hctx);
	}

	q->mq_map = NULL;

	kfree(q->queue_hw_ctx);

	/* ctx kobj stays in queue_ctx */
	free_percpu(q->queue_ctx);
}

struct request_queue *blk_mq_init_queue(struct blk_mq_tag_set *set)
{
	struct request_queue *uninit_q, *q;

	uninit_q = blk_alloc_queue_node(GFP_KERNEL, set->numa_node, NULL);
	if (!uninit_q)
		return ERR_PTR(-ENOMEM);

	q = blk_mq_init_allocated_queue(set, uninit_q);
	if (IS_ERR(q))
		blk_cleanup_queue(uninit_q);

	return q;
}
EXPORT_SYMBOL(blk_mq_init_queue);

static void blk_mq_realloc_hw_ctxs(struct blk_mq_tag_set *set,
						struct request_queue *q)
{
	int i, j;
	struct blk_mq_hw_ctx **hctxs = q->queue_hw_ctx;

	blk_mq_sysfs_unregister(q);

	/* protect against switching io scheduler  */
	mutex_lock(&q->sysfs_lock);
	for (i = 0; i < set->nr_hw_queues; i++) {
		int node;

		if (hctxs[i])
			continue;

		node = blk_mq_hw_queue_to_node(q->mq_map, i);
		hctxs[i] = kzalloc_node(sizeof(struct blk_mq_hw_ctx),
					GFP_KERNEL, node);
		if (!hctxs[i])
			break;

		if (!zalloc_cpumask_var_node(&hctxs[i]->cpumask, GFP_KERNEL,
						node)) {
			kfree(hctxs[i]);
			hctxs[i] = NULL;
			break;
		}

		atomic_set(&hctxs[i]->nr_active, 0);
		hctxs[i]->numa_node = node;
		hctxs[i]->queue_num = i;

		if (blk_mq_init_hctx(q, set, hctxs[i], i)) {
			free_cpumask_var(hctxs[i]->cpumask);
			kfree(hctxs[i]);
			hctxs[i] = NULL;
			break;
		}
		blk_mq_hctx_kobj_init(hctxs[i]);
	}
	for (j = i; j < q->nr_hw_queues; j++) {
		struct blk_mq_hw_ctx *hctx = hctxs[j];

		if (hctx) {
			if (hctx->tags)
				blk_mq_free_map_and_requests(set, j);
			blk_mq_exit_hctx(q, set, hctx, j);
			free_cpumask_var(hctx->cpumask);
			kobject_put(&hctx->kobj);
			kfree(hctx->ctxs);
			kfree(hctx);
			hctxs[j] = NULL;

		}
	}
	q->nr_hw_queues = i;
	mutex_unlock(&q->sysfs_lock);
	blk_mq_sysfs_register(q);
}

struct request_queue *blk_mq_init_allocated_queue(struct blk_mq_tag_set *set,
						  struct request_queue *q)
{
	/* mark the queue as mq asap */
	q->mq_ops = set->ops;

	q->poll_cb = blk_stat_alloc_callback(blk_mq_poll_stats_fn,
					     blk_stat_rq_ddir, 2, q);
	if (!q->poll_cb)
		goto err_exit;

	q->queue_ctx = alloc_percpu(struct blk_mq_ctx);
	if (!q->queue_ctx)
		goto err_exit;

	q->queue_hw_ctx = kzalloc_node(nr_cpu_ids * sizeof(*(q->queue_hw_ctx)),
						GFP_KERNEL, set->numa_node);
	if (!q->queue_hw_ctx)
		goto err_percpu;

	q->mq_map = set->mq_map;

	blk_mq_realloc_hw_ctxs(set, q);
	if (!q->nr_hw_queues)
		goto err_hctxs;

	INIT_WORK(&q->timeout_work, blk_mq_timeout_work);
	blk_queue_rq_timeout(q, set->timeout ? set->timeout : 30 * HZ);

	q->nr_queues = nr_cpu_ids;

	q->queue_flags |= QUEUE_FLAG_MQ_DEFAULT;

	if (!(set->flags & BLK_MQ_F_SG_MERGE))
		q->queue_flags |= 1 << QUEUE_FLAG_NO_SG_MERGE;

	q->sg_reserved_size = INT_MAX;

	INIT_DELAYED_WORK(&q->requeue_work, blk_mq_requeue_work);
	INIT_LIST_HEAD(&q->requeue_list);
	spin_lock_init(&q->requeue_lock);

	blk_queue_make_request(q, blk_mq_make_request);

	/*
	 * Do this after blk_queue_make_request() overrides it...
	 */
	q->nr_requests = set->queue_depth;

	if (set->ops->complete)
		blk_queue_softirq_done(q, set->ops->complete);

	blk_mq_init_cpu_queues(q, set->nr_hw_queues);

	get_online_cpus();
	mutex_lock(&all_q_mutex);

	list_add_tail(&q->all_q_node, &all_q_list);
	blk_mq_add_queue_tag_set(set, q);
	blk_mq_map_swqueue(q, cpu_online_mask);

	mutex_unlock(&all_q_mutex);
	put_online_cpus();

	if (!(set->flags & BLK_MQ_F_NO_SCHED)) {
		int ret;

		ret = blk_mq_sched_init(q);
		if (ret)
			return ERR_PTR(ret);
	}

	return q;

err_hctxs:
	kfree(q->queue_hw_ctx);
err_percpu:
	free_percpu(q->queue_ctx);
err_exit:
	q->mq_ops = NULL;
	return ERR_PTR(-ENOMEM);
}
EXPORT_SYMBOL(blk_mq_init_allocated_queue);

void blk_mq_free_queue(struct request_queue *q)
{
	struct blk_mq_tag_set	*set = q->tag_set;

	mutex_lock(&all_q_mutex);
	list_del_init(&q->all_q_node);
	mutex_unlock(&all_q_mutex);

	blk_mq_del_queue_tag_set(q);

	blk_mq_exit_hw_queues(q, set, set->nr_hw_queues);
	blk_mq_free_hw_queues(q, set);
}

/* Basically redo blk_mq_init_queue with queue frozen */
static void blk_mq_queue_reinit(struct request_queue *q,
				const struct cpumask *online_mask)
{
	WARN_ON_ONCE(!atomic_read(&q->mq_freeze_depth));

	blk_mq_debugfs_unregister_hctxs(q);
	blk_mq_sysfs_unregister(q);

	/*
	 * redo blk_mq_init_cpu_queues and blk_mq_init_hw_queues. FIXME: maybe
	 * we should change hctx numa_node according to new topology (this
	 * involves free and re-allocate memory, worthy doing?)
	 */

	blk_mq_map_swqueue(q, online_mask);

	blk_mq_sysfs_register(q);
	blk_mq_debugfs_register_hctxs(q);
}

static void blk_mq_freeze_queue_list(struct list_head *list)
{
	struct request_queue *q;

	/*
	 * We need to freeze and reinit all existing queues.  Freezing
	 * involves synchronous wait for an RCU grace period and doing it
	 * one by one may take a long time.  Start freezing all queues in
	 * one swoop and then wait for the completions so that freezing can
	 * take place in parallel.
	 */
	list_for_each_entry(q, list, all_q_node)
		blk_freeze_queue_start(q);
	list_for_each_entry(q, list, all_q_node) {
		blk_mq_freeze_queue_wait(q);

		/*
		 * timeout handler can't touch hw queue during the
		 * reinitialization
		 */
		del_timer_sync(&q->timeout);
	}
}

/*
 * When freezing queues in blk_mq_queue_reinit_notify(), we have to freeze
 * queues in order from the list of 'all_q_list' for avoid IO deadlock:
 *
 * 1) DM queue or other queue which is at the top of usual queues, it
 * has to be frozen before the underlying queues, otherwise once the
 * underlying queue is frozen, any IO from upper layer queue can't be
 * drained up, and blk_mq_freeze_queue_wait() will wait for ever on this
 * kind of queue
 *
 * 2) NVMe admin queue is used in NVMe's reset handler, and IO queue is
 * frozen and quiesced before resetting controller, if there is any pending
 * IO before sending requests to admin queue, IO hang is caused because admin
 * queue may has been frozon, so reset can't move on, and finally
 * blk_mq_freeze_queue_wait() waits for ever on NVMe IO queue in
 * blk_mq_queue_reinit_notify(). Avoid this issue by freezing admin queue
 * after NVMe namespace queue is frozen.
 */
static void __blk_mq_freeze_all_queue_list(void)
{
	struct request_queue *q, *next;
	LIST_HEAD(front);
	LIST_HEAD(tail);

	list_for_each_entry_safe(q, next, &all_q_list, all_q_node) {
		if (q->front_queue)
			list_move(&q->all_q_node, &front);
		else if (q->tail_queue)
			list_move(&q->all_q_node, &tail);
	}

	blk_mq_freeze_queue_list(&front);
	blk_mq_freeze_queue_list(&all_q_list);
	blk_mq_freeze_queue_list(&tail);

	list_splice(&front, &all_q_list);
	list_splice_tail(&tail, &all_q_list);
}

static int blk_mq_queue_reinit_notify(struct notifier_block *nb,
				      unsigned long action, void *hcpu)
{
	struct request_queue *q;
	int cpu = (unsigned long)hcpu;
	/*
	 * New online cpumask which is going to be set in this hotplug event.
	 * Declare this cpumasks as global as cpu-hotplug operation is invoked
	 * one-by-one and dynamically allocating this could result in a failure.
	 */
	static struct cpumask online_new;

	/*
	 * Before hotadded cpu starts handling requests, new mappings must
	 * be established.  Otherwise, these requests in hw queue might
	 * never be dispatched.
	 *
	 * For example, there is a single hw queue (hctx) and two CPU queues
	 * (ctx0 for CPU0, and ctx1 for CPU1).
	 *
	 * Now CPU1 is just onlined and a request is inserted into
	 * ctx1->rq_list and set bit0 in pending bitmap as ctx1->index_hw is
	 * still zero.
	 *
	 * And then while running hw queue, blk_mq_flush_busy_ctxs() finds
	 * bit0 is set in pending bitmap and tries to retrieve requests in
	 * hctx->ctxs[0]->rq_list. But htx->ctxs[0] is a pointer to ctx0, so
	 * the request in ctx1->rq_list is ignored.
	 */
	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_DEAD:
	case CPU_UP_CANCELED:
		cpumask_copy(&online_new, cpu_online_mask);
		break;
	case CPU_UP_PREPARE:
		cpumask_copy(&online_new, cpu_online_mask);
		cpumask_set_cpu(cpu, &online_new);
		break;
	default:
		return NOTIFY_OK;
	}

	mutex_lock(&all_q_mutex);

	__blk_mq_freeze_all_queue_list();

	/*
	 * Multiple queues can share the same tag set, so we keep track of
	 * which tag_sets we have already locked by setting
	 * BLK_MQ_F_TAG_LOCKED
	 */
	list_for_each_entry(q, &all_q_list, all_q_node) {
		if (!(q->tag_set->flags & BLK_MQ_F_TAG_LOCKED)) {
			mutex_lock(&q->tag_set->tag_list_lock);
			q->tag_set->flags |= BLK_MQ_F_TAG_LOCKED;
		}
		blk_mq_queue_reinit(q, &online_new);
	}

	list_for_each_entry(q, &all_q_list, all_q_node) {
		if (q->tag_set->flags & BLK_MQ_F_TAG_LOCKED) {
			q->tag_set->flags &= ~BLK_MQ_F_TAG_LOCKED;
			mutex_unlock(&q->tag_set->tag_list_lock);
		}
		blk_mq_unfreeze_queue(q);
	}

	mutex_unlock(&all_q_mutex);
	return NOTIFY_OK;
}

static int __blk_mq_alloc_rq_maps(struct blk_mq_tag_set *set)
{
	int i;

	for (i = 0; i < set->nr_hw_queues; i++)
		if (!__blk_mq_alloc_rq_map(set, i))
			goto out_unwind;

	return 0;

out_unwind:
	while (--i >= 0)
		blk_mq_free_rq_map(set->tags[i]);

	return -ENOMEM;
}

/*
 * Allocate the request maps associated with this tag_set. Note that this
 * may reduce the depth asked for, if memory is tight. set->queue_depth
 * will be updated to reflect the allocated depth.
 */
static int blk_mq_alloc_rq_maps(struct blk_mq_tag_set *set)
{
	unsigned int depth;
	int err;

	depth = set->queue_depth;
	do {
		err = __blk_mq_alloc_rq_maps(set);
		if (!err)
			break;

		set->queue_depth >>= 1;
		if (set->queue_depth < set->reserved_tags + BLK_MQ_TAG_MIN) {
			err = -ENOMEM;
			break;
		}
	} while (set->queue_depth);

	if (!set->queue_depth || err) {
		pr_err("blk-mq: failed to allocate request map\n");
		return -ENOMEM;
	}

	if (depth != set->queue_depth)
		pr_info("blk-mq: reduced tag depth (%u -> %u)\n",
						depth, set->queue_depth);

	return 0;
}

static int blk_mq_update_queue_map(struct blk_mq_tag_set *set)
{
	if (set->ops->aux_ops && set->ops->aux_ops->map_queues) {
		int cpu;
		/*
		 * transport .map_queues is usually done in the following
		 * way:
		 *
		 * for (queue = 0; queue < set->nr_hw_queues; queue++) {
		 * 	mask = get_cpu_mask(queue)
		 * 	for_each_cpu(cpu, mask)
		 * 		set->mq_map[cpu] = queue;
		 * }
		 *
		 * When we need to remap, the table has to be cleared for
		 * killing stale mapping since one CPU may not be mapped
		 * to any hw queue.
		 */
		for_each_possible_cpu(cpu)
			set->mq_map[cpu] = 0;
		return set->ops->aux_ops->map_queues(set);
	} else
		return blk_mq_map_queues(set);
}

/*
 * Alloc a tag set to be associated with one or more request queues.
 * May fail with EINVAL for various error conditions. May adjust the
 * requested depth down, if if it too large. In that case, the set
 * value will be stored in set->queue_depth.
 */
int blk_mq_alloc_tag_set(struct blk_mq_tag_set *set)
{
	int ret;

	BUILD_BUG_ON(BLK_MQ_MAX_DEPTH > 1 << BLK_MQ_UNIQUE_TAG_BITS);

	if (!set->nr_hw_queues)
		return -EINVAL;
	if (!set->queue_depth)
		return -EINVAL;
	if (set->queue_depth < set->reserved_tags + BLK_MQ_TAG_MIN)
		return -EINVAL;

	if (!set->ops->queue_rq)
		return -EINVAL;

	if (set->queue_depth > BLK_MQ_MAX_DEPTH) {
		pr_info("blk-mq: reduced tag depth to %u\n",
			BLK_MQ_MAX_DEPTH);
		set->queue_depth = BLK_MQ_MAX_DEPTH;
	}

	/*
	 * If a crashdump is active, then we are potentially in a very
	 * memory constrained environment. Limit us to 1 queue and
	 * 64 tags to prevent using too much memory.
	 */
	if (is_kdump_kernel()) {
		set->nr_hw_queues = 1;
		set->queue_depth = min(64U, set->queue_depth);
	}
	/*
	 * There is no use for more h/w queues than cpus.
	 */
	if (set->nr_hw_queues > nr_cpu_ids)
		set->nr_hw_queues = nr_cpu_ids;

	/* make rq_aux() natual aligned */
	set->cmd_size = round_up(set->cmd_size, sizeof(unsigned long));

	set->tags = kzalloc_node(nr_cpu_ids * sizeof(struct blk_mq_tags *),
				 GFP_KERNEL, set->numa_node);
	if (!set->tags)
		return -ENOMEM;

	ret = -ENOMEM;
	set->mq_map = kzalloc_node(sizeof(*set->mq_map) * nr_cpu_ids,
			GFP_KERNEL, set->numa_node);
	if (!set->mq_map)
		goto out_free_tags;

	ret = blk_mq_update_queue_map(set);
	if (ret)
		goto out_free_mq_map;

	ret = blk_mq_alloc_rq_maps(set);
	if (ret)
		goto out_free_mq_map;

	mutex_init(&set->tag_list_lock);
	INIT_LIST_HEAD(&set->tag_list);

	return 0;

out_free_mq_map:
	kfree(set->mq_map);
	set->mq_map = NULL;
out_free_tags:
	kfree(set->tags);
	set->tags = NULL;
	return ret;
}
EXPORT_SYMBOL(blk_mq_alloc_tag_set);

void blk_mq_free_tag_set(struct blk_mq_tag_set *set)
{
	int i;

	for (i = 0; i < nr_cpu_ids; i++)
		blk_mq_free_map_and_requests(set, i);

	kfree(set->mq_map);
	set->mq_map = NULL;

	kfree(set->tags);
	set->tags = NULL;
}
EXPORT_SYMBOL(blk_mq_free_tag_set);

int blk_mq_update_nr_requests(struct request_queue *q, unsigned int nr)
{
	struct blk_mq_tag_set *set = q->tag_set;
	struct blk_mq_hw_ctx *hctx;
	int i, ret;

	if (!set)
		return -EINVAL;

	blk_mq_freeze_queue(q);
	blk_mq_quiesce_queue(q);

	ret = 0;
	queue_for_each_hw_ctx(q, hctx, i) {
		if (!hctx->tags)
			continue;
		/*
		 * If we're using an MQ scheduler, just update the scheduler
		 * queue depth. This is similar to what the old code would do.
		 */
		if (!hctx->sched_tags) {
			ret = blk_mq_tag_update_depth(hctx, &hctx->tags, nr,
							false);
		} else {
			ret = blk_mq_tag_update_depth(hctx, &hctx->sched_tags,
							nr, true);
		}
		if (ret)
			break;
	}

	if (!ret)
		q->nr_requests = nr;

	blk_mq_unquiesce_queue(q);
	blk_mq_unfreeze_queue(q);

	return ret;
}

static void __blk_mq_update_nr_hw_queues(struct blk_mq_tag_set *set,
							int nr_hw_queues)
{
	struct request_queue *q;

	lockdep_assert_held(&set->tag_list_lock);

	if (nr_hw_queues > nr_cpu_ids)
		nr_hw_queues = nr_cpu_ids;
	if (nr_hw_queues < 1 || nr_hw_queues == set->nr_hw_queues)
		return;

	list_for_each_entry(q, &set->tag_list, tag_set_list)
		blk_mq_freeze_queue(q);
	/*
	 * Sync with blk_mq_queue_tag_busy_iter.
	 */
	synchronize_rcu();

	set->nr_hw_queues = nr_hw_queues;
	blk_mq_update_queue_map(set);
	list_for_each_entry(q, &set->tag_list, tag_set_list) {
		blk_mq_realloc_hw_ctxs(set, q);
		blk_mq_queue_reinit(q, cpu_online_mask);
	}

	list_for_each_entry(q, &set->tag_list, tag_set_list)
		blk_mq_unfreeze_queue(q);
}

void blk_mq_update_nr_hw_queues(struct blk_mq_tag_set *set, int nr_hw_queues)
{
	mutex_lock(&set->tag_list_lock);
	__blk_mq_update_nr_hw_queues(set, nr_hw_queues);
	mutex_unlock(&set->tag_list_lock);
}
EXPORT_SYMBOL_GPL(blk_mq_update_nr_hw_queues);

static void blk_mq_poll_stats_start(struct request_queue *q)
{
	/*
	 * We don't arm the callback if polling stats are not enabled or the
	 * callback is already active.
	 */
	if (!test_bit(QUEUE_FLAG_POLL_STATS, &q->queue_flags) ||
	    blk_stat_is_active(q->poll_cb))
		return;

	blk_stat_activate_msecs(q->poll_cb, 100);
}

static void blk_mq_poll_stats_fn(struct blk_stat_callback *cb)
{
	struct request_queue *q = cb->data;

	if (cb->stat[READ].nr_samples)
		q->poll_stat[READ] = cb->stat[READ];
	if (cb->stat[WRITE].nr_samples)
		q->poll_stat[WRITE] = cb->stat[WRITE];
}

void blk_mq_disable_hotplug(void)
{
	mutex_lock(&all_q_mutex);
}

void blk_mq_enable_hotplug(void)
{
	mutex_unlock(&all_q_mutex);
}

static int __init blk_mq_init(void)
{
	blk_mq_cpu_init();

	hotcpu_notifier(blk_mq_queue_reinit_notify, 0);

	return 0;
}
subsys_initcall(blk_mq_init);
