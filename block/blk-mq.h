#ifndef INT_BLK_MQ_H
#define INT_BLK_MQ_H

#include <linux/rh_kabi.h>

#include "blk-stat.h"
#include "blk-mq-tag.h"

struct blk_mq_tag_set;

struct blk_mq_ctx {
	struct {
		spinlock_t		lock;
		struct list_head	rq_list;
	}  ____cacheline_aligned_in_smp;

	unsigned int		cpu;
	unsigned int		index_hw;

	RH_KABI_DEPRECATE(unsigned int, ipi_redirect)

	/* incremented at dispatch time */
	unsigned long		rq_dispatched[2];
	unsigned long		rq_merged;

	/* incremented at completion time */
	unsigned long		____cacheline_aligned_in_smp rq_completed[2];

	struct request_queue	*queue;
	struct kobject		kobj;
} ____cacheline_aligned_in_smp;

void blk_mq_freeze_queue(struct request_queue *q);
void blk_mq_free_queue(struct request_queue *q);
int blk_mq_update_nr_requests(struct request_queue *q, unsigned int nr);
void blk_mq_wake_waiters(struct request_queue *q);
bool blk_mq_dispatch_rq_list(struct request_queue *, struct list_head *, bool);
void blk_mq_flush_busy_ctxs(struct blk_mq_hw_ctx *hctx, struct list_head *list);
bool blk_mq_get_driver_tag(struct request *rq, struct blk_mq_hw_ctx **hctx,
				bool wait);
struct request *blk_mq_dequeue_from_ctx(struct blk_mq_hw_ctx *hctx,
					struct blk_mq_ctx *start);

/*
 * Internal helpers for allocating/freeing the request map
 */
void blk_mq_free_rqs(struct blk_mq_tag_set *set, struct blk_mq_tags *tags,
		     unsigned int hctx_idx);
void blk_mq_free_rq_map(struct blk_mq_tags *tags);
struct blk_mq_tags *blk_mq_alloc_rq_map(struct blk_mq_tag_set *set,
					unsigned int hctx_idx,
					unsigned int nr_tags,
					unsigned int reserved_tags);
int blk_mq_alloc_rqs(struct blk_mq_tag_set *set, struct blk_mq_tags *tags,
		     unsigned int hctx_idx, unsigned int depth);

/*
 * Internal helpers for request insertion into sw queues
 */
void __blk_mq_insert_request(struct blk_mq_hw_ctx *hctx, struct request *rq,
				bool at_head);
void blk_mq_request_bypass_insert(struct request *rq, bool run_queue);
void blk_mq_insert_requests(struct blk_mq_hw_ctx *hctx, struct blk_mq_ctx *ctx,
				struct list_head *list);
/*
 * CPU hotplug helpers
 */
struct blk_mq_cpu_notifier;
void blk_mq_init_cpu_notifier(struct blk_mq_cpu_notifier *notifier,
			      int (*fn)(void *, unsigned long, unsigned int),
			      void *data);
void blk_mq_register_cpu_notifier(struct blk_mq_cpu_notifier *notifier);
void blk_mq_unregister_cpu_notifier(struct blk_mq_cpu_notifier *notifier);
void blk_mq_cpu_init(void);
void blk_mq_enable_hotplug(void);
void blk_mq_disable_hotplug(void);

/* Used by blk_insert_cloned_request() to issue request directly */
int blk_mq_request_issue_directly(struct request *rq);
void blk_mq_try_issue_list_directly(struct blk_mq_hw_ctx *hctx,
				    struct list_head *list);

/*
 * CPU -> queue mappings
 */
int blk_mq_map_queues(struct blk_mq_tag_set *set);
extern int blk_mq_hw_queue_to_node(unsigned int *map, unsigned int);

static inline struct blk_mq_hw_ctx *blk_mq_map_queue(struct request_queue *q,
		int cpu)
{
	return q->queue_hw_ctx[q->mq_map[cpu]];
}

/*
 * sysfs helpers
 */
extern int blk_mq_sysfs_register(struct request_queue *q);
extern void blk_mq_sysfs_unregister(struct request_queue *q);
extern void blk_mq_hctx_kobj_init(struct blk_mq_hw_ctx *hctx);
extern int __blk_mq_register_dev(struct device *dev, struct request_queue *q);

extern void blk_mq_rq_timed_out(struct request *req, bool reserved);

void blk_mq_release(struct request_queue *q);

static inline struct blk_mq_ctx *__blk_mq_get_ctx(struct request_queue *q,
					   unsigned int cpu)
{
	return per_cpu_ptr(q->queue_ctx, cpu);
}

/*
 * This assumes per-cpu software queueing queues. They could be per-node
 * as well, for instance. For now this is hardcoded as-is. Note that we don't
 * care about preemption, since we know the ctx's are persistent. This does
 * mean that we can't rely on ctx always matching the currently running CPU.
 */
static inline struct blk_mq_ctx *blk_mq_get_ctx(struct request_queue *q)
{
	return __blk_mq_get_ctx(q, get_cpu());
}

static inline void blk_mq_put_ctx(struct blk_mq_ctx *ctx)
{
	put_cpu();
}

struct blk_mq_alloc_data {
	/* input parameter */
	struct request_queue *q;
	unsigned int flags;
	unsigned int shallow_depth;

	/* input & output parameter */
	struct blk_mq_ctx *ctx;
	struct blk_mq_hw_ctx *hctx;
};

static inline struct blk_mq_tags *blk_mq_tags_from_data(struct blk_mq_alloc_data *data)
{
	if (data->flags & BLK_MQ_REQ_INTERNAL)
		return data->hctx->sched_tags;

	return data->hctx->tags;
}

/*
 * Internal helpers for request allocation/init/free
 */
void blk_mq_rq_ctx_init(struct request_queue *q, struct blk_mq_ctx *ctx,
			struct request *rq, unsigned int op);
void __blk_mq_finish_request(struct blk_mq_hw_ctx *hctx, struct blk_mq_ctx *ctx,
				struct request *rq);
void blk_mq_finish_request(struct request *rq);
struct request *__blk_mq_alloc_request(struct blk_mq_alloc_data *data, int rw);

static inline bool blk_mq_hctx_stopped(struct blk_mq_hw_ctx *hctx)
{
	return test_bit(BLK_MQ_S_STOPPED, &hctx->state);
}

static inline bool blk_mq_hw_queue_mapped(struct blk_mq_hw_ctx *hctx)
{
	return hctx->nr_ctx && hctx->tags;
}

static inline void blk_mq_put_dispatch_budget(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;

	if (q->mq_ops->aux_ops && q->mq_ops->aux_ops->put_budget)
		q->mq_ops->aux_ops->put_budget(hctx);
}

static inline bool blk_mq_get_dispatch_budget(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;

	if (q->mq_ops->aux_ops && q->mq_ops->aux_ops->get_budget)
		return q->mq_ops->aux_ops->get_budget(hctx);
	return true;
}

static inline void __blk_mq_put_driver_tag(struct blk_mq_hw_ctx *hctx,
					   struct request *rq)
{
	blk_mq_put_tag(hctx, hctx->tags, rq->mq_ctx, rq->tag);
	rq->tag = -1;

	if (rq->cmd_flags & REQ_MQ_INFLIGHT) {
		rq->cmd_flags &= ~REQ_MQ_INFLIGHT;
		atomic_dec(&hctx->nr_active);
	}
}

static inline void blk_mq_put_driver_tag_hctx(struct blk_mq_hw_ctx *hctx,
				       struct request *rq)
{
	if (rq->tag == -1 || rq_aux(rq)->internal_tag == -1)
		return;

	__blk_mq_put_driver_tag(hctx, rq);
}

static inline void blk_mq_put_driver_tag(struct request *rq)
{
	struct blk_mq_hw_ctx *hctx;

	if (rq->tag == -1 || rq_aux(rq)->internal_tag == -1)
		return;

	hctx = blk_mq_map_queue(rq->q, rq->mq_ctx->cpu);
	__blk_mq_put_driver_tag(hctx, rq);
}

void blk_mq_in_flight(struct request_queue *q, struct hd_struct *part,
		      unsigned int inflight[2]);
void blk_mq_in_flight_rw(struct request_queue *q, struct hd_struct *part,
			 unsigned int inflight[2]);

#endif
