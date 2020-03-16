#include <net/sock.h>
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/rbtree.h>

#include "pcs_types.h"
#include "pcs_sock_io.h"
#include "pcs_rpc.h"
#include "pcs_sock_io.h"
#include "pcs_req.h"
#include "pcs_map.h"
#include "pcs_cs.h"
#include "pcs_cluster.h"
#include "log.h"

#include "../../fuse_i.h"

void pcs_mapset_limit(struct pcs_map_set *maps, int limit)
{
	maps->map_thresh = limit - limit/4;
	maps->map_dirty_thresh = limit - limit/8;
	maps->map_max = limit;
}

static unsigned long pcs_map_shrink_count(struct shrinker *shrinker, struct shrink_control *sc)
{
	struct pcs_map_set *maps = container_of(shrinker,
					struct pcs_map_set, shrinker);

	return list_lru_count_node(&maps->lru, sc->nid) +
		list_lru_count_node(&maps->dirty_lru, sc->nid);
}


static int pcs_mapset_init(struct pcs_map_set *maps)
{
	if (list_lru_init(&maps->lru))
		return -ENOMEM;

	if (list_lru_init(&maps->dirty_lru)) {
		list_lru_destroy(&maps->lru);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&maps->dirty_queue);
	atomic_set(&maps->count, 0);
	atomic_set(&maps->dirty_count, 0);
	pcs_mapset_limit(maps, PCS_MAP_LIMIT);
	pcs_flow_table_global_init(&maps->ftab);

	maps->shrinker.count_objects = pcs_map_shrink_count;
	maps->shrinker.scan_objects  = pcs_map_shrink_scan;
	maps->shrinker.seeks = DEFAULT_SEEKS;
	maps->shrinker.batch = 0;	/* use default reclaim batch size */
	maps->shrinker.flags = SHRINKER_NUMA_AWARE;
	register_shrinker(&maps->shrinker);

	return 0;
}

static void pcs_mapset_fini(struct pcs_map_set *maps)
{
	unregister_shrinker(&maps->shrinker);

	BUG_ON(list_lru_count(&maps->lru));
	BUG_ON(list_lru_count(&maps->dirty_lru));
	BUG_ON(!list_empty(&maps->dirty_queue));

	list_lru_destroy(&maps->lru);
	list_lru_destroy(&maps->dirty_lru);
}

static void init_def_mss(struct pcs_cluster_core *cc)
{
	cc->cfg.def.wmss = PCS_DFLT_MSS_WRITE;
	cc->cfg.def.rmss = PCS_DFLT_MSS_READ;
	cc->cfg.def.lmss = PCS_DFLT_MSS_LOCAL;
}


static void cc_workqueue_handler(struct work_struct *w)
{
	LIST_HEAD(queue);
	struct pcs_cluster_core *cc = (struct pcs_cluster_core *)
		container_of(w, struct pcs_cluster_core, main_job);

	spin_lock_irq(&cc->lock);
	list_splice_tail_init(&cc->work_queue, &queue);
	spin_unlock_irq(&cc->lock);

	while (!list_empty(&queue)) {
		struct pcs_int_request *ireq = list_first_entry(&queue, struct pcs_int_request, list);

		list_del_init(&ireq->list);
		TRACE("process ireq:%p" DENTRY_FMT " type=%u\n", ireq, DENTRY_ARGS(ireq->dentry), ireq->type);
		cc->op.ireq_process(ireq);
	}
}

static void cc_completion_handler(struct work_struct *w)
{
	struct pcs_cluster_core *cc = (struct pcs_cluster_core *)
		container_of(w, struct pcs_cluster_core, completion_job);
	LIST_HEAD(queue);

	spin_lock_irq(&cc->lock);
	list_splice_tail_init(&cc->completion_queue, &queue);
	spin_unlock_irq(&cc->lock);

	while (!list_empty(&queue)) {
		struct pcs_int_request *ireq = list_first_entry(&queue, struct pcs_int_request, list);

		list_del_init(&ireq->list);
		TRACE("complete " DENTRY_FMT " type=%u\n", DENTRY_ARGS(ireq->dentry), ireq->type);
		ireq_complete(ireq);
	}
}

int pcs_cc_init(struct pcs_cluster_core *cc, struct workqueue_struct *wq,
		const char *cluster_name, struct pcs_cluster_core_attr *attr)
{
	int err;

	if (!cluster_name)
		return -EINVAL;

	spin_lock_init(&cc->lock);
	INIT_LIST_HEAD(&cc->work_queue);
	INIT_LIST_HEAD(&cc->completion_queue); /* completion queue only for sanity */
	INIT_WORK(&cc->main_job, cc_workqueue_handler);
	INIT_WORK(&cc->completion_job, cc_completion_handler);
	INIT_WORK(&cc->fiemap_work, fiemap_work_func);
	cc->wq = wq;
	snprintf(cc->cluster_name, sizeof(cc->cluster_name), "%s", cluster_name);

	pcs_csset_init(&cc->css);

	err = pcs_mapset_init(&cc->maps);
	if (err)
		return err;

	pcs_rpc_engine_init(&cc->eng, PCS_NODE_ROLE_TOOL);
	pcs_rpc_init_gc(&cc->eng, 1024);
	if (attr) {
		pcs_rpc_set_cluster_id(&cc->eng, &attr->cluster);
		pcs_rpc_set_local_id(&cc->eng, &attr->node);
		if (attr->abort_timeout_ms)
			pcs_cc_set_abort_timeout(cc, attr->abort_timeout_ms);
	}
	/* TODO resurect ratelimit and randeng
	 * pcs_ratelimit_init(cc, &cc->rlim);
	 * pcs_srandomdev(&cc->rng);
	 */

	pcs_fuse_stat_init(&cc->stat);

	memset(&cc->cfg,   0, sizeof(cc->cfg));
	memset(&cc->op,	   0, sizeof(cc->op));

	init_def_mss(cc);
	cc->cfg.def.kernel_cache_en = 1;
	cc->cfg.curr = cc->cfg.def;
	cc->cfg.sn = PCS_CONFIG_SEQ_ANY;

	cc->io_tweaks = 0;
	cc->netlat_cutoff = PCS_MAX_NETWORK_LATENCY*1000;
	cc->iolat_cutoff = PCS_MAX_IO_LATENCY*1000;
	cc->abort_callback = NULL;

	TRACE("Ok cc->{ cl_id:" CLUSTER_ID_FMT ", node_id:" NODE_FMT ", f:%x}\n",
	      CLUSTER_ID_ARGS(cc->eng.cluster_id), NODE_ARGS(cc->eng.local_id),
	      cc->eng.flags);

	return 0;
}

void pcs_cc_fini(struct pcs_cluster_core *cc)
{
	pcs_csset_fini(&cc->css);
	pcs_mapset_fini(&cc->maps);
	pcs_rpc_engine_fini(&cc->eng);
	pcs_fuse_stat_fini(&cc->stat);

	BUG_ON(!list_empty(&cc->completion_queue));
	BUG_ON(!list_empty(&cc->work_queue));
	pcs_flow_table_global_fini(&cc->maps.ftab);
}

void pcs_cc_submit(struct pcs_cluster_core *cc, struct pcs_int_request *ireq)
{
	int was_idle = 0;
	unsigned long flags;

	spin_lock_irqsave(&cc->lock, flags);
	was_idle = list_empty(&cc->work_queue);
	list_add_tail(&ireq->list, &cc->work_queue);
	spin_unlock_irqrestore(&cc->lock, flags);

	if (was_idle)
		queue_work(cc->wq, &cc->main_job);
}

/* move request queue "q" back to main work_queue, it will be processed from the very beginning */
void pcs_cc_requeue(struct pcs_cluster_core *cc, struct list_head *q)
{
	unsigned long flags;
	int was_idle = 0;

	if (list_empty(q))
		return;

	spin_lock_irqsave(&cc->lock, flags);
	was_idle = list_empty(&cc->work_queue);
	list_splice_tail_init(q, &cc->work_queue);
	spin_unlock_irqrestore(&cc->lock, flags);

	if (was_idle)
		queue_work(cc->wq, &cc->main_job);
}
