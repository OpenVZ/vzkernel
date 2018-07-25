#include <net/sock.h>
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/highmem.h>
#include <linux/log2.h>

#include "pcs_types.h"
#include "pcs_sock_io.h"
#include "pcs_rpc.h"
#include "pcs_sock_io.h"
#include "pcs_req.h"
#include "pcs_map.h"
#include "pcs_cs.h"
#include "pcs_ioctl.h"
#include "pcs_cluster.h"
#include "log.h"
#include "fuse_ktrace.h"

/*  Lock order
   ->map->lock	: Motivated by truncate
     ->mapping->map_lock

   map->lock
    ->cs->lock	 : pcs_map_set_cslist

*/
#define MAP_BATCH 16

static struct pcs_cs_list *cs_link_to_cs_list(struct pcs_cs_link *csl)
{
	struct pcs_cs_record *cs_rec;
	struct pcs_cs_list *cs_list;

	cs_rec = container_of(csl, struct pcs_cs_record, cslink);
	cs_list = container_of(cs_rec - csl->index, struct pcs_cs_list, cs[0]);
	return cs_list;
}

abs_time_t get_real_time_ms(void)
{
	struct timespec tv = current_kernel_time();
	return (abs_time_t)tv.tv_sec * 1000 + tv.tv_nsec / 1000000;
}


static inline unsigned int pcs_sync_timeout(struct pcs_cluster_core *cc)
{
	/* This is ~8 second distribution around PCS_SYNC_TIMEOUT */
	//// TODO: timeout randomization temproraly disabled
	////return PCS_SYNC_TIMEOUT - 0x1000 + (pcs_random(&cc->rng) & 0x1FFF);
	return PCS_SYNC_TIMEOUT;
}

static void cslist_destroy(struct pcs_cs_list * csl)
{
	int i;

	TRACE("csl:%p csl->map:%p refcnt:%d\n", csl, csl->map, atomic_read(&csl->refcnt));
	BUG_ON(csl->map);

	rcu_read_lock();
	for (i = 0; i < csl->nsrv; i++) {
		struct pcs_cs_link * cslink = &csl->cs[i].cslink;
		struct pcs_cs __rcu *cs = rcu_dereference(cslink->cs);

		/* Possible after error inside cslist_alloc() */
		if (!cs)
			continue;

		spin_lock(&cs->lock);
		if (!list_empty(&cslink->link)) {
			list_del_init(&cslink->link);
			cs->nmaps--;
		}
		spin_unlock(&cs->lock);
	}
	rcu_read_unlock();
	kfree(csl);
}

static inline void cslist_get(struct pcs_cs_list * csl)
{
	TRACE("csl:%p csl->map:%p refcnt:%d\n", csl, csl->map, atomic_read(&csl->refcnt));

	atomic_inc(&csl->refcnt);
}
static inline void cslist_put(struct pcs_cs_list * csl)
{
	TRACE("csl:%p csl->map:%p refcnt:%d\n", csl, csl->map, atomic_read(&csl->refcnt));
	if (atomic_dec_and_test(&csl->refcnt))
		cslist_destroy(csl);
}

static void map_drop_cslist(struct pcs_map_entry * m)
{
	assert_spin_locked(&m->lock);

	if (m->cs_list == NULL)
		return;

	rcu_assign_pointer(m->cs_list->map, NULL);
	/* Barrier here is only for sanity checks in cslist_destroy() */
	smp_mb__before_atomic_dec();
	cslist_put(m->cs_list);
	m->cs_list = NULL;
}

static void pcs_map_callback(struct rcu_head *head)
{
	struct pcs_map_entry *m = container_of(head, struct pcs_map_entry, rcu);

	BUG_ON(atomic_read(&m->__refcnt));
	BUG_ON(!list_empty(&m->queue));
	BUG_ON(!(m->state & PCS_MAP_DEAD));
	BUG_ON(m->cs_list);

	kfree(m);
}

static void __pcs_map_free(struct pcs_map_entry *m)
{
	call_rcu(&m->rcu, pcs_map_callback);
}

void __pcs_map_put(struct pcs_map_entry *m)
__releases(m->lock)
{
	TRACE(" %p id:%lld state:%x ref:%d\n",m, m->id, m->state, atomic_read(&m->__refcnt));

	assert_spin_locked(&m->lock);
	if (m->state & PCS_MAP_DEAD) {
		spin_unlock(&m->lock);
		__pcs_map_free(m);
		return;
	}
	map_add_lru(m);
	spin_unlock(&m->lock);
}

static struct pcs_map_entry *  __pcs_map_get(struct pcs_map_entry *m)
{
	//TRACE( MAP_FMT " ref:%d, maps-count:%d \n", MAP_ARGS(m), m->__refcnt);
	BUG_ON(atomic_inc_return(&m->__refcnt) <= 1);

	return m;
}

static void pcs_map_reset(struct pcs_map_entry * m)
{
	m->state &= ~(PCS_MAP_READABLE|PCS_MAP_WRITEABLE);
}
static void map_sync_work_add(struct pcs_map_entry *m, unsigned long timeout);
static void map_sync_work_del(struct pcs_map_entry *m);

/* Truncate map from mapping */
static void pcs_map_truncate(struct pcs_map_entry *m, struct list_head *queue)
{

	void *ret;

	TRACE( MAP_FMT " ref:%d\n", MAP_ARGS(m), atomic_read(&m->__refcnt));

	assert_spin_locked(&m->lock);
	BUG_ON(m->state & PCS_MAP_DEAD);
	BUG_ON(!m->mapping);
	BUG_ON(!list_empty(&m->queue) && !queue);

	spin_lock(&m->mapping->map_lock);
	ret = radix_tree_delete(&m->mapping->map_tree, m->index);
	BUG_ON(!ret || ret != m);
	m->mapping->nrmaps--;
	spin_unlock(&m->mapping->map_lock);

	list_splice_tail_init(&m->queue, queue);
	m->mapping = NULL;
	map_sync_work_del(m);
	pcs_map_reset(m);
	m->state |= PCS_MAP_DEAD;
	map_drop_cslist(m);
}

void pcs_mapping_init(struct pcs_cluster_core *cc, struct pcs_mapping * mapping)
{
	mapping->cluster = cc;
	INIT_RADIX_TREE(&mapping->map_tree, GFP_ATOMIC);
	spin_lock_init(&mapping->map_lock);
	pcs_flow_table_init(&mapping->ftab, &cc->maps.ftab);
}

/* Must be called once right after lease is acquired. At that point we already
 * have all the file attributes.
 */
void pcs_mapping_open(struct pcs_mapping * mapping)
{
	struct pcs_dentry_info *di = pcs_dentry_from_mapping(mapping);

	switch (di->fileinfo.sys.map_type) {
	default:
		BUG();
	case PCS_MAP_PLAIN:
		return;
	}
}

void pcs_mapping_dump(struct pcs_mapping * mapping)
{
	struct pcs_dentry_info *di = pcs_dentry_from_mapping(mapping);
	unsigned long pos = 0;
	struct pcs_map_entry *maps[MAP_BATCH];
	int nr_maps, total = 0;

	if (!mapping->nrmaps)
		return;

	DTRACE(DENTRY_FMT "\n", DENTRY_ARGS(di));

	do {
		int i;
		rcu_read_lock();
		nr_maps = radix_tree_gang_lookup(&mapping->map_tree,
				(void **)maps, pos, MAP_BATCH);

		for (i = 0; i < nr_maps; i++, total++) {
			pos = maps[i]->index;
			DTRACE("[%d] " MAP_FMT ", id:" CUID_FMT ",  v:" VER_FMT " ref:%d\n", total,  MAP_ARGS(maps[i]),
			       CUID_ARGS(maps[i]->id), VER_ARGS(maps[i]->version),
			       atomic_read(&maps[i]->__refcnt));
		}
		pos++;
		rcu_read_unlock();
	} while (nr_maps);
}

void map_truncate_tail(struct pcs_mapping * mapping, u64 offset)
{

	unsigned long pos = offset >> mapping->chunk_size_bits;
	struct pcs_map_entry *maps[MAP_BATCH];
	int nr_maps;
	LIST_HEAD(dispose);

	TRACE("%s " DENTRY_FMT "\n", __FUNCTION__, DENTRY_ARGS(pcs_dentry_from_mapping(mapping)));
	do {
		int i;

		rcu_read_lock();
		nr_maps = radix_tree_gang_lookup(&mapping->map_tree,
				(void **)maps, pos, MAP_BATCH);

		for (i = 0; i < nr_maps; i++) {
			struct pcs_map_entry *m = maps[i];

			spin_lock(&m->lock);
			if (!pcs_map_get_locked(m)) {
				spin_unlock(&m->lock);
				continue;
			}
			pcs_map_truncate(m, &dispose);
			map_del_lru(m);
			spin_unlock(&m->lock);
			pcs_map_put(m);
		}
		pos++;
		rcu_read_unlock();
	} while (nr_maps);

	pcs_ireq_queue_fail(&dispose, PCS_ERR_NET_ABORT);
}

void pcs_cs_truncate_maps(struct pcs_cs *cs)
{
	struct pcs_cs_list *cs_list;
	struct pcs_cs_link *cs_link;
	struct pcs_map_entry *m;
	LIST_HEAD(map_list);
	bool once = true;

	cs->use_count++;
again:
	lockdep_assert_held(&cs->lock);

	while (!list_empty(&cs->map_list)) {
		cs_link = list_first_entry(&cs->map_list,
					   struct pcs_cs_link, link);
		list_move(&cs_link->link, &map_list);

		cs_list = cs_link_to_cs_list(cs_link);
		cslist_get(cs_list);
		spin_unlock(&cs->lock);

		rcu_read_lock();
		m = rcu_dereference(cs_list->map);
		if (!m)
			goto skip;
		spin_lock(&m->lock);
		if (!list_empty(&m->queue)) {
			WARN(once, "Not empty map queue\n");
			once = false;
		} else if (!(m->state & PCS_MAP_DEAD)) {
			pcs_map_truncate(m, NULL);
			map_del_lru(m);
		}
		spin_unlock(&m->lock);
skip:
		rcu_read_unlock();
		/*
		 * cs_link will be removed from map_list
		 * on the final cslist_put(). Maybe now.
		 */
		cslist_put(cs_list);
		spin_lock(&cs->lock);
	}

	list_splice(&map_list, &cs->map_list);
	if (!list_empty(&cs->map_list)) {
		spin_unlock(&cs->lock);
		schedule_timeout_uninterruptible(HZ);
		spin_lock(&cs->lock);
		goto again;
	}
	cs->use_count--;
}

void pcs_mapping_invalidate(struct pcs_mapping * mapping)
{
	pcs_mapping_dump(mapping);
	map_truncate_tail(mapping, 0);
	/* If some CSes are still not shutdown, we can have some map entries referenced in their queues */
	pcs_flow_table_fini(&mapping->ftab, &pcs_dentry_from_mapping(mapping)->cluster->maps.ftab);
}

void pcs_mapping_deinit(struct pcs_mapping * mapping)
{

	BUG_ON(mapping->nrmaps);
}

static inline int map_reclaimable(struct pcs_map_entry * m)
{
	return list_empty(&m->queue)
		&& !(m->state & (PCS_MAP_ERROR|PCS_MAP_RESOLVING));
}

static enum lru_status map_isolate(struct list_head *item,
		struct list_lru_one *lru, spinlock_t *lru_lock, void *arg)
{
	struct list_head *dispose = arg;
	struct pcs_map_entry *m = list_entry(item, struct pcs_map_entry, lru_link);

	if (!spin_trylock(&m->lock))
		return LRU_SKIP;

	if (!map_reclaimable(m)) {
		spin_unlock(&m->lock);
		return LRU_SKIP;
	}

	pcs_map_truncate(m, NULL);
	list_lru_isolate_move(lru, item, dispose);
	spin_unlock(&m->lock);

	return LRU_REMOVED;
}

static enum lru_status map_dirty_walk(struct list_head *item,
		struct list_lru_one *lru, spinlock_t *lru_lock, void *arg)
{
	struct pcs_map_entry *m = list_entry(item, struct pcs_map_entry, lru_link);


	if (!spin_trylock(&m->lock))
		return LRU_SKIP;

	BUG_ON(!(m->flags & PCS_MAP_DIRTY));
	/* Flushes are not limited by ireq_delay(). So, we have
	 * to suppress too frequent flushes when MDS fails to update map
	 * by any reason.
	 */
	if (!(m->flags & (PCS_MAP_FLUSHING|PCS_MAP_DIRTY_GC)) &&
	    timer_pending(&m->sync_work.timer) &&
	    (jiffies >= m->error_tstamp + PCS_ERROR_DELAY)) {
		m->flags |= PCS_MAP_DIRTY_GC;
		map_sync_work_add(m, 0);
	}
	spin_unlock(&m->lock);
	return LRU_SKIP;
}

unsigned long pcs_map_shrink_scan(struct shrinker *shrink,
					 struct shrink_control *sc)
{
	LIST_HEAD(dispose);
	unsigned long freed = 0;
	unsigned long nr_to_scan = sc->nr_to_scan;
	struct pcs_map_set *maps = container_of(shrink,
					struct pcs_map_set, shrinker);

	/* This shrinker performs only atomic operations,
	 * any GFP maks will works
	 * if (!(sc->gfp_mask & __GFP_FS)) */
	/*	return SHRINK_STOP; */

	freed = list_lru_walk_node(&maps->lru, sc->nid, map_isolate,
				       &dispose, &nr_to_scan);

	if (nr_to_scan)
		list_lru_walk_node(&maps->dirty_lru, sc->nid,
				   map_dirty_walk, NULL, &nr_to_scan);

	while (!list_empty(&dispose)) {
		struct pcs_map_entry *m;
		m = list_first_entry(&dispose, struct pcs_map_entry, lru_link);
		list_del_init(&m->lru_link);
		__pcs_map_free(m);
	}

	if (!list_empty(&maps->dirty_queue)) {
		INIT_LIST_HEAD(&dispose);
		spin_lock(&maps->lock);
		list_splice_tail(&maps->dirty_queue, &dispose);
		spin_unlock(&maps->lock);
		pcs_cc_requeue(container_of(maps, struct pcs_cluster_core, maps), &dispose);
	}
	TRACE(" lru_freed:%ld \n", freed);
	return freed;
}

unsigned long map_gc(struct pcs_map_set *maps)
{
	struct shrink_control sc = {
		.gfp_mask = GFP_NOIO,
		.nr_to_scan = 1,
		.nid = numa_node_id(),
	};

	return pcs_map_shrink_scan(&maps->shrinker, &sc);
}

static inline int is_dirtying(struct pcs_map_entry * map, struct pcs_int_request *ireq)
{
	if (!pcs_req_direction(ireq->iochunk.cmd))
		return 0;

	/* Was not dirty? */
	if (!(map->flags & PCS_MAP_DIRTY))
		return 1;

	/* Is already dirty, but we work on flush right now. Wait for end of flush. */
	if (map->flags & (PCS_MAP_FLUSHING|PCS_MAP_DIRTY_GC))
		return 1;

	return 0;
}

static void map_queue_on_limit(struct pcs_int_request *ireq)
{
	struct pcs_map_set * maps = &ireq->dentry->cluster->maps;

	FUSE_KTRACE(ireq->cc->fc, "queueing due to dirty limit");

	if (ireq->type == PCS_IREQ_IOCHUNK && ireq->iochunk.map) {
		pcs_map_put(ireq->iochunk.map);
		ireq->iochunk.map = NULL;
	}

	list_add_tail(&ireq->list, &maps->dirty_queue);
	map_gc(maps);
}

/* TODO: this check differ from original */
int map_check_limit(struct pcs_map_entry * map, struct pcs_int_request *ireq)
{
	struct pcs_map_set * maps = &ireq->dentry->cluster->maps;

	if (map == NULL) {
		map_queue_on_limit(ireq);
		return 1;
	}

	if (list_empty(&maps->dirty_queue))
		return 0;

	/* The goal is to queue request which is going to increase pressure on map limit. */

	/* If map failed the request must pass. If it is under resolution it can pass.
	 *
	 * This looks dangerous, error maps can overflow map table.
	 * Nevertheless, altogether this combines to another statement: if map is not reclaimable,
	 * the request passes. So, it really does not increase pressure.
	 */

	if (!map_reclaimable(map))
		return 0;
	/*
	 * When map is new, the request definitely increases the pressure.
	 *
	 * Also it does if the request is going to move clean map to dirty state
	 */
	if (((map->state & PCS_MAP_NEW) || is_dirtying(map, ireq))) {
		int nid = page_to_nid(virt_to_page(map));

		if (list_lru_count_node(&maps->dirty_lru, nid) >
		    maps->map_dirty_thresh)
		map_queue_on_limit(ireq);
		return 1;
	}
	return 0;
}

static void map_sync_work_add(struct pcs_map_entry *m, unsigned long timeout)
{
	struct pcs_cluster_core *cc = cc_from_maps(m->maps);

	assert_spin_locked(&m->lock);

	if (WARN_ON_ONCE(m->state & PCS_MAP_DEAD))
		return;
	/*
	 * Note, that work func takes m->lock on all paths,
	 * so it can't put map before we get it below.
	 */
	if (!mod_delayed_work(cc->wq, &m->sync_work, timeout))
		__pcs_map_get(m);
}
static void map_sync_work_del(struct pcs_map_entry *m)
{
	assert_spin_locked(&m->lock);

	if (cancel_delayed_work(&m->sync_work))
		pcs_map_put_locked(m);
}
static void sync_timer_work(struct work_struct *w);

/* Returns map with incremented refcnt */
struct pcs_map_entry * pcs_find_get_map(struct pcs_dentry_info *di, u64 offset)
{
	struct pcs_map_set * maps = &di->mapping.cluster->maps;
	unsigned long idx = offset >> DENTRY_CHUNK_SIZE_BITS(di);
	struct pcs_map_entry *m;

again:
	for (;;) {
		rcu_read_lock();
		m = radix_tree_lookup(&di->mapping.map_tree, idx);
		if (m) {
			BUG_ON(m->index != idx);
			m = pcs_map_get(m);
			rcu_read_unlock();
			if (!m)
				continue;
			else
				return m;
		}
		rcu_read_unlock();
		/* No direct throttler here */
		break;
	}
	m = kzalloc(sizeof(struct pcs_map_entry), GFP_NOIO);
	if (!m)
		return NULL;

	if (radix_tree_preload(GFP_NOIO)) {
		kfree(m);
		return NULL;
	}

	m->mapping = NULL;
	m->maps = NULL;
	m->res_offset = offset;
	m->chunk_psize = 0;
	m->index = idx;

	map_version_init(&m->version);
	m->id = 0;		/* For logging only, it is not used before map is completed */
	m->state = PCS_MAP_NEW;
	m->flags = 0;
	atomic_set(&m->__refcnt, 1);
	m->mds_flags = 0;
	m->cs_list = NULL;
	m->error_tstamp = 0;
	m->mapping = &di->mapping;
	INIT_DELAYED_WORK(&m->sync_work, sync_timer_work);
	INIT_LIST_HEAD(&m->queue);
	INIT_LIST_HEAD(&m->lru_link);
	spin_lock_init(&m->lock);
	atomic_inc(&maps->count);
	m->maps = maps;

	spin_lock(&di->mapping.map_lock);
	m->mapping->nrmaps++;
	if (radix_tree_insert(&di->mapping.map_tree, idx, m)) {
		m->mapping->nrmaps--;
		spin_unlock(&di->mapping.map_lock);
		radix_tree_preload_end();
		kfree(m);
		goto again;
	}
	spin_unlock(&di->mapping.map_lock);
	radix_tree_preload_end();

	return m;
}

/* When CS goes up/down invalidate read_index on all the maps using this CS.
 * This results in reevaluation of CS used for reads from this chunk at the next read.
 */

static void map_recalc_maps(struct pcs_cs * cs)
{
	struct pcs_cs_link * csl;
	assert_spin_locked(&cs->lock);

	list_for_each_entry(csl, &cs->map_list, link) {
		struct pcs_cs_list *cs_list;
		struct pcs_cs *cur_cs;
		int read_idx;

		cs_list = cs_link_to_cs_list(csl);
		read_idx = READ_ONCE(cs_list->read_index);

		if (read_idx < 0)
			continue;
		cur_cs = rcu_access_pointer(cs_list->cs[read_idx].cslink.cs);
		if (!cs_is_blacklisted(cs) || cur_cs == cs)
			WRITE_ONCE(cs_list->read_index, -1);
	}
}

void pcs_map_force_reselect(struct pcs_cs * cs)
{
	struct pcs_cs_link * csl;
	assert_spin_locked(&cs->lock);

	list_for_each_entry(csl, &cs->map_list, link) {
		struct pcs_cs_list *cs_list;
		struct pcs_cs *cur_cs;
		int read_idx;

		cs_list = cs_link_to_cs_list(csl);
		read_idx = READ_ONCE(cs_list->read_index);

		if (read_idx < 0)
			continue;
		cur_cs = rcu_access_pointer(cs_list->cs[read_idx].cslink.cs);
		if (cur_cs == cs)
			WRITE_ONCE(cs_list->read_index, -1);
	}
}

static int all_blacklisted(struct pcs_cs_list * csl)
{
	int i = 0;

	for (i = 0; i < csl->nsrv; i++) {
		if (test_bit(i, &csl->blacklist)) {
			if (jiffies < READ_ONCE(csl->blacklist_expires))
				continue;
			TRACE("expire replication blacklist");
			clear_bit(i, &csl->blacklist);
		}
		if (!test_bit(CS_SF_BLACKLISTED, &csl->cs[i].cslink.cs->state))
			break;
	}
	return i == csl->nsrv;
}

static int urgent_whitelist(struct pcs_cs * cs)
{
	struct pcs_cs_link * csl;
	assert_spin_locked(&cs->lock);

	list_for_each_entry(csl, &cs->map_list, link) {
		struct pcs_cs_list *cs_list;

		cs_list = cs_link_to_cs_list(csl);

		/* FIXME: do we need rcu here? */
		if (cs_list->map == NULL)
			continue;

		if (all_blacklisted(cs_list))
			return 1;
	}
	return 0;
}

void cs_blacklist(struct pcs_cs * cs, int error, char * reason)
{
	assert_spin_locked(&cs->lock);

	if (!cs_is_blacklisted(cs)) {
		spin_lock(&cs->css->lock);
		set_bit(CS_SF_BLACKLISTED, &cs->state);
		cs->blacklist_reason = error;
		FUSE_KTRACE(cc_from_csset(cs->css)->fc, "Blacklisting CS" NODE_FMT " by %s, err=%d", NODE_ARGS(cs->id), reason, error);
		if (list_empty(&cs->css->bl_list)) {
			struct pcs_cluster_core *cc = cc_from_csset(cs->css);

			mod_delayed_work(cc->wq, &cs->css->bl_work, PCS_CS_BLACKLIST_TIMER);
		}
		list_add_tail(&cs->bl_link, &cs->css->bl_list);
		spin_unlock(&cs->css->lock);
		map_recalc_maps(cs);
	}
}

static void cs_blacklist_unlocked(struct pcs_cs * cs, int error, char * reason)
{
	spin_lock(&cs->lock);
	cs_blacklist(cs, error, reason);
	spin_unlock(&cs->lock);
}

void cs_whitelist(struct pcs_cs * cs, char * reason)
{
	assert_spin_locked(&cs->lock);

	if (cs_is_blacklisted(cs)) {
		clear_bit(CS_SF_BLACKLISTED, &cs->state);
		FUSE_KTRACE(cc_from_csset(cs->css)->fc, "Whitelisting CS" NODE_FMT " by %s", NODE_ARGS(cs->id), reason);

		map_recalc_maps(cs);

		spin_lock(&cs->css->lock);
		list_del_init(&cs->bl_link);
		if (list_empty(&cs->css->bl_list))
			cancel_delayed_work(&cs->css->bl_work);
		spin_unlock(&cs->css->lock);
	}
}

static inline void __map_error(struct pcs_map_entry *m , int remote, int error, u64 offender)
{
	assert_spin_locked(&m->lock);
	m->state = PCS_MAP_ERROR;
	m->iofailure.remote = remote;
	m->iofailure.value = error;
	m->iofailure.offender.val = offender;
}

static inline void map_remote_error_nolock(struct pcs_map_entry *m , int error, u64 offender)
{
	__map_error(m, 1 , error, offender);
}
static void map_remote_error(struct pcs_map_entry *m , int error, u64 offender)
{
	spin_lock(&m->lock);
	map_remote_error_nolock(m, error, offender);
	spin_unlock(&m->lock);
}

void pcs_map_notify_addr_change(struct pcs_cs * cs)
{
	struct pcs_cs_list *cs_list, *prev_cs_list = NULL;
	struct pcs_cs_link * csl;
	assert_spin_locked(&cs->lock);

	cs->use_count++; /* Prohibit to isolate cs */

	rcu_read_lock();
	list_for_each_entry(csl, &cs->map_list, link) {
		struct pcs_map_entry *m;

		if (csl->addr_serno == cs->addr_serno)
			continue;
		cs_list = cs_link_to_cs_list(csl);
		m = rcu_dereference(cs_list->map);
		if (!m)
			continue;
		/*
		 * Get cs_list to prevent its destruction and unlinking from cs.
		 * Thus, csl stays on the place in the list. New elements may be
		 * added to head of cs->map_list, so our caller must care, they
		 * will contain correct rpc addr.
		 */
		cslist_get(cs_list);
		spin_unlock(&cs->lock);

		if (prev_cs_list)
			cslist_put(prev_cs_list);
		prev_cs_list = cs_list;

		spin_lock(&m->lock);
		if ((m->state & PCS_MAP_DEAD) || m->cs_list != cs_list)
			goto unlock;

		if (m->state & (PCS_MAP_ERROR|PCS_MAP_RESOLVING|PCS_MAP_NEW))
			goto unlock;

		FUSE_KTRACE(cc_from_csset(cs->css)->fc, MAP_FMT " invalidating due to address change of CS#"NODE_FMT,
		      MAP_ARGS(m), NODE_ARGS(cs->id));

		map_remote_error_nolock(m, PCS_ERR_CSD_STALE_MAP, cs->id.val);
unlock:
		spin_unlock(&m->lock);
		spin_lock(&cs->lock);
	}

	if (prev_cs_list) {
		spin_unlock(&cs->lock);
		cslist_put(prev_cs_list);
		spin_lock(&cs->lock);
	}
	rcu_read_unlock();
	cs->use_count--;
	BUG_ON(cs->is_dead);
}

void transfer_sync_data(struct pcs_cs_list * new_cs_list, struct pcs_cs_list * old_cs_list)
{
	int i, k;

	if (new_cs_list->nsrv == 0 || old_cs_list->nsrv == 0)
		return;

	for (i = 0; i < new_cs_list->nsrv; i++) {
		for (k = 0; k < old_cs_list->nsrv; k++) {
			if (old_cs_list->cs[k].info.id.val == new_cs_list->cs[i].info.id.val) {
				new_cs_list->cs[i].sync = old_cs_list->cs[k].sync;
				break;
			}
		}
	}
}

static int cs_is_dirty(struct cs_sync_state * sync)
{
	int res;

	if (!sync->dirty_integrity || !sync->dirty_epoch || !sync->dirty_seq)
		return 0;

	res = pcs_sync_seq_compare(sync->dirty_epoch, sync->sync_epoch);
	if (!res)
		res = pcs_sync_seq_compare(sync->dirty_seq, sync->sync_seq);

	return res >= 0;
}

static void evaluate_dirty_status(struct pcs_map_entry * m)
{
	int i;

	assert_spin_locked(&m->lock);

	if (m->flags & PCS_MAP_DIRTY) {
		m->flags &= ~PCS_MAP_DIRTY;
		atomic_dec(&m->maps->dirty_count);
	}

	if (m->cs_list == NULL)
		return;

	for (i = 0; i < m->cs_list->nsrv; i++) {
		struct pcs_cs_record * rec = m->cs_list->cs + i;

		BUG_ON(rec->info.integrity_seq == 0);

		if (cs_is_dirty(&rec->sync)) {
			if (rec->sync.dirty_integrity == rec->info.integrity_seq) {
				if (!(m->flags & PCS_MAP_DIRTY)) {
					m->flags |= PCS_MAP_DIRTY;
					atomic_inc(&m->maps->dirty_count);
				}
			} else {
				FUSE_KTRACE(cc_from_maps(m->maps)->fc, MAP_FMT " integrity seq advanced on CS#"NODE_FMT,
				      MAP_ARGS(m), NODE_ARGS(rec->info.id));

				rec->sync.dirty_integrity = 0;
				rec->sync.dirty_epoch = 0;
				rec->sync.dirty_seq = 0;
			}
		} else
			rec->sync.dirty_integrity = 0;
	}

	if (!(m->flags & PCS_MAP_DIRTY)) {
		map_sync_work_del(m);
		FUSE_KLOG(cc_from_maps(m->maps)->fc, LOG_DEBUG5, "map %p is clean", m);
	} else {
		FUSE_KLOG(cc_from_maps(m->maps)->fc, LOG_DEBUG5, "map %p is dirty", m);
		if (!timer_pending(&m->sync_work.timer) && !(m->flags & PCS_MAP_FLUSHING))
			map_sync_work_add(m, pcs_sync_timeout(cc_from_map(m)));
	}
}

int pcs_map_encode_req(struct pcs_map_entry*m, struct pcs_ioc_getmap *map, int direction)
{
	int i;

	spin_lock(&m->lock);
	BUG_ON(map_chunk_start(m) > m->res_offset);
	BUG_ON(map_chunk_end(m) < m->res_offset);
	/*
	 * Someone truncate mapping while IO is in progress
	 * aio_dio vs truncate race ?
	*/
	if (m->state & PCS_MAP_DEAD) {
		spin_unlock(&m->lock);
		pcs_map_put(m);
		return 1;
	}

	map->uid = m->id;
	map->version = m->version;
	map->chunk_start = m->res_offset;
	map->chunk_end = map_chunk_end(m);
	map->state = 0;
	if (m->state & PCS_MAP_READABLE)
		map->state |= PCS_IOC_MAP_S_READ;
	if (m->state & PCS_MAP_WRITEABLE || direction)
		map->state |= PCS_IOC_MAP_S_WRITE;
	if (m->state & PCS_MAP_NEW)
		map->state |= PCS_IOC_MAP_S_NEW;
	if (m->state & PCS_MAP_ERROR) {
		map->state |= PCS_IOC_MAP_S_ERROR;
		map->error = m->iofailure;
	}
	map->mds_flags = m->mds_flags;
	map->psize_ret = 0;  /* UNUSED */
	map->chunk_psize = 0; /* UNUSED */

	if (m->cs_list && m->cs_list->nsrv) {
		map->cs_cnt = m->cs_list->nsrv;
		for (i = 0; i < m->cs_list->nsrv; i++) {
			map->cs[i] = m->cs_list->cs[i].info;
			if (!(m->flags & PCS_MAP_DIRTY) || !cs_is_dirty(&m->cs_list->cs[i].sync))
				map->cs[i].integrity_seq = 0;
		}
	}

#ifdef __PCS_DEBUG
	printk("%s submit  m(%p)->uid:%lld\n", __FUNCTION__, m, m->id);
	printk("map {id:%lld [%lld, %lld] v:{" VER_FMT "} st:%x, cnt:%d max:%d SZ:%ld}\n",
	       m->id, map->chunk_start, map->chunk_end, VER_ARGS(m->version),
	       map->state, map->cs_cnt, map->cs_max, map_sz);

	printk("cs_list: ");
	for (i = 0; i < map->cs_cnt; i++) {
		printk("[%d]{id:%lld fl:%x} ",
		       i, map->cs[i].id.val, map->cs[i].flags);
	}
	printk("\n.");
#endif
	spin_unlock(&m->lock);
	return 0;
}

/*
 * Alloc and initialize cslist, grab cs->lock inside
 */
struct pcs_cs_list* cslist_alloc( struct pcs_cs_set *css, struct pcs_cs_info *rec, int cs_cnt,
				     int read_tout, int write_tout, int error_clear)
{
	struct pcs_cs_list * cs_list = NULL;
	struct pcs_cs * cs;
	int i;

	cs_list = kzalloc(sizeof(struct pcs_cs_list) + cs_cnt * sizeof(struct pcs_cs_record), GFP_NOFS);
	if (!cs_list)
		return NULL;

	atomic_set(&cs_list->refcnt, 1);
	atomic_set(&cs_list->seq_read_in_flight, 0);
	cs_list->read_index = -1;
	cs_list->flags = 0;
	cs_list->serno = atomic64_inc_return(&css->csl_serno_gen);
	cs_list->blacklist = 0;
	cs_list->read_timeout = (read_tout * HZ) / 1000;
	cs_list->write_timeout = (write_tout * HZ) / 1000;
	cs_list->nsrv = cs_cnt;
	for (i = 0; i < cs_cnt; i++) {
		cs_list->cs[i].info = rec[i];
		memset(&cs_list->cs[i].sync, 0, sizeof(cs_list->cs[i].sync));
		RCU_INIT_POINTER(cs_list->cs[i].cslink.cs, NULL);
		INIT_LIST_HEAD(&cs_list->cs[i].cslink.link);
		cs_list->cs[i].cslink.index = i;
	}


	for (i = 0; i < cs_cnt; i++) {
		struct pcs_cs_link * cslink = &cs_list->cs[i].cslink;

		if (cs_list->cs[i].info.flags & CS_FL_REPLICATING) {
			__set_bit(i, &cs_list->blacklist);
			cs_list->blacklist_expires = jiffies + PCS_REPLICATION_BLACKLIST_TIMEOUT;
		}

		cs = pcs_cs_find_create(css, &cs_list->cs[i].info.id,
				 &cs_list->cs[i].info.addr, cs_list->cs[i].info.flags);

		if (!cs) {
			cslist_destroy(cs_list);
			return NULL;
		}
		assert_spin_locked(&cs->lock);
		BUG_ON(cs->is_dead);

		rcu_assign_pointer(cslink->cs, cs);
		cslink->addr_serno = cs->addr_serno;

		cs->io_prio = cs_list->cs[i].info.io_prio;
		cs->net_prio = cs_list->cs[i].info.net_prio;
		cs->io_prio_stamp = jiffies;

		/* update cs state */
		cs->mds_flags = cs_list->cs[i].info.flags;
		if (cs->mds_flags & CS_FL_LOCAL) {
			set_bit(CS_SF_LOCAL, &cs->state);
			cs_list->flags |= CSL_FL_HAS_LOCAL;
		}
		if (cs->mds_flags & CS_FL_LOCAL_SOCK)
			set_bit(CS_SF_LOCAL_SOCK, &cs->state);
		if (cs->mds_flags & CS_FL_INACTIVE) {
			set_bit(CS_SF_INACTIVE, &cs->state);
			cs_blacklist(cs, PCS_ERR_NET_ABORT, "mds hint");
		}
		if (cs->mds_flags & CS_FL_REPLICATING)
			set_bit(CS_SF_REPLICATING, &cs->state);
		if (cs->mds_flags & CS_FL_FAILED)
			set_bit(CS_SF_FAILED, &cs->state);

		list_add(&cslink->link, &cs->map_list);
		cs->nmaps++;
		spin_unlock(&cs->lock);
	}

	for (i = cs_cnt - 1; i >= 0; i--) {
		cs = rcu_dereference_protected(cs_list->cs[i].cslink.cs,
					       atomic_read(&cs_list->refcnt) > 0);
		spin_lock(&cs->lock);
		if (cs_is_blacklisted(cs) && !(test_bit(CS_SF_INACTIVE, &cs->state))) {
			if (error_clear)
				cs_whitelist(cs, "mds hint");
			else if (urgent_whitelist(cs))
				cs_whitelist(cs, "urgent");
		}
		spin_unlock(&cs->lock);
	}

	return cs_list;
}

void pcs_map_complete(struct pcs_map_entry *m, struct pcs_ioc_getmap *omap)
{
	pcs_error_t error = omap->error;
	struct pcs_cs_list * cs_list = NULL;
	struct list_head queue;
	int error_sensed = 0;

	INIT_LIST_HEAD(&queue);

	spin_lock(&m->lock);

	TRACE(" recv m:%p, state:%x resp{ st:%d, err:%d, v:" VER_FMT "}\n",
	      m, m->state, omap->state, omap->error.value, VER_ARGS(omap->version));

	if (pcs_if_error(&omap->error))
		goto error;

	if (m->state & PCS_MAP_DEAD) {
		spin_unlock(&m->lock);
		goto out_ignore;
	}
	TRACE("dentry: "DENTRY_FMT, DENTRY_ARGS(pcs_dentry_from_map(m)));

	error_sensed = m->state & PCS_MAP_ERROR;

	if (omap->cs_cnt) {
		spin_unlock(&m->lock);
		cs_list = cslist_alloc(&cc_from_map(m)->css, omap->cs, omap->cs_cnt, omap->read_tout, omap->write_tout, error_sensed);
		spin_lock(&m->lock);
		if (!cs_list) {
			pcs_set_local_error(&error, PCS_ERR_NOMEM);
			goto error;
		}
		/* Recheck one more time because we drop the lock */
		if (m->state & PCS_MAP_DEAD) {
			spin_unlock(&m->lock);
			goto out_ignore;
		}
	}

	if (!(m->state & PCS_MAP_RESOLVING)) {
		/* This may happen because of __pcs_map_error() explicit assign
		   m->state = PCS_MAP_ERROR;
		   If m->state becomes atomic bit fields this will be impossible.
		 */
		spin_unlock(&m->lock);
		goto out_ignore;
	}
	pcs_map_reset(m);
	m->id = omap->uid;
	m->version = omap->version;

	if (cs_list) {
		if (m->cs_list) {
			transfer_sync_data(cs_list, m->cs_list);
			map_drop_cslist(m);
		}
		rcu_assign_pointer(cs_list->map, m);
		cs_list->version = m->version;
		m->cs_list = cs_list;
		cs_list = NULL;
	} else if (m->state & PCS_MAP_NEW) {
		/* This suppose to be zero chunk */
		BUG_ON(!(m->state & (PCS_MAP_READABLE|PCS_MAP_NEW)));
		map_drop_cslist(m);
		m->chunk_psize = 0;
		if (m->flags & PCS_MAP_DIRTY) {
			m->flags &= ~PCS_MAP_DIRTY;
			atomic_dec(&m->maps->dirty_count);
		}

	}

	m->state = 0;
	if (omap->state & PCS_IOC_MAP_S_READ)
		m->state |= PCS_MAP_READABLE;
	if (omap->state & PCS_IOC_MAP_S_WRITE)
		m->state |= PCS_MAP_WRITEABLE;
	if (omap->state & PCS_IOC_MAP_S_ERROR)
		m->state |= PCS_MAP_ERROR;
	if (omap->state & PCS_IOC_MAP_S_NEW) {
		m->state |= PCS_MAP_NEW;
		/* Userspace has optimization which may return map
		 * which cover larger range, But this complicate locking.
		 * Simply ignore it for now. */
		if (omap->chunk_start < map_chunk_start(m))
			omap->chunk_start = map_chunk_start(m);
		if (map_chunk_end(m) < omap->chunk_end)
			omap->chunk_end = map_chunk_end(m);
	}
	m->mds_flags = omap->mds_flags;
	m->chunk_psize = omap->chunk_psize; /* UNUSED */
	m->res_offset  = omap->chunk_start;
	if (map_chunk_start(m) != omap->chunk_start ||
	    map_chunk_end(m)   != omap->chunk_end) {
		BUG();
	}

	evaluate_dirty_status(m);
#ifdef __PCS_DEBUG
	/* The output is too ugly and it is unnecessary. The information is in user space log */
	if (0) {
		int i;
		TRACE(MAP_FMT " -> " CUID_FMT " psize=%u %d node map { ",
			MAP_ARGS(m), CUID_ARGS(m->id),
		      m->chunk_psize, m->cs_list ? m->cs_list->nsrv : 0);
		if (m->cs_list) {
			for (i = 0; i < m->cs_list->nsrv; i++)
				trace_printk( NODE_FMT ":%x:%u ",
				       NODE_ARGS(m->cs_list->cs[i].info.id),
				       m->cs_list->cs[i].info.flags,
				       CS_FL_ROLE_GET(m->cs_list->cs[i].info.flags));
		}
		trace_puts("}\n");
	}
#endif
	m->error_tstamp = 0;
	list_splice_tail_init(&m->queue, &queue);
	spin_unlock(&m->lock);

	/* Success, resubmit waiting requests */
	pcs_cc_requeue(cc_from_map(m), &queue);
	BUG_ON(!list_empty(&queue));
	pcs_map_put(m);

	return;

error:
	TRACE(" map error: %d for " MAP_FMT "\n", error.value, MAP_ARGS(m));
	BUG_ON(!pcs_if_error(&error));

	m->state &= ~PCS_MAP_RESOLVING;
	m->error_tstamp = jiffies;
	list_splice_tail_init(&m->queue, &queue);
	pcs_map_reset(m);
	spin_unlock(&m->lock);

	pcs_ireq_queue_fail(&queue, error.value);
out_ignore:
	BUG_ON(!list_empty(&queue));
	pcs_map_put(m);
	if (cs_list)
		cslist_put(cs_list);
}

/* Atomically schedule map resolve and push ireq to wait completion */
static void pcs_map_queue_resolve(struct pcs_map_entry * m, struct pcs_int_request *ireq, int direction)
{
	LIST_HEAD(l);
	int ret;

	DTRACE("enter m:%p, state:%x, ireq:%p dir:%d \n", m, m->state, ireq, direction);

	spin_lock(&m->lock);
	/* This should not happen unless aio_dio/fsync vs truncate race */
	if (m->state & PCS_MAP_DEAD) {
		spin_unlock(&m->lock);
		list_add(&ireq->list, &l);
		pcs_ireq_queue_fail(&l, PCS_ERR_NET_ABORT);
		return;
	}
	DTRACE("dentry: "DENTRY_FMT, DENTRY_ARGS(pcs_dentry_from_map(m)));
	DTRACE("%p {%p %p}\n",ireq,  ireq->list.next, ireq->list.prev);
	BUG_ON(!list_empty(&ireq->list));

	list_add_tail(&ireq->list, &m->queue);
	if (m->state & PCS_MAP_RESOLVING) {
		spin_unlock(&m->lock);
		return;
	}
	/* If converting a hole, adjust res_offset */
	if (direction && !m->cs_list && !(m->state & PCS_MAP_RESOLVING)
	    && ireq->type == PCS_IREQ_IOCHUNK)
		m->res_offset = ireq->iochunk.chunk + ireq->iochunk.offset;

	m->state |= PCS_MAP_RESOLVING;
	__pcs_map_get(m); /* drop on pcs_map_complete */

	spin_unlock(&m->lock);
	/// TODO: THINK!!!!
	/// May be it is reasonable to schedule fuse_map_resolve from work_queue?
	ret = fuse_map_resolve(m, direction);
	if (ret) {
		TRACE("map error: %d for " MAP_FMT "\n", ret, MAP_ARGS(m));
		spin_lock(&m->lock);
		pcs_map_truncate(m, &l);
		map_del_lru(m);
		spin_unlock(&m->lock);
		pcs_ireq_queue_fail(&l, PCS_ERR_NOMEM);
		pcs_map_put(m);
	}
}

/* If version on m is not already advanced, we must notify MDS about the error.
 * It it is still not advanced, we just ignore the error in hope new map
 * will work.
 */
static void map_notify_error(struct pcs_map_entry * m, struct pcs_int_request * sreq,
			     PCS_MAP_VERSION_T * failed_version, struct pcs_cs_list * csl)
{
	int cs_notify = 0;

	spin_lock(&m->lock);
	if (m->state & PCS_MAP_DEAD) {
		spin_unlock(&m->lock);
		return;
	}
	if (sreq->error.remote &&
	    !(m->state & (PCS_MAP_ERROR|PCS_MAP_NEW|PCS_MAP_RESOLVING|PCS_MAP_DEAD)) &&
	    map_version_compare(failed_version, &m->version) >= 0) {
		int suppress_error = 0;

		if (csl) {
			int i;

			for (i = 0; i < csl->nsrv; i++) {
				if (csl->cs[i].info.id.val == sreq->error.offender.val) {
					if (csl->cs[i].cslink.cs->addr_serno != csl->cs[i].cslink.addr_serno) {
						FUSE_KTRACE(cc_from_maps(m->maps)->fc, "error for CS"NODE_FMT " has been suppressed", NODE_ARGS(sreq->error.offender));
						suppress_error = 1;
					}
					break;
				}
			}
		}
		if (suppress_error)
			map_remote_error_nolock(m, PCS_ERR_CSD_STALE_MAP, sreq->error.offender.val);
		else {
			map_remote_error_nolock(m, sreq->error.value, sreq->error.offender.val);
			cs_notify = 1;
		}
	}
	spin_unlock(&m->lock);
	if (cs_notify)
		pcs_cs_notify_error(sreq->dentry->cluster, &sreq->error);

}

/* This function notifies map about fatal error, which does not result in request restart.
 * Even though the request is not retried internally, it can be retried by client, so that
 * we have to force invalidation of current version.
 */
void map_notify_iochunk_error(struct pcs_int_request * sreq)
{
	struct pcs_map_entry * m = sreq->iochunk.map;

	if (!m || (m->state & PCS_MAP_DEAD))
		return;

	map_notify_error(m, sreq, &sreq->iochunk.hbuf.map_version, sreq->iochunk.csl);
}

static void map_replicating(struct pcs_int_request *ireq)
{
	struct pcs_cs_list * csl = ireq->iochunk.csl;
	int read_idx;

	BUG_ON(pcs_req_direction(ireq->iochunk.cmd));

	if (csl == NULL || csl->map == NULL)
		return;

	read_idx = READ_ONCE(csl->read_index);

	FUSE_KTRACE(ireq->cc->fc, "reading unfinished replica %lx %d", csl->blacklist, read_idx);

	if (ireq->iochunk.cs_index != read_idx)
		return;

	BUG_ON(read_idx < 0 || read_idx > csl->nsrv);

	if (!ireq->error.remote ||
	    csl->cs[read_idx].cslink.cs->id.val != ireq->error.offender.val) {
		FUSE_KTRACE(ireq->cc->fc, "wrong cs id " NODE_FMT " " NODE_FMT, NODE_ARGS(csl->cs[read_idx].cslink.cs->id), NODE_ARGS(ireq->error.offender));
		return;
	}

	/* If request was issued for the last CS in the list, clear error. */
	pcs_clear_error(&ireq->error);
	WRITE_ONCE(csl->blacklist_expires, jiffies + PCS_REPLICATION_BLACKLIST_TIMEOUT);

	/* And blacklist the last replica */
	if (!(test_bit(read_idx, &csl->blacklist))) {
		WRITE_ONCE(csl->read_index, -1);
		set_bit(read_idx, &csl->blacklist);
	}
}

static void map_read_error(struct pcs_int_request *ireq)
{
	struct pcs_cs_list * csl = ireq->iochunk.csl;
	struct pcs_cs * cs;

	BUG_ON(pcs_req_direction(ireq->iochunk.cmd));

	if (csl == NULL || csl->map == NULL || (csl->map->state & PCS_MAP_ERROR))
		return;

	cs = rcu_dereference_protected(csl->cs[ireq->iochunk.cs_index].cslink.cs,
				       atomic_read(&csl->refcnt) > 0);

	if (ireq->flags & IREQ_F_MAPPED) {
		cs_blacklist_unlocked(cs, ireq->error.value, "error on directly mapped CS");
		return;
	}

	/* If everything is already backlisted, proceed reporting error to MDS */
	if (all_blacklisted(csl)) {
		cs_blacklist_unlocked(cs, ireq->error.value, "total read error");
		return;
	}

	/* If this CS is already blacklisted, select another CS, we have spare ones */
	if (cs_is_blacklisted(cs)) {
		FUSE_KTRACE(ireq->cc->fc, "Skipping CS" NODE_FMT, NODE_ARGS(cs->id));
		WRITE_ONCE(csl->read_index, -1);
		pcs_clear_error(&ireq->error);
		return;
	}

	/* Mark CS as dubioius */
	if (csl->cs[ireq->iochunk.cs_index].cslink.addr_serno == cs->addr_serno)
		cs_blacklist_unlocked(cs, ireq->error.value, "read error");

	/* If some clean CSes remained, select another one, otherwise report error to MDS */
	if (!all_blacklisted(csl)) {
		WRITE_ONCE(csl->read_index, -1);
		pcs_clear_error(&ireq->error);
	}
}

static unsigned int cong_roundup(unsigned int size)
{
	return (size + 65535) & ~65535;
}

static int worth_to_grow(struct pcs_int_request *ireq, struct pcs_cs * cs)
{
	if (ireq->type == PCS_IREQ_FLUSH)
		return 0;

	return ktime_to_ms(ktime_sub(ktime_get(), ireq->ts_sent)) + cc_from_csset(cs->css)->netlat_cutoff;
}

static void pcs_cs_deaccount(struct pcs_int_request *ireq, struct pcs_cs * cs, int error)
{
	unsigned int cost;

	spin_lock(&cs->lock);
	if (ireq->type == PCS_IREQ_IOCHUNK) {
		if (ireq->iochunk.cmd == PCS_REQ_T_WRITE_HOLE ||
		    ireq->iochunk.cmd == PCS_REQ_T_WRITE_ZERO)
			cost = PCS_CS_HOLE_WEIGHT;
		else
			cost = (ireq->flags & IREQ_F_RND_WEIGHT) ? 512*1024 : cong_roundup(ireq->iochunk.size);
	} else
		cost = PCS_CS_FLUSH_WEIGHT;

	if (!error) {
		int iolat_cutoff = cc_from_csset(cs->css)->iolat_cutoff;

		if (cs->last_latency > iolat_cutoff && ireq->type != PCS_IREQ_FLUSH) {
			unsigned int clamp;

			clamp = PCS_CS_INIT_CWND;
			if (cs->last_latency > iolat_cutoff*8)
				clamp = PCS_CS_INIT_CWND/8;
			else if (cs->last_latency > iolat_cutoff*4)
				clamp = PCS_CS_INIT_CWND/4;
			else if (cs->last_latency > iolat_cutoff*2)
				clamp = PCS_CS_INIT_CWND/2;

			FUSE_KTRACE(cc_from_csset(cs->css)->fc, "IO latency on CS" NODE_FMT " is %u, cwnd %u, clamp %u", NODE_ARGS(cs->id), cs->last_latency, cs->cwnd, clamp);

			if (cs->cwnd > clamp)
				cs->cwnd = clamp;
		} else if (cs->in_flight >= cs->cwnd && !cs->cwr_state && worth_to_grow(ireq, cs)) {
			unsigned int cwnd;

			if (cs->cwnd < PCS_CS_INIT_CWND)
				cwnd = cs->cwnd + cost;
			else
				cwnd = cs->cwnd + 0x100000000ULL/cs->cwnd;

			if (cwnd > PCS_CS_MAX_CWND)
				cwnd = PCS_CS_MAX_CWND;
			if (cwnd != cs->cwnd) {
				cs->cwnd = cwnd;
				FUSE_KDTRACE(cc_from_csset(cs->css)->fc, "Congestion window on CS" NODE_FMT " UP %u", NODE_ARGS(cs->id), cwnd);
			}
		}
		cs->eff_cwnd = cs->cwnd;
		cs_whitelist(cs, "io hint");
	} else if (error > 0) {
		/* In case of error coming from some CS temporarily shrink congestion
		 * window to minimum to allow one request in flight. It will come back to normal
		 * as soon as CS is probed for aliveness.
		 */
		FUSE_KTRACE(cc_from_csset(cs->css)->fc, "Congestion window on CS" NODE_FMT " is closed (%u)", NODE_ARGS(cs->id), cs->cwnd);
		cs->eff_cwnd = 1;
	}
	cs_decrement_in_flight(cs, cost);
	spin_unlock(&cs->lock);
}

static void pcs_cs_wakeup(struct pcs_cs * cs)
{
	struct pcs_int_request * sreq;
	struct pcs_map_entry * map;

	while (1) {
		spin_lock(&cs->lock);

		if (cs->in_flight >= cs->eff_cwnd || list_empty(&cs->active_list)) {
			spin_unlock(&cs->lock);
			break;
		}
		sreq = list_first_entry(&cs->active_list, struct pcs_int_request, list);
		list_del_init(&sreq->list);
		cs->cong_queue_len--;
		spin_unlock(&cs->lock);

		if (sreq->type == PCS_IREQ_TOKEN) {
			struct pcs_int_request * parent = sreq->token.parent;
			int do_execute = 0;

			if (parent == NULL) {
				ireq_destroy(sreq);
				continue;
			}

			spin_lock(&parent->completion_data.child_lock);
			if (sreq->token.parent) {
				parent->tok_reserved |= (1ULL << sreq->token.cs_index);
				list_del(&sreq->token.tok_link);
				do_execute = list_empty(&parent->tok_list);
			}
			spin_unlock(&parent->completion_data.child_lock);
			ireq_destroy(sreq);
			if (!do_execute)
				continue;
			sreq = parent;
		}

		if (sreq->type != PCS_IREQ_FLUSH) {
			map = pcs_find_get_map(sreq->dentry, sreq->iochunk.chunk +
						   ((sreq->flags & IREQ_F_MAPPED) ? 0 : sreq->iochunk.offset));
			if (map) {
				if (sreq->iochunk.map)
					pcs_map_put(sreq->iochunk.map);
				sreq->iochunk.map = map;
				if (sreq->iochunk.flow) {
					struct pcs_int_request * preq = sreq->completion_data.parent;

					pcs_flow_confirm(sreq->iochunk.flow, &map->mapping->ftab, preq->apireq.req->type == PCS_REQ_T_WRITE,
							 preq->apireq.req->pos, preq->apireq.req->size,
							 &sreq->cc->maps.ftab);
				}
				map_submit(map, sreq);
			} else {
				map_queue_on_limit(sreq);
			}
		} else {
			map = sreq->flushreq.map;
			if (map->state & PCS_MAP_DEAD) {
				pcs_clear_error(&sreq->error);
				ireq_complete(sreq);
			} else
				map_submit(map, sreq);
		}
	}
}

static int __pcs_cs_still_congested(struct pcs_cs * cs)
{
	list_splice_tail_init(&cs->active_list, &cs->cong_queue);

	if (list_empty(&cs->cong_queue)) {
		BUG_ON(cs->cong_queue_len);
		return 0;
	}

	return cs->in_flight < cs->eff_cwnd;
}

static int pcs_cs_still_congested(struct pcs_cs * cs)
{
	int res;

	spin_lock(&cs->lock);
	res = __pcs_cs_still_congested(cs);
	spin_unlock(&cs->lock);

	return res;
}

void pcs_deaccount_ireq(struct pcs_int_request *ireq, pcs_error_t * err)
{
	int error = 0;
	unsigned long long match_id = 0;
	struct pcs_cs_list * csl, ** csl_p = 0;

	switch (ireq->type) {
	case PCS_IREQ_IOCHUNK:
		csl_p = &ireq->iochunk.csl;
		if (ireq->iochunk.map) {
			pcs_map_put(ireq->iochunk.map);
			ireq->iochunk.map = NULL;
		}
		break;
	case PCS_IREQ_FLUSH:
		csl_p = &ireq->flushreq.csl;
		break;
	default:
		BUG();
	}

	if ((csl = *csl_p) == NULL)
		return;

	if (pcs_if_error(err)) {
		if (!err->remote) {
			error = -1;
		} else {
			match_id = err->offender.val;
			error = err->value;

			switch (error) {
			case PCS_ERR_CSD_STALE_MAP:
			case PCS_ERR_CSD_REPLICATING:
			case PCS_ERR_CSD_RO_MAP:
				error = 0;
			}
		}
	}

	if (ireq->type == PCS_IREQ_FLUSH || (pcs_req_direction(ireq->iochunk.cmd) && !(ireq->flags & IREQ_F_MAPPED))) {
		int i;
		int requeue;

		for (i = csl->nsrv - 1; i >= 0; i--) {
			if (!match_id || csl->cs[i].cslink.cs->id.val == match_id)
				break;

			pcs_cs_deaccount(ireq, csl->cs[i].cslink.cs, -1);
		}

		if (i >= 0) {
			pcs_cs_deaccount(ireq, csl->cs[i].cslink.cs, error);
			i--;
		}

		for ( ; i >= 0; i--) {
			pcs_cs_deaccount(ireq, csl->cs[i].cslink.cs, 0);
		}

		for (;;) {
			for (i = csl->nsrv - 1; i >= 0; i--)
				pcs_cs_wakeup(csl->cs[i].cslink.cs);

			requeue = 0;
			for (i = csl->nsrv - 1; i >= 0; i--)
				requeue |= pcs_cs_still_congested(csl->cs[i].cslink.cs);

			if (!requeue)
				break;

			for (i = csl->nsrv - 1; i >= 0; i--) {
				struct pcs_cs * cs = csl->cs[i].cslink.cs;
				spin_lock(&cs->lock);
				pcs_cs_activate_cong_queue(cs);
				spin_unlock(&cs->lock);
			}
		};
	} else {
		struct pcs_cs * rcs = csl->cs[ireq->iochunk.cs_index].cslink.cs;

		if (ireq->flags & IREQ_F_SEQ_READ) {
			ireq->flags &= ~IREQ_F_SEQ_READ;
			if (atomic_dec_and_test(&csl->seq_read_in_flight))
				WRITE_ONCE(csl->select_stamp, jiffies);
		}

		pcs_cs_deaccount(ireq, rcs, error);

		for (;;) {
			pcs_cs_wakeup(rcs);

			if (!pcs_cs_still_congested(rcs))
				break;

			spin_lock(&rcs->lock);
			pcs_cs_activate_cong_queue(rcs);
			spin_unlock(&rcs->lock);
		};
	}
	*csl_p = NULL;
	cslist_put(csl);
}

void map_notify_soft_error(struct pcs_int_request *ireq)
{
	pcs_error_t err;

	if (ireq->error.value == PCS_ERR_CSD_REPLICATING)
		map_replicating(ireq);

	if (ireq->error.value == PCS_ERR_CANCEL_KEEPWAIT)
		pcs_clear_error(&ireq->error);

	err = ireq->error;

	if (!pcs_req_direction(ireq->iochunk.cmd) &&
	    pcs_if_error(&err) &&
	    err.remote &&
	    err.value != PCS_ERR_CSD_STALE_MAP &&
	    err.value != PCS_ERR_CSD_REPLICATING &&
	    err.value != PCS_ERR_CSD_RO_MAP)
		map_read_error(ireq);

	if (pcs_if_error(&ireq->error))
		map_notify_iochunk_error(ireq);

	if (map_version_compare(&ireq->iochunk.hbuf.map_version, &ireq->iochunk.map->version) < 0)
		ireq->flags &= ~IREQ_F_ONCE;

	pcs_deaccount_ireq(ireq, &err);
}

static unsigned int map_ioprio_to_latency(unsigned int io_prio)
{
	static unsigned int map[] = {
		50000,
		50000,
		10000,
		4000,
		2000,
	};

	if (io_prio < sizeof(map)/sizeof(map[0]))
		return map[io_prio];
	else
		return 500;
}

static int get_io_locality(struct pcs_cluster_core *cc)
{
	int io_locality;

	io_locality = cc->io_locality;
	if (io_locality == 0)
		io_locality = cc->cfg.curr.io_locality;

	return io_locality;
}

static unsigned int get_io_tweaks(struct pcs_cluster_core *cc)
{
	unsigned int io_tweaks;

	io_tweaks = cc->io_tweaks;
	if (io_tweaks == 0)
		io_tweaks = cc->cfg.curr.io_tweaks;

	return io_tweaks;
}

static int select_cs_for_read(struct pcs_cluster_core *cc, struct pcs_cs_list * csl, int is_seq, unsigned int pos, PCS_NODE_ID_T banned_cs)
{
	abs_time_t now = jiffies;
	unsigned int local_min, remote_min, local_pipe, remote_pipe;
	unsigned int local_mask, local_busy_mask;
	int local_idx, remote_idx, selected;
	int io_locality = get_io_locality(cc);
	int io_cost;
	int failed_cnt = 0;
	int i;

next_pass:

	local_min = remote_min = local_pipe = remote_pipe = ~0U;
	local_idx = remote_idx = -1;
	local_mask = local_busy_mask = 0;

	for (i = csl->nsrv - 1; i >= 0; i--) {
		struct pcs_cs * cs = csl->cs[i].cslink.cs;
		unsigned int w, io_lat, net_lat;
		unsigned int in_flight;
		abs_time_t io_prio_stamp;

		if (failed_cnt >= 0 && ((test_bit(CS_SF_FAILED, &cs->state)) || cs->id.val == banned_cs.val)) {
			failed_cnt++;
			continue;
		}

		if (test_bit(i, &csl->blacklist)) {
			if (jiffies < READ_ONCE(csl->blacklist_expires))
				continue;
			FUSE_KTRACE(cc_from_csset(cs->css)->fc, "expire replication blacklist");
			clear_bit(i, &csl->blacklist);
		}

		if (cs_is_blacklisted(cs))
			continue;

		io_lat = __cs_get_avg_latency(cs, now);
		net_lat = __cs_get_avg_net_latency(cs, now);
		in_flight = READ_ONCE(cs->in_flight);
		io_prio_stamp = READ_ONCE(cs->io_prio_stamp);

		w = io_lat + net_lat;

		if ((io_lat >> CS_LAT_EWMA_LOG) == 0 &&
		    now < io_prio_stamp + PCS_CS_IO_PRIO_VALID_TIME)
			w = map_ioprio_to_latency(READ_ONCE(cs->io_prio)) + net_lat;

		if (get_io_tweaks(cc) & PCS_TWEAK_USE_FLOW_LOAD)
			w += pcs_flow_cs_analysis(cs) * 8000;

		if (w <= remote_min) {

			if (w < remote_min || in_flight <= remote_pipe) {
				remote_min = w;
				remote_pipe = in_flight;
				remote_idx = i;
			}
		}

		if (test_bit(CS_SF_LOCAL, &cs->state)) {
			local_mask |= (1 << i);
			if (io_lat > 1000)
				local_busy_mask |= (1 << i);

			if (w < local_min || (w == local_min && in_flight <= local_pipe)) {
				local_min = w;
				local_pipe = in_flight;
				local_idx = i;
			}
		}
	}

	if (remote_idx < 0) {
		if (failed_cnt > 0) {
			failed_cnt = -1;
			goto next_pass;
		}
		return -1;
	}

	/* If the flow is sequential, but we have too many sequential flows, consider
	 * all of them random, which is essentially true.
	 */
	io_cost = 8000;
	if (is_seq) {
		int nflows = pcs_flow_analysis(&cc->maps.ftab);

		if (nflows >= PCS_FLOW_THRESH && io_locality < 0)
			is_seq = 0;

		if (nflows < PCS_FLOW_THRESH)
			io_cost = 500;
	}

	if (local_idx < 0)
		selected = remote_idx;
	else if (io_locality > 0)
		selected = local_idx;
	else if (io_locality == 0 && local_mask != local_busy_mask) {
		selected = local_idx;
		io_cost = local_min / 16;
	} else if (get_io_tweaks(cc) & PCS_TWEAK_IGNORE_SEQUENTIAL)
		selected = remote_idx;
	else {
		if (is_seq)
			selected = local_idx;
		else
			selected = remote_idx;
	}

	/* Add penalty. The result of current decision will reflect itself in latency
	 * after at least one round-trip time. Penalty poisons weight until that moment.
	 * Ideally it should decay and be replaced with EWMA average introduced by increased latency.
	 * Think about better algorithm, maybe, it is the key to finally correct algorithm.
	 */
	if (!(get_io_tweaks(cc) & PCS_TWEAK_USE_FLOW_LOAD))
		cs_account_latency(csl->cs[selected].cslink.cs, io_cost);

	return selected;
}

struct pcs_int_request *
pcs_ireq_split(struct pcs_int_request *ireq, unsigned int iochunk, int noalign)
{
	struct pcs_int_request * sreq;

	sreq = ireq_alloc(ireq->dentry);
	if (!sreq)
		return NULL;

	sreq->dentry = ireq->dentry;
	sreq->type = PCS_IREQ_IOCHUNK;
	sreq->flags = ireq->flags;
	sreq->iochunk.map = ireq->iochunk.map;
	if (sreq->iochunk.map)
		__pcs_map_get(sreq->iochunk.map);
	INIT_LIST_HEAD(&sreq->tok_list);
	BUG_ON(!list_empty(&ireq->tok_list));
	sreq->tok_reserved = ireq->tok_reserved;
	sreq->tok_serno = ireq->tok_serno;
	sreq->iochunk.flow = pcs_flow_get(ireq->iochunk.flow);
	sreq->iochunk.cmd = ireq->iochunk.cmd;
	sreq->iochunk.role = ireq->iochunk.role;
	sreq->iochunk.cs_index = ireq->iochunk.cs_index;
	sreq->iochunk.chunk = ireq->iochunk.chunk;
	sreq->iochunk.offset = ireq->iochunk.offset;
	sreq->iochunk.dio_offset = ireq->iochunk.dio_offset;
	if (!noalign &&
	    (sreq->iochunk.offset & 4095) &&
	    iochunk > (sreq->iochunk.offset & 4095) &&
	    ireq->iochunk.map &&
	    sreq->iochunk.chunk + sreq->iochunk.offset + iochunk != map_chunk_end(ireq->iochunk.map))
		iochunk -= (sreq->iochunk.offset & 4095);
	sreq->iochunk.size = iochunk;

	if (ireq->flags & IREQ_F_LOC_TOKEN)
		BUG();

	sreq->iochunk.csl = NULL;
	sreq->iochunk.banned_cs.val = 0;
	sreq->complete_cb = ireq->complete_cb;
	sreq->iochunk.msg.destructor = NULL;
	sreq->iochunk.msg.rpc = NULL;
	pcs_sreq_attach(sreq, ireq->completion_data.parent);

	ireq->iochunk.size -= iochunk;
	ireq->iochunk.offset += iochunk;
	ireq->iochunk.dio_offset += iochunk;

	return sreq;
}

static int pcs_cslist_submit_read(struct pcs_int_request *ireq, struct pcs_cs_list * csl)
{
	struct pcs_cluster_core *cc = ireq->cc;
	struct pcs_cs * cs;
	unsigned int iochunk;
	int allot;
	int i = -1;
	int is_seq, csl_seq = atomic_read(&csl->seq_read_in_flight);

	is_seq = csl_seq || pcs_flow_sequential(ireq->iochunk.flow);
	i = READ_ONCE(csl->read_index);

	if (i >= 0) {
		abs_time_t now = jiffies;
		abs_time_t selected = READ_ONCE(csl->select_stamp);

		cs = csl->cs[i].cslink.cs;

		/* Force rebalance after long timeout or when there is no sequential IO
		 * on this chunk and new read begins from chunk start.
		 * Also rebalance after short timeout, but only if one of the following conditions hold:
		 * 1. No active sequential reads on this chunk, including this one.
		 * 2. io_locality < 0
		 * 3. No active sequential reads, sequential read from remote CS. Maybe, we want to switch to local.
		 */
		if (now > selected + PCS_MAP_MAX_REBALANCE_TIMEOUT ||
		    (!csl_seq && ireq->iochunk.offset == 0) ||
		    (get_io_tweaks(cc) & PCS_TWEAK_REBALANCE_ALWAYS) ||
		    (now > selected + PCS_MAP_MIN_REBALANCE_TIMEOUT &&
		     (!is_seq || get_io_locality(cc) < 0 ||
		      (!csl_seq &&
		       !(test_bit(CS_SF_LOCAL, &cs->state)) && (csl->flags & CSL_FL_HAS_LOCAL))))) {
			i = -1;
			WRITE_ONCE(csl->read_index, -1);
		}
	}

	if (i < 0) {
		i = select_cs_for_read(cc, csl, is_seq, ireq->iochunk.offset, ireq->iochunk.banned_cs);

		if (i < 0) {
			/* All CSes are blacklisted. Generate error for the first one
			 * and let MDS to figure what heppened with the rest.
			 */
			cs = csl->cs[0].cslink.cs;
			map_remote_error(ireq->iochunk.map, cs->blacklist_reason, cs->id.val);

			FUSE_KTRACE(ireq->cc->fc, "Read from " MAP_FMT " blocked by blacklist error %d, CS" NODE_FMT,
			      MAP_ARGS(ireq->iochunk.map), cs->blacklist_reason, NODE_ARGS(cs->id));
			return -1;
		}

		WRITE_ONCE(csl->read_index, i);
		WRITE_ONCE(csl->select_stamp, jiffies);

		FUSE_KTRACE(ireq->cc->fc, "Selected read map " MAP_FMT " to CS" NODE_FMT "; is_seq=%d\n", MAP_ARGS(ireq->iochunk.map),
		      NODE_ARGS(csl->cs[i].cslink.cs->id), is_seq);
		pcs_flow_bind_cs(ireq->iochunk.flow, csl->cs[i].cslink.cs);
	}
	cs = csl->cs[i].cslink.cs;

	ireq->iochunk.cs_index = i;

	spin_lock(&cs->lock);
	cs_cwnd_use_or_lose(cs);
	allot = cs->eff_cwnd - cs->in_flight;
	spin_unlock(&cs->lock);

	if (allot < 0) {
		if (pcs_cs_cong_enqueue_cond(ireq, cs))
			return 0;
	}

	if (allot < ireq->dentry->cluster->cfg.curr.lmss)
		allot = ireq->dentry->cluster->cfg.curr.lmss;

	if (test_bit(CS_SF_LOCAL, &cs->state))
		iochunk = ireq->dentry->cluster->cfg.curr.lmss;
	else
		iochunk = ireq->dentry->cluster->cfg.curr.rmss;

	for (;;) {
		struct pcs_int_request * sreq = ireq;
		unsigned int weight;

		if (ireq->iochunk.size > iochunk && ireq->iochunk.cmd == PCS_REQ_T_WRITE) {
			sreq = pcs_ireq_split(ireq, iochunk, 0);

			if (sreq == NULL) {
				pcs_set_local_error(&ireq->error, PCS_ERR_NOMEM);
				ireq_complete(ireq);
				return 0;
			}
		}

		sreq->flags &= ~(IREQ_F_RND_WEIGHT | IREQ_F_SEQ);
		BUG_ON(sreq->flags & IREQ_F_SEQ_READ);
		if (pcs_flow_sequential(sreq->iochunk.flow)) {
			sreq->flags |= IREQ_F_SEQ_READ | IREQ_F_SEQ;
			atomic_inc(&csl->seq_read_in_flight);
			weight = cong_roundup(sreq->iochunk.size);
		} else if (sreq->iochunk.size >= 512*1024 || !(get_io_tweaks(cc) & PCS_TWEAK_USE_FLOW_WEIGHT)) {
			weight = cong_roundup(sreq->iochunk.size);
		} else {
			sreq->flags |= IREQ_F_RND_WEIGHT;
			weight = 512*1024;
		}

		cs_increment_in_flight(cs, weight);
		allot -= weight;

		BUG_ON(sreq->iochunk.csl);
		cslist_get(csl);
		sreq->iochunk.csl = csl;
		pcs_cs_submit(cs, sreq);

		if (sreq == ireq)
			return 0;

		if (allot < 0) {
			if (pcs_cs_cong_enqueue_cond(ireq, cs))
				return 0;
		}
	}
}

static int ireq_queue_tokens(struct pcs_int_request * ireq, struct pcs_cs_list * csl)
{
       int i;
       int queued = 0;
       struct list_head drop;
       struct pcs_int_request * toks[csl->nsrv];

       INIT_LIST_HEAD(&drop);

       for (i = 0; i < csl->nsrv; i++) {
               struct pcs_int_request * ntok;

	       /* ireq is private; no need to lock tok_* fields */

               if (ireq->tok_reserved & (1ULL << i)) {
		       toks[i] = NULL;
                       continue;
	       }

               ntok = ireq_alloc(ireq->dentry);
               BUG_ON(!ntok);
               ntok->type = PCS_IREQ_TOKEN;
               ntok->token.parent = ireq;
               ntok->token.cs_index = i;
	       toks[i] = ntok;
       }

       /* Publish tokens in CS queues */
       spin_lock(&ireq->completion_data.child_lock);
       for (i = 0; i < csl->nsrv; i++) {
	       if (toks[i]) {
		       struct pcs_cs * cs = csl->cs[i].cslink.cs;
		       if (pcs_cs_cong_enqueue_cond(toks[i], cs)) {
			       list_add(&toks[i]->token.tok_link, &ireq->tok_list);
			       toks[i] = NULL;
			       queued = 1;
		       } else {
			       ireq->tok_reserved |= (1ULL << i);
			       list_add(&toks[i]->token.tok_link, &drop);
		       }
	       }
       }
       spin_unlock(&ireq->completion_data.child_lock);

       while (!list_empty(&drop)) {
	       struct pcs_int_request * tok = list_first_entry(&drop, struct pcs_int_request, token.tok_link);
	       list_del(&tok->token.tok_link);
	       ireq_destroy(tok);
       }
       return queued;
}

void ireq_drop_tokens(struct pcs_int_request * ireq)
{
	assert_spin_locked(&ireq->completion_data.child_lock);

	while (!list_empty(&ireq->tok_list)) {
		struct pcs_int_request * tok = list_first_entry(&ireq->tok_list, struct pcs_int_request, token.tok_link);
		tok->token.parent = NULL;
		list_del(&tok->token.tok_link);
        }
}

static int pcs_cslist_submit_write(struct pcs_int_request *ireq, struct pcs_cs_list * csl)
{
	struct pcs_cs * cs;
	unsigned int iochunk;
	int i;
	int allot;
	struct pcs_cs * congested_cs = NULL;
	u64 congested = 0;

	ireq->iochunk.cs_index = 0;
	iochunk = ireq->dentry->cluster->cfg.curr.lmss;

restart:
	allot = ireq->iochunk.size;
	if (csl->serno != ireq->tok_serno)
		ireq->tok_reserved = 0;
	BUG_ON(!list_empty(&ireq->tok_list));

	for (i = 0; i < csl->nsrv; i++) {
		cs = csl->cs[i].cslink.cs;
		if (cs_is_blacklisted(cs)) {
			map_remote_error(ireq->iochunk.map, cs->blacklist_reason, cs->id.val);
			FUSE_KTRACE(cc_from_csset(cs->css)->fc, "Write to " MAP_FMT " blocked by blacklist error %d, CS" NODE_FMT,
			      MAP_ARGS(ireq->iochunk.map), cs->blacklist_reason, NODE_ARGS(cs->id));
			spin_lock(&ireq->completion_data.child_lock);
			ireq_drop_tokens(ireq);
			spin_unlock(&ireq->completion_data.child_lock);
			return -1;
		}
		spin_lock(&cs->lock);
		cs_cwnd_use_or_lose(cs);
		spin_unlock(&cs->lock);

		if (cs->in_flight > cs->eff_cwnd && !(ireq->tok_reserved & (1ULL << i))) {
			congested_cs = cs;
			congested |= (1ULL << i);
		} else
			ireq->tok_reserved |= (1ULL << i);

		if (!(test_bit(CS_SF_LOCAL, &cs->state)))
			iochunk = ireq->dentry->cluster->cfg.curr.wmss;
	}

	if (allot < ireq->dentry->cluster->cfg.curr.lmss)
		allot = ireq->dentry->cluster->cfg.curr.lmss;

	if (congested) {
		int queued;

		ireq->tok_serno = csl->serno;
		if (congested & (congested - 1))
			queued = ireq_queue_tokens(ireq, csl);
		else
			queued = pcs_cs_cong_enqueue_cond(ireq, congested_cs);
		if (queued)
			return 0;
	}

	for (;;) {
		struct pcs_int_request * sreq = ireq;
		unsigned int weight;

		if (ireq->iochunk.size > iochunk) {
			sreq = pcs_ireq_split(ireq, iochunk, 0);

			if (sreq == NULL) {
				pcs_set_local_error(&ireq->error, PCS_ERR_NOMEM);
				ireq_complete(ireq);
				return 0;
			}
		}

		sreq->flags &= ~(IREQ_F_RND_WEIGHT | IREQ_F_SEQ);
		BUG_ON(sreq->flags & IREQ_F_SEQ_READ);
		if (ireq->iochunk.cmd != PCS_REQ_T_WRITE) {
			weight = PCS_CS_HOLE_WEIGHT;
		} else if (pcs_flow_sequential(sreq->iochunk.flow)) {
			weight = cong_roundup(sreq->iochunk.size);
			sreq->flags |= IREQ_F_SEQ;
		} else if (!(get_io_tweaks(ireq->cc) & PCS_TWEAK_USE_FLOW_WEIGHT) ||
			   sreq->iochunk.size > 512*1024) {
			weight = cong_roundup(sreq->iochunk.size);
		} else {
			weight = 512*1024;
			sreq->flags |= IREQ_F_RND_WEIGHT;
		}

		for (i = 0; i < csl->nsrv; i++)
			cs_increment_in_flight(csl->cs[i].cslink.cs, weight);

		allot -= weight;
		cs = csl->cs[0].cslink.cs;

		cslist_get(csl);
		BUG_ON(sreq->iochunk.csl);
		sreq->iochunk.csl = csl;
		pcs_cs_submit(cs, sreq);

		if (ireq == sreq)
			return 0;

		/* Window for some of CSes is closed. Restart processing remaining part
		 * of request. Note, if state of map has been changed, it even can fail
		 * and return to caller with -1.
		 */
		if (allot < 0)
			goto restart;
	}
}

static int pcs_cslist_submit_flush(struct pcs_int_request *ireq, struct pcs_cs_list * csl)
{
	struct pcs_cs * cs;
	int i;
	int allot = PCS_CS_FLUSH_WEIGHT;
	struct pcs_msg * msg;
	struct pcs_cs_iohdr * ioh;
	u64 congested = 0;
	struct pcs_cs * congested_cs = NULL;

	if (csl->serno != ireq->tok_serno)
		ireq->tok_reserved = 0;
	BUG_ON(!list_empty(&ireq->tok_list));

	for (i = 0; i < csl->nsrv; i++) {
		cs = csl->cs[i].cslink.cs;

		if (cs_is_blacklisted(cs)) {
			map_remote_error(ireq->flushreq.map, cs->blacklist_reason, cs->id.val);
			FUSE_KTRACE(cc_from_csset(cs->css)->fc, "Flush to " MAP_FMT " blocked by blacklist error %d, CS" NODE_FMT,
			      MAP_ARGS(ireq->flushreq.map), cs->blacklist_reason, NODE_ARGS(cs->id));
			spin_lock(&ireq->completion_data.child_lock);
			ireq_drop_tokens(ireq);
			spin_unlock(&ireq->completion_data.child_lock);
			return -1;
		}

		spin_lock(&cs->lock);
		cs_cwnd_use_or_lose(cs);
		spin_unlock(&cs->lock);
		if (cs->in_flight > cs->eff_cwnd && !(ireq->tok_reserved & (1ULL << i))) {
			congested_cs = cs;
			congested |= (1ULL << i);
		} else
			ireq->tok_reserved |= (1ULL << i);
	}

	if (congested) {
		int queued;

		ireq->tok_serno = csl->serno;
		if (congested & (congested - 1))
			queued = ireq_queue_tokens(ireq, csl);
		else
			queued = pcs_cs_cong_enqueue_cond(ireq, congested_cs);
		if (queued)
			return 0;
	}

	for (i = 0; i < csl->nsrv; i++) {
		cs = csl->cs[i].cslink.cs;
		cs_increment_in_flight(cs, allot);
	}

	cs = csl->cs[0].cslink.cs;

	BUG_ON(ireq->flushreq.csl);
	cslist_get(csl);
	ireq->flushreq.csl = csl;
	ireq->ts_sent = ktime_get();
	ireq->wait_origin.val = 0;

	msg = ireq->flushreq.msg;
	msg->private2 = ireq;

	ioh = (struct pcs_cs_iohdr *)msg->_inline_buffer;

	if (msg->rpc) {
		pcs_rpc_put(msg->rpc);
		msg->rpc = NULL;
	}
	pcs_clear_error(&msg->error);
	msg->timeout = csl->write_timeout;

	pcs_rpc_get_new_xid(cs->rpc->eng, &ioh->hdr.xid);
	ioh->map_version = csl->version;

	pcs_rpc_call(cs->rpc, msg);
	return 0;
}



int pcs_cslist_submit(struct pcs_int_request *ireq, struct pcs_cs_list *csl)
{
	BUG_ON(!atomic_read(&csl->refcnt));

	if (ireq->type == PCS_IREQ_FLUSH) {
		return pcs_cslist_submit_flush(ireq, csl);
	} else if (!pcs_req_direction(ireq->iochunk.cmd)) {
		return pcs_cslist_submit_read(ireq, csl);
	} else if (ireq->flags & IREQ_F_MAPPED) {
		BUG();
		return -EIO;
	} else {
		return pcs_cslist_submit_write(ireq, csl);
	}
	BUG();
	return -EIO;
}

void map_submit(struct pcs_map_entry * m, struct pcs_int_request *ireq)
{
	int direction;
	int done;

	DTRACE("enter m: " MAP_FMT ", ireq:%p \n", MAP_ARGS(m),	 ireq);
	BUG_ON(ireq->type != PCS_IREQ_IOCHUNK && ireq->type != PCS_IREQ_FLUSH);
	BUG_ON(pcs_if_error(&ireq->error));

	direction = (ireq->type != PCS_IREQ_FLUSH ? pcs_req_direction(ireq->iochunk.cmd) : 1);

	do {
		struct pcs_cs_list *csl = NULL;

		spin_lock(&m->lock);
		if (ireq->type == PCS_IREQ_IOCHUNK && !(ireq->flags & IREQ_F_MAPPED))
			ireq->iochunk.hbuf.map_version = m->version;

		if (!(m->state & (1 << direction))) {
			spin_unlock(&m->lock);
			pcs_map_queue_resolve(m, ireq, direction);
			return;
		}
		csl = m->cs_list;
		if (csl)
			cslist_get(csl);
		spin_unlock(&m->lock);

		if (ireq->type != PCS_IREQ_FLUSH && !(ireq->flags & IREQ_F_MAPPED)) {
			u64 pos = ireq->iochunk.chunk + ireq->iochunk.offset;
			u64 len = map_chunk_end(m) - pos;

			/*
			 * For non variable chunks all alligment should be done
			 * inside pcs_cc_process_ireq_ioreq();
			 */
			BUG_ON(pos < map_chunk_start(m));
			BUG_ON(ireq->iochunk.chunk != map_chunk_start(m));
			BUG_ON(ireq->iochunk.offset != pos - ireq->iochunk.chunk);
			if (ireq->iochunk.size > len) {
				if (ireq->iochunk.cmd == PCS_REQ_T_FIEMAP) {
					pcs_api_iorequest_t * ar = ireq->completion_data.parent->apireq.req;
					ireq->iochunk.size = len;
					ar->size = ireq->iochunk.size;
				} else {
					struct pcs_int_request * sreq;

					sreq = pcs_ireq_split(ireq, len, 0);
					if (ireq->iochunk.map) {
						pcs_map_put(ireq->iochunk.map);
						ireq->iochunk.map = NULL;
					}
					ireq->iochunk.chunk = map_chunk_end(m);
					ireq->iochunk.offset = 0;
					pcs_cc_submit(ireq->dentry->cluster, ireq);
					ireq = sreq;
				}
			}
		}

		if (!csl) {
			if (ireq->type != PCS_IREQ_FLUSH)
				ireq_handle_hole(ireq);
			else
				ireq_complete(ireq);
			return;
		}

		if (direction && ireq->type != PCS_IREQ_FLUSH)
			ireq->dentry->local_mtime = get_real_time_ms();

		done = !pcs_cslist_submit(ireq, csl);
		cslist_put(csl);
	} while (!done);
}

static int valid_for_truncate(struct pcs_map_entry * m, struct pcs_int_request *ireq)
{
	/* This weird test means that map is valid, but points to a hole. In this case
	 * truncate is noop.
	 */
	if ((m->state & (PCS_MAP_ERROR|PCS_MAP_RESOLVING|PCS_MAP_NEW|PCS_MAP_READABLE)) ==
	    (PCS_MAP_NEW|PCS_MAP_READABLE))
		return 1;

	/* If we already have valid map, remember its version
	 * and switch to the next phase: invalidation and requesting
	 * new map.
	 */
	if (!(m->state & (PCS_MAP_ERROR|PCS_MAP_RESOLVING|PCS_MAP_NEW))) {
		map_remote_error_nolock(m, PCS_ERR_CSD_STALE_MAP, m->cs_list ? m->cs_list->cs[0].info.id.val : 0);
		ireq->truncreq.version = m->version;
	}
	/* Otherwise lookup valid map first. */
	return 0;
}


//// TODO: truncate should probably synhroniously truncate local mapping.
void process_ireq_truncate(struct pcs_int_request *ireq)
{
	struct pcs_dentry_info *di = ireq->dentry;
	struct pcs_map_entry * m;
	u64 end;

	/* Special case: full truncate */
	if (ireq->truncreq.offset == 0) {
		map_truncate_tail(&di->mapping, 0);
		ireq_complete(ireq);
		return;
	}

	m = pcs_find_get_map(di, ireq->truncreq.offset - 1);

	FUSE_KTRACE(ireq->cc->fc, "process TRUNCATE %llu@" DENTRY_FMT " %x",
	      (unsigned long long)ireq->truncreq.offset, DENTRY_ARGS(di), m ? m->state : -1);

	if (m == NULL) {
		map_queue_on_limit(ireq);
		return;
	}
	end = map_chunk_end(m);
	if (end <= ireq->truncreq.offset) {
		map_truncate_tail(&di->mapping, end);
		ireq_complete(ireq);
		return;
	}

	if (ireq->truncreq.phase == 0) {
		if (valid_for_truncate(m, ireq)) {
			map_truncate_tail(&di->mapping, end);
			ireq_complete(ireq);
			return;
		}
	} else {
		/* We already had some valid map. Must get new one. */


		spin_lock(&m->lock);
		if ((m->state & (PCS_MAP_ERROR|PCS_MAP_RESOLVING|PCS_MAP_NEW|PCS_MAP_READABLE)) ==
		    (PCS_MAP_NEW|PCS_MAP_READABLE)) {

			spin_unlock(&m->lock);
			FUSE_KLOG(cc_from_maps(m->maps)->fc, LOG_INFO, "map " MAP_FMT " unexpectedly converted to hole", MAP_ARGS(m));
			map_truncate_tail(&di->mapping, end);
			ireq_complete(ireq);
			return;
		}

		if (m->state & PCS_MAP_RESOLVING) {
			list_add_tail(&ireq->list, &m->queue);
			spin_unlock(&m->lock);
			return;
		}

		if (!(m->state & (PCS_MAP_ERROR|PCS_MAP_NEW))) {
			if (map_version_compare(&m->version, &ireq->truncreq.version) > 0) {
				spin_unlock(&m->lock);
				map_truncate_tail(&di->mapping, end);
				ireq_complete(ireq);
				return;
			}

			FUSE_KTRACE(ireq->cc->fc, "map " MAP_FMT " is not updated yet", MAP_ARGS(m));
			map_remote_error_nolock(m, PCS_ERR_CSD_STALE_MAP, m->cs_list ? m->cs_list->cs[0].info.id.val : 0);

		}
		spin_unlock(&m->lock);
	}
	pcs_map_queue_resolve(m, ireq, 1);
}


noinline void pcs_mapping_truncate(struct pcs_int_request *ireq, u64 old_size)
{
	struct pcs_dentry_info *di = ireq->dentry;
	u64 new_size = DENTRY_SIZE(di);
	u64 offset;
	struct pcs_map_entry * m = NULL;
	int queue = 0;

	di->local_mtime = get_real_time_ms();

	if (new_size < old_size)
		pcs_flow_truncate(&di->mapping.ftab, new_size, &di->cluster->maps.ftab);

	if (old_size < new_size)
		offset = old_size;
	else
		offset = new_size;

	ireq->truncreq.offset = offset;
	ireq->truncreq.phase = 0;

	if (offset == 0) {
		map_truncate_tail(&di->mapping, offset);
		ireq_complete(ireq);
		return;
	}

	map_truncate_tail(&di->mapping, offset + 1);

	m = pcs_find_get_map(di, offset - 1);

	if (m) {
		FUSE_KTRACE(ireq->cc->fc, "mapping truncate %llu->%llu " DENTRY_FMT " %x", (unsigned long long)old_size,
		      (unsigned long long)new_size, DENTRY_ARGS(ireq->dentry), m ? m->state : -1);
	}
	if (m && map_chunk_end(m) == offset) {
		map_truncate_tail(&di->mapping, offset);
		ireq_complete(ireq);
		return;
	}


	if (m == NULL)
		queue = 1;

	spin_lock(&m->lock);
	if (valid_for_truncate(m, ireq))
		queue = 1;
	spin_unlock(&m->lock);

	if (queue) {
		if (m) {
			pcs_map_queue_resolve(m, ireq, 1);
		} else {
			map_queue_on_limit(ireq);
		}
	} else {
		map_truncate_tail(&di->mapping, map_chunk_end(m));
		ireq_complete(ireq);
	}

	if (m)
		pcs_map_put(m);
}

static int commit_cs_record(struct pcs_map_entry * m, struct pcs_cs_record * rec,
			     struct pcs_cs_sync_data * sync, u32 lat, int op_type)
{
	int dirtify;
	struct cs_sync_state * srec = &rec->sync;
	if (sync->ts_net > sync->ts_io)
		lat -= sync->ts_net;
	else
		lat -= sync->ts_io;

	pcs_cs_update_stat(rec->cslink.cs, sync->ts_io, ((int)lat < 0) ? 0 : lat, op_type);
	cs_update_io_latency(rec->cslink.cs, sync->ts_io);

	/* First: verify integrity sequence. */
	if (rec->info.integrity_seq != sync->integrity_seq) {
		/* Now this is possible only if IO was issued and completed
		 * before CS rebooted, but we see the result after.
		 *
		 * The request is restarted with new map.
		 */
		FUSE_KTRACE(cc_from_maps(m->maps)->fc, MAP_FMT " integrity seq mismatch CS" NODE_FMT " %d != %d, %d",
			MAP_ARGS(m),
			NODE_ARGS(rec->info.id),
			rec->info.integrity_seq, sync->integrity_seq, srec->dirty_integrity);
		return 1;
	}

	BUG_ON(srec->dirty_integrity && srec->dirty_integrity != sync->integrity_seq);

	dirtify = (op_type == PCS_CS_WRITE_SYNC_RESP || op_type == PCS_CS_WRITE_RESP ||
		   op_type == PCS_CS_WRITE_HOLE_RESP || op_type == PCS_CS_WRITE_ZERO_RESP);
	/* The following looks scary, could be more clear.
	 * The goal is to update sync seq numbers:
	 *
	 * READ/SYNC (!dirtifying):
	 * - sync_epoch/sync_seq advance sync_epoch/seq
	 * WRITE/WRITE_SYNC (dirtifying):
	 * - sync_epoch/sync_seq advance sync_epoch/seq
	 * - sync_epoch/sync_dirty advance dirty_epoch/seq
	 */
	if (dirtify && sync->sync_dirty) {
		srec->dirty_integrity = sync->integrity_seq;

		if (srec->dirty_epoch == 0 ||
		    pcs_sync_seq_compare(sync->sync_epoch, srec->dirty_epoch) > 0) {
			srec->dirty_epoch = sync->sync_epoch;
			srec->dirty_seq = sync->sync_dirty;
		} else if (sync->sync_epoch == srec->dirty_epoch &&
			   pcs_sync_seq_compare(sync->sync_dirty, srec->dirty_seq) > 0) {
			srec->dirty_seq = sync->sync_dirty;
		}
	}

	if (srec->sync_epoch == 0 ||
	    pcs_sync_seq_compare(sync->sync_epoch, srec->sync_epoch) > 0) {
		srec->sync_epoch = sync->sync_epoch;
		srec->sync_seq = sync->sync_current;
	} else if (sync->sync_epoch == srec->sync_epoch &&
		   pcs_sync_seq_compare(sync->sync_current, srec->sync_seq) > 0) {
		srec->sync_seq = sync->sync_current;
	}
	return 0;
}

static int commit_one_record(struct pcs_map_entry * m, PCS_NODE_ID_T cs_id,
			     struct pcs_cs_sync_data * sync, u32 lat, int op_type)
{
	int err = 0;
	int i;

	BUG_ON(sync->integrity_seq == 0);

	if (m->cs_list == NULL)
		return 0;

	FUSE_KDTRACE(cc_from_maps(m->maps)->fc, "sync ["NODE_FMT",%u,%u,%u,%u]", NODE_ARGS(cs_id),
	      sync->integrity_seq, sync->sync_epoch, sync->sync_dirty, sync->sync_current);

	for (i = 0; i < m->cs_list->nsrv; i++) {
		if (m->cs_list->cs[i].info.id.val == cs_id.val) {
			err = commit_cs_record(m, &m->cs_list->cs[i], sync, lat, op_type);

			FUSE_KDTRACE(cc_from_maps(m->maps)->fc, "commited ["NODE_FMT",%u/%u,%u/%u,%u/%u]", NODE_ARGS(cs_id),
			      m->cs_list->cs[i].info.integrity_seq,
			      m->cs_list->cs[i].sync.dirty_integrity,
			      m->cs_list->cs[i].sync.dirty_epoch,
			      m->cs_list->cs[i].sync.dirty_seq,
			      m->cs_list->cs[i].sync.sync_epoch,
			      m->cs_list->cs[i].sync.sync_seq);
			break;
		}
	}
	return err;
}

static void update_net_latency(struct pcs_cs_list * csl, PCS_NODE_ID_T id,
			       struct pcs_cs_sync_data * sync, unsigned int lat)
{
	int i;

	if (sync->ts_net > sync->ts_io)
		lat -= sync->ts_net;
	else
		lat -= sync->ts_io;

	if ((int)lat <= 0)
		return;

	for (i = 0; i < csl->nsrv; i++) {
		if (id.val == csl->cs[i].info.id.val) {
			struct pcs_cs * cs = csl->cs[i].cslink.cs;

			if (i != 0 || !(test_bit(CS_SF_LOCAL, &cs->state)))
				cs_update_net_latency(csl->cs[i].cslink.cs, lat);
			break;
		}
	}
}

static inline u32 calc_latency(ktime_t start)
{
	ktime_t now = ktime_get();

	if (ktime_compare(now, start) > 0) {
		u64 elapsed = ktime_to_ms(ktime_sub(now, start));
		return elapsed > ~0U ? ~0U : elapsed;
	} else {
		return 0;
	}
}

static int commit_sync_info(struct pcs_int_request *req,
			struct pcs_map_entry * m, struct pcs_cs_list * csl,
			struct pcs_msg * resp)
{
	struct pcs_cs_iohdr *h = (struct pcs_cs_iohdr *)resp->_inline_buffer;
	int err = 0;
	unsigned int max_iolat, lat = calc_latency(req->ts_sent);

	err |= commit_one_record(m, resp->rpc->peer_id, &h->sync, lat, h->hdr.type);

	/* Network latency is updated only for the first CS in chain.
	 * The results for anothers are ignored, which looks sad, because we lose
	 * alot of information. The thing is that measured latency
	 * is actually sum of network latencies in both directions, so that if we
	 * average all the results we get not CS latency but CS latency + average_over_cluster,
	 * which is even undefined when we use EWMA averaging (it would be defined
	 * if we calculated EWMA latency for each link, otherwise it is EWMA of a random number)
	 * If we fix one node (client in this case), we calculate average sum of client
	 * plus CS, which is enough to use this value to select the least loaded CS for read.
	 */
	update_net_latency(csl, resp->rpc->peer_id, &h->sync, lat);
	max_iolat = h->sync.ts_io;

	if (h->hdr.type != PCS_CS_READ_RESP && h->hdr.type != PCS_CS_FIEMAP_RESP) {
		struct pcs_cs_sync_resp * srec;
		lat = h->sync.ts_net;
		for (srec = (struct pcs_cs_sync_resp*)(h + 1);
		     (void*)(srec + 1) <= (void*)h + h->hdr.len;
		     srec++) {
			err |= commit_one_record(m, srec->cs_id, &srec->sync, lat, h->hdr.type);
			lat  = srec->sync.ts_net;
			if (max_iolat < srec->sync.ts_io)
				max_iolat = srec->sync.ts_io;
		}
	}
	cs_log_io_times(req, resp, max_iolat);

	evaluate_dirty_status(m);
	return err;
}

void pcs_map_verify_sync_state(struct pcs_dentry_info *di, struct pcs_int_request *ireq, struct pcs_msg * msg)
{
	struct pcs_map_entry * m = ireq->iochunk.map;
	struct pcs_msg * resp = msg->response;

	if (!m)
		return;

	spin_lock (&m->lock);
	if (m->cs_list == NULL || (m->state & PCS_MAP_DEAD)) {
		spin_unlock(&m->lock);
		return;
	}
	if (commit_sync_info(ireq, m, ireq->iochunk.csl, resp)) {
		FUSE_KTRACE(cc_from_maps(m->maps)->fc, MAP_FMT " sync integrity error: map retry follows", MAP_ARGS(m));

		msg->error.value = PCS_ERR_CSD_STALE_MAP;
		msg->error.remote = 1;
		msg->error.offender = m->cs_list->cs[0].info.id;
	}
	spin_unlock(&m->lock);

	if (ireq->iochunk.flow) {
		struct pcs_int_request * preq = ireq->completion_data.parent;

		pcs_flow_confirm(ireq->iochunk.flow, &ireq->dentry->mapping.ftab,
				 preq->apireq.req->type == PCS_REQ_T_WRITE,
				 preq->apireq.req->pos, preq->apireq.req->size,
				 &ireq->cc->maps.ftab);
	}

}

void sync_done(struct pcs_msg * msg)
{
	struct pcs_int_request * sreq = msg->private;
	struct pcs_map_entry * m = sreq->flushreq.map;
	struct pcs_msg * resp = msg->response;

	spin_lock(&m->lock);
	if (m->state & PCS_MAP_DEAD)
		goto done;
	if (!(m->flags & PCS_MAP_DIRTY))
		goto done;

	if (pcs_if_error(&msg->error)) {
		pcs_copy_error(&sreq->error, &msg->error);
		goto done;
	}

	if (commit_sync_info(sreq, m, sreq->flushreq.csl, resp)) {
		FUSE_KTRACE(cc_from_maps(m->maps)->fc, MAP_FMT " sync integrity error: sync retry follows", MAP_ARGS(m));

		sreq->error.remote = 1;
		sreq->error.value = PCS_ERR_CSD_STALE_MAP;
		sreq->error.offender = m->cs_list->cs[0].info.id;
	}

done:
	spin_unlock(&m->lock);
	ireq_complete(sreq);
	return;
}

static int sync_is_finished(struct pcs_msg * msg, struct pcs_map_entry * m)
{
	struct pcs_cs_iohdr * h = (struct pcs_cs_iohdr *)msg->_inline_buffer;
	struct pcs_cs_sync_resp * srec;

	if (m->cs_list == NULL)
		return 1;

	for (srec = (struct pcs_cs_sync_resp *)(h + 1);
	     (void*)(srec + 1) <= (void*)h + h->hdr.len;
	     srec++) {
		int i;

		FUSE_KDTRACE(cc_from_maps(m->maps)->fc, "Checking cs="NODE_FMT" sync=[%d,%d,%d,%d]", NODE_ARGS(srec->cs_id), srec->sync.integrity_seq,
		      srec->sync.sync_epoch,
		      srec->sync.sync_dirty, srec->sync.sync_current);

		for (i = 0; i < m->cs_list->nsrv; i++) {
			if (m->cs_list->cs[i].info.id.val == srec->cs_id.val) {
				FUSE_KDTRACE(cc_from_maps(m->maps)->fc, "Checking against sync=[%d,%d,%d,%d,%d]",
				      m->cs_list->cs[i].sync.dirty_integrity,
				      m->cs_list->cs[i].sync.dirty_epoch,
				      m->cs_list->cs[i].sync.dirty_seq,
				      m->cs_list->cs[i].sync.sync_epoch,
				      m->cs_list->cs[i].sync.sync_seq);
				if (cs_is_dirty(&m->cs_list->cs[i].sync) &&
				    srec->sync.sync_epoch == m->cs_list->cs[i].sync.sync_epoch &&
				    pcs_sync_seq_compare(srec->sync.sync_current, m->cs_list->cs[i].sync.sync_seq) >= 0)
					return 0;
				break;
			}
		}
	}
	return 1;
}

void process_flush_req(struct pcs_int_request *ireq)
{
	struct pcs_map_entry * m = ireq->flushreq.map;

	spin_lock(&m->lock);
	if (m->state & PCS_MAP_DEAD)
		goto done;

	FUSE_KTRACE(ireq->cc->fc, "process FLUSH " MAP_FMT, MAP_ARGS(m));

	if (!(m->flags & PCS_MAP_DIRTY))
		goto done;
	if (sync_is_finished(ireq->flushreq.msg, m)) {
		FUSE_KTRACE(ireq->cc->fc, "finished");
		goto done;
	}
	spin_unlock(&m->lock);
	map_submit(m, ireq);
	return;

done:
	spin_unlock(&m->lock);
	if (pcs_if_error(&ireq->error)) {
		FUSE_KTRACE(ireq->cc->fc, "oops, delete me %d", ireq->error.value);
		pcs_clear_error(&ireq->error);
	}
	ireq_complete(ireq);
}

static void pcs_flushreq_complete(struct pcs_int_request * sreq)
{
	struct pcs_int_request *ireq = sreq->completion_data.parent;
	struct pcs_map_entry * m = sreq->flushreq.map;
	struct pcs_cs_iohdr * ioh = (struct pcs_cs_iohdr*)msg_inline_head(sreq->flushreq.msg);
	int notify_error = 0;

	spin_lock(&m->lock);
	if (!ireq)
		m->flags &= ~PCS_MAP_FLUSHING;
	m->flags &= ~PCS_MAP_DIRTY_GC;

	if (m->state & PCS_MAP_DEAD)
		goto done;
	if (!(m->flags & PCS_MAP_DIRTY))
		goto done;

	if (!pcs_if_error(&sreq->error)) {
		if (sync_is_finished(sreq->flushreq.msg, m)) {
			FUSE_KTRACE(sreq->cc->fc, "finished");
			goto done_dirty;
		}
		sreq->error.value = PCS_ERR_CSD_STALE_MAP;
		sreq->error.remote = 1;
		sreq->error.offender = m->cs_list->cs[0].info.id;
	}

	if (ireq && !pcs_if_error(&ireq->error)) {
		if (ireq_check_redo(sreq)) {
			FUSE_KTRACE(sreq->cc->fc, "restart after flush error %d", sreq->error.value);
			if (map_version_compare(&ioh->map_version, &m->version) < 0)
				sreq->flags &= ~IREQ_F_ONCE;
			spin_unlock(&m->lock);

			map_notify_error(m, sreq, &ioh->map_version, sreq->flushreq.csl);
			pcs_deaccount_ireq(sreq, &sreq->error);
			pcs_clear_error(&sreq->error);

			if (!(sreq->flags & IREQ_F_ONCE)) {
				sreq->flags |= IREQ_F_ONCE;
				pcs_cc_submit(sreq->cc, sreq);
			} else
				ireq_delay(sreq);
			return;
		}
		FUSE_KTRACE(sreq->cc->fc, "flush error %d", sreq->error.value);
		pcs_copy_error(&ireq->error, &sreq->error);
		notify_error = 1;
	}

done_dirty:
	if (!ireq)
		map_sync_work_add(m, pcs_sync_timeout(cc_from_map(m)));
done:
	spin_unlock(&m->lock);
	if (notify_error)
		map_notify_error(m, sreq, &ioh->map_version, sreq->flushreq.csl);

	pcs_deaccount_ireq(sreq, &sreq->error);

	if (ireq) {
		if (!pcs_sreq_detach(sreq))
			ireq_complete(ireq);
	}

	pcs_free_msg(sreq->flushreq.msg);
	pcs_map_put(m);
	ireq_destroy(sreq);
}

/* Allocate and format sync message. Important: this message hold values of sync counters
 * as they are now. If sync request fails and retried, this message is not reallocated
 * and sync counters remain the same.
 */
static void prepare_map_flush_msg(struct pcs_map_entry * m, struct pcs_int_request * sreq, struct pcs_msg * msg)
{
	struct pcs_cs_iohdr * ioh;
	struct pcs_cs_sync_resp * arr;

	assert_spin_locked(&m->lock);

	ioh = (struct pcs_cs_iohdr *)msg->_inline_buffer;
	arr = (struct pcs_cs_sync_resp *)(ioh + 1);

	ioh->hdr.len = sizeof(struct pcs_cs_iohdr);
	ioh->hdr.type = PCS_CS_SYNC_REQ;
	memset(&ioh->sync, 0, sizeof(ioh->sync));
	ioh->offset = 0;
	ioh->size = 0;
	ioh->_reserved = 0;
	ioh->sync.misc = PCS_CS_IO_SEQ;

	ioh->map_version = m->version;
	ioh->uid = m->id;
	ioh->iocontext = (u32)pcs_dentry_from_map(m)->fileinfo.attr.id;

	if (m->cs_list) {
		int i;

		for (i = 0; i < m->cs_list->nsrv; i++) {
			struct pcs_cs_record * rec = m->cs_list->cs + i;
			if (cs_is_dirty(&rec->sync)) {
				arr->cs_id = rec->info.id;
				arr->sync.integrity_seq = rec->sync.dirty_integrity;
				arr->sync.sync_epoch = rec->sync.dirty_epoch;
				arr->sync.sync_dirty = rec->sync.dirty_seq;
				arr->sync.sync_current = rec->sync.dirty_seq;
				arr->sync.misc = 0;
				arr->sync.ts_io = 0;
				arr->sync.ts_net = 0;
				arr->sync._reserved = 0;
				ioh->hdr.len += sizeof(struct pcs_cs_sync_resp);
				FUSE_KLOG(cc_from_maps(m->maps)->fc, LOG_DEBUG5, "fill sync "NODE_FMT" [%d,%d,%d,%d]", NODE_ARGS(arr->cs_id),
					arr->sync.integrity_seq, arr->sync.sync_epoch,
					arr->sync.sync_dirty, arr->sync.sync_current);
				arr++;
			}
		}
	}
	msg->size = ioh->hdr.len;
	msg->private = sreq;
	msg->done = sync_done;
}

static bool valid_for_flush(struct pcs_map_entry *m)
{
	if (m->state & PCS_MAP_DEAD)
		return false;

	if (!(m->flags & PCS_MAP_DIRTY))
		return false;
	if (m->flags & PCS_MAP_FLUSHING)
		return false;

	return true;
}

static int prepare_map_flush_ireq(struct pcs_map_entry *m, struct pcs_int_request **sreqp)
{
	struct pcs_dentry_info *de;
	struct pcs_cs_list *cslist;
	struct pcs_int_request *sreq;
	struct pcs_msg * msg;

	spin_lock(&m->lock);
	if (!valid_for_flush(m)) {
		spin_unlock(&m->lock);
		return 0;
	}

	if (!m->cs_list || !m->cs_list->nsrv) {
		/* TODO: userspace allow (cslist->nsrv==0), but IMHO it does not make sense */
		WARN_ON_ONCE(1);
		spin_unlock(&m->lock);
		return 0;
	}

	cslist = m->cs_list;
	cslist_get(cslist);
	/* TODO: Need to grab reference to de? */
	de = pcs_dentry_from_map(m);
	spin_unlock(&m->lock);

	sreq = ireq_alloc(de);
	if (!sreq)
		goto err_cslist;

	msg = pcs_rpc_alloc_output_msg(sizeof(struct pcs_cs_iohdr) +
				       cslist->nsrv * sizeof(struct pcs_cs_sync_resp));
	if (!msg)
		goto err_ireq;

	/* All resources allocated, we need to recheck maps state again */
	spin_lock(&m->lock);
	cslist_put(cslist);
	if (!valid_for_flush(m) || m->cs_list != cslist) {
		spin_unlock(&m->lock);
		return 0;
	}
	prepare_map_flush_msg(m, sreq, msg);
	sreq->type = PCS_IREQ_FLUSH;
	INIT_LIST_HEAD(&sreq->tok_list);
	sreq->tok_reserved = 0;
	sreq->ts = ktime_get();
	sreq->completion_data.parent = NULL;
	sreq->flushreq.map = m;
	sreq->flushreq.csl = NULL;
	sreq->complete_cb = pcs_flushreq_complete;
	sreq->flushreq.msg = msg;
	FUSE_KTRACE(sreq->cc->fc, "timed FLUSH " MAP_FMT, MAP_ARGS(m));
	m->flags |= PCS_MAP_FLUSHING;
	__pcs_map_get(m);
	spin_unlock(&m->lock);
	*sreqp	= sreq;
	return 0;

err_ireq:
	ireq_destroy(sreq);
err_cslist:
	cslist_put(cslist);
	return -ENOMEM;
}

/* Timer injects a sync request for dirty chunk, when sync timeout expires.
 * If the request fails, we just retry later.
 */
static void sync_timer_work(struct work_struct *w)
{
	struct pcs_map_entry *m = container_of(w, struct pcs_map_entry, sync_work.work);
	struct pcs_int_request * sreq = NULL;
	int err;

	err = prepare_map_flush_ireq(m, &sreq);
	if (err) {
		spin_lock(&m->lock);
		if (!(m->state & PCS_MAP_DEAD))
			map_sync_work_add(m, HZ);
		spin_unlock(&m->lock);
	} else {
		if (sreq)
			map_submit(m, sreq);
	}
	/* Counter part from map_sync_work_add */
	pcs_map_put(m);
}


/* Handle for api PCS_REQ_T_SYNC IO request. It scans through current map
 * and constructs internal subrequests for each chunk, which is dirty at the moment.
 * Current sync seq number are stored in subrequest right now, so that future
 * dirtifying writes will not delay execution of this request.
 *
 * XXX we can issue a lot of subrequests here: one per each dirty chunk.
 */
void map_inject_flush_req(struct pcs_int_request *ireq)
{
	struct pcs_dentry_info *di = ireq->dentry;
	struct list_head ireq_list;
	unsigned long idx, end_idx;
	u64 end;
	struct pcs_map_entry *maps[MAP_BATCH];
	int nr_maps;

	if (di->fileinfo.sys.map_type != PCS_MAP_PLAIN ||
	    di->fileinfo.sys.stripe_depth != 1) {
		FUSE_KLOG(ireq->cc->fc, LOG_ERR, "bad map_type");
		pcs_set_local_error(&ireq->error, PCS_ERR_PROTOCOL);
		ireq_complete(ireq);
		return;
	}

	atomic_set(&ireq->iocount, 1);
	INIT_LIST_HEAD(&ireq_list);

	idx = ireq->apireq.req->pos >> DENTRY_CHUNK_SIZE_BITS(di);
	end = (ireq->apireq.req->pos + ireq->apireq.req->size) >> DENTRY_CHUNK_SIZE_BITS(di);
	if (end <= ireq->apireq.req->pos)
		end = ~0ULL;
	end_idx = end >> DENTRY_CHUNK_SIZE_BITS(di);

	do {
		int i;

		rcu_read_lock();
		/* TODO !!!! use radix tree tags for DIRTY flags */
		nr_maps = radix_tree_gang_lookup(&di->mapping.map_tree,
				(void **)maps, idx, MAP_BATCH);

		for (i = 0; i < nr_maps; i++) {
			struct pcs_map_entry *m = maps[i];

			idx = maps[i]->index;
			if (idx > end_idx)
				break;

			spin_lock(&m->lock);
			if (!(m->flags & PCS_MAP_DIRTY) || !pcs_map_get_locked(m))
					maps[i] = NULL;
			spin_unlock(&m->lock);

		}
		rcu_read_unlock();
		for (i = 0; i < nr_maps; i++) {
			struct pcs_int_request * sreq = NULL;
			int err = 0;

			if (idx > end_idx)
				break;
			if (!maps[i])
				continue;
			err = prepare_map_flush_ireq(maps[i], &sreq);
			pcs_map_put(maps[i]);
			if (err) {
				pcs_set_local_error(&ireq->error, PCS_ERR_NOMEM);
				break;
			}
			/* Request not prepared, so sync is not required */
			if (!sreq)
				continue;
			pcs_sreq_attach(sreq, ireq);
			list_add_tail(&sreq->list, &ireq_list);
		}
		idx++;
	} while (nr_maps && idx < end_idx + 1);

	pcs_cc_requeue(ireq->dentry->cluster, &ireq_list);

	if (atomic_dec_and_test(&ireq->iocount))
		ireq_complete(ireq);
}
