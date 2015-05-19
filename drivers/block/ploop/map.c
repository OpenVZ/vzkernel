/*
 * Generic engine for mapping virtual blocks (cluster_t) to indices
 * in image (iblock_t).
 *
 * Mapping is global, it is defined not for some particular delta,
 * but for the whole disk. Therefore it is abstract and does not depend
 * on particular virtual disk format. Of course, for some disk types
 * it can be not so easy to fetch/update backing store. Actually,
 * this engine is tightly bound to organization of index tables in ploop1.
 *
 * Technically, it is just array of pages with some metainformation
 * attached to each page. The array may be highly sparse, so that it is
 * in rbtree keyed by array index cluster_no / (PAGE_SIZE / sizeof(map_index)).
 *
 * Sadly, it is completely similar to linux page cache for a virtual
 * mapping. "Sadly" is because linux page cache provides only a crippled
 * implementation of asynchronous read/writeback, which requires synchronous
 * waits for completions and does not making any callbacks on completion.
 * So that, we have to redo all the work here.
 *
 * Two words about synchronization. All the updates to map are
 * made from single thread. Lookups can happen in an unserialized context,
 * therefore we protect all critical updates with spinlock. RCU can be used too.
 *
 * Mapping is UPTODATE, when it is in sync with top delta.
 * When a mapping is accessed the first time and there is no mapping in top
 * delta, we search for lower level delta. We could create empty mapping
 * and this would have advantage: when the whole blocks are rewritten
 * we do not even need lower deltas (_XXX_).
 */

#include <linux/module.h>
#include <linux/version.h>

#include <linux/ploop/ploop.h>

/* This defines slot in mapping page. Right now it is 32 bit
 * and therefore it directly matches ploop1 structure. */
typedef u32 map_index_t;

#define INDEX_PER_PAGE	(PAGE_SIZE / sizeof(map_index_t))

static struct kmem_cache * ploop_map_cache;

static LIST_HEAD(map_lru);
static DEFINE_SPINLOCK(map_lru_lock);
static atomic_t map_pages_nr = ATOMIC_INIT(0);

/*
 * Additional information for each page is:
 * 1. rb tree link
 * 2. Page
 * 3. mn_start, mn_end - the first and the last index
 * (correspondingly) the page maps to iblocks.
 * 4. lru linkage
 * 5. delta level of whole page, it is delta, where this page
 *    is backed.
 * 6. Array of delta levels for each map_index in the page.
 *    If page is backed at level N, those levels cannot be >N.
 *    If all the levels == N, array of levels is not allocated.
 *    When at least one level < N, it is stored in the array.
 *    Note, that in this case exporting page to disk implies
 *    clearing irrelevant entries.
 */

struct map_node
{
	struct rb_node		rb_link;
	cluster_t		mn_start;
	cluster_t		mn_end;
	unsigned long		state;
	atomic_t		refcnt;
	struct ploop_map	*parent;

	struct page		*page;
	struct list_head	lru;
	u8			*levels;

	/* List of preq's blocking on this mapping.
	 *
	 * We queue here several kinds of requests:
	 * 1. If mapping is not uptodate, all the requests which need
	 *    this mapping are queued here. preq state is ENTRY.
	 * 2. If preq requires index update and it is delayed
	 *    because writeback is in progress. preq state is INDEX_DELAY,
	 *    new index is kept in preq->iblock.
	 * 3. If preq's started index update, preq state is INDEX_WB,
	 *    new indices are sent to io, but they are not inserted
	 *    into mapping until writeback is complete.
	 */
	struct list_head	io_queue;
};

cluster_t map_get_mn_end(struct map_node *m)
{
	return m->mn_end;
}

#define MAP_LEVEL(m)		((m)->state & 0xFF)
#define MAP_SET_LEVEL(m, l)	((m)->state = ((m)->state & ~0xFF) | (l))

#define MAP_UPTODATE(m)		(((m)->state >> 8) & 0xFFUL)
#define MAP_SET_UPTODATE(m, l)	((m)->state = ((m)->state & ~0xFF00UL) | ((l)<<8))

enum {
	PLOOP_MAP_UPTODATE	= 16,	/* Mapping is in sync with top_delta,
					 * we can write index. But zero entries
					 * still require read lower delta indices.
					 */
	PLOOP_MAP_READ		= 17,	/* Mapping read is scheduled */
	PLOOP_MAP_WRITEBACK	= 18,	/* Mapping is under writeback */
	PLOOP_MAP_ERROR		= 19,	/* Mapping is baaad */
};

void map_init(struct ploop_device * plo, struct ploop_map * map)
{
	INIT_LIST_HEAD(&map->delta_list);
	map->flags = 0;
	map->last_activity = jiffies;
	map->plo = plo;
	map->rb_root = RB_ROOT;
	map->lru_buffer_ptr = 0;
	init_waitqueue_head(&map->destroy_waitq);
}

/* Deliver batch of LRU updates from buffer to global LRU.
 * Everything, which has zero refcnt, is added to LRU or moved to tail
 * of LRU. Everything, which has non-zero refcnt, is removed from LRU.
 */
static void flush_lru_buffer(struct ploop_map * map)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave(&map_lru_lock, flags);
	for (i = 0; i < map->lru_buffer_ptr; i++) {
		struct map_node * m = map->lru_buffer[i];
		if (atomic_dec_and_test(&m->refcnt))
			list_move_tail(&m->lru, &map_lru);
		else
			list_del_init(&m->lru);
	}
	spin_unlock_irqrestore(&map_lru_lock, flags);

	map->lru_buffer_ptr = 0;
}

/*
 * map_release() must be called under plo-lock, because
 * The pair atomic_read & atomic_dec_and_test is not atomic.
 */
void map_release(struct map_node * m)
{
	struct ploop_map * map = m->parent;

	if (atomic_read(&m->refcnt) == 1) {
		if (!list_empty(&m->lru))
			return;
		if (map->lru_buffer_ptr == PLOOP_LRU_BUFFER)
			flush_lru_buffer(map);
		map->lru_buffer[map->lru_buffer_ptr++] = m;
		return;
	}
	if (atomic_dec_and_test(&m->refcnt))
		BUG();
}

static inline void cond_flush_lru_buffer(struct ploop_map * map)
{
	if (map->lru_buffer_ptr == PLOOP_LRU_BUFFER)
		flush_lru_buffer(map);
}


static struct map_node * map_lookup(struct ploop_map * map, cluster_t block)
{
	struct rb_node * n = map->rb_root.rb_node;
	struct map_node * m;

	while (n) {
		m = rb_entry(n, struct map_node, rb_link);

		if (block < m->mn_start)
			n = n->rb_left;
		else if (block > m->mn_end)
			n = n->rb_right;
		else
			return m;
	}
	return NULL;
}

/* Lookup mapping atomically. */

int ploop_fastmap(struct ploop_map * map, cluster_t block, iblock_t *result)
{
	struct map_node * m;
	u32 idx;
	map_index_t blk;

	if (unlikely(block >= map->max_index))
		return -1;

	if (test_bit(PLOOP_MAP_IDENTICAL, &map->flags)) {
		*result = block;
		return 0;
	}

	m = map_lookup(map, block);
	if (m == NULL)
		return -1;

	if (atomic_read(&m->refcnt) == 0) {
		cond_flush_lru_buffer(map);
		if (atomic_read(&m->refcnt) == 0) {
			atomic_inc(&m->refcnt);
			map->lru_buffer[map->lru_buffer_ptr++] = m;
		}
	}
	map->last_activity = jiffies;

	if (!test_bit(PLOOP_MAP_UPTODATE, &m->state))
		return -1;

	idx = (block + PLOOP_MAP_OFFSET) & (INDEX_PER_PAGE - 1); 
	blk = ((map_index_t *)page_address(m->page))[idx] >>
	       ploop_map_log(map->plo);

	if (blk) {
		*result = blk;
		if (m->levels)
			return m->levels[idx];
		else
			return MAP_LEVEL(m);
	}
	return -1;
}

static void map_node_destroy(struct map_node *m)
{
	rb_erase(&m->rb_link, &m->parent->rb_root);
	list_del_init(&m->lru);
	BUG_ON(atomic_read(&m->refcnt));
	BUG_ON(!list_empty(&m->io_queue));
	if (m->page)
		put_page(m->page);
	if (m->levels)
		kfree(m->levels);
	m->parent->pages--;
	atomic_dec(&map_pages_nr);
	kmem_cache_free(ploop_map_cache, m);
}

static void map_lru_scan(void)
{
	int max_loops = atomic_read(&map_pages_nr);

	while (atomic_read(&map_pages_nr) > max_map_pages &&
	       --max_loops >= 0) {
		struct ploop_map * map;
		struct map_node * candidate = NULL;

		spin_lock_irq(&map_lru_lock);
		if (!list_empty(&map_lru)) {
			candidate = list_first_entry(&map_lru, struct map_node, lru);
			atomic_inc(&candidate->refcnt);
		}
		spin_unlock_irq(&map_lru_lock);

		if (!candidate)
			break;

		map = candidate->parent;

		spin_lock_irq(&map->plo->lock);
		spin_lock(&map_lru_lock);

		if (waitqueue_active(&map->destroy_waitq)) {
			atomic_dec(&candidate->refcnt);
			wake_up(&map->destroy_waitq);
			spin_unlock(&map_lru_lock);
			spin_unlock_irq(&map->plo->lock);
			return;
		}

		list_del_init(&candidate->lru);

		if (atomic_dec_and_test(&candidate->refcnt)) {
			/* This instance is within its limits, just
			 * readd node back to tail of lru.
			 */
			if (map->pages <= map->plo->tune.min_map_pages &&
			    time_after(map->last_activity +
				       map->plo->tune.max_map_inactivity, jiffies) &&
			    !test_bit(PLOOP_MAP_DEAD, &map->flags)) {
				list_add_tail(&candidate->lru, &map_lru);
			} else {
				map_node_destroy(candidate);
			}
		}
		spin_unlock(&map_lru_lock);
		spin_unlock_irq(&map->plo->lock);

		if (!(max_loops & 16))
			cond_resched();
	}
}

static struct map_node *
map_create(struct ploop_map * map, cluster_t block)
{
	struct ploop_device * plo = map->plo;
	struct rb_node **p, *parent;
	struct map_node * m;
	cluster_t ondisk_pageno = (block + PLOOP_MAP_OFFSET) / INDEX_PER_PAGE;

	m = kmem_cache_alloc(ploop_map_cache, GFP_NOFS);
	if (unlikely(m == NULL))
		return ERR_PTR(-ENOMEM);

	m->page = alloc_page(GFP_NOFS);
	if (unlikely(m->page == NULL)) {
		kmem_cache_free(ploop_map_cache, m);
		return ERR_PTR(-ENOMEM);
	}

	if (ondisk_pageno == 0) {
		m->mn_start = 0;
		m->mn_end = INDEX_PER_PAGE - PLOOP_MAP_OFFSET - 1;
	} else {
		m->mn_start = ondisk_pageno * INDEX_PER_PAGE - PLOOP_MAP_OFFSET;
		m->mn_end = m->mn_start + INDEX_PER_PAGE - 1;
	}

	INIT_LIST_HEAD(&m->io_queue);
	INIT_LIST_HEAD(&m->lru);
	m->levels = NULL;
	m->state = 0;
	atomic_set(&m->refcnt, 1);
	m->parent = map;

	spin_lock_irq(&plo->lock);

	p = &map->rb_root.rb_node;
	parent = NULL;

	while (*p) {
		struct map_node * entry;
		parent = *p;
		entry = rb_entry(parent, struct map_node, rb_link);

		/* Nodes can be deleted by any of ploop threads,
		 * but they are inserted only in ploop thread.
		 * Before calling map_create() we checked the node
		 * is absent, therefore:
		 */
		BUG_ON(ondisk_pageno ==
		       (entry->mn_start + PLOOP_MAP_OFFSET) / INDEX_PER_PAGE);

		if (block < entry->mn_start)
			p = &(*p)->rb_left;
		else if (block > entry->mn_end)
			p = &(*p)->rb_right;
		else
			printk("map_create: Oops! block=%u; mn_range=[%u..%u]\n",
			       block, entry->mn_start, entry->mn_end);
	}

	rb_link_node(&m->rb_link, parent, p);
	rb_insert_color(&m->rb_link, &map->rb_root);

	map->pages++;
	atomic_inc(&map_pages_nr);
	spin_unlock_irq(&plo->lock);

	if (atomic_read(&map_pages_nr) > max_map_pages)
		map_lru_scan();

	return m;
}

/* helper for trans_map_get_index() and map_get_index() */
static iblock_t
cluster2iblock(struct ploop_request *preq, struct map_node *m, cluster_t block,
	       u32 *idx)
{
	iblock_t iblk;
	char *fmt;

	BUG_ON (block < INDEX_PER_PAGE - PLOOP_MAP_OFFSET && m->mn_start != 0);
	BUG_ON (block >= INDEX_PER_PAGE - PLOOP_MAP_OFFSET && m->mn_start !=
		((block + PLOOP_MAP_OFFSET) &
		 ~(INDEX_PER_PAGE - 1)) - PLOOP_MAP_OFFSET);

	*idx = (block + PLOOP_MAP_OFFSET) & (INDEX_PER_PAGE - 1);
	iblk = ((map_index_t *)page_address(m->page))[*idx];

	if (likely(iblk != PLOOP_ZERO_INDEX))
		iblk >>= ploop_map_log(preq->plo);

	if (m == preq->trans_map)
		fmt = "tmgi %u %d %u [ %u %u ]\n";
	else if (m == preq->map)
		fmt = "mgi %u %d %u [ %u %u ]\n";
	else
		BUG();

	__TRACE(fmt, block, *idx, iblk,
		((map_index_t *)page_address(m->page))[0],
		((map_index_t *)page_address(m->page))[1]);

	return iblk;
}

int trans_map_get_index(struct ploop_request * preq, cluster_t block, iblock_t *result)
{
	struct map_node * m = preq->trans_map;
	u32 idx;
	map_index_t blk;

	if (m == NULL)
		return -1;

	blk = cluster2iblock(preq, m, block, &idx);

	if (blk) {
		*result = blk;
		return 0;
	}
	return -1;
}


int map_get_index(struct ploop_request * preq, cluster_t block, iblock_t *result)
{
	struct map_node * m = preq->map;
	u32 idx;
	map_index_t blk;

	if (m == NULL) {
		*result = block;
		return 0;
	}

	blk = cluster2iblock(preq, m, block, &idx);

	if (blk) {
		*result = blk;
		if (m->levels)
			return m->levels[idx];
		else
			return MAP_LEVEL(m);
	}
	return -1;
}

int map_index_fault(struct ploop_request * preq)
{
	struct ploop_device * plo = preq->plo;
	struct ploop_delta * top_delta, * delta, * ndelta;
	struct map_node * m = preq->map;
	int uptodate_level;
	sector_t pos;
	int err;

	uptodate_level = MAP_UPTODATE(m);

	/* All the levels are read, mapping is absent. */
	if (uptodate_level == 0) {
		__TRACE("MAP E %u\n", preq->req_cluster);
		return -1;
	}

	top_delta = ploop_top_delta(plo);
	delta = NULL;

	list_for_each_entry(ndelta, &plo->map.delta_list, list) {
		int rc;

		if (ndelta->level >= uptodate_level)
			continue;

		rc = ndelta->ops->map_index(ndelta, m->mn_start, &pos);
		if (rc != 0) {
			delta = ndelta;
			break;
		}

		MAP_SET_UPTODATE(m, ndelta->level);
		__TRACE("MAP SKIP %u %d\n", preq->req_cluster, ndelta->level);
	}

	/* Not found anywhere. */
	if (!delta) {
		__TRACE("MAP NF %u\n", preq->req_cluster);
		return -1;
	}

	/* Mapping is present in lower delta, start merge */
	spin_lock_irq(&plo->lock);
	ploop_add_lockout(preq, 0);

	if (test_and_set_bit(PLOOP_MAP_READ, &m->state)) {
		__TRACE("r %p %u %p\n", preq, preq->req_cluster, m);
		list_add_tail(&preq->list, &m->io_queue);
		plo->st.merge_lockouts++;
		spin_unlock_irq(&plo->lock);
		/* Someone already scheduled read. */
		return 0;
	}
	spin_unlock_irq(&plo->lock);

	err = -EIO;
	if (test_bit(PLOOP_MAP_ERROR, &m->state))
		goto err_out;

	err = -ENOMEM;
	preq->sinfo.ri.tpage = alloc_page(GFP_NOFS);
	if (preq->sinfo.ri.tpage == NULL)
		goto err_out;

	preq->sinfo.ri.level = delta->level;
	preq->eng_state = PLOOP_E_INDEX_READ;

	plo->st.map_merges++;
	delta->ops->read_index(delta, preq, preq->sinfo.ri.tpage, pos);
	return 0;

err_out:
	clear_bit(PLOOP_MAP_READ, &m->state);
	ploop_fail_request(preq, err);
	return 0;
}

static void map_read_endio(struct ploop_request * preq, struct map_node * m)
{
	struct ploop_device * plo = preq->plo;
	struct list_head * n, *pn;
	LIST_HEAD(list);

	spin_lock_irq(&plo->lock);

	if (!preq->error) {
		set_bit(PLOOP_MAP_UPTODATE, &m->state);
	} else {
		set_bit(PLOOP_MAP_ERROR, &m->state);
	}
	clear_bit(PLOOP_MAP_READ, &m->state);

	__TRACE(">E %p %u %p\n", preq, preq->req_cluster, m);

	list_for_each_safe(n, pn, &m->io_queue) {
		preq = list_entry(n, struct ploop_request, list);
		if (preq->eng_state == PLOOP_E_ENTRY) {
			list_del(&preq->list);
			list_add_tail(&preq->list, &list);
		}
	}
	if (!list_empty(&list))
		list_splice(&list, &plo->ready_queue);
	spin_unlock_irq(&plo->lock);
}

static void map_merge_endio(struct ploop_request * preq, struct map_node * m)
{
	struct ploop_device * plo = preq->plo;
	struct list_head *n, *pn;
	LIST_HEAD(list);
	int i;
	u32 * map;
	u32 * merged;
	int skip = m->mn_start == 0 ? PLOOP_MAP_OFFSET : 0;

	__TRACE(">M %p %u %p\n", preq, preq->req_cluster, m);

	if (unlikely(preq->error))
		goto abort_update;

	map = page_address(m->page);
	merged = page_address(preq->sinfo.ri.tpage);

	for (i = skip; i < INDEX_PER_PAGE; i++) {
		if (map[i] != 0)
			continue;
		if (merged[i] == 0)
			continue;
		if (preq->sinfo.ri.level != MAP_LEVEL(m)) {
			if (!m->levels) {
				m->levels = kmalloc(INDEX_PER_PAGE, GFP_NOFS);
				if (unlikely(m->levels == NULL)) {
					preq->error = -ENOMEM;
					goto abort_update;
				}
				memset(m->levels, MAP_LEVEL(m), INDEX_PER_PAGE);
			}
			m->levels[i] = preq->sinfo.ri.level;
		}
		map[i] = merged[i];
	}

	put_page(preq->sinfo.ri.tpage);
	preq->sinfo.ri.tpage = NULL;

	spin_lock_irq(&plo->lock);
	clear_bit(PLOOP_MAP_READ, &m->state);
	MAP_SET_UPTODATE(m, preq->sinfo.ri.level);
	__TRACE("MAP U %u %d\n", preq->req_cluster, preq->sinfo.ri.level);
	preq->eng_state = PLOOP_E_ENTRY;

flush_queue:
	list_for_each_safe(n, pn, &m->io_queue) {
		preq = list_entry(n, struct ploop_request, list);
		if (preq->eng_state == PLOOP_E_ENTRY) {
			list_del(&preq->list);
			list_add_tail(&preq->list, &list);
		}
	}
	if (!list_empty(&list))
		list_splice(&list, &plo->ready_queue);
	spin_unlock_irq(&plo->lock);
	return;

abort_update:
	put_page(preq->sinfo.ri.tpage);
	preq->sinfo.ri.tpage = NULL;
	preq->eng_state = PLOOP_E_COMPLETE;

	spin_lock_irq(&plo->lock);
	clear_bit(PLOOP_MAP_READ, &m->state);
	set_bit(PLOOP_MAP_ERROR, &m->state);
	goto flush_queue;
}


void map_read_complete(struct ploop_request * preq)
{
	struct map_node * m = preq->map;

	if (preq->eng_state == PLOOP_E_TRANS_INDEX_READ)
		m = preq->trans_map;

	if (!test_bit(PLOOP_MAP_UPTODATE, &m->state))
		map_read_endio(preq, m);
	else
		map_merge_endio(preq, m);
}

static int
ploop_map_start_read(struct ploop_map * map, struct ploop_request * preq,
		     struct map_node * m)
{
	struct ploop_device * plo = map->plo;
	struct ploop_delta * top_delta, * delta, * ndelta;
	sector_t pos;

	top_delta = map_top_delta(map);
	delta = NULL;

	list_for_each_entry(ndelta, &map->delta_list, list) {
		int rc;

		rc = ndelta->ops->map_index(ndelta, m->mn_start, &pos);
		if (rc != 0) {
			delta = ndelta;
			break;
		}
	}

	if (delta) {
		__TRACE("MAP R0 %u %d %lu %d\n", preq->req_cluster, delta->level, pos, m->index);
		/* We know delta, we know position. We can read. */
		MAP_SET_LEVEL(m, delta->level);
		MAP_SET_UPTODATE(m, delta->level);
		if (map == &plo->map)
			preq->eng_state = PLOOP_E_INDEX_READ;
		else
			preq->eng_state = PLOOP_E_TRANS_INDEX_READ;
		delta->ops->read_index(delta, preq, m->page, pos);
		plo->st.map_reads++;
		return 1;
	}

	/* Otherwise mapping does not exist. */
	memset(page_address(m->page), 0, PAGE_SIZE);
	__TRACE("MAP R1 %u %d\n", preq->req_cluster, top_delta->level);
	MAP_SET_LEVEL(m, top_delta->level);
	MAP_SET_UPTODATE(m, 0);
	clear_bit(PLOOP_MAP_READ, &m->state);
	set_bit(PLOOP_MAP_UPTODATE, &m->state);
	return 0;
}

static int ploop_read_map(struct ploop_map * map, struct ploop_request * preq)
{
	struct ploop_device * plo = preq->plo;
	struct map_node * m = (map == &plo->map) ? preq->map : preq->trans_map;
	int err = 0;

	spin_lock_irq(&plo->lock);
	if (!test_bit(PLOOP_MAP_UPTODATE, &m->state)) {
		if (test_bit(PLOOP_MAP_ERROR, &m->state)) {
			err = -EIO;
			goto out;
		}

		if (!test_and_set_bit(PLOOP_MAP_READ, &m->state)) {
			spin_unlock_irq(&plo->lock);

			return ploop_map_start_read(map, preq, m);
		} else {
			__TRACE("g %p %u %p\n", preq, preq->req_cluster, m);
			plo->st.map_lockouts++;
			list_add_tail(&preq->list, &m->io_queue);
			err = 1;
		}
	}

out:
	spin_unlock_irq(&plo->lock);
	return err;
}

void ploop_update_map(struct ploop_map * map, int level,
		      cluster_t block, iblock_t iblk)
{
	struct map_node * m;
	u32 idx;
	map_index_t *p;

	spin_lock_irq(&map->plo->lock);

	m = map_lookup(map, block);
	if (!m || !test_bit(PLOOP_MAP_UPTODATE, &m->state))
		goto out;

	p = (map_index_t *)page_address(m->page);
	idx = (block  + PLOOP_MAP_OFFSET) & (INDEX_PER_PAGE - 1);

	if (p[idx]) {
		int lvl = m->levels ? m->levels[idx] : MAP_LEVEL(m);

		if (lvl == level)
			p[idx] = iblk << ploop_map_log(map->plo);
		else if (lvl < level)
			printk("Unexpected condition: uptodate map_node %p "
			       "covering range %u..%u maps %u to %u on level "
			       "%d, while user-space merge detected mapping "
			       "on level %d\n", m, m->mn_start, m->mn_end,
			       block, p[idx] >> map->plo->cluster_log, lvl,
			       level);
	}
out:
	spin_unlock_irq(&map->plo->lock);
}

void ploop_update_map_hdr(struct ploop_map * map, u8 *hdr, int hdr_size)
{
	struct map_node * m;

	spin_lock_irq(&map->plo->lock);

	m = map_lookup(map, 0);
	if (m && test_bit(PLOOP_MAP_UPTODATE, &m->state))
		memcpy(page_address(m->page), hdr, hdr_size);

	spin_unlock_irq(&map->plo->lock);
}
EXPORT_SYMBOL(ploop_update_map_hdr);

int ploop_find_trans_map(struct ploop_map * map, struct ploop_request * preq)
{
	struct map_node * m;
	cluster_t block;

	block = preq->req_cluster;

	if (unlikely(block >= map->max_index))
		return -ERANGE;

	map->last_activity = jiffies;

	m = preq->trans_map;
	if (m == NULL) {
		spin_lock_irq(&map->plo->lock);
		m = map_lookup(map, block);
		if (m) {
			atomic_inc(&m->refcnt);
			if (!list_empty(&m->lru) && atomic_read(&m->refcnt) == 1) {
				cond_flush_lru_buffer(map);
				if (atomic_read(&m->refcnt) == 1) {
					atomic_inc(&m->refcnt);
					map->lru_buffer[map->lru_buffer_ptr++] = m;
				}
			}
		}
		spin_unlock_irq(&map->plo->lock);

		if (m == NULL) {
			struct ploop_delta * mdelta = map_top_delta(map);
			sector_t sec;
			if (mdelta->ops->map_index(mdelta, block, &sec) == 0)
				return 0;

			m = map_create(map, block);
			if (IS_ERR(m))
				return PTR_ERR(m);
		}

		preq->trans_map = m;
	}

	if (test_bit(PLOOP_MAP_UPTODATE, &m->state))
		return 0;

	return ploop_read_map(map, preq);
}

/* Find mapping for this request. Mapping can be not uptodate. */

int ploop_find_map(struct ploop_map * map, struct ploop_request * preq)
{
	struct map_node * m;
	cluster_t block;

	block = preq->req_cluster;

	if (unlikely(block >= map->max_index))
		return -ERANGE;

	if (test_bit(PLOOP_MAP_IDENTICAL, &map->flags))
		return 0;

	map->last_activity = jiffies;

	m = preq->map;
	if (m == NULL) {
		spin_lock_irq(&map->plo->lock);
		m = map_lookup(map, block);
		if (m) {
			atomic_inc(&m->refcnt);
			if (!list_empty(&m->lru) && atomic_read(&m->refcnt) == 1) {
				cond_flush_lru_buffer(map);
				if (atomic_read(&m->refcnt) == 1) {
					atomic_inc(&m->refcnt);
					map->lru_buffer[map->lru_buffer_ptr++] = m;
				}
			}
		}
		spin_unlock_irq(&map->plo->lock);

		if (m == NULL) {
			m = map_create(map, block);
			if (IS_ERR(m))
				return PTR_ERR(m);
		}

		preq->map = m;
	}

	if (test_bit(PLOOP_MAP_UPTODATE, &m->state))
		return 0;

	return ploop_read_map(map, preq);
}


/* Blank entries, which refer to another delta
 * _XXX_ a little more brain stress to detect the case, when we do not
 * have such entries. Also, copy cries for an optimization.
 */

static void copy_index_for_wb(struct page * page, struct map_node * m, int level)
{
	int i;
	u32 * s = page_address(m->page);
	u32 * d = page_address(page);
	int skip = 0;

	if (m->mn_start == 0) {
		skip = PLOOP_MAP_OFFSET;
		memcpy(d, s, skip * sizeof(u32));
	}

	for (i = skip; i < INDEX_PER_PAGE; i++) {
		if (level != (m->levels ? m->levels[i] : MAP_LEVEL(m)))
			d[i] = 0;
		else
			d[i] = s[i];
	}
}

/* Data write is commited. Now we need to update index. */

void ploop_index_update(struct ploop_request * preq)
{
	struct ploop_device * plo = preq->plo;
	struct map_node * m = preq->map;
	struct ploop_delta * top_delta = map_top_delta(m->parent);
	u32 idx;
	map_index_t blk;
	int old_level;
	struct page * page;
	sector_t sec;

	/* No way back, we are going to initiate index write. */

	idx = (preq->req_cluster + PLOOP_MAP_OFFSET) & (INDEX_PER_PAGE - 1);
	blk = ((map_index_t *)page_address(m->page))[idx]  >> ploop_map_log(plo);
	old_level = m->levels ? m->levels[idx] : MAP_LEVEL(m);

	if (top_delta->level != old_level) {
		if (m->levels == NULL) {
			u8 * levels = kmalloc(INDEX_PER_PAGE, GFP_NOFS);
			if (levels == NULL)
				goto enomem;
			memset(levels, MAP_LEVEL(m), INDEX_PER_PAGE);
			m->levels = levels;
		}
	}

	BUG_ON (test_bit(PLOOP_REQ_ZERO, &preq->state) && preq->iblock);
	if (test_bit(PLOOP_REQ_ZERO, &preq->state) && !blk) {
		printk("Either map_node is corrupted or bug in "
		       "ploop-balloon (%u)\n", preq->req_cluster);
		ploop_set_error(preq, -EIO);
		goto corrupted;
	}

	if (blk == preq->iblock && top_delta->level == old_level)
		goto out;

	if (test_and_set_bit(PLOOP_MAP_WRITEBACK, &m->state)) {
		preq->eng_state = PLOOP_E_INDEX_DELAY;
		list_add_tail(&preq->list, &m->io_queue);
		__TRACE("d %p %u %p\n", preq, preq->req_cluster, m);
		return;
	}

	page = alloc_page(GFP_NOFS);
	if (page == NULL) {
		clear_bit(PLOOP_MAP_WRITEBACK, &m->state);
		goto enomem;
	}

	copy_index_for_wb(page, m, top_delta->level);

	((map_index_t*)page_address(page))[idx] = preq->iblock << ploop_map_log(plo);

	preq->eng_state = PLOOP_E_INDEX_WB;
	get_page(page);
	preq->sinfo.wi.tpage = page;

	__TRACE("wbi %p %u %p\n", preq, preq->req_cluster, m);
	plo->st.map_single_writes++;
	top_delta->ops->map_index(top_delta, m->mn_start, &sec);
	/* Relocate requires consistent writes, mark such reqs appropriately */
	if (test_bit(PLOOP_REQ_RELOC_A, &preq->state) ||
	    test_bit(PLOOP_REQ_RELOC_S, &preq->state))
		set_bit(PLOOP_REQ_FORCE_FUA, &preq->state);

	top_delta->io.ops->write_page(&top_delta->io, preq, page, sec,
				      !!(preq->req_rw & REQ_FUA));
	put_page(page);
	return;

enomem:
	ploop_set_error(preq, -ENOMEM);
corrupted:
	set_bit(PLOOP_S_ABORT, &plo->state);
out:
	preq->eng_state = PLOOP_E_COMPLETE;
	spin_lock_irq(&plo->lock);
	list_add_tail(&preq->list, &plo->ready_queue);
	spin_unlock_irq(&plo->lock);
	return;
}
EXPORT_SYMBOL(ploop_index_update);

int map_index(struct ploop_delta * delta, struct ploop_request * preq, unsigned long *sec)
{
	return delta->ops->map_index(delta, preq->map->mn_start, sec);
}
EXPORT_SYMBOL(map_index);

struct ploop_delta * map_writable_delta(struct ploop_request * preq)
{
	struct map_node * m = preq->map;

	if (m == NULL)
		return ploop_top_delta(preq->plo);
	else
		return map_top_delta(m->parent);
}
EXPORT_SYMBOL(map_writable_delta);

static void map_idx_swap(struct map_node *m, unsigned int idx,
			 iblock_t *iblk, int log)
{
	iblock_t iblk2 = ((map_index_t*)page_address(m->page))[idx] >> log;
	((map_index_t*)page_address(m->page))[idx] = *iblk << log;
	*iblk = iblk2;
}

static inline void requeue_req(struct ploop_request *preq,
			       unsigned long new_eng_state)
{
	preq->eng_state = new_eng_state;
	spin_lock_irq(&preq->plo->lock);
	list_del(&preq->list);
	list_add_tail(&preq->list, &preq->plo->ready_queue);
	spin_unlock_irq(&preq->plo->lock);
}

/*
 * Index write-back for given preq happened, map_wb_complete()
 * found preq in m->io_queue in PLOOP_E_INDEX_WB eng_state and
 * updated in-core page of L2-table with preq->iblock. Now, it's
 * time to either finalize preq (main case) setting eng_state to
 * PLOOP_E_COMPLETE or process it further (RELOC_[A|S] case)
 */
static void map_wb_complete_post_process(struct ploop_map *map,
					 struct ploop_request *preq, int err)
{
	struct ploop_device *plo       = map->plo;
	struct ploop_delta  *top_delta = map_top_delta(map);
	struct bio_list sbl;
	int i;

	if (likely(err ||
		   (!test_bit(PLOOP_REQ_RELOC_A, &preq->state) &&
		    !test_bit(PLOOP_REQ_RELOC_S, &preq->state)))) {

		requeue_req(preq, PLOOP_E_COMPLETE);
		return;
	}

	if (test_bit(PLOOP_REQ_RELOC_S, &preq->state)) {
		spin_lock_irq(&plo->lock);
		del_lockout(preq);
		map_release(preq->map);
		preq->map = NULL;
		spin_unlock_irq(&plo->lock);

		requeue_req(preq, PLOOP_E_RELOC_COMPLETE);
		return;
	}

	BUG_ON (!test_bit(PLOOP_REQ_RELOC_A, &preq->state));
	BUG_ON (!preq->aux_bio);

	sbl.head = sbl.tail = preq->aux_bio;
	preq->eng_state = PLOOP_E_RELOC_NULLIFY;
	list_del_init(&preq->list);
	for (i = 0; i < preq->aux_bio->bi_vcnt; i++)
		memset(page_address(preq->aux_bio->bi_io_vec[i].bv_page),
		       0, PAGE_SIZE);

	/*
	 * Lately we think we does sync of nullified blocks at format
	 * driver by image fsync before header update.
	 * But we write this data directly into underlying device
	 * bypassing EXT4 by usage of extent map tree
	 * (see dio_submit()). So fsync of EXT4 image doesnt help us.
	 * We need to force sync of nullified blocks.
	 */
	set_bit(PLOOP_REQ_FORCE_FUA, &preq->state);
	top_delta->io.ops->submit(&top_delta->io, preq, preq->req_rw,
				  &sbl, preq->iblock, 1<<plo->cluster_log);
}

static void map_wb_complete(struct map_node * m, int err)
{
	struct ploop_device * plo = m->parent->plo;
	struct ploop_delta * top_delta = map_top_delta(m->parent);
	struct list_head * cursor, * tmp;
	struct ploop_request * main_preq;
	struct page * page = NULL;
	int delayed = 0;
	unsigned int idx;
	sector_t sec;
	int fua, force_fua;

	/* First, complete processing of written back indices,
	 * finally instantiate indices in mapping cache.
	 */
	list_for_each_safe(cursor, tmp, &m->io_queue) {
		struct ploop_request * preq;

		preq = list_entry(cursor, struct ploop_request, list);

		switch (preq->eng_state) {
		case PLOOP_E_ENTRY:
			break;
		case PLOOP_E_INDEX_WB:
			idx = (preq->req_cluster + PLOOP_MAP_OFFSET) & (INDEX_PER_PAGE - 1);
			if (!err) {
				struct ploop_request *pr = preq;

				if (unlikely(test_bit(PLOOP_REQ_ZERO, &preq->state))) {
					BUG_ON (list_empty(&preq->delay_list));
					pr = list_first_entry(&preq->delay_list,
							      struct ploop_request,
							      list);
				}

				if (unlikely(test_bit(PLOOP_REQ_RELOC_A, &preq->state) ||
					     test_bit(PLOOP_REQ_ZERO, &preq->state)))
					map_idx_swap(m, idx, &pr->iblock,
						     ploop_map_log(plo));
				else
					((map_index_t*)page_address(m->page))[idx] =
						pr->iblock << ploop_map_log(plo);

				if (m->levels) {
					m->levels[idx] = top_delta->level;
				} else {
					BUG_ON(MAP_LEVEL(m) != top_delta->level);
				}
			} else {
				ploop_set_error(preq, err);
			}
			put_page(preq->sinfo.wi.tpage);
			preq->sinfo.wi.tpage = NULL;
			map_wb_complete_post_process(m->parent, preq, err);
			break;
		case PLOOP_E_INDEX_DELAY:
			if (err) {
				ploop_set_error(preq, err);
				preq->eng_state = PLOOP_E_COMPLETE;
				spin_lock_irq(&plo->lock);
				list_del(cursor);
				list_add_tail(cursor, &preq->plo->ready_queue);
				spin_unlock_irq(&plo->lock);
			} else {
				delayed++;
			}
			break;
		}
	}

	if (!delayed) {
		clear_bit(PLOOP_MAP_WRITEBACK, &m->state);
		return;
	}

	page = alloc_page(GFP_NOFS);
	if (page)
		copy_index_for_wb(page, m, top_delta->level);

	main_preq = NULL;
	fua = 0;
	force_fua = 0;

	list_for_each_safe(cursor, tmp, &m->io_queue) {
		struct ploop_request * preq;

		preq = list_entry(cursor, struct ploop_request, list);

		switch (preq->eng_state) {
		case PLOOP_E_INDEX_DELAY:
			if (page == NULL) {
				ploop_set_error(preq, -ENOMEM);
				preq->eng_state = PLOOP_E_COMPLETE;
				spin_lock_irq(&plo->lock);
				list_del(cursor);
				list_add_tail(cursor, &plo->ready_queue);
				spin_unlock_irq(&plo->lock);
				break;
			}

			if (preq->req_rw & REQ_FUA)
				fua = 1;

			if (test_bit(PLOOP_REQ_RELOC_A, &preq->state) ||
			    test_bit(PLOOP_REQ_RELOC_S, &preq->state))
				force_fua = 1;

			preq->eng_state = PLOOP_E_INDEX_WB;
			get_page(page);
			preq->sinfo.wi.tpage = page;
			idx = (preq->req_cluster + PLOOP_MAP_OFFSET) & (INDEX_PER_PAGE - 1);

			((map_index_t*)page_address(page))[idx] = preq->iblock << ploop_map_log(plo);

			if (!main_preq) {
				main_preq = preq;
				list_del_init(&main_preq->list);
			}
			plo->st.map_multi_updates++;
		}
	}

	if (!page) {
		/* Writes are discarded */
		clear_bit(PLOOP_MAP_WRITEBACK, &m->state);
		return;
	}

	__TRACE("wbi2 %p %u %p\n", main_preq, main_preq->req_cluster, m);
	plo->st.map_multi_writes++;
	top_delta->ops->map_index(top_delta, m->mn_start, &sec);

	if (force_fua)
		set_bit(PLOOP_REQ_FORCE_FUA, &main_preq->state);

	top_delta->io.ops->write_page(&top_delta->io, main_preq, page, sec, fua);
	put_page(page);
}

void
ploop_index_wb_complete(struct ploop_request * preq)
{
	struct ploop_device * plo = preq->plo;
	struct map_node * m = preq->map;

	spin_lock_irq(&plo->lock);
	list_add_tail(&preq->list, &m->io_queue);
	spin_unlock_irq(&plo->lock);

	map_wb_complete(m, preq->error);
}

void ploop_map_start(struct ploop_map * map, u64 bd_size)
{
	struct ploop_device * plo = map->plo;

	map->max_index = (bd_size + (1 << plo->cluster_log) - 1 ) >> plo->cluster_log;
	map->flags = 0;
}


static void map_wait(struct ploop_map * map)
{
	DEFINE_WAIT(_wait);
	prepare_to_wait(&map->destroy_waitq, &_wait, TASK_UNINTERRUPTIBLE);

	spin_unlock(&map_lru_lock);
	spin_unlock_irq(&map->plo->lock);
	io_schedule();
	spin_lock_irq(&map->plo->lock);
	spin_lock(&map_lru_lock);

	finish_wait(&map->destroy_waitq, &_wait);
}

void ploop_map_destroy(struct ploop_map * map)
{
	int i;
	struct rb_node * node;

	spin_lock_irq(&map->plo->lock);
	set_bit(PLOOP_MAP_DEAD, &map->flags);

	for (i = 0; i < map->lru_buffer_ptr; i++)
		atomic_dec(&map->lru_buffer[i]->refcnt);

	map->lru_buffer_ptr = 0;

	spin_lock(&map_lru_lock);
	while ((node = map->rb_root.rb_node) != NULL) {
		struct map_node * m = rb_entry(node, struct map_node, rb_link);
		/* refcnt can be not zero if and only if this node is grabbed
		 * by map_lru_scan() and in flight between releasing
		 * map_lru_lock and taking plo->lock. We can skip this entry
		 * if will be destroyed by map_lru_scan(), because we
		 * set PLOOP_MAP_DEAD.
		 */
		if (atomic_read(&m->refcnt) == 0)
			map_node_destroy(m);
		else
			map_wait(map);
	}
	spin_unlock(&map_lru_lock);
	spin_unlock_irq(&map->plo->lock);
	BUG_ON(map->pages);
}

void ploop_map_remove_delta(struct ploop_map * map, int level)
{
	/* For now. */
	ploop_map_destroy(map);
}


int __init ploop_map_init(void)
{
	ploop_map_cache = kmem_cache_create("ploop_map",
						sizeof(struct map_node), 0,
						SLAB_MEM_SPREAD, NULL
						);
	if (!ploop_map_cache)
		return -ENOMEM;
	return 0;
}

void ploop_map_exit(void)
{
	if (ploop_map_cache)
		kmem_cache_destroy(ploop_map_cache);
}
