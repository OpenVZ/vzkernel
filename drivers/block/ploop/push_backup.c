#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/bio.h>
#include <linux/interrupt.h>
#include <linux/buffer_head.h>
#include <linux/kthread.h>

#include <trace/events/block.h>

#include <linux/ploop/ploop.h>
#include "push_backup.h"

#define NR_PAGES(bits) (((bits) + PAGE_SIZE*8 - 1) / (PAGE_SIZE*8))
#define BITS_PER_PAGE  (1UL << (PAGE_SHIFT + 3))

struct pb_set {
	struct rb_root	   tree;
	struct list_head   list;
	struct timer_list  timer;
	char		  *name;
	struct ploop_pushbackup_desc *pbd; /* points to parent pbd */
};

enum {
	PLOOP_PB_ALIVE,
	PLOOP_PB_STOPPING,
	PLOOP_PB_DEAD,
};

struct ploop_pushbackup_desc {
	struct ploop_device *plo;
	struct page **cbt_map; /* a 'snapshot' copy of CBT mask */
	blkcnt_t cbt_block_max;
	blkcnt_t cbt_block_bits;
	__u8 	 cbt_uuid[16];

	struct page **ppb_map; /* Ploop Push Backup mask */
	struct page **reported_map; /* what userspace reported as backed up */
	cluster_t ppb_block_max; /* first invalid index in ppb_map */

	spinlock_t	      ppb_lock;
	struct completion     ppb_comp;
	bool                  ppb_waiting;

	struct pb_set	      pending_set;
	struct pb_set	      reported_set;

	struct bio_list	      bio_pending_list;

	struct task_struct   *health_monitor_thread;
	wait_queue_head_t     ppb_waitq;
	int		      ppb_state; /* see enum above */
};

int ploop_pb_check_uuid(struct ploop_pushbackup_desc *pbd, __u8 *uuid)
{
	if (memcmp(pbd->cbt_uuid, uuid, sizeof(pbd->cbt_uuid)))
		return -1;
	return 0;
}

int ploop_pb_get_uuid(struct ploop_pushbackup_desc *pbd, __u8 *uuid)
{
	if (!pbd)
		return -1;

	memcpy(uuid, pbd->cbt_uuid, sizeof(pbd->cbt_uuid));
	return 0;
}

static struct page **ploop_pb_map_alloc(unsigned long block_max)
{
	unsigned long npages = NR_PAGES(block_max);
	struct page **map = vmalloc(npages * sizeof(void *));
	unsigned long i;

	if (!map)
		return NULL;

	memset(map, 0, npages * sizeof(void *));

	for (i = 0; i < npages; i++) {
		map[i] = alloc_page(GFP_KERNEL|__GFP_ZERO);
		if (!map[i]) {
			while (--i >= 0)
				__free_page(map[i]);
			vfree(map);
			return NULL;
		}
	}

	return map;
}

static void ploop_pb_map_free(struct page **map, unsigned long block_max)
{
	if (map) {
		unsigned long i;
		for (i = 0; i < NR_PAGES(block_max); i++)
			if (map[i])
				__free_page(map[i]);

		vfree(map);
	}
}

int ploop_pb_cbt_map_release(struct ploop_pushbackup_desc *pbd, bool do_merge)
{
	int ret = 0;

	if (pbd->cbt_map == NULL)
		return 0;

	if (do_merge) {
		ret = blk_cbt_map_merge(pbd->plo->queue,
					pbd->cbt_uuid,
					pbd->cbt_map,
					pbd->cbt_block_max,
					pbd->cbt_block_bits);
		if (ret)
			printk("ploop(%d): blk_cbt_map_merge() failed with "
			       "%d\n", pbd->plo->index, ret);
	}

	ploop_pb_map_free(pbd->cbt_map, pbd->cbt_block_max);
	pbd->cbt_map = NULL;
	return ret;
}

static void ploop_pb_timeout_func(unsigned long data);

static void ploop_pbs_init(struct pb_set *pbs,
		struct ploop_pushbackup_desc *pbd, char *name)
{
	pbs->pbd = pbd;
	pbs->name = name;
	pbs->tree = RB_ROOT;
	INIT_LIST_HEAD(&pbs->list);

	init_timer(&pbs->timer);
	pbs->timer.function = ploop_pb_timeout_func;
	pbs->timer.data = (unsigned long)pbs;
}

static void ploop_pbs_fini(struct pb_set *pbs)
{
	del_timer_sync(&pbs->timer);
}

struct ploop_pushbackup_desc *ploop_pb_alloc(struct ploop_device *plo)
{
	struct ploop_pushbackup_desc *pbd;

	pbd = kmalloc(sizeof(struct ploop_pushbackup_desc), GFP_KERNEL|__GFP_ZERO);
	if (pbd == NULL)
		return NULL;

	pbd->ppb_block_max = (plo->bd_size + (1 << plo->cluster_log) - 1)
		>> plo->cluster_log;

	pbd->ppb_map = ploop_pb_map_alloc(pbd->ppb_block_max);
	if (!pbd->ppb_map) {
		kfree(pbd);
		return NULL;
	}

	pbd->reported_map = ploop_pb_map_alloc(pbd->ppb_block_max);
	if (!pbd->reported_map) {
		ploop_pb_map_free(pbd->ppb_map, pbd->ppb_block_max);
		kfree(pbd);
		return NULL;
	}

	spin_lock_init(&pbd->ppb_lock);
	init_completion(&pbd->ppb_comp);
	ploop_pbs_init(&pbd->pending_set, pbd, "pending");
	ploop_pbs_init(&pbd->reported_set, pbd, "reported");
	init_waitqueue_head(&pbd->ppb_waitq);
	bio_list_init(&pbd->bio_pending_list);
	pbd->plo = plo;

	return pbd;
}

static int find_first_blk_in_map(struct page **map, u64 map_max, u64 *blk_p)
{
	u64 blk = *blk_p;
	unsigned long idx = blk >> (PAGE_SHIFT + 3);

	while (blk < map_max) {
		unsigned long off = blk & (BITS_PER_PAGE -1);
		unsigned long next_bit;
		struct page *page = map[idx];

		if (!page)
			goto next;

		next_bit = find_next_bit(page_address(page), BITS_PER_PAGE, off);
		if (next_bit != BITS_PER_PAGE) {
			*blk_p = ((u64)idx << (PAGE_SHIFT + 3)) + next_bit;
			return 0;
		}

	next:
		idx++;
		blk = (u64)idx << (PAGE_SHIFT + 3);
	}

	return -1;
}

enum {
	SET_BIT,
	CLEAR_BIT,
	CHECK_BIT,
};

static bool do_bit_in_map(struct page **map, u64 map_max, u64 blk, int action)
{
	unsigned long idx = blk >> (PAGE_SHIFT + 3);
	unsigned long off = blk & (BITS_PER_PAGE -1);
	struct page *page = map[idx];

	BUG_ON(blk >= map_max);

	switch (action) {
	case SET_BIT:
		__set_bit(off, page_address(page));
		break;
	case CLEAR_BIT:
		__clear_bit(off, page_address(page));
		break;
	case CHECK_BIT:
		return test_bit(off, page_address(page));
	default:
		BUG();
	}

	return false;
}

static void set_bit_in_map(struct page **map, u64 map_max, u64 blk)
{
	do_bit_in_map(map, map_max, blk, SET_BIT);
}

static void clear_bit_in_map(struct page **map, u64 map_max, u64 blk)
{
	do_bit_in_map(map, map_max, blk, CLEAR_BIT);
}

static bool check_bit_in_map(struct page **map, u64 map_max, u64 blk)
{
	return do_bit_in_map(map, map_max, blk, CHECK_BIT);
}

static void set_bits_in_map(struct page **map, u64 map_max, u64 blk, u64 cnt)
{
	if (blk + cnt > map_max) {
		printk("set_bits_in_map: extent [%llu, %llu) is out of range"
		       " [0, %llu)\n", blk, blk + cnt, map_max);
		return;
	}

	while (cnt) {
		unsigned long idx = blk >> (PAGE_SHIFT + 3);
		unsigned long off = blk & (BITS_PER_PAGE -1);
		unsigned long len;
		void *addr = page_address(map[idx]);

		len = min_t(unsigned long, BITS_PER_PAGE - off, cnt);
		cnt -= len;
		blk += len;

		while (len) {
			if ((off & 31) == 0 && len >= 32) {
				*(u32 *)(addr + (off >> 3)) = -1;
				off += 32;
				len -= 32;
			} else {
				__set_bit(off, addr);
				off += 1;
				len -= 1;
			}
		}
	}
}

/* intentionally lockless */
void ploop_pb_clear_bit(struct ploop_pushbackup_desc *pbd, cluster_t clu)
{
	BUG_ON(!pbd);
	clear_bit_in_map(pbd->ppb_map, pbd->ppb_block_max, clu);
}

/* intentionally lockless */
bool ploop_pb_check_bit(struct ploop_pushbackup_desc *pbd, cluster_t clu)
{
	if (!pbd)
		return false;

	return check_bit_in_map(pbd->ppb_map, pbd->ppb_block_max, clu);
}

static int convert_map_to_map(struct ploop_pushbackup_desc *pbd)
{
	struct page **from_map = pbd->cbt_map;
	blkcnt_t from_max = pbd->cbt_block_max;
	blkcnt_t from_bits = pbd->cbt_block_bits;

	struct page **to_map = pbd->ppb_map;
	cluster_t to_max = pbd->ppb_block_max;
	int to_bits = pbd->plo->cluster_log + 9;

	u64 from_blk, to_blk;

	if ((u64)from_max << from_bits != (u64)to_max << to_bits) {
		printk("mismatch in map convert: %lu %lu ---> %u %d\n",
		       from_max, from_bits, to_max, to_bits);
		return -EINVAL;
	}

	for (from_blk = 0; from_blk < from_max;
	     from_blk = (++to_blk << to_bits) >> from_bits) {

		if (find_first_blk_in_map(from_map, from_max, &from_blk))
			break;

		to_blk = (from_blk << from_bits) >> to_bits;
		set_bit_in_map(to_map, to_max, to_blk);
	}

	return 0;

}

static int ploop_pb_health_monitor(void * data)
{
	struct ploop_pushbackup_desc *pbd = data;
	struct ploop_device	     *plo = pbd->plo;

	spin_lock_irq(&pbd->ppb_lock);
	while (!kthread_should_stop() || pbd->ppb_state == PLOOP_PB_STOPPING) {

		DEFINE_WAIT(_wait);
		for (;;) {
			prepare_to_wait(&pbd->ppb_waitq, &_wait, TASK_INTERRUPTIBLE);
			if (pbd->ppb_state == PLOOP_PB_STOPPING ||
			    kthread_should_stop())
				break;

			spin_unlock_irq(&pbd->ppb_lock);
			schedule();
			spin_lock_irq(&pbd->ppb_lock);
		}
		finish_wait(&pbd->ppb_waitq, &_wait);

		if (pbd->ppb_state == PLOOP_PB_STOPPING) {
			spin_unlock_irq(&pbd->ppb_lock);
			mutex_lock(&plo->ctl_mutex);
			ploop_pb_stop(pbd, true);
			mutex_unlock(&plo->ctl_mutex);
			spin_lock_irq(&pbd->ppb_lock);
		}
	}
	spin_unlock_irq(&pbd->ppb_lock);
	return 0;
}

int ploop_pb_init(struct ploop_pushbackup_desc *pbd, __u8 *uuid, bool full)
{
	struct task_struct *ts;

	memcpy(pbd->cbt_uuid, uuid, sizeof(pbd->cbt_uuid));

	if (full) {
		int i, off;
		for (i = 0; i < NR_PAGES(pbd->ppb_block_max); i++)
			memset(page_address(pbd->ppb_map[i]), 0xff, PAGE_SIZE);

		/* nullify bits beyond [0, pbd->ppb_block_max) range */
		off = pbd->ppb_block_max & (BITS_PER_PAGE -1);
		i = pbd->ppb_block_max >> (PAGE_SHIFT + 3);
		while (off && off < BITS_PER_PAGE) {
			__clear_bit(off, page_address(pbd->ppb_map[i]));
			off++;
		}
	} else {
		int rc = blk_cbt_map_copy_once(pbd->plo->queue,
					       uuid,
					       &pbd->cbt_map,
					       &pbd->cbt_block_max,
					       &pbd->cbt_block_bits);
		if (rc)
			return rc;

		rc = convert_map_to_map(pbd);
		if (rc)
			return rc;
	}

	ts = kthread_create(ploop_pb_health_monitor, pbd, "ploop_pb_hm%d",
			    pbd->plo->index);
	if (IS_ERR(ts))
		return PTR_ERR(ts);

	pbd->health_monitor_thread = ts;
	wake_up_process(ts);
	return 0;
}

void ploop_pb_fini(struct ploop_pushbackup_desc *pbd)
{
	if (pbd == NULL)
		return;

	if (!RB_EMPTY_ROOT(&pbd->pending_set.tree))
		printk("ploop_pb_fini: pending_tree is not empty!\n");
	if (!RB_EMPTY_ROOT(&pbd->reported_set.tree))
		printk("ploop_pb_fini: reported_tree is not empty!\n");

	if (pbd->health_monitor_thread) {
		kthread_stop(pbd->health_monitor_thread);
		pbd->health_monitor_thread = NULL;
	}

	if (pbd->plo) {
		struct ploop_device *plo = pbd->plo;
		mutex_lock(&plo->sysfs_mutex);
		plo->pbd = NULL;
		mutex_unlock(&plo->sysfs_mutex);
	}

	ploop_pb_cbt_map_release(pbd, true);
	ploop_pb_map_free(pbd->ppb_map, pbd->ppb_block_max);
	ploop_pb_map_free(pbd->reported_map, pbd->ppb_block_max);

	kfree(pbd);
}

int ploop_pb_copy_cbt_to_user(struct ploop_pushbackup_desc *pbd, char *user_addr)
{
	unsigned long i;

	for (i = 0; i < NR_PAGES(pbd->cbt_block_max); i++) {
		struct page *page = pbd->cbt_map[i] ? : ZERO_PAGE(0);

		if (copy_to_user(user_addr, page_address(page), PAGE_SIZE))
			return -EFAULT;

		user_addr += PAGE_SIZE;
	}

	return 0;
}

static void ploop_pb_add_req_to_tree(struct ploop_request *preq,
				     struct pb_set *pbs)
{
	struct rb_root *tree = &pbs->tree;
	struct rb_node ** p = &tree->rb_node;
	struct rb_node *parent = NULL;
	struct ploop_request * pr;
	unsigned long timeout = preq->plo->tune.push_backup_timeout * HZ;

	while (*p) {
		parent = *p;
		pr = rb_entry(parent, struct ploop_request, reloc_link);
		BUG_ON (preq->req_cluster == pr->req_cluster);

		if (preq->req_cluster < pr->req_cluster)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	preq->tstamp = jiffies;
	if (timeout && list_empty(&pbs->list) &&
	    pbs->pbd->ppb_state == PLOOP_PB_ALIVE)
		mod_timer(&pbs->timer, preq->tstamp + timeout + 1);

	if (pbs->list.prev->next != &pbs->list) {
		printk("list_add corruption. pbs->list.prev->next should be "
		       "&pbs->list (%p), but was %p. (pbs->list.prev=%p)."
		       " preq=%p\n",
		       &pbs->list, pbs->list.prev->next, pbs->list.prev, preq);
		BUG();
	}
	list_add_tail(&preq->list, &pbs->list);

	rb_link_node(&preq->reloc_link, parent, p);
	rb_insert_color(&preq->reloc_link, tree);
}

static void ploop_pb_add_req_to_pending(struct ploop_pushbackup_desc *pbd,
					struct ploop_request *preq)
{
	ploop_pb_add_req_to_tree(preq, &pbd->pending_set);
}

static void ploop_pb_add_req_to_reported(struct ploop_pushbackup_desc *pbd,
					 struct ploop_request *preq)
{
	ploop_pb_add_req_to_tree(preq, &pbd->reported_set);
}

static void remove_req_from_pbs(struct pb_set *pbs,
					 struct ploop_request *preq)
{
	unsigned long timeout = preq->plo->tune.push_backup_timeout * HZ;
	bool oldest_deleted = false;

	if (preq == list_first_entry(&pbs->list, struct ploop_request, list))
		oldest_deleted = true;

	rb_erase(&preq->reloc_link, &pbs->tree);
	list_del_init(&preq->list);

	if (timeout && oldest_deleted && !list_empty(&pbs->list) &&
	    pbs->pbd->ppb_state == PLOOP_PB_ALIVE) {
		preq = list_first_entry(&pbs->list, struct ploop_request,
					list);
		mod_timer(&pbs->timer, preq->tstamp + timeout + 1);
	}
}


static inline bool preq_match(struct ploop_request *preq, cluster_t clu,
			      cluster_t len)
{
	return preq &&
		clu <= preq->req_cluster &&
		preq->req_cluster < clu + len;
}

/* returns leftmost preq which req_cluster >= clu */
static struct ploop_request *ploop_pb_get_req_from_tree(struct pb_set *pbs,
						cluster_t clu, cluster_t len,
						struct ploop_request **npreq)
{
	struct rb_root *tree = &pbs->tree;
	struct rb_node *n = tree->rb_node;
	struct ploop_request *p = NULL;

	*npreq = NULL;

	while (n) {
		p = rb_entry(n, struct ploop_request, reloc_link);

		if (clu < p->req_cluster)
			n = n->rb_left;
		else if (clu > p->req_cluster)
			n = n->rb_right;
		else { /* perfect match */
			n = rb_next(n);
			if (n)
				*npreq = rb_entry(n, struct ploop_request,
						  reloc_link);
			remove_req_from_pbs(pbs, p);
			return p;
		}
	}
	/* here p is not perfect, but it's closest */

	if (p && p->req_cluster < clu) {
		n = rb_next(&p->reloc_link);
		if (n)
			p = rb_entry(n, struct ploop_request, reloc_link);
	}

	if (preq_match(p, clu, len)) {
		n = rb_next(&p->reloc_link);
		if (n)
			*npreq = rb_entry(n, struct ploop_request, reloc_link);
		remove_req_from_pbs(pbs, p);
		return p;
	}

	return NULL;
}

static struct ploop_request *
ploop_pb_get_first_req_from_tree(struct pb_set *pbs,
				 struct ploop_request **npreq)
{
	struct rb_root *tree = &pbs->tree;
	struct ploop_request *p;
	struct rb_node *n = rb_first(tree);

	if (!n)
		return NULL;

	if (npreq) {
		struct rb_node *next = rb_next(n);
		if (next)
			*npreq = rb_entry(next, struct ploop_request,
					  reloc_link);
		else
			*npreq = NULL;
	}

	p = rb_entry(n, struct ploop_request, reloc_link);
	remove_req_from_pbs(pbs, p);
	return p;
}

static struct ploop_request *
ploop_pb_get_first_req_from_pending(struct ploop_pushbackup_desc *pbd)
{
	return ploop_pb_get_first_req_from_tree(&pbd->pending_set, NULL);
}

static struct ploop_request *
ploop_pb_get_first_reqs_from_pending(struct ploop_pushbackup_desc *pbd,
				     struct ploop_request **npreq)
{
	return ploop_pb_get_first_req_from_tree(&pbd->pending_set, npreq);
}

static struct ploop_request *
ploop_pb_get_first_req_from_reported(struct ploop_pushbackup_desc *pbd)
{
	return ploop_pb_get_first_req_from_tree(&pbd->reported_set, NULL);
}

int ploop_pb_preq_add_pending(struct ploop_pushbackup_desc *pbd,
			       struct ploop_request *preq)
{
	BUG_ON(!pbd);

	spin_lock_irq(&pbd->ppb_lock);

	if (pbd->ppb_state != PLOOP_PB_ALIVE) {
		spin_unlock_irq(&pbd->ppb_lock);
		return -ESTALE;
	}

	if (!test_bit(PLOOP_S_PUSH_BACKUP, &pbd->plo->state)) {
		spin_unlock_irq(&pbd->ppb_lock);
		return -EINTR;
	}

	if (check_bit_in_map(pbd->reported_map, pbd->ppb_block_max,
			     preq->req_cluster)) {
		spin_unlock_irq(&pbd->ppb_lock);
		return -EALREADY;
	}

	ploop_pb_add_req_to_pending(pbd, preq);

	if (pbd->ppb_waiting)
		complete(&pbd->ppb_comp);

	spin_unlock_irq(&pbd->ppb_lock);
	return 0;
}

bool ploop_pb_check_and_clear_bit(struct ploop_pushbackup_desc *pbd,
				  cluster_t clu)
{
	if (!pbd)
		return false;

	if (!check_bit_in_map(pbd->ppb_map, pbd->ppb_block_max, clu))
		return false;

	spin_lock(&pbd->ppb_lock);

	if (pbd->ppb_state != PLOOP_PB_ALIVE ||
	    check_bit_in_map(pbd->reported_map, pbd->ppb_block_max, clu)) {
		spin_unlock(&pbd->ppb_lock);
		ploop_pb_clear_bit(pbd, clu);
		return false;
	}

	spin_unlock(&pbd->ppb_lock);
	return true;
}

static void return_bios_back_to_plo(struct ploop_device *plo,
				    struct bio_list *bl)
{
	if (!bl->head)
		return;

	if (plo->bio_tail)
		plo->bio_tail->bi_next = bl->head;
	else
		plo->bio_head = bl->head;

	plo->bio_tail = bl->tail;

	bio_list_init(bl);
}

/* Always serialized by plo->ctl_mutex */
unsigned long ploop_pb_stop(struct ploop_pushbackup_desc *pbd, bool do_merge)
{
	unsigned long ret = 0;
	int merge_status = 0;
	LIST_HEAD(drop_list);

	if (pbd == NULL)
		return 0;

	spin_lock_irq(&pbd->ppb_lock);
	if (pbd->ppb_state == PLOOP_PB_DEAD) {
		spin_unlock_irq(&pbd->ppb_lock);
		return 0;
	}
	pbd->ppb_state = PLOOP_PB_DEAD;
	spin_unlock_irq(&pbd->ppb_lock);

	ploop_pbs_fini(&pbd->pending_set);
	ploop_pbs_fini(&pbd->reported_set);

	merge_status = ploop_pb_cbt_map_release(pbd, do_merge);

	spin_lock_irq(&pbd->ppb_lock);

	while (!RB_EMPTY_ROOT(&pbd->pending_set.tree)) {
		struct ploop_request *preq =
			ploop_pb_get_first_req_from_pending(pbd);
		list_add(&preq->list, &drop_list);
		ret++;
	}

	while (!RB_EMPTY_ROOT(&pbd->reported_set.tree)) {
		struct ploop_request *preq =
			ploop_pb_get_first_req_from_reported(pbd);
		list_add(&preq->list, &drop_list);
		ret++;
	}

	if (pbd->ppb_waiting)
		complete(&pbd->ppb_comp);
	spin_unlock_irq(&pbd->ppb_lock);

	if (!list_empty(&drop_list) || !ploop_pb_bio_list_empty(pbd)) {
		struct ploop_device *plo = pbd->plo;

		BUG_ON(!plo);
		spin_lock_irq(&plo->lock);
		list_splice_init(&drop_list, plo->ready_queue.prev);
		return_bios_back_to_plo(plo, &pbd->bio_pending_list);
		if (test_bit(PLOOP_S_WAIT_PROCESS, &plo->state))
			wake_up_interruptible(&plo->waitq);
		spin_unlock_irq(&plo->lock);
	}

	return merge_status ? : ret;
}

int ploop_pb_get_pending(struct ploop_pushbackup_desc *pbd,
			 cluster_t *clu_p, cluster_t *len_p, unsigned n_done)
{
	bool blocking  = !n_done;
	struct ploop_request *preq, *npreq;
	int err = 0;

	spin_lock_irq(&pbd->ppb_lock);

	preq = ploop_pb_get_first_reqs_from_pending(pbd, &npreq);
	if (!preq) {
		struct ploop_device *plo = pbd->plo;

		if (!blocking) {
			err = -ENOENT;
			goto get_pending_unlock;
		}

                /* blocking case */
		if (pbd->ppb_state != PLOOP_PB_ALIVE) {
			err = -ESTALE;
			goto get_pending_unlock;
		}
		if (unlikely(pbd->ppb_waiting)) {
			/* Other task is already waiting for event */
			err = -EBUSY;
			goto get_pending_unlock;
		}
wait_again:
		pbd->ppb_waiting = true;
		spin_unlock_irq(&pbd->ppb_lock);

		mutex_unlock(&plo->ctl_mutex);
		err = wait_for_completion_interruptible(&pbd->ppb_comp);
		mutex_lock(&plo->ctl_mutex);

		if (plo->pbd != pbd)
			return -EINTR;

		spin_lock_irq(&pbd->ppb_lock);
		pbd->ppb_waiting = false;
		init_completion(&pbd->ppb_comp);

		preq = ploop_pb_get_first_reqs_from_pending(pbd, &npreq);
		if (!preq) {
			if (!test_bit(PLOOP_S_PUSH_BACKUP, &plo->state))
				err = -EINTR;
			else if (pbd->ppb_state != PLOOP_PB_ALIVE)
				err =  -ESTALE;
			else if (signal_pending(current))
				err = -ERESTARTSYS;
			else
				goto wait_again;

			goto get_pending_unlock;
		}
	}

	ploop_pb_add_req_to_reported(pbd, preq);

	*clu_p = preq->req_cluster;
	*len_p = 1;

	while (npreq && npreq->req_cluster == *clu_p + *len_p) {
		struct rb_node *next = rb_next(&npreq->reloc_link);

		preq = npreq;
		if (next)
			npreq = rb_entry(next, struct ploop_request,
					 reloc_link);
		else
			npreq = NULL;

		remove_req_from_pbs(&pbd->pending_set, preq);
		ploop_pb_add_req_to_reported(pbd, preq);

		(*len_p)++;
	}

get_pending_unlock:
	spin_unlock_irq(&pbd->ppb_lock);
	return err;
}

static void fill_page_to_backup(struct ploop_pushbackup_desc *pbd,
				unsigned long idx, struct page *page)
{
	u32 *dst = page_address(page);
	u32 *fin = page_address(page) + PAGE_SIZE;
	u32 *map = page_address(pbd->ppb_map[idx]);
	u32 *rep = page_address(pbd->reported_map[idx]);

	while (dst < fin) {
		*dst = *map & ~*rep;
		dst++;
		map++;
		rep++;
	}
}

int ploop_pb_peek(struct ploop_pushbackup_desc *pbd,
		  cluster_t *clu_p, cluster_t *len_p, unsigned n_done)
{
	unsigned long block = *clu_p + *len_p;
	unsigned long idx = block >> (PAGE_SHIFT + 3);
	unsigned long clu = 0;
	unsigned long len = 0;
	unsigned long off, off2;
	struct page *page;
	bool found = 0;

	if (block >= pbd->ppb_block_max)
		return -ENOENT;

	if (pbd->ppb_state != PLOOP_PB_ALIVE)
		return -ESTALE;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	spin_lock_irq(&pbd->ppb_lock);
	while (block < pbd->ppb_block_max) {
		fill_page_to_backup(pbd, idx, page);
		off = block & (BITS_PER_PAGE -1);

		if (!found) {
			clu = find_next_bit(page_address(page),
					       BITS_PER_PAGE, off);
			if (clu == BITS_PER_PAGE)
				goto next;

			off = clu;
			clu += idx << (PAGE_SHIFT + 3);
			found = 1;
		}

		if (found) {
			off2 = find_next_zero_bit(page_address(page),
						  BITS_PER_PAGE, off);
			len += off2 - off;
			if (off2 != BITS_PER_PAGE)
				break;
		}

	next:
		idx++;
		block = idx << (PAGE_SHIFT + 3);
	}
	spin_unlock_irq(&pbd->ppb_lock);

	__free_page(page);

	if (!found)
		return -ENOENT;

	*clu_p = clu;
	*len_p = len;
	return 0;
}

static void ploop_pb_process_extent(struct pb_set *pbs, cluster_t clu,
				    cluster_t len, struct list_head *ready_list,
				    int *n_found)
{
	struct ploop_request *preq, *npreq;

	preq = ploop_pb_get_req_from_tree(pbs, clu, len, &npreq);

	while (preq) {
		struct rb_node *n;

		set_bit(PLOOP_REQ_PUSH_BACKUP, &preq->ppb_state);
		list_add(&preq->list, ready_list);

		if (n_found)
			(*n_found)++;

		if (!preq_match(npreq, clu, len))
			break;

		preq = npreq;
		n = rb_next(&preq->reloc_link);
		if (n)
			npreq = rb_entry(n, struct ploop_request, reloc_link);
		else
			npreq = NULL;
		remove_req_from_pbs(pbs, preq);
	}
}

void ploop_pb_put_reported(struct ploop_pushbackup_desc *pbd,
			   cluster_t clu, cluster_t len)
{
	int n_found = 0;
	LIST_HEAD(ready_list);

	spin_lock_irq(&pbd->ppb_lock);

	ploop_pb_process_extent(&pbd->reported_set, clu, len, &ready_list, &n_found);
	ploop_pb_process_extent(&pbd->pending_set, clu, len, &ready_list, NULL);

	/*
	 * If preq not found above, it's unsolicited report. Then it's
	 * enough to have corresponding bit set in reported_map because if
	 * any WRITE-request comes afterwards, ploop_pb_preq_add_pending()
	 * fails and ploop_thread will clear corresponding bit in ppb_map
	 * -- see "push_backup special processing" in ploop_entry_request()
	 * for details.
	 */
	set_bits_in_map(pbd->reported_map, pbd->ppb_block_max, clu, len);

	spin_unlock_irq(&pbd->ppb_lock);

	if (!list_empty(&ready_list)) {
		struct ploop_device *plo = pbd->plo;

		spin_lock_irq(&plo->lock);
		list_splice(&ready_list, plo->ready_queue.prev);
		if (test_bit(PLOOP_S_WAIT_PROCESS, &plo->state))
			wake_up_interruptible(&plo->waitq);
		spin_unlock_irq(&plo->lock);
	}
}

int ploop_pb_destroy(struct ploop_device *plo, __u32 *status)
{
	struct ploop_pushbackup_desc *pbd = plo->pbd;
	unsigned long ret;
	bool do_merge;

	if (!test_and_clear_bit(PLOOP_S_PUSH_BACKUP, &plo->state))
		return -EINVAL;

	BUG_ON (!pbd);
	do_merge = status ? *status : true;
	ret = ploop_pb_stop(pbd, do_merge);

	if (status)
		*status = ret;

	ploop_quiesce(plo);
	ploop_pb_fini(plo->pbd);
	plo->maintenance_type = PLOOP_MNTN_OFF;
	ploop_relax(plo);

	return 0;
}

static bool ploop_pb_set_expired(struct pb_set *pbs)
{
	struct ploop_pushbackup_desc *pbd = pbs->pbd;
	struct ploop_device          *plo = pbd->plo;
	unsigned long timeout = plo->tune.push_backup_timeout * HZ;
	unsigned long tstamp = 0;
	cluster_t clu = 0;
	bool ret = false;
	unsigned long flags;

	if (!timeout)
		return false;

	spin_lock_irqsave(&pbd->ppb_lock, flags);

	if (pbd->ppb_state != PLOOP_PB_ALIVE) {
		spin_unlock_irqrestore(&pbd->ppb_lock, flags);
		return false;
	}

	/* No need to scan the whole list: the first preq is the oldest! */
	if (!list_empty(&pbs->list)) {
		struct ploop_request *preq = list_first_entry(&pbs->list,
							      struct ploop_request, list);
		if (time_before(preq->tstamp + timeout, jiffies)) {
			tstamp = preq->tstamp;
			clu = preq->req_cluster;
			ret = true;
		} else
			mod_timer(&pbs->timer, preq->tstamp + timeout + 1);
	}

	spin_unlock_irqrestore(&pbd->ppb_lock, flags);

	if (ret)
		printk(KERN_WARNING "Abort push_backup for ploop%d: found "
		       "preq (clu=%d) in %s tree delayed for %u msecs\n",
		       plo->index, clu, pbs->name,
		       jiffies_to_msecs(jiffies - tstamp));

	return ret;
}

static void ploop_pb_timeout_func(unsigned long data)
{
	struct pb_set                *pbs = (void*)data;
	struct ploop_pushbackup_desc *pbd = pbs->pbd;
	struct ploop_device          *plo = pbd->plo;
	unsigned long flags;

	if (!plo->tune.push_backup_timeout ||
	    !test_bit(PLOOP_S_RUNNING, &plo->state) ||
	    !test_bit(PLOOP_S_PUSH_BACKUP, &plo->state) ||
	    !ploop_pb_set_expired(pbs))
		return;

	spin_lock_irqsave(&pbd->ppb_lock, flags);
	if (pbd->ppb_state == PLOOP_PB_ALIVE) {
		pbd->ppb_state = PLOOP_PB_STOPPING;
		if (waitqueue_active(&pbd->ppb_waitq))
			wake_up_interruptible(&pbd->ppb_waitq);
	}
	spin_unlock_irqrestore(&pbd->ppb_lock, flags);
}

/* Return true if bio was detained, false otherwise */
bool ploop_pb_bio_detained(struct ploop_pushbackup_desc *pbd, struct bio *bio)
{
	cluster_t   clu = bio->bi_sector >> pbd->plo->cluster_log;

	if (ploop_pb_check_and_clear_bit(pbd, clu)) {
		bio_list_add(&pbd->bio_pending_list, bio);
		return true;
	}

	return false;
}

/* Return true if no detained bio-s present, false otherwise */
bool ploop_pb_bio_list_empty(struct ploop_pushbackup_desc *pbd)
{
	return !pbd || bio_list_empty(&pbd->bio_pending_list);
}

struct bio *ploop_pb_bio_get(struct ploop_pushbackup_desc *pbd)
{
	return bio_list_pop(&pbd->bio_pending_list);
}

void ploop_pb_bio_list_merge(struct ploop_pushbackup_desc *pbd,
			     struct bio_list *tmp)
{
	bio_list_merge(&pbd->bio_pending_list, tmp);
}
