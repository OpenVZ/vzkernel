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

struct ploop_pushbackup_desc {
	struct ploop_device *plo;
	struct page **cbt_map; /* a 'snapshot' copy of CBT mask */
	blkcnt_t cbt_block_max;
	blkcnt_t cbt_block_bits;
	__u8 	 cbt_uuid[16];

	struct page **ppb_map; /* Ploop Push Backup mask */
	cluster_t ppb_block_max; /* first invalid index in ppb_map */
	cluster_t ppb_offset; /* [0, ppb_offset) is ACKed by userspace */

	spinlock_t	      ppb_lock;
	struct completion     ppb_comp;
	bool                  ppb_waiting;


	struct rb_root	      pending_tree;
	struct rb_root	      reported_tree;
};

int ploop_pb_check_uuid(struct ploop_pushbackup_desc *pbd, __u8 *uuid)
{
	if (memcmp(pbd->cbt_uuid, uuid, sizeof(pbd->cbt_uuid)))
		return -1;
	return 0;
}

struct ploop_pushbackup_desc *ploop_pb_alloc(struct ploop_device *plo)
{
	struct ploop_pushbackup_desc *pbd;
	int i, npages;

	pbd = kmalloc(sizeof(struct ploop_pushbackup_desc), GFP_KERNEL|__GFP_ZERO);
	if (pbd == NULL)
		return NULL;

	pbd->ppb_block_max = (plo->bd_size + (1 << plo->cluster_log) - 1)
		>> plo->cluster_log;
	npages = NR_PAGES(pbd->ppb_block_max);

	pbd->ppb_map = vmalloc(npages * sizeof(void *));
	if (!pbd->ppb_map) {
		kfree(pbd);
		return NULL;
	}

	memset(pbd->ppb_map, 0, npages * sizeof(void *));

	for (i = 0; i < npages; i++) {
		pbd->ppb_map[i] = alloc_page(GFP_KERNEL|__GFP_ZERO);
		if (!pbd->ppb_map[i]) {
			while (--i >= 0)
				__free_page(pbd->ppb_map[i]);
			vfree(pbd->ppb_map);
			kfree(pbd);
			return NULL;
		}
	}

	spin_lock_init(&pbd->ppb_lock);
	init_completion(&pbd->ppb_comp);
	pbd->pending_tree = RB_ROOT;
	pbd->reported_tree = RB_ROOT;
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

int ploop_pb_init(struct ploop_pushbackup_desc *pbd, __u8 *uuid, bool full)
{
	int rc;

	memcpy(pbd->cbt_uuid, uuid, sizeof(pbd->cbt_uuid));

	if (full) {
		int i;
		for (i = 0; i < NR_PAGES(pbd->ppb_block_max); i++)
			memset(page_address(pbd->ppb_map[i]), 0xff, PAGE_SIZE);
		return 0;
	}

	rc = blk_cbt_map_copy_once(pbd->plo->queue,
				   uuid,
				   &pbd->cbt_map,
				   &pbd->cbt_block_max,
				   &pbd->cbt_block_bits);
	if (rc)
		return rc;

	return convert_map_to_map(pbd);
}

static void ploop_pb_free_cbt_map(struct ploop_pushbackup_desc *pbd)
{
	if (pbd->cbt_map) {
		unsigned long i;
		for (i = 0; i < NR_PAGES(pbd->cbt_block_max); i++)
			if (pbd->cbt_map[i])
				__free_page(pbd->cbt_map[i]);

		vfree(pbd->cbt_map);
		pbd->cbt_map = NULL;
	}
}

void ploop_pb_fini(struct ploop_pushbackup_desc *pbd)
{
	int i;

	if (pbd == NULL)
		return;

	if (!RB_EMPTY_ROOT(&pbd->pending_tree))
		printk("ploop_pb_fini: pending_tree is not empty!\n");
	if (!RB_EMPTY_ROOT(&pbd->reported_tree))
		printk("ploop_pb_fini: reported_tree is not empty!\n");

	if (pbd->plo)
		pbd->plo->pbd = NULL;

	ploop_pb_free_cbt_map(pbd);

	for (i = 0; i < NR_PAGES(pbd->ppb_block_max); i++)
		__free_page(pbd->ppb_map[i]);

	vfree(pbd->ppb_map);
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

	ploop_pb_free_cbt_map(pbd);
	return 0;
}

static void ploop_pb_add_req_to_tree(struct ploop_request *preq,
				     struct rb_root *tree)
{
	struct rb_node ** p = &tree->rb_node;
	struct rb_node *parent = NULL;
	struct ploop_request * pr;

	while (*p) {
		parent = *p;
		pr = rb_entry(parent, struct ploop_request, reloc_link);
		BUG_ON (preq->req_cluster == pr->req_cluster);

		if (preq->req_cluster < pr->req_cluster)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	rb_link_node(&preq->reloc_link, parent, p);
	rb_insert_color(&preq->reloc_link, tree);
}

static void ploop_pb_add_req_to_pending(struct ploop_pushbackup_desc *pbd,
					struct ploop_request *preq)
{
	ploop_pb_add_req_to_tree(preq, &pbd->pending_tree);
}

static void ploop_pb_add_req_to_reported(struct ploop_pushbackup_desc *pbd,
					 struct ploop_request *preq)
{
	ploop_pb_add_req_to_tree(preq, &pbd->reported_tree);
}

static struct ploop_request *ploop_pb_get_req_from_tree(struct rb_root *tree,
							cluster_t clu)
{
	struct rb_node *n = tree->rb_node;
	struct ploop_request *p;

	while (n) {
		p = rb_entry(n, struct ploop_request, reloc_link);

		if (clu < p->req_cluster)
			n = n->rb_left;
		else if (clu > p->req_cluster)
			n = n->rb_right;
		else {
			rb_erase(&p->reloc_link, tree);
			return p;
		}
	}
	return NULL;
}

static struct ploop_request *
ploop_pb_get_first_req_from_tree(struct rb_root *tree)
{
	static struct ploop_request *p;
	struct rb_node *n = rb_first(tree);

	if (!n)
		return NULL;

	p = rb_entry(n, struct ploop_request, reloc_link);
	rb_erase(&p->reloc_link, tree);
	return p;
}

static struct ploop_request *
ploop_pb_get_first_req_from_pending(struct ploop_pushbackup_desc *pbd)
{
	return ploop_pb_get_first_req_from_tree(&pbd->pending_tree);
}

static struct ploop_request *
ploop_pb_get_req_from_pending(struct ploop_pushbackup_desc *pbd,
			      cluster_t clu)
{
	return ploop_pb_get_req_from_tree(&pbd->pending_tree, clu);
}

static struct ploop_request *
ploop_pb_get_req_from_reported(struct ploop_pushbackup_desc *pbd,
			       cluster_t clu)
{
	return ploop_pb_get_req_from_tree(&pbd->reported_tree, clu);
}

int ploop_pb_preq_add_pending(struct ploop_pushbackup_desc *pbd,
			       struct ploop_request *preq)
{
	BUG_ON(!pbd);

	spin_lock(&pbd->ppb_lock);

	if (!test_bit(PLOOP_S_PUSH_BACKUP, &pbd->plo->state)) {
		spin_unlock(&pbd->ppb_lock);
		return -EINTR;
	}

	/* if (preq matches pbd->reported_map) return -EALREADY; */
	if (preq->req_cluster < pbd->ppb_offset) {
		spin_unlock(&pbd->ppb_lock);
		return -EALREADY;
	}

	ploop_pb_add_req_to_pending(pbd, preq);

	if (pbd->ppb_waiting)
		complete(&pbd->ppb_comp);

	spin_unlock(&pbd->ppb_lock);
	return 0;
}

unsigned long ploop_pb_stop(struct ploop_pushbackup_desc *pbd)
{
	if (pbd == NULL)
		return 0;

	spin_lock(&pbd->ppb_lock);

	if (pbd->ppb_waiting)
		complete(&pbd->ppb_comp);
	spin_unlock(&pbd->ppb_lock);

	return 0;
}

int ploop_pb_get_pending(struct ploop_pushbackup_desc *pbd,
			 cluster_t *clu_p, cluster_t *len_p, unsigned n_done)
{
	bool blocking  = !n_done;
	struct ploop_request *preq;
	int err = 0;

	spin_lock(&pbd->ppb_lock);

	/* OPTIMIZE ME LATER: rb_first() once, then rb_next() */
	preq = ploop_pb_get_first_req_from_pending(pbd);
	if (!preq) {
		struct ploop_device *plo = pbd->plo;

		if (!blocking) {
			err = -ENOENT;
			goto get_pending_unlock;
		}

                /* blocking case */
		if (unlikely(pbd->ppb_waiting)) {
			/* Other task is already waiting for event */
			err = -EBUSY;
			goto get_pending_unlock;
		}
		pbd->ppb_waiting = true;
		spin_unlock(&pbd->ppb_lock);

		mutex_unlock(&plo->ctl_mutex);
		err = wait_for_completion_interruptible(&pbd->ppb_comp);
		mutex_lock(&plo->ctl_mutex);

		if (plo->pbd != pbd)
			return -EINTR;

		spin_lock(&pbd->ppb_lock);
		pbd->ppb_waiting = false;
		init_completion(&pbd->ppb_comp);

		preq = ploop_pb_get_first_req_from_pending(pbd);
		if (!preq) {
			if (!test_bit(PLOOP_S_PUSH_BACKUP, &plo->state))
				err = -EINTR;
			else if (signal_pending(current))
				err = -ERESTARTSYS;
			else err = -ENOENT;

			goto get_pending_unlock;
		}
	}

	ploop_pb_add_req_to_reported(pbd, preq);

	*clu_p = preq->req_cluster;
	*len_p = 1;

get_pending_unlock:
	spin_unlock(&pbd->ppb_lock);
	return err;
}

void ploop_pb_put_reported(struct ploop_pushbackup_desc *pbd,
			   cluster_t clu, cluster_t len)
{
	struct ploop_request *preq;
	int n_found = 0;

	/* OPTIMIZE ME LATER: find leftmost item for [clu, clu+len),
	 * then rb_next() while req_cluster < clu+len.
	 * Do this firstly for reported, then for pending */
	BUG_ON(len != 1);

	spin_lock(&pbd->ppb_lock);

	preq = ploop_pb_get_req_from_reported(pbd, clu);
	if (!preq)
		preq = ploop_pb_get_req_from_pending(pbd, clu);
	else
		n_found++;

	if (preq)
		__set_bit(PLOOP_REQ_PUSH_BACKUP, &preq->state);

	/*
	 * If preq not found above, it's unsolicited report. Then it's
	 * enough to have corresponding bit set in reported_map because if
	 * any WRITE-request comes afterwards, ploop_pb_preq_add_pending()
	 * fails and ploop_thread will clear corresponding bit in ppb_map
	 * -- see "push_backup special processing" in ploop_entry_request()
	 * for details.
	 */

	/*
	 * "If .. else if .." below will be fully reworked when switching
	 * from pbd->ppb_offset to pbd->reported_map. All we need here is
	 * actaully simply to set bits corresponding to [clu, clu+len) in
	 * pbd->reported_map.
	 */
	if (pbd->ppb_offset >= clu) { /* lucky strike */
		if (clu + len > pbd->ppb_offset) {
			pbd->ppb_offset = clu + len;
		}
	} else if (n_found != len) { /* a hole, bad luck */
		printk("ploop: push_backup ERR: off=%u ext=[%u, %u) found %d\n",
		       pbd->ppb_offset, clu, clu + len, n_found);
	}

	spin_unlock(&pbd->ppb_lock);

	if (preq) {
		struct ploop_device *plo = preq->plo;
		BUG_ON(preq->req_cluster != clu);
		BUG_ON(plo != pbd->plo);

		spin_lock_irq(&plo->lock);
		list_add_tail(&preq->list, &plo->ready_queue);
		if (test_bit(PLOOP_S_WAIT_PROCESS, &plo->state))
			wake_up_interruptible(&plo->waitq);
		spin_unlock_irq(&plo->lock);
	}
}
