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
