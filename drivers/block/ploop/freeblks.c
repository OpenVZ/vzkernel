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
#include "freeblks.h"

#define MIN(a, b) (a < b ? a : b)

struct ploop_freeblks_extent
{
	struct list_head list; /* List link */

	cluster_t clu;
	iblock_t  iblk;
	u32	  len;

};

struct ploop_relocblks_extent
{
	struct list_head list; /* List link */

	cluster_t clu;
	iblock_t  iblk;
	u32	  len;
	u32	  free;	/* this extent is also present in freemap */
};

struct ploop_fextent_ptr {
	struct ploop_freeblks_extent *ext;
	u32 off;
};

struct ploop_rextent_ptr {
	struct ploop_relocblks_extent *ext;
	u32 off;
};

struct ploop_freeblks_desc {
	struct ploop_device *plo;

	int fbd_n_free;	       /* # free blocks remaining
				  (i.e. "not re-used") */

	/* fbd_ffb.ext->clu + fbd_ffb.off can be used as
	 * 'clu of first free block to reuse' for WRITE ops */
	struct ploop_fextent_ptr fbd_ffb; /* 'ffb' stands for
					     'first free block' */

	/* fbd_lfb.ext->clu + fbd_lfb.off can be used as
	 * 'clu of first block to overwrite' (draining reloc range from end) */
	struct ploop_fextent_ptr fbd_lfb; /* 'lfb' stands for
					     'last free block for relocation'*/

	/* fbd_reloc_extents[fbd->fbd_last_reloc_extent].clu +
	 * fbd_last_reloc_off can be used as 'clu of first block to relocate'
	 * (draining reloc range from end)
	 * NB: ffb and lfb above deal with free_list, while lrb deals with
	 * reloc_list! */
	struct ploop_rextent_ptr fbd_lrb; /* 'lrb' stands for
					     'last block to relocate' */

	/* counters to trace the progress of relocation */
	int fbd_n_relocated;  /* # blocks actually relocated */
	int fbd_n_relocating; /* # blocks whose relocation was at
				   least started */

	/* lost_range: [fbd_first_lost_iblk ..
	 *		fbd_first_lost_iblk + fbd_lost_range_len - 1] */
	iblock_t fbd_first_lost_iblk;
	int	 fbd_lost_range_len;
	int	 fbd_lost_range_addon; /* :)) */

	/* any reloc request resides there while it's "in progress" */
	struct rb_root		reloc_tree;

	/* list of ploop_request-s for PLOOP_REQ_ZERO ops: firstly zero index
	 * for PLOOP_REQ_ZERO req_cluster, then schedule ordinary request
	 * pinned to given PLOOP_REQ_ZERO request */
	struct list_head	free_zero_list;

	/* storage for free-block extents: list for now */
	struct list_head	fbd_free_list;

	/* storage for reloc-block extents: list for now */
	struct list_head	fbd_reloc_list;

	int	 fbd_freezed_level; /* for sanity - level on
				     * PLOOP_IOC_FREEBLKS stage */

	struct bio_list	fbd_dbl; /* dbl stands for 'discard bio list' */
};

int ploop_fb_get_n_relocated(struct ploop_freeblks_desc *fbd)
{
	return fbd->fbd_n_relocated;
}
int ploop_fb_get_n_relocating(struct ploop_freeblks_desc *fbd)
{
	return fbd->fbd_n_relocating;
}
int ploop_fb_get_n_free(struct ploop_freeblks_desc *fbd)
{
	return fbd->fbd_n_free;
}
iblock_t ploop_fb_get_alloc_head(struct ploop_freeblks_desc *fbd)
{
	return fbd->fbd_first_lost_iblk + fbd->fbd_lost_range_len;
}
int ploop_fb_get_lost_range_len(struct ploop_freeblks_desc *fbd)
{
	return fbd->fbd_lost_range_len;
}
iblock_t ploop_fb_get_first_lost_iblk(struct ploop_freeblks_desc *fbd)
{
	return fbd->fbd_first_lost_iblk;
}

int ploop_fb_get_freezed_level(struct ploop_freeblks_desc *fbd)
{
	return fbd->fbd_freezed_level;
}
void ploop_fb_set_freezed_level(struct ploop_freeblks_desc *fbd, int level)
{
	fbd->fbd_freezed_level = level;
}

void ploop_fb_add_reloc_req(struct ploop_freeblks_desc *fbd,
			    struct ploop_request *preq)
{
	struct rb_node ** p;
	struct rb_node *parent = NULL;
	struct ploop_request * pr;

	if (fbd == NULL)
		return;

	p = &fbd->reloc_tree.rb_node;
	while (*p) {
		parent = *p;
		pr = rb_entry(parent, struct ploop_request, reloc_link);
		BUG_ON (preq->src_iblock == pr->src_iblock);

		if (preq->src_iblock < pr->src_iblock)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	rb_link_node(&preq->reloc_link, parent, p);
	rb_insert_color(&preq->reloc_link, &fbd->reloc_tree);
}

void ploop_fb_del_reloc_req(struct ploop_freeblks_desc *fbd,
			    struct ploop_request *preq)
{
	BUG_ON (fbd == NULL);

	rb_erase(&preq->reloc_link, &fbd->reloc_tree);
}

int ploop_fb_check_reloc_req(struct ploop_freeblks_desc *fbd,
			     struct ploop_request *preq,
			     unsigned long pin_state)
{
	struct rb_node *n;
	struct ploop_request * p;

	BUG_ON (fbd == NULL);
	BUG_ON (preq->iblock == 0);
	BUG_ON (preq->iblock >= fbd->fbd_first_lost_iblk);

	n = fbd->reloc_tree.rb_node;
	if (n == NULL)
		return 0;

	while (n) {
		p = rb_entry(n, struct ploop_request, reloc_link);

		if (preq->iblock < p->src_iblock)
			n = n->rb_left;
		else if (preq->iblock > p->src_iblock)
			n = n->rb_right;
		else {
			spin_lock_irq(&fbd->plo->lock);
			preq->eng_state = pin_state;
			list_add_tail(&preq->list, &p->delay_list);
			spin_unlock_irq(&fbd->plo->lock);
			return 1;
		}
	}
	return 0;
}

int ploop_fb_copy_freeblks_to_user(struct ploop_freeblks_desc *fbd, void *arg,
				   struct ploop_freeblks_ctl *ctl)
{
	int   rc = 0;
	int   n	 = 0;
	struct ploop_freeblks_extent	 *fextent;
	struct ploop_freeblks_ctl_extent  cext;

	list_for_each_entry(fextent, &fbd->fbd_free_list, list)
		if (ctl->n_extents) {
			int off = offsetof(struct ploop_freeblks_ctl,
					   extents[n]);
			if (n++ >= ctl->n_extents) {
				rc = -ENOSPC;
				break;
			}

			cext.clu  = fextent->clu;
			cext.iblk = fextent->iblk;
			cext.len  = fextent->len;

			rc = copy_to_user((u8*)arg + off, &cext, sizeof(cext));
			if (rc)
				break;
		} else {
			n++;
		}

	if (!rc) {
		ctl->n_extents = n;
		rc = copy_to_user((void*)arg, ctl, sizeof(*ctl));
	}

	return rc;
}

int ploop_fb_filter_freeblks(struct ploop_freeblks_desc *fbd, unsigned long minlen)
{
	struct ploop_freeblks_extent *fextent, *n;

	list_for_each_entry_safe(fextent, n, &fbd->fbd_free_list, list)
		if (fextent->len < minlen) {
			list_del(&fextent->list);
			fbd->fbd_n_free -= fextent->len;
			kfree(fextent);
		}

	if (list_empty(&fbd->fbd_free_list))
		fbd->fbd_ffb.ext = NULL;
	else
		fbd->fbd_ffb.ext = list_entry(fbd->fbd_free_list.next,
						struct ploop_freeblks_extent,
						list);
	fbd->fbd_ffb.off = 0;

	return fbd->fbd_n_free;
}

struct ploop_request *
ploop_fb_get_zero_request(struct ploop_freeblks_desc *fbd)
{
	struct ploop_request * preq;

	BUG_ON (fbd == NULL);
	BUG_ON (list_empty(&fbd->free_zero_list));

	preq = list_entry(fbd->free_zero_list.next,
			  struct ploop_request, list);
	list_del(&preq->list);
	return preq;
}

void ploop_fb_put_zero_request(struct ploop_freeblks_desc *fbd,
			       struct ploop_request *preq)
{
	list_add(&preq->list, &fbd->free_zero_list);
}

static iblock_t ffb_iblk(struct ploop_freeblks_desc *fbd)
{
	return fbd->fbd_ffb.ext->iblk + fbd->fbd_ffb.off;
}
static cluster_t ffb_clu(struct ploop_freeblks_desc *fbd)
{
	return fbd->fbd_ffb.ext->clu + fbd->fbd_ffb.off;
}
static iblock_t lfb_iblk(struct ploop_freeblks_desc *fbd)
{
	return fbd->fbd_lfb.ext->iblk + fbd->fbd_lfb.off;
}
static cluster_t lfb_clu(struct ploop_freeblks_desc *fbd)
{
	return fbd->fbd_lfb.ext->clu + fbd->fbd_lfb.off;
}
static iblock_t lrb_iblk(struct ploop_freeblks_desc *fbd)
{
	return fbd->fbd_lrb.ext->iblk + fbd->fbd_lrb.off;
}

static iblock_t get_first_reloc_iblk(struct ploop_freeblks_desc *fbd)
{
	struct ploop_relocblks_extent *r_extent;

	BUG_ON (list_empty(&fbd->fbd_reloc_list));
	r_extent = list_entry(fbd->fbd_reloc_list.next,
			      struct ploop_relocblks_extent, list);
	return r_extent->iblk;
}

static void advance_ffb_simple(struct ploop_freeblks_desc *fbd)
{
	BUG_ON (fbd->fbd_ffb.ext == NULL);

	if (fbd->fbd_ffb.off < fbd->fbd_ffb.ext->len - 1) {
		fbd->fbd_ffb.off++;
	} else {
		if (fbd->fbd_ffb.ext->list.next == &fbd->fbd_free_list)
			fbd->fbd_ffb.ext = NULL;
		else
			fbd->fbd_ffb.ext = list_entry(fbd->fbd_ffb.ext->list.next,
						      struct ploop_freeblks_extent,
						      list);
		fbd->fbd_ffb.off = 0;
	}

	if (fbd->fbd_ffb.ext != NULL &&
	    ffb_iblk(fbd) >= fbd->fbd_first_lost_iblk) {
		/* invalidate ffb */
		fbd->fbd_ffb.ext = NULL;
		fbd->fbd_ffb.off = 0;
	}
}

static void advance_lrb(struct ploop_freeblks_desc *fbd)
{
	iblock_t skip = 0;
	BUG_ON (fbd->fbd_lrb.ext == NULL);

	if (likely(fbd->fbd_lrb.off)) {
		fbd->fbd_lrb.off--;
	} else {
		struct ploop_relocblks_extent *r_extent = fbd->fbd_lrb.ext;
		/* here 'skip' means: [new_lrb_ext]<--skip-->[r_extent] */

		if (fbd->fbd_lrb.ext->list.prev == &fbd->fbd_reloc_list) {
			BUG_ON (fbd->fbd_lost_range_addon < 0);
			skip = fbd->fbd_lost_range_addon;
			fbd->fbd_lrb.ext = NULL;
		} else {
			fbd->fbd_lrb.ext = list_entry(fbd->fbd_lrb.ext->list.prev,
						      struct ploop_relocblks_extent,
						      list);
			fbd->fbd_lrb.off = fbd->fbd_lrb.ext->len - 1;
			BUG_ON (r_extent->iblk < fbd->fbd_lrb.ext->iblk +
						 fbd->fbd_lrb.ext->len);
			skip = r_extent->iblk - (fbd->fbd_lrb.ext->iblk +
						 fbd->fbd_lrb.ext->len);
		}
	}

	fbd->fbd_first_lost_iblk -= 1 + skip;
	fbd->fbd_lost_range_len	 += 1 + skip;

	if (fbd->fbd_ffb.ext != NULL &&
	    ffb_iblk(fbd) >= fbd->fbd_first_lost_iblk) {
		/* invalidate ffb */
		fbd->fbd_ffb.ext = NULL;
		fbd->fbd_ffb.off = 0;
	}

	BUG_ON(fbd->fbd_n_free <= 0);
	fbd->fbd_n_free--;
}

static int split_fb_extent(struct ploop_freeblks_extent *extent, u32 *off_p,
			   struct ploop_freeblks_desc *fbd)
{
	struct ploop_freeblks_extent *new_extent;

	new_extent = kzalloc(sizeof(*new_extent), GFP_KERNEL);
	if (new_extent == NULL) {
		printk("Can't allocate new freeblks extent for splittig!\n");
		return -ENOMEM;
	}

	new_extent->clu	 = extent->clu	+ *off_p + 1;
	new_extent->iblk = extent->iblk + *off_p + 1;
	new_extent->len	 = extent->len	- *off_p - 1;

	extent->len  = *off_p;

	list_add(&new_extent->list, &extent->list);

	(*off_p)--;
	return 0;
}

static int advance_lfb_left(struct ploop_freeblks_desc *fbd)
{
	int rc = 0;
	struct ploop_freeblks_extent *lfb_ext = fbd->fbd_lfb.ext;

	BUG_ON (fbd->fbd_ffb.ext == NULL);
	BUG_ON (lfb_ext == NULL);
	BUG_ON (ffb_iblk(fbd) > lfb_iblk(fbd));

	if (ffb_iblk(fbd) == lfb_iblk(fbd)) {
		/* invalidate lfb */
		fbd->fbd_lfb.ext = NULL;
		fbd->fbd_lfb.off = 0;
		advance_ffb_simple(fbd);
		return 0;
	}

	if (fbd->fbd_lfb.off) {
		if (fbd->fbd_lfb.off == lfb_ext->len - 1) {
			lfb_ext->len--;
			fbd->fbd_lfb.off--;
		} else {
			rc = split_fb_extent(lfb_ext, &fbd->fbd_lfb.off, fbd);
		}
	} else {
		BUG_ON (lfb_ext->list.prev == &fbd->fbd_free_list);
		BUG_ON (lfb_ext == fbd->fbd_ffb.ext);

		lfb_ext->clu++;
		lfb_ext->iblk++;
		lfb_ext->len--;

		fbd->fbd_lfb.ext = list_entry(lfb_ext->list.prev,
					      struct ploop_freeblks_extent,
					      list);
		fbd->fbd_lfb.off = fbd->fbd_lfb.ext->len - 1;

		if (lfb_ext->len == 0) {
			list_del(&lfb_ext->list);
			kfree(lfb_ext);
		}
	}

	BUG_ON (fbd->fbd_ffb.ext == NULL);
	BUG_ON (fbd->fbd_lfb.ext == NULL);
	BUG_ON (lfb_iblk(fbd) < ffb_iblk(fbd));
	return rc;
}

int ploop_fb_get_reloc_block(struct ploop_freeblks_desc *fbd,
			     cluster_t *from_clu_p, iblock_t *from_iblk_p,
			     cluster_t *to_clu_p, iblock_t *to_iblk_p,
			     u32 *free_p)
{
	cluster_t from_clu, to_clu;
	iblock_t  from_iblk, to_iblk;
	u32 free;
	struct ploop_relocblks_extent *r_extent;

	if (!fbd)
		return -1;

	r_extent = fbd->fbd_lrb.ext;
	/* whole range is drained? */
	if (r_extent == NULL)
		return -1;

	BUG_ON (fbd->fbd_lrb.off >= r_extent->len);

	from_clu  = r_extent->clu  + fbd->fbd_lrb.off;
	from_iblk = r_extent->iblk + fbd->fbd_lrb.off;
	free	  = r_extent->free;

	/* from_iblk is in range to relocate, but it's marked as free.
	 * This means that we only need to zero its index, no actual
	 * relocation needed. Such an operation doesn't consume free
	 * block that fbd_last_free refers to */
	if (free) {
		/* The block we're going to zero-index was already re-used? */
		if (fbd->fbd_ffb.ext == NULL || ffb_iblk(fbd) > from_iblk)
			return -1;

		BUG_ON (fbd->fbd_ffb.off  >= fbd->fbd_ffb.ext->len);

		to_iblk = ~0U;
		to_clu	= ~0U;
	} else {
		/* run out of free blocks which can be used as destination
		 * for relocation ? */
		if (fbd->fbd_lfb.ext == NULL)
			return -1;

		BUG_ON (fbd->fbd_ffb.ext == NULL);
		BUG_ON (fbd->fbd_ffb.off  >= fbd->fbd_ffb.ext->len);
		BUG_ON (fbd->fbd_lfb.off  >= fbd->fbd_lfb.ext->len);
		BUG_ON (ffb_iblk(fbd) > lfb_iblk(fbd));

		to_clu	= lfb_clu(fbd);
		to_iblk = lfb_iblk(fbd);

		if (advance_lfb_left(fbd)) {
			/* Error implies stopping relocation */
			fbd->fbd_lrb.ext = NULL;
			fbd->fbd_lrb.off = 0;
			return -1;
		}
	}

	/* consume one block from the end of reloc list */
	advance_lrb(fbd);

	fbd->fbd_n_relocating++;

	*from_clu_p  = from_clu;
	*from_iblk_p = from_iblk;
	*to_clu_p    = to_clu;
	*to_iblk_p   = to_iblk;
	*free_p	     = free;
	return 0;
}

void ploop_fb_relocate_req_completed(struct ploop_freeblks_desc *fbd)
{
	fbd->fbd_n_relocated++;
}

static void advance_lfb_right(struct ploop_freeblks_desc *fbd)
{
	iblock_t iblk = get_first_reloc_iblk(fbd);

	if (fbd->fbd_lfb.off < fbd->fbd_lfb.ext->len - 1) {
		if (fbd->fbd_lfb.ext->iblk + fbd->fbd_lfb.off + 1 < iblk) {
			fbd->fbd_lfb.off++;
		}
	} else if (fbd->fbd_lfb.ext->list.next != &fbd->fbd_free_list) {
		struct ploop_freeblks_extent *f_extent;
		f_extent = list_entry(fbd->fbd_lfb.ext->list.next,
				      struct ploop_freeblks_extent,
				      list);
		if (f_extent->iblk < iblk) {
			fbd->fbd_lfb.ext = f_extent;
			fbd->fbd_lfb.off = 0;
		}
	}

	/* invalidating ffb always implies invalidating lfb */
	BUG_ON (fbd->fbd_ffb.ext == NULL && fbd->fbd_lfb.ext != NULL);

	/* caller has just advanced ffb, but we must keep lfb intact
	 * if next-free-block (following to lfb) is in reloc-range */
	if (fbd->fbd_ffb.ext != NULL && fbd->fbd_lfb.ext != NULL &&
	    lfb_iblk(fbd) < ffb_iblk(fbd)) {
		fbd->fbd_lfb.ext = NULL;
		fbd->fbd_lfb.off = 0;
	}
}

static void trim_reloc_list_one_blk(struct ploop_freeblks_desc *fbd)
{
	struct ploop_relocblks_extent *r_extent_first;
	iblock_t iblk = lrb_iblk(fbd);
	int invalidate = 0;

	BUG_ON (list_empty(&fbd->fbd_reloc_list));
	r_extent_first = list_entry(fbd->fbd_reloc_list.next,
				    struct ploop_relocblks_extent, list);

	if (r_extent_first->len > 1) {
		fbd->fbd_lost_range_addon = 0;
		r_extent_first->iblk++;
		r_extent_first->clu++;
		r_extent_first->len--;
		if (iblk < r_extent_first->iblk) {
			invalidate = 1;
		} else if (r_extent_first == fbd->fbd_lrb.ext) {
			BUG_ON (fbd->fbd_lrb.off == 0);
			fbd->fbd_lrb.off--;
		}
	} else {
		if (r_extent_first == fbd->fbd_lrb.ext) {
			invalidate = 1;
		} else {
			struct ploop_relocblks_extent *r_extent;
			BUG_ON (r_extent_first->list.next ==
				&fbd->fbd_reloc_list);
			r_extent = list_entry(r_extent_first->list.next,
					      struct ploop_relocblks_extent,
					      list);
			fbd->fbd_lost_range_addon = r_extent->iblk -
				(r_extent_first->iblk + r_extent_first->len);
		}
		list_del(&r_extent_first->list);
		kfree(r_extent_first);
	}

	if (invalidate) {
		/* invalidate both lfb and lrb */
		fbd->fbd_lrb.ext = NULL;
		fbd->fbd_lrb.off = 0;
		if (fbd->fbd_lfb.ext != NULL) {
			fbd->fbd_lfb.ext = NULL;
			fbd->fbd_lfb.off = 0;
		}
	}
}

static void advance_ffb(struct ploop_freeblks_desc *fbd)
{
	BUG_ON (fbd->fbd_ffb.ext == NULL);
	BUG_ON (fbd->fbd_lfb.ext != NULL && ffb_iblk(fbd) > lfb_iblk(fbd));

	if (fbd->fbd_ffb.off < fbd->fbd_ffb.ext->len - 1) {
		fbd->fbd_ffb.off++;
	} else {
		if (fbd->fbd_ffb.ext->list.next == &fbd->fbd_free_list) {
			BUG_ON (fbd->fbd_lfb.ext != NULL &&
				ffb_iblk(fbd) != lfb_iblk(fbd));
			fbd->fbd_ffb.ext = NULL;
		} else {
			fbd->fbd_ffb.ext = list_entry(fbd->fbd_ffb.ext->list.next,
						      struct ploop_freeblks_extent,
						      list);
		}
		fbd->fbd_ffb.off = 0;
	}

	if (fbd->fbd_ffb.ext == NULL && fbd->fbd_lfb.ext != NULL) {
		/* invalidate lfb */
		fbd->fbd_lfb.ext = NULL;
		fbd->fbd_lfb.off = 0;
		return;
	}

	if (fbd->fbd_ffb.ext != NULL &&
	    ffb_iblk(fbd) >= fbd->fbd_first_lost_iblk) {
		/* invalidate both ffb and lfb */
		fbd->fbd_ffb.ext = NULL;
		fbd->fbd_ffb.off = 0;
		fbd->fbd_lfb.ext = NULL;
		fbd->fbd_lfb.off = 0;
	}

	/* nothing to do anymore if relocation process is completed */
	if (fbd->fbd_lrb.ext == NULL)
		return;

	trim_reloc_list_one_blk(fbd);

	/* trim could invalidate both lrb and lfb */
	if (fbd->fbd_lrb.ext == NULL || fbd->fbd_lfb.ext == NULL)
		return;

	advance_lfb_right(fbd);
}

int ploop_fb_get_free_block(struct ploop_freeblks_desc *fbd,
			    cluster_t *clu, iblock_t *iblk)
{
	if (!fbd)
		return -1;

	if (fbd->fbd_ffb.ext == NULL) {
		BUG_ON (fbd->fbd_lfb.ext != NULL);
		BUG_ON (fbd->fbd_lost_range_len < 0);

		if (fbd->fbd_lost_range_len == 0)
			return -1;

		*iblk = fbd->fbd_first_lost_iblk++;
		fbd->fbd_lost_range_len--;

		if (fbd->fbd_lrb.ext != NULL) {
			/* stop relocation process */
			fbd->fbd_lrb.ext = NULL;
			fbd->fbd_lrb.off = 0;
		}

		return 0;
	}

	BUG_ON (ffb_iblk(fbd) >= fbd->fbd_first_lost_iblk);
	BUG_ON (fbd->fbd_n_free <= 0);

	*clu = ffb_clu(fbd);
	fbd->fbd_n_free--;

	if (fbd->plo->maintenance_type == PLOOP_MNTN_RELOC)
		advance_ffb(fbd);
	else
		advance_ffb_simple(fbd);

	BUG_ON (fbd->fbd_ffb.ext == NULL && fbd->fbd_n_free != 0);
	BUG_ON (fbd->fbd_ffb.ext != NULL && fbd->fbd_n_free == 0);

	return 1;
}

static void fbd_complete_bio(struct ploop_freeblks_desc *fbd, int err)
{
	unsigned int nr_completed = 0;

	while (fbd->fbd_dbl.head) {
		struct bio * bio = fbd->fbd_dbl.head;
		fbd->fbd_dbl.head = bio->bi_next;
		bio->bi_next = NULL;
		BIO_ENDIO(fbd->plo->queue, bio, err);
		nr_completed++;
	}
	fbd->fbd_dbl.tail = NULL;

	spin_lock_irq(&fbd->plo->lock);
	fbd->plo->bio_total -= nr_completed;
	spin_unlock_irq(&fbd->plo->lock);
}

void ploop_fb_reinit(struct ploop_freeblks_desc *fbd, int err)
{
	fbd_complete_bio(fbd, err);

	while (!list_empty(&fbd->fbd_free_list)) {
		struct ploop_freeblks_extent *fblk_extent;

		fblk_extent = list_first_entry(&fbd->fbd_free_list,
					       struct ploop_freeblks_extent,
					       list);
		list_del(&fblk_extent->list);
		kfree(fblk_extent);
	}

	while (!list_empty(&fbd->fbd_reloc_list)) {
		struct ploop_relocblks_extent *rblk_extent;

		rblk_extent = list_first_entry(&fbd->fbd_reloc_list,
					       struct ploop_relocblks_extent,
					       list);
		list_del(&rblk_extent->list);
		kfree(rblk_extent);
	}

	fbd->fbd_n_free = 0;
	fbd->fbd_ffb.ext = NULL;
	fbd->fbd_lfb.ext = NULL;
	fbd->fbd_lrb.ext = NULL;
	fbd->fbd_ffb.off = 0;
	fbd->fbd_lfb.off = 0;
	fbd->fbd_lrb.off = 0;
	fbd->fbd_n_relocated = fbd->fbd_n_relocating = 0;
	fbd->fbd_lost_range_len = 0;
	fbd->fbd_lost_range_addon = 0;

	BUG_ON(!RB_EMPTY_ROOT(&fbd->reloc_tree));
}

struct ploop_freeblks_desc *ploop_fb_init(struct ploop_device *plo)
{
	struct ploop_freeblks_desc *fbd;
	int i;

	fbd = kmalloc(sizeof(struct ploop_freeblks_desc), GFP_KERNEL);
	if (fbd == NULL)
		return NULL;

	fbd->fbd_dbl.tail = fbd->fbd_dbl.head = NULL;
	INIT_LIST_HEAD(&fbd->fbd_free_list);
	INIT_LIST_HEAD(&fbd->fbd_reloc_list);
	fbd->reloc_tree = RB_ROOT;
	fbd->fbd_freezed_level = -1;

	fbd->plo = plo;

	ploop_fb_reinit(fbd, 0);

	INIT_LIST_HEAD(&fbd->free_zero_list);
	for (i = 0; i < plo->tune.max_requests; i++) {
		struct ploop_request * preq;
		preq = kzalloc(sizeof(struct ploop_request), GFP_KERNEL);
		if (preq == NULL)
			goto fb_init_failed;

		preq->plo = plo;
		INIT_LIST_HEAD(&preq->delay_list);
		list_add(&preq->list, &fbd->free_zero_list);
	}

	return fbd;

fb_init_failed:
	ploop_fb_fini(fbd, -ENOMEM);
	return NULL;
}

void ploop_fb_fini(struct ploop_freeblks_desc *fbd, int err)
{
	struct ploop_device *plo;

	if (fbd == NULL)
		return;

	plo = fbd->plo;
	BUG_ON (plo == NULL);

	fbd_complete_bio(fbd, err);

	while (!list_empty(&fbd->fbd_free_list)) {
		struct ploop_freeblks_extent *fblk_extent;

		fblk_extent = list_first_entry(&fbd->fbd_free_list,
					       struct ploop_freeblks_extent,
					       list);
		list_del(&fblk_extent->list);
		kfree(fblk_extent);
	}

	while (!list_empty(&fbd->fbd_reloc_list)) {
		struct ploop_relocblks_extent *rblk_extent;

		rblk_extent = list_first_entry(&fbd->fbd_reloc_list,
					       struct ploop_relocblks_extent,
					       list);
		list_del(&rblk_extent->list);
		kfree(rblk_extent);
	}

	while (!list_empty(&fbd->free_zero_list)) {
		struct ploop_request * preq;

		preq = list_first_entry(&fbd->free_zero_list,
					struct ploop_request,
					list);
		list_del(&preq->list);
		kfree(preq);
	}

	kfree(fbd);
	plo->fbd = NULL;
}

int ploop_fb_add_free_extent(struct ploop_freeblks_desc *fbd,
			     cluster_t clu, iblock_t iblk, u32 len)
{
	struct ploop_freeblks_extent *fblk_extent;
	struct ploop_freeblks_extent *ex;

	if (len == 0) {
		printk("ploop_fb_add_free_extent(): empty extent! (%u/%u)\n",
		       clu, iblk);
		return 0;
	}

	list_for_each_entry_reverse(ex, &fbd->fbd_free_list, list)
		if (ex->iblk < iblk)
			break;

	if (ex->list.next != &fbd->fbd_free_list) {
		struct ploop_freeblks_extent *tmp;
		tmp = list_entry(ex->list.next, struct ploop_freeblks_extent, list);

		if (iblk + len > tmp->iblk) {
			printk("ploop_fb_add_free_extent(): intersected extents");
			return -EINVAL;
		}
	}

	if (&ex->list != &fbd->fbd_free_list) {
		if (ex->iblk + ex->len > iblk) {
			printk("ploop_fb_add_free_extent(): intersected extents");
			return -EINVAL;
		}
	}

	fblk_extent = kzalloc(sizeof(*fblk_extent), GFP_KERNEL);
	if (fblk_extent == NULL)
		return -ENOMEM;

	fblk_extent->clu  = clu;
	fblk_extent->iblk = iblk;
	fblk_extent->len  = len;

	list_add(&fblk_extent->list, &ex->list);

	fbd->fbd_n_free	 += len;

	fbd->fbd_ffb.ext = list_entry(fbd->fbd_free_list.next, struct ploop_freeblks_extent, list);
	fbd->fbd_ffb.off = 0;

	return 0;
}

int ploop_fb_add_reloc_extent(struct ploop_freeblks_desc *fbd,
			      cluster_t clu, iblock_t iblk, u32 len, u32 free)
{
	struct ploop_relocblks_extent *rblk_extent;

	if (len == 0) {
		printk("ploop_fb_add_reloc_extent(): empty extent! (%u/%u)\n",
		       clu, iblk);
		return 0;
	}

	if (!list_empty(&fbd->fbd_reloc_list)) {
		rblk_extent = list_entry(fbd->fbd_reloc_list.prev,
					 struct ploop_relocblks_extent, list);
		if (rblk_extent->iblk + rblk_extent->len > iblk) {
			printk("ploop_fb_add_reloc_extent(): extents should be sorted");
			return -EINVAL;
		}

		if (rblk_extent->list.next != &fbd->fbd_reloc_list) {
			rblk_extent = list_entry(rblk_extent->list.next,
					 struct ploop_relocblks_extent, list);
			if (iblk + len > rblk_extent->iblk) {
				printk("ploop_fb_add_reloc_extent(): intersected extents");
				return -EINVAL;
			}
		}
	}

	rblk_extent = kzalloc(sizeof(*rblk_extent), GFP_KERNEL);
	if (rblk_extent == NULL)
		return -ENOMEM;

	rblk_extent->clu  = clu;
	rblk_extent->iblk = iblk;
	rblk_extent->len  = len;
	rblk_extent->free = free;

	list_add_tail(&rblk_extent->list, &fbd->fbd_reloc_list);

	return 0;
}

void ploop_fb_lost_range_init(struct ploop_freeblks_desc *fbd,
			      iblock_t first_lost_iblk)
{
	fbd->fbd_first_lost_iblk = first_lost_iblk;
	fbd->fbd_lost_range_len = 0;
}

void ploop_fb_relocation_start(struct ploop_freeblks_desc *fbd,
			       __u32 n_scanned)
{
	iblock_t a_h = fbd->fbd_first_lost_iblk;
	iblock_t new_a_h; /* where a_h will be after relocation
			     if no WRITEs intervene */
	struct ploop_relocblks_extent *r_extent;
	struct ploop_relocblks_extent *r_extent_first;
	int n_free = fbd->fbd_n_free;
	u32 l;
	struct ploop_freeblks_extent *fextent;

	BUG_ON(fbd->fbd_lost_range_len != 0);
	if (list_empty(&fbd->fbd_reloc_list)) {
		fbd->fbd_first_lost_iblk -= n_scanned;
		fbd->fbd_lost_range_len	 += n_scanned;
		return;
	}

	r_extent_first = list_entry(fbd->fbd_reloc_list.next,
				    struct ploop_relocblks_extent, list);
	r_extent = list_entry(fbd->fbd_reloc_list.prev,
			      struct ploop_relocblks_extent, list);
	new_a_h = r_extent->iblk + r_extent->len;

	BUG_ON(fbd->fbd_first_lost_iblk < new_a_h);
	fbd->fbd_lost_range_len = fbd->fbd_first_lost_iblk - new_a_h;
	fbd->fbd_first_lost_iblk = new_a_h;

	if (!n_free)
		return;

	while (1) {
		l = MIN(n_free, r_extent->len);

		n_free	-= l;
		new_a_h -= l;

		if (!n_free)
			break;

		if (r_extent->list.prev == &fbd->fbd_reloc_list) {
			r_extent = NULL;
			break;
		} else {
			r_extent = list_entry(r_extent->list.prev,
					      struct ploop_relocblks_extent,
					      list);
		}
		/* skip lost blocks */
		new_a_h = r_extent->iblk + r_extent->len;
	}

	l = 0;

	/* ploop-balloon scanned exactly range [a_h - n_scanned .. a_h - 1] */
	if (n_free) {
		l = r_extent_first->iblk - (a_h - n_scanned);
	} else if (r_extent->iblk == new_a_h) {
		if (r_extent == r_extent_first) {
			l = r_extent->iblk - (a_h - n_scanned);
		} else {
			struct ploop_relocblks_extent *r_extent_prev;

			BUG_ON (r_extent->list.prev == &fbd->fbd_reloc_list);
			r_extent_prev = list_entry(r_extent->list.prev,
						   struct ploop_relocblks_extent,
						   list);
			l = r_extent->iblk - (r_extent_prev->iblk +
					      r_extent_prev->len);
		}
	}

	new_a_h -= l;

	/* let's trim reloc_list a bit based on new_a_h */
	while (r_extent_first->iblk < new_a_h) {

		if (r_extent_first->iblk + r_extent_first->len > new_a_h) {
			l = new_a_h - r_extent_first->iblk;
			r_extent_first->iblk += l;
			r_extent_first->clu  += l;
			r_extent_first->len  -= l;
			break;
		}

		if (r_extent_first->list.next == &fbd->fbd_reloc_list) {
			list_del(&r_extent_first->list);
			kfree(r_extent_first);
			break;
		}

		list_del(&r_extent_first->list);
		kfree(r_extent_first);
		r_extent_first = list_entry(fbd->fbd_reloc_list.next,
					    struct ploop_relocblks_extent,
					    list);
	}

	if (!list_empty(&fbd->fbd_reloc_list)) {
		fbd->fbd_lrb.ext = list_entry(fbd->fbd_reloc_list.prev,
					      struct ploop_relocblks_extent,
					      list);
		fbd->fbd_lrb.off = fbd->fbd_lrb.ext->len - 1;

		fbd->fbd_lost_range_addon = r_extent_first->iblk - new_a_h;
	}

	/* new_a_h is calculated. now, let's find "last free block" position */
	if (ffb_iblk(fbd) < new_a_h) {
		list_for_each_entry_reverse(fextent, &fbd->fbd_free_list, list)
			if (fextent->iblk < new_a_h)
				break;

		BUG_ON(&fextent->list == &fbd->fbd_free_list);
	} else
		fextent = NULL;

	fbd->fbd_lfb.ext = fextent; /* NULL means
				       "no free blocks for relocation" */
	if (fextent != NULL)
		fbd->fbd_lfb.off = MIN(new_a_h - fextent->iblk,
				       fextent->len) - 1;
}

int ploop_discard_add_bio(struct ploop_freeblks_desc *fbd, struct bio *bio)
{
	struct ploop_device *plo;

	if (!fbd)
		return -EOPNOTSUPP;

	plo = fbd->plo;

	if (!test_bit(PLOOP_S_DISCARD, &plo->state))
		return -EOPNOTSUPP;
	if (fbd->plo->maintenance_type != PLOOP_MNTN_DISCARD)
		return -EBUSY;
	/* only one request can be processed simultaneously */
	if (fbd->fbd_dbl.head)
		return -EBUSY;

	fbd->fbd_dbl.head = fbd->fbd_dbl.tail = bio;

	return 0;
}

int ploop_discard_is_inprogress(struct ploop_freeblks_desc *fbd)
{
	return fbd && fbd->fbd_dbl.head != NULL;
}
