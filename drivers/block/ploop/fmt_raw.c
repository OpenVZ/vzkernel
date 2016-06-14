/*
 *  drivers/block/ploop/fmt_raw.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/file.h>

#include <linux/ploop/ploop.h>

/* An implementation of raw linear image format.
 *
 * Right now it is not quite optimal because we simulate
 * raw image as ploop1-like image with dummy preallocated
 * index tables. It is optimized only when we have
 * just one raw image without any deltas on top.
 * Probably, this is all that we need.
 */

static int raw_stop(struct ploop_delta * delta)
{
	return delta->io.ops->sync(&delta->io);
}

static int
raw_compose(struct ploop_delta * delta, int nchunks, struct ploop_ctl_chunk * pc)
{
	return ploop_io_init(delta, nchunks, pc);
}

static int
raw_open(struct ploop_delta * delta)
{
	int err;
	loff_t pos;
	int cluster_log = list_empty(&delta->plo->map.delta_list) ?
		delta->cluster_log : delta->plo->cluster_log;

	err = ploop_io_open(&delta->io);
	if (err)
		return err;

	if (delta->plo->bd_size) {
		if (delta->plo->bd_size > (delta->io.ops->i_size_read(&delta->io) >> 9))
			return -EINVAL;
	} else {
		delta->plo->bd_size = delta->io.ops->i_size_read(&delta->io) >> 9;
	}

	pos = delta->io.ops->i_size_read(&delta->io);
	pos += (1 << (cluster_log + 9)) - 1;
	delta->io.alloc_head = pos >> (cluster_log + 9);

	/* no more allocations at all */
	delta->flags |= PLOOP_FMT_PREALLOCATED;

	return 0;
}

/*
 * Sanity checks below assumes that we can be called only by
 * ploop_del_delta() or raw_start_merge(). Thus, there recently
 * was a ploop1 delta above us. Adding ploop1 delta on the top
 * of raw delta is only supported if raw delta is cluster-block
 * aligned.
 *
 * Another assumption is that either size of raw delta was
 * kept unchanged or it was grown in user-space while merging.
 */
static int
raw_refresh(struct ploop_delta * delta)
{
	loff_t pos;

	pos = delta->io.ops->i_size_read(&delta->io);
	if (pos & ((1 << (delta->plo->cluster_log + 9)) - 1)) {
		printk("raw delta is not aligned (%llu bytes)\n", pos);
		return -EINVAL;
	}
	if ((pos >> (delta->plo->cluster_log + 9)) < delta->io.alloc_head) {
		printk("raw delta was corrupted "
		       "(old_size=%u new_size=%llu iblocks)\n",
		       delta->io.alloc_head,
		       pos >> (delta->plo->cluster_log + 9));
		return -EINVAL;
	}

	delta->io.alloc_head = pos >> (delta->plo->cluster_log + 9);
	return 0;
}

static void
raw_allocate(struct ploop_delta * delta, struct ploop_request * preq,
		struct bio_list * sbl, unsigned int size)
{
	delta->io.ops->submit_alloc(&delta->io, preq, sbl, size);
}

int raw_map_index(struct ploop_delta * delta, unsigned long index, sector_t *sec)
{
	*sec = index;
	return 1;
}

static void
raw_read_index(struct ploop_delta * delta, struct ploop_request * preq,
	       struct page * page, sector_t sec)
{
	int i;
	u32 * ptr = page_address(page);
	int skip = (sec == 0) ? PLOOP_MAP_OFFSET : 0;

	for (i = skip; i < PAGE_SIZE/4; i++) {
		if ((sec << delta->plo->cluster_log) >=
		    (delta->io.alloc_head << delta->plo->cluster_log)) {
			ptr[i] = 0;
			sec++;
		} else if (sec == 0) {
			/* ptr[i]==0 would be interpreted as "iblock not alloced" */
			ptr[i] = PLOOP_ZERO_INDEX;
			sec++;
		} else {
			ptr[i] = sec++ << ploop_map_log(delta->plo);
		}
	}

	ploop_complete_io_state(preq);
}

static void
raw_destroy(struct ploop_delta * delta)
{
	ploop_io_destroy(&delta->io);
}

static int
raw_start(struct ploop_delta * delta)
{
	return 0;
//	return delta->io.ops->start(&delta->io);
}

static int
raw_prepare_snapshot(struct ploop_delta * delta, struct ploop_snapdata * sd)
{
	return delta->io.ops->prepare_snapshot(&delta->io, sd);
}

static int
raw_complete_snapshot(struct ploop_delta * delta, struct ploop_snapdata * sd)
{
	int err = 0;

	if (delta->flags & PLOOP_FMT_RDONLY)
		goto out;

	err = -EIO;
	if (test_bit(PLOOP_S_ABORT, &delta->plo->state))
		goto out;

	err = delta->io.ops->sync(&delta->io);
	if (err)
		goto out;

	err = delta->io.ops->complete_snapshot(&delta->io, sd);
	if (err)
		goto out;

	delta->flags |= PLOOP_FMT_RDONLY;
	return 0;

out:
	if (sd->file) {
		fput(sd->file);
		sd->file = NULL;
	}
	return err;
}

static int
raw_prepare_merge(struct ploop_delta * delta, struct ploop_snapdata * sd)
{
	int err;

	err = delta->io.ops->prepare_merge(&delta->io, sd);
	if (err)
		return err;

	delta->flags &= ~PLOOP_FMT_RDONLY;
	return 0;
}

static int
raw_start_merge(struct ploop_delta * delta, struct ploop_snapdata * sd)
{
	int err;

	err = delta->io.ops->start_merge(&delta->io, sd);
	if (err)
		return err;

	if (test_bit(PLOOP_S_ABORT, &delta->plo->state)) {
		printk(KERN_WARNING "raw_start_merge for ploop%d failed "
		       "(state ABORT)\n", delta->plo->index);
		return -EIO;
	}

	err = raw_refresh(delta);
	if (err)
		return err;

	return delta->io.ops->sync(&delta->io);
}


static int
raw_prepare_grow(struct ploop_delta * delta, u64 *new_size, int *reloc)
{
	*new_size = (*new_size + (PAGE_SIZE >> 9) - 1) &
		    ~((PAGE_SIZE >> 9) - 1);
	return delta->io.ops->alloc(&delta->io,
				    delta->plo->bd_size << 9,
				    (*new_size - delta->plo->bd_size) << 9);
}

static struct ploop_delta_ops raw_delta_ops =
{
	.id		=	PLOOP_FMT_RAW,
	.name		=	"raw",
	.owner		=	THIS_MODULE,
	.capability	=	PLOOP_FMT_CAP_WRITABLE|PLOOP_FMT_CAP_IDENTICAL,

	.map_index	=	raw_map_index,
	.read_index	=	raw_read_index,

	.allocate	=	raw_allocate,

	.compose	=	raw_compose,
	.open		=	raw_open,
	.destroy	=	raw_destroy,
	.start		=	raw_start,
	.stop		=	raw_stop,
	.refresh	=	raw_refresh,
	.prepare_snapshot =	raw_prepare_snapshot,
	.complete_snapshot =	raw_complete_snapshot,
	.prepare_merge	=	raw_prepare_merge,
	.start_merge	=	raw_start_merge,
	.prepare_grow	=	raw_prepare_grow,
};

static int __init pfmt_raw_mod_init(void)
{
	return ploop_register_format(&raw_delta_ops);
}

static void __exit pfmt_raw_mod_exit(void)
{
	ploop_unregister_format(&raw_delta_ops);
}

module_init(pfmt_raw_mod_init);
module_exit(pfmt_raw_mod_exit);

MODULE_LICENSE("GPL");
