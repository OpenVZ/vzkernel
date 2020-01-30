/*
 *  drivers/block/ploop/fmt_ploop1.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/file.h>

#include <linux/ploop/ploop.h>
#include "ploop1_image.h"
#include "map.h"

/* The implementaion of ploop1 (PVD) delta format, defined in ploop1_fmt.h
 */

struct ploop1_private
{
	struct page	*dyn_page;
	u64		bd_size;
	u32		alloc_head;
	sector_t	l1_off;
	u32		nr_bat_entries;
	u32		nr_clusters_in_bitmap;
};

static void ploop_set_holes_bitmap_bit(unsigned int nr, struct ploop_delta *delta)
{
	struct ploop1_private *ph = delta->priv;

	if (WARN_ON_ONCE(nr >= ph->nr_clusters_in_bitmap)) {
		pr_err("nr=%u, nr_clusters=%u\n", nr, ph->nr_clusters_in_bitmap);
		return;
	}

	set_bit(nr, delta->holes_bitmap);
}

static void ploop_clear_holes_bitmap_bit(unsigned int nr, struct ploop_delta *delta)
{
	struct ploop1_private *ph = delta->priv;

	if (WARN_ON_ONCE(nr >= ph->nr_clusters_in_bitmap)) {
		pr_err("nr=%u, nr_clusters=%u\n", nr, ph->nr_clusters_in_bitmap);
		return;
	}

	clear_bit(nr, delta->holes_bitmap);
}

int ploop1_map_index(struct ploop_delta * delta, unsigned long block, sector_t *sec)
{
	struct ploop1_private * ph = delta->priv;

	if ((u64)block << delta->plo->cluster_log >= ph->bd_size)
		return 0;

	/*
	 * ondisk_pageno == (block + off) >> INDEX_PER_PAGE_SHIFT
	 * sec == ondisk_pageno << (PAGE_SHIFT - 9)
	 * (8 sectors per page, and log(8) == PAGE_SHIFT - 9)
	 */
	*sec = ((block + PLOOP_MAP_OFFSET) >> INDEX_PER_PAGE_SHIFT) <<
	       (PAGE_SHIFT - 9);
	return 1;
}

static void
ploop1_read_index(struct ploop_delta * delta, struct ploop_request * preq,
		  struct page * page, sector_t sec)
{
	return delta->io.ops->read_page(&delta->io, preq, page, sec);
}

static void
ploop1_destroy_priv(struct ploop_delta * delta)
{
	struct ploop1_private * ph = delta->priv;

	if (ph == NULL)
		return;

	delta->priv = NULL;

	if (ph->dyn_page)
		put_page(ph->dyn_page);

	kfree(ph);
}

static int ploop1_stop(struct ploop_delta * delta)
{
	int err;
	struct ploop_pvd_header *vh;
	struct ploop1_private * ph = delta->priv;

	if (delta->holes_bitmap) {
		kvfree(delta->holes_bitmap);
		delta->holes_bitmap = NULL;
	}

	if ((delta->flags & PLOOP_FMT_RDONLY) ||
	    test_bit(PLOOP_S_ABORT, &delta->plo->state))
		return 0;

	ph->alloc_head = delta->io.alloc_head;

	err = delta->io.ops->sync(&delta->io);
	if (err)
		return err;

	vh = (struct ploop_pvd_header *)page_address(ph->dyn_page);

	err = delta->io.ops->sync_read(&delta->io, ph->dyn_page, 4096, 0, 0);
	if (err)
		return err;

	if (ph->alloc_head > (ph->l1_off >> delta->plo->cluster_log)) {
		vh->m_Flags = le32_to_cpu(vh->m_Flags);
		vh->m_Flags &= ~CIF_Empty;
		vh->m_Flags = cpu_to_le32(vh->m_Flags);
	}

	pvd_header_set_disk_closed(vh);

	err = delta->io.ops->sync_write(&delta->io, ph->dyn_page, 4096, 0, 0);
	if (err)
		return err;

	return delta->io.ops->sync(&delta->io);
}

static int
ploop1_compose(struct ploop_delta * delta, int nchunks, struct ploop_ctl_chunk * pc)
{
	return ploop_io_init(delta, nchunks, pc);
}

static int populate_holes_bitmap(struct ploop_delta *delta,
				 struct ploop1_private *ph)
{
	unsigned int block, nr_blocks, size, off, md_off;
	struct page *page;
	sector_t sec;
	u32 *index;
	int i, ret;

	if (test_bit(PLOOP_S_NO_FALLOC_DISCARD, &delta->plo->state))
		return 0;

	/* To do: add discard alignment for v1 */
	if (delta->plo->fmt_version != PLOOP_FMT_V2) {
		set_bit(PLOOP_S_NO_FALLOC_DISCARD, &delta->plo->state);
		return 0;
	}

	ret = -ENOMEM;
	page = alloc_page(GFP_KERNEL);
	if (!page)
		return ret;

	/*
	 * Holes bitmap is map of clusters from start of file to maximum
	 * cluster, which may be refered by BAT.
	 * Absolute offset is useful for grow operation. Also it allows
	 * to handle failing allocation requests, which ends after grow.
	 */
	md_off = (ph->l1_off >> delta->cluster_log);
	nr_blocks = md_off + ph->nr_bat_entries;

	/* Bits to bytes */
	size = DIV_ROUND_UP(nr_blocks, 8);

	delta->holes_bitmap = kvmalloc(size, GFP_KERNEL);
	if (!delta->holes_bitmap)
		goto put_page;
	ph->nr_clusters_in_bitmap = nr_blocks;
	memset(delta->holes_bitmap, 0xff, size);
	/* Tail clusters are not available for allocation */
	for (i = nr_blocks; i < size * 8; i++)
		clear_bit(i, delta->holes_bitmap);
	/* Header and BAT cluster are not available too */
	for (i = 0; i < md_off; i++)
		clear_bit(i, delta->holes_bitmap);

	block = 0;
	while (block < nr_blocks) {
		if (!ploop1_map_index(delta, block, &sec)) {
			/*
			 * BAT area can address wider region, than disk size.
			 * This may be a result of shrinking large disk
			 * to a small size.
			 */
			pr_info("ploop%u: bat is bigger than disk size\n",
				delta->plo->index);
			goto put_page;
		}
		ret = delta->io.ops->sync_read(&delta->io, page,
					       4096, 0, sec);
		if (ret)
			goto put_page;

		off = block ? 0 : PLOOP_MAP_OFFSET;

		index = page_address(page);
		for (i = off; i < INDEX_PER_PAGE && block + i - off < nr_blocks; i++) {
			if (index[i] != 0) {
				unsigned int cluster = index[i] >> ploop_map_log(delta->plo);
				/*
				 * On grow cluster above nr_clusters_in_bitmap may
				 * be assigned. Ignore it.
				 */
				if (likely(cluster < ph->nr_clusters_in_bitmap))
					ploop_clear_holes_bitmap_bit(cluster, delta);
			}
		}

		block += (block ? INDEX_PER_PAGE : INDEX_PER_PAGE - PLOOP_MAP_OFFSET);
	}

	ret = 0;

put_page:
	put_page(page);
	return ret;
}

static int
ploop1_open(struct ploop_delta * delta)
{
	int err;
	struct ploop1_private * ph;
	struct ploop_pvd_header *vh;
	u64 i_size;
	int version;

	err = -ENOMEM;
	ph = kzalloc(sizeof(struct ploop1_private), GFP_KERNEL);
	if (ph == NULL)
		return -ENOMEM;

	delta->priv = ph;

	ph->dyn_page = alloc_page(GFP_KERNEL);
	if (ph->dyn_page == NULL)
		goto out_err;

	err = ploop_io_open(&delta->io);
	if (err)
		goto out_err;

	/* IO engine is ready. */
	err = delta->io.ops->sync_read(&delta->io, ph->dyn_page, 4096, 0, 0);
	if (err)
		goto out_err;

	err = -EINVAL;
	vh = (struct ploop_pvd_header *)page_address(ph->dyn_page);
	version = ploop1_version(vh);
	if (version == -1 || 
	    vh->m_Type	  != cpu_to_le32(PRL_IMAGE_COMPRESSED) ||
	    vh->m_Sectors != cpu_to_le32(1 << delta->cluster_log))
		goto out_err;

	/* We don't support mixed configuration of V1 and V2 images */
	if (delta->plo->fmt_version && delta->plo->fmt_version != version)
		goto out_err;

	ph->l1_off = le32_to_cpu(vh->m_FirstBlockOffset);
	ph->nr_bat_entries = le32_to_cpu(vh->m_Size);

	err = -EBUSY;
	if (pvd_header_is_disk_in_use(vh))
		goto out_err;

	err = -EINVAL;
	i_size = delta->io.ops->i_size_read(&delta->io);
	ph->alloc_head = i_size >> (delta->cluster_log + 9);
	if (!(le32_to_cpu(vh->m_Sectors) << 9) ||
	    do_div(i_size, le32_to_cpu(vh->m_Sectors) << 9))
		goto out_err;

	ph->bd_size = get_SizeInSectors_from_le(vh, version);

	if (delta->plo->bd_size > ph->bd_size)
		goto out_err;
	if (ph->bd_size & (le32_to_cpu(vh->m_Sectors) - 1))
		goto out_err;
	if (delta->plo->bd_size & (le32_to_cpu(vh->m_Sectors) - 1))
		goto out_err;

	if (!(delta->flags & PLOOP_FMT_RDONLY)) {
		pvd_header_set_disk_in_use(vh);
		err = delta->io.ops->sync_write(&delta->io, ph->dyn_page, 4096, 0, 0);
		if (err)
			goto out_err;
	}

	delta->io.alloc_head = ph->alloc_head;
	delta->plo->bd_size = ph->bd_size;
	delta->plo->fmt_version = version;

	/* If i_size >= max_size, no more allocations needed */
	if ((u64)ph->alloc_head << (delta->cluster_log + 9) >=
	    ((u64)ph->bd_size + ph->l1_off) << 9)
		delta->flags |= PLOOP_FMT_PREALLOCATED;

	if (delta->io.ops->id != PLOOP_IO_DIRECT)
		set_bit(PLOOP_S_NO_FALLOC_DISCARD, &delta->plo->state);

	return 0;

out_err:
	ploop1_destroy_priv(delta);
	return err;
}

static int
ploop1_refresh(struct ploop_delta * delta)
{
	int err;
	struct ploop_pvd_header *vh;
	struct ploop1_private * ph = delta->priv;

	vh = (struct ploop_pvd_header *)page_address(ph->dyn_page);

	err = delta->io.ops->sync_read(&delta->io, ph->dyn_page, 4096, 0, 0);
	if (err)
		return err;

	ph->bd_size = get_SizeInSectors_from_le(vh, delta->plo->fmt_version);

	return 0;
}

/*
 * The function gets preq with a bio. Caller checked that this bio
 * is write to a block, which is not allocated in this delta.
 * If this block is totally new, bio can cover only a part of block,
 * if bio is a COW from previous delta, the function gets a bio
 * covering the whole cluster, which is read from original delta.
 *
 * Task of this function is to allocate new block in image,
 * to copy data there and to update index after this. A lot, huh?
 */

static void
ploop1_allocate(struct ploop_delta * delta, struct ploop_request * preq,
		struct bio_list * sbl, unsigned int size)
{
	struct ploop1_private * ph = delta->priv;
	unsigned int max_size;
	cluster_t cluster = 0;
	int ret;

	if (delta->holes_bitmap) {
		unsigned nr_clusters = ph->nr_clusters_in_bitmap;

		cluster = find_first_bit(delta->holes_bitmap, nr_clusters);
		if (cluster >= nr_clusters)
			cluster = 0; /* grow in process? */
	}

	max_size = (delta->max_delta_size >> delta->cluster_log);
	if (!cluster && delta->io.alloc_head >= max_size) {
		PLOOP_FAIL_REQUEST(preq, -E2BIG);
		return;
	}

	ret = ploop_submit_alloc(delta, preq, sbl, size, cluster);

	if (ret == 1 && cluster) {
		/* Success. Mark cluster as occupied */
		ploop_clear_holes_bitmap_bit(cluster, delta);
		/*
		 * FIXME: but what about failing requests,
		 * which return success? Should we add
		 * a handler in ploop_complete_request()?
		 */
	}
}

/* Call this when data write is complete */

static void
ploop1_allocate_complete(struct ploop_delta * delta, struct ploop_request * preq)
{
	if ((preq->req_rw & REQ_DISCARD) &&
	    !test_bit(PLOOP_REQ_DISCARD, &preq->state)) {
		preq->iblock = 0;
	}

	ploop_index_update(preq);
}

static void
ploop1_destroy(struct ploop_delta * delta)
{
	if (delta->holes_bitmap) {
		kvfree(delta->holes_bitmap);
		delta->holes_bitmap = NULL;
	}
	ploop_io_destroy(&delta->io);
	ploop1_destroy_priv(delta);
}

static int
ploop1_start(struct ploop_delta * delta)
{
	struct ploop1_private *ph = delta->priv;
	struct ploop_device *plo = delta->plo;

	if (!list_is_singular(&plo->map.delta_list))
		return 0;

	return populate_holes_bitmap(delta, ph);

//	return delta->io.ops->start(&delta->io);
}

static int
ploop1_sync(struct ploop_delta * delta)
{
	int err;
	struct ploop_pvd_header *vh;
	struct ploop1_private * ph = delta->priv;

	if (delta->flags & PLOOP_FMT_RDONLY)
		return 0;

	if (test_bit(PLOOP_S_ABORT, &delta->plo->state))
		return -EIO;

	ph->alloc_head = delta->io.alloc_head;

	err = delta->io.ops->sync(&delta->io);
	if (err)
		return err;

	err = delta->io.ops->sync_read(&delta->io, ph->dyn_page, 4096, 0, 0);
	if (err)
		return err;

	vh = (struct ploop_pvd_header *)page_address(ph->dyn_page);
	pvd_header_set_disk_in_use(vh);

	if (ph->alloc_head > (ph->l1_off >> delta->plo->cluster_log)) {
		vh->m_Flags = le32_to_cpu(vh->m_Flags);
		vh->m_Flags &= ~CIF_Empty;
		vh->m_Flags = cpu_to_le32(vh->m_Flags);
	}

	err = delta->io.ops->sync_write(&delta->io, ph->dyn_page, 4096, 0, 0);
	if (err)
		return err;

	return delta->io.ops->sync(&delta->io);
}

static int
ploop1_prepare_snapshot(struct ploop_delta * delta, struct ploop_snapdata * sd)
{
	return delta->io.ops->prepare_snapshot(&delta->io, sd);
}

static int
ploop1_complete_snapshot(struct ploop_delta * delta, struct ploop_snapdata * sd)
{
	int err = 0;
	struct ploop_pvd_header *vh;
	struct ploop1_private * ph = delta->priv;

	if (delta->flags & PLOOP_FMT_RDONLY)
		goto out;

	err = -EIO;
	if (test_bit(PLOOP_S_ABORT, &delta->plo->state))
		goto out;

	ph->alloc_head = delta->io.alloc_head;

	err = delta->io.ops->sync(&delta->io);
	if (err)
		goto out;

	err = delta->io.ops->sync_read(&delta->io, ph->dyn_page, 4096, 0, 0);
	if (err)
		goto out;

	vh = (struct ploop_pvd_header *)page_address(ph->dyn_page);

	if (ph->alloc_head > (ph->l1_off >> delta->io.plo->cluster_log)) {
		vh->m_Flags = le32_to_cpu(vh->m_Flags);
		vh->m_Flags &= ~CIF_Empty;
		vh->m_Flags = cpu_to_le32(vh->m_Flags);
	}

	pvd_header_set_disk_closed(vh);

	/*
	 * NB: we don't call ploop_update_map_hdr() here because top
	 * delta after snapshot completion should bear m_DiskInUse != 0.
	 * Also, we rely on the fact that new top delta (created while
	 * snapshotting) has exactly the same PVD-header as former top
	 * delta. So, first 64 bytes of correspondent map_node page
	 * remain valid.
	 */

	err = delta->io.ops->sync_write(&delta->io, ph->dyn_page, 4096, 0, 0);
	if (err)
		goto out;

	err = delta->io.ops->sync(&delta->io);
	if (err)
		goto out;

	err = delta->io.ops->complete_snapshot(&delta->io, sd);
	if (err)
		goto out;

	if (delta->holes_bitmap) {
		/* New top_delta will be added ahead @delta */
		kvfree(delta->holes_bitmap);
		delta->holes_bitmap = NULL;
	}

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
ploop1_prepare_merge(struct ploop_delta * delta, struct ploop_snapdata * sd)
{
	int err;
	struct ploop_pvd_header *vh;
	struct ploop1_private * ph = delta->priv;
	struct ploop_device *plo = delta->plo;

	vh = (struct ploop_pvd_header *)page_address(ph->dyn_page);

	err = delta->io.ops->sync_read(&delta->io, ph->dyn_page, 4096, 0, 0);
	if (err)
		return err;

	if (pvd_header_is_disk_in_use(vh))
		return -EBUSY;

	/* Close race with submit_alloc */
	ploop_quiesce(plo);
	ph->alloc_head = delta->io.ops->i_size_read(&delta->io) >>
			 (delta->io.plo->cluster_log + 9);
	delta->io.alloc_head = ph->alloc_head;
	ploop_relax(plo);

	return 0;
}

static int
ploop1_start_merge(struct ploop_delta * delta, struct ploop_snapdata * sd)
{
	int err;
	struct ploop_pvd_header *vh;
	struct ploop1_private * ph = delta->priv;

	err = delta->io.ops->start_merge(&delta->io, sd);
	if (err)
		return err;

	if (test_bit(PLOOP_S_ABORT, &delta->plo->state)) {
		printk(KERN_WARNING "ploop1_start_merge for ploop%d failed "
		       "(state ABORT)\n", delta->plo->index);
		return -EIO;
	}

	err = delta->io.ops->sync_read(&delta->io, ph->dyn_page, 4096, 0, 0);
	if (err)
		return err;

	vh = (struct ploop_pvd_header *)page_address(ph->dyn_page);
	pvd_header_set_disk_in_use(vh);

	/* keep hdr in ph->dyn_page and in map_node in sync */
	ploop_update_map_hdr(&delta->plo->map, (u8 *)vh, sizeof(*vh));

	err = delta->io.ops->sync_write(&delta->io, ph->dyn_page, 4096, 0, 0);
	if (err)
		return err;

	ph->bd_size = get_SizeInSectors_from_le(vh, delta->plo->fmt_version);
	ph->l1_off = le32_to_cpu(vh->m_FirstBlockOffset);
	ph->nr_bat_entries = le32_to_cpu(vh->m_Size);

	err = delta->io.ops->sync(&delta->io);
	if (err)
		return err;

	/*
	 * Do this as last of operations, which may fail. After this,
	 * nothing can stop killing current top_delta. Otherwise,
	 * in case of other operation fail, we will have two deltas
	 * and holes_bitmap assigned.
	 */
	if (delta->level == 0)
		err = populate_holes_bitmap(delta, ph);

	return err;
}

static int
ploop1_replace_delta(struct ploop_delta *delta)
{
	struct ploop1_private *ph = delta->priv;
	struct ploop_device *plo = delta->plo;

	if (delta->level != 0)
		return 0;

	/*
	 * @delta is not linked, but old delta is still in list.
	 * So, we check whether old delta is only element there.
	 */
	if (!list_is_singular(&plo->map.delta_list))
		return 0;

	return populate_holes_bitmap(delta, ph);
}

static int ploop1_truncate(struct ploop_delta * delta, struct file * file,
			   __u32 alloc_head)
{
	struct ploop1_private * ph = delta->priv;

	/*
	 * Maybe we should call here ploop1_refresh() and re-read PVD-header
	 * from disk. This will be clear in the course of porting
	 * ploop-shrink.c::shrink_in_place().
	 */

	ph->alloc_head = alloc_head;
	delta->io.alloc_head = alloc_head;

	return delta->io.ops->truncate(&delta->io,
				       file ? file : delta->io.files.file,
				       alloc_head);
}

static int expand_holes_bitmap(struct ploop_delta *delta,
			       struct ploop_pvd_header *vh,
			       unsigned int old_nr)
{
	unsigned int i, nr, md_off, size, old_size;
	unsigned int log = delta->cluster_log;
	void *holes_bitmap;

	if (!delta->holes_bitmap)
		return 0;

	/*
	 * According to BUG_ON() in ploop1_prepare_grow(),
	 * we do not support zero m_FirstBlockOffset
	 * at least since 2013.
	 */
	md_off = vh->m_FirstBlockOffset >> log;
	nr = md_off + vh->m_Size;

	old_size = DIV_ROUND_UP(old_nr, 8);
	size = DIV_ROUND_UP(nr, 8);

	if (WARN_ON(old_size > size))
		return -EINVAL;

	holes_bitmap = kvmalloc(size, GFP_KERNEL);
	if (!holes_bitmap) {
		pr_err("Can't allocate holes_bitmap\n");
		return -ENOMEM;
	}

	memcpy(holes_bitmap, delta->holes_bitmap, old_size);
	kvfree(delta->holes_bitmap);

	/* Tail bits of old bitmap */
	for (i = old_nr; i < old_size * 8; i++)
		set_bit(i, holes_bitmap);
	/* Header and BAT are not available for allocation */
	for (i = 0; i < md_off; i++)
		clear_bit(i, holes_bitmap);
	/* Fill all new bytes */
	memset(holes_bitmap + old_size, 0xff, size - old_size);
	/*
	 * But clear clusters above old bitmap,
	 * which were allocated during grow.
	 */
	for (i = old_nr; i < delta->io.alloc_head && i < nr; i++)
		clear_bit(i, holes_bitmap);
	/* Clear alignment bytes */
	for (i = nr; i < size * 8; i++)
		clear_bit(i, holes_bitmap);

	delta->holes_bitmap = holes_bitmap;
	return 0;
}

static int
ploop1_prepare_grow(struct ploop_delta * delta, u64 *new_size, int *reloc)
{
	struct ploop1_private * ph = delta->priv;
	struct ploop_pvd_header *vh;
	int idxs_per_iblk; /* # indices in one cluster-block */
	iblock_t bdsize;   /* block-device size measured in cluster-blocks */
	int n_present;     /* # cluster-blocks in L2-table (existent now) */
	int n_needed;      /* # cluster-blocks in L2-table (for new_size) */
	int n_alloced = 0; /* # cluster-blocks we can alloc right now */
	int i, err;
	iblock_t a_h = delta->io.alloc_head;
	int	 log = delta->io.plo->cluster_log;

	if (*new_size & ((1 << delta->cluster_log) - 1))
		return -EINVAL;

	if (*new_size > ploop1_max_size(1 << delta->plo->cluster_log,
					delta->plo->fmt_version))
		return -EFBIG;

	vh = (struct ploop_pvd_header *)page_address(ph->dyn_page);
	n_present  = le32_to_cpu(vh->m_FirstBlockOffset) >> log;
	BUG_ON (!n_present);

	bdsize = (*new_size + (1 << log) - 1) >> log;

	idxs_per_iblk = (1 << (log + 9)) / sizeof(u32);
	n_needed = (bdsize + PLOOP_MAP_OFFSET + idxs_per_iblk - 1) /
		   idxs_per_iblk;

	if (n_needed <= n_present)
		return 0;

	if (a_h < n_needed) {
		n_alloced = n_needed - a_h;
		err = delta->io.ops->alloc(&delta->io,
					   (loff_t)a_h << (log + 9),
					   (loff_t)(n_alloced) << (log + 9));
		if (err)
			return err;
	}

	*reloc = n_needed - n_present - n_alloced;
	if (*reloc) {
		/* Feeling irresistable infatuation to relocate ... */
		delta->io.plo->grow_start = n_present;
		delta->io.plo->grow_end = n_needed - n_alloced - 1;

		/* Does not use rellocated data clusters during grow. */
		if (delta->holes_bitmap) {
			i = delta->io.plo->grow_start;
			while (i <= n_needed - 1)
				ploop_clear_holes_bitmap_bit(i++, delta);
		}
	}

	return 0;
}

static int ploop1_complete_grow(struct ploop_delta * delta, u64 new_size)
{
	unsigned int log = delta->cluster_log;
	struct ploop_pvd_header *vh;
	struct ploop1_private * ph = delta->priv;
	int err;
	u32 vh_bsize; /* block size in sectors */

	err = delta->io.ops->sync(&delta->io);
	if (err)
		return err;

	err = delta->io.ops->sync_read(&delta->io, ph->dyn_page, 4096, 0, 0);
	if (err)
		return err;

	vh = (struct ploop_pvd_header *)page_address(ph->dyn_page);
	vh_bsize = le32_to_cpu(vh->m_Sectors);

	if (vh_bsize != (1 << delta->io.plo->cluster_log)) {
		printk("grow: vh->m_Sectors=%u != 1<<plo->cluster_log=%u\n",
		       vh_bsize, 1 << delta->io.plo->cluster_log);
		return -EINVAL;
	}

	generate_pvd_header(vh, new_size, vh_bsize, delta->plo->fmt_version);

	err = expand_holes_bitmap(delta, vh,
				  (ph->l1_off >> log) + ph->nr_bat_entries);
	if (err)
		return err;

	vh->m_Type             = cpu_to_le32(vh->m_Type);
	cpu_to_le_SizeInSectors(vh, delta->plo->fmt_version);
	vh->m_Sectors          = cpu_to_le32(vh->m_Sectors);
	vh->m_Heads            = cpu_to_le32(vh->m_Heads);
	vh->m_Cylinders        = cpu_to_le32(vh->m_Cylinders);
	vh->m_Size             = cpu_to_le32(vh->m_Size);
	vh->m_FirstBlockOffset = cpu_to_le32(vh->m_FirstBlockOffset);

	/* keep hdr in ph->dyn_page and in map_node in sync */
	ploop_update_map_hdr(&delta->plo->map, (u8 *)vh, sizeof(*vh));

	err = delta->io.ops->sync_write(&delta->io, ph->dyn_page, 4096, 0, 0);
	if (err)
		return err;

	err = delta->io.ops->sync(&delta->io);
	if (err)
		return err;

	ph->bd_size = new_size;
	ph->l1_off = le32_to_cpu(vh->m_FirstBlockOffset);
	ph->nr_bat_entries = le32_to_cpu(vh->m_Size);
	ph->nr_clusters_in_bitmap = (ph->l1_off >> log) + ph->nr_bat_entries;

	return 0;
}

static void ploop1_add_free_blk(struct ploop_delta *delta, struct ploop_request *preq)
{
	struct ploop1_private *ph = delta->priv;
	struct map_node *m = preq->map;
	cluster_t cluster;
	map_index_t blk;
	u32 idx;

	if (!delta->holes_bitmap)
		return;

	idx = (preq->req_cluster + PLOOP_MAP_OFFSET) & (INDEX_PER_PAGE - 1);
	blk = ((map_index_t *)page_address(m->page))[idx];

	/* Reapeted discard? */
	if (!blk)
		return;

	cluster = blk >> ploop_map_log(delta->plo);
	if (cluster > ph->nr_clusters_in_bitmap) {
		/*
		 * On grow cluster above nr_clusters_in_bitmap
		 * may be assigned. Here we handle that.
		 */
		return;
	}

	WARN_ON_ONCE(test_bit(cluster, delta->holes_bitmap));
	ploop_set_holes_bitmap_bit(cluster, delta);
}

static struct ploop_delta_ops ploop1_delta_ops =
{
	.id		=	PLOOP_FMT_PLOOP1,
	.name		=	"ploop1",
	.owner		=	THIS_MODULE,
	.capability	=	PLOOP_FMT_CAP_WRITABLE | PLOOP_FMT_CAP_DELTA,

	.map_index	=	ploop1_map_index,
	.read_index	=	ploop1_read_index,

	.allocate	=	ploop1_allocate,
	.allocate_complete =	ploop1_allocate_complete,

	.compose	=	ploop1_compose,
	.open		=	ploop1_open,
	.destroy	=	ploop1_destroy,
	.start		=	ploop1_start,
	.stop		=	ploop1_stop,
	.refresh	=	ploop1_refresh,
	.sync		=	ploop1_sync,
	.prepare_snapshot =	ploop1_prepare_snapshot,
	.complete_snapshot =	ploop1_complete_snapshot,
	.fmt_prepare_merge =	ploop1_prepare_merge,
	.start_merge	=	ploop1_start_merge,
	.replace_delta 	=	ploop1_replace_delta,
	.truncate	=	ploop1_truncate,
	.prepare_grow	=	ploop1_prepare_grow,
	.complete_grow	=	ploop1_complete_grow,
	.add_free_blk	=	ploop1_add_free_blk,
};

static int __init pfmt_ploop1_mod_init(void)
{
	return ploop_register_format(&ploop1_delta_ops);
}

static void __exit pfmt_ploop1_mod_exit(void)
{
	ploop_unregister_format(&ploop1_delta_ops);
}

module_init(pfmt_ploop1_mod_init);
module_exit(pfmt_ploop1_mod_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Virtuozzo <devel@openvz.org>");
