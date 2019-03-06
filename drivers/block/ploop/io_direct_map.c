/*
 *  drivers/block/ploop/io_direct_map.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/sched.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/buffer_head.h>
#include <linux/interrupt.h>
#include <linux/falloc.h>
#include <linux/slab.h>

#include <linux/ploop/ploop_if.h>
#include "io_direct_events.h"
#include "io_direct_map.h"

/* Part of io_direct shared between all the devices.
 * No way this code is good. But it is the best, which we can do
 * not modifying core.
 *
 * Keep track of images opened by ploop. Maintain shared extent
 * maps for shared images, which are open read-only. Top level
 * deltas, which are open for write, are open exclusively.
 *
 * Also take care about setting/clearing S_SWAPFILE and setting
 * mapping gfp mask to GFP_NOFS.
 */

struct ploop_mapping
{
	struct list_head	list;
	struct address_space	* mapping;
	int			readers;
	unsigned long		saved_gfp_mask;
	loff_t			size;

	struct extent_map_tree	extent_root;
};

static LIST_HEAD(ploop_mappings);
static DEFINE_SPINLOCK(ploop_mappings_lock);

/* total number of extent_map structures */
static atomic_t ploop_extent_maps_count = ATOMIC_INIT(0);

static void extent_map_tree_init(struct extent_map_tree *tree);
static int drop_extent_map(struct extent_map_tree *tree);
static int remove_extent_mapping(struct extent_map_tree *tree, struct extent_map *em);

extern atomic_long_t ploop_io_images_size;

/*
 * ploop_dio_* functions must be called with i_mutex taken.
 */

struct extent_map_tree *
ploop_dio_open(struct ploop_io * io, int rdonly)
{
	int err;
	struct ploop_mapping *m, *pm;
	struct file * file = io->files.file;
	struct address_space * mapping = file->f_mapping;

	pm = kzalloc(sizeof(struct ploop_mapping), GFP_KERNEL);

	err = 0;
	spin_lock(&ploop_mappings_lock);
	list_for_each_entry(m, &ploop_mappings, list) {
		if (m->mapping == mapping) {
			if (rdonly) {
				if (m->readers < 0)
					err = -ETXTBSY;
				else
					m->readers++;
			} else {
				if (m->readers)
					err = -EBUSY;
				else
					m->readers = -1;
			}

out_unlock:
			spin_unlock(&ploop_mappings_lock);
			if (pm)
				kfree(pm);
			if (!err)
				io->size_ptr = &m->size;
			return err ? ERR_PTR(err) : &m->extent_root;
		}
	}

	if (pm == NULL) {
		err = -ENOMEM;
		goto out_unlock;
	}

	if (mapping->host->i_flags & S_SWAPFILE) {
		err = -EBUSY;
		goto out_unlock;
	}

	pm->mapping = mapping;
	extent_map_tree_init(&pm->extent_root);
	pm->extent_root.mapping = mapping;
	pm->readers = rdonly ? 1 : -1;
	list_add(&pm->list, &ploop_mappings);
	mapping->host->i_flags |= S_SWAPFILE;
	io->size_ptr = &pm->size;
	*io->size_ptr = i_size_read(mapping->host);
	atomic_long_add(*io->size_ptr, &ploop_io_images_size);

	pm->saved_gfp_mask = mapping_gfp_mask(mapping);
	mapping_set_gfp_mask(mapping,
			     pm->saved_gfp_mask & ~__GFP_FS);

	spin_unlock(&ploop_mappings_lock);

	return &pm->extent_root;
}

int
ploop_dio_close(struct ploop_io * io, int rdonly)
{
	struct address_space * mapping = io->files.mapping;
	struct ploop_mapping *m, *pm = NULL;

	spin_lock(&ploop_mappings_lock);
	list_for_each_entry(m, &ploop_mappings, list) {
		if (m->mapping == mapping) {
			if (rdonly) {
				m->readers--;
			} else {
				BUG_ON(m->readers != -1);
				m->readers = 0;
			}

			if (m->readers == 0) {
				atomic_long_sub(*io->size_ptr,
						&ploop_io_images_size);
				*io->size_ptr = 0;
				mapping->host->i_flags &= ~S_SWAPFILE;
				list_del(&m->list);
				pm = m;
			}
			break;
		}
	}
	spin_unlock(&ploop_mappings_lock);

	if (pm) {
		drop_extent_map(&pm->extent_root);
		BUG_ON(pm->extent_root.map_size);
		kfree(pm);
		return 0;
	}
	return -ENOENT;
}

void ploop_dio_downgrade(struct address_space * mapping)
{
	struct ploop_mapping * m;

	spin_lock(&ploop_mappings_lock);
	list_for_each_entry(m, &ploop_mappings, list) {
		if (m->mapping == mapping) {
			BUG_ON(m->readers != -1);
			m->readers = 1;
			break;
		}
	}
	spin_unlock(&ploop_mappings_lock);
}

int ploop_dio_upgrade(struct ploop_io * io)
{
	struct address_space * mapping = io->files.mapping;
	struct ploop_mapping * m;
	int err = -ESRCH;

	spin_lock(&ploop_mappings_lock);
	list_for_each_entry(m, &ploop_mappings, list) {
		if (m->mapping == mapping) {
			err = -EBUSY;
			if (m->readers == 1) {
				loff_t new_size = i_size_read(io->files.inode);
				atomic_long_add(new_size - *io->size_ptr,
						&ploop_io_images_size);
				*io->size_ptr = new_size;

				m->readers = -1;
				err = 0;
			}
			break;
		}
	}
	spin_unlock(&ploop_mappings_lock);
	return err;
}


/* The rest of the file is written by Jens Axboe.
 * I just fixed a few of bugs (requests not aligned at fs block size
 * due to direct-io aligned to 512) and truncated some useless functionality.
 *
 * In any case, it must be remade: not only because of GPL, but also
 * because it is not good.
 */

static struct kmem_cache *extent_map_cache;

int __init ploop_extent_map_init(void)
{
	extent_map_cache = kmem_cache_create("ploop_itree",
						sizeof(struct extent_map), 0,
						SLAB_MEM_SPREAD, NULL
						);
	if (!extent_map_cache)
		return -ENOMEM;
	return 0;
}

void ploop_extent_map_exit(void)
{
	if (extent_map_cache)
		kmem_cache_destroy(extent_map_cache);
}

static void extent_map_tree_init(struct extent_map_tree *tree)
{
	tree->map.rb_node = NULL;
	INIT_LIST_HEAD(&tree->lru_list);
	tree->map_size = 0;
	rwlock_init(&tree->lock);
}

struct extent_map *ploop_alloc_extent_map(gfp_t mask)
{
	struct extent_map *em;

	em = kmem_cache_alloc(extent_map_cache, GFP_NOFS);
	if (em) {
		atomic_set(&em->refs, 1);
		INIT_LIST_HEAD(&em->lru_link);
		atomic_inc(&ploop_extent_maps_count);
		em->uninit = false;
	}
	return em;
}

void ploop_extent_put(struct extent_map *em)
{
	if (!em)
		return;
	if (atomic_dec_and_test(&em->refs)) {
		atomic_dec(&ploop_extent_maps_count);
		kmem_cache_free(extent_map_cache, em);
	}
}

static struct rb_node *tree_insert(struct rb_root *root, sector_t start,
				   sector_t end, struct rb_node *node)
{
	struct rb_node ** p = &root->rb_node;
	struct rb_node * parent = NULL;
	struct extent_map *entry;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct extent_map, rb_node);

		if (end <= entry->start)
			p = &(*p)->rb_left;
		else if (start >= entry->end)
			p = &(*p)->rb_right;
		else
			return parent;
	}

	rb_link_node(node, parent, p);
	rb_insert_color(node, root);
	return NULL;
}

/* Find extent which contains "offset". If there is no such extent,
 * prev_ret is the first extent following "offset".
 */
static struct rb_node *__tree_search(struct rb_root *root, sector_t offset,
				     struct rb_node **prev_ret)
{
	struct rb_node * n = root->rb_node;
	struct rb_node *prev = NULL;
	struct extent_map *entry;
	struct extent_map *prev_entry = NULL;

	while (n) {
		entry = rb_entry(n, struct extent_map, rb_node);
		prev = n;
		prev_entry = entry;

		if (offset < entry->start)
			n = n->rb_left;
		else if (offset >= entry->end)
			n = n->rb_right;
		else
			return n;
	}
	if (!prev_ret)
		return NULL;

	while (prev && offset >= prev_entry->end) {
		prev = rb_next(prev);
		prev_entry = rb_entry(prev, struct extent_map, rb_node);
	}
	*prev_ret = prev;
	return NULL;
}

/* Find the first extent which could intersect a range starting at offset.
 * Probably, it does not contain offset.
 */
static inline struct rb_node *tree_search(struct rb_root *root, sector_t offset)
{
	struct rb_node *prev;
	struct rb_node *ret;
	ret = __tree_search(root, offset, &prev);
	if (!ret)
		return prev;
	return ret;
}

static int tree_delete(struct rb_root *root, sector_t offset)
{
	struct rb_node *node;

	node = __tree_search(root, offset, NULL);
	if (!node)
		return -ENOENT;
	rb_erase(node, root);
	return 0;
}

static int mergable_maps(struct extent_map *prev, struct extent_map *next)
{
	if (prev->end == next->start &&
	    next->block_start == extent_map_block_end(prev))
		return 1;
	return 0;
}

static inline int purge_lru_mapping(struct extent_map_tree *tree)
{
	int max_entries = (max_extent_map_pages << PAGE_SHIFT) /
		sizeof(struct extent_map);

	return atomic_read(&ploop_extent_maps_count) > max_entries &&
	       tree->map_size > max(1, min_extent_map_entries) &&
	       (u64)tree->map_size * atomic_long_read(&ploop_io_images_size) >
	       (u64)max_entries * i_size_read(tree->mapping->host);
}

static inline void purge_lru_warn(struct extent_map_tree *tree)
{
	int max_entries = (max_extent_map_pages << PAGE_SHIFT) /
		sizeof(struct extent_map);

	loff_t ratio = i_size_read(tree->mapping->host) * 100;
	do_div(ratio, atomic_long_read(&ploop_io_images_size));

	printk(KERN_WARNING "Purging lru entry from extent tree for inode %ld "
	       "(map_size=%d ratio=%lld%%)\n",
	       tree->mapping->host->i_ino, tree->map_size, ratio);

	/* Claim FS as 'too fragmented' if average_extent_size < 8MB */
	if ((u64)max_entries * (8 * 1024 * 1024) <
	    atomic_long_read(&ploop_io_images_size))
		printk(KERN_WARNING "max_extent_map_pages=%d is too low for "
		       "ploop_io_images_size=%ld bytes\n",
		       max_extent_map_pages,
		       atomic_long_read(&ploop_io_images_size));
	else {
		loff_t avg_siz = i_size_read(tree->mapping->host);
		do_div(avg_siz, tree->map_size);

		printk(KERN_WARNING "host fs is too fragmented: average extent"
		       " size is lesser than %lld bytes\n", avg_siz);
	}
}

/*
 * add_extent_mapping tries a simple forward/backward merge with existing
 * mappings.  The extent_map struct passed in will be inserted into
 * the tree directly (no copies made, just a reference taken).
 */
static int add_extent_mapping(struct extent_map_tree *tree,
			      struct extent_map *em)
{
	int ret = 0;
	struct rb_node *rb;

	write_lock_irq(&tree->lock);

	do {
		rb = tree_insert(&tree->map, em->start, em->end, &em->rb_node);
		/* A part of this extent can be in tree */
		if (rb) {
			struct extent_map *tmp =
				rb_entry(rb, struct extent_map, rb_node);
			BUG_ON(tmp->block_start - tmp->start !=
					em->block_start - em->start);
			if (tmp->start <= em->start &&
			    tmp->end >= em->end) {
				ret =  -EEXIST;
				goto out;
			}
			if (tmp->start < em->start) {
				em->start = tmp->start;
				em->block_start = tmp->block_start;
			}
			if (tmp->end > em->end)
				em->end = tmp->end;
			rb_erase(rb, &tree->map);
			list_del_init(&tmp->lru_link);
			tree->map_size--;
			ploop_extent_put(tmp);
		} else {
			list_add_tail(&em->lru_link, &tree->lru_list);
			tree->map_size++;

			if (purge_lru_mapping(tree)) {
				struct extent_map *victim_em;
				static unsigned long purge_lru_time;

				/* Warn about this once per hour */
				if (printk_timed_ratelimit(&purge_lru_time,
							   60*60*HZ))
					purge_lru_warn(tree);

				victim_em = list_entry(tree->lru_list.next,
						       struct extent_map,
						       lru_link);

				list_del_init(&victim_em->lru_link);
				tree->map_size--;
				rb_erase(&victim_em->rb_node, &tree->map);
				ploop_extent_put(victim_em);
			}
		}
	} while (rb);

	atomic_inc(&em->refs);
	if (em->start != 0) {
		rb = rb_prev(&em->rb_node);
		if (rb) {
			struct extent_map *merge;

			merge = rb_entry(rb, struct extent_map, rb_node);
			if (mergable_maps(merge, em)) {
				em->start = merge->start;
				em->block_start = merge->block_start;
				rb_erase(&merge->rb_node, &tree->map);
				list_del_init(&merge->lru_link);
				tree->map_size--;
				ploop_extent_put(merge);
			}
		}
	}
	rb = rb_next(&em->rb_node);
	if (rb) {
		struct extent_map *merge;

		merge = rb_entry(rb, struct extent_map, rb_node);
		if (mergable_maps(em, merge)) {
			em->end = merge->end;
			rb_erase(&merge->rb_node, &tree->map);
			list_del_init(&merge->lru_link);
			tree->map_size--;
			ploop_extent_put(merge);
		}
	}

	trace_add_extent_mapping(em);
out:
	write_unlock_irq(&tree->lock);
	return ret;
}

struct extent_map *
extent_lookup(struct extent_map_tree *tree, sector_t start)
{
	struct extent_map *em = NULL;
	struct rb_node *rb_node;

	read_lock(&tree->lock);
	rb_node = __tree_search(&tree->map, start, NULL);
	if (rb_node) {
		em = rb_entry(rb_node, struct extent_map, rb_node);
		atomic_inc(&em->refs);
	}
	read_unlock(&tree->lock);

	if (em) {
		write_lock(&tree->lock);
		/* em could not be released, but could be deleted
		 * from the list before we re-acquired the lock */
		if (!list_empty(&em->lru_link)) {
			list_del(&em->lru_link);
			list_add_tail(&em->lru_link, &tree->lru_list);
		}
		write_unlock(&tree->lock);
	}

	return em;
}

/*
 * lookup_extent_mapping returns the first extent_map struct in the
 * tree that intersects the [start, start+len) range.  There may
 * be additional objects in the tree that intersect, so check the object
 * returned carefully to make sure you don't need additional lookups.
 */
static struct extent_map *
lookup_extent_mapping(struct extent_map_tree *tree, sector_t start, sector_t len)
{
	struct extent_map *em;
	struct rb_node *rb_node;
	unsigned long flags;

	read_lock_irqsave(&tree->lock, flags);
	rb_node = tree_search(&tree->map, start);
	if (!rb_node) {
		em = NULL;
		goto out;
	}
	em = rb_entry(rb_node, struct extent_map, rb_node);
	if (em->end <= start || em->start >= start + len) {
		em = NULL;
		goto out;
	}
	atomic_inc(&em->refs);

out:
	read_unlock_irqrestore(&tree->lock, flags);
	return em;
}

/*
 * removes an extent_map struct from the tree.  No reference counts are
 * dropped, and no checks are done to  see if the range is in use
 *
 * caller called spin_lock_irq(plo->lock), so we needn't _irq locking
 */
static int remove_extent_mapping(struct extent_map_tree *tree, struct extent_map *em)
{
	int ret;

	WARN_ON(!irqs_disabled());

	write_lock(&tree->lock);
	ret = tree_delete(&tree->map, em->start);
	if (!ret) {
		list_del_init(&em->lru_link);
		tree->map_size--;
	}
	write_unlock(&tree->lock);
	return ret;
}

static int fallocate_cluster(struct ploop_io *io, struct inode *inode,
			     loff_t start_off, loff_t len, bool align)
{
	struct ploop_device *plo = io->plo;
	struct file *file = io->files.file;
	unsigned int clu_sz = cluster_size_in_bytes(plo);
	struct fiemap_extent_info fieinfo;
	struct fiemap_extent fi_extent;
	loff_t start_clu = round_down(start_off, clu_sz);
	int ret;

	if (start_clu + clu_sz >= i_size_read(inode))
		return -EINVAL;

	if (test_bit(PLOOP_S_NO_FALLOC_DISCARD, &plo->state)) {
		pr_err("a hole in image file detected (i_size=%llu off=%llu)",
		       i_size_read(inode), start_off);
		return -EINVAL;
	}

	fieinfo.fi_extents_start = &fi_extent;
	fieinfo.fi_extents_max = 1;
	fieinfo.fi_flags = 0;
	fieinfo.fi_extents_mapped = 0;
	fi_extent.fe_flags = 0;

	if (!align)
		goto not_align;

	ret = inode->i_op->fiemap(inode, &fieinfo, start_clu, clu_sz);
	if (ret)
		goto out;

	if (fieinfo.fi_extents_mapped == 0) {
		start_off = start_clu;
		len = clu_sz;
	} else {
not_align:
		fi_extent.fe_flags = 0;
		ret = inode->i_op->fiemap(inode, &fieinfo, start_off, len);
		if (ret)
			goto out;
		if (fieinfo.fi_extents_mapped != 0) {
			WARN_ON_ONCE(fi_extent.fe_logical <= start_off);
			len = fi_extent.fe_logical - start_off;
		}
	}

	ret = file->f_op->fallocate(file, FALLOC_FL_KEEP_SIZE, start_off, len);
out:
	return ret;
}

static struct extent_map *__map_extent_bmap(struct ploop_io *io,
				       struct address_space *mapping,
				       sector_t start, sector_t len, gfp_t gfp_mask)
{
	struct extent_map_tree *tree = io->files.em_tree;
	struct inode *inode = mapping->host;
	loff_t start_off = (loff_t)start << 9;
	struct extent_map *em;
	struct fiemap_extent_info fieinfo;
	struct fiemap_extent fi_extent;
	mm_segment_t old_fs;
	bool align_to_clu;
	int ret;

again:
	align_to_clu = true;
	em = lookup_extent_mapping(tree, start, len);
	if (em) {
		/*
		 * we may have found an extent that starts after the
		 * requested range.  Double check and alter the length
		 * appropriately
		 */
		if (em->start > start) {
			len = em->start - start;
			align_to_clu = false;
		} else {
			return em;
		}
		ploop_extent_put(em);
	}

	BUG_ON(gfp_mask & GFP_ATOMIC);

	if (!inode->i_op->fiemap)
		return ERR_PTR(-EINVAL);

	em = ploop_alloc_extent_map(gfp_mask);
	if (!em)
		return ERR_PTR(-ENOMEM);

	fieinfo.fi_extents_start = &fi_extent;
	fieinfo.fi_extents_max = 1;
	fieinfo.fi_flags = 0;
	fieinfo.fi_extents_mapped = 0;
	fi_extent.fe_flags = 0;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = inode->i_op->fiemap(inode, &fieinfo, start_off, 1);

	/* chase for PSBM-26762: em->block_start == 0 */
	if (!ret && fieinfo.fi_extents_mapped == 1 &&
	    !(fi_extent.fe_flags & FIEMAP_EXTENT_UNWRITTEN) &&
	    (fi_extent.fe_physical >> 9) == 0) {
		/* see how ext4_fill_fiemap_extents() implemented */
		if (!(fi_extent.fe_flags & FIEMAP_EXTENT_DELALLOC)) {
			printk("bad fiemap(%ld,%ld) on inode=%p &fieinfo=%p"
			" i_size=%lld\n", start, len, inode, &fieinfo,
			i_size_read(inode));
			BUG();
		}
		/* complain about delalloc case -- ploop always fallocate
		* before buffered write */
		WARN(1, "ploop%d: delalloc extent [%lld,%lld] for [%lld,%ld];"
			" i_size=%lld\n", io->plo->index, fi_extent.fe_logical,
			fi_extent.fe_length, start_off, len << 9, i_size_read(inode));
		ret = -ENOENT;
	}
	set_fs(old_fs);

	if (ret) {
		ploop_extent_put(em);
		return ERR_PTR(ret);
	}

	if (fieinfo.fi_extents_mapped != 1) {
		ploop_extent_put(em);
		ret = fallocate_cluster(io, inode, start_off, len, align_to_clu);
		if (!ret)
			goto again;
		return ERR_PTR(ret);
	}

	em->start = fi_extent.fe_logical >> 9;
	em->end = (fi_extent.fe_logical + fi_extent.fe_length) >> 9;
	em->block_start = fi_extent.fe_physical >> 9;

	if (fi_extent.fe_flags & FIEMAP_EXTENT_UNWRITTEN) {
		em->uninit = true;
	} else {
		ret = add_extent_mapping(tree, em);
		if (ret == -EEXIST) {
			ploop_extent_put(em);
			goto again;
		}
	}
	return em;
}

static struct extent_map *__map_extent(struct ploop_io *io,
				       struct address_space *mapping,
				       sector_t start, sector_t len,
				       gfp_t gfp_mask)
{
	return __map_extent_bmap(io, mapping, start,len, gfp_mask);
}

static struct extent_map *map_extent_get_block(struct ploop_io *io,
					       struct address_space *mapping,
					       sector_t start, sector_t len,
					       gfp_t gfp_mask)
{
	struct extent_map *em;
	sector_t last;
	sector_t map_ahead_len = 0;

	em = __map_extent(io, mapping, start, len, gfp_mask);

	/*
	 * if we're doing a write or we found a large extent, return it
	 */
	if (IS_ERR(em) || start + len < em->end) {
		return em;
	}

	/*
	 * otherwise, try to walk forward a bit and see if we can build
	 * something bigger.
	 */
	do {
		/* avoid race with userspace merge */
		if (em->end >=
		    ((sector_t)io->alloc_head << io->plo->cluster_log))
			break;

		last = em->end;
		ploop_extent_put(em);
		em = __map_extent(io, mapping, last, len, gfp_mask);
		if (IS_ERR(em) || !em)
			break;
		map_ahead_len += em->end - last;
	} while (em->start <= start && start + len <= em->end &&
		 map_ahead_len < 1024);

	/* make sure we return the extent for this range */
	if (!em || IS_ERR(em) || em->start > start ||
	    start + len > em->end) {
		if (em && !IS_ERR(em))
			ploop_extent_put(em);
		em = __map_extent(io, mapping, start, len, gfp_mask);
	}
	return em;
}


struct extent_map *extent_lookup_create(struct ploop_io *io,
					sector_t start, sector_t len)
{
	struct extent_map_tree *tree = io->files.em_tree;

	return map_extent_get_block(io, tree->mapping,
				    start, len, mapping_gfp_mask(tree->mapping));
}

static int drop_extent_map(struct extent_map_tree *tree)
{
	struct extent_map *em;
	struct rb_node * node;

	write_lock_irq(&tree->lock);
	while ((node = tree->map.rb_node) != NULL) {
		em = rb_entry(node, struct extent_map, rb_node);
		rb_erase(node, &tree->map);
		list_del_init(&em->lru_link);
		tree->map_size--;
		ploop_extent_put(em);
	}
	write_unlock_irq(&tree->lock);
	return 0;
}

void trim_extent_mappings(struct ploop_device *plo, struct extent_map_tree *tree,
			  sector_t start, sector_t len)
{
	struct extent_map *em;

	spin_lock_irq(&plo->lock);
	while ((em = lookup_extent_mapping(tree, start, len)) != NULL) {
		remove_extent_mapping(tree, em);
		WARN_ON(atomic_read(&em->refs) != 2);
		/* once for us */
		ploop_extent_put(em);
		/* No concurrent lookups due to ploop_quiesce(). See WARN_ON above */
		/* once for the tree */
		ploop_extent_put(em);
	}
	spin_unlock_irq(&plo->lock);
}


void dump_extent_map(struct extent_map_tree *tree)
{
	struct rb_node * r = rb_first(&tree->map);

	while (r) {
		struct extent_map *em0 = rb_entry(r, struct extent_map, rb_node);
		printk("N=%ld %ld -> %ld\n", (long)em0->start, (long)(em0->end - em0->start), (long)em0->block_start);
		r = rb_next(r);
	}
}

