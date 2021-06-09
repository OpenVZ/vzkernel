/*
 *  drivers/md/dm-ploop-bat.c
 *
 *  Copyright (c) 2020-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/init.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/mm.h>
#include "dm-ploop.h"

struct md_page * md_page_find(struct ploop *ploop, unsigned int id)
{
	struct rb_node *node;
	struct md_page *md;

	node = ploop->bat_entries.rb_node;

	while (node) {
		md = rb_entry(node, struct md_page, node);
		if (id < md->id)
			node = node->rb_left;
		else if (id > md->id)
			node = node->rb_right;
		else
			return md;
	}

	return NULL;
}

static void __md_page_insert(struct rb_root *root, struct md_page *new_md)
{
	unsigned int new_id = new_md->id;
	struct rb_node *parent, **node;
	struct md_page *md;

	node = &root->rb_node;
	parent = NULL;

	while (*node) {
		parent = *node;
		md = rb_entry(*node, struct md_page, node);
		if (new_id < md->id)
			node = &parent->rb_left;
		else if (new_id > md->id)
			node = &parent->rb_right;
		else
			BUG();
	}

	rb_link_node(&new_md->node, parent, node);
	rb_insert_color(&new_md->node, root);
}

void md_page_insert(struct ploop *ploop, struct md_page *new_md)
{
	__md_page_insert(&ploop->bat_entries, new_md);
}

static struct md_page * alloc_md_page(unsigned int id)
{
	struct md_page *md;
	struct page *page;
	unsigned int size;
	u8 *levels;

	md = kmalloc(sizeof(*md), GFP_KERNEL); /* FIXME: memcache */
	if (!md)
		return NULL;
	size = sizeof(u8) * PAGE_SIZE / sizeof(map_index_t);
	levels = kzalloc(size, GFP_KERNEL);
	if (!levels)
		goto err_levels;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		goto err_page;

	md->bat_levels = levels;
	md->page = page;
	md->id = id;
	return md;
err_page:
	kfree(levels);
err_levels:
	kfree(md);
	return NULL;
}

void ploop_free_md_page(struct md_page *md)
{
	put_page(md->page);
	kfree(md->bat_levels);
	kfree(md);
}

int prealloc_md_pages(struct rb_root *root, unsigned int nr_bat_entries,
		      unsigned int new_nr_bat_entries)
{
	unsigned int i, nr_pages, new_nr_pages;
	struct md_page *md;
	void *addr;

	new_nr_pages = bat_clu_to_page_nr(new_nr_bat_entries - 1) + 1;
	nr_pages = 0;
	if (nr_bat_entries)
		nr_pages = bat_clu_to_page_nr(nr_bat_entries - 1) + 1;

	for (i = nr_pages; i < new_nr_pages; i++) {
		md = alloc_md_page(i);
		if (!md)
			return -ENOMEM;
		addr = kmap_atomic(md->page);
		memset32(addr, BAT_ENTRY_NONE, PAGE_SIZE / 4);
		kunmap_atomic(addr);

		__md_page_insert(root, md);
	}

	return 0;
}

bool try_update_bat_entry(struct ploop *ploop, unsigned int cluster,
			  u8 level, unsigned int dst_cluster)
{
	unsigned int *bat_entries, id = bat_clu_to_page_nr(cluster);
	struct md_page *md = md_page_find(ploop, id);

	lockdep_assert_held(&ploop->bat_rwlock);

	if (!md)
		return false;

	cluster = bat_clu_idx_in_page(cluster); /* relative offset */

	if (md->bat_levels[cluster] == level) {
		bat_entries = kmap_atomic(md->page);
		bat_entries[cluster] = dst_cluster;
		kunmap_atomic(bat_entries);
		return true;
	}
	return false;
}

#if 0
/*
 * Clear all clusters, which are referred to in BAT, from holes_bitmap.
 * Set bat_levels[] to top delta's level. Mark unmapped clusters as
 * BAT_ENTRY_NONE.
 */
static int parse_bat_entries(struct ploop *ploop, map_index_t *bat_entries,
			     u8 *bat_levels, unsigned int nr,
			     unsigned int page_id, u8 nr_deltas)
{
	int i = 0;

	if (page_id == 0)
		i = PLOOP_MAP_OFFSET;

	for (; i < nr; i++) {
		if (bat_entries[i] == BAT_ENTRY_NONE)
			return -EINVAL;
		if (bat_entries[i]) {
			bat_levels[i] = nr_deltas - 1; /* See top_level() */
			/* Cluster may refer out holes_bitmap after shrinking */
			if (bat_entries[i] < ploop->hb_nr)
				ploop_hole_clear_bit(bat_entries[i], ploop);
		} else {
			bat_entries[i] = BAT_ENTRY_NONE;
		}
	}

	return 0;
}

/*
 * Read from disk and fill bat_entries. Note, that on enter here, cluster #0
 * is already read from disk (with header) -- just parse bio pages content.
 */
int ploop_read_bat(struct ploop *ploop, struct bio *bio, u8 nr_deltas)
{
	unsigned int id, entries_per_page, nr_copy, nr_all, page, i = 0;
	map_index_t *from, *to, cluster = 0;
	struct md_page *md;
	int ret = 0;

	entries_per_page = PAGE_SIZE / sizeof(map_index_t);
	nr_all = ploop->nr_bat_entries + PLOOP_MAP_OFFSET;

	do {
		for (page = 0; page < nr_pages_in_cluster(ploop); page++) {
			id = i * sizeof(map_index_t) / PAGE_SIZE;
			md = md_page_find(ploop, id);
			if (WARN_ON_ONCE(!md)) {
				ret = -ENOENT;
				goto out;
			}

			nr_copy = entries_per_page;
			if (i + nr_copy > nr_all)
				nr_copy = nr_all - i;

			to = kmap(md->page);
			from = kmap(bio->bi_io_vec[page].bv_page);
			memcpy(to, from, nr_copy * sizeof(map_index_t));
			kunmap(bio->bi_io_vec[page].bv_page);
			if (unlikely(nr_copy < BAT_ENTRIES_PER_PAGE)) {
				memset(to + nr_copy, 0, sizeof(map_index_t) *
				       (BAT_ENTRIES_PER_PAGE - nr_copy));
			}

			ret = parse_bat_entries(ploop, to, md->bat_levels,
						nr_copy, id, nr_deltas);
			kunmap(md->page);
			if (ret)
				goto out;

			i += nr_copy;
			if (i >= nr_all)
				goto out;
		}

		ret = ploop_read_cluster_sync(ploop, bio, ++cluster);
		if (ret)
			goto out;

	} while (1);

out:
	return ret;
}
#endif

/* Alloc holes_bitmap and set bits of free clusters */
static int ploop_setup_holes_bitmap(struct ploop *ploop,
				    unsigned int bat_clusters)
{
	unsigned int i, size;

	/*
	 * + number of data clusters.
	 * Note, that after shrink of large disk, ploop->bat_entries[x] may
	 * refer outward of [0, ploop->hb_nr-1], and we never allocate
	 * holes_bitmap for such the clusters. Just remember to skip these
	 * clusters after discard frees them.
	 */
	ploop->hb_nr = bat_clusters + ploop->nr_bat_entries;
	size = round_up(DIV_ROUND_UP(ploop->hb_nr, 8), sizeof(unsigned long));

	/* holes_bitmap numbers is relative to start of file */
	ploop->holes_bitmap = kvmalloc(size, GFP_KERNEL);
	if (!ploop->holes_bitmap)
		return -ENOMEM;
	memset(ploop->holes_bitmap, 0xff, size);

	/* Mark all BAT clusters as occupied. */
	for (i = 0; i < bat_clusters; i++)
		ploop_hole_clear_bit(i, ploop);

	return 0;
}

int ploop_setup_metadata(struct ploop *ploop, struct page *page)
{
	unsigned int bat_clusters, offset_clusters;
	struct ploop_pvd_header *m_hdr = NULL;
	unsigned long size;
	int ret;

	m_hdr = kmap(page);

	ret = -ENOTSUPP;
	if (strncmp(m_hdr->m_Sig, "WithouFreSpacExt", 16))
		goto out;

	ret = -ENOLCK;
	if (m_hdr->m_DiskInUse != cpu_to_le32(SIGNATURE_DISK_IN_USE) &&
	    !ploop_is_ro(ploop) && !ignore_signature_disk_in_use)
		goto out;

	ret = -EINVAL;
	if (le32_to_cpu(m_hdr->m_Sectors) != CLU_TO_SEC(ploop, 1))
		goto out;

	memcpy(ploop->m_Sig, m_hdr->m_Sig, sizeof(ploop->m_Sig));
	ploop->m_Type = le32_to_cpu(m_hdr->m_Type);
	ploop->m_Sectors = le32_to_cpu(m_hdr->m_Sectors);
	ploop->nr_bat_entries = le32_to_cpu(m_hdr->m_Size);

	/* Header and BAT-occupied clusters at start of file */
	size = (PLOOP_MAP_OFFSET + ploop->nr_bat_entries) * sizeof(map_index_t);
	bat_clusters = DIV_ROUND_UP(size, CLU_SIZE(ploop));

	/* Clusters from start of file to first data block */
	offset_clusters = SEC_TO_CLU(ploop, le32_to_cpu(m_hdr->m_FirstBlockOffset));
	if (bat_clusters != offset_clusters) {
		pr_err("ploop: custom FirstBlockOffset\n");
		goto out;
	}
	kunmap(page);
	m_hdr = NULL;

	ret = ploop_setup_holes_bitmap(ploop, bat_clusters);
out:
	if (m_hdr)
		kunmap(page);
	return ret;
}

static int ploop_delta_check_header(struct ploop *ploop, struct page *page,
		       unsigned int *nr_pages, unsigned int *last_page_len)
{
	unsigned int bytes, delta_nr_be, offset_clusters, bat_clusters;
	struct ploop_pvd_header *d_hdr;
	int ret = -EPROTO;

	d_hdr = kmap(page);

	if (memcmp(d_hdr->m_Sig, ploop->m_Sig, sizeof(d_hdr->m_Sig)) ||
	    d_hdr->m_Sectors != ploop->m_Sectors ||
	    d_hdr->m_Type != ploop->m_Type)
		goto out;

	delta_nr_be = le32_to_cpu(d_hdr->m_Size);
	offset_clusters = SEC_TO_CLU(ploop, le32_to_cpu(d_hdr->m_FirstBlockOffset));
	bytes = (PLOOP_MAP_OFFSET + delta_nr_be) * sizeof(map_index_t);
	bat_clusters = DIV_ROUND_UP(bytes, CLU_SIZE(ploop));

	if (delta_nr_be > ploop->nr_bat_entries ||
	    bat_clusters != offset_clusters)
		goto out;

	*nr_pages = DIV_ROUND_UP(bytes, PAGE_SIZE);
	bytes &= ~PAGE_MASK;
	*last_page_len = bytes ? : PAGE_SIZE;
	ret = 0;
out:
	kunmap(page);
	return ret;
}

int convert_bat_entries(u32 *bat_entries, u32 count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (bat_entries[i] == BAT_ENTRY_NONE)
			return -EPROTO;
		if (!bat_entries[i])
			bat_entries[i] = BAT_ENTRY_NONE;
	}

	return 0;
}

int ploop_read_delta_metadata(struct ploop *ploop, struct file *file,
			      void **d_hdr)
{
	unsigned int i, last_page_len, size, nr_pages = 1;
	unsigned int *delta_bat_entries;
	struct iov_iter iter;
	struct bio_vec bvec;
	struct page *page;
	ssize_t len;
	void *from;
	loff_t pos;
	int ret;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	size = (PLOOP_MAP_OFFSET + ploop->nr_bat_entries) * sizeof(map_index_t);
	*d_hdr = vzalloc(size);
	if (!*d_hdr) {
		ret = -ENOMEM;
		goto out_put_page;
	}

	for (i = 0; i < nr_pages; i++) {
		bvec.bv_page = page;
		bvec.bv_len = PAGE_SIZE;
		bvec.bv_offset = 0;

		iov_iter_bvec(&iter, READ, &bvec, 1, bvec.bv_len);
		pos = i << PAGE_SHIFT;

		len = vfs_iter_read(file, &iter, &pos, 0);
		if (len != PAGE_SIZE) {
			ret = len < 0 ? (int)len : -ENODATA;
			goto out_vfree;
		}

		if (i == 0) {
			/* First page with header. Updates nr_pages. */
			ret = ploop_delta_check_header(ploop, page,
					&nr_pages, &last_page_len);
			if (ret)
				goto out_vfree;
		}

		if (i + 1 == nr_pages) {
			/* Last page, possible, incomplete */
			len = last_page_len;
		}

		from = kmap(page);
		memcpy(*d_hdr + (i << PAGE_SHIFT), from, len);
		kunmap(page);
	}

	delta_bat_entries = *d_hdr + PLOOP_MAP_OFFSET * sizeof(map_index_t);
	ret = convert_bat_entries(delta_bat_entries, ploop->nr_bat_entries);

out_vfree:
	if (ret) {
		vfree(*d_hdr);
		*d_hdr = NULL;
	}
out_put_page:
	put_page(page);
	return ret;
}

static void ploop_set_not_hole(struct ploop *ploop, u32 dst_cluster)
{
	/* Cluster may refer out holes_bitmap after shrinking */
	if (dst_cluster < ploop->hb_nr)
		ploop_hole_clear_bit(dst_cluster, ploop);
}

/*
 * Prefer first added delta, since the order is:
 * 1)add top device
 * 2)add newest delta
 * ...
 * n)add oldest delta
 */
static void apply_delta_mappings(struct ploop *ploop, struct ploop_delta *deltas,
				 u32 level, void *hdr, u64 size_in_clus)
{
	map_index_t *bat_entries, *delta_bat_entries;
	bool is_top_level, is_raw, stop = false;
	unsigned int i, end, dst_cluster, clu;
	struct rb_node *node;
	struct md_page *md;

	/* Points to hdr since md_page[0] also contains hdr. */
	delta_bat_entries = (map_index_t *)hdr;
	is_raw = deltas[level].is_raw;
	is_top_level = (level == top_level(ploop));

	write_lock_irq(&ploop->bat_rwlock);
	ploop_for_each_md_page(ploop, md, node) {
		bat_entries = kmap_atomic(md->page);

		if (is_top_level && md->id == 0) {
			/* bat_entries before PLOOP_MAP_OFFSET is hdr */
			memcpy(bat_entries, hdr, sizeof(struct ploop_pvd_header));
		}

		init_bat_entries_iter(ploop, md->id, &i, &end);

		for (; i <= end; i++) {
			clu = page_clu_idx_to_bat_clu(md->id, i);
			if (clu >= size_in_clus) {
				WARN_ON_ONCE(is_top_level);
				stop = true;
				goto unmap;
			}

			if (bat_entries[i] != BAT_ENTRY_NONE) {
				/* md0 is already populated */
				WARN_ON_ONCE(md->id && is_top_level);
				goto set_not_hole;
			}

			if (!is_raw)
				dst_cluster = delta_bat_entries[i];
			else {
				dst_cluster = clu;
				if (dst_cluster >= size_in_clus)
					dst_cluster = BAT_ENTRY_NONE;
			}
			if (dst_cluster == BAT_ENTRY_NONE)
				continue;
			md->bat_levels[i] = level;
			bat_entries[i] = dst_cluster;
set_not_hole:
			if (is_top_level)
				ploop_set_not_hole(ploop, bat_entries[i]);
		}
unmap:
		kunmap_atomic(bat_entries);
		if (stop)
			break;
		delta_bat_entries += PAGE_SIZE / sizeof(map_index_t);
	}
	write_unlock_irq(&ploop->bat_rwlock);
}

static int ploop_check_delta_length(struct ploop *ploop, struct file *file,
				    loff_t *file_size)
{
	loff_t loff = i_size_read(file->f_mapping->host);

	if (loff & (CLU_SIZE(ploop) - 1))
		return -EPROTO;
	*file_size = loff;
	return 0;
}

/*
 * @fd refers to a new delta, which is placed right before top_delta.
 * So, userspace has to populate deltas stack from oldest to newest.
 */
int ploop_add_delta(struct ploop *ploop, u32 level, struct file *file, bool is_raw)
{
	struct ploop_delta *deltas = ploop->deltas;
	struct ploop_pvd_header *hdr = NULL;
	loff_t file_size;
	u32 size_in_clus;
	int ret;

	ret = ploop_check_delta_length(ploop, file, &file_size);
	if (ret)
		goto out;

	if (!is_raw) {
		ret = ploop_read_delta_metadata(ploop, file, (void *)&hdr);
		if (ret)
			goto out;
		size_in_clus = le32_to_cpu(hdr->m_Size);
	} else {
		size_in_clus = POS_TO_CLU(ploop, file_size);
	}

	ret = -EBADSLT;
	if (level != top_level(ploop) &&
	    size_in_clus > deltas[level + 1].size_in_clus)
		goto out;

	apply_delta_mappings(ploop, deltas, level, (void *)hdr, size_in_clus);

	deltas[level].file = file;
	deltas[level].file_size = file_size;
	deltas[level].file_preallocated_area_start = file_size;
	deltas[level].size_in_clus = size_in_clus;
	deltas[level].is_raw = is_raw;
	ret = 0;
out:
	vfree(hdr);
	return ret;
}
