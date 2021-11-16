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

struct md_page * md_page_find(struct ploop *ploop, u32 id)
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
	struct rb_node *parent, **node;
	u32 new_id = new_md->id;
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

static struct md_page * alloc_md_page(u32 id)
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
	INIT_LIST_HEAD(&md->wait_list);
	INIT_LIST_HEAD(&md->wb_link);

	md->status = 0;
	md->bat_levels = levels;
	md->piwb = NULL;
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

int prealloc_md_pages(struct rb_root *root, u32 nr_bat_entries,
		      u32 new_nr_bat_entries)
{
	u32 i, nr_pages, new_nr_pages;
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

bool try_update_bat_entry(struct ploop *ploop, u32 clu, u8 level, u32 dst_clu)
{
	u32 *bat_entries, id = bat_clu_to_page_nr(clu);
	struct md_page *md = md_page_find(ploop, id);

	lockdep_assert_held(&ploop->bat_rwlock);

	if (!md)
		return false;

	clu = bat_clu_idx_in_page(clu); /* relative offset */

	if (md->bat_levels[clu] == level) {
		bat_entries = kmap_atomic(md->page);
		bat_entries[clu] = dst_clu;
		kunmap_atomic(bat_entries);
		return true;
	}
	return false;
}

/* Alloc holes_bitmap and set bits of free clusters */
static int ploop_setup_holes_bitmap(struct ploop *ploop, u32 bat_clusters)
{
	u32 i, size;

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
	struct ploop_pvd_header *m_hdr = NULL;
	u32 bat_clusters, offset_clusters;
	struct dm_target *ti = ploop->ti;
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
	ret = -EBADSLT;
	if (le64_to_cpu(m_hdr->m_SizeInSectors_v2) < ti->len) {
		pr_err("ploop: Too short BAT\n");
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

static int ploop_delta_check_header(struct ploop *ploop,
				    struct rb_root *md_root,
				    u32 *delta_nr_be_ret)
{
	u32 bytes, delta_nr_be, offset_clusters, bat_clusters;
	struct md_page *md0 = md_first_entry(md_root);
	struct ploop_pvd_header *d_hdr;
	int ret = -EPROTO;

	WARN_ON_ONCE(md0->id != 0);

	d_hdr = kmap(md0->page);
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

	*delta_nr_be_ret = delta_nr_be;
	ret = 0;
out:
	kunmap(md0->page);
	return ret;
}

static int convert_bat_entries(struct ploop *ploop, struct rb_root *md_root,
			       u32 nr_be, u32 nr_pages, loff_t file_size)
{
	u32 i, end, bytes, bat_clusters, page_id, *bat_entries, max_file_clu;
	struct rb_node *node;
	struct md_page *md;
	int ret = 0;

	bytes = (PLOOP_MAP_OFFSET + nr_be) * sizeof(map_index_t);
	bat_clusters = DIV_ROUND_UP(bytes, CLU_SIZE(ploop));
	max_file_clu = file_size / CLU_SIZE(ploop) - 1;

	page_id = 0;
	rb_root_for_each_md_page(md_root, md, node) {
		bat_entries = kmap(md->page);
		init_be_iter(nr_be, md->id, &i, &end);
		WARN_ON_ONCE(page_id != md->id);
		page_id++;

		for (; i <= end; i++) {
			if (bat_entries[i] > max_file_clu)
				ret = -EPROTO;
			if (!bat_entries[i])
				bat_entries[i] = BAT_ENTRY_NONE;
			if (bat_entries[i] < bat_clusters)
				ret = -EXDEV;
		}
		kunmap(md->page);

		if (ret || page_id == nr_pages)
			break;
	}

	return ret;
}

int ploop_read_delta_metadata(struct ploop *ploop, struct file *file,
			      struct rb_root *md_root, u32 *delta_nr_be_ret)
{
	struct bio_vec bvec_on_stack, *bvec = &bvec_on_stack;
	u32 i, size, delta_nr_be, nr_segs;
	loff_t pos, file_size;
	struct iov_iter iter;
	struct rb_node *node;
	struct md_page *md;
	ssize_t len;
	int ret;

	ret = -ENOMEM;
	if (prealloc_md_pages(md_root, 0, 1))
		goto out;
	bvec[0].bv_page = md_first_entry(md_root)->page;
	bvec[0].bv_len = PAGE_SIZE;
	bvec[0].bv_offset = 0;

	iov_iter_bvec(&iter, READ, bvec, 1, PAGE_SIZE);
	pos = 0;

	len = vfs_iter_read(file, &iter, &pos, 0);
	if (len != PAGE_SIZE) {
		ret = len < 0 ? (int)len : -ENODATA;
		goto out;
	}

	ret = ploop_delta_check_header(ploop, md_root, &delta_nr_be);
	if (ret)
		goto out;

	size = (PLOOP_MAP_OFFSET + delta_nr_be) * sizeof(map_index_t);
	size = ALIGN(size, PAGE_SIZE); /* file may be open as direct */
	nr_segs = size / PAGE_SIZE;

	ret = -ENOMEM;
	if (prealloc_md_pages(md_root, 1, delta_nr_be))
		goto out;

	bvec = kvmalloc(sizeof(*bvec) * nr_segs, GFP_KERNEL);
	if (!bvec)
		goto out;

	ret = -EMLINK;
	i = 0;
	rb_root_for_each_md_page(md_root, md, node) {
		if (WARN_ON_ONCE(md->id != i))
			goto out;
		bvec[i].bv_page = md->page;
		bvec[i].bv_len = PAGE_SIZE;
		bvec[i].bv_offset = 0;
		i++;
	}

	iov_iter_bvec(&iter, READ, bvec, nr_segs, size);
	pos = 0;

	len = vfs_iter_read(file, &iter, &pos, 0);
	if (len != size) {
		ret = len < 0 ? (int)len : -ENODATA;
		goto out;
	}

	file_size = i_size_read(file->f_mapping->host);

	ret = convert_bat_entries(ploop, md_root, delta_nr_be, nr_segs, file_size);

	*delta_nr_be_ret = delta_nr_be;
out:
	if (ret)
		free_md_pages_tree(md_root);
	if (bvec != &bvec_on_stack)
		kvfree(bvec);
	return ret;
}

static void ploop_set_not_hole(struct ploop *ploop, u32 dst_clu)
{
	/* Cluster may refer out holes_bitmap after shrinking */
	if (dst_clu < ploop->hb_nr)
		ploop_hole_clear_bit(dst_clu, ploop);
}

/*
 * Prefer first added delta, since the order is:
 * 1)add top device
 * 2)add newest delta
 * ...
 * n)add oldest delta
 */
static void apply_delta_mappings(struct ploop *ploop, struct ploop_delta *deltas,
				 u32 level, struct rb_root *md_root, u64 size_in_clus)
{
	map_index_t *bat_entries, *d_bat_entries = NULL;
	bool is_top_level, is_raw, stop = false;
	struct md_page *md, *d_md = NULL;
	u32 i, end, dst_clu, clu;
	struct rb_node *node;

	is_raw = deltas[level].is_raw;
	is_top_level = (level == top_level(ploop));

	if (!is_raw)
		d_md = md_first_entry(md_root);

	write_lock_irq(&ploop->bat_rwlock);
	ploop_for_each_md_page(ploop, md, node) {
		bat_entries = kmap_atomic(md->page);
		if (!is_raw)
			d_bat_entries = kmap_atomic(d_md->page);

		if (is_top_level && md->id == 0 && !is_raw) {
			/* bat_entries before PLOOP_MAP_OFFSET is hdr */
			memcpy(bat_entries, d_bat_entries,
			       sizeof(struct ploop_pvd_header));
		}

		init_be_iter(size_in_clus, md->id, &i, &end);

		for (; i <= end; i++) {
			clu = page_clu_idx_to_bat_clu(md->id, i);
			if (clu == size_in_clus - 1)
				stop = true;

			if (bat_entries[i] != BAT_ENTRY_NONE) {
				/* md0 is already populated */
				WARN_ON_ONCE(md->id && is_top_level);
				goto set_not_hole;
			}

			if (!is_raw)
				dst_clu = d_bat_entries[i];
			else
				dst_clu = clu;

			if (dst_clu == BAT_ENTRY_NONE)
				continue;
			md->bat_levels[i] = level;
			bat_entries[i] = dst_clu;
set_not_hole:
			if (is_top_level)
				ploop_set_not_hole(ploop, bat_entries[i]);
		}

		kunmap_atomic(bat_entries);
		if (!is_raw)
			kunmap_atomic(d_bat_entries);
		if (stop)
			break;
		if (!is_raw)
			d_md = md_next_entry(d_md);
	}
	write_unlock_irq(&ploop->bat_rwlock);
}

int ploop_check_delta_length(struct ploop *ploop, struct file *file, loff_t *file_size)
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
	struct rb_root md_root = RB_ROOT;
	loff_t file_size;
	u32 size_in_clus;
	int ret;

	ret = ploop_check_delta_length(ploop, file, &file_size);
	if (ret)
		goto out;

	if (!is_raw) {
		ret = ploop_read_delta_metadata(ploop, file, &md_root,
						&size_in_clus);
		if (ret)
			goto out;
	} else {
		size_in_clus = POS_TO_CLU(ploop, file_size);
	}

	ret = -EBADSLT; /* Lower delta can't be bigger then upper */
	if (level != top_level(ploop) &&
	    size_in_clus > deltas[level + 1].size_in_clus)
		goto out;

	apply_delta_mappings(ploop, deltas, level, &md_root, size_in_clus);

	deltas[level].file = file;
	deltas[level].file_size = file_size;
	deltas[level].file_preallocated_area_start = file_size;
	deltas[level].size_in_clus = size_in_clus;
	deltas[level].is_raw = is_raw;
	ret = 0;
out:
	free_md_pages_tree(&md_root);
	return ret;
}
