#include <linux/init.h>
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

void md_page_insert(struct ploop *ploop, struct md_page *new_md)
{
	struct rb_root *root = &ploop->bat_entries;
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

struct md_page * alloc_md_page(unsigned int id)
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

void free_md_page(struct md_page *md)
{
	put_page(md->page);
	kfree(md->bat_levels);
	kfree(md);
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

/*
 * Clear all clusters, which are referred to in BAT, from holes_bitmap.
 * Set bat_levels[] to top delta's level. Mark unmapped clusters as
 * BAT_ENTRY_NONE.
 */
static int parse_bat_entries(struct ploop *ploop, map_index_t *bat_entries,
		     u8 *bat_levels, unsigned int nr, unsigned int page_id)
{
	int i = 0;

	if (page_id == 0)
		i = PLOOP_MAP_OFFSET;

	for (; i < nr; i++) {
		if (bat_entries[i] == BAT_ENTRY_NONE)
			return -EINVAL;
		if (bat_entries[i]) {
			bat_levels[i] = BAT_LEVEL_TOP;
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
static int ploop_read_bat(struct ploop *ploop, struct bio *bio)
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
			md = alloc_md_page(id);
			if (!md) {
				ret = -ENOMEM;
				goto out;
			}
			md_page_insert(ploop, md);

			nr_copy = entries_per_page;
			if (i + nr_copy > nr_all)
				nr_copy = nr_all - i;

			to = kmap(md->page);
			from = kmap(bio->bi_io_vec[page].bv_page);
			memcpy(to, from, nr_copy * sizeof(map_index_t));
			kunmap(bio->bi_io_vec[page].bv_page);
			ret = parse_bat_entries(ploop, to, md->bat_levels,
						nr_copy, id);
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

/*
 * Allocate memory for bat_entries, bat_levels and holes_bitmap,
 * and read their content from disk.
 */
int ploop_read_metadata(struct dm_target *ti, struct ploop *ploop)
{
	unsigned int bat_clusters, offset_clusters, cluster_log;
	struct ploop_pvd_header *m_hdr = NULL;
	unsigned long size;
	struct page *page;
	struct bio *bio;
	int ret;

	cluster_log = ploop->cluster_log;

	bio = alloc_bio_with_pages(ploop);
	if (!bio)
		return -ENOMEM;

	ret = ploop_read_cluster_sync(ploop, bio, 0);
	if (ret < 0)
		goto out;

	page = bio->bi_io_vec[0].bv_page;
	m_hdr = kmap(page);

	ret = -ENOTSUPP;
	if (strncmp(m_hdr->m_Sig, "WithouFreSpacExt", 16))
		goto out;

	ret = -ENOLCK;
	if (m_hdr->m_DiskInUse != cpu_to_le32(SIGNATURE_DISK_IN_USE) &&
	    !ploop_is_ro(ploop))
		goto out;

	ret = -EINVAL;
	if (le32_to_cpu(m_hdr->m_Sectors) != 1 << cluster_log)
		goto out;

	ploop->nr_bat_entries = le32_to_cpu(m_hdr->m_Size);

	/* Header and BAT-occupied clusters at start of file */
	size = (PLOOP_MAP_OFFSET + ploop->nr_bat_entries) * sizeof(map_index_t);
	bat_clusters = DIV_ROUND_UP(size, 1 << (cluster_log + 9));

	/* Clusters from start of file to first data block */
	offset_clusters = le32_to_cpu(m_hdr->m_FirstBlockOffset) >> cluster_log;
	if (bat_clusters != offset_clusters) {
		pr_err("ploop: custom FirstBlockOffset\n");
		goto out;
	}
	kunmap(page);
	m_hdr = NULL;

	ret = ploop_setup_holes_bitmap(ploop, bat_clusters);
	if (ret)
		goto out;

	ret = ploop_read_bat(ploop, bio);
out:
	if (m_hdr)
		kunmap(page);
	free_bio_with_pages(ploop, bio);
	return ret;
}

static int ploop_delta_check_header(struct ploop *ploop, struct page *page,
		       unsigned int *nr_pages, unsigned int *last_page_len)
{
	unsigned int bytes, delta_nr_be, offset_clusters, bat_clusters, cluster_log;
	struct ploop_pvd_header *d_hdr, *hdr;
	u64 size, delta_size;
	struct md_page *md;
	int ret = -EPROTO;

	md = md_page_find(ploop, 0);
	if (!md)
		return -ENXIO;

	hdr = kmap(md->page);
	d_hdr = kmap(page);

	if (memcmp(d_hdr->m_Sig, hdr->m_Sig, sizeof(d_hdr->m_Sig)) ||
	    d_hdr->m_Sectors != hdr->m_Sectors ||
	    d_hdr->m_Type != hdr->m_Type)
		goto out;

	delta_size = le64_to_cpu(d_hdr->m_SizeInSectors_v2);
	delta_nr_be = le32_to_cpu(d_hdr->m_Size);
	size = hdr->m_SizeInSectors_v2;
	cluster_log = ploop->cluster_log;
	offset_clusters = le32_to_cpu(d_hdr->m_FirstBlockOffset) >> cluster_log;
	bytes = (PLOOP_MAP_OFFSET + delta_nr_be) * sizeof(map_index_t);
	bat_clusters = DIV_ROUND_UP(bytes, 1 << (cluster_log + 9));

	if (delta_size > size || delta_nr_be > ploop->nr_bat_entries ||
	    bat_clusters != offset_clusters)
		goto out;

	*nr_pages = DIV_ROUND_UP(bytes, PAGE_SIZE);
	bytes &= ~PAGE_MASK;
	*last_page_len = bytes ? : PAGE_SIZE;
	ret = 0;
out:
	kunmap(md->page);
	kunmap(page);
	return ret;
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

		iov_iter_bvec(&iter, READ|ITER_BVEC, &bvec, 1, bvec.bv_len);
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
	for (i = 0; i < ploop->nr_bat_entries; i++) {
		if (delta_bat_entries[i] == BAT_ENTRY_NONE) {
			ret = -EPROTO;
			goto out_vfree;
		}
		if (!delta_bat_entries[i])
			delta_bat_entries[i] = BAT_ENTRY_NONE;
	}

out_vfree:
	if (ret) {
		vfree(*d_hdr);
		*d_hdr = NULL;
	}
out_put_page:
	put_page(page);
	return ret;
}
