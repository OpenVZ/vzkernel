/*
 *  drivers/md/dm-ploop-bat.c
 *
 *  Copyright (c) 2020-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/init.h>
#include <linux/uio.h>
#include <linux/mm.h>
#include "dm-ploop.h"

/*
 * Read from disk and fill bat_entries[]. Note, that on enter here, cluster #0
 * is already read from disk (with header) -- just parse bio pages content.
 */
static int ploop_read_bat(struct ploop *ploop, struct bio *bio)
{
	unsigned int entries_per_page, nr_copy, page, i = 0;
	map_index_t *addr, off, cluster = 0;
	int ret = 0;

	entries_per_page = PAGE_SIZE / sizeof(map_index_t);

	do {
		for (page = 0; page < nr_pages_in_cluster(ploop); page++) {
			if (i == 0)
				off = PLOOP_MAP_OFFSET;
			else
				off = 0;

			nr_copy = entries_per_page - off;
			if (i + nr_copy > ploop->nr_bat_entries)
				nr_copy = ploop->nr_bat_entries - i;

			addr = kmap(bio->bi_io_vec[page].bv_page);
			memcpy(&ploop->bat_entries[i], addr + off,
				nr_copy * sizeof(map_index_t));
			kunmap(bio->bi_io_vec[page].bv_page);
			i += nr_copy;

			if (i >= ploop->nr_bat_entries)
				goto out;
		}

		ret = ploop_read_cluster_sync(ploop, bio, ++cluster);
		if (ret)
			goto err;

	} while (1);

out:
	for (i = 0; i < ploop->nr_bat_entries; i++) {
		if (ploop->bat_entries[i] == BAT_ENTRY_NONE) {
			ret = -EINVAL;
			goto err;
		}
		if (!ploop->bat_entries[i])
			ploop->bat_entries[i] = BAT_ENTRY_NONE;
	}

err:
	return ret;
}

/* Alloc holes_bitmap and set bits of free clusters */
static int ploop_assign_hb_and_levels(struct ploop *ploop,
				      unsigned int bat_clusters)
{
	unsigned int i, size, dst_cluster;

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

	size = ploop->nr_bat_entries * sizeof(ploop->bat_levels[0]);
	ploop->bat_levels = kvzalloc(size, GFP_KERNEL);
	if (!ploop->bat_levels)
		return -ENOMEM;

	/* Mark all BAT clusters as occupied. */
	for (i = 0; i < bat_clusters; i++)
		ploop_hole_clear_bit(i, ploop);

	/*
	 * Clear all clusters, which are referred to in BAT, from holes_bitmap.
	 * Set bat_levels[] to top delta's level.
	 */
	for (i = 0; i < ploop->nr_bat_entries; i++) {
		dst_cluster = ploop->bat_entries[i];
		if (dst_cluster != BAT_ENTRY_NONE) {
			ploop->bat_levels[i] = BAT_LEVEL_TOP;
			/* Cluster may refer out holes_bitmap after shrinking */
			if (dst_cluster < ploop->hb_nr)
				ploop_hole_clear_bit(dst_cluster, ploop);
		}
	}

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
	void *data;

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

	ret = -ENOMEM;
	/*
	 * Memory for hdr and array of BAT mapping. We keep them
	 * neighbours like they are stored on disk to simplify
	 * BAT update code.
	 */
	data = vmalloc(size);
	if (!data)
		goto out;
	BUG_ON((unsigned long)data & ~PAGE_MASK);

	memcpy(data, m_hdr, sizeof(*m_hdr));
	ploop->hdr = data;
	ploop->bat_entries = data + sizeof(*m_hdr);
	kunmap(page);
	m_hdr = NULL;

	ret = ploop_read_bat(ploop, bio);
	if (ret)
		goto out;

	ret = ploop_assign_hb_and_levels(ploop, bat_clusters);
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
	struct ploop_pvd_header *hdr;
	u64 size, delta_size;
	int ret = -EPROTO;

	hdr = kmap(page);

	if (memcmp(hdr->m_Sig, ploop->hdr->m_Sig, sizeof(hdr->m_Sig)) ||
	    hdr->m_Sectors != ploop->hdr->m_Sectors ||
	    hdr->m_Type != ploop->hdr->m_Type)
		goto out;

	delta_size = le64_to_cpu(hdr->m_SizeInSectors_v2);
	delta_nr_be = le32_to_cpu(hdr->m_Size);
	size = ploop->hdr->m_SizeInSectors_v2;
	cluster_log = ploop->cluster_log;
	offset_clusters = le32_to_cpu(hdr->m_FirstBlockOffset) >> cluster_log;
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
