/*
 *  drivers/block/ploop/io_direct_map.h
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *
 */

#ifndef __INTERVAL_TREE_H__
#define __INTERVAL_TREE_H__

#include <linux/rbtree.h>

struct extent_map_tree
{
	struct rb_root map;
	struct list_head lru_list;
	unsigned int map_size; /* # entries in map */
	rwlock_t lock;
	struct address_space * mapping;
	int (*_get_extent)(struct inode *inode, sector_t isec,
			   unsigned int nr, sector_t *start,
			   sector_t *psec, int creat);
};

struct extent_map
{
	struct rb_node rb_node;
	struct list_head lru_link;

	sector_t	start;
	sector_t	end;

	sector_t	block_start;

	atomic_t refs;

	bool uninit;
};

extern int max_extent_map_pages;
extern int min_extent_map_entries;

static inline sector_t extent_map_block_end(struct extent_map *em)
{
	return em->block_start + (em->end - em->start);
}

struct extent_map *extent_lookup_create(struct ploop_io *io,
					sector_t start, sector_t len);
struct extent_map *extent_lookup(struct extent_map_tree *tree,
				 sector_t start);
void ploop_extent_put(struct extent_map *em);

struct extent_map *map_extent_get_block(struct ploop_io *io,
					struct address_space *mapping,
					sector_t start, sector_t len, int create,
					gfp_t gfp_mask, get_block_t get_block);
void trim_extent_mappings(struct ploop_device *plo,
			  struct extent_map_tree *tree, sector_t start);

int ploop_dio_close(struct ploop_io * io, int rdonly);
struct extent_map_tree * ploop_dio_open(struct ploop_io * io, int rdonly);
void ploop_dio_downgrade(struct address_space * mapping);
int ploop_dio_upgrade(struct ploop_io * io);

int __init ploop_extent_map_init(void);
void ploop_extent_map_exit(void);

#endif
