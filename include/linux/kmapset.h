/*
 *  include/linux/kmapset.h
 *
 *  Copyright (c) 2013-2015 Parallels IP Holdings GmbH
 *
 */

#ifndef _LINUX_KMAPSET_H
#define _LINUX_KMAPSET_H

#include <linux/kernel.h>
#include <linux/rbtree.h>
#include <linux/rculist.h>
#include <linux/kref.h>

struct kmapset_map;

struct kmapset_set {
	struct mutex		mutex;
	struct rb_root		tree;
	unsigned long		default_value;
};

struct kmapset_map {
	struct kref		kref;
	unsigned		size;
	struct kmapset_set	*set;
	unsigned long		default_value;
	unsigned long		hash;
	struct hlist_head	links;
	union {
		struct rb_node		node;
		struct rcu_head		rcu_head;
	};
};

struct kmapset_key {
	struct hlist_head	links;
};

struct kmapset_link {
	struct kmapset_map	*map;
	struct kmapset_key	*key;
	unsigned long		value;
	struct hlist_node	map_link;
	union {
		struct hlist_node	key_link;
		struct rcu_head		rcu_head;
	};
};

static inline void kmapset_lock(struct kmapset_set *set)
{
	mutex_lock(&set->mutex);
}

static inline void kmapset_unlock(struct kmapset_set *set)
{
	mutex_unlock(&set->mutex);
}

struct kmapset_map *kmapset_new(struct kmapset_set *set);

static inline void kmapset_init_set(struct kmapset_set *set)
{
	mutex_init(&set->mutex);
	set->tree = RB_ROOT;
	set->default_value = 0;
}

static inline void kmapset_init_map(struct kmapset_map *map,
		struct kmapset_set *set)
{
	kref_init(&map->kref);
	map->size = 0;
	map->set = set;
	map->default_value = set->default_value;
	INIT_HLIST_HEAD(&map->links);
	RB_CLEAR_NODE(&map->node);
}

static inline void kmapset_init_key(struct kmapset_key *key)
{
	 INIT_HLIST_HEAD(&key->links);
}

struct kmapset_map *kmapset_get(struct kmapset_map *map);
void kmapset_put(struct kmapset_map *map);

struct kmapset_map *kmapset_dup(struct kmapset_map *old);
struct kmapset_map *kmapset_commit(struct kmapset_map *map);

struct kmapset_link *kmapset_lookup(struct kmapset_map *map,
		struct kmapset_key *key);
unsigned long kmapset_get_value(struct kmapset_map *map,
		struct kmapset_key *key);
int kmapset_set_value(struct kmapset_map *map,
		struct kmapset_key *key, unsigned long value);
bool kmapset_del_value(struct kmapset_map *map, struct kmapset_key *key);
void kmapset_set_default(struct kmapset_map *map, unsigned long value);

void kmapset_unlink(struct kmapset_key *key, struct kmapset_set *set);

#endif /* _LINUX_KMAPSET_H */
