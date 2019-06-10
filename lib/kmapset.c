/*
 *  lib/kmapset.c
 *
 *  Copyright (c) 2013-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/kmapset.h>
#include <linux/slab.h>
#include <linux/hash.h>

struct kmapset_map *kmapset_new(struct kmapset_set *set)
{
	struct kmapset_map *map;

	map = kmalloc(sizeof(struct kmapset_map), GFP_KERNEL);
	if (!map)
		return NULL;
	kmapset_init_map(map, set);
	return map;
}

static void kmapset_free(struct kmapset_map *map)
{
	struct kmapset_link *link;
	struct hlist_node *next;

	hlist_for_each_entry_safe(link, next, &map->links, map_link)
		kfree_rcu(link, rcu_head);
	kfree_rcu(map, rcu_head);
}

static long kmapset_cmp(struct kmapset_map *map_a, struct kmapset_map *map_b)
{
	struct kmapset_link *link_a, *link_b;

	if (map_a->hash != map_b->hash)
		return map_a->hash - map_b->hash;

	if (map_a->size != map_b->size)
		return map_a->size - map_b->size;

	link_b = hlist_entry(map_b->links.first,
			struct kmapset_link, map_link);
	hlist_for_each_entry(link_a, &map_a->links, map_link) {
		if (link_a->key != link_b->key)
			return (long)link_a->key - (long)link_b->key;
		if (link_a->value != link_b->value)
			return link_a->value - link_b->value;
		link_b = hlist_entry(link_b->map_link.next,
				struct kmapset_link, map_link);
	}

	return map_a->default_value - map_b->default_value;
}

static inline bool kmapset_hashed(struct kmapset_map *map)
{
	return !RB_EMPTY_NODE(&map->node);
}

static bool kmapset_hash(struct kmapset_map *map, struct kmapset_map **old)
{
	struct rb_node **p = &map->set->tree.rb_node;
	struct rb_node *parent = NULL;
	struct kmapset_map *cur;
	struct kmapset_link *link;
	long diff;

	map->hash = hash_long(map->default_value, BITS_PER_LONG);
	hlist_for_each_entry(link, &map->links, map_link)
		map->hash ^= hash_ptr(link->key, BITS_PER_LONG) *
			     hash_long(link->value, BITS_PER_LONG);

	while (*p) {
		parent = *p;
		cur = rb_entry(parent, struct kmapset_map, node);
		diff = kmapset_cmp(map, cur);
		if (diff < 0)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
		if (!diff && old) {
			*old = cur;
			return true;
		}
	}
	rb_link_node(&map->node, parent, p);
	rb_insert_color(&map->node, &map->set->tree);
	return false;
}

static void kmapset_unhash(struct kmapset_map *map)
{
	rb_erase(&map->node, &map->set->tree);
	RB_CLEAR_NODE(&map->node);
}

static void kmapset_rehash(struct kmapset_map *map)
{
	if (kmapset_hashed(map)) {
		kmapset_unhash(map);
		kmapset_hash(map, NULL);
	}
}

struct kmapset_map *kmapset_get(struct kmapset_map *map)
{
	if (map)
		kref_get(&map->kref);
	return map;
}

static void kmapset_release(struct kref *kref)
{
	struct kmapset_map *map = container_of(kref, struct kmapset_map, kref);
	struct kmapset_set *set = map->set;
	struct kmapset_link *link;

	if (kmapset_hashed(map))
		kmapset_unhash(map);
	hlist_for_each_entry(link, &map->links, map_link)
		hlist_del(&link->key_link);
	mutex_unlock(&set->mutex);

	kmapset_free(map);
}

void kmapset_put(struct kmapset_map *map)
{
	if (map)
		kref_put_mutex(&map->kref, kmapset_release, &map->set->mutex);
}

/*
 * kmapset_commit - hash new map into set or lookup existing copy\
 *
 * after committing map must stay immutable
 */
struct kmapset_map *kmapset_commit(struct kmapset_map *map)
{
	struct kmapset_set *set = map->set;
	struct kmapset_map *ret = map;

	kmapset_lock(set);
	if (kmapset_hash(map, &ret)) {
		kmapset_get(ret);
		kmapset_release(&map->kref);
	} else
		kmapset_unlock(set);

	return ret;
}

/*
 * kmapset_copy - copy content of one set to another
 */
static int kmapset_copy(struct kmapset_map *dst, struct kmapset_map *src)
{
	struct kmapset_set *set = src->set;
	struct kmapset_link *old_link, *new_link;
	struct hlist_node *next;
	int i;

	for (i = src->size; i; i--) {
		new_link = kmalloc(sizeof(struct kmapset_link), GFP_KERNEL);
		if (!new_link)
			return -ENOMEM;
		hlist_add_head(&new_link->map_link, &dst->links);
	}

	kmapset_lock(set);
	dst->default_value = src->default_value;
	new_link = hlist_entry(dst->links.first, struct kmapset_link, map_link);
	hlist_for_each_entry(old_link, &src->links, map_link) {
		new_link->key = old_link->key;
		new_link->value = old_link->value;
		new_link->map = dst;
		dst->size++;
		hlist_add_head(&new_link->key_link, &new_link->key->links);
		new_link = hlist_entry(new_link->map_link.next,
				struct kmapset_link, map_link);
	}
	kmapset_unlock(set);

	while (&new_link->map_link) {
		next = new_link->map_link.next;
		hlist_del(&new_link->map_link);
		kfree(new_link);
		new_link = hlist_entry(next, struct kmapset_link, map_link);
	}

	return 0;
}

struct kmapset_map *kmapset_dup(struct kmapset_map *map)
{
	struct kmapset_map *new;

	new = kmapset_new(map->set);
	if (!new)
		return NULL;

	if (kmapset_copy(new, map)) {
		kmapset_free(new);
		return NULL;
	}

	return new;
}

/*
 * kmapset_value - lookup link object for given key
 *
 * requires kmapset_lock or rcu_read_lock
 */
struct kmapset_link *
kmapset_lookup(struct kmapset_map *map, struct kmapset_key *key)
{
	struct kmapset_link *link;

	hlist_for_each_entry_rcu(link, &map->links, map_link) {
		if (link->key == key)
			return link;
		if (link->key > key)
			break;
	}
	return NULL;
}

/*
 * kmapset_get_value - retrieve value for given key
 */
unsigned long
kmapset_get_value(struct kmapset_map *map, struct kmapset_key *key)
{
	struct kmapset_link *link;
	unsigned long value;

	rcu_read_lock();
	link = kmapset_lookup(map, key);
	value = link ? link->value : map->default_value;
	rcu_read_unlock();
	return value;
}

int kmapset_set_value(struct kmapset_map *map,
		struct kmapset_key *key, unsigned long value)
{
	struct kmapset_set *set = map->set;
	struct kmapset_link *new_link, *old_link, *last_link = NULL;

	new_link = kmalloc(sizeof(struct kmapset_link), GFP_KERNEL);
	if (!new_link)
		return -ENOMEM;

	new_link->key = key;
	new_link->value = value;
	new_link->map = map;

	kmapset_lock(set);
	if (hlist_empty(&map->links)) {
		hlist_add_head_rcu(&new_link->map_link, &map->links);
	} else {
		hlist_for_each_entry(old_link, &map->links, map_link) {
			last_link = old_link;
			if (old_link->key < key)
				continue;
			if (old_link->key == key) {
				old_link->value = value;
				kfree(new_link);
				goto out;
			}
			hlist_add_before_rcu(&new_link->map_link,
					     &old_link->map_link);
			goto add;
		}
		hlist_add_behind_rcu(&new_link->map_link, &last_link->map_link);
	}
add:
	hlist_add_head(&new_link->key_link, &new_link->key->links);
	map->size++;
out:
	kmapset_unlock(set);

	return 0;
}

bool kmapset_del_value(struct kmapset_map *map, struct kmapset_key *key)
{
	struct kmapset_set *set = map->set;
	struct kmapset_link *link;
	bool ret = false;

	kmapset_lock(set);
	link = kmapset_lookup(map, key);
	if (link) {
		hlist_del_rcu(&link->map_link);
		hlist_del(&link->key_link);
		kfree_rcu(link, rcu_head);
		ret = true;
	}
	kmapset_unlock(set);
	return ret;
}

void kmapset_set_default(struct kmapset_map *map, unsigned long value)
{
	struct kmapset_set *set = map->set;

	kmapset_lock(set);
	map->default_value = value;
	kmapset_unlock(set);
}

/*
 * kmapset_unlink - unlink key from all maps in set
 */
void kmapset_unlink(struct kmapset_key *key, struct kmapset_set *set)
{
	struct kmapset_link *link;
	struct kmapset_map *map;
	struct hlist_node *next;

	kmapset_lock(set);
	hlist_for_each_entry_safe(link, next, &key->links, key_link) {
		map = link->map;
		hlist_del(&link->key_link);
		hlist_del_rcu(&link->map_link);
		map->size--;
		kfree_rcu(link, rcu_head);
		kmapset_rehash(map);
	}
	kmapset_unlock(set);
}
