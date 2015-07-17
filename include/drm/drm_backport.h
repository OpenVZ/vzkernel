/*
 * Copyright (C) 2013 Red Hat
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License v2. See the file COPYING in the main directory of this archive for
 * more details.
 */

#ifndef DRM_BACKPORT_H_
#define DRM_BACKPORT_H_

#include <linux/hrtimer.h>

static inline u64 ktime_get_raw_ns(void)
{
	struct timespec now;
	getrawmonotonic(&now);
	return timespec_to_ns(&now);
}

/**
 * ktime_mono_to_real - Convert monotonic time to clock realtime
 */
static inline ktime_t ktime_mono_to_real(ktime_t mono)
{
	return ktime_sub(mono, ktime_get_monotonic_offset());
}

/*
 *
 */

/**
 * list_last_entry - get the last element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_last_entry(ptr, type, member) \
	list_entry((ptr)->prev, type, member)


#define module_param_named_unsafe(name, value, type, perm)		\
	module_param_named(name, value, type, perm)

/*
 *
 */

extern struct workqueue_struct *system_power_efficient_wq;


/*
 *
 */

#include <linux/rculist.h>

/**
 * hlist_add_behind_rcu
 * @n: the new element to add to the hash list.
 * @prev: the existing element to add the new element after.
 *
 * Description:
 * Adds the specified element to the specified hlist
 * after the specified node while permitting racing traversals.
 *
 * The caller must take whatever precautions are necessary
 * (such as holding appropriate locks) to avoid racing
 * with another list-mutation primitive, such as hlist_add_head_rcu()
 * or hlist_del_rcu(), running on this same list.
 * However, it is perfectly legal to run concurrently with
 * the _rcu list-traversal primitives, such as
 * hlist_for_each_entry_rcu(), used to prevent memory-consistency
 * problems on Alpha CPUs.
 */
static inline void hlist_add_behind_rcu(struct hlist_node *n,
                                       struct hlist_node *prev)
{
	hlist_add_after_rcu(prev, n);
}

/* stubs, we don't have mipi-dsi.. */
struct mipi_dsi_device;
struct mipi_dsi_packet;
struct mipi_dsi_msg;
static inline ssize_t mipi_dsi_dcs_write_buffer(struct mipi_dsi_device *dsi,
				  const void *data, size_t len)
{
	return -EINVAL;
}

static inline ssize_t mipi_dsi_generic_write(struct mipi_dsi_device *dsi, const void *payload,
			       size_t size)
{
	return -EINVAL;
}

static inline int mipi_dsi_create_packet(struct mipi_dsi_packet *packet,
			   const struct mipi_dsi_msg *msg)
{
	return -EINVAL;
}

static inline int mipi_dsi_attach(struct mipi_dsi_device *dsi)
{
	return -ENOSYS;
}


int __init drm_backport_init(void);
void __exit drm_backport_exit(void);

#undef pr_fmt

#endif /* DRM_BACKPORT_H_ */
