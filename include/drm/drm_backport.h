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
#include <linux/err.h>
#include <linux/io.h>

/**
 * ktime_mono_to_real - Convert monotonic time to clock realtime
 */
static inline ktime_t ktime_mono_to_real(ktime_t mono)
{
	return ktime_sub(mono, ktime_get_monotonic_offset());
}

static inline void get_monotonic_boottime64(struct timespec64 *ts)
{
	*ts = ktime_to_timespec64(ktime_get_boottime());
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
#define module_param_unsafe(name, type, perm)			\
	module_param(name, type, perm)

/*
 *
 */

#include <linux/mm.h>

#define SHRINK_STOP (~0UL)
/*
 * A callback you can register to apply pressure to ageable caches.
 *
 * @count_objects should return the number of freeable items in the cache. If
 * there are no objects to free or the number of freeable items cannot be
 * determined, it should return 0. No deadlock checks should be done during the
 * count callback - the shrinker relies on aggregating scan counts that couldn't
 * be executed due to potential deadlocks to be run at a later call when the
 * deadlock condition is no longer pending.
 *
 * @scan_objects will only be called if @count_objects returned a non-zero
 * value for the number of freeable objects. The callout should scan the cache
 * and attempt to free items from the cache. It should then return the number
 * of objects freed during the scan, or SHRINK_STOP if progress cannot be made
 * due to potential deadlocks. If SHRINK_STOP is returned, then no further
 * attempts to call the @scan_objects will be made from the current reclaim
 * context.
 *
 * @flags determine the shrinker abilities, like numa awareness
 */
struct shrinker2 {
	unsigned long (*count_objects)(struct shrinker2 *,
				       struct shrink_control *sc);
	unsigned long (*scan_objects)(struct shrinker2 *,
				      struct shrink_control *sc);

	int seeks;	/* seeks to recreate an obj */
	long batch;	/* reclaim batch size, 0 = default */
	unsigned long flags;

	/* These are for internal use */
	struct list_head list;
	/* objs pending delete, per node */
	atomic_long_t *nr_deferred;

	/* compat: */
	struct shrinker compat;
};
int register_shrinker2(struct shrinker2 *shrinker);
void unregister_shrinker2(struct shrinker2 *shrinker);

#define shrinker            shrinker2
#define register_shrinker   register_shrinker2
#define unregister_shrinker unregister_shrinker2

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

#define cpu_relax_lowlatency() cpu_relax()
#define pagefault_disabled()   in_atomic()

static inline int arch_phys_wc_index(int handle)
{
#ifdef CONFIG_X86
	int phys_wc_to_mtrr_index(int handle);
	return phys_wc_to_mtrr_index(handle);
#else
	return -1;
#endif
}

#ifdef CONFIG_X86
static inline void __iomem *acpi_os_ioremap(u64 phys, u32 size)
{
	return ioremap_cache(phys, size);
}
#endif

/*
 * avoiding/emulating 87521e16a7abbf3fa337f56cb4d1e18247f15e8a upstream:
 */

enum acpi_backlight_type {
	acpi_backlight_undef = -1,
	acpi_backlight_none = 0,
	acpi_backlight_video,
	acpi_backlight_vendor,
	acpi_backlight_native,
};

static inline enum acpi_backlight_type acpi_video_get_backlight_type(void)
{
	int acpi_video_backlight_support(void);
	bool acpi_video_verify_backlight_support(void);
	if (acpi_video_backlight_support() &&
			!acpi_video_verify_backlight_support())
		return acpi_backlight_native;
	return acpi_backlight_undef;
}

static inline bool apple_gmux_present(void) { return false; }

int __init drm_backport_init(void);
void __exit drm_backport_exit(void);

#undef pr_fmt

#endif /* DRM_BACKPORT_H_ */
