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
#include <linux/console.h>
#include <linux/refcount.h>
#include <linux/rwsem.h>
#include <linux/mm.h>


#include <linux/time64.h>
static inline time64_t ktime_get_real_seconds(void)
{
	return get_seconds();
}

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

extern struct workqueue_struct *system_power_efficient_wq;


/*
 *
 */

#include <linux/rculist.h>

#define cpu_relax_lowlatency() cpu_relax()

static inline int arch_phys_wc_index(int handle)
{
#ifdef CONFIG_X86
	int phys_wc_to_mtrr_index(int handle);
	return phys_wc_to_mtrr_index(handle);
#else
	return -1;
#endif
}

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
#if IS_ENABLED(CONFIG_ACPI_VIDEO)
	bool acpi_video_verify_backlight_support(void);
	if (acpi_video_backlight_support() &&
			!acpi_video_verify_backlight_support())
		return acpi_backlight_native;
#else
	if (acpi_video_backlight_support())
		return acpi_backlight_native;
#endif
	return acpi_backlight_undef;
}

static inline bool apple_gmux_present(void) { return false; }
static inline bool vga_switcheroo_client_probe_defer(struct pci_dev *pdev) { return false; }

/* cmpxchg_relaxed */
#ifndef cmpxchg_relaxed
#define  cmpxchg_relaxed		cmpxchg
#define  cmpxchg_acquire		cmpxchg
#define  cmpxchg_release		cmpxchg
#endif

static inline int register_vmap_purge_notifier(struct notifier_block *nb)
{
	return 0;
}

static inline int unregister_vmap_purge_notifier(struct notifier_block *nb)
{
	return 0;
}

enum mutex_trylock_recursive_enum {
	MUTEX_TRYLOCK_FAILED    = 0,
	MUTEX_TRYLOCK_SUCCESS   = 1,
	MUTEX_TRYLOCK_RECURSIVE,
};

static bool mutex_is_locked_by(struct mutex *mutex, struct task_struct *task)
{
	if (!mutex_is_locked(mutex))
		return false;

#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_MUTEXES)
	return mutex->owner == task;
#else
	/* Since UP may be pre-empted, we cannot assume that we own the lock */
	return false;
#endif
}

static inline __deprecated __must_check enum mutex_trylock_recursive_enum
mutex_trylock_recursive(struct mutex *lock)
{
	/* BACKPORT NOTE:
	 * Different from upstream to avoid backporting
	 * 3ca0ff571b092ee4d807f1168caa428d95b0173b, but functionally
	 * equivalent for i915 to previous behavior
	 */
	if (unlikely(mutex_is_locked_by(lock, current)))
		return MUTEX_TRYLOCK_RECURSIVE;

	return mutex_trylock(lock);
}


static inline int __must_check down_write_killable(struct rw_semaphore *sem)
{
	down_write(sem);
	return 0;
}


static inline long __drm_get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long start, unsigned long nr_pages, int write,
		int force, struct page **pages, struct vm_area_struct **vmas)
{
	return get_user_pages(tsk, mm, start, nr_pages, write, force, pages, vmas);
}

#define get_user_pages_remote(c, mm, start, nr_pages, write, pages, vmas, locked) \
		__drm_get_user_pages(c, mm, start, nr_pages, write, 0, pages, vmas)
#define get_user_pages(start, nr_pages, write, pages, vmas) \
	__drm_get_user_pages(current, current->mm, start, nr_pages, write, 0, pages, vmas)

#ifndef atomic_set_release
#define  atomic_set_release(v, i)	smp_store_release(&(v)->counter, (i))
#endif

#ifdef CONFIG_X86
#ifndef atomic_andnot
static inline void atomic_andnot(int i, atomic_t *v)
{
	atomic_and(~i, v);
}
#endif
#endif

/* drm_panel stubs to make i915 happy.. I don't think we support any hw
 * using DSI and panel stuff without some work will be unhappy on power
 * or anything else w/ CONFIG_OF..
 */
struct drm_panel;
struct drm_connector;
static inline void drm_panel_init(struct drm_panel *panel) {}
static inline int drm_panel_attach(struct drm_panel *panel, struct drm_connector *connector)
{
	return -ENXIO;
}
static inline int drm_panel_detach(struct drm_panel *panel)
{
	return 0;
}
static inline int drm_panel_add(struct drm_panel *panel)
{
	return -ENXIO;
}
static inline void drm_panel_remove(struct drm_panel *panel) {}

typedef wait_queue_t wait_queue_entry_t;
#define __add_wait_queue_entry_tail __add_wait_queue_tail

static inline void init_wait_entry(wait_queue_entry_t *entry, int flags)
{
	init_wait(entry);
}

unsigned int swiotlb_max_size(void);
#define swiotlb_max_segment swiotlb_max_size

#define SLAB_TYPESAFE_BY_RCU SLAB_DESTROY_BY_RCU

#include <linux/fs.h>

static inline int call_mmap(struct file *file, struct vm_area_struct *vma)
{
	return file->f_op->mmap(file, vma);
}

/*
 * since we just use get_user()/put_user() for unsafe_put_user()
 * and unsafe_get_user(), these can be no-op
 */
#define user_access_begin() do {} while (0)
#define user_access_end()   do {} while (0)

#define unsafe_put_user(x, ptr, err_label)	\
do {						\
	int __pu_err = put_user(x, ptr);	\
	if (unlikely(__pu_err)) goto err_label;	\
} while (0)

#define unsafe_get_user(x, ptr, err_label)	\
do {						\
	int __gu_err = get_user(x, ptr);	\
	if (unlikely(__gu_err)) goto err_label;	\
} while (0)

/*
 * We don't have the commits in the rhel7 kernel which necessitate
 * this flag, so it is just zero.  Define it as an enum so if someone
 * does backport the pci/pm patches, it won't go unnoticed that this
 * needs to be removed.  See bac2a909a096c9110525c18cbb8ce73c660d5f71
 * and 4d071c3238987325b9e50e33051a40d1cce311cc upstream.
 */
enum {
	PCI_DEV_FLAGS_NEEDS_RESUME = 0,
};

#define get_random_u32() ((u32)get_random_int())
#define dev_pm_set_driver_flags(...) do { } while (0)
#define __GFP_RETRY_MAYFAIL __GFP_REPEAT

/* TODO partial backport of a55bbd375d1802141f0f043e2cd08f85c23d6209 */
#define idr_for_each_entry_continue(idp, entry, id)                    \
       for ((entry) = idr_get_next((idp), &(id));                      \
            entry;                                                     \
            ++id, (entry) = idr_get_next((idp), &(id)))

/* until 8eb8284b412906181357c2b0110d879d5af95e52 is backported: */
#define kmem_cache_create_usercopy(n, s, a, f, uo, us, c) \
	kmem_cache_create(n, s, a, f, c)

/*
 * Avoid backporting 6ce711f2750031d12cec91384ac5cfa0a485b60a which
 * depends on 0a835c4f090af2c76fc2932c539c3b32fd21fbbb
 */
#include <linux/idr.h>
static inline void idr_init_base(struct idr *idr, int base)
{
	/* TODO we might need to remap things to idr_get_new_above().. */
	idr_init(idr);
}

/*
 * Avoid backporting 5ade60dda43c8906d4554374226c2eb11cc2ffba
 */

static inline void ida_free(struct ida *ida, unsigned int id)
{
	ida_simple_remove(ida, id);
}

static inline int ida_alloc_range(struct ida *ida, unsigned int min, unsigned int _max, gfp_t gfp)
{
	unsigned int end = max(_max, _max + 1);
	return ida_simple_get(ida, min, end, gfp);
}

static inline int ida_alloc(struct ida *ida, gfp_t gfp)
{
	return ida_alloc_range(ida, 0, ~0, gfp);
}

static inline int ida_alloc_min(struct ida *ida, unsigned int min, gfp_t gfp)
{
	return ida_alloc_range(ida, min, ~0, gfp);
}

static inline int ida_alloc_max(struct ida *ida, unsigned int max, gfp_t gfp)
{
	return ida_alloc_range(ida, 0, max, gfp);
}

/*
 * Avoid poll API changes
 */
typedef unsigned int __poll_t;
#define EPOLLIN POLLIN
#define EPOLLOUT POLLOUT
#define EPOLLRDNORM POLLRDNORM


int __init drm_backport_init(void);
void __exit drm_backport_exit(void);

#undef pr_fmt

#endif /* DRM_BACKPORT_H_ */
