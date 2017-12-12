/*
 *  include/bc/beancounter.h
 *
 *  Copyright (C) 1999-2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 *  Andrey Savochkin	saw@sw-soft.com
 *
 */

#ifndef _LINUX_BEANCOUNTER_H
#define _LINUX_BEANCOUNTER_H

#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/cache.h>
#include <linux/threads.h>
#include <linux/percpu.h>
#include <linux/percpu_counter.h>
#include <linux/ratelimit.h>
#include <linux/cgroup.h>
#include <bc/decl.h>
#include <asm/atomic.h>

#include <uapi/linux/beancounter.h>

/*
 * This magic is used to distinuish user beancounter and pages beancounter
 * in struct page. page_ub and page_bc are placed in union and MAGIC
 * ensures us that we don't use pbc as ubc in ub_page_uncharge().
 */
#define UB_MAGIC		0x62756275

/*
 * UB_MAXVALUE is essentially LONG_MAX declared in a cross-compiling safe form.
 */
#define UB_MAXVALUE	( (1UL << (sizeof(unsigned long)*8-1)) - 1)


/*
 *	Resource management structures
 * Serialization issues:
 *   beancounter list management is protected via ub_hash_lock
 *   task pointers are set only for current task and only once
 *   refcount is managed atomically
 *   value and limit comparison and change are protected by per-ub spinlock
 */

struct task_beancounter;

struct ub_percpu_struct {
	int dirty_pages;
	int writeback_pages;
	int wb_requests;
	int wb_sectors;

	unsigned long fuse_requests;
	unsigned long fuse_bytes;

#ifdef CONFIG_BC_IO_ACCOUNTING
	unsigned long async_write_complete;
	unsigned long async_write_canceled;
	unsigned long long sync_write_bytes;
	unsigned long long sync_read_bytes;
#endif
	unsigned long	sync;
	unsigned long	sync_done;

	unsigned long	fsync;
	unsigned long	fsync_done;

	unsigned long	fdsync;
	unsigned long	fdsync_done;

	unsigned long	frsync;
	unsigned long	frsync_done;

	/* percpu resource precharge */
	int	precharge[UB_RESOURCES];
};

enum {
	UB_MEM_CGROUP,
	UB_BLKIO_CGROUP,
	NR_UB_BOUND_CGROUPS,
};

struct user_beancounter {
	struct cgroup_subsys_state css;

	struct cgroup_subsys_state *ub_bound_css[NR_UB_BOUND_CGROUPS];

	unsigned long		ub_magic;
	struct list_head	ub_list;

	spinlock_t		ub_lock;
	const char		*ub_name;

	struct ratelimit_state	ub_ratelimit;

	atomic_long_t		dirty_pages;
	atomic_long_t		writeback_pages;
	atomic_long_t		wb_requests;
	atomic_long_t		wb_sectors;

	void			*iolimit;

	/* resources statistic and settings */
	struct ubparm		ub_parms[UB_RESOURCES];
	/* resources statistic for last interval */
	struct ubparm		*ub_store;

	struct ub_percpu_struct	*ub_percpu;
};

extern int ub_count;

enum ub_severity { UB_HARD, UB_SOFT, UB_FORCE };

#define UB_TEST	0x100
#define UB_SEV_FLAGS	UB_TEST

extern struct cgroup_subsys_state *
__ub_get_css(struct user_beancounter *ub, int idx);

static inline struct cgroup_subsys_state *
ub_get_mem_css(struct user_beancounter *ub)
{
	return __ub_get_css(ub, UB_MEM_CGROUP);
}

static inline struct cgroup_subsys_state *
ub_get_blkio_css(struct user_beancounter *ub)
{
	return __ub_get_css(ub, UB_BLKIO_CGROUP);
}

static inline int ub_barrier_hit(struct user_beancounter *ub, int resource)
{
	return ub->ub_parms[resource].held > ub->ub_parms[resource].barrier;
}

static inline int ub_hfbarrier_hit(struct user_beancounter *ub, int resource)
{
	return (ub->ub_parms[resource].held > 
		((ub->ub_parms[resource].barrier) >> 1));
}

static inline int ub_barrier_farnr(struct user_beancounter *ub, int resource)
{
	struct ubparm *p;
	p = ub->ub_parms + resource;
	return p->held <= (p->barrier >> 3);
}

static inline int ub_barrier_farsz(struct user_beancounter *ub, int resource)
{
	struct ubparm *p;
	p = ub->ub_parms + resource;
	return p->held <= (p->barrier >> 3) && p->barrier >= 1024 * 1024;
}

static inline unsigned long ub_resource_bound(struct user_beancounter *ub,
		int resource, enum ub_severity strict)
{
	switch (strict) {
		case UB_HARD:
			return ub->ub_parms[resource].barrier;
		case UB_SOFT:
			return ub->ub_parms[resource].limit;
		case UB_FORCE:
			return UB_MAXVALUE;
		default:
			{
				extern int no_such_severity(void);
				return no_such_severity();
			}
	}
}

static inline unsigned long ub_resource_excess(struct user_beancounter *ub,
		int resource, enum ub_severity strict)
{
	unsigned long held, bound;

	held = ub->ub_parms[resource].held;
	bound = ub_resource_bound(ub, resource, strict);
	if (likely(held < bound))
		return bound - held;
	return 0;
}

#ifndef CONFIG_BEANCOUNTERS

#define ub_percpu(ub, cpu)		(NULL)
#define __ub_percpu_sum(ub, field)	(0)
#define ub_percpu_sum(ub, field)	(0)
#define ub_percpu_add(ub, f, v)	do { } while (0)
#define ub_percpu_sub(ub, f, v)	do { } while (0)
#define ub_percpu_inc(ub, f)	do { } while (0)
#define ub_percpu_dec(ub, f)	do { } while (0)

#define mm_ub(mm)	(NULL)

#define for_each_beancounter(__ubp)	while (0)

extern inline struct user_beancounter *get_beancounter_by_name
		(const char *name, int create) { return NULL; }
extern inline struct user_beancounter *get_beancounter_byuid
		(uid_t uid, int create) { return NULL; }
extern inline struct user_beancounter *get_beancounter
		(struct user_beancounter *ub) { return NULL; }
extern inline void put_beancounter(struct user_beancounter *ub) { }

static inline uid_t ub_legacy_id(struct user_beancounter *ub) { return -1; }

static inline void ub_init_late(void) { };
static inline void ub_init_early(void) { };

static inline int charge_beancounter(struct user_beancounter *ub,
			int resource, unsigned long val,
			enum ub_severity strict) { return 0; }
#define charge_beancounter_fast charge_beancounter
static inline void uncharge_beancounter(struct user_beancounter *ub,
			int resource, unsigned long val) { }
#define uncharge_beancounter_fast uncharge_beancounter

#else /* CONFIG_BEANCOUNTERS */

extern struct list_head ub_list_head;

#define for_each_beancounter(__ubp) \
	list_for_each_entry_rcu(__ubp, &ub_list_head, ub_list)

#define ub_percpu(ub, cpu) (per_cpu_ptr((ub)->ub_percpu, (cpu)))

#define __ub_percpu_sum(ub, field)	({			\
		struct user_beancounter *__ub = (ub);		\
		typeof(ub_percpu(__ub, 0)->field) __sum = 0;	\
		int __cpu;					\
		for_each_possible_cpu(__cpu)			\
			__sum += ub_percpu(__ub, __cpu)->field;	\
		__sum;						\
	})

#define ub_percpu_sum(ub, field)	({			\
		long __sum = __ub_percpu_sum(ub, field);	\
		(__sum < 0) ? 0 : __sum;			\
	})

#define ub_percpu_add(ub, field, v)		do {			\
		per_cpu_ptr(ub->ub_percpu, get_cpu())->field += (v);	\
		put_cpu();						\
	} while (0)
#define ub_percpu_inc(ub, field) ub_percpu_add(ub, field, 1)

#define ub_percpu_sub(ub, field, v)		do {			\
		per_cpu_ptr(ub->ub_percpu, get_cpu())->field -= (v);	\
		put_cpu();						\
	} while (0)
#define ub_percpu_dec(ub, field) ub_percpu_sub(ub, field, 1)

#define mm_ub(mm)	((mm)->mm_ub)
/*
 *  Charge/uncharge operations
 */

extern int __charge_beancounter_locked(struct user_beancounter *ub,
		int resource, unsigned long val, enum ub_severity strict);

extern void __uncharge_beancounter_locked(struct user_beancounter *ub,
		int resource, unsigned long val);

extern void uncharge_warn(struct user_beancounter *ub, const char *resource,
		unsigned long val, unsigned long held);

extern int ub_update_memcg(struct user_beancounter *ub);
extern void ub_sync_memcg(struct user_beancounter *ub);

extern const char *ub_rnames[];
/*
 *	Put a beancounter reference
 */

static inline void put_beancounter(struct user_beancounter *ub)
{
	if (unlikely(ub == NULL))
		return;

	css_put(&ub->css);
}

/*
 *	Create a new beancounter reference
 */
extern struct user_beancounter *get_beancounter_byuid(uid_t uid, int create);
extern struct user_beancounter *get_beancounter_by_name(const char *name,
							int create);

static inline 
struct user_beancounter *get_beancounter(struct user_beancounter *ub)
{
	if (unlikely(ub == NULL))
		return NULL;

	css_get(&ub->css);
	return ub;
}

static inline 
struct user_beancounter *get_beancounter_rcu(struct user_beancounter *ub)
{
	return css_tryget(&ub->css) ? ub : NULL;
}

extern uid_t ub_legacy_id(struct user_beancounter *ub);

extern void ub_init_late(void);
extern void ub_init_early(void);

#define UB_STAT_BATCH	64

static inline void __ub_stat_add(atomic_long_t *stat, int *pcpu, long val)
{
	unsigned long flags;

	local_irq_save(flags);
	pcpu = per_cpu_ptr(pcpu, smp_processor_id());
	if (*pcpu + val <= UB_STAT_BATCH)
		*pcpu += val;
	else {
		atomic_long_add(*pcpu + val, stat);
		*pcpu = 0;
	}
	local_irq_restore(flags);
}

static inline void __ub_stat_sub(atomic_long_t *stat, int *pcpu, long val)
{
	unsigned long flags;

	local_irq_save(flags);
	pcpu = per_cpu_ptr(pcpu, smp_processor_id());
	if (*pcpu - val >= -UB_STAT_BATCH)
		*pcpu -= val;
	else {
		atomic_long_add(*pcpu - val, stat);
		*pcpu = 0;
	}
	local_irq_restore(flags);
}

static inline void __ub_stat_flush_pcpu(atomic_long_t *stat, int *pcpu)
{
	unsigned long flags;

	local_irq_save(flags);
	pcpu = per_cpu_ptr(pcpu, smp_processor_id());
	atomic_long_add(*pcpu, stat);
	*pcpu = 0;
	local_irq_restore(flags);
}

#define ub_stat_add(ub, name, val)	__ub_stat_add(&(ub)->name, &(ub)->ub_percpu->name, val)
#define ub_stat_sub(ub, name, val)	__ub_stat_sub(&(ub)->name, &(ub)->ub_percpu->name, val)
#define ub_stat_inc(ub, name)		ub_stat_add(ub, name, 1)
#define ub_stat_dec(ub, name)		ub_stat_sub(ub, name, 1)
#define ub_stat_mod(ub, name, val)	atomic_long_add(val, &(ub)->name)
#define __ub_stat_get(ub, name)		atomic_long_read(&(ub)->name)
#define ub_stat_get(ub, name)		max(0l, atomic_long_read(&(ub)->name))
#define ub_stat_get_exact(ub, name)	max(0l, __ub_stat_get(ub, name) + __ub_percpu_sum(ub, name))
#define ub_stat_flush_pcpu(ub, name)	__ub_stat_flush_pcpu(&(ub)->name, &(ub)->ub_percpu->name)

int ubstat_alloc_store(struct user_beancounter *ub);

/*
 *	Resource charging
 * Change user's account and compare against limits
 */

static inline void ub_adjust_maxheld(struct user_beancounter *ub, int resource)
{
	if (ub->ub_parms[resource].maxheld < ub->ub_parms[resource].held)
		ub->ub_parms[resource].maxheld = ub->ub_parms[resource].held;
	if (ub->ub_parms[resource].minheld > ub->ub_parms[resource].held)
		ub->ub_parms[resource].minheld = ub->ub_parms[resource].held;
}

int charge_beancounter(struct user_beancounter *ub, int resource,
		unsigned long val, enum ub_severity strict);
void uncharge_beancounter(struct user_beancounter *ub, int resource,
		unsigned long val);

extern int ub_resource_precharge[UB_RESOURCES];
void init_beancounter_precharge(struct user_beancounter *ub, int resource);

static inline int __try_charge_beancounter_percpu(struct user_beancounter *ub,
		struct ub_percpu_struct *ub_pcpu, int resource, unsigned long val)
{
	BUG_ON(ub->ub_parms[resource].max_precharge < 0);

	if (likely(ub_pcpu->precharge[resource] >= val)) {
		ub_pcpu->precharge[resource] -= val;
		return 0;
	}
	return -ENOMEM;
}

static inline int __try_uncharge_beancounter_percpu(struct user_beancounter *ub,
		struct ub_percpu_struct *ub_pcpu, int resource, unsigned long val)
{
	BUG_ON(ub->ub_parms[resource].max_precharge < 0);

	if (likely(ub_pcpu->precharge[resource] + val <=
				ub->ub_parms[resource].max_precharge)) {
		ub_pcpu->precharge[resource] += val;
		return 0;
	}

	return -E2BIG;
}

int __charge_beancounter_percpu(struct user_beancounter *ub,
		struct ub_percpu_struct *ub_pcpu,
		int resource, unsigned long val, enum ub_severity strict);

void __uncharge_beancounter_percpu(struct user_beancounter *ub,
		struct ub_percpu_struct *ub_pcpu,
		int resource, unsigned long val);

static inline int charge_beancounter_fast(struct user_beancounter *ub,
		int resource, unsigned long val, enum ub_severity strict)
{
	struct ub_percpu_struct *ub_pcpu;
	unsigned long flags;
	int retval = 0;

	if (val > UB_MAXVALUE)
		return -EINVAL;

	local_irq_save(flags);
	ub_pcpu = ub_percpu(ub, smp_processor_id());
	if (__try_charge_beancounter_percpu(ub, ub_pcpu, resource, val))
		retval = __charge_beancounter_percpu(ub, ub_pcpu, resource,
							val, strict);
	local_irq_restore(flags);

	return retval;
}

static inline void uncharge_beancounter_fast(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	struct ub_percpu_struct *ub_pcpu;
	unsigned long flags;

	local_irq_save(flags);
	ub_pcpu = ub_percpu(ub, smp_processor_id());
	if (__try_uncharge_beancounter_percpu(ub, ub_pcpu, resource, val))
		__uncharge_beancounter_percpu(ub, ub_pcpu, resource, val);
	local_irq_restore(flags);
}

unsigned long __get_beancounter_usage_percpu(struct user_beancounter *ub,
		int resource);

int precharge_beancounter(struct user_beancounter *ub,
		int resource, unsigned long val);
void ub_precharge_snapshot(struct user_beancounter *ub, int *precharge);

#define UB_IOPRIO_MIN 0
#define UB_IOPRIO_MAX 8

#endif /* CONFIG_BEANCOUNTERS */

#ifdef CONFIG_BC_IO_PRIORITY
extern int ub_set_ioprio(int id, int ioprio);
#else
static inline int ub_set_ioprio(int veid, int ioprio) { return -EINVAL; }
#endif

#endif /* _LINUX_BEANCOUNTER_H */
