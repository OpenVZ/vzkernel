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
#include <linux/oom.h>
#include <linux/ratelimit.h>
#include <linux/cgroup.h>
#include <bc/debug.h>
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
struct sock_beancounter;

struct page_private {
	unsigned long		ubp_tmpfs_respages;
};

struct sock_private {
	unsigned long		ubp_rmem_thres;
	unsigned long		ubp_wmem_pressure;
	unsigned long		ubp_maxadvmss;
	unsigned long		ubp_rmem_pressure;
	int			ubp_tw_count;
#define UB_RMEM_EXPAND          0
#define UB_RMEM_KEEP            1
#define UB_RMEM_SHRINK          2
	struct list_head	ubp_other_socks;
	struct list_head	ubp_tcp_socks;
	struct percpu_counter	ubp_orphan_count;
};

struct ub_percpu_struct {
	int dirty_pages;
	int writeback_pages;
	int wb_requests;
	int wb_sectors;

	unsigned long fuse_requests;
	unsigned long fuse_bytes;

	unsigned long swapin;
	unsigned long swapout;

	unsigned long vswapin;
	unsigned long vswapout;

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

	int pincount;
};

struct user_beancounter {
	struct cgroup_subsys_state css;

	unsigned long		ub_magic;
	struct list_head	ub_list;

	struct rcu_head		rcu;

	spinlock_t		ub_lock;
	const char		*ub_name;

	unsigned long		ub_flags;

	struct ratelimit_state	ub_ratelimit;

	struct page_private	ppriv;
#define ub_tmpfs_respages	ppriv.ubp_tmpfs_respages
	struct sock_private	spriv;
#define ub_rmem_thres		spriv.ubp_rmem_thres
#define ub_maxadvmss		spriv.ubp_maxadvmss
#define ub_rmem_pressure	spriv.ubp_rmem_pressure
#define ub_wmem_pressure	spriv.ubp_wmem_pressure
#define ub_tcp_sk_list		spriv.ubp_tcp_socks
#define ub_other_sk_list	spriv.ubp_other_socks
#define ub_orphan_count		spriv.ubp_orphan_count
#define ub_tw_count		spriv.ubp_tw_count

	atomic_long_t		dirty_pages;
	atomic_long_t		writeback_pages;
	atomic_long_t		wb_requests;
	atomic_long_t		wb_sectors;

	/* reclaim rate-limit */
	spinlock_t		rl_lock;
	unsigned		rl_step;	/* ns per page */
	ktime_t			rl_wall;	/* wall time */

	void			*private_data2;

	struct list_head	ub_dentry_lru;
	struct list_head	ub_dentry_top;
	int			ub_dentry_unused;
	int			ub_dentry_batch;
	unsigned long		ub_dentry_pruned;

	/* resources statistic and settings */
	struct ubparm		ub_parms[UB_RESOURCES];
	/* resources statistic for last interval */
	struct ubparm		*ub_store;

	struct ub_percpu_struct	*ub_percpu;
	struct oom_control	oom_ctrl;
};

enum ub_flags {
	UB_DIRTY_EXCEEDED,
	UB_OOM_NOPROC,
	UB_OOM_MANUAL_SCORE_ADJ,
};

extern int ub_count;
extern struct oom_control global_oom_ctrl;

enum ub_severity { UB_HARD, UB_SOFT, UB_FORCE };

#define UB_TEST	0x100
#define UB_SEV_FLAGS	UB_TEST

extern struct cgroup_subsys ub_subsys;
static inline struct user_beancounter *cgroup_ub(struct cgroup *cg)
{
	return container_of(cgroup_subsys_state(cg, ub_subsys_id),
			    struct user_beancounter, css);
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

static inline void ub_reclaim_rate_limit(struct user_beancounter *ub,
					 int wait, unsigned count) { }

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

extern long ub_oomguarpages_left(struct user_beancounter *ub);
extern void ub_update_resources_locked(struct user_beancounter *ub);
extern void ub_update_resources(struct user_beancounter *ub);

extern int ub_update_mem_cgroup_limits(struct user_beancounter *ub);

extern void ub_get_mem_cgroup_parms(struct user_beancounter *ub,
				    struct ubparm *physpages,
				    struct ubparm *swappages,
				    struct ubparm *kmemsize);
extern void ub_page_stat(struct user_beancounter *ub,
			 const nodemask_t *nodemask,
			 unsigned long *pages);

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
	return css_refcnt_inc_not_zero(&ub->css) ? ub : NULL;
}

static inline bool ub_dead(struct user_beancounter *ub)
{
	return !(ub->css.flags & CSS_ONLINE);
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

void ub_reclaim_rate_limit(struct user_beancounter *ub, int wait, unsigned count);

#define UB_IOPRIO_MIN 0
#define UB_IOPRIO_MAX 8
#ifdef CONFIG_BC_IO_PRIORITY
extern int ub_set_ioprio(int id, int ioprio);
#else
static inline int ub_set_ioprio(int veid, int ioprio) { return -EINVAL; }
#endif

extern void ub_init_ioprio(struct user_beancounter *ub);
extern void ub_fini_ioprio(struct user_beancounter *ub);

#endif /* CONFIG_BEANCOUNTERS */

#endif /* _LINUX_BEANCOUNTER_H */
