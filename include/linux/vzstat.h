/*
 *  include/linux/vzstat.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __VZSTAT_H__
#define __VZSTAT_H__

#include <linux/mmzone.h>

struct swap_cache_info_struct {
	unsigned long add_total;
	unsigned long del_total;
	unsigned long find_success;
	unsigned long find_total;
};

struct kstat_lat_snap_struct {
	u64 maxlat, totlat;
	unsigned long count;
};
struct kstat_lat_pcpu_snap_struct {
	u64 maxlat, totlat;
	unsigned long count;
	seqcount_t lock;
} ____cacheline_aligned_in_smp;

struct kstat_lat_struct {
	struct kstat_lat_snap_struct cur, last;
	u64 avg[3];
};
struct kstat_lat_pcpu_struct {
	struct kstat_lat_pcpu_snap_struct *cur;
	u64 max_snap;
	struct kstat_lat_snap_struct last;
	u64 avg[3];
};

struct kstat_perf_snap_struct {
	u64 wall_tottime, cpu_tottime;
	u64 wall_maxdur, cpu_maxdur;
	unsigned long count;
};

struct kstat_perf_pcpu_snap_struct {
	u64 wall_tottime, cpu_tottime;
	u64 wall_maxdur, cpu_maxdur;
	unsigned long count;
	seqcount_t lock;
};

struct kstat_perf_pcpu_struct {
	struct kstat_perf_pcpu_snap_struct *cur;
	struct kstat_perf_snap_struct last;
};

struct kstat_zone_avg {
	unsigned long		free_pages_avg[3],
				nr_active_avg[3],
				nr_inactive_avg[3];
};

enum {
	KSTAT_ALLOCSTAT_ATOMIC,
	KSTAT_ALLOCSTAT_LOW,
	KSTAT_ALLOCSTAT_HIGH,
	KSTAT_ALLOCSTAT_LOW_MP,
	KSTAT_ALLOCSTAT_HIGH_MP,
	KSTAT_ALLOCSTAT_NR,
};

struct kernel_stat_glob {
	unsigned long nr_unint_avg[3];

	unsigned long alloc_fails[NR_CPUS][KSTAT_ALLOCSTAT_NR];
	struct kstat_lat_pcpu_struct alloc_lat[KSTAT_ALLOCSTAT_NR];
	struct kstat_lat_pcpu_struct sched_lat;
	struct kstat_lat_pcpu_struct page_in;
	struct kstat_lat_struct swap_in;

	struct kstat_perf_pcpu_struct ttfp, cache_reap,
			refill_inact, shrink_icache, shrink_dcache;

	struct kstat_zone_avg zone_avg[MAX_NR_ZONES];
} ____cacheline_aligned;

extern struct kernel_stat_glob kstat_glob ____cacheline_aligned;
extern spinlock_t kstat_glb_lock;

extern void kstat_init(void);

static inline void
KSTAT_PERF_ADD(struct kstat_perf_pcpu_struct *ptr, u64 real_time, u64 cpu_time)
{
	struct kstat_perf_pcpu_snap_struct *cur = get_cpu_ptr(ptr->cur);

	write_seqcount_begin(&cur->lock);
	cur->count++;
	if (cur->wall_maxdur < real_time)
		cur->wall_maxdur = real_time;
	cur->wall_tottime += real_time;
	if (cur->cpu_maxdur < cpu_time)
		cur->cpu_maxdur = cpu_time;
	cur->cpu_tottime += real_time;
	write_seqcount_end(&cur->lock);
	put_cpu_ptr(cur);
}

#ifdef CONFIG_VE
#define KSTAT_PERF_ENTER(name)				\
	u64 start, sleep_time;				\
							\
	start = ktime_to_ns(ktime_get());		\
	sleep_time = current->se.statistics.sum_sleep_runtime; \

#define KSTAT_PERF_LEAVE(name)				\
	start = ktime_to_ns(ktime_get()) - start;	\
	sleep_time = current->se.statistics.sum_sleep_runtime - sleep_time; \
	KSTAT_PERF_ADD(&kstat_glob.name, start, start - sleep_time);

#else
#define KSTAT_PERF_ENTER(name)
#define KSTAT_PERF_LEAVE(name)
#endif

/*
 * Add another statistics reading.
 * Serialization is the caller's due.
 */
static inline void KSTAT_LAT_ADD(struct kstat_lat_struct *p,
		u64 dur)
{
	p->cur.count++;
	if (p->cur.maxlat < dur)
		p->cur.maxlat = dur;
	p->cur.totlat += dur;
}

/*
 * Must be called with disabled interrupts to remove any possible
 * locks and seqcounts under write-lock and avoid this 3-way deadlock:
 *
 * timer interrupt:
 *	write_seqlock(&xtime_lock);
 *	 spin_lock_irqsave(&kstat_glb_lock);
 *
 * update_schedule_latency():
 *	spin_lock_irq(&kstat_glb_lock);
 *	 read_seqcount_begin(&cur->lock)
 *
 * some-interrupt during KSTAT_LAT_PCPU_ADD()
 *   KSTAT_LAT_PCPU_ADD()
 *    write_seqcount_begin(&cur->lock);
 *     <interrupt>
 *      ktime_get()
 *       read_seqcount_begin(&xtime_lock);
 */
static inline void KSTAT_LAT_PCPU_ADD(struct kstat_lat_pcpu_struct *p, int cpu,
		u64 dur)
{
	struct kstat_lat_pcpu_snap_struct *cur;

	cur = per_cpu_ptr(p->cur, cpu);
	write_seqcount_begin(&cur->lock);
	cur->count++;
	if (cur->maxlat < dur)
		cur->maxlat = dur;
	cur->totlat += dur;
	write_seqcount_end(&cur->lock);
}

/*
 * Move current statistics to last, clear last.
 * Serialization is the caller's due.
 */
static inline void KSTAT_LAT_UPDATE(struct kstat_lat_struct *p)
{
	u64 m;
	memcpy(&p->last, &p->cur, sizeof(p->last));
	p->cur.maxlat = 0;
	m = p->last.maxlat;
	CALC_LOAD(p->avg[0], EXP_1, m)
	CALC_LOAD(p->avg[1], EXP_5, m)
	CALC_LOAD(p->avg[2], EXP_15, m)
}

static inline void KSTAT_LAT_PCPU_UPDATE(struct kstat_lat_pcpu_struct *p)
{
	unsigned i, cpu;
	struct kstat_lat_pcpu_snap_struct snap, *cur;
	u64 m;

	memset(&p->last, 0, sizeof(p->last));
	for_each_online_cpu(cpu) {
		cur = per_cpu_ptr(p->cur, cpu);
		do {
			i = read_seqcount_begin(&cur->lock);
			memcpy(&snap, cur, sizeof(snap));
		} while (read_seqcount_retry(&cur->lock, i));
		/* 
		 * read above and this update of maxlat is not atomic,
		 * but this is OK, since it happens rarely and losing
		 * a couple of peaks is not essential. xemul
		 */
		cur->maxlat = 0;

		p->last.count += snap.count;
		p->last.totlat += snap.totlat;
		if (p->last.maxlat < snap.maxlat)
			p->last.maxlat = snap.maxlat;
	}

	m = (p->last.maxlat > p->max_snap ? p->last.maxlat : p->max_snap);
	CALC_LOAD(p->avg[0], EXP_1, m);
	CALC_LOAD(p->avg[1], EXP_5, m);
	CALC_LOAD(p->avg[2], EXP_15, m);
	/* reset max_snap to calculate it correctly next time */
	p->max_snap = 0;
}

#endif /* __VZSTAT_H__ */
