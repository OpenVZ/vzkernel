/*
 *  include/linux/vzstat.h
 *
 *  Copyright (c) 2005-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *
 */

#ifndef __VZSTAT_H__
#define __VZSTAT_H__

#include <linux/mmzone.h>
#include <linux/kstat.h>

struct swap_cache_info_struct {
	unsigned long add_total;
	unsigned long del_total;
	unsigned long find_success;
	unsigned long find_total;
};

struct kstat_zone_avg {
	unsigned long		free_pages_avg[3],
				nr_active_avg[3],
				nr_inactive_avg[3];
};

struct kernel_stat_glob {
	unsigned long nr_unint_avg[3];
	seqcount_t nr_unint_avg_seq;

	unsigned long alloc_fails[NR_CPUS][KSTAT_ALLOCSTAT_NR];
	struct kstat_lat_pcpu_struct alloc_lat[KSTAT_ALLOCSTAT_NR];
	struct kstat_lat_pcpu_struct sched_lat;
	struct kstat_lat_pcpu_struct page_in;
	struct kstat_lat_pcpu_struct swap_in;

	struct kstat_perf_pcpu_struct ttfp, cache_reap,
			refill_inact, shrink_icache, shrink_dcache;

	struct kstat_zone_avg zone_avg[MAX_NR_ZONES];
} ____cacheline_aligned;

DECLARE_PER_CPU(seqcount_t, kstat_pcpu_seq);

extern struct kernel_stat_glob kstat_glob ____cacheline_aligned;
extern spinlock_t kstat_glb_lock;

extern void kstat_init(void);

#ifdef CONFIG_VE

extern void KSTAT_PERF_ADD(struct kstat_perf_pcpu_struct *ptr, u64 real_time,
			   u64 cpu_time);

#define KSTAT_PERF_ENTER(name)				\
	u64 start, sleep_time;				\
							\
	start = ktime_to_ns(ktime_get());		\
	sleep_time = current->se.statistics->sum_sleep_runtime; \

#define KSTAT_PERF_LEAVE(name)				\
	start = ktime_to_ns(ktime_get()) - start;	\
	sleep_time = current->se.statistics->sum_sleep_runtime - sleep_time; \
	KSTAT_PERF_ADD(&kstat_glob.name, start, start - sleep_time);

extern void KSTAT_LAT_PCPU_ADD(struct kstat_lat_pcpu_struct *p, u64 dur);
extern void KSTAT_LAT_PCPU_UPDATE(struct kstat_lat_pcpu_struct *p);

#else
#define KSTAT_PERF_ADD(ptr, real_time, cpu_time)
#define KSTAT_PERF_ENTER(name)
#define KSTAT_PERF_LEAVE(name)
#define KSTAT_LAT_PCPU_ADD(p, dur)
#define KSTAT_LAT_PCPU_UPDATE(p)
#define KSTAT_LAT_PCPU_UPDATE(p)
#endif

#endif /* __VZSTAT_H__ */
