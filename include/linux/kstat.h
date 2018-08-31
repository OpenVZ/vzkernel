#ifndef __LINUX_KSTAT_H
#define __LINUX_KSTAT_H

enum {
	KSTAT_ALLOCSTAT_ATOMIC,
	KSTAT_ALLOCSTAT_LOW,
	KSTAT_ALLOCSTAT_HIGH,
	KSTAT_ALLOCSTAT_LOW_MP,
	KSTAT_ALLOCSTAT_HIGH_MP,
	KSTAT_ALLOCSTAT_IRQ,
	KSTAT_ALLOCSTAT_NR,
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

struct kstat_lat_snap_struct {
	u64 maxlat[2], totlat;
	unsigned long count;
	unsigned long time[2];
};

struct kstat_lat_pcpu_snap_struct {
	u64 maxlat, totlat;
	unsigned long count;
} ____cacheline_aligned_in_smp;

struct kstat_lat_pcpu_struct {
	struct kstat_lat_pcpu_snap_struct *cur;
	u64 max_snap;
	struct kstat_lat_snap_struct last;
	u64 avg[3];
};

#endif
