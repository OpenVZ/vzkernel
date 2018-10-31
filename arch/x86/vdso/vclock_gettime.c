/*
 * Copyright 2006 Andi Kleen, SUSE Labs.
 * Subject to the GNU Public License, v.2
 *
 * Fast user context implementation of clock_gettime, gettimeofday, and time.
 *
 * The code should have no internal unresolved relocations.
 * Check with readelf after changing.
 */

/* Disable profiling for userspace code: */
#define DISABLE_BRANCH_PROFILING

#include <linux/kernel.h>
#include <linux/posix-timers.h>
#include <linux/time.h>
#include <linux/string.h>
#include <asm/vsyscall.h>
#include <asm/fixmap.h>
#include <asm/vgtod.h>
#include <asm/timex.h>
#include <asm/hpet.h>
#include <asm/unistd.h>
#include <asm/io.h>
#include <asm/pvclock.h>
#include <asm/mshyperv.h>
#include <asm/msr.h>

#define gtod (&VVAR(vsyscall_gtod_data))

#ifdef CONFIG_HYPERV_TSCPAGE
static notrace u64 vread_hvclock(int *mode)
{
	const struct ms_hyperv_tsc_page *tsc_pg =
		(const struct ms_hyperv_tsc_page *)
		__fix_to_virt(HVCLOCK_TSC_PAGE);
	u64 current_tick = hv_read_tsc_page(tsc_pg);

	if (current_tick != U64_MAX)
		return current_tick;

	*mode = VCLOCK_NONE;
	return 0;
}
#endif

notrace static u64 vread_tsc(void)
{
	u64 ret = (u64)rdtsc_ordered();
	u64 last = VVAR(vsyscall_gtod_data).clock.cycle_last;

	if (likely(ret >= last))
		return ret;

	/*
	 * GCC likes to generate cmov here, but this branch is extremely
	 * predictable (it's just a funciton of time and the likely is
	 * very likely) and there's a data dependence, so force GCC
	 * to generate a branch instead.  I don't barrier() because
	 * we don't actually need a barrier, and if this function
	 * ever gets inlined it will generate worse code.
	 */
	asm volatile ("");
	return last;
}

static notrace u64 vread_hpet(void)
{
	return readl((const void __iomem *)fix_to_virt(VSYSCALL_HPET) + HPET_COUNTER);
}

#ifdef CONFIG_PARAVIRT_CLOCK

static notrace const struct pvclock_vsyscall_time_info *get_pvti(int cpu)
{
	const struct pvclock_vsyscall_time_info *pvti_base;
	int idx = cpu / (PAGE_SIZE/PVTI_SIZE);
	int offset = cpu % (PAGE_SIZE/PVTI_SIZE);

	BUG_ON(PVCLOCK_FIXMAP_BEGIN + idx > PVCLOCK_FIXMAP_END);

	pvti_base = (struct pvclock_vsyscall_time_info *)
		    __fix_to_virt(PVCLOCK_FIXMAP_BEGIN+idx);

	return &pvti_base[offset];
}

static notrace u64 vread_pvclock(int *mode)
{
	const struct pvclock_vcpu_time_info *pvti = &get_pvti(0)->pvti;
	u64 ret;
	u64 last;
	u32 version;

	/*
	 * Note: The kernel and hypervisor must guarantee that cpu ID
	 * number maps 1:1 to per-CPU pvclock time info.
	 *
	 * Because the hypervisor is entirely unaware of guest userspace
	 * preemption, it cannot guarantee that per-CPU pvclock time
	 * info is updated if the underlying CPU changes or that that
	 * version is increased whenever underlying CPU changes.
	 *
	 * On KVM, we are guaranteed that pvti updates for any vCPU are
	 * atomic as seen by *all* vCPUs.  This is an even stronger
	 * guarantee than we get with a normal seqlock.
	 *
	 * On Xen, we don't appear to have that guarantee, but Xen still
	 * supplies a valid seqlock using the version field.
	 *
	 * We only do pvclock vdso timing at all if
	 * PVCLOCK_TSC_STABLE_BIT is set, and we interpret that bit to
	 * mean that all vCPUs have matching pvti and that the TSC is
	 * synced, so we can just look at vCPU 0's pvti.
	 */

	do {
		version = pvclock_read_begin(pvti);

		if (unlikely(!(pvti->flags & PVCLOCK_TSC_STABLE_BIT))) {
			*mode = VCLOCK_NONE;
			return 0;
		}

		ret = __pvclock_read_cycles(pvti, rdtsc_ordered());
	} while (pvclock_read_retry(pvti, version));

	/* refer to tsc.c read_tsc() comment for rationale */
	last = VVAR(vsyscall_gtod_data).clock.cycle_last;

	if (likely(ret >= last))
		return ret;

	return last;
}
#endif

notrace static long vdso_fallback_gettime(long clock, struct timespec *ts)
{
	long ret;
	asm("syscall" : "=a" (ret) :
	    "0" (__NR_clock_gettime),"D" (clock), "S" (ts) : "memory");
	return ret;
}

notrace static long vdso_fallback_gtod(struct timeval *tv, struct timezone *tz)
{
	long ret;

	asm("syscall" : "=a" (ret) :
	    "0" (__NR_gettimeofday), "D" (tv), "S" (tz) : "memory");
	return ret;
}


notrace static inline u64 vgetsns(int *mode)
{
	long v;
	cycles_t cycles;
	if (gtod->clock.vclock_mode == VCLOCK_TSC)
		cycles = vread_tsc();
	else if (gtod->clock.vclock_mode == VCLOCK_HPET)
		cycles = vread_hpet();
#ifdef CONFIG_PARAVIRT_CLOCK
	else if (gtod->clock.vclock_mode == VCLOCK_PVCLOCK)
		cycles = vread_pvclock(mode);
#endif
#ifdef CONFIG_HYPERV_TSCPAGE
	else if (gtod->clock.vclock_mode == VCLOCK_HVCLOCK)
		cycles = vread_hvclock(mode);
#endif
	else
		return 0;
	v = (cycles - gtod->clock.cycle_last) & gtod->clock.mask;
	return v * gtod->clock.mult;
}

/* Code size doesn't matter (vdso is 4k anyway) and this is faster. */
notrace static int __always_inline do_realtime(struct timespec *ts)
{
	unsigned long seq;
	u64 ns;
	int mode;

	ts->tv_nsec = 0;
	do {
		seq = read_seqcount_begin(&gtod->seq);
		mode = gtod->clock.vclock_mode;
		ts->tv_sec = gtod->wall_time_sec;
		ns = gtod->wall_time_snsec;
		ns += vgetsns(&mode);
		ns >>= gtod->clock.shift;
	} while (unlikely(read_seqcount_retry(&gtod->seq, seq)));

	timespec_add_ns(ts, ns);
	return mode;
}

notrace static int do_monotonic(struct timespec *ts)
{
	unsigned long seq;
	u64 ns;
	int mode;

	ts->tv_nsec = 0;
	do {
		seq = read_seqcount_begin(&gtod->seq);
		mode = gtod->clock.vclock_mode;
		ts->tv_sec = gtod->monotonic_time_sec;
		ns = gtod->monotonic_time_snsec;
		ns += vgetsns(&mode);
		ns >>= gtod->clock.shift;
	} while (unlikely(read_seqcount_retry(&gtod->seq, seq)));
	timespec_add_ns(ts, ns);

	return mode;
}

notrace static int do_realtime_coarse(struct timespec *ts)
{
	unsigned long seq;
	do {
		seq = read_seqcount_begin(&gtod->seq);
		ts->tv_sec = gtod->wall_time_coarse.tv_sec;
		ts->tv_nsec = gtod->wall_time_coarse.tv_nsec;
	} while (unlikely(read_seqcount_retry(&gtod->seq, seq)));
	return 0;
}

notrace static int do_monotonic_coarse(struct timespec *ts)
{
	unsigned long seq;
	do {
		seq = read_seqcount_begin(&gtod->seq);
		ts->tv_sec = gtod->monotonic_time_coarse.tv_sec;
		ts->tv_nsec = gtod->monotonic_time_coarse.tv_nsec;
	} while (unlikely(read_seqcount_retry(&gtod->seq, seq)));

	return 0;
}

notrace int __vdso_clock_gettime(clockid_t clock, struct timespec *ts)
{
	int ret = VCLOCK_NONE;

	switch (clock) {
	case CLOCK_REALTIME:
		ret = do_realtime(ts);
		break;
	case CLOCK_MONOTONIC:
		ret = do_monotonic(ts);
		break;
	case CLOCK_REALTIME_COARSE:
		return do_realtime_coarse(ts);
	case CLOCK_MONOTONIC_COARSE:
		return do_monotonic_coarse(ts);
	}

	if (ret == VCLOCK_NONE)
		return vdso_fallback_gettime(clock, ts);
	return 0;
}
int clock_gettime(clockid_t, struct timespec *)
	__attribute__((weak, alias("__vdso_clock_gettime")));

notrace int __vdso_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	long ret = VCLOCK_NONE;

	if (likely(tv != NULL)) {
		BUILD_BUG_ON(offsetof(struct timeval, tv_usec) !=
			     offsetof(struct timespec, tv_nsec) ||
			     sizeof(*tv) != sizeof(struct timespec));
		ret = do_realtime((struct timespec *)tv);
		tv->tv_usec /= 1000;
	}
	if (unlikely(tz != NULL)) {
		/* Avoid memcpy. Some old compilers fail to inline it */
		tz->tz_minuteswest = gtod->sys_tz.tz_minuteswest;
		tz->tz_dsttime = gtod->sys_tz.tz_dsttime;
	}

	if (ret == VCLOCK_NONE)
		return vdso_fallback_gtod(tv, tz);
	return 0;
}
int gettimeofday(struct timeval *, struct timezone *)
	__attribute__((weak, alias("__vdso_gettimeofday")));

/*
 * This will break when the xtime seconds get inaccurate, but that is
 * unlikely
 */
notrace time_t __vdso_time(time_t *t)
{
	/* This is atomic on x86_64 so we don't need any locks. */
	time_t result = ACCESS_ONCE(VVAR(vsyscall_gtod_data).wall_time_sec);

	if (t)
		*t = result;
	return result;
}
int time(time_t *t)
	__attribute__((weak, alias("__vdso_time")));
