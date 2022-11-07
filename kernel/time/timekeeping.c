/*
 *  linux/kernel/time/timekeeping.c
 *
 *  Kernel timekeeping code and accessor functions
 *
 *  This code was moved from linux/kernel/timer.c.
 *  Please see that file for copyright and history logs.
 *
 */

#include <linux/timekeeper_internal.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/syscore_ops.h>
#include <linux/clocksource.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/tick.h>
#include <linux/stop_machine.h>
#include <linux/pvclock_gtod.h>
#include <linux/compiler.h>

#include "tick-internal.h"
#include "ntp_internal.h"
#include "timekeeping_internal.h"

#define TK_CLEAR_NTP		(1 << 0)
#define TK_MIRROR		(1 << 1)
#define TK_CLOCK_WAS_SET	(1 << 2)

static struct timekeeper timekeeper;
static DEFINE_RAW_SPINLOCK(timekeeper_lock);
static seqcount_t timekeeper_seq;
static struct timekeeper shadow_timekeeper;

/**
 * struct tk_fast - NMI safe timekeeper
 * @seq:	Sequence counter for protecting updates. The lowest bit
 *		is the index for the tk_read_base array
 * @base:	tk_read_base array. Access is indexed by the lowest bit of
 *		@seq.
 *
 * See @update_fast_timekeeper() below.
 */
struct tk_fast {
	seqcount_t		seq;
	struct tk_read_base	base[2];
};

static struct tk_fast tk_fast_mono ____cacheline_aligned;
static struct tk_fast tk_fast_raw  ____cacheline_aligned;

/* flag for if timekeeping is suspended */
int __read_mostly timekeeping_suspended;

/* Flag for if there is a persistent clock on this platform */
bool __read_mostly persistent_clock_exist = false;

static inline void tk_normalize_xtime(struct timekeeper *tk)
{
	while (tk->tkr_mono.xtime_nsec >= ((u64)NSEC_PER_SEC << tk->tkr_mono.shift)) {
		tk->tkr_mono.xtime_nsec -= (u64)NSEC_PER_SEC << tk->tkr_mono.shift;
		tk->xtime_sec++;
	}
}

static void tk_set_xtime(struct timekeeper *tk, const struct timespec64 *ts)
{
	tk->xtime_sec = ts->tv_sec;
	tk->tkr_mono.xtime_nsec = (u64)ts->tv_nsec << tk->tkr_mono.shift;
}

static void tk_xtime_add(struct timekeeper *tk, const struct timespec64 *ts)
{
	tk->xtime_sec += ts->tv_sec;
	tk->tkr_mono.xtime_nsec += (u64)ts->tv_nsec << tk->tkr_mono.shift;
	tk_normalize_xtime(tk);
}

static void tk_set_wall_to_mono(struct timekeeper *tk, struct timespec64 wtm)
{
	struct timespec64 tmp;

	/*
	 * Verify consistency of: offset_real = -wall_to_monotonic
	 * before modifying anything
	 */
	set_normalized_timespec64(&tmp, -tk->wall_to_monotonic.tv_sec,
					-tk->wall_to_monotonic.tv_nsec);
	WARN_ON_ONCE(tk->offs_real.tv64 != timespec64_to_ktime(tmp).tv64);
	tk->wall_to_monotonic = wtm;
	set_normalized_timespec64(&tmp, -wtm.tv_sec, -wtm.tv_nsec);
	tk->offs_real = timespec64_to_ktime(tmp);
	tk->offs_tai = ktime_add(tk->offs_real, ktime_set(tk->tai_offset, 0));
}

static void tk_set_sleep_time(struct timekeeper *tk, struct timespec64 t)
{
	/* Verify consistency before modifying */
	WARN_ON_ONCE(tk->offs_boot.tv64 != timespec64_to_ktime(tk->total_sleep_time).tv64);

	tk->total_sleep_time	= t;
	tk->offs_boot		= timespec64_to_ktime(t);
}

/**
 * timekeeper_setup_internals - Set up internals to use clocksource clock.
 *
 * @clock:		Pointer to clocksource.
 *
 * Calculates a fixed cycle/nsec interval for a given clocksource/adjustment
 * pair and interval request.
 *
 * Unless you're the timekeeping code, you should not be using this!
 */
static void tk_setup_internals(struct timekeeper *tk, struct clocksource *clock)
{
	u64 interval;
	u64 tmp, ntpinterval;
	struct clocksource *old_clock;

	++tk->cs_was_changed_seq;
	old_clock = tk->tkr_mono.clock;
	tk->tkr_mono.clock = clock;
	tk->tkr_mono.cycle_last = clock->cycle_last = clock->read(clock);

	tk->tkr_raw.clock = clock;
	tk->tkr_raw.clock->read(clock);
	tk->tkr_raw.clock->mask = clock->mask;
	tk->tkr_raw.cycle_last = tk->tkr_mono.cycle_last;

	/* Do the ns -> cycle conversion first, using original mult */
	tmp = NTP_INTERVAL_LENGTH;
	tmp <<= clock->shift;
	ntpinterval = tmp;
	tmp += clock->mult/2;
	do_div(tmp, clock->mult);
	if (tmp == 0)
		tmp = 1;

	interval = (u64) tmp;
	tk->cycle_interval = interval;

	/* Go back from cycles -> shifted ns */
	tk->xtime_interval = (u64) interval * clock->mult;
	tk->xtime_remainder = ntpinterval - tk->xtime_interval;
	tk->raw_interval =
		((u64) interval * clock->mult) >> clock->shift;

	 /* if changing clocks, convert xtime_nsec shift units */
	if (old_clock) {
		int shift_change = clock->shift - old_clock->shift;
		if (shift_change < 0)
			tk->tkr_mono.xtime_nsec >>= -shift_change;
		else
			tk->tkr_mono.xtime_nsec <<= shift_change;
	}
	tk->tkr_raw.xtime_nsec = 0;

	tk->tkr_mono.shift = clock->shift;
	tk->tkr_raw.shift = clock->shift;

	tk->ntp_error = 0;
	tk->ntp_error_shift = NTP_SCALE_SHIFT - clock->shift;
	tk->ntp_tick = ntpinterval << tk->ntp_error_shift;

	/*
	 * The timekeeper keeps its own mult values for the currently
	 * active clocksource. These value will be adjusted via NTP
	 * to counteract clock drifting.
	 */
	tk->tkr_mono.mult = clock->mult;
	tk->tkr_raw.mult = clock->mult;
	tk->ntp_err_mult = 0;
}

/* Timekeeper helper functions. */

#ifdef CONFIG_ARCH_USES_GETTIMEOFFSET
static u32 default_arch_gettimeoffset(void) { return 0; }
u32 (*arch_gettimeoffset)(void) = default_arch_gettimeoffset;
#else
static inline u32 arch_gettimeoffset(void) { return 0; }
#endif

static inline u64 timekeeping_get_delta(struct tk_read_base *tkr)
{
	u64 cycle_now, delta;
	struct clocksource *clock;

	/* read clocksource: */
	clock = tkr->clock;
	cycle_now = tkr->clock->read(clock);

	/* calculate the delta since the last update_wall_time */
	delta = clocksource_delta(cycle_now, clock->cycle_last, clock->mask);

	return delta;
}

static inline s64 timekeeping_delta_to_ns(struct tk_read_base *tkr,
					  u64 delta)
{
	u64 nsec;

	nsec = delta * tkr->mult + tkr->xtime_nsec;
	nsec >>= tkr->shift;

	/* If arch requires, add in get_arch_timeoffset() */
	return (s64)nsec + arch_gettimeoffset();
}

static inline s64 timekeeping_get_ns(struct tk_read_base *tkr)
{
	u64 delta;

	delta = timekeeping_get_delta(tkr);
	return timekeeping_delta_to_ns(tkr, delta);
}

/**
 * update_fast_timekeeper - Update the fast and NMI safe monotonic timekeeper.
 * @tkr: Timekeeping readout base from which we take the update
 *
 * We want to use this from any context including NMI and tracing /
 * instrumenting the timekeeping code itself.
 *
 * Employ the latch technique; see @raw_write_seqcount_latch.
 *
 * So if a NMI hits the update of base[0] then it will use base[1]
 * which is still consistent. In the worst case this can result is a
 * slightly wrong timestamp (a few nanoseconds). See
 * @ktime_get_mono_fast_ns.
 */
static void update_fast_timekeeper(struct tk_read_base *tkr, struct tk_fast *tkf)
{
	struct tk_read_base *base = tkf->base;

	/* Force readers off to base[1] */
	raw_write_seqcount_latch(&tkf->seq);

	/* Update base[0] */
	memcpy(base, tkr, sizeof(*base));

	/* Force readers back to base[0] */
	raw_write_seqcount_latch(&tkf->seq);

	/* Update base[1] */
	memcpy(base + 1, base, sizeof(*base));
}

/**
 * ktime_get_mono_fast_ns - Fast NMI safe access to clock monotonic
 *
 * This timestamp is not guaranteed to be monotonic across an update.
 * The timestamp is calculated by:
 *
 *	now = base_mono + clock_delta * slope
 *
 * So if the update lowers the slope, readers who are forced to the
 * not yet updated second array are still using the old steeper slope.
 *
 * tmono
 * ^
 * |    o  n
 * |   o n
 * |  u
 * | o
 * |o
 * |12345678---> reader order
 *
 * o = old slope
 * u = update
 * n = new slope
 *
 * So reader 6 will observe time going backwards versus reader 5.
 *
 * While other CPUs are likely to be able observe that, the only way
 * for a CPU local observation is when an NMI hits in the middle of
 * the update. Timestamps taken from that NMI context might be ahead
 * of the following timestamps. Callers need to be aware of that and
 * deal with it.
 */
static __always_inline u64 __ktime_get_fast_ns(struct tk_fast *tkf)
{
	struct tk_read_base *tkr;
	unsigned int seq;
	u64 now;

	do {
		seq = raw_read_seqcount(&tkf->seq);
		tkr = tkf->base + (seq & 0x01);
		now = ktime_to_ns(tkr->base) + timekeeping_get_ns(tkr);
	} while (read_seqcount_retry(&tkf->seq, seq));

	return now;
}

u64 ktime_get_mono_fast_ns(void)
{
	return __ktime_get_fast_ns(&tk_fast_mono);
}
EXPORT_SYMBOL_GPL(ktime_get_mono_fast_ns);

u64 ktime_get_raw_fast_ns(void)
{
	return __ktime_get_fast_ns(&tk_fast_raw);
}
EXPORT_SYMBOL_GPL(ktime_get_raw_fast_ns);

static inline s64 timekeeping_cycles_to_ns(struct tk_read_base *tkr,
					    u64 cycles)
{
	u64 delta;

	/* calculate the delta since the last update_wall_time */
	delta = clocksource_delta(cycles, tkr->clock->cycle_last,
				  tkr->clock->mask);
	return timekeeping_delta_to_ns(tkr, delta);
}

static RAW_NOTIFIER_HEAD(pvclock_gtod_chain);

static void update_pvclock_gtod(struct timekeeper *tk, bool was_set)
{
	raw_notifier_call_chain(&pvclock_gtod_chain, was_set, tk);
}

/**
 * pvclock_gtod_register_notifier - register a pvclock timedata update listener
 */
int pvclock_gtod_register_notifier(struct notifier_block *nb)
{
	struct timekeeper *tk = &timekeeper;
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&timekeeper_lock, flags);
	ret = raw_notifier_chain_register(&pvclock_gtod_chain, nb);
	update_pvclock_gtod(tk, true);
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(pvclock_gtod_register_notifier);

/**
 * pvclock_gtod_unregister_notifier - unregister a pvclock
 * timedata update listener
 */
int pvclock_gtod_unregister_notifier(struct notifier_block *nb)
{
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&timekeeper_lock, flags);
	ret = raw_notifier_chain_unregister(&pvclock_gtod_chain, nb);
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(pvclock_gtod_unregister_notifier);

/*
 * tk_update_leap_state - helper to update the next_leap_ktime
 */
static inline void tk_update_leap_state(struct timekeeper *tk)
{
	tk->next_leap_ktime = ntp_get_next_leap();
	if (tk->next_leap_ktime.tv64 != KTIME_MAX)
		/* Convert to monotonic time */
		tk->next_leap_ktime = ktime_sub(tk->next_leap_ktime, tk->offs_real);
}

/*
 * Update the ktime_t based scalar nsec members of the timekeeper
 */
static inline void tk_update_ktime_data(struct timekeeper *tk)
{
	s64 nsec;

	/*
	 * The xtime based monotonic readout is:
	 *	nsec = (xtime_sec + wtm_sec) * 1e9 + wtm_nsec + now();
	 * The ktime based monotonic readout is:
	 *	nsec = base_mono + now();
	 * ==> base_mono = (xtime_sec + wtm_sec) * 1e9 + wtm_nsec
	 */
	nsec = (s64)(tk->xtime_sec + tk->wall_to_monotonic.tv_sec);
	nsec *= NSEC_PER_SEC;
	nsec += tk->wall_to_monotonic.tv_nsec;
	tk->tkr_mono.base = ns_to_ktime(nsec);

	/* Update the monotonic raw base */
	tk->tkr_raw.base = timespec64_to_ktime(tk->raw_time);
}

/* must hold timekeeper_lock */
static void timekeeping_update(struct timekeeper *tk, unsigned int action)
{
	if (action & TK_CLEAR_NTP) {
		tk->ntp_error = 0;
		ntp_clear();
	}

	tk_update_leap_state(tk);
	tk_update_ktime_data(tk);

	update_vsyscall(tk);
	update_pvclock_gtod(tk, action & TK_CLOCK_WAS_SET);

	if (action & TK_CLOCK_WAS_SET)
		tk->clock_was_set_seq++;

	if (action & TK_MIRROR)
		memcpy(&shadow_timekeeper, &timekeeper, sizeof(timekeeper));

	update_fast_timekeeper(&tk->tkr_mono, &tk_fast_mono);
	update_fast_timekeeper(&tk->tkr_raw,  &tk_fast_raw);
}

/**
 * timekeeping_forward_now - update clock to the current time
 *
 * Forward the current clock to update its state since the last call to
 * update_wall_time(). This is useful before significant clock changes,
 * as it avoids having to deal with this time offset explicitly.
 */
static void timekeeping_forward_now(struct timekeeper *tk)
{
	u64 cycle_now, delta;
	struct clocksource *clock;
	s64 nsec;

	clock = tk->tkr_mono.clock;
	cycle_now = clock->read(clock);
	delta = clocksource_delta(cycle_now, clock->cycle_last, clock->mask);
	tk->tkr_mono.cycle_last = clock->cycle_last = cycle_now;
	tk->tkr_raw.cycle_last  = cycle_now;

	tk->tkr_mono.xtime_nsec += delta * tk->tkr_mono.mult;

	/* If arch requires, add in arch_gettimeoffset() */
	tk->tkr_mono.xtime_nsec += (u64)arch_gettimeoffset() << tk->tkr_mono.shift;

	tk_normalize_xtime(tk);

	nsec = clocksource_cyc2ns(delta, tk->tkr_raw.mult, tk->tkr_raw.shift);
	timespec64_add_ns(&tk->raw_time, nsec);
}

/**
 * __getnstimeofday64 - Returns the time of day in a timespec64.
 * @ts:		pointer to the timespec to be set
 *
 * Updates the time of day in the timespec.
 * Returns 0 on success, or -ve when suspended (timespec will be undefined).
 */
int __getnstimeofday64(struct timespec64 *ts)
{
	struct timekeeper *tk = &timekeeper;
	unsigned long seq;
	s64 nsecs = 0;

	do {
		seq = read_seqcount_begin(&timekeeper_seq);

		ts->tv_sec = tk->xtime_sec;
		nsecs = timekeeping_get_ns(&tk->tkr_mono);

	} while (read_seqcount_retry(&timekeeper_seq, seq));

	ts->tv_nsec = 0;
	timespec64_add_ns(ts, nsecs);

	/*
	 * Do not bail out early, in case there were callers still using
	 * the value, even in the face of the WARN_ON.
	 */
	if (unlikely(timekeeping_suspended))
		return -EAGAIN;
	return 0;
}
EXPORT_SYMBOL(__getnstimeofday64);

/**
 * getnstimeofday64 - Returns the time of day in a timespec64.
 * @ts:		pointer to the timespec to be set
 *
 * Returns the time of day in a timespec (WARN if suspended).
 */
void getnstimeofday64(struct timespec64 *ts)
{
	WARN_ON(__getnstimeofday64(ts));
}
EXPORT_SYMBOL(getnstimeofday64);

ktime_t ktime_get(void)
{
	struct timekeeper *tk = &timekeeper;
	unsigned int seq;
	s64 secs, nsecs;

	WARN_ON(timekeeping_suspended);

	do {
		seq = read_seqcount_begin(&timekeeper_seq);
		secs = tk->xtime_sec + tk->wall_to_monotonic.tv_sec;
		nsecs = timekeeping_get_ns(&tk->tkr_mono) +
			tk->wall_to_monotonic.tv_nsec;

	} while (read_seqcount_retry(&timekeeper_seq, seq));
	/*
	 * Use ktime_set/ktime_add_ns to create a proper ktime on
	 * 32-bit architectures without CONFIG_KTIME_SCALAR.
	 */
	return ktime_add_ns(ktime_set(secs, 0), nsecs);
}
EXPORT_SYMBOL_GPL(ktime_get);

/**
 * ktime_get_raw - Returns the raw monotonic time in ktime_t format
 */
ktime_t ktime_get_raw(void)
{
	struct timekeeper *tk = &timekeeper;
	unsigned int seq;
	ktime_t base;
	s64 nsecs;

	do {
		seq = read_seqcount_begin(&timekeeper_seq);
		base = tk->tkr_raw.base;
		nsecs = timekeeping_get_ns(&tk->tkr_raw);

	} while (read_seqcount_retry(&timekeeper_seq, seq));

	return ktime_add_ns(base, nsecs);
}
EXPORT_SYMBOL_GPL(ktime_get_raw);

/**
 * ktime_get_ts64 - get the monotonic clock in timespec64 format
 * @ts:		pointer to timespec variable
 *
 * The function calculates the monotonic clock from the realtime
 * clock and the wall_to_monotonic offset and stores the result
 * in normalized timespec format in the variable pointed to by @ts.
 */
void ktime_get_ts64(struct timespec64 *ts)
{
	struct timekeeper *tk = &timekeeper;
	struct timespec64 tomono;
	s64 nsec;
	unsigned int seq;

	WARN_ON(timekeeping_suspended);

	do {
		seq = read_seqcount_begin(&timekeeper_seq);
		ts->tv_sec = tk->xtime_sec;
		nsec = timekeeping_get_ns(&tk->tkr_mono);
		tomono = tk->wall_to_monotonic;

	} while (read_seqcount_retry(&timekeeper_seq, seq));

	ts->tv_sec += tomono.tv_sec;
	ts->tv_nsec = 0;
	timespec64_add_ns(ts, nsec + tomono.tv_nsec);
}
EXPORT_SYMBOL_GPL(ktime_get_ts64);


/**
 * timekeeping_clocktai - Returns the TAI time of day in a timespec
 * @ts:		pointer to the timespec to be set
 *
 * Returns the time of day in a timespec.
 */
void timekeeping_clocktai(struct timespec *ts)
{
	struct timekeeper *tk = &timekeeper;
	struct timespec64 ts64;
	unsigned long seq;
	u64 nsecs;

	WARN_ON(timekeeping_suspended);

	do {
		seq = read_seqcount_begin(&timekeeper_seq);

		ts64.tv_sec = tk->xtime_sec + tk->tai_offset;
		nsecs = timekeeping_get_ns(&tk->tkr_mono);

	} while (read_seqcount_retry(&timekeeper_seq, seq));

	ts64.tv_nsec = 0;
	timespec64_add_ns(&ts64, nsecs);
	*ts = timespec64_to_timespec(ts64);

}
EXPORT_SYMBOL(timekeeping_clocktai);


/**
 * ktime_get_clocktai - Returns the TAI time of day in a ktime
 *
 * Returns the time of day in a ktime.
 */
ktime_t ktime_get_clocktai(void)
{
	struct timespec ts;

	timekeeping_clocktai(&ts);
	return timespec_to_ktime(ts);
}
EXPORT_SYMBOL(ktime_get_clocktai);

/* Scale base by mult/div checking for overflow */
static int scale64_check_overflow(u64 mult, u64 div, u64 *base)
{
	u64 tmp, rem;

	tmp = div64_u64_rem(*base, div, &rem);

	if (((int)sizeof(u64)*8 - fls64(mult) < fls64(tmp)) ||
	    ((int)sizeof(u64)*8 - fls64(mult) < fls64(rem)))
		return -EOVERFLOW;
	tmp *= mult;
	rem *= mult;

	do_div(rem, div);
	*base = tmp + rem;
	return 0;
}

/**
 * adjust_historical_crosststamp - adjust crosstimestamp previous to current interval
 * @history:			Snapshot representing start of history
 * @partial_history_cycles:	Cycle offset into history (fractional part)
 * @total_history_cycles:	Total history length in cycles
 * @discontinuity:		True indicates clock was set on history period
 * @ts:				Cross timestamp that should be adjusted using
 *	partial/total ratio
 *
 * Helper function used by get_device_system_crosststamp() to correct the
 * crosstimestamp corresponding to the start of the current interval to the
 * system counter value (timestamp point) provided by the driver. The
 * total_history_* quantities are the total history starting at the provided
 * reference point and ending at the start of the current interval. The cycle
 * count between the driver timestamp point and the start of the current
 * interval is partial_history_cycles.
 */
static int adjust_historical_crosststamp(struct system_time_snapshot *history,
					 u64 partial_history_cycles,
					 u64 total_history_cycles,
					 bool discontinuity,
					 struct system_device_crosststamp *ts)
{
	struct timekeeper *tk = &timekeeper;
	u64 corr_raw, corr_real;
	bool interp_forward;
	int ret;

	if (total_history_cycles == 0 || partial_history_cycles == 0)
		return 0;

	/* Interpolate shortest distance from beginning or end of history */
	interp_forward = partial_history_cycles > total_history_cycles/2 ?
		true : false;
	partial_history_cycles = interp_forward ?
		total_history_cycles - partial_history_cycles :
		partial_history_cycles;

	/*
	 * Scale the monotonic raw time delta by:
	 *	partial_history_cycles / total_history_cycles
	 */
	corr_raw = (u64)ktime_to_ns(
		ktime_sub(ts->sys_monoraw, history->raw));
	ret = scale64_check_overflow(partial_history_cycles,
				     total_history_cycles, &corr_raw);
	if (ret)
		return ret;

	/*
	 * If there is a discontinuity in the history, scale monotonic raw
	 *	correction by:
	 *	mult(real)/mult(raw) yielding the realtime correction
	 * Otherwise, calculate the realtime correction similar to monotonic
	 *	raw calculation
	 */
	if (discontinuity) {
		corr_real = mul_u64_u32_div
			(corr_raw, tk->tkr_mono.mult, tk->tkr_raw.mult);
	} else {
		corr_real = (u64)ktime_to_ns(
			ktime_sub(ts->sys_realtime, history->real));
		ret = scale64_check_overflow(partial_history_cycles,
					     total_history_cycles, &corr_real);
		if (ret)
			return ret;
	}

	/* Fixup monotonic raw and real time time values */
	if (interp_forward) {
		ts->sys_monoraw = ktime_add_ns(history->raw, corr_raw);
		ts->sys_realtime = ktime_add_ns(history->real, corr_real);
	} else {
		ts->sys_monoraw = ktime_sub_ns(ts->sys_monoraw, corr_raw);
		ts->sys_realtime = ktime_sub_ns(ts->sys_realtime, corr_real);
	}

	return 0;
}

/*
 * cycle_between - true if test occurs chronologically between before and after
 */
static bool cycle_between(u64 before, u64 test, u64 after)
{
	if (test > before && test < after)
		return true;
	if (test < before && before > after)
		return true;
	return false;
}

/**
 * get_device_system_crosststamp - Synchronously capture system/device timestamp
 * @get_time_fn:	Callback to get simultaneous device time and
 *	system counter from the device driver
 * @ctx:		Context passed to get_time_fn()
 * @history_begin:	Historical reference point used to interpolate system
 *	time when counter provided by the driver is before the current interval
 * @xtstamp:		Receives simultaneously captured system and device time
 *
 * Reads a timestamp from a device and correlates it to system time
 */
int get_device_system_crosststamp(int (*get_time_fn)
				  (ktime_t *device_time,
				   struct system_counterval_t *sys_counterval,
				   void *ctx),
				  void *ctx,
				  struct system_time_snapshot *history_begin,
				  struct system_device_crosststamp *xtstamp)
{
	struct system_counterval_t system_counterval;
	struct timekeeper *tk = &timekeeper;
	u64 cycles, now, interval_start;
	unsigned int clock_was_set_seq = 0;
	ktime_t base_real, base_raw;
	s64 nsec_real, nsec_raw;
	u8 cs_was_changed_seq;
	unsigned long seq;
	bool do_interp;
	int ret;

	do {
		seq = read_seqcount_begin(&timekeeper_seq);
		/*
		 * Try to synchronously capture device time and a system
		 * counter value calling back into the device driver
		 */
		ret = get_time_fn(&xtstamp->device, &system_counterval, ctx);
		if (ret)
			return ret;

		/*
		 * Verify that the clocksource associated with the captured
		 * system counter value is the same as the currently installed
		 * timekeeper clocksource
		 */
		if (tk->tkr_mono.clock != system_counterval.cs)
			return -ENODEV;
		cycles = system_counterval.cycles;

		/*
		 * Check whether the system counter value provided by the
		 * device driver is on the current timekeeping interval.
		 */
		now = tk->tkr_mono.clock->read(tk->tkr_mono.clock);
		interval_start = tk->tkr_mono.cycle_last;
		if (!cycle_between(interval_start, cycles, now)) {
			clock_was_set_seq = tk->clock_was_set_seq;
			cs_was_changed_seq = tk->cs_was_changed_seq;
			cycles = interval_start;
			do_interp = true;
		} else {
			do_interp = false;
		}

		base_real = ktime_add(tk->tkr_mono.base,
				      tk->offs_real);
		base_raw = tk->tkr_raw.base;

		nsec_real = timekeeping_cycles_to_ns(&tk->tkr_mono,
						     system_counterval.cycles);
		nsec_raw = timekeeping_cycles_to_ns(&tk->tkr_raw,
						    system_counterval.cycles);
	} while (read_seqcount_retry(&timekeeper_seq, seq));

	xtstamp->sys_realtime = ktime_add_ns(base_real, nsec_real);
	xtstamp->sys_monoraw = ktime_add_ns(base_raw, nsec_raw);

	/*
	 * Interpolate if necessary, adjusting back from the start of the
	 * current interval
	 */
	if (do_interp) {
		u64 partial_history_cycles, total_history_cycles;
		bool discontinuity;

		/*
		 * Check that the counter value occurs after the provided
		 * history reference and that the history doesn't cross a
		 * clocksource change
		 */
		if (!history_begin ||
		    !cycle_between(history_begin->cycles,
				   system_counterval.cycles, cycles) ||
		    history_begin->cs_was_changed_seq != cs_was_changed_seq)
			return -EINVAL;
		partial_history_cycles = cycles - system_counterval.cycles;
		total_history_cycles = cycles - history_begin->cycles;
		discontinuity =
			history_begin->clock_was_set_seq != clock_was_set_seq;

		ret = adjust_historical_crosststamp(history_begin,
						    partial_history_cycles,
						    total_history_cycles,
						    discontinuity, xtstamp);
		if (ret)
			return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(get_device_system_crosststamp);

/**
 * do_gettimeofday - Returns the time of day in a timeval
 * @tv:		pointer to the timeval to be set
 *
 * NOTE: Users should be converted to using getnstimeofday()
 */
void do_gettimeofday(struct timeval *tv)
{
	struct timespec64 now;

	getnstimeofday64(&now);
	tv->tv_sec = now.tv_sec;
	tv->tv_usec = now.tv_nsec/1000;
}
EXPORT_SYMBOL(do_gettimeofday);

/**
 * do_settimeofday - Sets the time of day
 * @tv:		pointer to the timespec variable containing the new time
 *
 * Sets the time of day to the new time and update NTP and notify hrtimers
 */
int do_settimeofday(const struct timespec *tv)
{
	struct timekeeper *tk = &timekeeper;
	struct timespec64 ts_delta, xt, tmp;
	unsigned long flags;

	if (!timespec_valid_strict(tv))
		return -EINVAL;

	raw_spin_lock_irqsave(&timekeeper_lock, flags);
	write_seqcount_begin(&timekeeper_seq);

	timekeeping_forward_now(tk);

	xt = tk_xtime(tk);
	ts_delta.tv_sec = tv->tv_sec - xt.tv_sec;
	ts_delta.tv_nsec = tv->tv_nsec - xt.tv_nsec;

	tk_set_wall_to_mono(tk, timespec64_sub(tk->wall_to_monotonic, ts_delta));

	tmp = timespec_to_timespec64(*tv);
	tk_set_xtime(tk, &tmp);

	timekeeping_update(tk, TK_CLEAR_NTP | TK_MIRROR | TK_CLOCK_WAS_SET);

	write_seqcount_end(&timekeeper_seq);
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);

	/* signal hrtimers about time change */
	clock_was_set();

	return 0;
}
EXPORT_SYMBOL(do_settimeofday);

/**
 * timekeeping_inject_offset - Adds or subtracts from the current time.
 * @tv:		pointer to the timespec variable containing the offset
 *
 * Adds or subtracts an offset value from the current time.
 */
int timekeeping_inject_offset(struct timespec *ts)
{
	struct timekeeper *tk = &timekeeper;
	unsigned long flags;
	struct timespec64 ts64, tmp;
	int ret = 0;

	if ((unsigned long)ts->tv_nsec >= NSEC_PER_SEC)
		return -EINVAL;

	ts64 = timespec_to_timespec64(*ts);

	raw_spin_lock_irqsave(&timekeeper_lock, flags);
	write_seqcount_begin(&timekeeper_seq);

	timekeeping_forward_now(tk);

	/* Make sure the proposed value is valid */
	tmp = timespec64_add(tk_xtime(tk),  ts64);
	if (!timespec64_valid_strict(&tmp)) {
		ret = -EINVAL;
		goto error;
	}

	tk_xtime_add(tk, &ts64);
	tk_set_wall_to_mono(tk, timespec64_sub(tk->wall_to_monotonic, ts64));

error: /* even if we error out, we forwarded the time, so call update */
	timekeeping_update(tk, TK_CLEAR_NTP | TK_MIRROR | TK_CLOCK_WAS_SET);

	write_seqcount_end(&timekeeper_seq);
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);

	/* signal hrtimers about time change */
	clock_was_set();

	return ret;
}
EXPORT_SYMBOL(timekeeping_inject_offset);

/**
 * ktime_get_snapshot - snapshots the realtime/monotonic raw clocks with counter
 * @systime_snapshot:	pointer to struct receiving the system time snapshot
 */
void ktime_get_snapshot(struct system_time_snapshot *systime_snapshot)
{
	struct timekeeper *tk = &timekeeper;
	unsigned long seq;
	ktime_t base_raw;
	ktime_t base_real;
	s64 nsec_raw;
	s64 nsec_real;
	u64 now;

	WARN_ON_ONCE(timekeeping_suspended);

	do {
		seq = read_seqcount_begin(&timekeeper_seq);

		now = tk->tkr_mono.clock->read(tk->tkr_mono.clock);
		systime_snapshot->cs_was_changed_seq = tk->cs_was_changed_seq;
		systime_snapshot->clock_was_set_seq = tk->clock_was_set_seq;
		base_real = ktime_add(tk->tkr_mono.base,
				      tk->offs_real);
		base_raw = tk->tkr_raw.base;
		nsec_real = timekeeping_cycles_to_ns(&tk->tkr_mono, now);
		nsec_raw  = timekeeping_cycles_to_ns(&tk->tkr_raw, now);
	} while (read_seqcount_retry(&timekeeper_seq, seq));

	systime_snapshot->cycles = now;
	systime_snapshot->real = ktime_add_ns(base_real, nsec_real);
	systime_snapshot->raw = ktime_add_ns(base_raw, nsec_raw);
}
EXPORT_SYMBOL_GPL(ktime_get_snapshot);

/**
 * timekeeping_get_tai_offset - Returns current TAI offset from UTC
 *
 */
s32 timekeeping_get_tai_offset(void)
{
	struct timekeeper *tk = &timekeeper;
	unsigned int seq;
	s32 ret;

	do {
		seq = read_seqcount_begin(&timekeeper_seq);
		ret = tk->tai_offset;
	} while (read_seqcount_retry(&timekeeper_seq, seq));

	return ret;
}

/**
 * __timekeeping_set_tai_offset - Lock free worker function
 *
 */
static void __timekeeping_set_tai_offset(struct timekeeper *tk, s32 tai_offset)
{
	tk->tai_offset = tai_offset;
	tk->offs_tai = ktime_add(tk->offs_real, ktime_set(tai_offset, 0));
}

/**
 * timekeeping_set_tai_offset - Sets the current TAI offset from UTC
 *
 */
void timekeeping_set_tai_offset(s32 tai_offset)
{
	struct timekeeper *tk = &timekeeper;
	unsigned long flags;

	raw_spin_lock_irqsave(&timekeeper_lock, flags);
	write_seqcount_begin(&timekeeper_seq);
	__timekeeping_set_tai_offset(tk, tai_offset);
	timekeeping_update(tk, TK_MIRROR | TK_CLOCK_WAS_SET);
	write_seqcount_end(&timekeeper_seq);
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);
	clock_was_set();
}

/**
 * change_clocksource - Swaps clocksources if a new one is available
 *
 * Accumulates current time interval and initializes new clocksource
 */
static int change_clocksource(void *data)
{
	struct timekeeper *tk = &timekeeper;
	struct clocksource *new, *old;
	unsigned long flags;

	new = (struct clocksource *) data;

	raw_spin_lock_irqsave(&timekeeper_lock, flags);
	write_seqcount_begin(&timekeeper_seq);

	timekeeping_forward_now(tk);
	/*
	 * If the cs is in module, get a module reference. Succeeds
	 * for built-in code (owner == NULL) as well.
	 */
	if (try_module_get(new->owner)) {
		if (!new->enable || new->enable(new) == 0) {
			old = tk->tkr_mono.clock;
			tk_setup_internals(tk, new);
			if (old->disable)
				old->disable(old);
			module_put(old->owner);
		} else {
			module_put(new->owner);
		}
	}
	timekeeping_update(tk, TK_CLEAR_NTP | TK_MIRROR | TK_CLOCK_WAS_SET);

	write_seqcount_end(&timekeeper_seq);
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);

	return 0;
}

/**
 * timekeeping_notify - Install a new clock source
 * @clock:		pointer to the clock source
 *
 * This function is called from clocksource.c after a new, better clock
 * source has been registered. The caller holds the clocksource_mutex.
 */
int timekeeping_notify(struct clocksource *clock)
{
	struct timekeeper *tk = &timekeeper;

	if (tk->tkr_mono.clock == clock)
		return 0;
	stop_machine(change_clocksource, clock, NULL);
	tick_clock_notify();
	return tk->tkr_mono.clock == clock ? 0 : -1;
}

/**
 * ktime_get_real - get the real (wall-) time in ktime_t format
 *
 * returns the time in ktime_t format
 */
ktime_t ktime_get_real(void)
{
	struct timespec64 now;

	getnstimeofday64(&now);

	return timespec64_to_ktime(now);
}
EXPORT_SYMBOL_GPL(ktime_get_real);

/**
 * getrawmonotonic64 - Returns the raw monotonic time in a timespec
 * @ts:		pointer to the timespec64 to be set
 *
 * Returns the raw monotonic time (completely un-modified by ntp)
 */
void getrawmonotonic64(struct timespec64 *ts)
{
	struct timekeeper *tk = &timekeeper;
	struct timespec64 ts64;
	unsigned long seq;
	s64 nsecs;

	do {
		seq = read_seqcount_begin(&timekeeper_seq);
		nsecs = timekeeping_get_ns(&tk->tkr_raw);
		ts64 = tk->raw_time;

	} while (read_seqcount_retry(&timekeeper_seq, seq));

	timespec64_add_ns(&ts64, nsecs);
	*ts = ts64;
}
EXPORT_SYMBOL(getrawmonotonic64);


/**
 * timekeeping_valid_for_hres - Check if timekeeping is suitable for hres
 */
int timekeeping_valid_for_hres(void)
{
	struct timekeeper *tk = &timekeeper;
	unsigned long seq;
	int ret;

	do {
		seq = read_seqcount_begin(&timekeeper_seq);

		ret = tk->tkr_mono.clock->flags & CLOCK_SOURCE_VALID_FOR_HRES;

	} while (read_seqcount_retry(&timekeeper_seq, seq));

	return ret;
}

/**
 * timekeeping_max_deferment - Returns max time the clocksource can be deferred
 */
u64 timekeeping_max_deferment(void)
{
	struct timekeeper *tk = &timekeeper;
	unsigned long seq;
	u64 ret;

	do {
		seq = read_seqcount_begin(&timekeeper_seq);

		ret = tk->tkr_mono.clock->max_idle_ns;

	} while (read_seqcount_retry(&timekeeper_seq, seq));

	return ret;
}

/**
 * read_persistent_clock -  Return time from the persistent clock.
 *
 * Weak dummy function for arches that do not yet support it.
 * Reads the time from the battery backed persistent clock.
 * Returns a timespec with tv_sec=0 and tv_nsec=0 if unsupported.
 *
 *  XXX - Do be sure to remove it once all arches implement it.
 */
void __weak read_persistent_clock(struct timespec *ts)
{
	ts->tv_sec = 0;
	ts->tv_nsec = 0;
}

/**
 * read_boot_clock -  Return time of the system start.
 *
 * Weak dummy function for arches that do not yet support it.
 * Function to read the exact time the system has been started.
 * Returns a timespec with tv_sec=0 and tv_nsec=0 if unsupported.
 *
 *  XXX - Do be sure to remove it once all arches implement it.
 */
void __weak read_boot_clock(struct timespec *ts)
{
	ts->tv_sec = 0;
	ts->tv_nsec = 0;
}

/*
 * timekeeping_init - Initializes the clocksource and common timekeeping values
 */
void __init timekeeping_init(void)
{
	struct timekeeper *tk = &timekeeper;
	struct clocksource *clock;
	unsigned long flags;
	struct timespec64 now, boot, tmp;
	struct timespec ts;

	read_persistent_clock(&ts);
	now = timespec_to_timespec64(ts);
	if (!timespec64_valid_strict(&now)) {
		pr_warn("WARNING: Persistent clock returned invalid value!\n"
			"         Check your CMOS/BIOS settings.\n");
		now.tv_sec = 0;
		now.tv_nsec = 0;
	} else if (now.tv_sec || now.tv_nsec)
		persistent_clock_exist = true;

	read_boot_clock(&ts);
	boot = timespec_to_timespec64(ts);
	if (!timespec64_valid_strict(&boot)) {
		pr_warn("WARNING: Boot clock returned invalid value!\n"
			"         Check your CMOS/BIOS settings.\n");
		boot.tv_sec = 0;
		boot.tv_nsec = 0;
	}

	raw_spin_lock_irqsave(&timekeeper_lock, flags);
	write_seqcount_begin(&timekeeper_seq);
	ntp_init();

	clock = clocksource_default_clock();
	if (clock->enable)
		clock->enable(clock);
	tk_setup_internals(tk, clock);

	tk_set_xtime(tk, &now);
	tk->raw_time.tv_sec = 0;
	tk->raw_time.tv_nsec = 0;
	if (boot.tv_sec == 0 && boot.tv_nsec == 0)
		boot = tk_xtime(tk);

	set_normalized_timespec64(&tmp, -boot.tv_sec, -boot.tv_nsec);
	tk_set_wall_to_mono(tk, tmp);

	tmp.tv_sec = 0;
	tmp.tv_nsec = 0;
	tk_set_sleep_time(tk, tmp);

	timekeeping_update(tk, TK_MIRROR | TK_CLOCK_WAS_SET);

	write_seqcount_end(&timekeeper_seq);
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);
}

/* time in seconds when suspend began */
static struct timespec64 timekeeping_suspend_time;

/**
 * __timekeeping_inject_sleeptime - Internal function to add sleep interval
 * @delta: pointer to a timespec delta value
 *
 * Takes a timespec offset measuring a suspend interval and properly
 * adds the sleep offset to the timekeeping variables.
 */
static void __timekeeping_inject_sleeptime(struct timekeeper *tk,
					   struct timespec64 *delta)
{
	if (!timespec64_valid_strict(delta)) {
		printk_deferred(KERN_WARNING "__timekeeping_inject_sleeptime: Invalid "
					"sleep delta value!\n");
		return;
	}
	tk_xtime_add(tk, delta);
	tk_set_wall_to_mono(tk, timespec64_sub(tk->wall_to_monotonic, *delta));
	tk_set_sleep_time(tk, timespec64_add(tk->total_sleep_time, *delta));
}

/**
 * timekeeping_inject_sleeptime - Adds suspend interval to timeekeeping values
 * @delta: pointer to a timespec delta value
 *
 * This hook is for architectures that cannot support read_persistent_clock
 * because their RTC/persistent clock is only accessible when irqs are enabled.
 *
 * This function should only be called by rtc_resume(), and allows
 * a suspend offset to be injected into the timekeeping values.
 */
void timekeeping_inject_sleeptime(struct timespec *delta)
{
	struct timekeeper *tk = &timekeeper;
	struct timespec64 tmp;
	unsigned long flags;

	/*
	 * Make sure we don't set the clock twice, as timekeeping_resume()
	 * already did it
	 */
	if (has_persistent_clock())
		return;

	raw_spin_lock_irqsave(&timekeeper_lock, flags);
	write_seqcount_begin(&timekeeper_seq);

	timekeeping_forward_now(tk);

	tmp = timespec_to_timespec64(*delta);
	__timekeeping_inject_sleeptime(tk, &tmp);

	timekeeping_update(tk, TK_CLEAR_NTP | TK_MIRROR | TK_CLOCK_WAS_SET);

	write_seqcount_end(&timekeeper_seq);
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);

	/* signal hrtimers about time change */
	clock_was_set();
}

/**
 * timekeeping_resume - Resumes the generic timekeeping subsystem.
 *
 * This is for the generic clocksource timekeeping.
 * xtime/wall_to_monotonic/jiffies/etc are
 * still managed by arch specific suspend/resume code.
 */
static void timekeeping_resume(void)
{
	struct timekeeper *tk = &timekeeper;
	struct clocksource *clock = tk->tkr_mono.clock;
	unsigned long flags;
	struct timespec64 ts_new, ts_delta;
	struct timespec tmp;
	u64 cycle_now, cycle_delta;
	bool suspendtime_found = false;

	read_persistent_clock(&tmp);
	ts_new = timespec_to_timespec64(tmp);

	clockevents_resume();
	clocksource_resume();

	raw_spin_lock_irqsave(&timekeeper_lock, flags);
	write_seqcount_begin(&timekeeper_seq);

	/*
	 * After system resumes, we need to calculate the suspended time and
	 * compensate it for the OS time. There are 3 sources that could be
	 * used: Nonstop clocksource during suspend, persistent clock and rtc
	 * device.
	 *
	 * One specific platform may have 1 or 2 or all of them, and the
	 * preference will be:
	 *	suspend-nonstop clocksource -> persistent clock -> rtc
	 * The less preferred source will only be tried if there is no better
	 * usable source. The rtc part is handled separately in rtc core code.
	 */
	cycle_now = clock->read(clock);
	if ((clock->flags & CLOCK_SOURCE_SUSPEND_NONSTOP) &&
		cycle_now > clock->cycle_last) {
		u64 num, max = ULLONG_MAX;
		u32 mult = clock->mult;
		u32 shift = clock->shift;
		s64 nsec = 0;

		cycle_delta = clocksource_delta(cycle_now, clock->cycle_last,
						clock->mask);

		/*
		 * "cycle_delta * mutl" may cause 64 bits overflow, if the
		 * suspended time is too long. In that case we need do the
		 * 64 bits math carefully
		 */
		do_div(max, mult);
		if (cycle_delta > max) {
			num = div64_u64(cycle_delta, max);
			nsec = (((u64) max * mult) >> shift) * num;
			cycle_delta -= num * max;
		}
		nsec += ((u64) cycle_delta * mult) >> shift;

		ts_delta = ns_to_timespec64(nsec);
		suspendtime_found = true;
	} else if (timespec64_compare(&ts_new, &timekeeping_suspend_time) > 0) {
		ts_delta = timespec64_sub(ts_new, timekeeping_suspend_time);
		suspendtime_found = true;
	}

	if (suspendtime_found)
		__timekeeping_inject_sleeptime(tk, &ts_delta);

	/* Re-base the last cycle value */
	tk->tkr_mono.cycle_last = clock->cycle_last = cycle_now;
	tk->tkr_raw.cycle_last  = cycle_now;

	tk->ntp_error = 0;
	timekeeping_suspended = 0;
	timekeeping_update(tk, TK_MIRROR | TK_CLOCK_WAS_SET);
	write_seqcount_end(&timekeeper_seq);
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);

	touch_softlockup_watchdog();

	clockevents_notify(CLOCK_EVT_NOTIFY_RESUME, NULL);

	/* Resume hrtimers */
	hrtimers_resume();
}

static int timekeeping_suspend(void)
{
	struct timekeeper *tk = &timekeeper;
	unsigned long flags;
	struct timespec64		delta, delta_delta;
	static struct timespec64	old_delta;
	struct timespec tmp;

	read_persistent_clock(&tmp);
	timekeeping_suspend_time = timespec_to_timespec64(tmp);

	/*
	 * On some systems the persistent_clock can not be detected at
	 * timekeeping_init by its return value, so if we see a valid
	 * value returned, update the persistent_clock_exists flag.
	 */
	if (timekeeping_suspend_time.tv_sec || timekeeping_suspend_time.tv_nsec)
		persistent_clock_exist = true;

	raw_spin_lock_irqsave(&timekeeper_lock, flags);
	write_seqcount_begin(&timekeeper_seq);
	timekeeping_forward_now(tk);
	timekeeping_suspended = 1;

	/*
	 * To avoid drift caused by repeated suspend/resumes,
	 * which each can add ~1 second drift error,
	 * try to compensate so the difference in system time
	 * and persistent_clock time stays close to constant.
	 */
	delta = timespec64_sub(tk_xtime(tk), timekeeping_suspend_time);
	delta_delta = timespec64_sub(delta, old_delta);
	if (abs(delta_delta.tv_sec)  >= 2) {
		/*
		 * if delta_delta is too large, assume time correction
		 * has occured and set old_delta to the current delta.
		 */
		old_delta = delta;
	} else {
		/* Otherwise try to adjust old_system to compensate */
		timekeeping_suspend_time =
			timespec64_add(timekeeping_suspend_time, delta_delta);
	}

	timekeeping_update(tk, TK_MIRROR);
	write_seqcount_end(&timekeeper_seq);
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);

	clockevents_notify(CLOCK_EVT_NOTIFY_SUSPEND, NULL);
	clocksource_suspend();
	clockevents_suspend();

	return 0;
}

/* sysfs resume/suspend bits for timekeeping */
static struct syscore_ops timekeeping_syscore_ops = {
	.resume		= timekeeping_resume,
	.suspend	= timekeeping_suspend,
};

static int __init timekeeping_init_ops(void)
{
	register_syscore_ops(&timekeeping_syscore_ops);
	return 0;
}
device_initcall(timekeeping_init_ops);

/*
 * Apply a multiplier adjustment to the timekeeper
 */
static __always_inline void timekeeping_apply_adjustment(struct timekeeper *tk,
							 s64 offset,
							 bool negative,
							 int adj_scale)
{
	s64 interval = tk->cycle_interval;
	s32 mult_adj = 1;

	if (negative) {
		mult_adj = -mult_adj;
		interval = -interval;
		offset  = -offset;
	}
	mult_adj <<= adj_scale;
	interval <<= adj_scale;
	offset <<= adj_scale;

	/*
	 * So the following can be confusing.
	 *
	 * To keep things simple, lets assume mult_adj == 1 for now.
	 *
	 * When mult_adj != 1, remember that the interval and offset values
	 * have been appropriately scaled so the math is the same.
	 *
	 * The basic idea here is that we're increasing the multiplier
	 * by one, this causes the xtime_interval to be incremented by
	 * one cycle_interval. This is because:
	 *	xtime_interval = cycle_interval * mult
	 * So if mult is being incremented by one:
	 *	xtime_interval = cycle_interval * (mult + 1)
	 * Its the same as:
	 *	xtime_interval = (cycle_interval * mult) + cycle_interval
	 * Which can be shortened to:
	 *	xtime_interval += cycle_interval
	 *
	 * So offset stores the non-accumulated cycles. Thus the current
	 * time (in shifted nanoseconds) is:
	 *	now = (offset * adj) + xtime_nsec
	 * Now, even though we're adjusting the clock frequency, we have
	 * to keep time consistent. In other words, we can't jump back
	 * in time, and we also want to avoid jumping forward in time.
	 *
	 * So given the same offset value, we need the time to be the same
	 * both before and after the freq adjustment.
	 *	now = (offset * adj_1) + xtime_nsec_1
	 *	now = (offset * adj_2) + xtime_nsec_2
	 * So:
	 *	(offset * adj_1) + xtime_nsec_1 =
	 *		(offset * adj_2) + xtime_nsec_2
	 * And we know:
	 *	adj_2 = adj_1 + 1
	 * So:
	 *	(offset * adj_1) + xtime_nsec_1 =
	 *		(offset * (adj_1+1)) + xtime_nsec_2
	 *	(offset * adj_1) + xtime_nsec_1 =
	 *		(offset * adj_1) + offset + xtime_nsec_2
	 * Canceling the sides:
	 *	xtime_nsec_1 = offset + xtime_nsec_2
	 * Which gives us:
	 *	xtime_nsec_2 = xtime_nsec_1 - offset
	 * Which simplfies to:
	 *	xtime_nsec -= offset
	 *
	 * XXX - TODO: Doc ntp_error calculation.
	 */
	tk->tkr_mono.mult += mult_adj;
	tk->xtime_interval += interval;
	tk->tkr_mono.xtime_nsec -= offset;
	tk->ntp_error -= (interval - offset) << tk->ntp_error_shift;
}

/*
 * Calculate the multiplier adjustment needed to match the frequency
 * specified by NTP
 */
static __always_inline void timekeeping_freqadjust(struct timekeeper *tk,
							s64 offset)
{
	s64 interval = tk->cycle_interval;
	s64 xinterval = tk->xtime_interval;
	u32 base = tk->tkr_mono.clock->mult;
	u32 max = tk->tkr_mono.clock->maxadj;
	u32 cur_adj = tk->tkr_mono.mult;
	s64 tick_error;
	bool negative;
	u32 adj_scale;

	/* Remove any current error adj from freq calculation */
	if (tk->ntp_err_mult)
		xinterval -= tk->cycle_interval;

	tk->ntp_tick = ntp_tick_length();

	/* Calculate current error per tick */
	tick_error = ntp_tick_length() >> tk->ntp_error_shift;
	tick_error -= (xinterval + tk->xtime_remainder);

	/* Don't worry about correcting it if its small */
	if (likely((tick_error >= 0) && (tick_error <= interval)))
		return;

	/* preserve the direction of correction */
	negative = (tick_error < 0);

	/* If any adjustment would pass the max, just return */
	if (negative && (cur_adj - 1) <= (base - max))
		return;
	if (!negative && (cur_adj + 1) >= (base + max))
		return;
	/*
	 * Sort out the magnitude of the correction, but
	 * avoid making so large a correction that we go
	 * over the max adjustment.
	 */
	adj_scale = 0;
	tick_error = abs(tick_error);
	while (tick_error > interval) {
		u32 adj = 1 << (adj_scale + 1);

		/* Check if adjustment gets us within 1 unit from the max */
		if (negative && (cur_adj - adj) <= (base - max))
			break;
		if (!negative && (cur_adj + adj) >= (base + max))
			break;

		adj_scale++;
		tick_error >>= 1;
	}

	/* scale the corrections */
	timekeeping_apply_adjustment(tk, offset, negative, adj_scale);
}

/*
 * Adjust the timekeeper's multiplier to the correct frequency
 * and also to reduce the accumulated error value.
 */
static void timekeeping_adjust(struct timekeeper *tk, s64 offset)
{
	/* Correct for the current frequency error */
	timekeeping_freqadjust(tk, offset);

	/* Next make a small adjustment to fix any cumulative error */
	if (!tk->ntp_err_mult && (tk->ntp_error > 0)) {
		tk->ntp_err_mult = 1;
		timekeeping_apply_adjustment(tk, offset, 0, 0);
	} else if (tk->ntp_err_mult && (tk->ntp_error <= 0)) {
		/* Undo any existing error adjustment */
		timekeeping_apply_adjustment(tk, offset, 1, 0);
		tk->ntp_err_mult = 0;
	}

	if (unlikely(tk->tkr_mono.clock->maxadj &&
		(tk->tkr_mono.mult > tk->tkr_mono.clock->mult + tk->tkr_mono.clock->maxadj))) {
		printk_deferred_once(KERN_WARNING
			"Adjusting %s more than 11%% (%ld vs %ld)\n",
			tk->tkr_mono.clock->name, (long)tk->tkr_mono.mult,
			(long)tk->tkr_mono.clock->mult + tk->tkr_mono.clock->maxadj);
	}

	/*
	 * It may be possible that when we entered this function, xtime_nsec
	 * was very small.  Further, if we're slightly speeding the clocksource
	 * in the code above, its possible the required corrective factor to
	 * xtime_nsec could cause it to underflow.
	 *
	 * Now, since we already accumulated the second, cannot simply roll
	 * the accumulated second back, since the NTP subsystem has been
	 * notified via second_overflow. So instead we push xtime_nsec forward
	 * by the amount we underflowed, and add that amount into the error.
	 *
	 * We'll correct this error next time through this function, when
	 * xtime_nsec is not as small.
	 */
	if (unlikely((s64)tk->tkr_mono.xtime_nsec < 0)) {
		s64 neg = -(s64)tk->tkr_mono.xtime_nsec;
		tk->tkr_mono.xtime_nsec = 0;
		tk->ntp_error += neg << tk->ntp_error_shift;
	}
}

/**
 * accumulate_nsecs_to_secs - Accumulates nsecs into secs
 *
 * Helper function that accumulates a the nsecs greater then a second
 * from the xtime_nsec field to the xtime_secs field.
 * It also calls into the NTP code to handle leapsecond processing.
 *
 */
static inline unsigned int accumulate_nsecs_to_secs(struct timekeeper *tk)
{
	u64 nsecps = (u64)NSEC_PER_SEC << tk->tkr_mono.shift;
	unsigned int clock_set = 0;

	while (tk->tkr_mono.xtime_nsec >= nsecps) {
		int leap;

		tk->tkr_mono.xtime_nsec -= nsecps;
		tk->xtime_sec++;

		/* Figure out if its a leap sec and apply if needed */
		leap = second_overflow(tk->xtime_sec);
		if (unlikely(leap)) {
			struct timespec64 ts;

			tk->xtime_sec += leap;

			ts.tv_sec = leap;
			ts.tv_nsec = 0;
			tk_set_wall_to_mono(tk,
				timespec64_sub(tk->wall_to_monotonic, ts));

			__timekeeping_set_tai_offset(tk, tk->tai_offset - leap);

			clock_set = TK_CLOCK_WAS_SET;
		}
	}
	return clock_set;
}

/**
 * logarithmic_accumulation - shifted accumulation of cycles
 *
 * This functions accumulates a shifted interval of cycles into
 * into a shifted interval nanoseconds. Allows for O(log) accumulation
 * loop.
 *
 * Returns the unconsumed cycles.
 */
static u64 logarithmic_accumulation(struct timekeeper *tk, u64 offset,
						u32 shift,
						unsigned int *clock_set)
{
	u64 interval = tk->cycle_interval << shift;
	u64 raw_nsecs;

	/* If the offset is smaller then a shifted interval, do nothing */
	if (offset < interval)
		return offset;

	/* Accumulate one shifted interval */
	offset -= interval;
	tk->tkr_mono.cycle_last += interval;
	tk->tkr_raw.cycle_last  += interval;

	tk->tkr_mono.xtime_nsec += tk->xtime_interval << shift;
	*clock_set |= accumulate_nsecs_to_secs(tk);

	/* Accumulate raw time */
	raw_nsecs = (u64)tk->raw_interval << shift;
	raw_nsecs += tk->raw_time.tv_nsec;
	if (raw_nsecs >= NSEC_PER_SEC) {
		u64 raw_secs = raw_nsecs;
		raw_nsecs = do_div(raw_secs, NSEC_PER_SEC);
		tk->raw_time.tv_sec += raw_secs;
	}
	tk->raw_time.tv_nsec = raw_nsecs;

	/* Accumulate error between NTP and clock interval */
	tk->ntp_error += tk->ntp_tick << shift;
	tk->ntp_error -= (tk->xtime_interval + tk->xtime_remainder) <<
						(tk->ntp_error_shift + shift);

	return offset;
}

#ifdef CONFIG_GENERIC_TIME_VSYSCALL_OLD
static inline void old_vsyscall_fixup(struct timekeeper *tk)
{
	s64 remainder;

	/*
	* Store only full nanoseconds into xtime_nsec after rounding
	* it up and add the remainder to the error difference.
	* XXX - This is necessary to avoid small 1ns inconsistnecies caused
	* by truncating the remainder in vsyscalls. However, it causes
	* additional work to be done in timekeeping_adjust(). Once
	* the vsyscall implementations are converted to use xtime_nsec
	* (shifted nanoseconds), and CONFIG_GENERIC_TIME_VSYSCALL_OLD
	* users are removed, this can be killed.
	*/
	remainder = tk->tkr_mono.xtime_nsec & ((1ULL << tk->tkr_mono.shift) - 1);
	tk->tkr_mono.xtime_nsec -= remainder;
	tk->tkr_mono.xtime_nsec += 1ULL << tk->tkr_mono.shift;
	tk->ntp_error += remainder << tk->ntp_error_shift;
	tk->ntp_error -= (1ULL << tk->tkr_mono.shift) << tk->ntp_error_shift;
}
#else
#define old_vsyscall_fixup(tk)
#endif



/**
 * update_wall_time - Uses the current clocksource to increment the wall time
 *
 */
void update_wall_time(void)
{
	struct clocksource *clock;
	struct timekeeper *real_tk = &timekeeper;
	struct timekeeper *tk = &shadow_timekeeper;
	u64 offset;
	int shift = 0, maxshift;
	unsigned int clock_set = 0;
	unsigned long flags;

	raw_spin_lock_irqsave(&timekeeper_lock, flags);

	/* Make sure we're fully resumed: */
	if (unlikely(timekeeping_suspended))
		goto out;

	clock = real_tk->tkr_mono.clock;

#ifdef CONFIG_ARCH_USES_GETTIMEOFFSET
	offset = real_tk->cycle_interval;
#else
	offset = clocksource_delta(clock->read(clock), clock->cycle_last,
				   clock->mask);
#endif

	/* Check if there's really nothing to do */
	if (offset < real_tk->cycle_interval)
		goto out;

	/*
	 * With NO_HZ we may have to accumulate many cycle_intervals
	 * (think "ticks") worth of time at once. To do this efficiently,
	 * we calculate the largest doubling multiple of cycle_intervals
	 * that is smaller than the offset.  We then accumulate that
	 * chunk in one go, and then try to consume the next smaller
	 * doubled multiple.
	 */
	shift = ilog2(offset) - ilog2(tk->cycle_interval);
	shift = max(0, shift);
	/* Bound shift to one less than what overflows tick_length */
	maxshift = (64 - (ilog2(ntp_tick_length())+1)) - 1;
	shift = min(shift, maxshift);
	while (offset >= tk->cycle_interval) {
		offset = logarithmic_accumulation(tk, offset, shift,
							&clock_set);
		if (offset < tk->cycle_interval<<shift)
			shift--;
	}

	/* correct the clock when NTP error is too big */
	timekeeping_adjust(tk, offset);

	/*
	 * XXX This can be killed once everyone converts
	 * to the new update_vsyscall.
	 */
	old_vsyscall_fixup(tk);

	/*
	 * Finally, make sure that after the rounding
	 * xtime_nsec isn't larger than NSEC_PER_SEC
	 */
	clock_set |= accumulate_nsecs_to_secs(tk);

	write_seqcount_begin(&timekeeper_seq);
	/* Update clock->cycle_last with the new value */
	clock->cycle_last = tk->tkr_mono.cycle_last;
	/*
	 * Update the real timekeeper.
	 *
	 * We could avoid this memcpy by switching pointers, but that
	 * requires changes to all other timekeeper usage sites as
	 * well, i.e. move the timekeeper pointer getter into the
	 * spinlocked/seqcount protected sections. And we trade this
	 * memcpy under the timekeeper_seq against one before we start
	 * updating.
	 */
	timekeeping_update(tk, clock_set);
	memcpy(real_tk, tk, sizeof(*tk));
	/* The memcpy must come last. Do not put anything here! */
	write_seqcount_end(&timekeeper_seq);
out:
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);
	if (clock_set)
		/* Have to call _delayed version, since in irq context*/
		clock_was_set_delayed();
}

/**
 * getboottime - Return the real time of system boot.
 * @ts:		pointer to the timespec to be set
 *
 * Returns the wall-time of boot in a timespec.
 *
 * This is based on the wall_to_monotonic offset and the total suspend
 * time. Calls to settimeofday will affect the value returned (which
 * basically means that however wrong your real time clock is at boot time,
 * you get the right time here).
 */
void getboottime(struct timespec *ts)
{
	struct timekeeper *tk = &timekeeper;
	struct timespec boottime = {
		.tv_sec = tk->wall_to_monotonic.tv_sec +
				tk->total_sleep_time.tv_sec,
		.tv_nsec = tk->wall_to_monotonic.tv_nsec +
				tk->total_sleep_time.tv_nsec
	};

	set_normalized_timespec(ts, -boottime.tv_sec, -boottime.tv_nsec);
}
EXPORT_SYMBOL_GPL(getboottime);

/**
 * get_monotonic_boottime - Returns monotonic time since boot
 * @ts:		pointer to the timespec to be set
 *
 * Returns the monotonic time since boot in a timespec.
 *
 * This is similar to CLOCK_MONTONIC/ktime_get_ts, but also
 * includes the time spent in suspend.
 */
void get_monotonic_boottime(struct timespec *ts)
{
	struct timekeeper *tk = &timekeeper;
	struct timespec64 tomono, sleep, ret;
	s64 nsec;
	unsigned int seq;

	WARN_ON(timekeeping_suspended);

	do {
		seq = read_seqcount_begin(&timekeeper_seq);
		ret.tv_sec = tk->xtime_sec;
		nsec = timekeeping_get_ns(&tk->tkr_mono);
		tomono = tk->wall_to_monotonic;
		sleep = tk->total_sleep_time;

	} while (read_seqcount_retry(&timekeeper_seq, seq));

	ret.tv_sec += tomono.tv_sec + sleep.tv_sec;
	ret.tv_nsec = 0;
	timespec64_add_ns(&ret, nsec + tomono.tv_nsec + sleep.tv_nsec);
	*ts = timespec64_to_timespec(ret);
}
EXPORT_SYMBOL_GPL(get_monotonic_boottime);

/**
 * ktime_get_boottime - Returns monotonic time since boot in a ktime
 *
 * Returns the monotonic time since boot in a ktime
 *
 * This is similar to CLOCK_MONTONIC/ktime_get, but also
 * includes the time spent in suspend.
 */
ktime_t ktime_get_boottime(void)
{
	struct timespec ts;

	get_monotonic_boottime(&ts);
	return timespec_to_ktime(ts);
}
EXPORT_SYMBOL_GPL(ktime_get_boottime);

/**
 * monotonic_to_bootbased - Convert the monotonic time to boot based.
 * @ts:		pointer to the timespec to be converted
 */
void monotonic_to_bootbased(struct timespec *ts)
{
	struct timekeeper *tk = &timekeeper;
	struct timespec64 ts64;

	ts64 = timespec_to_timespec64(*ts);
	ts64 = timespec64_add(ts64, tk->total_sleep_time);
	*ts = timespec64_to_timespec(ts64);
}
EXPORT_SYMBOL_GPL(monotonic_to_bootbased);

unsigned long get_seconds(void)
{
	struct timekeeper *tk = &timekeeper;

	return tk->xtime_sec;
}
EXPORT_SYMBOL(get_seconds);

struct timespec __current_kernel_time(void)
{
	struct timekeeper *tk = &timekeeper;

	return timespec64_to_timespec(tk_xtime(tk));
}

struct timespec current_kernel_time(void)
{
	struct timekeeper *tk = &timekeeper;
	struct timespec64 now;
	unsigned long seq;

	do {
		seq = read_seqcount_begin(&timekeeper_seq);

		now = tk_xtime(tk);
	} while (read_seqcount_retry(&timekeeper_seq, seq));

	return timespec64_to_timespec(now);
}
EXPORT_SYMBOL(current_kernel_time);

struct timespec64 get_monotonic_coarse64(void)
{
	struct timekeeper *tk = &timekeeper;
	struct timespec64 now, mono;
	unsigned long seq;

	do {
		seq = read_seqcount_begin(&timekeeper_seq);

		now = tk_xtime(tk);
		mono = tk->wall_to_monotonic;
	} while (read_seqcount_retry(&timekeeper_seq, seq));

	set_normalized_timespec64(&now, now.tv_sec + mono.tv_sec,
				now.tv_nsec + mono.tv_nsec);

	return now;
}

/*
 * Must hold jiffies_lock
 */
void do_timer(unsigned long ticks)
{
	jiffies_64 += ticks;
	calc_global_load(ticks);
}

/**
 * ktime_get_update_offsets_now - hrtimer helper
 * @cwsseq:	pointer to check and store the clock was set sequence number
 * @offs_real:	pointer to storage for monotonic -> realtime offset
 * @offs_boot:	pointer to storage for monotonic -> boottime offset
 *
 * Returns current monotonic time and updates the offsets if the
 * sequence number in @cwsseq and timekeeper.clock_was_set_seq are
 * different.
 *
 * Called from hrtimer_interupt() or retrigger_next_event()
 */
ktime_t ktime_get_update_offsets_now(unsigned int *cwsseq, ktime_t *offs_real,
				     ktime_t *offs_boot, ktime_t *offs_tai)
{
	struct timekeeper *tk = &timekeeper;
	unsigned int seq;
	ktime_t base;
	u64 nsecs;

	do {
		seq = read_seqcount_begin(&timekeeper_seq);

		base = tk->tkr_mono.base;
		nsecs = timekeeping_get_ns(&tk->tkr_mono);
		base = ktime_add_ns(base, nsecs);

		if (*cwsseq != tk->clock_was_set_seq) {
			*cwsseq = tk->clock_was_set_seq;
			*offs_real = tk->offs_real;
			*offs_boot = tk->offs_boot;
			*offs_tai = tk->offs_tai;
		}

		/* Handle leapsecond insertion adjustments */
		if (unlikely(base.tv64 >= tk->next_leap_ktime.tv64))
			*offs_real = ktime_sub(tk->offs_real, ktime_set(1, 0));

	} while (read_seqcount_retry(&timekeeper_seq, seq));

	return base;
}

/**
 * ktime_get_monotonic_offset() - get wall_to_monotonic in ktime_t format
 */
ktime_t ktime_get_monotonic_offset(void)
{
	struct timekeeper *tk = &timekeeper;
	unsigned long seq;
	struct timespec64 wtom;

	do {
		seq = read_seqcount_begin(&timekeeper_seq);
		wtom = tk->wall_to_monotonic;
	} while (read_seqcount_retry(&timekeeper_seq, seq));

	return timespec64_to_ktime(wtom);
}
EXPORT_SYMBOL_GPL(ktime_get_monotonic_offset);

/**
 * do_adjtimex() - Accessor function to NTP __do_adjtimex function
 */
int do_adjtimex(struct timex *txc)
{
	struct timekeeper *tk = &timekeeper;
	unsigned long flags;
	struct timespec64 ts;
	s32 orig_tai, tai;
	int ret;

	/* Validate the data before disabling interrupts */
	ret = ntp_validate_timex(txc);
	if (ret)
		return ret;

	if (txc->modes & ADJ_SETOFFSET) {
		struct timespec delta;
		delta.tv_sec  = txc->time.tv_sec;
		delta.tv_nsec = txc->time.tv_usec;
		if (!(txc->modes & ADJ_NANO))
			delta.tv_nsec *= 1000;
		ret = timekeeping_inject_offset(&delta);
		if (ret)
			return ret;
	}

	getnstimeofday64(&ts);

	raw_spin_lock_irqsave(&timekeeper_lock, flags);
	write_seqcount_begin(&timekeeper_seq);

	orig_tai = tai = tk->tai_offset;
	ret = __do_adjtimex(txc, &ts, &tai);

	if (tai != orig_tai) {
		__timekeeping_set_tai_offset(tk, tai);
		timekeeping_update(tk, TK_MIRROR | TK_CLOCK_WAS_SET);
	}
	tk_update_leap_state(tk);

	write_seqcount_end(&timekeeper_seq);
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);

	if (tai != orig_tai)
		clock_was_set();

	ntp_notify_cmos_timer();

	return ret;
}

#ifdef CONFIG_NTP_PPS
/**
 * hardpps() - Accessor function to NTP __hardpps function
 */
void hardpps(const struct timespec *phase_ts, const struct timespec *raw_ts)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&timekeeper_lock, flags);
	write_seqcount_begin(&timekeeper_seq);

	__hardpps(phase_ts, raw_ts);

	write_seqcount_end(&timekeeper_seq);
	raw_spin_unlock_irqrestore(&timekeeper_lock, flags);
}
EXPORT_SYMBOL(hardpps);
#endif

/**
 * xtime_update() - advances the timekeeping infrastructure
 * @ticks:	number of ticks, that have elapsed since the last call.
 *
 * Must be called with interrupts disabled.
 */
void xtime_update(unsigned long ticks)
{
	write_seqlock(&jiffies_lock);
	do_timer(ticks);
	write_sequnlock(&jiffies_lock);
	update_wall_time();
}
