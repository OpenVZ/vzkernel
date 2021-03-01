#ifndef _TIMEKEEPING_INTERNAL_H
#define _TIMEKEEPING_INTERNAL_H
/*
 * timekeeping debug functions
 */
#include <linux/time.h>
#include <linux/clocksource.h>

#ifdef CONFIG_CLOCKSOURCE_VALIDATE_LAST_CYCLE
static inline u64 clocksource_delta(u64 now, u64 last, u64 mask)
{
	u64 ret = (now - last) & mask;

	return (s64) ret > 0 ? ret : 0;
}
#else
static inline u64 clocksource_delta(u64 now, u64 last, u64 mask)
{
	return (now - last) & mask;
}
#endif

#endif /* _TIMEKEEPING_INTERNAL_H */
