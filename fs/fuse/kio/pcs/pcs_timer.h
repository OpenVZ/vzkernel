#ifndef _PCS_TIMER_H_
#define _PCS_TIMER_H_ 1

#include "pcs_types.h"

abs_time_t get_real_time_ms(void);

static inline abs_time_t get_abs_time_fast_us(void)
{
	return ktime_to_ns(ktime_get()) / NSEC_PER_USEC;
}

static inline abs_time_t get_abs_time_us(void)
{
	return ktime_to_ns(ktime_get_real()) / NSEC_PER_USEC;
}


#endif /* _PCS_TIMER_H_ */
