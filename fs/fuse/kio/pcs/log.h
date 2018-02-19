#ifndef __PCSLOG_H__
#define __PCSLOG_H__

#include <linux/printk.h>

/*
 * Log level values and flags
 */
#define LOG_ERR		0
#define LOG_WARN	1
#define LOG_INFO	2
#define LOG_DEBUG	4
/* The high debug levels are used for dumping the system state */
#define LOG_DEBUG2	5
#define LOG_DEBUG3	6
/* Tracing levels */
#define LOG_TRACE	7
#define LOG_DEBUG4	8
#define LOG_DEBUG5	9
#define LOG_LEVEL_MAX	LOG_DEBUG5


#define __PCS_DEBUG__ 1
#define __PCS_DTRACE__ 1

#ifndef __PCS_DEBUG__
#define pcs_log(level, fmt, ...)
#define TRACE(fmt, ...) do {} while (0)
#define DTRACE(fmt, ...) do {} while (0)
#else
static int pcs_loglevel __attribute__ ((unused)) = LOG_DEBUG;
#define pcs_log(level, fmt, args...) do					\
	{								\
		if (level <= pcs_loglevel)				\
			pr_debug(fmt , ##args);				\
	} while (0)
#define TRACE(fmt, args...)	trace_printk("%d: " fmt "\n", __LINE__, ## args)

#ifndef __PCS_DTRACE__
#define DTRACE(fmt, ...) do {} while (0)
#else
#define DTRACE(fmt, args...)	trace_printk("%d: " fmt "\n", __LINE__, ## args)
#endif
#endif
#endif /* __PCSLOG_H__ */
