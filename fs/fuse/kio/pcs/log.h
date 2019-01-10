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

#define LOG_DTRACE LOG_DEBUG4

extern unsigned int pcs_loglevel;
extern unsigned int debugfs_tracing;

#define TRACE(fmt, args...)	if (unlikely(debugfs_tracing && pcs_loglevel >= LOG_TRACE)) trace_printk("%d: " fmt "\n", __LINE__, ## args)
#define DTRACE(fmt, args...)	if (unlikely(debugfs_tracing && pcs_loglevel >= LOG_DTRACE)) trace_printk("%d: " fmt "\n", __LINE__, ## args)
#endif /* __PCSLOG_H__ */
