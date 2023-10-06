/*
 *  fs/fuse/kio/pcs/log.h
 *
 *  Copyright (c) 2018-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

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

extern void (*fuse_printk_plugin)(unsigned long, const char *fmt, ...);

#define fuse_kio_trace_printk(fmt, ...)				\
do {								\
	char _______STR[] = __stringify((__VA_ARGS__));		\
	if (sizeof(_______STR) > 3)				\
		__fuse_kio_do_trace_printk(fmt, ##__VA_ARGS__);	\
	else							\
		__trace_puts(_THIS_IP_, fmt, strlen(fmt));	\
} while (0)

#define __fuse_kio_do_trace_printk(fmt, ...)				\
do {									\
	void (*__plugin)(unsigned long, const char *, ...); 		\
	__trace_printk_check_format(fmt, ##__VA_ARGS__);		\
        rcu_read_lock(); 						\
        __plugin = rcu_dereference(fuse_printk_plugin); 		\
        if (__plugin) (*__plugin)(_THIS_IP_, fmt, ##__VA_ARGS__);       \
	rcu_read_unlock(); 						\
} while (0)


#define TRACE(fmt, ...)	if (unlikely(debugfs_tracing && pcs_loglevel >= LOG_TRACE)) fuse_kio_trace_printk(__stringify(__LINE__) ": " fmt, ##__VA_ARGS__)
#define DTRACE(fmt, ...)	if (unlikely(debugfs_tracing && pcs_loglevel >= LOG_DTRACE)) fuse_kio_trace_printk(__stringify(__LINE__) ": " fmt, ##__VA_ARGS__)
#endif /* __PCSLOG_H__ */
