/*
 *  include/uapi/linux/bc/statd.h
 *
 *  Copyright (c) 2005-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *
 */

#ifndef __BC_STATD_H_
#define __BC_STATD_H_

/* sys_ubstat commands list */
#define UBSTAT_READ_ONE			0x010000
#define UBSTAT_READ_ALL			0x020000
#define UBSTAT_READ_FULL		0x030000
#define UBSTAT_UBLIST			0x040000
#define UBSTAT_UBPARMNUM		0x050000
#define UBSTAT_GETTIME			0x060000

#define UBSTAT_CMD(func)		((func) & 0xF0000)
#define UBSTAT_PARMID(func)		((func) & 0x0FFFF)

#define TIME_MAX_SEC		(LONG_MAX / HZ)
#define TIME_MAX_JIF		(TIME_MAX_SEC * HZ)

typedef unsigned long ubstattime_t;

typedef struct {
	ubstattime_t	start_time;
	ubstattime_t	end_time;
	ubstattime_t	cur_time;
	/*
	 * On any changes to this struct keep in mind fixing
	 * all copy_to_user instances, initializing new fields/paddings
	 * to prevent possible leaks from kernel-space.
	 */
} ubgettime_t;

typedef struct {
	long		maxinterval;
	int		signum;
} ubnotifrq_t;

typedef struct {
	unsigned long	maxheld;
	unsigned long	failcnt;
	/*
	 * On any changes to this struct keep in mind fixing
	 * all copy_to_user instances, initializing new fields/paddings
	 * to prevent possible leaks from kernel-space.
	 */
} ubstatparm_t;

typedef struct {
	unsigned long	barrier;
	unsigned long	limit;
	unsigned long	held;
	unsigned long	maxheld;
	unsigned long	minheld;
	unsigned long	failcnt;
	unsigned long __unused1;
	unsigned long __unused2;
	/*
	 * On any changes to this struct keep in mind fixing
	 * all copy_to_user instances, initializing new fields/paddings
	 * to prevent possible leaks from kernel-space.
	 */
} ubstatparmf_t;

typedef struct {
	ubstattime_t	start_time;
	ubstattime_t	end_time;
	ubstatparmf_t	param[0];
} ubstatfull_t;

#endif
