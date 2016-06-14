/*
 *  include/uapi/linux/beancounter.h
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *
 */

#ifndef _UAPI_LINUX_BEANCOUNTER_H
#define _UAPI_LINUX_BEANCOUNTER_H

/*
 * Resource list.
 */
#define UB_KMEMSIZE		0	/* Unswappable kernel memory size including
					 * struct task, page directories, etc. */
#define UB_LOCKEDPAGES		1	/* Mlock()ed pages. */
#define UB_PRIVVMPAGES		2	/* Total number of pages, counting potentially
					 * private pages as private and used. */
#define UB_SHMPAGES		3	/* IPC SHM segment size. */
#define UB_DUMMY		4	/* Dummy resource (compatibility) */
#define UB_NUMPROC		5	/* Number of processes. */
#define UB_PHYSPAGES		6	/* All resident pages, for swapout guarantee. */
#define UB_VMGUARPAGES		7	/* Guarantee for memory allocation,
					 * checked against PRIVVMPAGES. */
#define UB_OOMGUARPAGES		8	/* Guarantees against OOM kill.
					 * Only limit is used, no accounting. */
#define UB_NUMTCPSOCK		9	/* Number of TCP sockets. */
#define UB_NUMFLOCK		10	/* Number of file locks. */
#define UB_NUMPTY		11	/* Number of PTYs. */
#define UB_NUMSIGINFO		12	/* Number of siginfos. */
#define UB_TCPSNDBUF		13	/* Total size of tcp send buffers. */
#define UB_TCPRCVBUF		14	/* Total size of tcp receive buffers. */
#define UB_OTHERSOCKBUF		15	/* Total size of other socket
					 * send buffers (all buffers for PF_UNIX). */
#define UB_DGRAMRCVBUF		16	/* Total size of other socket
					 * receive buffers. */
#define UB_NUMOTHERSOCK		17	/* Number of other sockets. */
#define UB_DCACHESIZE		18	/* Size of busy dentry/inode cache. */
#define UB_NUMFILE		19	/* Number of open files. */

#define UB_RESOURCES_COMPAT	24

/*
 * Add new resources here.
 */
#define UB_NUMXTENT		23
#define UB_SWAPPAGES		24
#define UB_RESOURCES		25

struct ubparm {
	/*
	 * A barrier over which resource allocations are failed gracefully.
	 * If the amount of consumed memory is over the barrier further sbrk()
	 * or mmap() calls fail, the existing processes are not killed.
	 */
	unsigned long	barrier;
	unsigned long	limit;		/* hard resource limit */
	unsigned long	held;		/* consumed resources */
	unsigned long	maxheld;	/* maximum amount of consumed resources through the last period */
	unsigned long	minheld;	/* minimum amount of consumed resources through the last period */
	unsigned long	failcnt;	/* count of failed charges */
	int		max_precharge;	/* maximum percpu resource precharge */
};

#endif /* _UAPI_LINUX_BEANCOUNTER_H */
