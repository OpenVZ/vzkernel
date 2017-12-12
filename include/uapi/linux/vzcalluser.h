/*
 *  include/uapi/linux/vzcalluser.h
 *
 *  Copyright (c) 2005-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef _UAPI_LINUX_VZCALLUSER_H
#define _UAPI_LINUX_VZCALLUSER_H

#include <linux/types.h>
#include <linux/ioctl.h>

#ifndef __ENVID_T_DEFINED__
# define __ENVID_T_DEFINED__
typedef unsigned int envid_t;
#endif

#ifndef __KERNEL__
#define __user
#endif

#define VE_USE_MAJOR	010	/* Test MAJOR supplied in rule */
#define VE_USE_MINOR	030	/* Test MINOR supplied in rule */
#define VE_USE_MASK	030	/* Testing mask, VE_USE_MAJOR|VE_USE_MINOR */

#define VE_CONFIGURE_OS_RELEASE		2 /* unused */
#define VE_CONFIGURE_CREATE_PROC_LINK	4 /* unused */
#define VE_CONFIGURE_OPEN_TTY		5

struct vzctl_ve_configure {
	envid_t				veid;
	unsigned int			key;
	unsigned int			val;
	unsigned int			size;
	char				data[0];
};

#define VE_FEATURE_SYSFS	(1ULL << 0)	/* deprecated */
#define VE_FEATURE_NFS		(1ULL << 1)
#define VE_FEATURE_DEF_PERMS	(1ULL << 2)	/* deprecated */
#define VE_FEATURE_SIT          (1ULL << 3)
#define VE_FEATURE_IPIP         (1ULL << 4)
#define VE_FEATURE_PPP		(1ULL << 5)
#define VE_FEATURE_IPGRE	(1ULL << 6)	/* deprecated */
#define VE_FEATURE_BRIDGE	(1ULL << 7)
#define VE_FEATURE_NFSD		(1ULL << 8)

#define VE_FEATURES_OLD		(VE_FEATURE_SYSFS)
#define VE_FEATURES_DEF		(VE_FEATURE_SYSFS | VE_FEATURE_DEF_PERMS)

struct vz_load_avg {
	int				val_int;
	int				val_frac;
};

struct vz_cpu_stat {
	unsigned long			user_jif;	/* clock_t */
	unsigned long			nice_jif;	/* clock_t */
	unsigned long			system_jif	/* clock_t */;
	unsigned long			uptime_jif	/* clock_t */;
	__u64				idle_clk;	/* ns */
	__u64				strv_clk;	/* deprecated */
	__u64				uptime_clk;	/* ns */
	struct vz_load_avg		avenrun[3];	/* loadavg data */
};

struct vzctl_cpustatctl {
	envid_t				veid;
	struct vz_cpu_stat __user	*cpustat;
};

#define VZCTLTYPE			'.'
#define VZCTL_OLD_ENV_CREATE		_IOW(VZCTLTYPE,  0, @DEPRECATED)
#define VZCTL_MARK_ENV_TO_DOWN		_IOW(VZCTLTYPE,  1, @DEPRECATED)
#define VZCTL_SETDEVPERMS		_IOW(VZCTLTYPE,  2, @DEPRECATED)
#define VZCTL_ENV_CREATE_CID		_IOW(VZCTLTYPE,  4, @DEPRECATED)
#define VZCTL_ENV_CREATE		_IOW(VZCTLTYPE,  5, @DEPRECATED)
#define VZCTL_GET_CPU_STAT		_IOW(VZCTLTYPE,  6, struct vzctl_cpustatctl)
#define VZCTL_ENV_CREATE_DATA		_IOW(VZCTLTYPE, 10, @DEPRECATED)
#define VZCTL_VE_NETDEV			_IOW(VZCTLTYPE, 11, @DEPRECATED)
#define VZCTL_VE_MEMINFO		_IOW(VZCTLTYPE, 13, @DEPRECATED)
#define VZCTL_VE_CONFIGURE		_IOW(VZCTLTYPE, 15, struct vzctl_ve_configure)

#endif /* _UAPI_LINUX_VZCALLUSER_H */
