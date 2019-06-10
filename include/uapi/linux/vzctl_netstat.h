/*
 *  include/uapi/linux/vzctl_netstat.h
 *
 *  Copyright (c) 2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef __VZCTL_NETSTAT_H__
#define __VZCTL_NETSTAT_H__

#include <linux/types.h>
#include <linux/ioctl.h>

#ifndef __ENVID_T_DEFINED__
# define __ENVID_T_DEFINED__
typedef unsigned int envid_t;
#endif

/*
 * Traffic accouting management ioctl
 */

struct vz_tc_class_info {
	__u32				cid;	/* class number */
	__u32				addr;	/* Network byte order */
	__u32				mask;	/* subnet mask */
	/*
	 * On any changes to this struct keep in mind fixing
	 * all copy_to_user instances, initializing new fields/paddings
	 * to prevent possible leaks from kernel-space.
	 */
};


struct vzctl_tc_classes {
	struct vz_tc_class_info		*info;
	int				length;
};

/* For IPv6 */
struct vz_tc_class_info_v6 {
	__u32				cid;	/* class number */
	__u32				addr[4];/* Network byte order */
	__u32				mask[4];/* subnet mask */
	/*
	 * On any changes to this struct keep in mind fixing
	 * all copy_to_user instances, initializing new fields/paddings
	 * to prevent possible leaks from kernel-space.
	 */
};

struct vzctl_tc_classes_v6 {
	struct vz_tc_class_info_v6	*info;
	int				length;
};

struct vzctl_tc_get_stat {
	envid_t				veid;
	__u64				*incoming;
	__u64				*outgoing;
	__u32				*incoming_pkt;
	__u32				*outgoing_pkt;
	int				length;
};

struct vzctl_tc_get_stat_list {
	envid_t				*list;
	int				length;
};

struct vzctl_tc_set_base {
	envid_t				veid;
	__u16				base;
};

#define VZTCCTLTYPE			'='
#define VZCTL_TC_MAX_CLASS		_IO(VZTCCTLTYPE, 1)
#define VZCTL_TC_CLASS_NUM		_IO(VZTCCTLTYPE, 2)
#define VZCTL_TC_SET_CLASS_TABLE	_IOW(VZTCCTLTYPE, 3, struct vzctl_tc_classes)
#define VZCTL_TC_GET_CLASS_TABLE	_IOR(VZTCCTLTYPE, 4, struct vzctl_tc_classes)
#define VZCTL_TC_STAT_NUM		_IO(VZTCCTLTYPE, 5)
#define VZCTL_TC_GET_STAT_LIST		_IOR(VZTCCTLTYPE, 6, struct vzctl_tc_get_stat_list)
#define VZCTL_TC_GET_STAT		_IOR(VZTCCTLTYPE, 7, struct vzctl_tc_get_stat)
#define VZCTL_TC_DESTROY_STAT		_IO(VZTCCTLTYPE, 8)
#define VZCTL_TC_DESTROY_ALL_STAT	_IO(VZTCCTLTYPE, 9)

#define VZCTL_TC_GET_BASE		_IO(VZTCCTLTYPE, 11)
#define VZCTL_TC_SET_BASE		_IOW(VZTCCTLTYPE, 12, struct vzctl_tc_set_base)

#define VZCTL_TC_GET_STAT_V6		_IOR(VZTCCTLTYPE, 13, struct vzctl_tc_get_stat)
#define VZCTL_TC_SET_CLASS_TABLE_V6	_IOW(VZTCCTLTYPE, 14, struct vzctl_tc_classes_v6)
#define VZCTL_TC_GET_CLASS_TABLE_V6	_IOR(VZTCCTLTYPE, 15, struct vzctl_tc_classes_v6)

#define VZCTL_TC_CLASS_NUM_V6		_IO(VZTCCTLTYPE, 16)

#define VZCTL_TC_CLEAR_STAT		_IO(VZTCCTLTYPE, 17)
#define VZCTL_TC_CLEAR_ALL_STAT		_IO(VZTCCTLTYPE, 18)

#ifdef __KERNEL__
#ifdef CONFIG_COMPAT
#include <linux/compat.h>

struct compat_vzctl_tc_classes {
	compat_uptr_t			info;
	int				length;
};

struct compat_vzctl_tc_get_stat {
	envid_t				veid;
	compat_uptr_t			incoming;
	compat_uptr_t			outgoing;
	compat_uptr_t			incoming_pkt;
	compat_uptr_t			outgoing_pkt;
	int				length;
};

struct compat_vzctl_tc_get_stat_list {
	compat_uptr_t			list;
	int				length;
};

#define COMPAT_VZCTL_TC_SET_CLASS_TABLE	_IOW(VZTCCTLTYPE, 3, struct compat_vzctl_tc_classes)
#define COMPAT_VZCTL_TC_GET_CLASS_TABLE	_IOR(VZTCCTLTYPE, 4, struct compat_vzctl_tc_classes)
#define COMPAT_VZCTL_TC_GET_STAT_LIST	_IOR(VZTCCTLTYPE, 6, struct compat_vzctl_tc_get_stat_list)
#define COMPAT_VZCTL_TC_GET_STAT	_IOR(VZTCCTLTYPE, 7, struct compat_vzctl_tc_get_stat)
#endif /* CONFIG_COMPAT */
#endif /* __KERNEL__ */

#endif /* __VZCTL_NETSTAT_H__ */
