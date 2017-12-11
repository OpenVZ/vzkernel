/*
 *  include/linux/vzctl_venet.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef _UAPI_VZCTL_VENET_H
#define _UAPI_VZCTL_VENET_H

#include <linux/types.h>
#include <linux/ioctl.h>

#ifndef __ENVID_T_DEFINED__
#define __ENVID_T_DEFINED__
typedef unsigned envid_t;
#endif

#define VE_IP_ADD	1
#define VE_IP_DEL	2
#define VE_IP_EXT_ADD	3
#define VE_IP_EXT_DEL	4

struct vzctl_ve_ip_map {
	envid_t		veid;
	int		op;
	struct sockaddr *addr;
	int		addrlen;
};

#define VENETCTLTYPE		'('
#define VENETCTL_VE_IP_MAP	_IOW(VENETCTLTYPE, 3, struct vzctl_ve_ip_map)

#ifdef __KERNEL__
#ifdef CONFIG_COMPAT
#include <linux/compat.h>

struct compat_vzctl_ve_ip_map {
	envid_t		veid;
	int		op;
	compat_uptr_t	addr;
	int		addrlen;
};

#define VENETCTL_COMPAT_VE_IP_MAP	_IOW(VENETCTLTYPE, 3, struct compat_vzctl_ve_ip_map)

#endif /* CONFIG_COMPAT */
#endif /* __KERNEL__ */

#endif /* _UAPI_VZCTL_VENET_H */
