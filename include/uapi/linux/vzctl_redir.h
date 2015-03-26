/*
 * include/linux/vzctl_redir.h
 *
 * Copyright (c) 2015 Parallels IP Holdings GmbH
 *
 */

#ifndef _UAPI_VZCTL_REDIR_H
#define _UAPI_VZCTL_REDIR_H

#include <linux/types.h>
#include <linux/ioctl.h>

#ifndef __ENVID_T_DEFINED__
# define __ENVID_T_DEFINED__
typedef unsigned int envid_t;
#endif

/*
 * WARN: Please note, that until the moment we drop vzcompat module
 * support for old ioctls vzctl_ve_redir_ip_map struct should be _exactly_
 * the same as vzctl_ve_ip_map.
 * The op numbers are kept not renumbered for the same purpose.
 */
#define VE_IPPOOL_ADD	3
#define VE_IPPOOL_DEL	4
#define VE_IPPOOL_GET	5

struct vzctl_ve_redir_ip_map {
	envid_t			veid;
	int			op;
	struct sockaddr		*addr;
	int			addrlen;
};

/*
 * Port redirection description.
 * Applies to TCP connections in VE0 routed to venet0 device.
 * Also affects filtering of packets entering VE0 from VEs.
 * Multiple redirections to different VEs are allowed, but their port
 * ranges must not intersect (otherwise redirection results are undefined).
 */
struct vzctl_ve_redir_port_compat {
	envid_t			target;
	envid_t			source;
	__u32			ip;		/* ip of the redirect */
	int			numports;	/* length of the ports array below */
	__u16			ports[0];	/* ranges (port pairs), inclusive, sorted, host byte order */
};

struct vzctl_ve_redir_port {
	envid_t			target;
	envid_t			source;

	struct sockaddr		*addr;
	int			addrlen;

	int			numports;
	__u16			ports[0];
};

struct vzctl_ve_redir_port_del {
	envid_t			veid;
};

#define VZTRCTLTYPE			')'
#define VZTRCTL_VE_IP_MAP		_IOW(VZTRCTLTYPE, 0, struct vzctl_ve_redir_ip_map)
#define VZTRCTL_VE_REDIR_PORT_COMPAT	_IOW(VZTRCTLTYPE, 1, struct vzctl_ve_redir_port_compat)
#define VZTRCTL_VE_REDIR_PORT_DEL	_IOW(VZTRCTLTYPE, 2, struct vzctl_ve_redir_port_del)
#define VZTRCTL_VE_REDIR_PORT		_IOW(VZTRCTLTYPE, 3, struct vzctl_ve_redir_port)

#endif /* _UAPI_VZCTL_REDIR_H */
