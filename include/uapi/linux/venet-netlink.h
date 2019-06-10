/*
 *  include/uapi/linux/venet-netlink.h
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef __NET_VENET_H_
#define __NET_VENET_H_

enum {
	VENET_INFO_UNSPEC,
	VENET_INFO_CMD,

	__VENET_INFO_MAX
#define VENET_INFO_MAX   (__VENET_INFO_MAX - 1)
};

enum {
	VENET_IP_ADD,
	VENET_IP_DEL,
};

struct venetaddrmsg {
	__u8		va_family;
	__u8		va_cmd;
	__u32		va_addr[4];
};

#endif
