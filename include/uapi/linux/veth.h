/*
 *  include/linux/veth.h
 *
 *  Copyright (C) 2007  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */
#ifndef __NET_VETH_H_
#define __NET_VETH_H_

enum {
	VETH_INFO_UNSPEC,
	VETH_INFO_PEER,

	__VETH_INFO_MAX
#define VETH_INFO_MAX	(__VETH_INFO_MAX - 1)
};

#define SIOCSVENET	(SIOCDEVPRIVATE + 0xf)

#endif
