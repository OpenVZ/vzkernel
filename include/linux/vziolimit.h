/*
 *  include/linux/vziolimit.h
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *
 */

#ifndef _LINUX_VZIOLIMIT_H
#define _LINUX_VZIOLIMIT_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define VZIOLIMITTYPE 'I'

struct iolimit_state {
	unsigned int id;
	unsigned int speed;
	unsigned int burst;
	unsigned int latency;
};

#define VZCTL_SET_IOLIMIT	_IOW(VZIOLIMITTYPE, 0, struct iolimit_state)
#define VZCTL_GET_IOLIMIT	_IOR(VZIOLIMITTYPE, 1, struct iolimit_state)
#define VZCTL_SET_IOPSLIMIT	_IOW(VZIOLIMITTYPE, 2, struct iolimit_state)
#define VZCTL_GET_IOPSLIMIT	_IOR(VZIOLIMITTYPE, 3, struct iolimit_state)

#endif /* _LINUX_VZIOLIMIT_H */
