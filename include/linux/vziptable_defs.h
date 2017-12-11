#ifndef _LINUX_VZIPTABLE_DEFS_H
#define _LINUX_VZIPTABLE_DEFS_H

#include <linux/types.h>
#include <linux/sched.h>

#include <uapi/linux/vziptable_defs.h>

static inline bool mask_ipt_allow(__u64 permitted, __u64 mask)
{
	return (permitted & mask) == mask;
}

#endif /* _LINUX_VZIPTABLE_DEFS_H */
