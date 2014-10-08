#ifndef _XT_OWNER_MATCH_H
#define _XT_OWNER_MATCH_H

#include <linux/types.h>

enum {
	XT_OWNER_UID    = 1 << 0,
	XT_OWNER_GID    = 1 << 1,
	XT_OWNER_SOCKET = 1 << 2,
};

struct ipt_owner_info {
	uid_t uid;
	gid_t gid;
	pid_t pid;
	pid_t sid;
	char comm[16];
	u_int8_t match, invert;     /* flags */
};

struct ip6t_owner_info {
	uid_t uid;
	gid_t gid;
	pid_t pid;
	pid_t sid;
	u_int8_t match, invert;     /* flags */
};

struct xt_owner_match_info {
	__u32 uid_min, uid_max;
	__u32 gid_min, gid_max;
	__u8 match, invert;
};

#endif /* _XT_OWNER_MATCH_H */
