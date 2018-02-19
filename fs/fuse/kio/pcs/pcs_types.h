#ifndef __PCS_TYPES_H__
#define __PCS_TYPES_H__

#include <linux/types.h>
#include <linux/timer.h>

typedef int pcs_fd_t;
typedef int pcs_sock_t;
typedef unsigned long ULONG_PTR;
typedef unsigned long long abs_time_t;
typedef struct timer_list pcs_timer_t;
#define PCS_INVALID_FD (-1)
#define PCS_API

#include "pcs_align.h"

typedef struct __pre_aligned(8) _PCS_NODE_ID_T {
	u64    val;
} PCS_NODE_ID_T __aligned(8);


/* from: pcs_net_addr.h */
enum
{
	PCS_ADDRTYPE_NONE = 0,
	PCS_ADDRTYPE_IP = 1,
	PCS_ADDRTYPE_IP6 = 2,
	PCS_ADDRTYPE_UNIX = 3,
};

/* alignment makes it usable in binary protocols */
typedef struct __pre_aligned(8) _PCS_NET_ADDR_T {
	u32	type;
	u32	port;			/* network byteorder! */
	u8	address[16];
} PCS_NET_ADDR_T __aligned(8);

#endif /* __PCS_TYPES_H__ */
