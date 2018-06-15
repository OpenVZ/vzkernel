#ifndef _PCS_NET_PROT_H_
#define _PCS_NET_PROT_H_ 1

#include "pcs_prot_types.h"

/* Current version of protocol. We promise to support all the messages forever,
 * so that no version checks are required. However, we must not send new messages
 * to old peers, that. where this version is required.
 */
#define PCS_VERSION_CURRENT	1U

struct pcs_rpc_hdr
{
	u32		len;
	u32		type;
	PCS_XID_T	xid;
} __attribute__((aligned(8)));

#define PCS_RPC_DIRECTION	1

#define RPC_IS_RESPONSE(type) (type & PCS_RPC_DIRECTION)


#define PCS_RPC_ERROR_RESP	1

struct pcs_rpc_payload
{
	u32	len;
	u32	type;
	/* Variable size data follows */
} __attribute__((aligned(8)));


struct pcs_rpc_error_resp
{
	struct pcs_rpc_hdr	hdr;
	PCS_NODE_ID_T		offender;
	u32			code;
	u32			npayloads;
	struct pcs_rpc_payload	payload;
} __attribute__((aligned(8)));


#define PCS_RPC_CS_CLIENT_BASE	256
#define PCS_RPC_MDS_CLIENT_BASE	512
#define PCS_RPC_CS_CS_BASE	1024
#define PCS_RPC_LOCAL_BASE	2048

/* Payload types */
#define PCS_RPC_EMPTY_PAYLOAD		0

/* Authentication payload types */
#define PCS_RPC_AUTH_TYPE_PAYLOAD	11
#define PCS_RPC_SSL_PAYLOAD		12
#define PCS_RPC_DIGEST_PAYLOAD		13
#define PCS_RPC_AUTH_SIMPLE_PAYLOAD	14

/* System payload types */
#define PCS_RPC_SYS_PAYLOAD_BASE	128
#define PCS_RPC_BUILD_VERSION_PAYLOAD	PCS_RPC_SYS_PAYLOAD_BASE

/* Application specific payload types */
#define PCS_RPC_APP_PAYLOAD_BASE	512

/* Node role */
enum
{
	PCS_NODE_ROLE_TEST	= 0,			/* Can be used for diagnostics. Functionality is reduced. */
	PCS_NODE_ROLE_CN	= 1,			/* Client */
	PCS_NODE_ROLE_CS	= 2,			/* Chunk server */
	PCS_NODE_ROLE_MDS	= 3,			/* Meta-data server */
	PCS_NODE_ROLE_TOOL	= 4,			/* Similar to the client but not visible in stat */
	PCS_NODE_ROLE_SVC	= 5,			/* Generic service */
	PCS_NODE_ROLES_
};

static inline const char *pcs_role_to_str(u8 role)
{
	static const char *roles_str[PCS_NODE_ROLES_] = {
		"TEST", "CN", "CS", "MDS", "TOOL", "SVC"
	};

	if (role >= PCS_NODE_ROLES_)
		return "Unknown";
	return roles_str[role];
}

struct pcs_rpc_keep_waiting
{
	struct pcs_rpc_hdr	hdr;

	PCS_XID_T		xid;	/* XID of request which should not timeout */
} __attribute__((aligned(8)));

#define PCS_RPC_KEEP_WAITING	(12)

#endif /* _PCS_RPC_PROT_H_ */
