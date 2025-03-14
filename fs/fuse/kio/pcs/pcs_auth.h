/*
 *  fs/fuse/kio/pcs/pcs_auth.h
 *
 *  Copyright (c) 2018-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef _PCS_AUTH_H_
#define _PCS_AUTH_H_ 1

#include "pcs_rpc.h"

enum {
	PCS_AUTH_DIGEST = 0,
};

int rpc_client_start_auth(struct pcs_rpc *ep, int auth_type, char *cluster_name);

#endif /* _PCS_AUTH_H_ */
