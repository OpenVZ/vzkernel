#ifndef _PCS_SOCK_CONN_H_
#define _PCS_SOCK_CONN_H_ 1

void pcs_sockconnect_start(struct pcs_rpc *ep);
int pcs_netaddr2sockaddr(PCS_NET_ADDR_T const* addr, struct sockaddr *sa, int *salen);

#endif /* _PCS_SOCK_CONN_H_ */
