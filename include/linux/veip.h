#ifndef __VE_IP_H_
#define __VE_IP_H_

struct ve_addr_struct {
	int family;
	__u32 key[4];
};

struct sockaddr;

extern void veaddr_print(char *, int, struct ve_addr_struct *);
extern int sockaddr_to_veaddr(struct sockaddr __user *uaddr, int addrlen,
		struct ve_addr_struct *veaddr);

#endif
