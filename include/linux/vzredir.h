/*
 * include/linux/vzredir.h
 *
 * Copyright (c) 2015 Parallels IP Holdings GmbH
 *
 */

#ifndef _VZREDIR_H
#define _VZREDIR_H

#include <linux/list.h>
#include <linux/veip.h>

/*
 *    veip_redir_port describes a single redirect rule for a veip_struct:
 *    one IP address or a wildcard, a set of ports and the target VE.
 *
 *    If the target VE is stopped, the redirected packets are dropped.
 *    ve_struct pointer is stored in veip_redir_port in addition to
 *    target_veid for efficiency.
 *
 *    veip_redir_port's are linked via src_lh to the veip_struct of the VE the
 *    redirects apply to.  They are linked to veip_struct not ip_entry_struct
 *    to handle wildcard IP redirects.
 *    To handle target VE start/stop efficiently, veip_redir_port's are linked
 *    by dst_lh also.
 *
 *    redirect field of ip_entry_struct is set and reset by VE_IPPOOL_ADD and
 *    VE_IPPOOL_DEL calls.
 *    If redirect field is NULL, no port redirecting is performed.
 *
 * Locking scheme:
 *
 *    Lists above are protected by veip_hash_lock.
 *    ve_list_guard should be taken before veip_hash_lock
 */

struct veip_redir_port {
	struct list_head	src_list;
	struct list_head	dst_list;
	struct ve_struct	*target;
	envid_t			target_veid;
	struct ve_addr_struct	addr;
	int			numports;
	__u16			ports[0];
};

static inline int redir_match_any(struct veip_redir_port *redir)
{
	struct ve_addr_struct *addr;

	addr = &redir->addr;
	return (addr->key[0] | addr->key[1] | addr->key[2] | addr->key[3]) == 0;
}

#define skb_set_redirect(skb)	(skb)->redirected = 1
#define skb_redirected(skb)	((skb)->redirected)

struct ve_struct *venet_find_redirect_ve(struct ve_addr_struct *addr,
		__u16 port, struct list_head *search_lh);
int skb_extract_addr_port(struct sk_buff *skb,
		struct ve_addr_struct *addr, __u16 *port, int dir);
#endif
