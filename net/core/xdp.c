/* net/core/xdp.c
 *
 * Copyright (c) 2017 Jesper Dangaard Brouer, Red Hat Inc.
 * Released under terms in GPL version 2.  See COPYING.
 */
#include <linux/types.h>
#include <linux/mm.h>

#include <net/xdp.h>

#define REG_STATE_NEW		0x0
#define REG_STATE_REGISTERED	0x1
#define REG_STATE_UNREGISTERED	0x2
#define REG_STATE_UNUSED	0x3

void xdp_rxq_info_unreg(struct xdp_rxq_info *xdp_rxq)
{
	return;
}
EXPORT_SYMBOL_GPL(xdp_rxq_info_unreg);

/* Returns 0 on success, negative on failure */
int xdp_rxq_info_reg(struct xdp_rxq_info *xdp_rxq,
		     struct net_device *dev, u32 queue_index)
{
	return 0;
}
EXPORT_SYMBOL_GPL(xdp_rxq_info_reg);

void xdp_rxq_info_unused(struct xdp_rxq_info *xdp_rxq)
{
	return;
}
EXPORT_SYMBOL_GPL(xdp_rxq_info_unused);

bool xdp_rxq_info_is_reg(struct xdp_rxq_info *xdp_rxq)
{
	return true;
}
EXPORT_SYMBOL_GPL(xdp_rxq_info_is_reg);

int xdp_rxq_info_reg_mem_model(struct xdp_rxq_info *xdp_rxq,
			       enum xdp_mem_type type, void *allocator)
{
	return 0;
}
EXPORT_SYMBOL_GPL(xdp_rxq_info_reg_mem_model);

void xdp_rxq_info_unreg_mem_model(struct xdp_rxq_info *xdp_rxq)
{
	return;
}
EXPORT_SYMBOL_GPL(xdp_rxq_info_unreg_mem_model);
