/*
 * rh_wrap.c - RHEL specific wrappers
 */

#include <linux/netdevice.h>
#include <net/pkt_cls.h>

/* Structures used by out-of-tree drivers compiled against
 * RHEL7.4 code base.
 */
struct tc_cls_u32_offload_rh74 {
	/* knode values */
	enum tc_clsu32_command command;
	union {
		struct tc_cls_u32_knode knode;
		struct tc_cls_u32_hnode hnode;
	};
};

struct tc_cls_flower_offload_rh74 {
	enum tc_fl_command command;
	u32 prio;
	unsigned long cookie;
	struct flow_dissector *dissector;
	struct fl_flow_key *mask;
	struct fl_flow_key *key;
	struct tcf_exts *exts;
};

struct tc_cls_matchall_offload_rh74 {
	enum tc_matchall_command command;
	struct tcf_exts *exts;
	unsigned long cookie;
};

struct tc_to_netdev_rh74 {
	unsigned int type;
	union {
		u8 tc;
		struct tc_cls_u32_offload_rh74 *cls_u32;
		struct tc_cls_flower_offload_rh74 *cls_flower;
		struct tc_cls_matchall_offload_rh74 *cls_mall;
	};
	bool egress_dev;
};

static inline
int handle_sch_mqprio_rh74(struct net_device *dev,
			   const struct tc_mqprio_qopt *mqprio)
{
	struct tc_to_netdev_rh74 tc74 = {
		.type	= TC_SETUP_MQPRIO,
		.tc	= mqprio->num_tc,
	};

	return dev->netdev_ops->ndo_setup_tc_rh74(dev, 0, 0, &tc74);
}

static inline
int handle_cls_u32_rh74(struct net_device *dev,
			const struct tc_cls_u32_offload *cls_u32)
{
	struct tc_cls_u32_offload_rh74 cls_u32_rh74 = {
		.command	= cls_u32->command,
		.knode		= cls_u32->knode,
		.hnode		= cls_u32->hnode,
	};
	struct tc_to_netdev_rh74 tc74 = {
		.type		= TC_SETUP_CLSU32,
		.cls_u32	= &cls_u32_rh74,
	};
	const struct tc_cls_common_offload *common = &cls_u32->common;

	/* All older drivers supports only single chain */
	if (common->chain_index)
		return -ENOTSUPP;

	return dev->netdev_ops->ndo_setup_tc_rh74(dev, common->handle,
						  common->protocol, &tc74);
}

static inline
int handle_cls_flower_rh74(struct net_device *dev,
			   const struct tc_cls_flower_offload *cls_flower)
{
	struct tc_cls_flower_offload_rh74 cls_flower_rh74 = {
		.command	= cls_flower->command,
		.prio		= cls_flower->common.prio,
		.cookie		= cls_flower->cookie,
		.dissector	= cls_flower->dissector,
		.mask		= cls_flower->mask,
		.key		= cls_flower->key,
		.exts		= cls_flower->exts,
	};
	struct tc_to_netdev_rh74 tc74 = {
		.type		= TC_SETUP_CLSFLOWER,
		.cls_flower	= &cls_flower_rh74,
		.egress_dev	= cls_flower->egress_dev,
	};
	const struct tc_cls_common_offload *common = &cls_flower->common;

	/* All older drivers supports only single chain */
	if (common->chain_index)
		return -ENOTSUPP;

	return dev->netdev_ops->ndo_setup_tc_rh74(dev, common->handle,
						  common->protocol, &tc74);
}

static inline
int handle_cls_matchall_rh74(struct net_device *dev,
			     const struct tc_cls_matchall_offload *cls_mall)
{
	struct tc_cls_matchall_offload_rh74 cls_mall_rh74 = {
		.command	= cls_mall->command,
		.exts		= cls_mall->exts,
		.cookie		= cls_mall->cookie,
	};
	struct tc_to_netdev_rh74 tc74 = {
		.type		= TC_SETUP_CLSMATCHALL,
		.cls_mall	= &cls_mall_rh74,
	};
	const struct tc_cls_common_offload *common = &cls_mall->common;

	/* All older drivers supports only single chain */
	if (common->chain_index)
		return -ENOTSUPP;

	return dev->netdev_ops->ndo_setup_tc_rh74(dev, common->handle,
						  common->protocol, &tc74);
}

int __rh_call_ndo_setup_tc(struct net_device *dev, enum tc_setup_type type,
			   void *type_data)
{
	const struct net_device_ops *ops = dev->netdev_ops;

	if (get_ndo_ext(ops, ndo_setup_tc_rh)) {
		return get_ndo_ext(ops, ndo_setup_tc_rh)(dev, type, type_data);
	} else if (ops->ndo_setup_tc_rh74) {
		switch (type) {
		case TC_SETUP_MQPRIO:
			return handle_sch_mqprio_rh74(dev, type_data);
		case TC_SETUP_CLSU32:
			return handle_cls_u32_rh74(dev, type_data);
		case TC_SETUP_CLSFLOWER:
			return handle_cls_flower_rh74(dev, type_data);
		case TC_SETUP_CLSMATCHALL:
			return handle_cls_matchall_rh74(dev, type_data);
		case TC_SETUP_CLSBPF:
			return -EOPNOTSUPP;
		}
	} else if (ops->ndo_setup_tc_rh72 && type == TC_SETUP_MQPRIO) {
		/* Drivers implementing .ndo_setup_tc_rh72()
		 * Note that drivers that implement .ndo_setup_tc_rh72() can
		 * only support mqprio so this entry-point can be called
		 * only for this type.
		 */
		struct tc_mqprio_qopt *mqprio = type_data;

		return ops->ndo_setup_tc_rh72(dev, mqprio->num_tc);
	}

	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(__rh_call_ndo_setup_tc);
