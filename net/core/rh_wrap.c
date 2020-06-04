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
			   const struct tc_mqprio_qopt_offload *mqprio)
{
	struct tc_to_netdev_rh74 tc74 = {
		.type	= TC_SETUP_QDISC_MQPRIO,
		.tc	= mqprio->qopt.num_tc,
	};

	/* For RHEL7.4 only DCB mode is valid */
	if (mqprio->mode != TC_MQPRIO_MODE_DCB)
		return -ENOTSUPP;

	return dev->netdev_ops->ndo_setup_tc_rh74(dev, 0, 0, &tc74);
}

static inline
int handle_cls_u32_rh74(struct net_device *dev, u32 handle,
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

	return dev->netdev_ops->ndo_setup_tc_rh74(dev, handle, common->protocol,
						  &tc74);
}

static inline
int tcf_exts_get_dev(struct net_device *dev, struct tcf_exts *exts,
		     struct net_device **hw_dev)
{
#ifdef CONFIG_NET_CLS_ACT
	const struct tc_action *a;
	LIST_HEAD(actions);

	if (!tcf_exts_has_actions(exts))
		return -EINVAL;

	tcf_exts_to_list(exts, &actions);
	list_for_each_entry(a, &actions, list) {
		if (a->ops->get_dev)
			*hw_dev = a->ops->get_dev(a);
	}
	if (*hw_dev)
		return 0;
#endif
	return -EOPNOTSUPP;
}

static inline
int handle_cls_flower_rh74(struct net_device *dev, u32 handle,
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
	};
	const struct tc_cls_common_offload *common = &cls_flower->common;

	/* All older drivers supports only single chain */
	if (common->chain_index)
		return -ENOTSUPP;

	/*
	 * Emulate 'egress_dev':
	 * tc_can_offload(dev)?
	 * yes - leave egress_dev unset
	 *     - call .ndo_setup_tc() for the 'dev'
	 * no - retrieve egress device from one of assigned action(s)
	 *    - set egress_dev to true
	 *    - call .ndo_setup_tc() for this egress device
	 */
	if (!tc_can_offload(dev)) {
		struct net_device *hw_dev = NULL;

		if (tcf_exts_get_dev(dev, cls_flower->exts, &hw_dev) ||
		    (hw_dev && !tc_can_offload(hw_dev)))
			return -EINVAL;

		dev = hw_dev;
		tc74.egress_dev = true;
	}

	return dev->netdev_ops->ndo_setup_tc_rh74(dev, handle, common->protocol,
						  &tc74);
}

static inline
int handle_cls_matchall_rh74(struct net_device *dev, u32 handle,
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

	return dev->netdev_ops->ndo_setup_tc_rh74(dev, handle, common->protocol,
						  &tc74);
}

static bool tech_preview_marked = false;

int __rh_call_ndo_setup_tc(struct net_device *dev, u32 handle,
			   enum tc_setup_type type, void *type_data)
{
	const struct net_device_ops *ops = dev->netdev_ops;
	int ret = -EOPNOTSUPP;

	if (get_ndo_ext(ops, ndo_setup_tc_rh)) {
		/*
		 * The drivers implementing .ndo_setup_tc_rh() should handle
		 * only types >= TC_SETUP_BLOCK & TC_SETUP_QDISC_MQPRIO.
		 * The types TC_SETUP_{CLSU32,CLSFLOWER, CLSMATCHALL,CLSBPF}
		 * are handled by TC setup callbacks.
		 */
		switch (type) {
		case TC_SETUP_CLSU32:
		case TC_SETUP_CLSFLOWER:
		case TC_SETUP_CLSMATCHALL:
		case TC_SETUP_CLSBPF:
			return 0;
		default:
			ret = get_ndo_ext(ops, ndo_setup_tc_rh)(dev, type,
								type_data);
		}
	} else if (ops->ndo_setup_tc_rh74) {
		/*
		 * Callback .ndo_setup_tc() for RHEL-7.4 drivers should be
		 * called only when TC offloading is supported and enabled
		 * by the device. There is one exception: flower classifier
		 * in combination with mirred action where offloading can
		 * be provided by egress device. This functionality is
		 * handled in handle_cls_flower_rh74().
		 */
		if (!tc_can_offload(dev) && type != TC_SETUP_CLSFLOWER)
			return 0;
		switch (type) {
		case TC_SETUP_QDISC_MQPRIO:
			ret = handle_sch_mqprio_rh74(dev, type_data);
			break;
		case TC_SETUP_CLSU32:
			ret = handle_cls_u32_rh74(dev, handle, type_data);
			break;
		case TC_SETUP_CLSFLOWER:
			ret = handle_cls_flower_rh74(dev, handle, type_data);
			break;
		case TC_SETUP_CLSMATCHALL:
			ret = handle_cls_matchall_rh74(dev, handle, type_data);
			break;
		default:
			break;
		}
	} else if (ops->ndo_setup_tc_rh72 && type == TC_SETUP_QDISC_MQPRIO) {
		/* Drivers implementing .ndo_setup_tc_rh72()
		 * Note that drivers that implement .ndo_setup_tc_rh72() can
		 * only support mqprio so this entry-point can be called
		 * only for this type.
		 */
		struct tc_mqprio_qopt_offload *mqprio = type_data;

		/* For RHEL7.2 only DCB mode is valid */
		if (mqprio->mode != TC_MQPRIO_MODE_DCB)
			return -ENOTSUPP;

		ret = ops->ndo_setup_tc_rh72(dev, mqprio->qopt.num_tc);
	}

	/* TC offloading is a Tech-Preview so inform an user in case that
	 * offloading setup succeeded.
	 */
	if (!ret && !tech_preview_marked) {
		mark_tech_preview("TC offloading", NULL);
		tech_preview_marked = true;
	}

	return ret;
}
EXPORT_SYMBOL(__rh_call_ndo_setup_tc);
