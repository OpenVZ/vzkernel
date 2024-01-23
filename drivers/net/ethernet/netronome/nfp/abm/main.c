// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright (C) 2018 Netronome Systems, Inc. */

#include <linux/bitfield.h>
#include <linux/etherdevice.h>
#include <linux/lockdep.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>
#include <net/red.h>

#include "../nfpcore/nfp.h"
#include "../nfpcore/nfp_cpp.h"
#include "../nfpcore/nfp_nsp.h"
#include "../nfp_app.h"
#include "../nfp_main.h"
#include "../nfp_net.h"
#include "../nfp_net_repr.h"
#include "../nfp_port.h"
#include "main.h"

static u32 nfp_abm_portid(enum nfp_repr_type rtype, unsigned int id)
{
	return FIELD_PREP(NFP_ABM_PORTID_TYPE, rtype) |
	       FIELD_PREP(NFP_ABM_PORTID_ID, id);
}

static int nfp_abm_reset_stats(struct nfp_abm_link *alink)
{
	int err;

	err = nfp_abm_ctrl_read_stats(alink, &alink->qdiscs[0].stats);
	if (err)
		return err;
	alink->qdiscs[0].stats.backlog_pkts = 0;
	alink->qdiscs[0].stats.backlog_bytes = 0;

	err = nfp_abm_ctrl_read_xstats(alink, &alink->qdiscs[0].xstats);
	if (err)
		return err;

	return 0;
}

static void
nfp_abm_red_destroy(struct net_device *netdev, struct nfp_abm_link *alink,
		    u32 handle)
{
	struct nfp_port *port = nfp_port_from_netdev(netdev);

	if (handle != alink->qdiscs[0].handle)
		return;

	alink->qdiscs[0].handle = TC_H_UNSPEC;
	port->tc_offload_cnt = 0;
	nfp_abm_ctrl_set_all_q_lvls(alink, ~0);
}

static int
nfp_abm_red_replace(struct net_device *netdev, struct nfp_abm_link *alink,
		    struct tc_red_qopt_offload *opt)
{
	struct nfp_port *port = nfp_port_from_netdev(netdev);
	int err;

	if (opt->set.min != opt->set.max || !opt->set.is_ecn) {
		nfp_warn(alink->abm->app->cpp,
			 "RED offload failed - unsupported parameters\n");
		err = -EINVAL;
		goto err_destroy;
	}
	err = nfp_abm_ctrl_set_all_q_lvls(alink, opt->set.min);
	if (err)
		goto err_destroy;

	/* Reset stats only on new qdisc */
	if (alink->qdiscs[0].handle != opt->handle) {
		err = nfp_abm_reset_stats(alink);
		if (err)
			goto err_destroy;
	}

	alink->qdiscs[0].handle = opt->handle;
	port->tc_offload_cnt = 1;

	return 0;
err_destroy:
	/* If the qdisc keeps on living, but we can't offload undo changes */
	if (alink->qdiscs[0].handle == opt->handle) {
		opt->set.qstats->qlen -= alink->qdiscs[0].stats.backlog_pkts;
		opt->set.qstats->backlog -=
			alink->qdiscs[0].stats.backlog_bytes;
	}
	if (alink->qdiscs[0].handle != TC_H_UNSPEC)
		nfp_abm_red_destroy(netdev, alink, alink->qdiscs[0].handle);
	return err;
}

static void
nfp_abm_update_stats(struct nfp_alink_stats *new, struct nfp_alink_stats *old,
		     struct tc_qopt_offload_stats *stats)
{
	_bstats_update(stats->bstats, new->tx_bytes - old->tx_bytes,
		       new->tx_pkts - old->tx_pkts);
	stats->qstats->qlen += new->backlog_pkts - old->backlog_pkts;
	stats->qstats->backlog += new->backlog_bytes - old->backlog_bytes;
	stats->qstats->overlimits += new->overlimits - old->overlimits;
	stats->qstats->drops += new->drops - old->drops;
}

static int
nfp_abm_red_stats(struct nfp_abm_link *alink, struct tc_red_qopt_offload *opt)
{
	struct nfp_alink_stats *prev_stats;
	struct nfp_alink_stats stats;
	int err;

	if (alink->qdiscs[0].handle != opt->handle)
		return -EOPNOTSUPP;
	prev_stats = &alink->qdiscs[0].stats;

	err = nfp_abm_ctrl_read_stats(alink, &stats);
	if (err)
		return err;

	nfp_abm_update_stats(&stats, prev_stats, &opt->stats);

	*prev_stats = stats;

	return 0;
}

static int
nfp_abm_red_xstats(struct nfp_abm_link *alink, struct tc_red_qopt_offload *opt)
{
	struct nfp_alink_xstats *prev_xstats;
	struct nfp_alink_xstats xstats;
	int err;

	if (alink->qdiscs[0].handle != opt->handle)
		return -EOPNOTSUPP;
	prev_xstats = &alink->qdiscs[0].xstats;

	err = nfp_abm_ctrl_read_xstats(alink, &xstats);
	if (err)
		return err;

	opt->xstats->forced_mark += xstats.ecn_marked - prev_xstats->ecn_marked;
	opt->xstats->pdrop += xstats.pdrop - prev_xstats->pdrop;

	*prev_xstats = xstats;

	return 0;
}

static int
nfp_abm_setup_tc_red(struct net_device *netdev, struct nfp_abm_link *alink,
		     struct tc_red_qopt_offload *opt)
{
	if (opt->parent != TC_H_ROOT)
		return -EOPNOTSUPP;

	switch (opt->command) {
	case TC_RED_REPLACE:
		return nfp_abm_red_replace(netdev, alink, opt);
	case TC_RED_DESTROY:
		nfp_abm_red_destroy(netdev, alink, opt->handle);
		return 0;
	case TC_RED_STATS:
		return nfp_abm_red_stats(alink, opt);
	case TC_RED_XSTATS:
		return nfp_abm_red_xstats(alink, opt);
	default:
		return -EOPNOTSUPP;
	}
}

static int
nfp_abm_setup_tc(struct nfp_app *app, struct net_device *netdev,
		 enum tc_setup_type type, void *type_data)
{
	struct nfp_repr *repr = netdev_priv(netdev);
	struct nfp_port *port;

	port = nfp_port_from_netdev(netdev);
	if (!port || port->type != NFP_PORT_PF_PORT)
		return -EOPNOTSUPP;

	switch (type) {
	case TC_SETUP_QDISC_RED:
		return nfp_abm_setup_tc_red(netdev, repr->app_priv, type_data);
	default:
		return -EOPNOTSUPP;
	}
}

static struct net_device *
nfp_abm_repr_get(struct nfp_app *app, u32 port_id, bool *redir_egress)
{
	enum nfp_repr_type rtype;
	struct nfp_reprs *reprs;
	u8 port;

	rtype = FIELD_GET(NFP_ABM_PORTID_TYPE, port_id);
	port = FIELD_GET(NFP_ABM_PORTID_ID, port_id);

	reprs = rcu_dereference(app->reprs[rtype]);
	if (!reprs)
		return NULL;

	if (port >= reprs->num_reprs)
		return NULL;

	return rcu_dereference(reprs->reprs[port]);
}

static int
nfp_abm_spawn_repr(struct nfp_app *app, struct nfp_abm_link *alink,
		   enum nfp_port_type ptype)
{
	struct net_device *netdev;
	enum nfp_repr_type rtype;
	struct nfp_reprs *reprs;
	struct nfp_repr *repr;
	struct nfp_port *port;
	int err;

	if (ptype == NFP_PORT_PHYS_PORT)
		rtype = NFP_REPR_TYPE_PHYS_PORT;
	else
		rtype = NFP_REPR_TYPE_PF;

	netdev = nfp_repr_alloc(app);
	if (!netdev)
		return -ENOMEM;
	repr = netdev_priv(netdev);
	repr->app_priv = alink;

	port = nfp_port_alloc(app, ptype, netdev);
	if (IS_ERR(port)) {
		err = PTR_ERR(port);
		goto err_free_repr;
	}

	if (ptype == NFP_PORT_PHYS_PORT) {
		port->eth_forced = true;
		err = nfp_port_init_phy_port(app->pf, app, port, alink->id);
		if (err)
			goto err_free_port;
	} else {
		port->pf_id = alink->abm->pf_id;
		port->vnic = alink->vnic->dp.ctrl_bar;
	}

	SET_NETDEV_DEV(netdev, &alink->vnic->pdev->dev);
	eth_hw_addr_random(netdev);

	err = nfp_repr_init(app, netdev, nfp_abm_portid(rtype, alink->id),
			    port, alink->vnic->dp.netdev);
	if (err)
		goto err_free_port;

	reprs = nfp_reprs_get_locked(app, rtype);
	WARN(nfp_repr_get_locked(app, reprs, alink->id), "duplicate repr");
	rtnl_lock();
	rcu_assign_pointer(reprs->reprs[alink->id], netdev);
	rtnl_unlock();

	nfp_info(app->cpp, "%s Port %d Representor(%s) created\n",
		 ptype == NFP_PORT_PF_PORT ? "PCIe" : "Phys",
		 alink->id, netdev->name);

	return 0;

err_free_port:
	nfp_port_free(port);
err_free_repr:
	nfp_repr_free(netdev);
	return err;
}

static void
nfp_abm_kill_repr(struct nfp_app *app, struct nfp_abm_link *alink,
		  enum nfp_repr_type rtype)
{
	struct net_device *netdev;
	struct nfp_reprs *reprs;

	reprs = nfp_reprs_get_locked(app, rtype);
	netdev = nfp_repr_get_locked(app, reprs, alink->id);
	if (!netdev)
		return;
	rtnl_lock();
	rcu_assign_pointer(reprs->reprs[alink->id], NULL);
	rtnl_unlock();
	synchronize_rcu();
	/* Cast to make sure nfp_repr_clean_and_free() takes a nfp_repr */
	nfp_repr_clean_and_free((struct nfp_repr *)netdev_priv(netdev));
}

static void
nfp_abm_kill_reprs(struct nfp_abm *abm, struct nfp_abm_link *alink)
{
	nfp_abm_kill_repr(abm->app, alink, NFP_REPR_TYPE_PF);
	nfp_abm_kill_repr(abm->app, alink, NFP_REPR_TYPE_PHYS_PORT);
}

static void nfp_abm_kill_reprs_all(struct nfp_abm *abm)
{
	struct nfp_pf *pf = abm->app->pf;
	struct nfp_net *nn;

	list_for_each_entry(nn, &pf->vnics, vnic_list)
		nfp_abm_kill_reprs(abm, (struct nfp_abm_link *)nn->app_priv);
}

static enum devlink_eswitch_mode nfp_abm_eswitch_mode_get(struct nfp_app *app)
{
	struct nfp_abm *abm = app->priv;

	return abm->eswitch_mode;
}

static int nfp_abm_eswitch_set_legacy(struct nfp_abm *abm)
{
	nfp_abm_kill_reprs_all(abm);
	nfp_abm_ctrl_qm_disable(abm);

	abm->eswitch_mode = DEVLINK_ESWITCH_MODE_LEGACY;
	return 0;
}

static void nfp_abm_eswitch_clean_up(struct nfp_abm *abm)
{
	if (abm->eswitch_mode != DEVLINK_ESWITCH_MODE_LEGACY)
		WARN_ON(nfp_abm_eswitch_set_legacy(abm));
}

static int nfp_abm_eswitch_set_switchdev(struct nfp_abm *abm)
{
	struct nfp_app *app = abm->app;
	struct nfp_pf *pf = app->pf;
	struct nfp_net *nn;
	int err;

	err = nfp_abm_ctrl_qm_enable(abm);
	if (err)
		return err;

	list_for_each_entry(nn, &pf->vnics, vnic_list) {
		struct nfp_abm_link *alink = nn->app_priv;

		err = nfp_abm_spawn_repr(app, alink, NFP_PORT_PHYS_PORT);
		if (err)
			goto err_kill_all_reprs;

		err = nfp_abm_spawn_repr(app, alink, NFP_PORT_PF_PORT);
		if (err)
			goto err_kill_all_reprs;
	}

	abm->eswitch_mode = DEVLINK_ESWITCH_MODE_SWITCHDEV;
	return 0;

err_kill_all_reprs:
	nfp_abm_kill_reprs_all(abm);
	nfp_abm_ctrl_qm_disable(abm);
	return err;
}

static int nfp_abm_eswitch_mode_set(struct nfp_app *app, u16 mode)
{
	struct nfp_abm *abm = app->priv;

	if (abm->eswitch_mode == mode)
		return 0;

	switch (mode) {
	case DEVLINK_ESWITCH_MODE_LEGACY:
		return nfp_abm_eswitch_set_legacy(abm);
	case DEVLINK_ESWITCH_MODE_SWITCHDEV:
		return nfp_abm_eswitch_set_switchdev(abm);
	default:
		return -EINVAL;
	}
}

static void
nfp_abm_vnic_set_mac(struct nfp_pf *pf, struct nfp_abm *abm, struct nfp_net *nn,
		     unsigned int id)
{
	struct nfp_eth_table_port *eth_port = &pf->eth_tbl->ports[id];
	u8 mac_addr[ETH_ALEN];
	const char *mac_str;
	char name[32];

	if (id > pf->eth_tbl->count) {
		nfp_warn(pf->cpp, "No entry for persistent MAC address\n");
		eth_hw_addr_random(nn->dp.netdev);
		return;
	}

	snprintf(name, sizeof(name), "eth%u.mac.pf%u",
		 eth_port->eth_index, abm->pf_id);

	mac_str = nfp_hwinfo_lookup(pf->hwinfo, name);
	if (!mac_str) {
		nfp_warn(pf->cpp, "Can't lookup persistent MAC address (%s)\n",
			 name);
		eth_hw_addr_random(nn->dp.netdev);
		return;
	}

	if (sscanf(mac_str, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		   &mac_addr[0], &mac_addr[1], &mac_addr[2],
		   &mac_addr[3], &mac_addr[4], &mac_addr[5]) != 6) {
		nfp_warn(pf->cpp, "Can't parse persistent MAC address (%s)\n",
			 mac_str);
		eth_hw_addr_random(nn->dp.netdev);
		return;
	}

	ether_addr_copy(nn->dp.netdev->dev_addr, mac_addr);
	ether_addr_copy(nn->dp.netdev->perm_addr, mac_addr);
}

static int
nfp_abm_vnic_alloc(struct nfp_app *app, struct nfp_net *nn, unsigned int id)
{
	struct nfp_eth_table_port *eth_port = &app->pf->eth_tbl->ports[id];
	struct nfp_abm *abm = app->priv;
	struct nfp_abm_link *alink;
	int err;

	alink = kzalloc(sizeof(*alink), GFP_KERNEL);
	if (!alink)
		return -ENOMEM;
	nn->app_priv = alink;
	alink->abm = abm;
	alink->vnic = nn;
	alink->id = id;

	/* This is a multi-host app, make sure MAC/PHY is up, but don't
	 * make the MAC/PHY state follow the state of any of the ports.
	 */
	err = nfp_eth_set_configured(app->cpp, eth_port->index, true);
	if (err < 0)
		goto err_free_alink;

	netif_keep_dst(nn->dp.netdev);

	nfp_abm_vnic_set_mac(app->pf, abm, nn, id);
	nfp_abm_ctrl_read_params(alink);

	return 0;

err_free_alink:
	kfree(alink);
	return err;
}

static void nfp_abm_vnic_free(struct nfp_app *app, struct nfp_net *nn)
{
	struct nfp_abm_link *alink = nn->app_priv;

	nfp_abm_kill_reprs(alink->abm, alink);
	kfree(alink);
}

static int nfp_abm_init(struct nfp_app *app)
{
	struct nfp_pf *pf = app->pf;
	struct nfp_reprs *reprs;
	struct nfp_abm *abm;
	int err;

	if (!pf->eth_tbl) {
		nfp_err(pf->cpp, "ABM NIC requires ETH table\n");
		return -EINVAL;
	}
	if (pf->max_data_vnics != pf->eth_tbl->count) {
		nfp_err(pf->cpp, "ETH entries don't match vNICs (%d vs %d)\n",
			pf->max_data_vnics, pf->eth_tbl->count);
		return -EINVAL;
	}
	if (!pf->mac_stats_bar) {
		nfp_warn(app->cpp, "ABM NIC requires mac_stats symbol\n");
		return -EINVAL;
	}

	abm = kzalloc(sizeof(*abm), GFP_KERNEL);
	if (!abm)
		return -ENOMEM;
	app->priv = abm;
	abm->app = app;

	err = nfp_abm_ctrl_find_addrs(abm);
	if (err)
		goto err_free_abm;

	/* We start in legacy mode, make sure advanced queuing is disabled */
	err = nfp_abm_ctrl_qm_disable(abm);
	if (err)
		goto err_free_abm;

	err = -ENOMEM;
	reprs = nfp_reprs_alloc(pf->max_data_vnics);
	if (!reprs)
		goto err_free_abm;
	RCU_INIT_POINTER(app->reprs[NFP_REPR_TYPE_PHYS_PORT], reprs);

	reprs = nfp_reprs_alloc(pf->max_data_vnics);
	if (!reprs)
		goto err_free_phys;
	RCU_INIT_POINTER(app->reprs[NFP_REPR_TYPE_PF], reprs);

	return 0;

err_free_phys:
	nfp_reprs_clean_and_free_by_type(app, NFP_REPR_TYPE_PHYS_PORT);
err_free_abm:
	kfree(abm);
	app->priv = NULL;
	return err;
}

static void nfp_abm_clean(struct nfp_app *app)
{
	struct nfp_abm *abm = app->priv;

	nfp_abm_eswitch_clean_up(abm);
	nfp_reprs_clean_and_free_by_type(app, NFP_REPR_TYPE_PF);
	nfp_reprs_clean_and_free_by_type(app, NFP_REPR_TYPE_PHYS_PORT);
	kfree(abm);
	app->priv = NULL;
}

const struct nfp_app_type app_abm = {
	.id		= NFP_APP_ACTIVE_BUFFER_MGMT_NIC,
	.name		= "abm",

	.init		= nfp_abm_init,
	.clean		= nfp_abm_clean,

	.vnic_alloc	= nfp_abm_vnic_alloc,
	.vnic_free	= nfp_abm_vnic_free,

	.setup_tc	= nfp_abm_setup_tc,

	.eswitch_mode_get	= nfp_abm_eswitch_mode_get,
	.eswitch_mode_set	= nfp_abm_eswitch_mode_set,

	.dev_get	= nfp_abm_repr_get,
};
