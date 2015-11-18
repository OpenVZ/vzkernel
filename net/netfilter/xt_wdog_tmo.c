/*
 *  net/netfilter/xt_wdog_tmo.c
 *
 *  Copyright (C) 2013, Parallels inc.
 *  All rights reserved.
 *
 */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/file.h>
#include <net/sock.h>
#include <linux/netfilter/x_tables.h>
#include <linux/fence-watchdog.h>

static bool
wdog_tmo_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	return fence_wdog_tmo_match();
}

int wdog_tmo_mt_check(const struct xt_mtchk_param *par)
{

	return ve_is_super(get_exec_env());
}

static struct xt_match wdog_tmo_mt_reg __read_mostly = {
		.name       = "wdog_tmo",
		.revision   = 0,
		.family     = NFPROTO_UNSPEC,
		.match      = wdog_tmo_mt,
		.checkentry = wdog_tmo_mt_check,
		.matchsize  = 0,
		.me         = THIS_MODULE,
};

static int __init wdog_tmo_mt_init(void)
{
	return xt_register_match(&wdog_tmo_mt_reg);
}

static void __exit wdog_tmo_mt_exit(void)
{
	xt_unregister_match(&wdog_tmo_mt_reg);
}

module_init(wdog_tmo_mt_init);
module_exit(wdog_tmo_mt_exit);
MODULE_AUTHOR("Dmitry Guryanov <dguryanov@parallels.com>");
MODULE_DESCRIPTION("Xtables: fence watchdog timeout matching");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_wdog_tmo");
MODULE_ALIAS("ip6t_wdog_tmo");
