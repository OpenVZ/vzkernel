/*
 *  kernel/ve/dummy/ip6_vzprivnet.c
 *
 *  Copyright (c) 2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>

int __init dummy_init(void)
{
	return 0;
}

void __exit dummy_exit(void)
{
}

module_init(dummy_init);
module_exit(dummy_exit);
MODULE_LICENSE("GPL v2");
