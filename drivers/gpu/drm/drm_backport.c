/*
 * Copyright (C) 2015 Red Hat
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License v2. See the file COPYING in the main directory of this archive for
 * more details.
 */

#include <drm/drm_backport.h>

struct workqueue_struct *system_power_efficient_wq __read_mostly;
EXPORT_SYMBOL_GPL(system_power_efficient_wq);

int __init drm_backport_init(void)
{
	system_power_efficient_wq = create_workqueue("events_power_efficient");
	return 0;
}

void __exit drm_backport_exit(void)
{
	destroy_workqueue(system_power_efficient_wq);
}
