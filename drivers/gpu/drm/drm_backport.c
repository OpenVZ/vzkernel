/*
 * Copyright (C) 2015 Red Hat
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License v2. See the file COPYING in the main directory of this archive for
 * more details.
 */

#include <drm/drm_backport.h>
#include <drm/drmP.h>
#include <linux/slab.h>

#if IS_ENABLED(CONFIG_SWIOTLB)
#  include <linux/dma-direction.h>
#  include <linux/swiotlb.h>
#endif

unsigned int swiotlb_max_size(void)
{
#if IS_ENABLED(CONFIG_SWIOTLB)
	return rounddown(swiotlb_nr_tbl() << IO_TLB_SHIFT, PAGE_SIZE);
#else
	return 0;
#endif
}
EXPORT_SYMBOL(swiotlb_max_size);

int __init drm_backport_init(void)
{
	return 0;
}

void __exit drm_backport_exit(void)
{
}
