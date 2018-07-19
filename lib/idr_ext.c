/*
 * lib/idr_ext.c		IDR extended
 *
 * Copyright 2017 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/*
 * An extension to IDR that allows to store u32 indices used by flower and
 * net-sched actions.
 * The current IDR implementation supports ID from range <0, INT_MAX> and
 * unfortunately classifiers and actions use u32's <0, UINT_MAX>. The IDR
 * in upstream was extended by commit 388f79fda74f ("idr: Add new APIs to
 * support unsigned long") that is not backportable currently because IDR
 * in upstream is based on radix-tree and RHEL uses an older implementation.
 * To backport this commit the IDR needs to be rebased and this is out of
 * scope of this series.
 * Instead of this this extension that uses two IDR ranges for requested
 * range has been created. The 1st is for <0, INT_MAX> and the 2nd is for
 * <INT_MAX+1, UINT_MAX>.
 *
 * Differences between this extension and upstream:
 *
 * - The API in RHEL uses 'struct idr_ext' instead of 'struct idr'
 * - To initialize and destroy idr_init_ext() and idr_destroy_ext() are
 *   used instead of idr_init() and idr_destroy()
 * - RHEL support only range <0, UINT_MAX> that is enough for net-sched
 *
 * The rest of API introduced by 388f79fda74f should be identical.
 */

#include <linux/idr_ext.h>

int idr_alloc_ext(struct idr_ext *idrext, void *ptr, unsigned long *index,
		  unsigned long start, unsigned long end, gfp_t gfp)
{
	struct idr *block = NULL;
	int ret;

	if (!end || end > UINT_MAX)
		end = UINT_MAX + 1UL;

	if (unlikely(start >= end))
		return -ENOSPC;

	/* Both endpoints map to low block */
	if (end <= (unsigned long)INT_MAX + 1)
		block = &idrext->idr_lo;

	/* Both endpoints map to high block */
	if (start >= (unsigned long)INT_MAX + 1) {
		block = &idrext->idr_hi;
		start -= (unsigned long)INT_MAX + 1;
		end -= (unsigned long)INT_MAX + 1;
	}

	/* In the two cases above, just map and fail if idr_alloc() fails */
	if (block) {
		ret = idr_alloc(block, ptr, (int)start,
				(int)(end > INT_MAX ? 0 : end), gfp);
		goto done;
	}

	/* If range spans over both blocks instead: try to map to low block */
	block = &idrext->idr_lo;
	ret = idr_alloc(block, ptr, (int)start, 0, gfp);
	if (ret != -ENOSPC)
		goto done;

	/* ...and if there's no space there, move to high block */
	end -= (unsigned long)INT_MAX + 1;
	block = &idrext->idr_hi;
	ret = idr_alloc(block, ptr, 0, (int)(end > INT_MAX ? 0 : end), gfp);

done:
	if (unlikely(ret < 0))
		return ret;

	if (index) {
		if (block == &idrext->idr_lo)
			*index = (unsigned long)ret;
		else
			*index = (unsigned long)ret + INT_MAX + 1;
	}

	return 0;
}
EXPORT_SYMBOL(idr_alloc_ext);

void *idr_get_next_ext(struct idr_ext *idrext, unsigned long *nextidp)
{
	void *ptr;
	int idp;

	if (*nextidp > UINT_MAX)
		return NULL;

	if (*nextidp <= INT_MAX) {
		idp = (int)*nextidp;
		ptr = idr_get_next(&idrext->idr_lo, &idp);
		if (ptr) {
			*nextidp = (unsigned long)idp;
			return ptr;
		}
		/* Not found - continue with higher range */
		idp = 0;
	} else {
		/* Subtract higher range offset */
		idp = (int)(*nextidp - INT_MAX - 1);
	}

	ptr = idr_get_next(&idrext->idr_hi, &idp);
	if (ptr) {
		/* Add higher range offset */
		*nextidp = (unsigned long)idp + INT_MAX + 1;
		return ptr;
	}

	return NULL;
}
EXPORT_SYMBOL(idr_get_next_ext);
