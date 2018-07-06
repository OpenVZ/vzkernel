/*
 * include/linux/idr_ext.h		IDR extended
 *
 * Copyright 2017 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __IDR_EXT_H__
#define __IDR_EXT_H__

#include <linux/idr.h>

struct idr_ext {
	struct idr	idr_lo;	/* Used for range <0, INT_MAX> */
	struct idr	idr_hi;	/* Used for range <INT_MAX+1, UINT_MAX> */
};

int idr_alloc_ext(struct idr_ext *idrext, void *ptr, unsigned long *index,
		  unsigned long start, unsigned long end, gfp_t gfp);

void *idr_get_next_ext(struct idr_ext *idrext, unsigned long *nextidp);

#define idr_for_each_entry_ext(idr, entry, id)			\
	for (id = 0; ((entry) = idr_get_next_ext(idr, &(id))) != NULL; ++id)

static inline
void idr_init_ext(struct idr_ext *idrext)
{
	idr_init(&idrext->idr_lo);
	idr_init(&idrext->idr_hi);
}

static inline
void idr_destroy_ext(struct idr_ext *idrext)
{
	idr_destroy(&idrext->idr_lo);
	idr_destroy(&idrext->idr_hi);
}

static inline
void idr_remove_ext(struct idr_ext *idrext, unsigned long id)
{
	if (id > UINT_MAX)
		return;

	if (id <= (unsigned long)INT_MAX)
		idr_remove(&idrext->idr_lo, (int)id);
	else
		idr_remove(&idrext->idr_hi, (int)(id - INT_MAX - 1));
}

static inline
void *idr_find_ext(struct idr_ext *idrext, unsigned long id)
{
	if (id > UINT_MAX)
		return NULL;

	if (id <= (unsigned long)INT_MAX)
		return idr_find(&idrext->idr_lo, (int)id);

	return idr_find(&idrext->idr_hi, (int)(id - INT_MAX - 1));
}

static inline
void *idr_replace_ext(struct idr_ext *idrext, void *ptr, unsigned long id)
{
	if (id > UINT_MAX)
		return NULL;

	if (id <= (unsigned long)INT_MAX)
		return idr_replace(&idrext->idr_lo, ptr, (int)id);

	return idr_replace(&idrext->idr_hi, ptr, (int)(id - INT_MAX - 1));
}

#endif /* __IDR_EXT_H__ */
