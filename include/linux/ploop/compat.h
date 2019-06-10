/*
 *  include/linux/ploop/compat.h
 *
 *  This file contained macros to provide compatibility layer for 2.6.18,
 *  where bio layer was different.
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef _LINUX_PLOOP_COMPAT_H_
#define _LINUX_PLOOP_COMPAT_H_

#include <linux/version.h>

#define DEFINE_BIO_CB(func) \
static void func(struct bio *bio, int err) {

#define END_BIO_CB(func)  }

#define BIO_ENDIO(_queue, _bio, _err)					\
	do {								\
		trace_block_bio_complete((_queue), (_bio), (_err));	\
		bio_endio((_bio), (_err));				\
	} while (0);

#define F_DENTRY(file)	(file)->f_path.dentry
#define F_MNT(file)	(file)->f_path.mnt

#define KOBJECT_INIT(kobj, ktype) kobject_init(kobj, ktype)
#define KOBJECT_ADD(kobj, parent, fmt, arg...) kobject_add(kobj, parent, fmt, arg)

#endif
