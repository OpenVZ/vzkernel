/*
 *  drivers/block/ploop/discard.h
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef _LINUX_PLOOP_DISCARD_H_
#define _LINUX_PLOOP_DISCARD_H_

extern int ploop_discard_init_ioc(struct ploop_device *plo);
extern int ploop_discard_fini_ioc(struct ploop_device *plo);
extern int ploop_discard_wait_ioc(struct ploop_device *plo);

#endif // _LINUX_PLOOP_DISCARD_H_
