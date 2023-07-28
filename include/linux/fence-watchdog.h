/*
 *  include/linux/fence-watchdog.h
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef _LINUX_FENCE_WATCHDOG_H_
#define _LINUX_FENCE_WATCHDOG_H_

inline int fence_wdog_check_timer(void);
bool fence_wdog_tmo_match(void);

#endif
