#ifndef _LINUX_FENCE_WATCHDOG_H_
#define _LINUX_FENCE_WATCHDOG_H_

inline int fence_wdog_check_timer(void);
bool fence_wdog_tmo_match(void);

#endif
