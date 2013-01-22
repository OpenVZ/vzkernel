/*
 *  include/bc/vmpages.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __UB_PAGES_H_
#define __UB_PAGES_H_

#include <linux/linkage.h>
#include <linux/sched.h>	/* for get_exec_ub() */
#include <linux/mm.h>
#include <bc/beancounter.h>
#include <bc/decl.h>

extern int glob_ve_meminfo;

struct shmem_inode_info;

extern void __ub_update_oomguarpages(struct user_beancounter *ub);

static inline int ub_swap_full(struct user_beancounter *ub)
{
	return (ub->ub_parms[UB_SWAPPAGES].held * 2 >
			ub->ub_parms[UB_SWAPPAGES].limit);
}

void __show_ub_mem(struct user_beancounter *ub);
void show_ub_mem(struct user_beancounter *ub);

#endif /* __UB_PAGES_H_ */
