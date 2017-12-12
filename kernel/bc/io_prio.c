/*
 *  kernel/bc/io_prio.c
 *
 *  Copyright (C) 2010  Parallels, inc.
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.Parallels" file.
 *
 */

#include <linux/module.h>
#include <linux/cgroup.h>
#include <bc/beancounter.h>
#include <bc/proc.h>


int ub_set_ioprio(int id, int ioprio)
{
	struct user_beancounter *ub;
	int ret;

	ret = -ERANGE;
	if (ioprio < UB_IOPRIO_MIN || ioprio >= UB_IOPRIO_MAX)
		goto out;

	ret = -ESRCH;
	ub = get_beancounter_byuid(id, 0);
	if (!ub)
		goto out;

	put_beancounter(ub);
out:
	return ret;
}
