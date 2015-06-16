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

static unsigned int ioprio_weight[UB_IOPRIO_MAX] = {
	320, 365, 410, 460, 500, 550, 600, 640,
};

extern int blkcg_set_weight(struct cgroup *cgrp, unsigned int weight);

int ub_set_ioprio(int id, int ioprio)
{
	struct user_beancounter *ub;
	struct cgroup_subsys_state *css;
	int ret;

	ret = -ERANGE;
	if (ioprio < UB_IOPRIO_MIN || ioprio >= UB_IOPRIO_MAX)
		goto out;

	ret = -ESRCH;
	ub = get_beancounter_byuid(id, 0);
	if (!ub)
		goto out;

	css = ub_get_blkio_css(ub);
	ret = blkcg_set_weight(css->cgroup, ioprio_weight[ioprio]);
	css_put(css);
	put_beancounter(ub);
out:
	return ret;
}
