/*
 * Copyright (C) 2015 Red Hat
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License v2. See the file COPYING in the main directory of this archive for
 * more details.
 */

#include <drm/drm_backport.h>

/*
 * shrinker
 */

#undef shrinker
#undef register_shrinker
#undef unregister_shrinker

static int shrinker2_shrink(struct shrinker *shrinker, struct shrink_control *sc)
{
	struct shrinker2 *s2 = container_of(shrinker, struct shrinker2, compat);
	int count;

	s2->scan_objects(s2, sc);
	count = s2->count_objects(s2, sc);
	shrinker->seeks = s2->seeks;

	return count;
}

void register_shrinker2(struct shrinker2 *s2)
{
	s2->compat.shrink = shrinker2_shrink;
	s2->compat.seeks = s2->seeks;
	register_shrinker(&s2->compat);
}
EXPORT_SYMBOL(register_shrinker2);

void unregister_shrinker2(struct shrinker2 *s2)
{
	unregister_shrinker(&s2->compat);
}
EXPORT_SYMBOL(unregister_shrinker2);

struct workqueue_struct *system_power_efficient_wq __read_mostly;
EXPORT_SYMBOL_GPL(system_power_efficient_wq);

int __init drm_backport_init(void)
{
	system_power_efficient_wq = create_workqueue("events_power_efficient");
	return 0;
}

void __exit drm_backport_exit(void)
{
	destroy_workqueue(system_power_efficient_wq);
}
