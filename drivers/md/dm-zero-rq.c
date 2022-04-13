/*
 * Copyright (C) 2003 Jana Saout <jana@saout.de>
 *
 * This file is released under the GPL.
 */

#include <linux/device-mapper.h>

#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/blk-mq.h>
#include "dm-rq.h"

#define DM_MSG_PREFIX "zero"

/*
 * Construct a dummy mapping that only returns zeros
 */
static int zero_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	if (argc != 0) {
		ti->error = "No arguments required";
		return -EINVAL;
	}

	/*
	 * Silently drop discards, avoiding -EOPNOTSUPP.
	 */
	ti->num_discard_bios = 1;

	return 0;
}

static int zero_clone_and_map_rq(struct dm_target *ti, struct request *rq,
				 union map_info *map_context,
				 struct request **clone)
{
	struct bio *bio = rq->bio;

	switch (bio_op(bio)) {
	case REQ_OP_READ:
		while (bio) {
			zero_fill_bio(bio);
			bio = bio->bi_next;
		}

		break;
	case REQ_OP_WRITE:
		/* writes get silently dropped */
		break;
	default:
		return DM_MAPIO_KILL;
	}

	dm_complete_request(rq, BLK_STS_OK);

	/* accepted rq, don't make new request */
	return DM_MAPIO_SUBMITTED;
}

static struct target_type zero_target = {
	.name   = "zero-rq",
	.version = {1, 1, 0},
	.features = DM_TARGET_NOWAIT,
	.module = THIS_MODULE,
	.ctr    = zero_ctr,
	.clone_and_map_rq = zero_clone_and_map_rq,
};

static int __init dm_zero_init(void)
{
	int r = dm_register_target(&zero_target);

	if (r < 0)
		DMERR("register failed %d", r);

	return r;
}

static void __exit dm_zero_exit(void)
{
	dm_unregister_target(&zero_target);
}

module_init(dm_zero_init)
module_exit(dm_zero_exit)

MODULE_AUTHOR("Jana Saout <jana@saout.de>");
MODULE_DESCRIPTION(DM_NAME " dummy request based target returning zeros");
MODULE_LICENSE("GPL");
