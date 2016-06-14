/*
 *  drivers/block/ploop/ploop_events.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/module.h>
#include <linux/interrupt.h>

#define CREATE_TRACE_POINTS
#include "ploop_events.h"

EXPORT_TRACEPOINT_SYMBOL(submit);
EXPORT_TRACEPOINT_SYMBOL(submit_alloc);
EXPORT_TRACEPOINT_SYMBOL(cached_submit);
