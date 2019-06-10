/*
 *  drivers/block/ploop/io_direct_events.h
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#if !defined(_TRACE_IO_DIRECT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_IO_DIRECT_H

#undef TRACE_SYSTEM
#define TRACE_SYSTEM ploop

#include <linux/sched.h>
#include <linux/tracepoint.h>

#include <linux/ploop/ploop.h>
#include "io_direct_map.h"

TRACE_EVENT(add_extent_mapping,
	TP_PROTO(struct extent_map *em),

	TP_ARGS(em),

	TP_STRUCT__entry(
		__field(sector_t,  start)
		__field(sector_t,  end)
		__field(sector_t,  bstart)
	),

	TP_fast_assign(
		__entry->start	= em->start;
		__entry->end	= em->end;
		__entry->bstart	= em->block_start;
	),

	TP_printk("start=0x%lx end=0x%lx block_start=0x%lx",
			__entry->start, __entry->end, __entry->bstart)
);

#endif /* _TRACE_PLOOP_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE io_direct_events

/* This part must be outside protection */
#include <trace/define_trace.h>
