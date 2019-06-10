/*
 *  drivers/block/ploop/ploop_events.h
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#if !defined(_TRACE_PLOOP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_PLOOP_H

#undef TRACE_SYSTEM
#define TRACE_SYSTEM ploop

#include <linux/sched.h>
#include <linux/tracepoint.h>

#include <linux/ploop/ploop.h>
#include "events.h"

DEFINE_EVENT(preq_template, submit,
	TP_PROTO(struct ploop_request *preq),
	TP_ARGS(preq));

DEFINE_EVENT(preq_template, submit_alloc,
	TP_PROTO(struct ploop_request *preq),
	TP_ARGS(preq));

DEFINE_EVENT(preq_template, cached_submit,
	TP_PROTO(struct ploop_request *preq),
	TP_ARGS(preq));

DEFINE_EVENT(preq_template, complete_request,
	TP_PROTO(struct ploop_request *preq),
	TP_ARGS(preq));

DEFINE_EVENT(preq_template, req_state_process,
	TP_PROTO(struct ploop_request *preq),
	TP_ARGS(preq));

DEFINE_EVENT(preq_template, bio_queue,
	TP_PROTO(struct ploop_request *preq),
	TP_ARGS(preq));

DEFINE_EVENT(preq_template, add_lockout,
	TP_PROTO(struct ploop_request *preq),
	TP_ARGS(preq));

DEFINE_EVENT(preq_template, del_lockout,
	TP_PROTO(struct ploop_request *preq),
	TP_ARGS(preq));

TRACE_EVENT(preq_lockout,
	TP_PROTO(struct ploop_request *preq,
		struct ploop_request *ppreq),

	TP_ARGS(preq, ppreq),

	TP_STRUCT__entry(
		__field(void *,		ppreq)
		__field(void *,		preq)
		__field(cluster_t,	clu)
		__field(iblock_t,	iblk)
		__field(unsigned int,	size)
		__field(unsigned long,	eng_state)
		__field(unsigned long,	state)
		__field(unsigned int,	rw)
	),

	TP_fast_assign(
		__entry->preq		= preq;
		__entry->ppreq		= ppreq;
		__entry->clu		= preq->req_cluster;
		__entry->iblk		= preq->iblock;
		__entry->size		= preq->req_size;
		__entry->eng_state	= preq->eng_state;
		__entry->state		= preq->state;
		__entry->rw		= preq->req_rw;
	),

	TP_printk("ppreq=%p "PREQ_FORMAT, __entry->ppreq, PREQ_ARGS)
);

DEFINE_EVENT(bio_template, make_request,
	TP_PROTO(struct bio *bio),
	TP_ARGS(bio));

DEFINE_EVENT(bio_template, bio_fast_map,
	TP_PROTO(struct bio *bio),
	TP_ARGS(bio));

#endif /* _TRACE_PLOOP_H */

#undef TRACE_INCLUDE_PATH
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_PATH .

#define TRACE_INCLUDE_FILE ploop_events

/* This part must be outside protection */
#include <trace/define_trace.h>
