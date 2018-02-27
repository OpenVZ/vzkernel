#ifndef _FUSE_KTRACE_H_
#define _FUSE_KTRACE_H_ 1

#include "fuse_ktrace_prot.h"
#include <linux/relay.h>

struct fuse_ktrace
{
	atomic_t				refcnt;
	struct rchan				*rchan;
	struct dentry				*dir;
	unsigned long __percpu			*ovfl;
	struct dentry				*prometheus_dentry;
	struct kfuse_histogram * __percpu	*prometheus_hist;
};

static inline void * fuse_trace_prepare(struct fuse_ktrace * tr, int type, int len)
{
	struct fuse_trace_hdr * t;
	unsigned long * ovfl;

	preempt_disable();
	ovfl = per_cpu_ptr(tr->ovfl, smp_processor_id());

	t = relay_reserve(tr->rchan, sizeof(*t) + len);
	if (t) {
		t->magic = FUSE_TRACE_MAGIC;
		t->type = type;
		t->pdu_len = len;
		if ((t->ovfl = *ovfl) != 0)
			*ovfl = 0;
		t->time = ktime_to_ns(ktime_get()) / 1000;

		return t;
	} else {
		if (++(*ovfl) == 0)
			*ovfl = 65535;
		return NULL;
	}
}

#define FUSE_TRACE_PREPARE(tr, type, len) fuse_trace_prepare((tr), (type), (len))
#define FUSE_TRACE_COMMIT(tr)       preempt_enable()

#endif /* _FUSE_KTRACE_H_ */
