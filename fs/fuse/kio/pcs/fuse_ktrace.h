#ifndef _FUSE_KTRACE_H_
#define _FUSE_KTRACE_H_ 1

#include "fuse_ktrace_prot.h"
#include <linux/relay.h>

#ifdef CONFIG_FUSE_KIO_DEBUG
#define DEBUGFS_TRACE 1
#else
#define DEBUGFS_TRACE 0
#endif /* CONFIG_FUSE_KIO_DEBUG */

#define KTRACE_LOG_BUF_SIZE	256

struct fuse_ktrace
{
	atomic_t				refcnt;
	struct rchan				*rchan;
	struct dentry				*dir;
	unsigned long __percpu			*ovfl;
	struct dentry				*prometheus_dentry;
	struct kfuse_histogram * __percpu	*prometheus_hist;
	u8 * __percpu				buf;
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

void __kfuse_trace(struct fuse_conn * fc, unsigned long ip, const char * fmt, ...);

#define FUSE_KTRACE(fc, fmt, args...) do { struct fuse_conn * __fc = (fc); if (__fc->ktrace_level >= LOG_TRACE) __kfuse_trace(__fc, _THIS_IP_, "%s: " fmt, __FUNCTION__, ## args); } while (0)
#define FUSE_KDTRACE(fc, fmt, args...) do { struct fuse_conn * __fc = (fc); if (__fc->ktrace_level >= LOG_DTRACE) __kfuse_trace(__fc, _THIS_IP_, "%s: " fmt, __FUNCTION__, ## args); } while (0)
#define FUSE_KLOG(fc, level, fmt, args...) do { struct fuse_conn * __fc = (fc); if (__fc->ktrace_level >= (level)) __kfuse_trace(__fc, 0, "%s: " fmt, __FUNCTION__, ## args); } while (0)

#endif /* _FUSE_KTRACE_H_ */
