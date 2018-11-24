
#include <net/sock.h>
#include <linux/net.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/highmem.h>

#include "pcs_types.h"
#include "pcs_sock_io.h"
#include "pcs_rpc.h"
#include "pcs_req.h"
#include "pcs_cluster.h"
#include "log.h"
#include "fuse_ktrace.h"

static void ireq_timer_handler(unsigned long arg)
{

	struct pcs_int_request *ireq = (struct pcs_int_request *)arg;
	pcs_cc_submit(ireq->cc, ireq);
}

static void __ireq_init(struct pcs_dentry_info *di, struct pcs_cluster_core *cc,
		 struct pcs_int_request *ireq)
{
	memset(ireq, 0, sizeof(*ireq));
	ireq->cc = cc;
	ireq->ts = ktime_get();
	ireq->create_ts = jiffies;
	setup_timer(&ireq->timer, ireq_timer_handler, (unsigned long)ireq);
	INIT_HLIST_HEAD(&ireq->completion_data.child_list);
	spin_lock_init(&ireq->completion_data.child_lock);
	INIT_LIST_HEAD(&ireq->list);
	ireq->dentry = di;
}

void ireq_init(struct pcs_dentry_info *di, struct pcs_int_request *ireq)
{
	__ireq_init(di, di->cluster, ireq);
}

void ireq_init_by_cluster(struct pcs_cluster_core *cc, struct pcs_int_request *ireq)
{
	__ireq_init(0, cc, ireq);
}

struct pcs_int_request *ireq_alloc(struct pcs_dentry_info *di)
{
	struct pcs_int_request *ireq;
	ireq =__ireq_alloc();
	if (!ireq)
		return NULL;

	__ireq_init(di, di->cluster, ireq);
	return ireq;
}

struct pcs_int_request *ireq_alloc_by_cluster(struct pcs_cluster_core *cc)
{
	struct pcs_int_request *ireq;
	ireq =__ireq_alloc();
	if (!ireq)
		return NULL;

	__ireq_init(NULL, cc, ireq);
	return ireq;
}

void ireq_delay(struct pcs_int_request *ireq)
{
	switch (ireq->error.value) {
	case PCS_ERR_NORES:
		if (!ireq->last_delay)
			ireq->last_delay = PCS_ERROR_DELAY;
		else if ((ireq->last_delay *= 2) > PCS_ERROR_DELAY_MAX)
			ireq->last_delay = PCS_ERROR_DELAY_MAX;
		break;
	default:
		ireq->last_delay = PCS_ERROR_DELAY;
	}
	mod_timer(&ireq->timer, jiffies + ireq->last_delay);
}

void ireq_handle_hole(struct pcs_int_request *ireq)
{
	unsigned int len;
	unsigned int offset;
	struct iov_iter it;
	pcs_api_iorequest_t * ar = ireq->completion_data.parent->apireq.req;

	BUG_ON(ireq->type != PCS_IREQ_IOCHUNK);
	BUG_ON(pcs_req_direction(ireq->iochunk.cmd));

	if (ireq->iochunk.cmd == PCS_REQ_T_FIEMAP) {
		ireq->completion_data.parent->apireq.aux = 0;
		ireq_complete(ireq);
		return;
	}

	len = ireq->iochunk.size;
	offset = 0;
	iov_iter_init_bad(&it);

	DTRACE("enter m: " MAP_FMT ", ireq:%p \n", MAP_ARGS(ireq->iochunk.map),	 ireq);

	while (len > 0) {
		void * map, *buf;
		size_t copy;

		if (!iov_iter_count(&it))
			ar->get_iter(ar->datasource, ireq->iochunk.dio_offset + offset, &it);

		map = iov_iter_kmap_atomic(&it, &buf, &copy);
		if (copy > len)
			copy = len;
		memset(buf, 0, copy);
		if (map)
			kunmap_atomic(map);
		len -= copy;
		offset += copy;
		iov_iter_advance(&it, copy);
	}

	ireq_complete(ireq);
}

noinline void pcs_ireq_queue_fail(struct list_head *queue, int error)
{
	while (!list_empty(queue)) {
		struct pcs_int_request *ireq = list_first_entry(queue, struct pcs_int_request, list);

		list_del_init(&ireq->list);

		pcs_set_local_error(&ireq->error, error);

		if (ireq->type == PCS_IREQ_TRUNCATE) {
			ireq_on_error(ireq);

			if (!(ireq->flags & IREQ_F_FATAL)) {
				pcs_clear_error(&ireq->error);

				FUSE_KTRACE(ireq->cc->fc, "requeue truncate(%d) %llu@" DENTRY_FMT "\n", ireq->type,
				      (unsigned long long)ireq->truncreq.offset, DENTRY_ARGS(ireq->dentry));

				ireq_delay(ireq);
				continue;
			}
		}
		ireq_complete(ireq);
	}
}
