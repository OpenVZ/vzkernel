#include <linux/types.h>
#include <linux/file.h>
#include <linux/rbtree.h>
#include <linux/highmem.h>
#include <linux/log2.h>
#include <linux/module.h>
#include <linux/anon_inodes.h>
#include <linux/pagemap.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>

#include "pcs_types.h"
#include "pcs_sock_io.h"
#include "pcs_rpc.h"
#include "pcs_sock_io.h"
#include "pcs_req.h"
#include "pcs_map.h"
#include "pcs_cs.h"
#include "pcs_ioctl.h"
#include "pcs_cluster.h"
#include "log.h"
#include "fuse_ktrace.h"

/* CSA context can be referenced from two places:
 *  * csaccel file struct as filp->private_data
 *    This reference is dropped at csaccel file close
 *  * struct cs as cs->csa_ctx
 *    This reference is dropped at unmount
 *
 * CSA entries can be referenced only from radix tree at corresponding CSA.
 * No reference counting is done, releases are done through RCU cycle.
 *
 * Tricky part which could be done nice. ctx->cs is protected with cs->lock and rcu.
 * So we dereference ctx->cs, lock cs and check that it is still the same afterwards.
 */

struct kmem_cache *pcs_csa_cachep;

struct pcs_csa_context
{
	struct rcu_work		rwork;
	struct pcs_cs		*cs;  /* The reference accounted in cs->nmaps */
	atomic_t		refcnt;
	int			dead;
	spinlock_t		lock;
	wait_queue_head_t	wqh;
	struct radix_tree_root  tree; /* GFP_ATOMIC */
	struct crypto_sync_skcipher * tfm;
};

struct pcs_csa_entry
{
	struct rcu_head		rcu;
	PCS_CHUNK_UID_T		chunk_id;
	PCS_MAP_VERSION_T	version;
	unsigned int		flags;
	int			dead;
	struct file		*file;
	struct file		*cfile;
};

/* Interestingly, fput is irq-safe. So, we can close files from rcu callback*/

static inline void __cse_destroy(struct pcs_csa_entry * cse)
{
	if (cse->file) {
		fput(cse->file);
		cse->file = NULL;
	}
	if (cse->cfile) {
		fput(cse->cfile);
		cse->cfile = NULL;
	}
	kmem_cache_free(pcs_csa_cachep, cse);
}

static void cse_destroy_rcu(struct rcu_head *head)
{
	struct pcs_csa_entry * cse = container_of(head, struct pcs_csa_entry, rcu);
	__cse_destroy(cse);
}

static void csa_clear_tree(struct pcs_csa_context *ctx)
{
#define BATCH_SIZE 16
	struct pcs_csa_entry *cse_buf[BATCH_SIZE];
	int nr;
	u64 pos = 0;

	do {
		int i;

		spin_lock(&ctx->lock);
		nr = radix_tree_gang_lookup(&ctx->tree, (void **)cse_buf, pos, BATCH_SIZE);

		for (i = 0; i < nr; i++) {
			struct pcs_csa_entry * cse = cse_buf[i];
			pos = cse->chunk_id;
			radix_tree_delete(&ctx->tree, cse->chunk_id);
			call_rcu(&cse->rcu, cse_destroy_rcu);
		}
		spin_unlock(&ctx->lock);
		pos++;
	} while (nr);
}

static void csa_destroy_rcu(struct work_struct *work)
{
	struct pcs_csa_context * ctx = container_of(to_rcu_work(work), struct pcs_csa_context, rwork);
	BUG_ON(!ctx->dead);
	csa_clear_tree(ctx);
	if (ctx->tfm)
		crypto_free_sync_skcipher(ctx->tfm);
	kfree(ctx);
}

static inline void pcs_csa_put(struct pcs_csa_context * ctx)
{
	if (atomic_dec_and_test(&ctx->refcnt)) {
		INIT_RCU_WORK(&ctx->rwork, csa_destroy_rcu);
		if (!queue_rcu_work(pcs_cleanup_wq, &ctx->rwork))
			BUG();
	}
}

static inline void __pcs_csa_put(struct pcs_csa_context * ctx)
{
	if (atomic_dec_and_test(&ctx->refcnt))
		BUG();
}

void pcs_csa_cs_detach(struct pcs_cs * cs)
{
	struct pcs_csa_context * csa_ctx;

	assert_spin_locked(&cs->lock);

	if ((csa_ctx = cs->csa_ctx) != NULL) {
		csa_ctx->cs = NULL;
		cs->nmaps--;
		cs->csa_ctx = NULL;
		csa_ctx->dead = 1;
		wake_up_poll(&csa_ctx->wqh, EPOLLHUP);
		pcs_csa_put(csa_ctx);
	}
}

static inline struct pcs_csa_entry * __cse_lookup(struct pcs_csa_context * ctx, u64 chunk_id)
{
	return radix_tree_lookup(&ctx->tree, chunk_id);
}

static int csa_update(struct pcs_csa_context * ctx, PCS_CHUNK_UID_T chunk_id, u32 flags, PCS_MAP_VERSION_T * vers,
		      struct file * file, struct file * cfile)
{
	struct pcs_csa_entry * csa, * csb;

	if (file == NULL) {
		spin_lock(&ctx->lock);
		csa = radix_tree_lookup(&ctx->tree, chunk_id);
		if (csa) {
			void * ret;
			ret = radix_tree_delete(&ctx->tree, chunk_id);
			BUG_ON(!ret || ret != csa);
			csa->dead = 1;
			call_rcu(&csa->rcu, cse_destroy_rcu);
		}
		spin_unlock(&ctx->lock);
		return 0;
	}

	if ((flags & PCS_CSA_FL_CSUM) && !crc_tfm)
		return -EOPNOTSUPP;

	csb = kmem_cache_zalloc(pcs_csa_cachep, GFP_NOIO);
	if (!csb)
		return -ENOMEM;

	csb->chunk_id = chunk_id;
	csb->version = *vers;
	csb->flags = flags;
	csb->file = file;
	get_file(file);
	if (cfile) {
		csb->cfile = cfile;
		get_file(cfile);
	}

again:
	if (radix_tree_preload(GFP_NOIO)) {
		__cse_destroy(csb);
		return -ENOMEM;
	}

	spin_lock(&ctx->lock);
	/* This is wrong to delete entry before insert. rcu lookup will see
	 * the gap. Not disasterous for us but dirty yet.
	 * But I do not see appropriate function in lib/radix-tree.c
	 */
	csa = radix_tree_lookup(&ctx->tree, chunk_id);
	if (csa) {
		void *ret;

		ret = radix_tree_delete(&ctx->tree, chunk_id);
		BUG_ON(!ret || ret != csa);
		csa->dead = 1;
		call_rcu(&csa->rcu, cse_destroy_rcu);
	}

	if (ctx->dead) {
		spin_unlock(&ctx->lock);
		radix_tree_preload_end();
		__cse_destroy(csb);
		return -ESTALE;
	}

	if (radix_tree_insert(&ctx->tree, chunk_id, csb)) {
		spin_unlock(&ctx->lock);
		radix_tree_preload_end();
		goto again;
	}
	spin_unlock(&ctx->lock);
	radix_tree_preload_end();

	return 0;
}

static int verify_crc(struct pcs_int_request * ireq, u32 * crc)
{
	struct iov_iter * it = &ireq->iochunk.ar.iter;
	unsigned int size = ireq->iochunk.size;
	char crc_desc[sizeof(struct shash_desc) + 4] __aligned(__alignof__(struct shash_desc));
	struct shash_desc *shash = (struct shash_desc *)crc_desc;
	int i;

	shash->tfm = crc_tfm;

	iov_iter_revert(it, size);

	for (i = 0; i < size/4096; i++) {
		unsigned int left = 4096;
		u32 ccrc;

		*(u32*)shash->__ctx = ~0U;

		do {
			size_t offset;
			int len;
			struct page * page;

			len = iov_iter_get_pages(it, &page, left, 1, &offset);
			BUG_ON(len <= 0);

			crypto_shash_alg(crc_tfm)->update(shash, kmap(page) + offset, len);
			kunmap(page);
			put_page(page);
			iov_iter_advance(it, len);
			left -= len;
		} while (left > 0);

		crypto_shash_alg(crc_tfm)->final(shash, (u8*)&ccrc);

		if (ccrc != crc[i]) {
			FUSE_KTRACE(ireq->cc->fc, "CRC error pg=%d@%u %08x %08x\n", i,
				    (unsigned)ireq->iochunk.offset, ccrc, crc[i]);
			return 1;
		}
	}
	return 0;
}

static int check_zero(struct page * page, unsigned int offset)
{
	u64 * addr = kmap(page) + offset;

        if (likely(addr[0] || memcmp(addr, addr + 1, 512 - 8))) {
		kunmap(page);
                return 0;
	}
	kunmap(page);
	return 1;
}

static int decrypt_data(struct pcs_int_request * ireq,  struct crypto_sync_skcipher * tfm)
{
	struct iov_iter * it = &ireq->iochunk.ar.iter;
	unsigned int size = ireq->iochunk.size;
	struct scatterlist sg;
	unsigned int pos;
	struct { u64 a, b; } iv;
	int iv_valid = 0;
	u64 hi = ireq->iochunk.map->id;
	/* XXX. Figure out how to distingush xts/ctr quickly and correctly */
	int is_ctr = (tfm->base.base.__crt_alg->cra_priority == 400);
	SYNC_SKCIPHER_REQUEST_ON_STACK(req, tfm);

	iov_iter_revert(it, size);

	skcipher_request_set_sync_tfm(req, tfm);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP, NULL, NULL);
	sg_init_table(&sg, 1);

	pos = 0;
	while (pos < size) {
		size_t offset;
		int len;
		struct page * page;

		len = iov_iter_get_pages(it, &page, size - pos, 1, &offset);
		BUG_ON(len <= 0);
		BUG_ON(len & 511);
		iov_iter_advance(it, len);

		if (is_ctr) {
			for (; len > 0; len -= 512) {
				if (likely(!check_zero(page, offset))) {
					if (unlikely(!iv_valid)) {
						iv.a = hi;
						iv.b = cpu_to_be64((ireq->iochunk.offset + pos) / 16);
						iv_valid = 1;
						sg_set_page(&sg, page, 512, offset);
						skcipher_request_set_crypt(req, &sg, &sg, 512, &iv);
					} else {
						sg.length += 512;
						req->cryptlen += 512;
					}
				} else {
					if (iv_valid) {
						crypto_skcipher_alg(crypto_skcipher_reqtfm(req))->decrypt(req);
						iv_valid = 0;
					}
				}
				pos += 512;
				offset += 512;
			}
			if (iv_valid) {
				crypto_skcipher_alg(crypto_skcipher_reqtfm(req))->decrypt(req);
				iv_valid = 0;
			}
		} else {
			sg_set_page(&sg, page, 512, offset);
			skcipher_request_set_crypt(req, &sg, &sg, 512, &iv);
			for (; len > 0; len -= 512) {
				if (likely(!check_zero(page, offset))) {
					iv.a = (ireq->iochunk.offset + pos) / 512;
					iv.b = hi;
					crypto_skcipher_alg(crypto_skcipher_reqtfm(req))->decrypt(req);
				}
				pos += 512;
				offset += 512;
				sg.offset += 512;
			}
		}
		put_page(page);
	}
	return 0;
}

static void __pcs_csa_final_completion(struct pcs_aio_req *areq)
{
	struct pcs_int_request * ireq;

	fput(areq->iocb.ki_filp);

	ireq = container_of(areq, struct pcs_int_request, iochunk.ar);

	if (!pcs_if_error(&ireq->error) && (ireq->flags & IREQ_F_CRYPT)) {
		struct pcs_cs * cs = ireq->iochunk.csl->cs[ireq->iochunk.cs_index].cslink.cs;
		struct pcs_csa_context * ctx;
		rcu_read_lock();
		ctx = rcu_dereference(cs->csa_ctx);
		if (!ctx || !ctx->tfm || decrypt_data(ireq, ctx->tfm))
			pcs_set_error_cond_atomic(&ireq->error, PCS_ERR_IO, 1, ireq->iochunk.csl->cs[ireq->iochunk.cs_index].info.id);
		rcu_read_unlock();
	}

	if (areq->crc) {
		if (!pcs_if_error(&ireq->error)) {
			if (verify_crc(ireq, areq->crc))
				pcs_set_error_cond_atomic(&ireq->error, PCS_ERR_IO, 1, ireq->iochunk.csl->cs[ireq->iochunk.cs_index].info.id);
		}

		if (areq->crc && areq->crc != areq->crcb) {
			kfree(areq->crc);
			areq->crc = NULL;
		}
	}

	if (!pcs_if_error(&ireq->error)) {
		struct fuse_conn * fc = ireq->cc->fc;

		fuse_stat_observe(fc, PCS_REQ_T_READ, ktime_sub(ktime_get(), ireq->ts_sent));
		if (fc->ktrace && fc->ktrace_level >= LOG_TRACE) {
			struct fuse_trace_hdr * t;

			t = FUSE_TRACE_PREPARE(fc->ktrace, FUSE_KTRACE_IOTIMES, sizeof(struct fuse_tr_iotimes_hdr) +
					       sizeof(struct fuse_tr_iotimes_cs));
			if (t) {
				struct fuse_tr_iotimes_hdr * th = (struct fuse_tr_iotimes_hdr *)(t + 1);
				struct fuse_tr_iotimes_cs * ch = (struct fuse_tr_iotimes_cs *)(th + 1);

				th->chunk = ireq->iochunk.chunk;
				th->offset = ireq->iochunk.chunk + ireq->iochunk.offset;
				th->size = ireq->iochunk.size;
				th->start_time = ktime_to_us(ireq->ts);
				th->local_delay = ktime_to_us(ktime_sub(ireq->ts_sent, ireq->ts));
				th->lat = t->time - ktime_to_us(ireq->ts_sent);
				th->ino = ireq->dentry->fileinfo.attr.id;
				th->type = PCS_CS_READ_RESP;
				th->cses = 1;
				th->__pad = 0;
				th->chid = (unsigned int)ireq->iochunk.map->id;

				ch->csid = ireq->iochunk.csl->cs[ireq->iochunk.cs_index].info.id.val | PCS_NODE_ALT_MASK;
				ch->misc = ktime_to_us(ireq->ts_sent);
				ch->ts_net = 0;
				ch->ts_io = th->lat;
			}
			FUSE_TRACE_COMMIT(fc->ktrace);
		}
	} else {
		FUSE_KTRACE(ireq->cc->fc, "AIO error %d %lu, ireq:%p : %llu:%u+%u",
		      ireq->error.value,
		      ireq->error.remote ? (unsigned long)ireq->error.offender.val : 0UL,
		      ireq, (unsigned long long)ireq->iochunk.chunk,
		      (unsigned)ireq->iochunk.offset,
		      (unsigned)ireq->iochunk.size);
		/* Prepare ireq for restart in slow path */
		ireq->flags |= IREQ_F_NO_ACCEL|IREQ_F_ACCELERROR;
		ireq->flags &= ~IREQ_F_ONCE;
		ireq->iochunk.msg.destructor = NULL;
		ireq->iochunk.msg.rpc = NULL;
	}

	ireq_complete(ireq);
}

static void pcs_csa_do_completion(struct pcs_aio_req *areq)
{
	if (atomic_dec_and_test(&areq->iocount))
		__pcs_csa_final_completion(areq);
}

static inline int quick_crc_fetch(struct pcs_int_request * ireq, struct file * cfile)
{
	unsigned offset = (ireq->iochunk.offset / 4096) * 4;
	unsigned sz = (ireq->iochunk.size / 4096) * 4;
	pgoff_t idx = offset / PAGE_SIZE;
	struct page * page;

	if (idx != ((offset + sz - 1) / PAGE_SIZE) || sz > sizeof(ireq->iochunk.ar.crcb))
		return 0;

	page = find_get_page(cfile->f_mapping, idx);
	if (!page)
		return 0;

	memcpy(ireq->iochunk.ar.crcb, kmap(page) + (offset & (PAGE_SIZE-1)), sz);
	ireq->iochunk.ar.crc = ireq->iochunk.ar.crcb;
	kunmap(page);
	put_page(page);
	return 1;
}

static void csa_crc_work(struct work_struct *w)
{
	struct pcs_aio_req * areq = container_of(w, struct pcs_aio_req, work);
	struct pcs_int_request * ireq = container_of(areq, struct pcs_int_request, iochunk.ar);
	int ncrc = (ireq->iochunk.size / 4096) * 4;
	ssize_t sz;
	loff_t pos;

	if (ncrc <= PCS_MAX_INLINE_CRC*4)
		areq->crc = areq->crcb;
	else {
		areq->crc = kmalloc(ncrc, GFP_KERNEL);
		if (areq->crc == NULL) {
out:
			pcs_set_error_cond_atomic(&ireq->error, PCS_ERR_NORES, 1, ireq->iochunk.csl->cs[ireq->iochunk.cs_index].info.id);
			fput(areq->cfile);
			if (areq->crc && areq->crc != areq->crcb) {
				kfree(areq->crc);
				areq->crc = NULL;
			}
			pcs_csa_do_completion(areq);
			return;
		}
	}

	pos = (ireq->iochunk.offset / 4096) * 4;
	sz = kernel_read(areq->cfile, areq->crc, ncrc, &pos);
	if (sz != ncrc) {
		FUSE_KTRACE(ireq->cc->fc, "Did not read crc res=%u expected=%u", (unsigned)sz, (unsigned)ncrc);
		goto out;
	}
	fput(areq->cfile);
	areq->cfile = NULL;
	pcs_csa_do_completion(areq);
}

static void csa_complete_work(struct work_struct *w)
{
	struct pcs_aio_req * areq = container_of(w, struct pcs_aio_req, work);

	__pcs_csa_final_completion(areq);
}

static void pcs_csa_complete(struct kiocb *iocb, long ret)
{
	struct pcs_aio_req * areq;
	struct pcs_int_request * ireq;

	areq = container_of(iocb, struct pcs_aio_req, iocb);
	ireq = container_of(areq, struct pcs_int_request, iochunk.ar);

	if (ret != ireq->iochunk.size)
		pcs_set_error_cond_atomic(&ireq->error, PCS_ERR_IO, 1, ireq->iochunk.csl->cs[ireq->iochunk.cs_index].info.id);

	if (atomic_dec_and_test(&areq->iocount)) {
		INIT_WORK(&areq->work, csa_complete_work);
		queue_work(ireq->cc->wq, &areq->work);
	}
}

static inline int csa_submit(struct file * file, struct file *cfile, int do_csum, struct pcs_int_request * ireq)
{
	struct pcs_aio_req * areq =  &ireq->iochunk.ar;
	struct kiocb * iocb = &areq->iocb;
	struct iov_iter * it = &areq->iter;
	struct pcs_int_request *parent = ireq->completion_data.parent;
	unsigned int size = ireq->iochunk.size;
	pcs_api_iorequest_t *ar;
	int ret;

	areq->cfile = NULL;
	areq->crc = NULL;

	if (do_csum) {
		if (cfile == NULL)
			return -EINVAL;

		if ((size|ireq->iochunk.offset) & 4095)
			return -EINVAL;

		quick_crc_fetch(ireq, cfile);
	}

	BUG_ON(parent->type != PCS_IREQ_API);
	ar = parent->apireq.req;

	ar->get_iter(ar->datasource, ireq->iochunk.dio_offset, it, READ);
	if (!iov_iter_is_bvec(it)) {
		FUSE_KTRACE(ireq->cc->fc, "Not a bvec, falling back");
		return -EINVAL;
	}

	iov_iter_truncate(it, size);

	iocb->ki_pos = ireq->iochunk.offset;
	iocb->ki_filp = get_file(file);
	iocb->ki_complete = pcs_csa_complete;
	iocb->ki_flags = IOCB_DIRECT;
	iocb->ki_ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0);

	/* One ref is ours, other is for AIO. If crc read is needed we will grab the third */
	atomic_set(&areq->iocount, 2);

	ret = call_read_iter(file, iocb, it);

	if (unlikely(ret != -EIOCBQUEUED)) {
		if (ret != size) {
			/* Do not drop refs, we do not want to complete ireq. */
			fput(areq->iocb.ki_filp);
			FUSE_KTRACE(ireq->cc->fc, "AIO submit rejected ret=%d %lu, ireq:%p : %llu:%u+%u",
				    ret, ireq->error.remote ? (unsigned long)ireq->error.offender.val : 0UL,
				    ireq, (unsigned long long)ireq->iochunk.chunk,
				    (unsigned)ireq->iochunk.offset,
				    (unsigned)size);
			return ret >= 0 ? -EIO : ret;
		}

		/* IO already finished. Drop AIO refcnt and proceed to crc */
		FUSE_KTRACE(ireq->cc->fc, "No good, AIO executed synchronously, ireq:%p : %llu:%u+%u",
			    ireq, (unsigned long long)ireq->iochunk.chunk,
			    (unsigned)ireq->iochunk.offset,
			    (unsigned)size);

		if (atomic_dec_and_test(&areq->iocount))
			BUG();
	}

	/* Successful or queued read. Need to start crc read, if it is not ready already */
	if (do_csum && !areq->crc) {
		FUSE_KTRACE(ireq->cc->fc, "Not a quicky crc");
		INIT_WORK(&areq->work, csa_crc_work);
		/* Grab ref for crc read work */
		atomic_inc(&areq->iocount);
		areq->cfile = cfile;
		get_file(cfile);
		queue_work(ireq->cc->wq, &areq->work);
	}

	/* Why not pcs_csa_do_completion? Because we do not want to execute real completion
	 * on stack of caller, crypto is a stack hog. Normally, iocount > 1 here, but if all
	 * the IO happen to complete so quickly (or even synchronously) that we are ready already,
	 * it will be the last ref.
	 */
	if (atomic_dec_and_test(&areq->iocount)) {
		INIT_WORK(&areq->work, csa_complete_work);
		queue_work(ireq->cc->wq, &areq->work);
	}
	return 0;
}

int pcs_csa_cs_submit(struct pcs_cs * cs, struct pcs_int_request * ireq)
{
	struct pcs_csa_context * csa_ctx;

	rcu_read_lock();
	csa_ctx = rcu_dereference(cs->csa_ctx);

	if (csa_ctx) {
		struct pcs_map_entry * map = ireq->iochunk.map;
		struct pcs_csa_entry * csa;

		csa = __cse_lookup(csa_ctx, map->id);
		if (csa && memcmp(&ireq->iochunk.csl->version, &csa->version, sizeof(PCS_MAP_VERSION_T)) == 0 &&
		    (csa->flags & PCS_CSA_FL_READ)) {
			/* XXX Paranoia? Verify! */
			if (!(map->state & PCS_MAP_DEAD) && map->cs_list == ireq->iochunk.csl) {
				struct file * file = get_file(csa->file);
				struct file * cfile = csa->cfile ? get_file(csa->cfile) : NULL;
				unsigned int flags = csa->flags;
				int err;

				if (csa_ctx->tfm)
					ireq->flags |= IREQ_F_CRYPT;

				rcu_read_unlock();
				err = csa_submit(file, cfile, flags&PCS_CSA_FL_CSUM, ireq);
				fput(file);
				if (cfile)
					fput(cfile);
				if (!err)
					return 1;
				rcu_read_lock();
				/* Clear state which could be rewritten by csa_submit */
				ireq->iochunk.msg.destructor = NULL;
				ireq->iochunk.msg.rpc = NULL;
				ireq->flags |= IREQ_F_NO_ACCEL;
			}
		}
	}
	rcu_read_unlock();
	return 0;
}

/* Write engine. It is similar to read, code could be merged. Actually the situation
 * with nsrv=1 is just exactly the same. But yet reads can be optimized a lot better
 * and we do not want to lose this advantage.
 *
 * Terminology:
 *  Original ireq - ireq which is supposed to be submitted to head of cs chain
 *   D-request    - replicas at head of chain which have accelrated mappings and eligible
 *                  for local aio processing
 *                  They are presented as struct's pcs_accel_write_req which are stored
 *                  as element of array awr[i] in struct pcs_accel_req in original ireq.iochunk.acr
 *   N-request    - Request to be submitted to tail of cs chain following the last D-request
 *                  It is presented as cloned original ireq with overriden completion callback,
 *                  so that its errors and not preocessed, but copied to the original ireq
 *                  to be processed on completion of original.
 */

static void ireq_init_acr(struct pcs_int_request * ireq)
{
	atomic_set(&ireq->iochunk.acr.iocount, 1);
	ireq->iochunk.acr.num_awr = 0;
	pcs_clear_error(&ireq->iochunk.acr.net_error);
	ireq->iochunk.acr.num_iotimes = 0;
}

static void ireq_clear_acr(struct pcs_int_request * ireq)
{
	int i, n;

	for (i = 0; i < ireq->iochunk.acr.num_awr; i++) {
		struct bio_vec * bvec = ireq->iochunk.acr.awr[i].bvec_copy;
		if (bvec) {
			for (n = ireq->iochunk.acr.awr[i].num_copy_bvecs-1; n>=0; n--) {
				if (bvec[n].bv_page)
					put_page(bvec[n].bv_page);
			}
			kfree(bvec);
			ireq->iochunk.acr.awr[i].bvec_copy = NULL;
		}
	}
	ireq->iochunk.msg.destructor = NULL;
	ireq->iochunk.msg.rpc = NULL;
	ireq->flags |= IREQ_F_NO_ACCEL;
}

void pcs_csa_relay_iotimes(struct pcs_int_request * ireq,  struct pcs_cs_iohdr * h, PCS_NODE_ID_T cs_id)
{
	int idx = ireq->iochunk.acr.num_awr;
	struct pcs_cs_sync_resp * srec;

	ireq->iochunk.acr.io_times[idx].csid = cs_id.val;
	ireq->iochunk.acr.io_times[idx].misc = h->sync.misc;
	ireq->iochunk.acr.io_times[idx].ts_net = h->sync.ts_net;
	ireq->iochunk.acr.io_times[idx].ts_io = h->sync.ts_io;

	for (srec = (struct pcs_cs_sync_resp*)(h + 1), idx++;
	     (void*)(srec + 1) <= (void*)h + h->hdr.len && idx < PCS_MAX_ACCEL_CS;
	     srec++, idx++) {
		ireq->iochunk.acr.io_times[idx].csid = srec->cs_id.val;
		ireq->iochunk.acr.io_times[idx].misc = srec->sync.misc;
		ireq->iochunk.acr.io_times[idx].ts_net = srec->sync.ts_net;
		ireq->iochunk.acr.io_times[idx].ts_io = srec->sync.ts_io;
	}

	ireq->iochunk.acr.num_iotimes = idx;
}

static void __complete_acr_work(struct work_struct * w)
{
	struct pcs_int_request * ireq = container_of(w, struct pcs_int_request, iochunk.acr.work);

	if (pcs_if_error(&ireq->iochunk.acr.net_error)) {
		/* Error on N-request overrides any error on a D-request. */
		pcs_copy_error(&ireq->error, &ireq->iochunk.acr.net_error);
		ireq->flags |= IREQ_F_NO_ACCEL;
		/* Clear ACCELERROR to deliver this error normally, through invalidating the map */
		ireq->flags &= ~(IREQ_F_ACCELERROR|IREQ_F_ONCE);
	} else if (pcs_if_error(&ireq->error)) {
		ireq->flags |= IREQ_F_NO_ACCEL|IREQ_F_ACCELERROR;
		ireq->flags &= ~IREQ_F_ONCE;
	}

	if (pcs_if_error(&ireq->error)) {
		FUSE_KTRACE(ireq->cc->fc, "IO error %d %lu, ireq:%p : %llu:%u+%u",
		      ireq->error.value,
		      ireq->error.remote ? (unsigned long)ireq->error.offender.val : 0UL,
		      ireq, (unsigned long long)ireq->iochunk.chunk,
		      (unsigned)ireq->iochunk.offset,
		      (unsigned)ireq->iochunk.size);
	} else if (ireq->iochunk.parent_N) {
		struct pcs_int_request * parent = ireq->iochunk.parent_N;
		int idx = ireq->iochunk.cs_index;

		WARN_ON(!(ireq->flags & IREQ_F_FANOUT));
		parent->iochunk.fo.io_times[idx] = ireq->iochunk.acr.io_times[idx];
	} else {
		struct fuse_conn * fc = container_of(ireq->cc, struct pcs_fuse_cluster, cc)->fc;

		fuse_stat_observe(fc, PCS_REQ_T_WRITE, ktime_sub(ktime_get(), ireq->ts_sent));

		if (fc->ktrace && fc->ktrace_level >= LOG_TRACE) {
			struct fuse_trace_hdr * t;
			int n = ireq->iochunk.acr.num_iotimes;

			t = FUSE_TRACE_PREPARE(fc->ktrace, FUSE_KTRACE_IOTIMES, sizeof(struct fuse_tr_iotimes_hdr) +
					       n*sizeof(struct fuse_tr_iotimes_cs));
			if (t) {
				struct fuse_tr_iotimes_hdr * th = (struct fuse_tr_iotimes_hdr *)(t + 1);
				struct fuse_tr_iotimes_cs * ch = (struct fuse_tr_iotimes_cs *)(th + 1);
				int i;

				th->chunk = ireq->iochunk.chunk;
				th->offset = ireq->iochunk.chunk + ireq->iochunk.offset;
				th->size = ireq->iochunk.size;
				th->start_time = ktime_to_us(ireq->ts);
				th->local_delay = ktime_to_us(ktime_sub(ireq->ts_sent, ireq->ts));
				th->lat = t->time - ktime_to_us(ireq->ts_sent);
				th->ino = ireq->dentry->fileinfo.attr.id;
				th->type = PCS_CS_WRITE_AL_RESP;
				th->cses = n;
				th->__pad = 0;
				th->chid = (unsigned int)ireq->iochunk.map->id;

				for (i = 0; i < n; i++, ch++)
					*ch = ireq->iochunk.acr.io_times[i];
			}
		}
		FUSE_TRACE_COMMIT(fc->ktrace);
	}

	ireq_clear_acr(ireq);
	/* This will either complete or retry the whole request */
	ireq_complete(ireq);
}

static inline void csa_complete_acr(struct pcs_int_request * ireq)
{
	if (atomic_dec_and_test(&ireq->iochunk.acr.iocount)) {
		INIT_WORK(&ireq->iochunk.acr.work, __complete_acr_work);
		queue_work(ireq->cc->wq, &ireq->iochunk.acr.work);
	}
}

static void __pcs_csa_write_final_completion(struct pcs_accel_write_req *areq)
{
	struct pcs_int_request * ireq;

	fput(areq->iocb.ki_filp);

	ireq = container_of(areq - areq->index, struct pcs_int_request, iochunk.acr.awr[0]);

	if (!pcs_if_error(&ireq->error)) {
		struct fuse_tr_iotimes_cs * th = &ireq->iochunk.acr.io_times[areq->index];
		th->csid = ireq->iochunk.csl->cs[areq->index].info.id.val | PCS_NODE_ALT_MASK;
		th->ts_net = 0;
		th->ts_io = ktime_to_us(ktime_get()) - th->misc;
		th->misc &= PCS_CS_TS_MASK;
		th->misc |= PCS_CS_IO_CLEAR | PCS_CS_IO_FANOUT;
		if (!(ireq->dentry->fileinfo.attr.attrib & PCS_FATTR_IMMEDIATE_WRITE) &&
		    !ireq->dentry->no_write_delay) {
			if (!test_and_set_bit(CSL_SF_DIRTY, &ireq->iochunk.csl->cs[areq->index].flags))
				pcs_map_reevaluate_dirty_status(ireq->iochunk.map);
		}
	}

	csa_complete_acr(ireq);
}

static void csa_sync_work(struct work_struct *w)
{
	struct pcs_accel_write_req * areq = container_of(w, struct pcs_accel_write_req, work);
	struct pcs_int_request * ireq = container_of(areq-areq->index, struct pcs_int_request, iochunk.acr.awr[0]);
	int res;

	clear_bit(CSL_SF_DIRTY, &ireq->iochunk.csl->cs[ireq->iochunk.cs_index].flags);

	res = vfs_fsync(areq->iocb.ki_filp, 1);

	if (res)
		pcs_set_error_cond_atomic(&ireq->error, PCS_ERR_IO, 1, ireq->iochunk.csl->cs[ireq->iochunk.cs_index].info.id);

	if (atomic_dec_and_test(&areq->iocount))
		__pcs_csa_write_final_completion(areq);
}

static void csa_write_complete_work(struct work_struct *w)
{
	struct pcs_accel_write_req * areq = container_of(w, struct pcs_accel_write_req, work);

	__pcs_csa_write_final_completion(areq);
}

static void csa_write_complete(struct kiocb *iocb, long ret)
{
	struct pcs_accel_write_req * areq;
	struct pcs_int_request * ireq;

	areq = container_of(iocb, struct pcs_accel_write_req, iocb);
	ireq = container_of(areq-areq->index, struct pcs_int_request, iochunk.acr.awr[0]);

	if (ret != ireq->iochunk.size) {
		if (!pcs_if_error(&ireq->error))
			pcs_set_error_cond_atomic(&ireq->error, PCS_ERR_IO, 1, ireq->iochunk.csl->cs[ireq->iochunk.cs_index].info.id);
	}

	if (!pcs_if_error(&ireq->error)) {
		if ((ireq->dentry->fileinfo.attr.attrib & PCS_FATTR_IMMEDIATE_WRITE) ||
		    ireq->dentry->no_write_delay) {
			INIT_WORK(&areq->work, csa_sync_work);
			queue_work(ireq->cc->wq, &areq->work);
			return;
		}
	}

	if (atomic_dec_and_test(&areq->iocount)) {
		INIT_WORK(&areq->work, csa_write_complete_work);
		queue_work(ireq->cc->wq, &areq->work);
	}
}

static void encrypt_page_ctr(struct crypto_sync_skcipher * tfm, struct page * dst, struct page *src,
			     unsigned int offset, unsigned int len, u64 pos, u64 chunk_id)
{
	struct scatterlist sgi, sgo;
	struct { u64 a, b; } iv;
	SYNC_SKCIPHER_REQUEST_ON_STACK(req, tfm);

	skcipher_request_set_sync_tfm(req, tfm);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP, NULL, NULL);
	sg_init_table(&sgi, 1);
	sg_init_table(&sgo, 1);

	iv.a = chunk_id;
	iv.b = cpu_to_be64(pos / 16);
	sg_set_page(&sgi, src, len, offset);
	sg_set_page(&sgo, dst, len, offset);
	skcipher_request_set_crypt(req, &sgi, &sgo, len, &iv);
	crypto_skcipher_alg(crypto_skcipher_reqtfm(req))->encrypt(req);
}

static void encrypt_page_xts(struct crypto_sync_skcipher * tfm, struct page * dst, struct page *src,
			     unsigned int offset, unsigned int len, u64 pos, u64 chunk_id)
{
	struct scatterlist sgi, sgo;
	struct { u64 a, b; } iv;
	SYNC_SKCIPHER_REQUEST_ON_STACK(req, tfm);

	skcipher_request_set_sync_tfm(req, tfm);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_SLEEP, NULL, NULL);
	sg_init_table(&sgi, 1);
	sg_init_table(&sgo, 1);

	for ( ; len > 0; len -= 512) {
		iv.a = pos / 512;
		iv.b = chunk_id;
		sg_set_page(&sgi, src, 512, offset);
		sg_set_page(&sgo, dst, 512, offset);
		skcipher_request_set_crypt(req, &sgi, &sgo, 512, &iv);
		crypto_skcipher_alg(crypto_skcipher_reqtfm(req))->encrypt(req);
		pos += 512;
		offset += 512;
	}
}

static int init_crypted_data(struct pcs_int_request * ireq, int idx)
{
	struct pcs_int_request *parent = ireq->completion_data.parent;
	struct pcs_fuse_req * r;
	struct bio_vec * bvec;
	int n, nvec;
	u64 pos;
	u64 chunk_id;
	struct pcs_csa_context * csa_ctx;
	struct crypto_sync_skcipher * tfm;

	BUG_ON(parent->type != PCS_IREQ_API);
	r = parent->apireq.req->datasource;

	nvec = r->exec.io.num_bvecs;

	/* XXX oops, this can sleep. tfm can be destroyed. Need refcount yet?
	 * Seems, not. We just have to refetch tfm from cs after allocations,
	 * failing if it is destroyed already.
	 */
	bvec = kmalloc(sizeof(struct bio_vec) * nvec, GFP_NOIO);
	if (!bvec)
		return -ENOMEM;

	for (n = 0; n < nvec; n++) {
		bvec[n] = r->exec.io.bvec[n];
		if ((bvec[n].bv_offset|bvec[n].bv_len)&511)
			goto out;
		bvec[n].bv_page = alloc_page(GFP_NOIO);
		if (!bvec[n].bv_page)
			goto out;
	}

	rcu_read_lock();
	csa_ctx = rcu_dereference(ireq->iochunk.csl->cs[idx].cslink.cs->csa_ctx);
	if (!csa_ctx || ((tfm = rcu_dereference(csa_ctx->tfm)) == NULL)) {
		rcu_read_unlock();
		goto out;
	}

	pos = ireq->iochunk.offset;
	chunk_id = ireq->iochunk.map->id;
	for (n = 0; n < nvec; n++) {
		if (tfm->base.base.__crt_alg->cra_priority == 400)
			encrypt_page_ctr(tfm, bvec[n].bv_page, r->exec.io.bvec[n].bv_page, bvec[n].bv_offset, bvec[n].bv_len, pos, chunk_id);
		else
			encrypt_page_xts(tfm, bvec[n].bv_page, r->exec.io.bvec[n].bv_page, bvec[n].bv_offset, bvec[n].bv_len, pos, chunk_id);
		pos += bvec[n].bv_len;
	}
	rcu_read_unlock();

	ireq->iochunk.acr.awr[idx].bvec_copy = bvec;
	ireq->iochunk.acr.awr[idx].num_copy_bvecs = n;
	return 0;

out:
	while (--n >= 0)
		put_page(bvec[n].bv_page);
	kfree(bvec);
	return -ENOMEM;
}

static inline int csa_submit_write(struct file * file, struct pcs_int_request * ireq, int idx, int do_crypt)
{
	struct pcs_accel_write_req * areq =  &ireq->iochunk.acr.awr[idx];
	struct kiocb * iocb = &areq->iocb;
	struct iov_iter iter;
	struct iov_iter * it = &iter; /* Just to use this pointer instead of &iter */
	unsigned int size = ireq->iochunk.size;
	int ret;

	if (do_crypt) {
		if (init_crypted_data(ireq, idx))
			return -EINVAL;
		iov_iter_bvec(it, WRITE, areq->bvec_copy, areq->num_copy_bvecs, size);
	} else {
		struct pcs_int_request *parent = ireq->completion_data.parent;
		pcs_api_iorequest_t *ar;

		areq->bvec_copy = NULL;
		BUG_ON(parent->type != PCS_IREQ_API);
		ar = parent->apireq.req;
		ar->get_iter(ar->datasource, ireq->iochunk.dio_offset, it, WRITE);
		if (!iov_iter_is_bvec(it)) {
			FUSE_KTRACE(ireq->cc->fc, "Not a bvec, falling back");
			return -EINVAL;
		}
		iov_iter_truncate(it, size);
	}

	iocb->ki_pos = ireq->iochunk.offset;
	iocb->ki_filp = get_file(file);
	iocb->ki_complete = csa_write_complete;
	iocb->ki_flags = IOCB_DIRECT;
	iocb->ki_ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0);

	/* One ref is ours, other is for AIO. */
	atomic_set(&areq->iocount, 2);
	atomic_inc(&ireq->iochunk.acr.iocount);
	areq->index = idx;
	ireq->iochunk.acr.num_awr = idx + 1;

	ireq->iochunk.acr.io_times[idx].misc = ktime_to_us(ktime_get());

	ret = call_write_iter(file, iocb, it);

	if (unlikely(ret != -EIOCBQUEUED)) {
		if (ret != size) {
			/* Do not drop refs, we do not want to complete ireq. */
			fput(areq->iocb.ki_filp);
			FUSE_KTRACE(ireq->cc->fc, "AIO submit rejected ret=%d %lu, ireq:%p : %llu:%u+%u",
				    ret, ireq->error.remote ? (unsigned long)ireq->error.offender.val : 0UL,
				    ireq, (unsigned long long)ireq->iochunk.chunk,
				    (unsigned)ireq->iochunk.offset,
				    (unsigned)size);
			if (atomic_dec_and_test(&ireq->iochunk.acr.iocount))
				BUG();
			return ret >= 0 ? -EIO : ret;
		}

		/* IO already finished. Drop AIO refcnt yet. */
		FUSE_KTRACE(ireq->cc->fc, "No good, AIO executed synchronously, ireq:%p : %llu:%u+%u",
			    ireq, (unsigned long long)ireq->iochunk.chunk,
			    (unsigned)ireq->iochunk.offset,
			    (unsigned)size);

		if (atomic_dec_and_test(&areq->iocount))
			BUG();
	}

	if (atomic_dec_and_test(&areq->iocount)) {
		INIT_WORK(&areq->work, csa_write_complete_work);
		queue_work(ireq->cc->wq, &areq->work);
	}
	return 0;
}

static int csa_cs_submit_write(struct pcs_int_request * ireq, int idx)
{
	struct pcs_cs * cs = ireq->iochunk.csl->cs[idx].cslink.cs;
	struct pcs_csa_context * csa_ctx;

	if (idx >= PCS_MAX_ACCEL_CS)
		return 0;

	rcu_read_lock();
	csa_ctx = rcu_dereference(cs->csa_ctx);
	if (csa_ctx) {
		struct pcs_map_entry * map = ireq->iochunk.map;
		struct pcs_csa_entry * csa = __cse_lookup(csa_ctx, map->id);
		if (csa && memcmp(&ireq->iochunk.csl->version, &csa->version, sizeof(PCS_MAP_VERSION_T)) == 0 &&
		    (csa->flags & PCS_CSA_FL_WRITE)) {
			/* XXX Paranoia? Verify! */
			if (!(map->state & PCS_MAP_DEAD) && map->cs_list == ireq->iochunk.csl) {
				struct file * file = get_file(csa->file);
				int do_crypt = (csa_ctx->tfm != NULL);
				int err;

				rcu_read_unlock();
				err = csa_submit_write(file, ireq, idx, do_crypt);
				fput(file);
				return !err;
			}
		}
	}
	rcu_read_unlock();
	return 0;
}

static void complete_N_request(struct pcs_int_request * sreq)
{
	struct pcs_int_request * ireq = sreq->iochunk.parent_N;

	if (pcs_if_error(&sreq->error))
		pcs_copy_error(&ireq->iochunk.acr.net_error, &sreq->error);

	/* And free all clone resources */
	if (!pcs_sreq_detach(sreq))
		BUG();
	if (sreq->iochunk.map)
		pcs_map_put(sreq->iochunk.map);
	if (sreq->iochunk.csl)
		cslist_put(sreq->iochunk.csl);
	if (sreq->iochunk.flow)
		pcs_flow_put(sreq->iochunk.flow, &sreq->cc->maps.ftab);
	ireq_destroy(sreq);

	csa_complete_acr(ireq);
}

struct pcs_int_request * pcs_csa_csl_write_submit(struct pcs_int_request * ireq)
{
	int idx;
	struct pcs_cs_list *csl = ireq->iochunk.csl;

	if (csl->nsrv > PCS_MAX_ACCEL_CS)
		return ireq;

	ireq_init_acr(ireq);

	for (idx = 0; idx < csl->nsrv; idx++) {
		/* If dirty status is unknown go to slow path to get a seed */
		if (csl->cs[idx].sync.dirty_seq == 0)
			break;
		if (!csa_cs_submit_write(ireq, idx))
			break;
	}

	if (idx == 0) {
		/* Nothing was handled. Just proceed to normal submit */
		ireq_clear_acr(ireq);
		return ireq;
	} else if (idx >= csl->nsrv) {
		/* Everything went locally. No network at all. */
		ireq->iochunk.acr.num_iotimes = idx;
		csa_complete_acr(ireq);
		return NULL;
	} else {
		/* Harder case. We have to transmit to tail replicas */
		struct pcs_int_request * sreq = pcs_ireq_split(ireq, 0, 1);
		if (sreq == NULL) {
			/* Some D replicas are submitted. So, we have to go
			 * through error cycle.
			 */
			pcs_set_error_cond_atomic(&ireq->error, PCS_ERR_NORES, 1, ireq->iochunk.csl->cs[idx].info.id);
			csa_complete_acr(ireq);
			return NULL;
		}

		ireq->iochunk.acr.num_iotimes = idx;

		/* ireq_split does not copy size and csl */
		sreq->iochunk.size = ireq->iochunk.size;
		sreq->iochunk.csl = ireq->iochunk.csl;
		cslist_get(ireq->iochunk.csl);
		/* Yet this sreq is not actually accounted, the accounting is made for original ireq */
		sreq->flags |= IREQ_F_NOACCT;
		sreq->complete_cb = complete_N_request;
		sreq->iochunk.parent_N = ireq;
		sreq->iochunk.cs_index = idx;

		/* Our original iocount ref goes to N-request,
		 * Proceed with sending sreq to the tail of cs chain
		 */
		return sreq;
	}
}

int pcs_csa_csl_write_submit_single(struct pcs_int_request * ireq, int idx)
{
	if (idx >= PCS_MAX_ACCEL_CS)
		return 0;
	if (ireq->iochunk.csl->cs[idx].sync.dirty_seq == 0)
		return 0;

	ireq_init_acr(ireq);

	if (!csa_cs_submit_write(ireq, idx)) {
		ireq_clear_acr(ireq);
		return 0;
	}

	ireq->iochunk.acr.num_iotimes = idx;
	csa_complete_acr(ireq);
	return 1;
}

static long csa_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct pcs_csa_context *ctx = file->private_data;
	struct file * filp = NULL;
	struct file * cfilp = NULL;
	int err;
	struct pcs_csa_setmap req;

	if (ctx->dead)
		return -ESTALE;

	switch (cmd) {
	case PCS_CSA_IOC_SETMAP:
		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		if (req.fd >= 0) {
			filp = fget(req.fd);
			if (filp == NULL)
				return -EBADF;
		}
		if (req.cfd >= 0) {
			cfilp = fget(req.cfd);
			err = -EBADF;
			if (cfilp == NULL)
				goto out;
		}
		err = csa_update(ctx, req.chunk_id, req.flags, &req.version, filp, cfilp);
		if (cfilp)
			fput(cfilp);
out:
		if (filp)
			fput(filp);
		return err;
	}

	return -EINVAL;
}

static __poll_t csa_poll(struct file *file, poll_table *wait)
{
	struct pcs_csa_context *ctx = file->private_data;
	__poll_t events = 0;

	poll_wait(file, &ctx->wqh, wait);

	if (ctx->dead)
		events |= EPOLLHUP;

	return events;
}

static int csa_release(struct inode *inode, struct file *file)
{
	struct pcs_csa_context *ctx = file->private_data;
	struct pcs_cs * cs;

	ctx->dead = 1;
	rcu_read_lock();
	if ((cs = rcu_dereference(ctx->cs)) != NULL) {
		spin_lock(&cs->lock);
		if (ctx->cs == cs) {
			BUG_ON(cs->csa_ctx != ctx);
			cs->csa_ctx = NULL;
			cs->nmaps--;
			ctx->cs = NULL;
			__pcs_csa_put(ctx);
		}
		spin_unlock(&cs->lock);
	}
	rcu_read_unlock();
	wake_up_poll(&ctx->wqh, EPOLLHUP);
	pcs_csa_put(ctx);
	return 0;
}

static const struct file_operations csa_fops = {
	.owner		= THIS_MODULE,
	.release	= csa_release,
	.poll		= csa_poll,
	.unlocked_ioctl	= csa_ioctl,
	.llseek		= noop_llseek,
};

int pcs_csa_register(struct pcs_cluster_core * cc, PCS_NODE_ID_T cs_id, struct crypto_sync_skcipher * tfm)
{
	int fd;
	struct pcs_cs * cs;
	struct pcs_csa_context * csa_ctx;
	struct file * file;
	PCS_NET_ADDR_T addr = { .type = PCS_ADDRTYPE_NONE };

	cs = pcs_cs_find_create(&cc->css, &cs_id, &addr, CS_FL_LOCAL_SOCK|CS_FL_INACTIVE);
	if (cs == NULL)
		return -ENOMEM;

	cs->nmaps++;
	spin_unlock(&cs->lock);

	fd = -ENOMEM;
	csa_ctx = kzalloc(sizeof(struct pcs_csa_context), GFP_KERNEL);
	if (csa_ctx == NULL)
		goto out;

	atomic_set(&csa_ctx->refcnt, 1);
	csa_ctx->cs = cs;
	INIT_RADIX_TREE(&csa_ctx->tree, GFP_ATOMIC);
	spin_lock_init(&csa_ctx->lock);
	init_waitqueue_head(&csa_ctx->wqh);

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		goto out;

	file = anon_inode_getfile("[csaccel]", &csa_fops, csa_ctx, 0);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		fd = PTR_ERR(file);
		goto out;
	}

	spin_lock(&cs->lock);
	if (cs->csa_ctx) {
		spin_unlock(&cs->lock);
		put_unused_fd(fd);
		fd = -EBUSY;
		goto out;
	}
	atomic_inc(&csa_ctx->refcnt);
	csa_ctx->tfm = tfm;
	cs->csa_ctx = csa_ctx;
	spin_unlock(&cs->lock);
	fd_install(fd, file);

	/* Not good, but handy, people will forget this, no doubts */
	if (!cs_io_locality)
		cs_io_locality = 1;
	return fd;

out:
	if (csa_ctx) {
		csa_ctx->dead = 1;
		pcs_csa_put(csa_ctx);
	}
	return fd;
}

int pcs_csa_init(void)
{
	struct _old_pcs_error_t
	{
		unsigned int     value : 31, remote: 1;
		PCS_NODE_ID_T           offender;
	};

	pcs_csa_cachep = kmem_cache_create("pcs_csa",
					    sizeof(struct pcs_csa_entry),
					    0, SLAB_RECLAIM_ACCOUNT|SLAB_ACCOUNT, NULL);
	if (!pcs_csa_cachep)
		return -ENOMEM;

	BUILD_BUG_ON(sizeof(struct _old_pcs_error_t) != sizeof(struct _pcs_error_t));

	return 0;
}

void pcs_csa_fini(void)
{
	if (pcs_csa_cachep)
		kmem_cache_destroy(pcs_csa_cachep);
}
