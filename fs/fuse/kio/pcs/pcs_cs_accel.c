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

static inline struct pcs_csa_entry * cse_lookup(struct pcs_csa_context * ctx, u64 chunk_id)
{
	struct pcs_csa_entry * cse;

	rcu_read_lock();
	cse= radix_tree_lookup(&ctx->tree, chunk_id);
	rcu_read_unlock();
	return cse;
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

			len = iov_iter_get_pages2(it, &page, left, 1, &offset);
			BUG_ON(len <= 0);

			crypto_shash_alg(crc_tfm)->update(shash, kmap(page) + offset, len);
			kunmap(page);
			put_page(page);
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

		len = iov_iter_get_pages2(it, &page, size - pos, 1, &offset);
		BUG_ON(len <= 0);
		BUG_ON(len & 511);

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
		struct pcs_csa_context * ctx = rcu_dereference(cs->csa_ctx);
		if (!ctx || !ctx->tfm || decrypt_data(ireq, ctx->tfm)) {
			ireq->error.remote = 1;
			ireq->error.offender = ireq->iochunk.csl->cs[ireq->iochunk.cs_index].info.id;
			ireq->error.value = PCS_ERR_IO;
		}
	}

	if (areq->crc) {
		if (!pcs_if_error(&ireq->error)) {
			if (verify_crc(ireq, areq->crc)) {
				ireq->error.remote = 1;
				ireq->error.offender = ireq->iochunk.csl->cs[ireq->iochunk.cs_index].info.id;
				ireq->error.value = PCS_ERR_IO;
			}
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
			if (!ireq->error.value) {
				ireq->error.remote = 1;
				ireq->error.offender = ireq->iochunk.csl->cs[ireq->iochunk.cs_index].info.id;
				ireq->error.value = PCS_ERR_NORES;
			}
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

	if (ret != ireq->iochunk.size) {
		if (!ireq->error.value) {
			ireq->error.remote = 1;
			ireq->error.offender = ireq->iochunk.csl->cs[ireq->iochunk.cs_index].info.id;
			ireq->error.value = PCS_ERR_IO;
		}
	}

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

	ar->get_iter(ar->datasource, ireq->iochunk.dio_offset, it, 0);
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

	ireq->ts_sent = ktime_get();
	ret = call_read_iter(file, iocb, it);

	if (unlikely(ret != -EIOCBQUEUED)) {
		if (ret != size) {
			if (!ireq->error.value) {
				ireq->error.remote = 1;
				ireq->error.offender = ireq->iochunk.csl->cs[ireq->iochunk.cs_index].info.id;
				ireq->error.value = PCS_ERR_IO;
			}

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
	struct pcs_csa_context * csa_ctx = rcu_dereference(cs->csa_ctx);

	if (csa_ctx) {
		struct pcs_map_entry * map = ireq->iochunk.map;
		struct pcs_csa_entry * csa = cse_lookup(csa_ctx, map->id);
		if (csa && memcmp(&ireq->iochunk.csl->version, &csa->version, sizeof(PCS_MAP_VERSION_T)) == 0 &&
		    (csa->flags & PCS_CSA_FL_READ)) {
			/* XXX Paranoia? Verify! */
			if (!(map->state & PCS_MAP_DEAD) && map->cs_list == ireq->iochunk.csl) {
				if (csa_ctx->tfm)
					ireq->flags |= IREQ_F_CRYPT;
				if (!csa_submit(csa->file, csa->cfile, csa->flags&PCS_CSA_FL_CSUM, ireq))
					return 1;
				/* Clear state which could be rewritten by csa_submit */
				ireq->iochunk.msg.destructor = NULL;
				ireq->iochunk.msg.rpc = NULL;
			}
		}
	}
	return 0;
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
	pcs_csa_cachep = kmem_cache_create("pcs_csa",
					    sizeof(struct pcs_csa_entry),
					    0, SLAB_RECLAIM_ACCOUNT|SLAB_ACCOUNT, NULL);
	if (!pcs_csa_cachep)
		return -ENOMEM;

	return 0;
}

void pcs_csa_fini(void)
{
	if (pcs_csa_cachep)
		kmem_cache_destroy(pcs_csa_cachep);
}
