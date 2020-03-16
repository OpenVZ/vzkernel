#include <linux/module.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/preempt_mask.h>

#include "pcs_rdma_rw.h"

static int dma_dir_to_ib_reg_access(enum dma_data_direction dir)
{
	switch (dir) {
		case DMA_BIDIRECTIONAL:
			return IB_ACCESS_REMOTE_READ |
			       IB_ACCESS_REMOTE_WRITE |
			       IB_ACCESS_LOCAL_WRITE;
		case DMA_TO_DEVICE:
			return IB_ACCESS_REMOTE_READ;
		case DMA_FROM_DEVICE:
			return IB_ACCESS_REMOTE_WRITE |
			       IB_ACCESS_LOCAL_WRITE;
		default:
			return 0;
	};
}

int pcs_sgl_buf_init_from_msg(struct pcs_sgl_buf *sbuf, struct pcs_msg *msg,
			      size_t offset, size_t end_offset, gfp_t gfp, bool allow_gaps)
{
	struct iov_iter it;
	size_t msg_offset;
	struct scatterlist *sg;
	int ret, i;

	if (offset >= end_offset || end_offset > msg->size)
		return -EINVAL;

	sbuf->pg_cnt = 0;
	sbuf->sg_cnt = 0;
	sbuf->page_clean = put_page;

	iov_iter_init_bad(&it);
	msg_offset = offset;
	while (msg_offset < end_offset) {
		size_t len;

		if (!iov_iter_count(&it))
			msg->get_iter(msg, msg_offset, &it);

		len = iov_iter_single_seg_count(&it);
		if (len > end_offset - msg_offset)
			len = end_offset - msg_offset;

		iov_iter_advance(&it, len);
		msg_offset += len;
		sbuf->sg_cnt++;
	}

	sbuf->pages = RE_NULL(kzalloc(sizeof(struct page*) * sbuf->sg_cnt,
				      gfp));
	if (!sbuf->pages)
		return -ENOMEM;

	sbuf->sgl = RE_NULL(kzalloc(sizeof(struct scatterlist) * sbuf->sg_cnt,
				    gfp));
	if (!sbuf->sgl) {
		ret = -ENOMEM;
		goto fail_pg;
	}
	sg_init_table(sbuf->sgl, sbuf->sg_cnt);

	iov_iter_init_bad(&it);
	msg_offset = offset;
	sg = sbuf->sgl;
	while (msg_offset < end_offset) {
		size_t off, len;

		if (!iov_iter_count(&it))
			msg->get_iter(msg, msg_offset, &it);

		sbuf->pages[sbuf->pg_cnt] = RE_NULL(iov_iter_get_page(&it, &off, &len));
		if (!sbuf->pages[sbuf->pg_cnt]) {
			ret = -EINVAL;
			goto fail_sgl;
		}

		if (len > end_offset - msg_offset)
			len = end_offset - msg_offset;

		sg_set_page(sg, sbuf->pages[sbuf->pg_cnt++], len, off);

		if (!allow_gaps &&
		    ((msg_offset != offset && !IS_ALIGNED(off, PAGE_SIZE)) ||
		     ((msg_offset + len != end_offset) && !IS_ALIGNED(off + len, PAGE_SIZE)))) {
			ret = -EINVAL;
			goto fail_sgl;
		}

		sg = sg_next(sg);
		iov_iter_advance(&it, len);
		msg_offset += len;
	}

	return 0;

fail_sgl:
	kfree(sbuf->sgl);
fail_pg:
	for (i = 0; i < sbuf->pg_cnt; i++)
		sbuf->page_clean(sbuf->pages[i]);
	kfree(sbuf->pages);

	return ret;
}

static void pcs_sgl_buf_free_page(struct page *page)
{
	__free_page(page);
}

int pcs_sgl_buf_init(struct pcs_sgl_buf *sbuf, size_t size, gfp_t gfp)
{
	struct scatterlist *sg;
	int ret, i;

	if (size == 0)
		return -EINVAL;

	sbuf->pg_cnt = 0;
	sbuf->sg_cnt = PAGE_ALIGN(size) >> PAGE_SHIFT;
	sbuf->page_clean = pcs_sgl_buf_free_page;

	sbuf->pages = RE_NULL(kzalloc(sizeof(struct page*) * sbuf->sg_cnt,
				      gfp));
	if (!sbuf->pages)
		return -ENOMEM;

	sbuf->sgl = RE_NULL(kzalloc(sizeof(struct scatterlist) * sbuf->sg_cnt,
				    gfp));
	if (!sbuf->sgl) {
		ret = -ENOMEM;
		goto fail_pg;
	}
	sg_init_table(sbuf->sgl, sbuf->sg_cnt);

	for_each_sg(sbuf->sgl, sg, sbuf->sg_cnt, i) {
		size_t sg_len = min_t(size_t, size, PAGE_SIZE);
		sbuf->pages[sbuf->pg_cnt] = RE_NULL(alloc_page(gfp));
		if (!sbuf->pages[sbuf->pg_cnt]) {
			ret = -ENOMEM;
			goto fail_sgl;
		}
		BUG_ON(!sg_len);
		sg_set_page(sg, sbuf->pages[sbuf->pg_cnt], sg_len, 0);
		size -= sg_len;
		sbuf->pg_cnt++;
	}

	return 0;

fail_sgl:
	kfree(sbuf->sgl);
fail_pg:
	for (i = 0; i < sbuf->pg_cnt; i++)
		sbuf->page_clean(sbuf->pages[i]);
	kfree(sbuf->pages);

	return ret;
}

void pcs_sgl_buf_destroy(struct pcs_sgl_buf *sbuf)
{
	int i;

	kfree(sbuf->sgl);

	for (i = 0; i < sbuf->pg_cnt; i++)
		sbuf->page_clean(sbuf->pages[i]);
	kfree(sbuf->pages);
}

int pcs_ib_mr_pool_init(struct pcs_ib_mr_pool *pool, struct ib_pd *pd,
			enum ib_mr_type mr_type, u32 max_num_sg, size_t mr_cnt)
{
	struct ib_mr *mr;
	int ret, i;

	pool->pd = pd;
	pool->mr_type = mr_type;
	pool->max_num_sg = max_num_sg;
	pool->mr_cnt = mr_cnt;

	spin_lock_init(&pool->lock);

	INIT_LIST_HEAD(&pool->mr_list);
	pool->used_mrs = 0;

	for (i = 0; i < mr_cnt; i++) {
		mr = RE_PTR_INV(ib_alloc_mr(pd, mr_type, max_num_sg));
		if (IS_ERR(mr)) {
			ret = PTR_ERR(mr);
			goto fail;
		}
		list_add_tail(&mr->qp_entry, &pool->mr_list);
	}

	return 0;

fail:
	pcs_ib_mr_pool_destroy(pool);
	return ret;
}

void pcs_ib_mr_pool_destroy(struct pcs_ib_mr_pool *pool)
{
	struct ib_mr *mr, *tmp;

	spin_lock_irq(&pool->lock);
	BUG_ON(pool->used_mrs);
	spin_unlock_irq(&pool->lock);

	list_for_each_entry_safe(mr, tmp, &pool->mr_list, qp_entry)
		ib_dereg_mr(mr);
}

struct ib_mr* pcs_ib_mr_pool_get(struct pcs_ib_mr_pool *pool)
{
	struct ib_mr *mr;
	unsigned long flags;

	spin_lock_irqsave(&pool->lock, flags);
	mr = list_first_entry_or_null(&pool->mr_list, struct ib_mr, qp_entry);
	if (mr) {
		list_del(&mr->qp_entry);
		BUG_ON(pool->used_mrs >= pool->mr_cnt);
		pool->used_mrs++;
	}
	spin_unlock_irqrestore(&pool->lock, flags);

	if (!mr && !in_interrupt()) {
		mr = RE_PTR_INV(ib_alloc_mr(pool->pd, pool->mr_type,
					    pool->max_num_sg));
		if (IS_ERR(mr))
			return NULL;

		spin_lock_irqsave(&pool->lock, flags);
		pool->mr_cnt++;
		BUG_ON(pool->used_mrs >= pool->mr_cnt);
		pool->used_mrs++;
		spin_unlock_irqrestore(&pool->lock, flags);
	}

	return mr;
}

void pcs_ib_mr_pool_put(struct pcs_ib_mr_pool *pool, struct ib_mr *mr)
{
	unsigned long flags;

	spin_lock_irqsave(&pool->lock, flags);
	list_add(&mr->qp_entry, &pool->mr_list);
	BUG_ON(!pool->used_mrs);
	pool->used_mrs--;
	spin_unlock_irqrestore(&pool->lock, flags);
}

int pcs_rdma_rw_init_from_msg(struct pcs_rdma_rw *rw, struct ib_device *dev,
			      enum dma_data_direction dir, u64 remote_addr, u32 rkey,
			      u32 local_dma_lkey, struct pcs_msg *msg, size_t offset,
			      size_t end_offset, gfp_t gfp, size_t sge_per_wr)
{
	struct scatterlist *sg;
	struct ib_sge *sge;
	size_t sge_cnt;
	int ret, i, k;

	if (dir != DMA_TO_DEVICE && dir != DMA_FROM_DEVICE)
		return -EINVAL;

	rw->dev = dev;
	rw->dir = dir;

	ret = pcs_sgl_buf_init_from_msg(&rw->sbuf, msg, offset, end_offset,
					gfp, true);
	if (ret)
		return ret;

	ret = RE_INV(ib_dma_map_sg(dev, rw->sbuf.sgl, rw->sbuf.sg_cnt,
				   dir));
	if (ret <= 0) {
		ret = ret < 0 ? ret : -EIO;
		goto fail_sgl;
	}
	rw->sbuf.sg_cnt = ret;

	rw->nr_wrs = DIV_ROUND_UP(rw->sbuf.sg_cnt, sge_per_wr);

	rw->sges = RE_NULL(kzalloc(sizeof(struct ib_sge) * rw->sbuf.sg_cnt, gfp));
	if (!rw->sges) {
		ret = -ENOMEM;
		goto fail_dma;
	}

	rw->wrs = RE_NULL(kzalloc(sizeof(struct ib_rdma_wr) * rw->nr_wrs, gfp));
	if (!rw->wrs) {
		ret = -ENOMEM;
		goto fail_sges;
	}

	sg = rw->sbuf.sgl;
	sge = rw->sges;
	sge_cnt = rw->sbuf.sg_cnt;
	for (i = 0; i < rw->nr_wrs; i++) {
		struct ib_rdma_wr *wr = rw->wrs + i;
		int num_sge = min_t(size_t, sge_cnt, sge_per_wr);

		wr->wr.opcode = dir == DMA_FROM_DEVICE ? IB_WR_RDMA_READ :
			IB_WR_RDMA_WRITE;
		wr->wr.sg_list = sge;
		wr->wr.num_sge = num_sge;
		wr->remote_addr = remote_addr;
		wr->rkey = rkey;

		for (k = 0; k < num_sge; k++, sg = sg_next(sg)) {
			sge->addr = ib_sg_dma_address(dev, sg);
			sge->length = ib_sg_dma_len(dev, sg);
			sge->lkey = local_dma_lkey;

			remote_addr += sge->length;
			sge++;
			sge_cnt--;
		}

		if (i > 0)
			rw->wrs[i - 1].wr.next = &wr->wr;
	}

	return 0;

fail_sges:
	kfree(rw->sges);
fail_dma:
	ib_dma_unmap_sg(dev, rw->sbuf.sgl, rw->sbuf.sg_cnt, dir);
fail_sgl:
	pcs_sgl_buf_destroy(&rw->sbuf);

	return ret;
}

void pcs_rdma_rw_destroy(struct pcs_rdma_rw *rw)
{
	kfree(rw->wrs);
	kfree(rw->sges);
	ib_dma_unmap_sg(rw->dev, rw->sbuf.sgl, rw->sbuf.sg_cnt, rw->dir);
	pcs_sgl_buf_destroy(&rw->sbuf);
}

static int pcs_rdma_mr_init_common(struct pcs_rdma_mr *mr, struct ib_device *dev,
				   struct ib_pd *pd, enum dma_data_direction dir, size_t size,
				   struct pcs_ib_mr_pool *ib_mr_pool)
{
	unsigned long dma_align = dma_get_cache_alignment();
	struct scatterlist *sg;
	int ret, i;

	/* For testing fallback */
	RE_SET(ib_mr_pool, NULL);

	/* Only cache aligned DMA transfers are reliable */
	for_each_sg(mr->sbuf.sgl, sg, mr->sbuf.sg_cnt, i)
		if (!IS_ALIGNED((uintptr_t)sg_virt(sg), dma_align) ||
				!IS_ALIGNED((uintptr_t)(sg_virt(sg) + ib_sg_dma_len(dev, sg)),
					    dma_align))
			return -EINVAL;

	INIT_LIST_HEAD(&mr->entry);
	mr->dev = dev;
	mr->pd = pd;
	mr->dir = dir;
	mr->size = size;
	mr->ib_mr_pool = ib_mr_pool && ib_mr_pool->mr_type == IB_MR_TYPE_MEM_REG &&
		ib_mr_pool->max_num_sg >= mr->sbuf.sg_cnt ? ib_mr_pool : NULL;

	ret = RE_INV(ib_dma_map_sg(dev, mr->sbuf.sgl, mr->sbuf.sg_cnt,
				   dir));
	if (ret <= 0)
		return ret < 0 ? ret : -EIO;
	mr->sbuf.sg_cnt = ret;

	if (mr->ib_mr_pool) {
		mr->mr = RE_NULL(pcs_ib_mr_pool_get(mr->ib_mr_pool));
		if (!mr->mr) {
			ret = -ENOMEM;
			goto fail_dma;
		}
	} else { /* fallback */
		mr->mr = RE_PTR_INV(ib_alloc_mr(pd, IB_MR_TYPE_MEM_REG,
						mr->sbuf.sg_cnt));
		if (IS_ERR(mr->mr)) {
			ret = PTR_ERR(mr->mr);
			goto fail_dma;
		}
	}

	ret = RE_INV(ib_map_mr_sg(mr->mr, mr->sbuf.sgl, mr->sbuf.sg_cnt,
				  NULL, PAGE_SIZE));
	if (ret != mr->sbuf.sg_cnt) {
		ret = ret < 0 ? ret : -EIO;
		goto fail_mr;
	}

	memset(&mr->inv_wr, 0, sizeof(mr->inv_wr));
	mr->inv_wr.next = &mr->reg_wr.wr;
	mr->inv_wr.opcode = IB_WR_LOCAL_INV;
	mr->inv_wr.ex.invalidate_rkey = mr->mr->lkey;

	ib_update_fast_reg_key(mr->mr, ib_inc_rkey(mr->mr->lkey));

	memset(&mr->reg_wr, 0, sizeof(mr->reg_wr));
	mr->reg_wr.wr.opcode = IB_WR_REG_MR;
	mr->reg_wr.mr = mr->mr;
	mr->reg_wr.key = mr->mr->lkey;
	mr->reg_wr.access = dma_dir_to_ib_reg_access(dir);

	mr->first_wr = mr->mr->need_inval ? &mr->inv_wr: &mr->reg_wr.wr;
	mr->last_wr = &mr->reg_wr.wr;
	mr->mr->need_inval = true;

	return 0;

fail_mr:
	if (mr->ib_mr_pool)
		pcs_ib_mr_pool_put(mr->ib_mr_pool, mr->mr);
	else /* fallback */
		ib_dereg_mr(mr->mr);
fail_dma:
	ib_dma_unmap_sg(dev, mr->sbuf.sgl, mr->sbuf.sg_cnt, dir);

	return ret;
}

int pcs_rdma_mr_init_from_msg(struct pcs_rdma_mr *mr, struct ib_device *dev,
			      struct ib_pd *pd, enum dma_data_direction dir, struct pcs_msg *msg,
			      size_t offset, size_t end_offset, gfp_t gfp,
			      struct pcs_ib_mr_pool *ib_mr_pool)
{
	int ret;

	ret = pcs_sgl_buf_init_from_msg(&mr->sbuf, msg, offset, end_offset,
					gfp, false);
	if (ret)
		return ret;

	ret = pcs_rdma_mr_init_common(mr, dev, pd, dir, end_offset - offset,
				      ib_mr_pool);
	if (ret)
		pcs_sgl_buf_destroy(&mr->sbuf);

	return ret;
}

int pcs_rdma_mr_init(struct pcs_rdma_mr *mr, struct ib_device *dev, struct ib_pd *pd,
		     enum dma_data_direction dir, size_t size, gfp_t gfp,
		     struct pcs_ib_mr_pool *ib_mr_pool)
{
	int ret;

	ret = pcs_sgl_buf_init(&mr->sbuf, size, gfp);
	if (ret)
		return ret;

	ret = pcs_rdma_mr_init_common(mr, dev, pd, dir, size, ib_mr_pool);
	if (ret)
		pcs_sgl_buf_destroy(&mr->sbuf);

	return ret;
}

void pcs_rdma_mr_destroy(struct pcs_rdma_mr *mr)
{
	if (mr->ib_mr_pool)
		pcs_ib_mr_pool_put(mr->ib_mr_pool, mr->mr);
	else /* fallback */
		ib_dereg_mr(mr->mr);
	ib_dma_unmap_sg(mr->dev, mr->sbuf.sgl, mr->sbuf.sg_cnt, mr->dir);
	pcs_sgl_buf_destroy(&mr->sbuf);
}

struct pcs_rdma_mr* pcs_rdma_mr_alloc(struct ib_device *dev, struct ib_pd *pd,
				      enum dma_data_direction dir, size_t size, gfp_t gfp,
				      struct pcs_ib_mr_pool *ib_mr_pool)
{
	struct pcs_rdma_mr *mr;
	int ret;

	mr = RE_NULL(kzalloc(sizeof(*mr), gfp));
	if (!mr)
		return ERR_PTR(-ENOMEM);

	ret = pcs_rdma_mr_init(mr, dev, pd, dir, size, gfp, ib_mr_pool);
	if (ret) {
		kfree(mr);
		return ERR_PTR(ret);
	}

	return mr;
}

void pcs_rdma_mr_free(struct pcs_rdma_mr *mr)
{
	pcs_rdma_mr_destroy(mr);
	kfree(mr);
}

void pcs_rdma_mr_sync_for_cpu(struct pcs_rdma_mr *mr, size_t size)
{
	struct scatterlist *sg;
	unsigned int i;

	for_each_sg(mr->sbuf.sgl, sg, mr->sbuf.sg_cnt, i) {
		size_t sg_len = min_t(size_t, size, ib_sg_dma_len(mr->dev, sg));
		ib_dma_sync_single_for_cpu(mr->dev,
					   ib_sg_dma_address(mr->dev, sg),
					   sg_len,
					   mr->dir);
		size -= sg_len;
		if (!size)
			break;
	}
}

void pcs_rdma_mr_sync_for_device(struct pcs_rdma_mr *mr, size_t size)
{
	struct scatterlist *sg;
	unsigned int i;

	for_each_sg(mr->sbuf.sgl, sg, mr->sbuf.sg_cnt, i) {
		size_t sg_len = min_t(size_t, size, ib_sg_dma_len(mr->dev, sg));
		ib_dma_sync_single_for_device(mr->dev,
					      ib_sg_dma_address(mr->dev, sg),
					      sg_len,
					      mr->dir);
		size -= sg_len;
		if (!size)
			break;
	}
}

int pcs_rdma_mr_sync_for_msg(struct pcs_rdma_mr *mr, struct pcs_msg *msg,
			     size_t offset, size_t end_offset, bool to_msg)
{
	struct iov_iter it;
	struct scatterlist *mr_sg;
	size_t mr_off;

	if (offset >= end_offset || end_offset > msg->size ||
	    end_offset - offset > mr->size)
		return -EINVAL;

	iov_iter_init_bad(&it);

	mr_sg = mr->sbuf.sgl;
	mr_off = 0;

	while (offset < end_offset) {
		void *msg_data;
		size_t msg_len, msg_off;
		struct page *msg_page;

		if (!iov_iter_count(&it))
			msg->get_iter(msg, offset, &it);

		msg_page = iov_iter_kmap(&it, &msg_data, &msg_len);
		if (msg_len > end_offset - offset)
			msg_len = end_offset - offset;
		msg_off = 0;
		while (msg_off < msg_len) {
			void *mr_data = sg_virt(mr_sg);
			size_t chunk_size = min_t(size_t, msg_len - msg_off, PAGE_SIZE - mr_off);

			if (to_msg)
				memcpy(msg_data + msg_off, mr_data + mr_off, chunk_size);
			else
				memcpy(mr_data + mr_off, msg_data + msg_off, chunk_size);

			mr_off += chunk_size;
			msg_off += chunk_size;
			if (mr_off == PAGE_SIZE) {
				mr_sg = sg_next(mr_sg);
				mr_off = 0;
			}
		}

		if (msg_page)
			kunmap(msg_page);

		iov_iter_advance(&it, msg_len);
		offset += msg_len;
	}

	return 0;
}

int pcs_rdma_mr_pool_init(struct pcs_rdma_mr_pool *pool, size_t mr_size,
			  size_t mr_cnt, struct ib_device *dev, struct ib_pd *pd,
			  enum dma_data_direction dir, gfp_t gfp, struct pcs_ib_mr_pool *ib_mr_pool)
{
	struct pcs_rdma_mr *mr;
	int ret, i;

	pool->mr_size = mr_size;
	pool->mr_cnt = mr_cnt;
	pool->dev = dev;
	pool->pd = pd;
	pool->dir = dir;
	pool->gfp = gfp;
	pool->ib_mr_pool = ib_mr_pool;

	spin_lock_init(&pool->lock);

	INIT_LIST_HEAD(&pool->mr_list);
	pool->used_mrs = 0;

	for (i = 0; i < mr_cnt; i++) {
		mr = pcs_rdma_mr_alloc(dev, pd, dir, mr_size, gfp, ib_mr_pool);
		if (IS_ERR(mr)) {
			ret = PTR_ERR(mr);
			goto fail;
		}
		list_add_tail(&mr->entry, &pool->mr_list);
	}

	return 0;

fail:
	pcs_rdma_mr_pool_destroy(pool);
	return ret;
}

void pcs_rdma_mr_pool_destroy(struct pcs_rdma_mr_pool *pool)
{
	struct pcs_rdma_mr *mr, *tmp;

	spin_lock_irq(&pool->lock);
	BUG_ON(pool->used_mrs);
	spin_unlock_irq(&pool->lock);

	list_for_each_entry_safe(mr, tmp, &pool->mr_list, entry)
		pcs_rdma_mr_free(mr);
}

struct pcs_rdma_mr* pcs_rdma_mr_pool_get(struct pcs_rdma_mr_pool *pool)
{
	struct pcs_rdma_mr *mr;
	unsigned long flags;

	spin_lock_irqsave(&pool->lock, flags);
	mr = list_first_entry_or_null(&pool->mr_list, struct pcs_rdma_mr, entry);
	if (mr) {
		list_del(&mr->entry);
		BUG_ON(pool->used_mrs >= pool->mr_cnt);
		pool->used_mrs++;
	}
	spin_unlock_irqrestore(&pool->lock, flags);

	if (!mr && !in_interrupt()) {
		mr = pcs_rdma_mr_alloc(pool->dev, pool->pd, pool->dir,
				       pool->mr_size, pool->gfp,
				       pool->ib_mr_pool);
		if (IS_ERR(mr))
			return NULL;

		spin_lock_irqsave(&pool->lock, flags);
		pool->mr_cnt++;
		BUG_ON(pool->used_mrs >= pool->mr_cnt);
		pool->used_mrs++;
		spin_unlock_irqrestore(&pool->lock, flags);
	}

	return mr;
}

void pcs_rdma_mr_pool_put(struct pcs_rdma_mr_pool *pool, struct pcs_rdma_mr *mr)
{
	unsigned long flags;

	spin_lock_irqsave(&pool->lock, flags);
	list_add(&mr->entry, &pool->mr_list);
	BUG_ON(!pool->used_mrs);
	pool->used_mrs--;
	spin_unlock_irqrestore(&pool->lock, flags);
}

static void pcs_rdma_msg_cleanup_map(struct pcs_rdma_msg *rdma_msg)
{
	pcs_rdma_mr_destroy(rdma_msg->mr);
}

static int pcs_rdma_msg_init_map(struct pcs_rdma_msg *rdma_msg, struct pcs_msg *msg,
				 size_t offset, size_t end_offset,
				 struct pcs_rdma_mr_pool *pool)
{
	int ret;

	if (offset >= end_offset || end_offset > msg->size)
		return -EINVAL;

	rdma_msg->msg = msg;
	rdma_msg->offset = offset;
	rdma_msg->end_offset = end_offset;

	rdma_msg->pool = NULL;
	rdma_msg->cleanup = pcs_rdma_msg_cleanup_map;

	rdma_msg->first_wr = NULL;
	rdma_msg->last_wr = NULL;

	rdma_msg->mr = &rdma_msg->_inline_mr;
	ret = pcs_rdma_mr_init_from_msg(rdma_msg->mr, pool->dev, pool->pd, pool->dir,
					msg, offset, end_offset, pool->gfp, pool->ib_mr_pool);
	if (ret)
		return ret;

	rdma_msg->lkey = rdma_msg->mr->mr->lkey;
	rdma_msg->rkey = rdma_msg->mr->mr->rkey;
	rdma_msg->iova = rdma_msg->mr->mr->iova;

	if (rdma_msg->mr->first_wr && rdma_msg->mr->last_wr) {
		rdma_msg->first_wr = rdma_msg->mr->first_wr;
		rdma_msg->last_wr = rdma_msg->mr->last_wr;
		rdma_msg->mr->first_wr = NULL;
		rdma_msg->mr->last_wr = NULL;
	}

	return 0;
}

static void pcs_rdma_msg_cleanup(struct pcs_rdma_msg *rdma_msg)
{
	pcs_rdma_mr_sync_for_cpu(rdma_msg->mr,
				 PAGE_ALIGN(rdma_msg->end_offset - rdma_msg->offset));
	if (rdma_msg->mr->dir == DMA_BIDIRECTIONAL ||
	    rdma_msg->mr->dir == DMA_FROM_DEVICE)
		BUG_ON(pcs_rdma_mr_sync_for_msg(rdma_msg->mr, rdma_msg->msg,
						rdma_msg->offset,
						rdma_msg->end_offset, true));

	if (rdma_msg->pool)
		pcs_rdma_mr_pool_put(rdma_msg->pool, rdma_msg->mr);
	else /* fallback */
		pcs_rdma_mr_destroy(rdma_msg->mr);
}

int pcs_rdma_msg_init(struct pcs_rdma_msg *rdma_msg, struct pcs_msg *msg,
		      size_t offset, size_t end_offset, struct pcs_rdma_mr_pool *pool,
		      bool try_to_map)
{
	size_t mr_size = PAGE_ALIGN(end_offset - offset);
	int ret;

	if (offset >= end_offset || end_offset > msg->size)
		return -EINVAL;

	if (try_to_map && !pcs_rdma_msg_init_map(rdma_msg, msg, offset, end_offset, pool))
		return 0;

	rdma_msg->msg = msg;
	rdma_msg->offset = offset;
	rdma_msg->end_offset = end_offset;

	rdma_msg->pool = mr_size > pool->mr_size ? NULL : pool;
	rdma_msg->cleanup = pcs_rdma_msg_cleanup;

	/* For testing fallback */
	RE_SET(rdma_msg->pool, NULL);

	rdma_msg->first_wr = NULL;
	rdma_msg->last_wr = NULL;

	if (rdma_msg->pool) {
		rdma_msg->mr = RE_NULL(pcs_rdma_mr_pool_get(rdma_msg->pool));
		if (!rdma_msg->mr)
			return -ENOMEM;
	} else { /* fallback */
		rdma_msg->mr = &rdma_msg->_inline_mr;
		ret = pcs_rdma_mr_init(rdma_msg->mr, pool->dev, pool->pd, pool->dir,
				       mr_size, pool->gfp, pool->ib_mr_pool);
		if (ret)
			return ret;
	}

	if (rdma_msg->mr->dir == DMA_BIDIRECTIONAL ||
	    rdma_msg->mr->dir == DMA_TO_DEVICE)
		BUG_ON(pcs_rdma_mr_sync_for_msg(rdma_msg->mr, msg, offset,
						end_offset, false));
	pcs_rdma_mr_sync_for_device(rdma_msg->mr, mr_size);

	rdma_msg->lkey = rdma_msg->mr->mr->lkey;
	rdma_msg->rkey = rdma_msg->mr->mr->rkey;
	rdma_msg->iova = rdma_msg->mr->mr->iova;

	if (rdma_msg->mr->first_wr && rdma_msg->mr->last_wr) {
		rdma_msg->first_wr = rdma_msg->mr->first_wr;
		rdma_msg->last_wr = rdma_msg->mr->last_wr;
		rdma_msg->mr->first_wr = NULL;
		rdma_msg->mr->last_wr = NULL;
	}

	return 0;
}

void pcs_rdma_msg_destroy(struct pcs_rdma_msg *rdma_msg)
{
	rdma_msg->cleanup(rdma_msg);
}
