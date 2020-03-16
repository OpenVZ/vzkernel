#ifndef _PCS_RMDA_RW_H_
#define _PCS_RMDA_RW_H_ 1

#include <linux/types.h>
#include <linux/list.h>
#include <linux/scatterlist.h>
#include <linux/dma-direction.h>

#include <rdma/ib_verbs.h>

#include "pcs_sock_io.h"

#if defined(CONFIG_DEBUG_KERNEL) && defined(CONFIG_FUSE_KIO_DEBUG)
extern u32 rdmaio_io_failing;
#define RE_FAIL() \
({ \
	static atomic_t __fail_cnt = ATOMIC_INIT(1); \
	static atomic_t __fail_hop = ATOMIC_INIT(1); \
	bool __ret = false; \
	if (rdmaio_io_failing && atomic_dec_return(&__fail_cnt) <= 0) { \
		atomic_add(atomic_inc_return(&__fail_hop), &__fail_cnt); \
		TRACE("RE: fail!!!\n"); \
		__ret = true; \
	} \
	__ret; \
})
#define RE(func, err) (RE_FAIL() ? err : (func))
#define RE_PTR(func, err) (RE_FAIL() ? ERR_PTR(err) : (func))
#define RE_NULL(func) (RE_FAIL() ? NULL : (func))
#define RE_SET(var, val) { if (RE_FAIL()) var = val; }
#else
#define RE(func, err) func
#define RE_PTR(func, err) func
#define RE_NULL(func) func
#define RE_SET(var, val)
#endif

#define RE_INV(func) RE(func, -EINVAL)
#define RE_PTR_INV(func) RE_PTR(func, -EINVAL)

struct pcs_sgl_buf
{
	struct page **pages;
	size_t pg_cnt;
	void (*page_clean)(struct page *page);

	struct scatterlist *sgl;
	size_t sg_cnt;
};

int pcs_sgl_buf_init_from_msg(struct pcs_sgl_buf *sbuf, struct pcs_msg *msg,
			      size_t offset, size_t end_offset, gfp_t gfp, bool allow_gaps);
int pcs_sgl_buf_init(struct pcs_sgl_buf *sbuf, size_t size, gfp_t gfp);
void pcs_sgl_buf_destroy(struct pcs_sgl_buf *sbuf);

struct pcs_ib_mr_pool
{
	struct ib_pd *pd;
	enum ib_mr_type mr_type;
	u32 max_num_sg;
	size_t mr_cnt;

	spinlock_t lock;

	struct list_head mr_list;
	size_t used_mrs;
};

int pcs_ib_mr_pool_init(struct pcs_ib_mr_pool *pool, struct ib_pd *pd,
			enum ib_mr_type mr_type, u32 max_num_sg, size_t mr_cnt);
void pcs_ib_mr_pool_destroy(struct pcs_ib_mr_pool *pool);

struct ib_mr* pcs_ib_mr_pool_get(struct pcs_ib_mr_pool *pool);
void pcs_ib_mr_pool_put(struct pcs_ib_mr_pool *pool, struct ib_mr *mr);

struct pcs_rdma_rw
{
	struct ib_device *dev;
	enum dma_data_direction dir;

	struct pcs_sgl_buf sbuf;

	struct ib_sge *sges;
	struct ib_rdma_wr *wrs;
	size_t nr_wrs;
};

int pcs_rdma_rw_init_from_msg(struct pcs_rdma_rw *rw, struct ib_device *dev,
			      enum dma_data_direction dir, u64 remote_addr, u32 rkey,
			      u32 local_dma_lkey, struct pcs_msg *msg, size_t offset,
			      size_t end_offset, gfp_t gfp, size_t sge_per_wr);
void pcs_rdma_rw_destroy(struct pcs_rdma_rw *rw);

struct pcs_rdma_mr
{
	struct list_head entry;

	struct ib_device *dev;
	struct ib_pd *pd;
	enum dma_data_direction dir;
	size_t size;
	struct pcs_ib_mr_pool *ib_mr_pool;

	struct pcs_sgl_buf sbuf;
	struct ib_mr *mr;

	struct ib_send_wr inv_wr;
	struct ib_reg_wr reg_wr;

	struct ib_send_wr *first_wr;
	struct ib_send_wr *last_wr;
};

int pcs_rdma_mr_init_from_msg(struct pcs_rdma_mr *mr, struct ib_device *dev,
			      struct ib_pd *pd, enum dma_data_direction dir, struct pcs_msg *msg,
			      size_t offset, size_t end_offset, gfp_t gfp,
			      struct pcs_ib_mr_pool *ib_mr_pool);
int pcs_rdma_mr_init(struct pcs_rdma_mr *mr, struct ib_device *dev,
		     struct ib_pd *pd, enum dma_data_direction dir, size_t size,
		     gfp_t gfp, struct pcs_ib_mr_pool *ib_mr_pool);
void pcs_rdma_mr_destroy(struct pcs_rdma_mr *mr);

struct pcs_rdma_mr* pcs_rdma_mr_alloc(struct ib_device *dev, struct ib_pd *pd,
				      enum dma_data_direction dir, size_t size, gfp_t gfp,
				      struct pcs_ib_mr_pool *ib_mr_pool);
void pcs_rdma_mr_free(struct pcs_rdma_mr *mr);

void pcs_rdma_mr_sync_for_cpu(struct pcs_rdma_mr *mr, size_t size);
void pcs_rdma_mr_sync_for_device(struct pcs_rdma_mr *mr, size_t size);

int pcs_rdma_mr_sync_for_msg(struct pcs_rdma_mr *mr, struct pcs_msg *msg,
			     size_t offset, size_t end_offset, bool to_msg);

struct pcs_rdma_mr_pool
{
	size_t mr_size;
	size_t mr_cnt;
	struct ib_device *dev;
	struct ib_pd *pd;
	enum dma_data_direction dir;
	gfp_t gfp;
	struct pcs_ib_mr_pool *ib_mr_pool;

	spinlock_t lock;

	struct list_head mr_list;
	size_t used_mrs;
};

int pcs_rdma_mr_pool_init(struct pcs_rdma_mr_pool *pool, size_t mr_size,
			  size_t mr_cnt, struct ib_device *dev, struct ib_pd *pd,
			  enum dma_data_direction dir, gfp_t gfp,
			  struct pcs_ib_mr_pool *ib_mr_pool);
void pcs_rdma_mr_pool_destroy(struct pcs_rdma_mr_pool *pool);

struct pcs_rdma_mr* pcs_rdma_mr_pool_get(struct pcs_rdma_mr_pool *pool);
void pcs_rdma_mr_pool_put(struct pcs_rdma_mr_pool *pool,
			  struct pcs_rdma_mr *mr);

struct pcs_rdma_msg
{
	struct pcs_msg *msg;
	size_t offset;
	size_t end_offset;

	struct pcs_rdma_mr_pool *pool;
	struct pcs_rdma_mr *mr;
	struct pcs_rdma_mr _inline_mr;
	void (*cleanup)(struct pcs_rdma_msg *rdma_msg);

	u32 lkey;
	u32 rkey;
	u64 iova;

	struct ib_send_wr *first_wr;
	struct ib_send_wr *last_wr;
};

int pcs_rdma_msg_init(struct pcs_rdma_msg *rdma_msg, struct pcs_msg *msg,
		      size_t offset, size_t end_offset, struct pcs_rdma_mr_pool *pool,
		      bool try_to_map);
void pcs_rdma_msg_destroy(struct pcs_rdma_msg *rdma_msg);

#endif /* _PCS_RMDA_RW_H_ */
