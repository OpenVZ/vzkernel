#ifndef __FREEBLKS_H__
#define __FREEBLKS_H__

/* freeblks API - in-kernel balloon support */

/* init/fini stuff */
struct ploop_freeblks_desc *ploop_fb_init(struct ploop_device *plo);
void ploop_fb_fini(struct ploop_freeblks_desc *fbd, int err);
void ploop_fb_reinit(struct ploop_freeblks_desc *fbd, int err);
int ploop_fb_add_free_extent(struct ploop_freeblks_desc *fbd, cluster_t clu, iblock_t iblk, u32 len);
int ploop_fb_add_reloc_extent(struct ploop_freeblks_desc *fbd, cluster_t clu, iblock_t iblk, u32 len, u32 free);
void ploop_fb_lost_range_init(struct ploop_freeblks_desc *fbd, iblock_t first_lost_iblk);
void ploop_fb_relocation_start(struct ploop_freeblks_desc *fbd, __u32 n_scanned);
int ploop_discard_add_bio(struct ploop_freeblks_desc *fbd, struct bio *bio);

/* avoid direct access to freeblks internals */
int ploop_fb_get_n_relocated(struct ploop_freeblks_desc *fbd);
int ploop_fb_get_n_relocating(struct ploop_freeblks_desc *fbd);
int ploop_fb_get_n_free(struct ploop_freeblks_desc *fbd);
iblock_t ploop_fb_get_alloc_head(struct ploop_freeblks_desc *fbd);
int ploop_fb_get_lost_range_len(struct ploop_freeblks_desc *fbd);
iblock_t ploop_fb_get_first_lost_iblk(struct ploop_freeblks_desc *fbd);

/* get/set freezed level (for sanity checks) */
int ploop_fb_get_freezed_level(struct ploop_freeblks_desc *fbd);
void ploop_fb_set_freezed_level(struct ploop_freeblks_desc *fbd, int level);

/* maintain rb-tree of "in progress" relocation requests */
void ploop_fb_add_reloc_req(struct ploop_freeblks_desc *fbd, struct ploop_request *preq);
void ploop_fb_del_reloc_req(struct ploop_freeblks_desc *fbd, struct ploop_request *preq);
int ploop_fb_check_reloc_req(struct ploop_freeblks_desc *fbd, struct ploop_request *preq, unsigned long pin_state);

/* helper for ioctl(PLOOP_IOC_FBGET) */
int ploop_fb_copy_freeblks_to_user(struct ploop_freeblks_desc *fbd, void *arg,
				   struct ploop_freeblks_ctl *ctl);
int ploop_fb_filter_freeblks(struct ploop_freeblks_desc *fbd, unsigned long minlen);

/* get/put "zero index" request */
struct ploop_request *ploop_fb_get_zero_request(struct ploop_freeblks_desc *fbd);
void ploop_fb_put_zero_request(struct ploop_freeblks_desc *fbd, struct ploop_request *preq);

/* get/put block to relocate */
int ploop_fb_get_reloc_block(struct ploop_freeblks_desc *fbd, cluster_t *from_clu, iblock_t *from_iblk,
			     cluster_t *to_clu, iblock_t *to_iblk, u32 *free);
void ploop_fb_relocate_req_completed(struct ploop_freeblks_desc *fbd);

/* get free block to reuse */
int ploop_fb_get_free_block(struct ploop_freeblks_desc *fbd, cluster_t *clu, iblock_t *iblk);

#endif
