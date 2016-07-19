struct ploop_pushbackup_desc;

struct ploop_pushbackup_desc *ploop_pb_alloc(struct ploop_device *plo);
int ploop_pb_init(struct ploop_pushbackup_desc *pbd, __u8 *uuid, bool full);
void ploop_pb_fini(struct ploop_pushbackup_desc *pbd);
int ploop_pb_copy_cbt_to_user(struct ploop_pushbackup_desc *pbd, char *user_addr);
unsigned long ploop_pb_stop(struct ploop_pushbackup_desc *pbd, bool do_merge);
int ploop_pb_check_uuid(struct ploop_pushbackup_desc *pbd, __u8 *uuid);
int ploop_pb_get_uuid(struct ploop_pushbackup_desc *pbd, __u8 *uuid);

int ploop_pb_get_pending(struct ploop_pushbackup_desc *pbd,
			 cluster_t *clu_p, cluster_t *len_p, unsigned n_done);
int ploop_pb_peek(struct ploop_pushbackup_desc *pbd,
		  cluster_t *clu_p, cluster_t *len_p, unsigned n_done);
void ploop_pb_put_reported(struct ploop_pushbackup_desc *pbd,
			   cluster_t clu, cluster_t len);

void ploop_pb_clear_bit(struct ploop_pushbackup_desc *pbd, cluster_t clu);
bool ploop_pb_check_bit(struct ploop_pushbackup_desc *pbd, cluster_t clu);
bool ploop_pb_check_and_clear_bit(struct ploop_pushbackup_desc *pbd, cluster_t clu);

int ploop_pb_preq_add_pending(struct ploop_pushbackup_desc *pbd,
			       struct ploop_request *preq);

int ploop_pb_destroy(struct ploop_device *plo, __u32 *status);

bool ploop_pb_bio_detained(struct ploop_pushbackup_desc *pbd, struct bio *bio);
bool ploop_pb_bio_list_empty(struct ploop_pushbackup_desc *pbd);
struct bio *ploop_pb_bio_get(struct ploop_pushbackup_desc *pbd);
void ploop_pb_bio_list_merge(struct ploop_pushbackup_desc *pbd, struct bio_list *tmp);
