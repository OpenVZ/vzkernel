struct ploop_pushbackup_desc;

struct ploop_pushbackup_desc *ploop_pb_alloc(struct ploop_device *plo);
int ploop_pb_init(struct ploop_pushbackup_desc *pbd, __u8 *uuid, bool full);
void ploop_pb_fini(struct ploop_pushbackup_desc *pbd);
int ploop_pb_copy_cbt_to_user(struct ploop_pushbackup_desc *pbd, char *user_addr);
unsigned long ploop_pb_stop(struct ploop_pushbackup_desc *pbd);
int ploop_pb_check_uuid(struct ploop_pushbackup_desc *pbd, __u8 *uuid);
