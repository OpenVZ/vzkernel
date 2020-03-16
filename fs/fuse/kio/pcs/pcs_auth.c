#include <linux/fs.h>
#include <linux/types.h>

#include <crypto/hash.h>
#include <crypto/md5.h>

#include "pcs_types.h"
#include "pcs_rpc.h"
#include "pcs_auth.h"
#include "log.h"

#define PCS_CFG_DIR		"/etc/vstorage"
#define AUTH_DIGEST_NAME	"digest"
#define AUTH_DIGEST_NAME_LEN	(sizeof(AUTH_DIGEST_NAME) - 1)
#define PCS_KEYPATH_FMT		(PCS_CFG_DIR"/clusters/%s/auth_digest.key")
#define LOCK_FILE_PATH_FMT	(PCS_CFG_DIR"/clusters/%s/.digest_auth.lock")

enum
{
	PCS_AUTH_INITIAL = 0,	/* Basic states of auth handshake required for establish SSL connection,
				 * other authentication protocols can require more states
				 */
	PCS_AUTH_SEND_HELLO,	/* Client sends hello at connect */
	PCS_AUTH_SEND_SRV_CERT,	/* Server sends its cert. to client */
	PCS_AUTH_SEND_CN_CERT,	/* Client sends its cert. to server */
	PCS_AUTH_SRV_ACCEPT,	/* Server accept client's cert. */
};

#define DIGEST_AUTH_ID_LEN 32
#define DIGEST_SALT_LEN 16
#define DIGEST_KEY_LEN 32

__pre_packed struct digest_hello_msg {
	unsigned char md5_cn[MD5_DIGEST_SIZE];
} __packed;

__pre_packed struct digest_srv_salt_msg {
	unsigned char salt[DIGEST_SALT_LEN];
	unsigned char id[DIGEST_AUTH_ID_LEN];
} __packed;

#define HMAC_SHA512_HSIZE 64U

__pre_packed struct digest_hmac_msg {
	unsigned int size;
	unsigned char data[HMAC_SHA512_HSIZE];
} __packed;

__pre_packed struct digest_msg {
	unsigned char id[DIGEST_AUTH_ID_LEN];
	struct digest_hmac_msg hmac;
} __packed;

static int pcs_generate_hmac(u8 *key, size_t key_sz, u8 *in, size_t in_sz,
			     u8 *out, u32 *out_sz)
{
	struct crypto_shash *hmacalg;
	struct shash_desc *shash;
	int ret;

	hmacalg = crypto_alloc_shash("hmac(sha1)", 0, 0);
	if (IS_ERR(hmacalg)) {
		TRACE("hmacalg: could not allocate crypto %ld", PTR_ERR(hmacalg));
		return PTR_ERR(hmacalg);
	}

	ret = crypto_shash_setkey(hmacalg, key, key_sz);
	if (ret) {
		TRACE("crypto_shash_setkey failed: err %d", ret);
		goto fail1;
	}

	shash = kzalloc(sizeof(*shash) + crypto_shash_descsize(hmacalg),
			GFP_NOIO);
	if (!shash) {
		ret = -ENOMEM;
		goto fail1;
	}

	shash->tfm = hmacalg;
	shash->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	ret = crypto_shash_digest(shash, in, in_sz, out);
	if (ret)
		TRACE("crypto_shash_digest failed: %d", ret);

	*out_sz = crypto_shash_alg(shash->tfm)->digestsize;
	kfree(shash);
fail1:
	crypto_free_shash(hmacalg);
	return ret;
}

static int pcs_validate_hmac(struct digest_msg *digest, u8 *key, size_t key_sz,
			     u8 *data, u32 data_sz)
{
	u8 hmac[HMAC_SHA512_HSIZE];
	int err;

	err = pcs_generate_hmac(key, key_sz, digest->id, sizeof(digest->id),
				hmac, &data_sz);
	if (err)
		return err;

	return !memcmp(hmac, data, min(data_sz, HMAC_SHA512_HSIZE));
}

static int pcs_md5_hash(char *result, char *data, size_t len)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	int err;

	tfm = crypto_alloc_shash("md5", 0, 0);
	if(IS_ERR(tfm)) {
		TRACE("md5: could not allocate crypto %ld", PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm),
		       GFP_NOIO);
	if (!desc) {
		err = -ENOMEM;
		goto fail1;
	}

	desc->tfm = tfm;
	desc->flags = 0;

	err = crypto_shash_init(desc);
	if (err)
		goto fail2;
	err = crypto_shash_update(desc, data, len);
	if (err)
		goto fail2;
	err = crypto_shash_final(desc, result);
fail2:
	kfree(desc);
fail1:
	crypto_free_shash(tfm);

	return err;
}

static struct file *lock_key_file(char *cluster_name)
{
	char lockfile[sizeof(LOCK_FILE_PATH_FMT) + NAME_MAX];
	struct file_lock *lock;
	struct file *f;
	int err;

	snprintf(lockfile, sizeof(lockfile) - 1, LOCK_FILE_PATH_FMT,
		 cluster_name);
	f = filp_open(lockfile, O_CREAT | O_RDONLY | O_CLOEXEC,
		      S_IRUSR | S_IRGRP | S_IROTH);
	if (IS_ERR(f))
		return f;

	lock = locks_alloc_lock(1);
	if (!lock) {
		filp_close(f, NULL);
		return ERR_PTR(-ENOMEM);
	}
	lock->fl_file = f;
	lock->fl_pid = current->tgid;
	lock->fl_flags = FL_FLOCK/* | FL_SLEEP*/;
	lock->fl_type = F_RDLCK;
	lock->fl_end = OFFSET_MAX;

	err = locks_lock_file_wait(f, lock);
	if (err < 0) {
		filp_close(f, NULL);
		return ERR_PTR(err);
	}
	return f;
}

static int pcs_load_keyfile_auth(char *cluster_name, u8 *key_out, u32 len)
{
	char keyfile[sizeof(PCS_KEYPATH_FMT) + NAME_MAX];
	struct file *f, *flock;
	u64 offs = 0;
	int err;

	flock = lock_key_file(cluster_name);
	if (IS_ERR(flock)) {
		TRACE("Lock keyfile failed: %ld", PTR_ERR(flock));
		return PTR_ERR(flock);
	}

	snprintf(keyfile, sizeof(keyfile) - 1, PCS_KEYPATH_FMT, cluster_name);

	f = filp_open(keyfile, O_RDONLY, 0);
	if (IS_ERR(f)) {
		err = PTR_ERR(f);
		TRACE("Can't open keyfile auth: %s, err: %d", keyfile, err);
		goto out;
	}

	err = vfs_read(f, key_out, len, &offs);
	if (err < 0) {
		TRACE("Can't read keyfile: %s, err: %d", keyfile, err);
	} else if (err != len)
		TRACE("Can't read full key(req: %d, read: %d)", len, err);
	filp_close(f, NULL);
out:
	filp_close(flock, NULL);

	return err < 0 ? err : 0;
}

#define __str_len(s) (ARRAY_SIZE(s) - sizeof(*(s)))

/* Multiple payloads are supported. They are expected to have fixed alignment in between. */
#define PCS_RPC_AUTH_PAYLOAD_ALIGN 8

#define PCS_BUILD_VERSION "unknown"
#define MAX_BUILD_VERSION_LENGTH 30

static struct {
	struct pcs_rpc_payload p;
	char build_version[MAX_BUILD_VERSION_LENGTH+1];
} s_version_data = {
	{
		.len = __str_len(PCS_BUILD_VERSION),
		.type = PCS_RPC_BUILD_VERSION_PAYLOAD,
	},
	.build_version = PCS_BUILD_VERSION
};

static inline unsigned rpc_auth_payload_size(struct pcs_rpc_payload const* p) {
	return sizeof(*p) + p->len;
}

static inline unsigned rpc_auth_payload_size_aligned(struct pcs_rpc_payload const* p) {
	return round_up(rpc_auth_payload_size(p), PCS_RPC_AUTH_PAYLOAD_ALIGN);
}

static inline struct pcs_rpc_payload* rpc_auth_payload_next(struct pcs_rpc_payload* p) {
	return (void*)p + rpc_auth_payload_size_aligned(p);
}

#define PCS_RPC_DIGEST_PAYLOAD 13

struct pcs_rpc_auth
{
	struct pcs_rpc_hdr hdr;

	PCS_CLUSTER_ID_T cluster_id;	/* Cluster identity */
	PCS_NODE_ID_T sender_id;	/* Identity of sender */
	PCS_NODE_ID_T recipient_id;	/* Expected identity of recipient */
	u8 sender_role;			/* Role of sender (TEST/CN/CS/MDS) */
	u8 recipient_role;		/* Expected role of recipient */
	u8 flags;			/* Flags */
	u8 state;			/* State of auth handshake */
	u32 version;			/* Protocol version */
	struct pcs_host_info host;
	u32 reserved[3];
	u32 npayloads;
	struct pcs_rpc_payload payload;
} __attribute__((aligned(8)));


#define PCS_RPC_AUTH_REQ 8
#define PCS_RPC_AUTH_RESP (PCS_RPC_AUTH_REQ | PCS_RPC_DIRECTION)

static int send_auth_msg(struct pcs_rpc *ep, void *data, size_t size, int state)
{
	struct pcs_rpc_engine *eng = ep->eng;
	struct pcs_netio *netio = (struct pcs_netio *)ep->conn;
	struct pcs_rpc_auth *au;
	size_t msg_sz = sizeof(struct pcs_rpc_auth) +
			round_up(size, PCS_RPC_AUTH_PAYLOAD_ALIGN) +
			rpc_auth_payload_size_aligned(&s_version_data.p);
	struct pcs_msg *msg;
	int err;

	msg = pcs_rpc_alloc_output_msg(msg_sz);
	if (!msg) {
		TRACE("Can't alloc auth msg");
		return -ENOMEM;
	}

	au = (struct pcs_rpc_auth *)msg->_inline_buffer;
	*au = (struct pcs_rpc_auth) {
		.hdr.type = PCS_RPC_AUTH_REQ,
		.hdr.len = msg_sz,
		.cluster_id = eng->cluster_id,
		.sender_id = eng->local_id,
		.recipient_id = ep->peer_id,
		.recipient_role = ep->peer_role,
		.version = PCS_VERSION_CURRENT,
		.state = state,
		.host = eng->my_host,
		.npayloads = 2,
	};
	pcs_rpc_get_new_xid(eng, &au->hdr.xid);

	if (size) {
		au->payload.type = PCS_RPC_DIGEST_PAYLOAD;
		au->payload.len = size;
		memcpy(au + 1, data, size);
	}
	memcpy(rpc_auth_payload_next(&au->payload), &s_version_data,
	       rpc_auth_payload_size(&s_version_data.p));

	if (!(ep->flags & PCS_RPC_F_PEER_ID))
		au->flags |= PCS_RPC_AUTH_F_VOID_RECIPIENT;
	if (!(eng->flags & PCS_KNOWN_MYID)) {
		au->flags |= PCS_RPC_AUTH_F_VOID_SENDER;
		if (ep->flags & PCS_RPC_F_ACQ_ID)
			au->flags |= PCS_RPC_AUTH_F_ACQ_SENDER;
	}

	if (!(eng->flags & PCS_KNOWN_CLUSTERID))
		au->flags |= PCS_RPC_AUTH_F_VOID_CLUSTERID;

	TRACE("state=%d, type=%d, len=%d, msg_sz: %lu",
	      au->state, au->payload.type, au->payload.len, msg_sz);

	err = netio->tops->sync_send(netio, msg);
	if (err)
		TRACE("Can't send au msg, err: %d", err);
	pcs_free_msg(msg);

	return err;
}

static int recv_auth_msg(struct pcs_rpc *ep, void *data, size_t size, int state)
{
	struct pcs_netio *netio = (struct pcs_netio *)ep->conn;
	struct pcs_rpc_auth *au;
	size_t fixed_sz = sizeof(struct pcs_rpc_auth) +
			  round_up(size, PCS_RPC_AUTH_PAYLOAD_ALIGN);
	struct pcs_msg *msg = NULL;
	int err;

	err = netio->tops->sync_recv(netio, &msg);
	if (err) {
		TRACE("Can't recv auth msg, err: %d", err);
		goto fail;
	}
	au = (struct pcs_rpc_auth *)msg->_inline_buffer;

	/* Fatal stream format error */
	if (msg->size < fixed_sz || au->hdr.len < fixed_sz ||
	    au->hdr.len > ep->params.max_msg_size) {
		TRACE("Bad message header %d %u %u\n", msg->size, au->hdr.len,
		      au->hdr.type);
		err = -EPROTO;
		goto fail;
	}
	WARN_ON_ONCE(au->hdr.type != PCS_RPC_AUTH_RESP &&
		     au->hdr.type != PCS_RPC_ERROR_RESP);

	TRACE("state=%d, payloads:=%u, type=%d, len=%d", au->state,
	      au->npayloads, au->payload.type, au->payload.len);
	if (au->state != state) {
		TRACE("Unexpected state %d, should be %d", au->state, state);
		err = -EPROTO;
		goto fail;
	}
	if (au->flags & PCS_RPC_AUTH_F_VOID_CLUSTERID)
		TRACE("Wrong: auth void cluster");

	WARN_ON_ONCE(au->npayloads != 2);
	if (au->payload.len != size) {
		TRACE("Wrong auth payload %u %u, data_sz: %lu\n",
		      au->payload.len, au->payload.type, size);
		err = -EPROTO;
		goto fail;
	}
	WARN_ON_ONCE(au->payload.type != PCS_RPC_DIGEST_PAYLOAD);
	memcpy(data, &au->payload + 1, size);

fail:
	if (msg)
		pcs_free_msg(msg);
	return err;
}

static int pcs_do_auth_digest(struct pcs_rpc *ep, char *cluster_name)
{
	struct {
		u8 key[DIGEST_KEY_LEN];
		u8 salt[DIGEST_SALT_LEN];
	} auth_cfg;
	struct digest_hello_msg hi;
	struct digest_srv_salt_msg slt;
	struct digest_msg digest;
	struct digest_hmac_msg hmac;
	int err;

	err = pcs_load_keyfile_auth(cluster_name, (u8*)&auth_cfg, sizeof(auth_cfg));
	if (err)
		return err;

	err = pcs_md5_hash(hi.md5_cn, cluster_name, strlen(cluster_name));
	if (err) {
		TRACE("Can't calculate md5 from cluster name, err: %d", err);
		return err;
	}

	err = send_auth_msg(ep, &hi, sizeof(hi), PCS_AUTH_SEND_HELLO);
	if (err) {
		TRACE("Can't send hello auth msg, err: %d", err);
		return err;
	}

	err = recv_auth_msg(ep, &slt, sizeof(slt), PCS_AUTH_SEND_SRV_CERT);
	if (err) {
		TRACE("Can't receive salt auth msg, err: %d", err);
		return err;
	}

	if (memcmp(slt.salt, auth_cfg.salt, sizeof(auth_cfg.salt))) {
		TRACE("Server use different salt");
		return -EPROTO;
	}

	get_random_bytes(digest.id, sizeof(digest.id));
	digest.hmac.size = sizeof(digest.hmac.data);
	err = pcs_generate_hmac(auth_cfg.key, sizeof(auth_cfg.key), slt.id,
				sizeof(slt.id), digest.hmac.data,
				&digest.hmac.size);
	if (err) {
		TRACE("HMAC generate fail %d", err);
		return err;
	}

	err = send_auth_msg(ep, &digest, sizeof(digest), PCS_AUTH_SEND_CN_CERT);
	if (err) {
		TRACE("Can't send digest msg, err: %d", err);
		return err;
	}

	err = recv_auth_msg(ep, &hmac, sizeof(hmac), PCS_AUTH_SRV_ACCEPT);
	if (err) {
		TRACE("Can't receive hmac auth msg, err: %d", err);
		return err;
	}

	if (!pcs_validate_hmac(&digest, auth_cfg.key, sizeof(auth_cfg.key),
			       hmac.data, hmac.size)) {
		TRACE("Received bad digest");
		return -EPROTO;
	}

	err = send_auth_msg(ep, NULL, 0, PCS_AUTH_SRV_ACCEPT + 1);
	if (err)
		TRACE("Can't send auth srv accept msg, err: %d", err);

	return err;
}

int rpc_client_start_auth(struct pcs_rpc *ep, int auth_type, char *cluster_name)
{
	switch (auth_type) {
		case PCS_AUTH_DIGEST:
			return pcs_do_auth_digest(ep, cluster_name);
		default:
			BUG();
	}
	return -EOPNOTSUPP;
}
