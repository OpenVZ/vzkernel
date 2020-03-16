#include <net/sock.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/tcp.h>

#include <crypto/hash.h>
#include <crypto/md5.h>

#include "pcs_types.h"
#include "pcs_sock_io.h"
#include "pcs_rpc.h"
#include "pcs_cluster.h"
#include "log.h"
#include "fuse_ktrace.h"

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
			GFP_KERNEL);
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
	struct shash_desc *desc;
	int err;

	desc = kmalloc(sizeof(*desc), GFP_KERNEL);
	if (!desc)
		return -ENOMEM;

	desc->tfm = crypto_alloc_shash("md5", 0, CRYPTO_ALG_ASYNC);
	if(IS_ERR(desc->tfm)) {
		err = PTR_ERR(desc->tfm);
		goto fail1;
	}

	err = crypto_shash_init(desc);
	if (err)
		goto fail2;
	err = crypto_shash_update(desc, data, len);
	if (err)
		goto fail2;
	err = crypto_shash_final(desc, result);
fail2:
	crypto_free_shash(desc->tfm);
fail1:
	kfree(desc);

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
	lock->fl_flags = FL_FLOCK;
	lock->fl_type = F_WRLCK;
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

static inline void pcs_sock_keepalive(struct socket *sock)
{
	int val;

	val = 1;
	kernel_setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
			  (char *)&val, sizeof(val));
	val = 60;
	kernel_setsockopt(sock, SOL_TCP, TCP_KEEPIDLE,
			  (char *)&val, sizeof(val));
	val = 5;
	kernel_setsockopt(sock, SOL_TCP, TCP_KEEPCNT,
			  (char *)&val, sizeof(val));
	val = 5;
	kernel_setsockopt(sock, SOL_TCP, TCP_KEEPINTVL,
			  (char *)&val, sizeof(val));
}

static inline int pcs_sock_cork(struct socket *sock)
{
	int val = 1;
	if (kernel_setsockopt(sock, SOL_TCP, TCP_CORK, (char *)&val,
			      sizeof(val)) == 0)
		return 0;
	return -1;
}

static inline void pcs_sock_nodelay(struct socket *sock)
{
	int val = 1;
	kernel_setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&val,
			  sizeof(val));
}

static int send_buf(struct socket *sock, u8 *buf, size_t size)
{
	struct msghdr msg = {
		.msg_flags = MSG_WAITALL | MSG_NOSIGNAL,
	};
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = size,
	};
	int ret = kernel_sendmsg(sock, &msg, &iov, 1, size);
	return ret < 0 ? ret : 0;
}

static int recv_buf(struct socket *sock, u8 *buf, size_t size)
{
	struct msghdr msg = {
		.msg_flags = MSG_WAITALL | MSG_NOSIGNAL,
	};
	struct kvec iov = {
		.iov_base = buf,
		.iov_len = size,
	};
	int ret = kernel_recvmsg(sock, &msg, &iov, 1, size,
				 MSG_WAITALL | MSG_NOSIGNAL);
	if (ret < 0)
		return ret;
	return ret != size ? -EPROTO : 0;
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

	err = send_buf(ep->conn->socket, (u8*)au, msg_sz);
	if (err)
		TRACE("Can't send au msg, err: %d", err);
	pcs_free_msg(msg);

	return err;
}

static int recv_auth_msg(struct pcs_rpc *ep, void *data, size_t size, int state)
{
	struct pcs_rpc_auth *au;
	size_t fixed_sz = sizeof(struct pcs_rpc_auth) +
			  round_up(size, PCS_RPC_AUTH_PAYLOAD_ALIGN);
	struct pcs_msg *msg;
	int err;

	msg = pcs_rpc_alloc_output_msg(fixed_sz);
	if (!msg) {
		TRACE("Can't alloc auth msg");
		return -ENOMEM;
	}

	err = recv_buf(ep->conn->socket, msg->_inline_buffer, fixed_sz);
	if (err) {
		TRACE("Can't recv auth msg(%d), err: %lu", err, fixed_sz);
		goto fail;
	}
	au = (struct pcs_rpc_auth *)msg->_inline_buffer;

	/* Fatal stream format error */
	if (au->hdr.len < sizeof(au->hdr) || au->hdr.len > ep->params.max_msg_size) {
		TRACE("Bad message header %u %u\n", au->hdr.len, au->hdr.type);
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

	/* Load rest of the message if needed */
	if (au->hdr.len > fixed_sz) {
		size_t rest_sz = au->hdr.len - fixed_sz;
		while (rest_sz) {
			size_t recv_sz = min(fixed_sz, rest_sz);
			err = recv_buf(ep->conn->socket, msg->_inline_buffer,
				       recv_sz);
			if (err) {
				TRACE("Can't recv auth msg(%d), err: %lu",
				      err, recv_sz);
				goto fail;
			}
			rest_sz -= recv_sz;
		}
	}

fail:
	pcs_free_msg(msg);
	return err;
}

static int pcs_do_auth_digest(struct pcs_rpc *ep)
{
	struct {
		u8 key[DIGEST_KEY_LEN];
		u8 salt[DIGEST_SALT_LEN];
	} auth_cfg;
	struct digest_hello_msg hi;
	struct digest_srv_salt_msg slt;
	struct digest_msg digest;
	struct digest_hmac_msg hmac;
	char *cluster_name = cc_from_rpc(ep->eng)->cluster_name;
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

enum {
	PCS_AUTH_DIGEST = 0,
};

static int rpc_client_start_auth(struct pcs_rpc *ep, int auth_type)
{
	switch (auth_type) {
		case PCS_AUTH_DIGEST:
			return pcs_do_auth_digest(ep);
		default:
			BUG();
	}
	return -EOPNOTSUPP;
}

int pcs_netaddr2sockaddr(PCS_NET_ADDR_T const* addr, struct sockaddr *sa, int *salen)
{
	BUG_ON(!sa);
	if (addr->type == PCS_ADDRTYPE_IP || addr->type == PCS_ADDRTYPE_RDMA) {
		struct sockaddr_in *saddr4 = (struct sockaddr_in *)sa;
		*saddr4 = (struct sockaddr_in) {
			.sin_family = AF_INET,
			.sin_port = (u16)addr->port,
		};
		memcpy(&saddr4->sin_addr, addr->address, sizeof(saddr4->sin_addr));
		*salen = sizeof(*saddr4);
	} else if (addr->type == PCS_ADDRTYPE_IP6) {
		struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)sa;
		*saddr6 = (struct sockaddr_in6) {
			.sin6_family = AF_INET6,
			.sin6_port = (u16)addr->port,
		};
		memcpy(&saddr6->sin6_addr, addr->address, sizeof(saddr6->sin6_addr));
		*salen = sizeof(*saddr6);
	} else
		return -EINVAL;

	return 0;
}

void pcs_sockconnect_start(struct pcs_rpc *ep)
{
	struct pcs_sockio *sio;
	struct sockaddr *sa = &ep->sh.sa;
	struct socket *sock;
	int err, alloc_max = ep->params.alloc_hdr_size;

	BUG_ON(!mutex_is_locked(&ep->mutex));

	sio = kzalloc(sizeof(struct pcs_sockio) + alloc_max, GFP_NOIO);
	if (!sio) {
		TRACE("Can't allocate sio\n");
		goto fail;
	}

	INIT_LIST_HEAD(&sio->write_queue);
	iov_iter_init_bad(&sio->read_iter);
	iov_iter_init_bad(&sio->write_iter);
	sio->hdr_max = sizeof(struct pcs_rpc_hdr);
	sio->flags = sa->sa_family != AF_UNIX ? PCS_SOCK_F_CORK : 0;
	INIT_LIST_HEAD(&sio->ioconn.list);

	err = sock_create(sa->sa_family, SOCK_STREAM, 0, &sock);
	if (err < 0) {
		TRACE("Can't create socket: %d\n", err);
		goto fail2;
	}
	pcs_clear_error(&sio->error);

	err = sock->ops->connect(sock, sa, ep->sh.sa_len, O_NONBLOCK);
	if (err != 0 && err != -EINPROGRESS) {
		TRACE("Failed connection: %d\n", err);
		sock_release(sock);
		goto fail2;
	}
	pcs_sock_keepalive(sock);
	if (!pcs_sock_cork(sock))
		sio->flags |= PCS_SOCK_F_CORK;
	else
		pcs_sock_nodelay(sock);

	TRACE(PEER_FMT " ->state:%d sock:%p\n", PEER_ARGS(ep), ep->state, sock);
	cancel_delayed_work(&ep->timer_work);
	ep->retries++;

	ep->conn = &sio->ioconn;
	sio->parent = pcs_rpc_get(ep);
	sio->get_msg = rpc_get_hdr;
	sio->eof = rpc_eof_cb;
	sio->send_timeout = PCS_SIO_TIMEOUT;
	sio->ioconn.socket = sock;
	sio->ioconn.destruct = pcs_sock_ioconn_destruct;
	if (ep->gc)
		list_lru_add(&ep->gc->lru, &ep->lru_link);

	if (ep->flags & PCS_RPC_F_CLNT_PEER_ID)
		ep->flags |= PCS_RPC_F_PEER_ID;

	ep->state = PCS_RPC_AUTH;
	err = rpc_client_start_auth(ep, PCS_AUTH_DIGEST);
	if (err < 0) {
		FUSE_KLOG(cc_from_rpc(ep->eng)->fc, LOG_ERR,
			  "Authorization failed: %d", err);
		goto fail; /* since ep->conn is initialized,
			    * sio will be freed in pcs_rpc_reset()
			    */
	}
	write_lock_bh(&sock->sk->sk_callback_lock);
	/*
	 * Backup original callbaks.
	 * TCP and unix sockets do not have sk_user_data set.
	 * So we avoid taking sk_callback_lock in callbacks,
	 * since this seems to be able to result in performance.
	 */
	WARN_ON_ONCE(sock->sk->sk_user_data);
	sio->ioconn.orig.user_data = sock->sk->sk_user_data;
	sio->ioconn.orig.data_ready = sock->sk->sk_data_ready;
	sio->ioconn.orig.write_space = sock->sk->sk_write_space;
	sio->ioconn.orig.error_report = sock->sk->sk_error_report;

	sock->sk->sk_sndtimeo = PCS_SIO_TIMEOUT;
	sock->sk->sk_allocation = GFP_NOFS;

	rcu_assign_sk_user_data(sock->sk, sio);
	smp_wmb(); /* Pairs with smp_rmb() in callbacks */
	sock->sk->sk_data_ready = pcs_sk_data_ready;
	sock->sk->sk_write_space = pcs_sk_write_space;
	sock->sk->sk_error_report = pcs_sk_error_report;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	ep->state = PCS_RPC_APPWAIT;
	pcs_rpc_enable(ep, 0);
	return;
fail2:
	kfree(sio);
fail:
	pcs_rpc_reset(ep);
	return;
}
