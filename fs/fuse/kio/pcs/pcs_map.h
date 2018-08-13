#ifndef _PCS_MAP_H_
#define _PCS_MAP_H_ 1

#include "pcs_client_types.h"
#include "pcs_mds_prot.h"
#include "pcs_flow_detect.h"
#include "log.h"

struct pcs_dentry_info;
struct pcs_int_request;

#define PCS_MAP_LIMIT		4096

#define PCS_SYNC_TIMEOUT		(20 * HZ)

#define PCS_REPLICATION_BLACKLIST_TIMEOUT  HZ

//// TODO:
#define PCS_MAP_MIN_REBALANCE_TIMEOUT	(HZ / 5)
#define PCS_MAP_MAX_REBALANCE_TIMEOUT	(60 * HZ)

#define PCS_TWEAK_REBALANCE_ALWAYS	1
#define PCS_TWEAK_IGNORE_SEQUENTIAL	2
#define PCS_TWEAK_USE_FLOW_LOAD		4
#define PCS_TWEAK_USE_FLOW_WEIGHT	8

struct pcs_cs_link
{
	struct pcs_cs __rcu *cs;
	int		index;
	int		addr_serno;
	struct list_head	link;  /* Link in list of maps routed via cs,
					* head is cs->map_list */
};

/*
 * PCS_MAP_DEAD		- mapping is under destruction
 * PCS_MAP_NEW		- version is invalid
 * PCS_MAP_READABLE	- read IO requests can be sent using this map.
 * PCS_MAP_WRITEABLE	- read/write IO requests can be sent using this map.
 * PCS_MAP_RESOLVING	- map is under resolution. If PCS_MAP_WRITEABLE/READABLE
 * PCS_MAP_ERROR	- some error when communicating to CS happened. map requires revalidation.
 *			  version is valid, but most likely will be obsoleted.
 */
enum
{
	PCS_MAP_READABLE	= 1,
	PCS_MAP_WRITEABLE	= 2,
	PCS_MAP_RESOLVING	= 4,
	PCS_MAP_ERROR		= 8,
	PCS_MAP_NEW		= 0x10,
	PCS_MAP_DEAD		= 0x20,
	PCS_MAP_EOF		= 0x40,
};

enum
{
	PCS_MAP_DIRTY		= 1,
	PCS_MAP_FLUSHING	= 2,
	PCS_MAP_DIRTY_GC	= 4,
	PCS_MAP_CLIENT_SIZE	= 8,	/* chunk size is controlled by client */
	PCS_MAP_CLIENT_ALLOC	= 0x10,	/* chunk allocation is controlled by client */
	PCS_MAP_CLIENT_PSIZE	= 0x20, /* physical size of chunk on CS must be transmitted to MDS */
};

struct cs_sync_state
{
	PCS_INTEGRITY_SEQ_T	dirty_integrity;
	PCS_SYNC_SEQ_T		dirty_epoch;
	PCS_SYNC_SEQ_T		dirty_seq;
	PCS_SYNC_SEQ_T		sync_epoch;
	PCS_SYNC_SEQ_T		sync_seq;
};

struct pcs_cs_record
{
	struct pcs_cs_info	info;
	struct cs_sync_state	sync;
	struct pcs_cs_link	cslink;
};

struct pcs_cs_list
{
	struct pcs_map_entry __rcu *map;		/* Currently modified under
							   ::map->lock */
	atomic_t		refcnt;
	atomic_t		seq_read_in_flight;
	int			read_index;		/* volatile read hint */
	unsigned long		blacklist;		/* Atomic bit field */
	abs_time_t		blacklist_expires;	/* volatile blacklist stamp */
	abs_time_t		select_stamp;		/* volatile read hint stamp */
	/* members below are immutable accross cslist life time */
#define CSL_FL_HAS_LOCAL	1
	unsigned int		flags;
	u64                     serno;
	int			read_timeout;
	int			write_timeout;
	int			nsrv;
	PCS_MAP_VERSION_T	version;		/* version inherented from map */
	struct pcs_cs_record	cs[0];
};

/* TODO, LOCKING!!!!!
 * the only immutable values are id and
 */
struct pcs_map_entry
{
	unsigned long		index;
	union {
		struct list_head lru_link;
		struct rcu_head	 rcu;
	};
	struct pcs_mapping	*mapping;
	struct pcs_map_set	*maps;

	spinlock_t		lock;
	int			state;
	int			flags;
	atomic_t		__refcnt;
	u16			mds_flags;
	u64			res_offset;

	u32			chunk_psize;

	PCS_MAP_VERSION_T	version;
	PCS_CHUNK_UID_T		id;

	pcs_error_t		iofailure;
	unsigned long long	error_tstamp;

	struct delayed_work	sync_work;
	struct pcs_cs_list	*cs_list;
	struct list_head	queue;
};

extern struct kmem_cache *pcs_map_cachep;

static inline u64 map_chunk_start(struct pcs_map_entry *m)
{
	return m->index << m->mapping->chunk_size_bits;
}

static inline u64 map_chunk_end(struct pcs_map_entry *m)
{
	return (m->index +1) << m->mapping->chunk_size_bits;
}

static inline struct pcs_dentry_info * pcs_dentry_from_mapping(struct pcs_mapping * mapping)
{
	return container_of(mapping, struct pcs_dentry_info, mapping);
}

static inline struct pcs_dentry_info * pcs_dentry_from_map(struct pcs_map_entry * m)
{
	return pcs_dentry_from_mapping(m->mapping);
}

static inline struct pcs_cluster_core *cc_from_map(struct pcs_map_entry * m)
{
	return pcs_dentry_from_mapping(m->mapping)->cluster;
}

void pcs_mapping_init(struct pcs_cluster_core *cc, struct pcs_mapping * mapping);
void pcs_mapping_open(struct pcs_mapping * mapping);
void pcs_mapping_invalidate(struct pcs_mapping * mapping);
void pcs_mapping_deinit(struct pcs_mapping * mapping);
void pcs_mapping_truncate(struct pcs_int_request *ireq, u64 old_size);
void process_ireq_truncate(struct pcs_int_request *ireq);

struct pcs_map_entry * pcs_find_get_map(struct pcs_dentry_info * de, u64 chunk);
void map_submit(struct pcs_map_entry * m, struct pcs_int_request *ireq);
void map_notify_iochunk_error(struct pcs_int_request *ireq);
void map_notify_soft_error(struct pcs_int_request *ireq);
void __pcs_map_put(struct pcs_map_entry *m);

void pcs_deaccount_ireq(struct pcs_int_request *ireq, pcs_error_t *);

void cs_blacklist(struct pcs_cs * cs, int error, char * reason);
void cs_whitelist(struct pcs_cs * cs, char * reason);
void pcs_map_notify_addr_change(struct pcs_cs * cs);
void pcs_map_force_reselect(struct pcs_cs * cs);

struct pcs_msg;
void pcs_map_verify_sync_state(struct pcs_dentry_info * de, struct pcs_int_request *ireq, struct pcs_msg *);
void map_inject_flush_req(struct pcs_int_request *ireq);
void process_flush_req(struct pcs_int_request *ireq);
int map_check_limit(struct pcs_map_entry * map, struct pcs_int_request *ireq);
int pcs_cslist_submit(struct pcs_int_request *ireq, struct pcs_cs_list *csl);
struct pcs_int_request * pcs_ireq_split(struct pcs_int_request *ireq, unsigned int iochunk, int noalign);
int  fuse_map_resolve(struct pcs_map_entry * m, int direction);
struct pcs_ioc_getmap;
void pcs_map_complete(struct pcs_map_entry *m, struct pcs_ioc_getmap *omap);
int pcs_map_encode_req(struct pcs_map_entry*m, struct pcs_ioc_getmap *map, int direction);
void map_truncate_tail(struct pcs_mapping *mapping, u64 offset);
void pcs_cs_truncate_maps(struct pcs_cs *cs);
unsigned long pcs_map_shrink_scan(struct shrinker *,  struct shrink_control *sc);
void ireq_drop_tokens(struct pcs_int_request * ireq);

#define MAP_FMT	"(%p) 0x%lld s:%x" DENTRY_FMT
#define MAP_ARGS(m) (m), (long long)(m)->index,	 (m)->state, DENTRY_ARGS(pcs_dentry_from_map((m)))

static inline void pcs_map_put(struct pcs_map_entry *m)
{
	TRACE("m(%p)->index:%ld ref:%d \n", m, m->index, atomic_read(&m->__refcnt));

	BUG_ON(atomic_read(&m->__refcnt) <= 0);
	if (atomic_dec_and_lock(&m->__refcnt, &m->lock))
		__pcs_map_put(m);
}

static inline void map_add_lru(struct pcs_map_entry *m)
{
	assert_spin_locked(&m->lock);
	if (m->flags & PCS_MAP_DIRTY)
		list_lru_add(&m->maps->dirty_lru, &m->lru_link);
	else
		list_lru_add(&m->maps->lru, &m->lru_link);
}

static inline void map_del_lru(struct pcs_map_entry *m)
{
	assert_spin_locked(&m->lock);
	if (m->flags & PCS_MAP_DIRTY)
		list_lru_del(&m->maps->dirty_lru, &m->lru_link);
	else
		list_lru_del(&m->maps->lru, &m->lru_link);
}

static inline void pcs_map_put_locked(struct pcs_map_entry *m)
{
	TRACE("m(%p)->index:%ld ref:%d \n", m, m->index, atomic_read(&m->__refcnt));

	BUG_ON(atomic_read(&m->__refcnt) <= 0);
	BUG_ON(m->state & PCS_MAP_DEAD);

	if (atomic_dec_and_test(&m->__refcnt))
		map_add_lru(m);
}

static inline bool pcs_map_get_locked(struct pcs_map_entry *m)
{
	BUG_ON(atomic_read(&m->__refcnt) < 0);

	if (m->state & PCS_MAP_DEAD)
		return 0;

	TRACE( MAP_FMT " refcnt:%d\n", MAP_ARGS(m), atomic_read(&m->__refcnt));

	if (atomic_inc_return(&m->__refcnt) == 1)
		map_del_lru(m);

	return 1;
}

static inline struct pcs_map_entry *pcs_map_get(struct pcs_map_entry *m)
{
	spin_lock(&m->lock);
	if (!pcs_map_get_locked(m)) {
		spin_unlock(&m->lock);
		m = NULL;
	} else
		spin_unlock(&m->lock);

	return m;
}

static inline void pcs_map_invalidate_tail(struct pcs_mapping * mapping, u64 offset)
{
	unsigned long index = offset >> mapping->chunk_size_bits;

	map_truncate_tail(mapping, index << mapping->chunk_size_bits);
}
#endif /* _PCS_MAP_H_ */
