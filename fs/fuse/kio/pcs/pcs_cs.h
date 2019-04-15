#ifndef _PCS_CS_H_
#define _PCS_CS_H_ 1

#include "pcs_prot_types.h"
#include "pcs_perfcounters.h"

struct pcs_map_entry;

#define PCS_CS_INIT_CWND	(1*1024*1024)
#define PCS_CS_MAX_CWND		(16*1024*1024)
#define PCS_MAX_NETWORK_LATENCY	((2000*3)/4)
#define PCS_MAX_IO_LATENCY	(8*HZ)
#define PCS_MAX_READ_IO_LATENCY	(5*HZ)

/* io_prio received from MDS is valid during this time, otherwise it is stale and cannot be used */
#define PCS_CS_IO_PRIO_VALID_TIME	(60*HZ)

/* When CS is idle its latency halves after CS_LAT_DECAY_INTERVAL */
#define CS_LAT_DECAY_INTERVAL	(HZ/2)

/* When CS is active time constant is ln(2) * 2^CS_LAT_EWMA_LOG / IOPS,
 * so that with IOPS=100 and CS_LAT_EWMA_LOG=6 we have ~400ms
 */
#define CS_LAT_EWMA_LOG		(6)

#define PCS_CS_BLACKLIST_TIMER	(10*HZ)

#define PCS_FIEMAP_BUFSIZE     (128*1024)
#define PCS_FIEMAP_CHUNK_COUNT (PCS_FIEMAP_BUFSIZE/sizeof(struct pcs_cs_fiemap_rec))

enum {
	CS_SF_LOCAL,
	CS_SF_LOCAL_SOCK,
	CS_SF_INACTIVE,
	CS_SF_REPLICATING,
	CS_SF_FAILED,
	CS_SF_BLACKLISTED,
	CS_SF_ACTIVE,
};

struct pcs_cs {
	struct hlist_node	hlist;
	union {
		struct list_head lru_link;
		struct rcu_head	 rcu;
	};
	spinlock_t		lock;
	struct pcs_cs_set	*css;

	PCS_NODE_ID_T		id;

	unsigned int		in_flight;
	unsigned int		eff_cwnd;
	unsigned int		cwnd;
	unsigned int            ssthresh;
	int			cwr_state;
	atomic_t		latency_avg;
	unsigned int		net_latency_avg;
	unsigned int		in_flight_avg;
	unsigned int		last_latency;
	unsigned int		in_flight_hwm;
	abs_time_t		in_flight_hwm_stamp;
	abs_time_t		latency_stamp;
	abs_time_t		net_latency_stamp;
	abs_time_t		idle_stamp;
	struct list_head	cong_queue;
	int			cong_queue_len;
	struct list_head	active_list;

	pcs_cs_io_prio_t	io_prio;
	pcs_cs_net_prio_t	net_prio;
	u8			mds_flags;
	abs_time_t		io_prio_stamp;

	struct list_head	flow_lru;
	int			nflows;

	unsigned long		state;
	int			blacklist_reason;
	unsigned int		use_count; /* Protects cs against isolation */
	struct list_head	bl_link;
	unsigned		is_dead:1;


	int			addr_serno;
	PCS_NET_ADDR_T		addr;

	struct pcs_rpc		*rpc;

	int			nmaps;
	struct list_head	map_list;

	struct {
		struct pcs_perf_stat_cnt iolat;
		struct pcs_perf_stat_cnt netlat;
		struct pcs_perf_rate_cnt read_ops_rate;
		struct pcs_perf_rate_cnt write_ops_rate;
		struct pcs_perf_rate_cnt sync_ops_rate;
	} stat;
};

static inline void pcs_cs_init_cong_queue(struct pcs_cs *cs)
{
	INIT_LIST_HEAD(&cs->cong_queue);
	cs->cong_queue_len = 0;
}

static inline void pcs_cs_init_active_list(struct pcs_cs *cs)
{
	INIT_LIST_HEAD(&cs->active_list);
}

static inline void pcs_cs_activate_cong_queue(struct pcs_cs *cs)
{
	assert_spin_locked(&cs->lock);
	list_splice_tail_init(&cs->cong_queue, &cs->active_list);
}

int pcs_cs_cong_enqueue_cond(struct pcs_int_request *ireq, struct pcs_cs *cs);

#define PCS_CS_HASH_SIZE 1024

struct pcs_cs_set {
	struct hlist_head	ht[PCS_CS_HASH_SIZE];
	struct list_head	lru;
	struct list_head	bl_list;
	struct delayed_work	bl_work;
	unsigned int		ncs;
	spinlock_t		lock;
	atomic64_t		csl_serno_gen;
};

void pcs_cs_submit(struct pcs_cs *cs, struct pcs_int_request *ireq);
struct pcs_cs *pcs_cs_find_create(struct pcs_cs_set *csset, PCS_NODE_ID_T *id, PCS_NET_ADDR_T *addr, int local);
void pcs_cs_notify_error(struct pcs_cluster_core *cc, pcs_error_t *err);

void cs_update_io_latency(struct pcs_cs *cs, u32 lat);
unsigned int cs_get_avg_latency(struct pcs_cs *cs);
unsigned int __cs_get_avg_latency(struct pcs_cs *cs, abs_time_t now);
void cs_account_latency(struct pcs_cs *cs, unsigned int to_add);
void cs_update_net_latency(struct pcs_cs *cs, u32 lat);
unsigned int cs_get_avg_net_latency(struct pcs_cs *cs);
unsigned int __cs_get_avg_net_latency(struct pcs_cs *cs, abs_time_t now);
void cs_increment_in_flight(struct pcs_cs *cs, unsigned int to_add);
void cs_decrement_in_flight(struct pcs_cs *cs, unsigned int to_dec);
void cs_cwnd_use_or_lose(struct pcs_cs *cs);
unsigned int cs_get_avg_in_flight(struct pcs_cs *cs);

void pcs_csset_init(struct pcs_cs_set *css);
void pcs_csset_fini(struct pcs_cs_set *css);

struct pcs_cs *pcs_cs_alloc(struct pcs_cs_set *css, struct pcs_cluster_core *cc);

void cs_log_io_times(struct pcs_int_request *ireq, struct pcs_msg *resp, unsigned int max_iolat);
int pcs_cs_format_io_times(char *buf, int buflen, struct pcs_int_request *ireq, struct pcs_msg *resp);
void cs_set_io_times_logger(void (*logger)(struct pcs_int_request *ireq, struct pcs_msg *resp, u32 max_iolat, void *ctx), void *ctx);

int pcs_cs_for_each_entry(struct pcs_cs_set *set, int (*cb)(struct pcs_cs *cs, void *arg), void *arg);

void pcs_cs_update_stat(struct pcs_cs *cs, u32 iolat, u32 netlat, int op_type);

static inline void pcs_cs_stat_up(struct pcs_cs *cs)
{
#if 0
	/* TODO: temproraly disable perf counters */
	pcs_perfcounter_stat_up(&cs->stat.iolat);
	pcs_perfcounter_stat_up(&cs->stat.netlat);
	pcs_perfcounter_up_rate(&cs->stat.write_ops_rate);
	pcs_perfcounter_up_rate(&cs->stat.read_ops_rate);
	pcs_perfcounter_up_rate(&cs->stat.sync_ops_rate);
#endif
}

static inline bool cs_is_blacklisted(struct pcs_cs *cs)
{
	return test_bit(CS_SF_BLACKLISTED, &cs->state);
}

void pcs_cs_set_stat_up(struct pcs_cs_set *set);

#endif /* _PCS_CS_H_ */
