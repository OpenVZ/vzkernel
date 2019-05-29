#ifndef _PCS_PERFCOUNTERS_H_
#define _PCS_PERFCOUNTERS_H_ 1

/* Generic event rate counter */
struct pcs_perf_rate_cnt {
        /* Total number of events */
        u64     total;
        u64     last_total;
        /* The number of events for the last 5 sec interval */
        u64     rate;
};

static inline void pcs_perfcounter_up_rate(struct pcs_perf_rate_cnt* cnt)
{
	BUG_ON(cnt->total < cnt->last_total);
	cnt->rate = cnt->total - cnt->last_total;
	cnt->last_total = cnt->total;
}

#endif /* _PCS_PERFCOUNTERS_H_ */
