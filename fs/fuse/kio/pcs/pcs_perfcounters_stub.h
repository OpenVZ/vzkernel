#ifndef _PCS_PERFCOUNTERS_STUB_H_
#define _PCS_PERFCOUNTERS_STUB_H_ 1


struct pcs_perf_stat_cnt {
        u64     val_total;
        u64     events;
        u64     curr_max;
        u64     events_last;
        u64     avg;
        u64     maximum;
};

/* Generic event rate counter */
struct pcs_perf_rate_cnt {
        /* Total number of events */
        u64     total;
        u64     last_total;
        /* The number of events for the last 5 sec interval */
        u64     rate;
        /* The number of events per 5 sec averaged over 1, 5, 15 min and shifted by AV_SHIFT to the left */
        u64     av1;
        u64     av5;
};


static inline void pcs_perfcounter_stat_update(struct pcs_perf_stat_cnt *cnt, u64 val) __attribute__((unused));

static inline void pcs_perfcounter_stat_update(struct pcs_perf_stat_cnt *cnt, u64 val) {}
#endif //_PCS_PERFCOUNTERS_STUB_H_
