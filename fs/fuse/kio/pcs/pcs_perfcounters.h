#ifndef _PCS_PERFCOUNTERS_H_
#define _PCS_PERFCOUNTERS_H_ 1

/* Average calculation */
#define AV_SHIFT  11
#define AV_EXP_1  1884 /* 1 min average */
#define AV_EXP_5  2014 /* 5 min average */
#define AV_EXP_15 2037 /* 15 min average */

/* The following macro update accumulated average value av producing the average left-shifted by AV_SHIFT bits */
#define AV_UPDATE(av, val, exp) (((av)*(exp)>>AV_SHIFT) + (val)*((1<<AV_SHIFT)-(exp)))

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
        u64	av15;
};

static inline void pcs_perfcounter_stat_update(struct pcs_perf_stat_cnt *cnt, u64 val)
{
	if (cnt->curr_max < val)
		cnt->curr_max = val;

	cnt->val_total += val;
	cnt->events++;
}

static inline void pcs_perfcounter_stat_up(struct pcs_perf_stat_cnt *cnt)
{
	cnt->avg = (cnt->events) ? cnt->val_total / cnt->events : 0;
	cnt->maximum = cnt->curr_max;
	cnt->events_last = cnt->events;
	cnt->val_total = cnt->events = cnt->curr_max = 0;
}

static inline void pcs_perfcounter_up_rate(struct pcs_perf_rate_cnt* cnt)
{
	BUG_ON(cnt->total < cnt->last_total);
	cnt->rate = cnt->total - cnt->last_total;
	cnt->last_total = cnt->total;
	cnt->av1  = AV_UPDATE(cnt->av1,  cnt->rate, AV_EXP_1);
	cnt->av5  = AV_UPDATE(cnt->av5,  cnt->rate, AV_EXP_5);
	cnt->av15 = AV_UPDATE(cnt->av15, cnt->rate, AV_EXP_15);
}

static inline u64 pcs_perfcounter_stat_max(struct pcs_perf_stat_cnt *cnt)
{
	return max(cnt->maximum, cnt->curr_max);
}

#endif /* _PCS_PERFCOUNTERS_H_ */
