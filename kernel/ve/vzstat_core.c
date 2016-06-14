/*
 *  kernel/ve/vzstat_core.c
 *
 *  Copyright (c) 2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/sched.h>
#include <linux/vzstat.h>

void KSTAT_PERF_ADD(struct kstat_perf_pcpu_struct *ptr, u64 real_time, u64 cpu_time)
{
	struct kstat_perf_pcpu_snap_struct *cur = get_cpu_ptr(ptr->cur);

	write_seqcount_begin(&cur->lock);
	cur->count++;
	if (cur->wall_maxdur < real_time)
		cur->wall_maxdur = real_time;
	cur->wall_tottime += real_time;
	if (cur->cpu_maxdur < cpu_time)
		cur->cpu_maxdur = cpu_time;
	cur->cpu_tottime += cpu_time;
	write_seqcount_end(&cur->lock);
	put_cpu_ptr(cur);
}

/*
 * Must be called with disabled interrupts to remove any possible
 * locks and seqcounts under write-lock and avoid this 3-way deadlock:
 *
 * timer interrupt:
 *	write_seqlock(&xtime_lock);
 *	 spin_lock_irqsave(&kstat_glb_lock);
 *
 * update_schedule_latency():
 *	spin_lock_irq(&kstat_glb_lock);
 *	 read_seqcount_begin(&cur->lock)
 *
 * some-interrupt during KSTAT_LAT_PCPU_ADD()
 *   KSTAT_LAT_PCPU_ADD()
 *    write_seqcount_begin(&cur->lock);
 *     <interrupt>
 *      ktime_get()
 *       read_seqcount_begin(&xtime_lock);
 */
void KSTAT_LAT_PCPU_ADD(struct kstat_lat_pcpu_struct *p, u64 dur)
{
	struct kstat_lat_pcpu_snap_struct *cur;
	seqcount_t *seq;

	cur = this_cpu_ptr(p->cur);
	seq = this_cpu_ptr(&kstat_pcpu_seq);

	write_seqcount_begin(seq);
	cur->count++;
	if (cur->maxlat < dur)
		cur->maxlat = dur;
	cur->totlat += dur;
	write_seqcount_end(seq);
}

/*
 * Move current statistics to last, clear last.
 * Serialization is the caller's due.
 */
void KSTAT_LAT_PCPU_UPDATE(struct kstat_lat_pcpu_struct *p)
{
	struct kstat_lat_pcpu_snap_struct snap, *cur;
	unsigned i, cpu;
	seqcount_t *seq;
	u64 m;

	memset(&p->last, 0, sizeof(p->last));
	for_each_online_cpu(cpu) {
		cur = per_cpu_ptr(p->cur, cpu);
		seq = per_cpu_ptr(&kstat_pcpu_seq, cpu);
		do {
			i = read_seqcount_begin(seq);
			memcpy(&snap, cur, sizeof(snap));
		} while (read_seqcount_retry(seq, i));
		/* 
		 * read above and this update of maxlat is not atomic,
		 * but this is OK, since it happens rarely and losing
		 * a couple of peaks is not essential. xemul
		 */
		cur->maxlat = 0;

		p->last.count += snap.count;
		p->last.totlat += snap.totlat;
		if (p->last.maxlat < snap.maxlat)
			p->last.maxlat = snap.maxlat;
	}

	m = (p->last.maxlat > p->max_snap ? p->last.maxlat : p->max_snap);
	CALC_LOAD(p->avg[0], EXP_1, m);
	CALC_LOAD(p->avg[1], EXP_5, m);
	CALC_LOAD(p->avg[2], EXP_15, m);
	/* reset max_snap to calculate it correctly next time */
	p->max_snap = 0;
}
EXPORT_SYMBOL(KSTAT_LAT_PCPU_UPDATE);
