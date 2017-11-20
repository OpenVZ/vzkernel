/*
 * kernel/ve/vzstat.c
 *
 * Copyright (c) 2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/ve.h>
#include <linux/ve_proto.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kernel_stat.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/suspend.h>
#include <linux/interrupt.h>
#include <linux/mmzone.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

#include <linux/vzstat.h>

/* local variables */
static struct task_struct *vzstat_thread_tsk;

static const char *alloc_descr[KSTAT_ALLOCSTAT_NR] = {
	"alocatomic:",
	"aloclow:",
	"alochigh:",
	"aloclowmp:",
	"alochighmp:"
};

/*
 * ------------------------------------------------------------------------
 * Kernel protection: kernel code checksumming
 * ------------------------------------------------------------------------
 */
#ifdef CONFIG_VE_KERNEL_CSUM

#ifdef __x86_64__
/* skip init_level4_pgt */
#define KERNEL_PROT_START	((unsigned long)(&_stext) + 0x2000)
#else
#define KERNEL_PROT_START	((unsigned long)(&_stext))
#endif
#define KERNEL_PROT_END		((unsigned long)(&_etext))
#define CSALIGN(value, size)	((value + (size - 1)) & ~(size - 1))

void kernel_text_csum_check(void)
{
#define CSUM_NR	2
	static unsigned long text_csum[CSUM_NR], text_csumed, csum_time;
	unsigned long start, end, ptr, csum[CSUM_NR];
	int i;

	if (jiffies - csum_time < 60*HZ)
		return;

	csum_time = jiffies;
	for (i = 0; i < CSUM_NR; i++) csum[i] = 0;
	start = CSALIGN(KERNEL_PROT_START, sizeof(csum[0]));
	end = CSALIGN(KERNEL_PROT_END, sizeof(csum[0]));

	for (ptr = start; ptr < end; ptr += sizeof(csum[0])) {
		unsigned long i = *(unsigned long*)ptr;
		csum[0] = csum[0] + i;
		csum[1] = (csum[1] ^ i) + ((csum[1] << 1) + (csum[1] >> 31));
		cond_resched();
	}

	if (!text_csumed) {
		for (i = 0; i < CSUM_NR; i++) text_csum[i] = csum[i];
		text_csumed = 1;
		return;
	}
	for (i = 0; i < CSUM_NR; i++)
		if (text_csum[i] != csum[i]) {
			printk(KERN_EMERG "Kernel checksum %d changed "
				"(csum%d=%08lx, onboot csum%d=%08lx)\n",
				i, i, csum[i], i, text_csum[i]);
			kernel_text_csum_broken++;
		}
}

#endif

/*
 * ------------------------------------------------------------------------
 * Latency update and show functions
 * ------------------------------------------------------------------------
 */
static inline u64 get_task_lat(struct task_struct *t, u64 now)
{
	u64 wstamp;

	wstamp = t->se.statistics->wait_start;
	if (wstamp && now > wstamp && now - wstamp < (1ULL << 63))
		return now - wstamp;
	return 0;
}

static void update_max_sched_latency_snap(void)
{
	struct task_struct *t, *g;
	u64 now, max, tmp;
	struct kstat_lat_pcpu_struct *st;

	max = 0;
	qread_lock(&tasklist_lock);
	now = ktime_to_ns(ktime_get());
	do_each_thread(g, t) {
		if (likely(t->state != TASK_RUNNING))
			continue;

		tmp = get_task_lat(t, now);
		if (max < tmp)
			max = tmp;
		st = &t->task_ve->sched_lat_ve;
		if (st->max_snap < tmp)
			st->max_snap = tmp;
	} while_each_thread(g, t);
	qread_unlock(&tasklist_lock);
	kstat_glob.sched_lat.max_snap = max;
}

static void update_schedule_latency(void)
{
	/*
	 * global scheduling latency is updated in schedule() and
	 * update_max_sched_latency_snap(). The latter function guarantees
	 * that tasks which do not recieve CPU time are still accounted in
	 * scheduling latency
	 */
	update_max_sched_latency_snap();

	spin_lock_irq(&kstat_glb_lock);
	KSTAT_LAT_PCPU_UPDATE(&kstat_glob.sched_lat);
	spin_unlock_irq(&kstat_glb_lock);
	/* Note: per-VE latency is updated in update_venum() */
}

static void update_alloc_latency(void)
{
	int i;

	spin_lock_irq(&kstat_glb_lock);
	for (i = 0; i < KSTAT_ALLOCSTAT_NR; i++)
		KSTAT_LAT_PCPU_UPDATE(&kstat_glob.alloc_lat[i]);
	KSTAT_LAT_PCPU_UPDATE(&kstat_glob.swap_in);
	KSTAT_LAT_PCPU_UPDATE(&kstat_glob.page_in);
	spin_unlock_irq(&kstat_glb_lock);
}

static void lastlat_seq_show(struct seq_file *m,
		const char *name,
		struct kstat_lat_snap_struct *snap)
{
	seq_printf(m, "%-11s %20Lu %20Lu %20lu\n", name,
			snap->maxlat, snap->totlat, snap->count);
}

static void avglat_seq_show(struct seq_file *m,
		const char *name,
		u64 *avg)
{
	seq_printf(m, "%-11s %20Lu %20Lu %20Lu\n", name,
			avg[0], avg[1], avg[2]);
}

static int latency_seq_show(struct seq_file *m, void *v)
{
	int i;

	if (!v)
		return 0;

	seq_puts(m, "Version: 2.5\n");

	seq_puts(m, "\nLatencies:\n");
	seq_printf(m, "%-11s %20s %20s %20s\n",
			"Type", "Lat", "Total_lat", "Calls");
	lastlat_seq_show(m, "scheduling:", &kstat_glob.sched_lat.last);
	for (i = 0; i < KSTAT_ALLOCSTAT_NR; i++)
		lastlat_seq_show(m, alloc_descr[i],
				&kstat_glob.alloc_lat[i].last);
	lastlat_seq_show(m, "swap_in:", &kstat_glob.swap_in.last);
	lastlat_seq_show(m, "page_in:", &kstat_glob.page_in.last);

	seq_puts(m, "\nAverages:\n");
	seq_printf(m, "%-11s %20s %20s %20s\n",
			"Type", "Avg1", "Avg5", "Avg15");
	avglat_seq_show(m, "scheduling:", kstat_glob.sched_lat.avg);
	for (i = 0; i < KSTAT_ALLOCSTAT_NR; i++)
		avglat_seq_show(m, alloc_descr[i],
				kstat_glob.alloc_lat[i].avg);
	avglat_seq_show(m, "swap_in:", kstat_glob.swap_in.avg);
	avglat_seq_show(m, "page_in:", kstat_glob.page_in.avg);

	return 0;
}

/*
 * ------------------------------------------------------------------------
 * General system info: processes, memory, VE
 * ------------------------------------------------------------------------
 */
static void update_memory(void)
{
	pg_data_t *pgdat;
	struct zone *zone;
	struct kstat_zone_avg *zone_avg;
	unsigned type;
	unsigned long nr_free, nr_active, nr_inactive;
	unsigned present;

	for (type = 0; type < MAX_NR_ZONES; type++) {
		present = 0;
		nr_free = 0;
		nr_active = 0;
		nr_inactive = 0;

		for_each_online_pgdat (pgdat) {
			zone = pgdat->node_zones + type;
			if (!zone->present_pages)
				continue;

			present++;
			nr_free += zone_page_state(zone, NR_FREE_PAGES);
			nr_active +=  zone_page_state(zone, NR_ACTIVE_ANON) +
				zone_page_state(zone, NR_ACTIVE_FILE);
			nr_inactive += zone_page_state(zone, NR_INACTIVE_ANON) +
				zone_page_state(zone, NR_INACTIVE_FILE);
		}

		if (!present)
			continue;

		zone_avg = &kstat_glob.zone_avg[type];

		CALC_LOAD(zone_avg->free_pages_avg[0], EXP_1, nr_free);
		CALC_LOAD(zone_avg->free_pages_avg[1], EXP_5, nr_free);
		CALC_LOAD(zone_avg->free_pages_avg[2], EXP_15,nr_free);

		CALC_LOAD(zone_avg->nr_active_avg[0], EXP_1, nr_active);
		CALC_LOAD(zone_avg->nr_active_avg[1], EXP_5, nr_active);
		CALC_LOAD(zone_avg->nr_active_avg[2], EXP_15, nr_active);

		CALC_LOAD(zone_avg->nr_inactive_avg[0], EXP_1, nr_inactive);
		CALC_LOAD(zone_avg->nr_inactive_avg[1], EXP_5, nr_inactive);
		CALC_LOAD(zone_avg->nr_inactive_avg[2], EXP_15, nr_inactive);
	}
}

static void mem_avg_show(struct seq_file *m, void *v)
{
	unsigned type;
	pg_data_t *pgdat;
	struct zone *zone;
	struct kstat_zone_avg *zone_avg;
	unsigned present;
	int zone_id;

	zone_id = 0;

	for (type = 0; type < MAX_NR_ZONES; type++) {
		present = 0;

		for_each_online_pgdat (pgdat) {
			zone = pgdat->node_zones + type;
			if (zone->present_pages) {
				present++;
				break;
			}
		}
		if (!present)
			continue;

		zone_avg = &kstat_glob.zone_avg[type];
		seq_printf(m, "ZONE%u %s averages: "
			"active %lu %lu %lu, "
			"inactive %lu %lu %lu, "
			"free %lu %lu %lu\n",
			zone_id++,
			zone->name,
			zone_avg->nr_active_avg[0],
			zone_avg->nr_active_avg[1],
			zone_avg->nr_active_avg[2],
			zone_avg->nr_inactive_avg[0],
			zone_avg->nr_inactive_avg[1],
			zone_avg->nr_inactive_avg[2],
			zone_avg->free_pages_avg[0],
			zone_avg->free_pages_avg[1],
			zone_avg->free_pages_avg[2]);
	}
}

static void update_venum(void)
{
	struct ve_struct *ve;

	mutex_lock(&ve_list_lock);
	spin_lock_irq(&kstat_glb_lock);
	for_each_ve(ve)
		/* max_snap is already set in update_schedule_latency */
		KSTAT_LAT_PCPU_UPDATE(&ve->sched_lat_ve);
	spin_unlock_irq(&kstat_glb_lock);
	mutex_unlock(&ve_list_lock);
}

static void task_counts_seq_show(struct seq_file *m, void *v)
{
	unsigned long _nr_running, _nr_sleeping, _nr_unint,
				_nr_zombie, _nr_dead, _nr_stopped;
	unsigned long avg[3], seq;

	_nr_running = nr_running();
	_nr_unint = nr_uninterruptible();
	_nr_sleeping = nr_sleeping();
	_nr_zombie = nr_zombie;
	_nr_dead = atomic_read(&nr_dead);
	_nr_stopped = nr_stopped();

	do {
		seq = read_seqcount_begin(&kstat_glob.nr_unint_avg_seq);
		memcpy(avg, kstat_glob.nr_unint_avg, sizeof(avg));
	} while (read_seqcount_retry(&kstat_glob.nr_unint_avg_seq, seq));

	seq_printf(m, "VEs: %d\n", nr_ve);
	seq_printf(m, "Processes: R %lu, S %lu, D %lu, "
		"Z %lu, T %lu, X %lu\n",
			_nr_running,
			_nr_sleeping,
			_nr_unint,
			_nr_zombie,
			_nr_stopped,
			_nr_dead);
	seq_printf(m, "Processes avg: unint %lu %lu %lu\n",
			avg[0] >> FSHIFT, avg[1] >> FSHIFT, avg[2] >> FSHIFT);
}

static void cycles_per_jiffy_show(struct seq_file *m, void *v)
{
	/* Now all time slices are measured in nanoseconds */
	seq_printf(m, "cycles_per_jiffy: %llu\n", ((u64) jiffies_to_usecs(1)) * 1000);
}

static void jiffies_per_second_show(struct seq_file *m, void *v)
{
	seq_printf(m, "jiffies_per_second: %u\n", HZ);
}

static void kernel_text_csum_seq_show(struct seq_file *m, void *v)
{
	seq_printf(m, "kernel_text_csum_broken: %d\n", 0);
}

static void swap_cache_seq_show(struct seq_file *m, void *v)
{
	struct swap_cache_info_struct *swpcache;
	extern struct swap_cache_info_struct swap_cache_info;

	swpcache = &swap_cache_info;
	seq_printf(m, "Swap cache: add %lu, del %lu, find %lu/%lu\n",
			swpcache->add_total,
			swpcache->del_total,
			swpcache->find_success,
			swpcache->find_total);
}

/*
 * Declare special structure to store summarized statistics. The 'struct zone'
 * is not used because of it's tremendous size.
 */
struct zonestat {
	const char *name;
	unsigned long free_pages;
	unsigned long nr_free[MAX_ORDER];
	unsigned long pages_min;
	unsigned long pages_low;
	unsigned long pages_high;
	unsigned long nr_active;
	unsigned long nr_inactive;
	unsigned long present_pages;
};

/*
 * Show information about all memory zones.
 */
static void mem_free_areas_show_zonestat(struct seq_file *m,
						struct zonestat *zstat)
{
	unsigned int order;
	unsigned type;

	for (type = 0; type < MAX_NR_ZONES; type++) {
		struct zonestat *zone = &zstat[type];

		if (!zone->name)
			continue;

		/* Skip empty zones */
		if (!zone->present_pages)
			continue;

		seq_printf(m, "%s free %lu (", zone->name, zone->free_pages);
		for (order = 0; order < MAX_ORDER; order++)
			seq_printf(m, "%lu*%lu ", zone->nr_free[order],
								1UL << order);

		seq_printf(m, ") min %lu low %lu high %lu "
			"active %lu inactive %lu size %lu\n",
				zone->pages_min,
				zone->pages_low,
				zone->pages_high,
				zone->nr_active,
				zone->nr_inactive,
				zone->present_pages);
	}
}

/*
 * Scan all registered pgdat's (i.e. memory nodes) and summarize
 * values for identical zones.
 */
static void mem_free_areas_show(struct seq_file *m, void *v)
{
	pg_data_t *pgdat;
	struct zonestat zones[MAX_NR_ZONES];
	struct zonestat *zdst;
	struct zone *zsrc;
	int type, order;

	memset(zones, 0, sizeof(zones));

	for_each_online_pgdat (pgdat) {
		for (type = 0; type < MAX_NR_ZONES; type++) {
			unsigned long flags;

			zdst = &zones[type];
			zsrc = pgdat->node_zones + type;
			if (!zsrc || !zsrc->name)
				continue;

			if (!zdst->name)
				zdst->name = zsrc->name;
			else if (strcmp(zsrc->name, zdst->name))
				/* This shouldn't happen! */
				printk("Warning: names mismatch for "
					"zone %d: %s != %s\n",
					type, zsrc->name, zdst->name);

			spin_lock_irqsave(&zsrc->lock, flags);
			for (order = 0; order < MAX_ORDER; order++)
				zdst->nr_free[order] += zsrc->free_area[order].nr_free;
			spin_unlock_irqrestore(&zsrc->lock, flags);

			zdst->nr_active     += zone_page_state(zsrc, NR_ACTIVE_ANON) +
						zone_page_state(zsrc, NR_ACTIVE_FILE);
			zdst->nr_inactive   += zone_page_state(zsrc, NR_INACTIVE_ANON) +
						zone_page_state(zsrc, NR_INACTIVE_FILE);
			zdst->pages_min     += min_wmark_pages(zsrc);
			zdst->pages_low     += low_wmark_pages(zsrc);
			zdst->pages_high    += high_wmark_pages(zsrc);
			zdst->present_pages += zsrc->present_pages;
			zdst->free_pages    += zone_page_state(zsrc, NR_FREE_PAGES);
		}
	}
	mem_free_areas_show_zonestat(m, zones);
}

static void mem_fails_show(struct seq_file *m, void *v)
{
	int i, cpu;
	unsigned long alloc_fails[KSTAT_ALLOCSTAT_NR];

	memset(alloc_fails, 0, sizeof(alloc_fails));
	for_each_online_cpu(cpu)
		for (i = 0; i < KSTAT_ALLOCSTAT_NR; i++)
			alloc_fails[i] += kstat_glob.alloc_fails[cpu][i];

	seq_puts(m, "\nMemory fails:\n");
	for (i = 0; i < KSTAT_ALLOCSTAT_NR; i++)
		seq_printf(m, "%-11s %20lu\n", alloc_descr[i],
				alloc_fails[i]);
}

/*
 * ------------------------------------------------------------------------
 * Memory management profiling
 * ------------------------------------------------------------------------
 */
static void KSTAT_PERF_UPDATE(struct kstat_perf_pcpu_struct *p)
{
	unsigned i, cpu;
	struct kstat_perf_pcpu_snap_struct snap, *cur;

	memset(&p->last, 0, sizeof(p->last));
	for_each_online_cpu(cpu) {
		cur = per_cpu_ptr(p->cur, cpu);
		do {
			i = read_seqcount_begin(&cur->lock);
			memcpy(&snap, cur, sizeof(snap));
		} while (read_seqcount_retry(&cur->lock, i));

		if (p->last.wall_maxdur < snap.wall_maxdur)
			p->last.wall_maxdur = snap.wall_maxdur;
		if (p->last.cpu_maxdur < snap.cpu_maxdur)
			p->last.cpu_maxdur = snap.cpu_maxdur;
		cur->wall_maxdur = cur->cpu_maxdur = 0;

		p->last.count += snap.count;
		p->last.wall_tottime += snap.wall_tottime;
		p->last.cpu_tottime += snap.cpu_tottime;
	}
}

static void update_mmperf(void)
{
	KSTAT_PERF_UPDATE(&kstat_glob.ttfp);
	KSTAT_PERF_UPDATE(&kstat_glob.cache_reap);
	KSTAT_PERF_UPDATE(&kstat_glob.refill_inact);
	KSTAT_PERF_UPDATE(&kstat_glob.shrink_icache);
	KSTAT_PERF_UPDATE(&kstat_glob.shrink_dcache);
}

static void perf_seq_show(struct seq_file *m,
		const char *name,
		struct kstat_perf_pcpu_struct *p)
{
	seq_printf(m, "%-14s %10lu %20Lu %20Lu %20Lu %20Lu\n",
			name,
			p->last.count,
			p->last.cpu_maxdur,
			p->last.wall_maxdur,
			p->last.cpu_tottime,
			p->last.wall_tottime);
}

static int mmperf_seq_show(struct seq_file *m, void *v)
{
	if (!v)
		return 0;
	seq_puts(m, "Version: 2.5.1\n");
	seq_printf(m, "%-14s %10s %20s %20s %20s %20s\n",
			"Type",
			"Count",
			"CPU_max_dur",
			"Wall_max_dur",
			"CPU_tot_time",
			"Wall_tot_time");
	perf_seq_show(m, "ttfp:", &kstat_glob.ttfp);
	perf_seq_show(m, "cache_reap:", &kstat_glob.cache_reap);
	perf_seq_show(m, "refill_inact:", &kstat_glob.refill_inact);
	perf_seq_show(m, "shrink_icache:", &kstat_glob.shrink_icache);
	perf_seq_show(m, "shrink_dcache:", &kstat_glob.shrink_dcache);
	return 0;
}

/*
 * ------------------------------------------------------------------------
 * Main loop
 * ------------------------------------------------------------------------
 */
static int vzstat_mon_loop(void* data)
{
	while (1) {
		try_to_freeze();
#ifdef CONFIG_VE_KERNEL_CSUM
		kernel_text_csum_check();
#endif
		update_alloc_latency();
		update_schedule_latency();
		update_memory();
		update_venum();
		update_mmperf();

		set_current_state(TASK_INTERRUPTIBLE);
		if (kthread_should_stop())
			break;
		schedule_timeout(LOAD_FREQ);
	}
	return 0;
}

/*
 * ------------------------------------------------------------------------
 * default sequential files methods
 * ------------------------------------------------------------------------
 */
static void *empty_seq_start(struct seq_file *m, loff_t *pos)
{
	if (*pos == 0)
		return (void*)1;
	else
		return NULL;
}

static void *empty_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	return NULL;
}

static void empty_seq_stop(struct seq_file *m, void *v)
{
}

/*
 * ------------------------------------------------------------------------
 * /proc/vz/latency sequential file methods
 * ------------------------------------------------------------------------
 */
static struct seq_operations latency_seq_op = {
	start:	empty_seq_start,
	next:	empty_seq_next,
	stop:	empty_seq_stop,
	show:	latency_seq_show
};

static int latency_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &latency_seq_op);
}

static struct file_operations proc_latency_operations = {
	.open = latency_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
	.owner = THIS_MODULE,
};

/*
 * ------------------------------------------------------------------------
 * /proc/vz/stats sequential file methods
 * ------------------------------------------------------------------------
 */
static int stats_seq_show(struct seq_file *m, void *v)
{
	if (!v)
		return 0;
	seq_puts(m, "Version: 2.6\n");
	cycles_per_jiffy_show(m, v);
	jiffies_per_second_show(m, v);
	seq_puts(m, "\nLoad info:\n");
	task_counts_seq_show(m, v);
	seq_puts(m, "\nMemory info:\n");
	kernel_text_csum_seq_show(m, v);
	swap_cache_seq_show(m, v);
	mem_free_areas_show(m, v);
	mem_avg_show(m, v);
	mem_fails_show(m, v);
	return 0;
}

static struct seq_operations stats_seq_op = {
	start:	empty_seq_start,
	next:	empty_seq_next,
	stop:	empty_seq_stop,
	show:	stats_seq_show
};

static int stats_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &stats_seq_op);
}

static struct file_operations proc_stats_operations = {
	.open = stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
	.owner = THIS_MODULE,
};

/*
 * ------------------------------------------------------------------------
 * /proc/vz/mmperf sequential file methods
 * ------------------------------------------------------------------------
 */
static struct seq_operations mmperf_seq_op = {
	start:	empty_seq_start,
	next:	empty_seq_next,
	stop:	empty_seq_stop,
	show:	mmperf_seq_show
};

static int mmperf_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &mmperf_seq_op);
}

static struct file_operations proc_mmperf_operations = {
	.open = mmperf_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
	.owner = THIS_MODULE,
};

/*
 * ------------------------------------------------------------------------
 * module init/exit code
 * ------------------------------------------------------------------------
 */

int __init vzstat_mon_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create("latency", S_IRUGO, proc_vz_dir, &proc_latency_operations);
	if (entry == NULL) {
		printk(KERN_WARNING "VZSTAT: can't make proc entry\n");
		goto fail_lat;
	}

	entry = proc_create("stats", S_IRUGO, proc_vz_dir, &proc_stats_operations);
	if (!entry) {
		printk(KERN_WARNING "VZSTAT: can't make proc entry\n");
		goto fail_stat;
	}

	entry = proc_create("mmperf", S_IRUGO, proc_vz_dir, &proc_mmperf_operations);
	if (!entry) {
		printk(KERN_WARNING "VZSTAT: can't make proc entry\n");
		goto fail_perf;
	}

	vzstat_thread_tsk = kthread_run(vzstat_mon_loop, NULL, "vzstat");
	if (IS_ERR(vzstat_thread_tsk))
		goto fail_thread;

	printk(KERN_INFO "VZSTAT: initialized successfully\n");

	return 0;

fail_thread:
	remove_proc_entry("mmperf", proc_vz_dir);
fail_perf:
	remove_proc_entry("stats", proc_vz_dir);
fail_stat:
	remove_proc_entry("latency", proc_vz_dir);
fail_lat:
	return -EBUSY;
}

void __exit vzstat_mon_exit(void)
{
	kthread_stop(vzstat_thread_tsk);

	remove_proc_entry("mmperf", proc_vz_dir);
	remove_proc_entry("stats", proc_vz_dir);
	remove_proc_entry("latency", proc_vz_dir);
}

module_init(vzstat_mon_init);
module_exit(vzstat_mon_exit);

MODULE_LICENSE("GPL v2");
