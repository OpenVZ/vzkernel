/*
 *  kernel/ve/vzwdog.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/ctype.h>
#include <linux/kobject.h>
#include <linux/genhd.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kernel_stat.h>
#include <linux/errno.h>
#include <linux/suspend.h>
#include <linux/ve.h>
#include <linux/vzstat.h>
#include <asm/uaccess.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

/* Staff regading kernel thread polling VE validity */
static int sleep_timeout = 60;
static struct task_struct *wdog_thread_tsk;

static struct file *intr_file;
static char page[PAGE_SIZE];

static void parse_irq_list(int len)
{
	int i, k, skip;
	for (i = 0; i < len; ) {
		k = i;
		while (i < len && page[i] != '\n' && page[i] != ':')
			i++;
		skip = 0;
		if (i < len && page[i] != '\n') {
			i++; /* skip ':' */
			while (i < len && (page[i] == ' ' || page[i] == '0'))
				i++;
			skip = (i < len && (page[i] < '0' || page[i] > '9'));
			while (i < len && page[i] != '\n')
				i++;
		}
		if (!skip)
			printk("%.*s\n", i - k, page + k);
		if (i < len)
			i++; /* skip '\n' */
	}
}

static void show_irq_list(void)
{
	mm_segment_t fs;
	int r;

	fs = get_fs();
	set_fs(KERNEL_DS);
	vfs_llseek(intr_file, 0, 0);
	r = vfs_read(intr_file, (void __user *)page, sizeof(page),
			&intr_file->f_pos);
	set_fs(fs);

	if (r > 0)
		parse_irq_list(r);
}

static u64 max_sched_lat;
static u64 max_alloc_lat[KSTAT_ALLOCSTAT_NR];

static void update_max_alloc_latency(void)
{
	int i;

	for (i = 0; i < KSTAT_ALLOCSTAT_NR; i++)
		max_alloc_lat[i] = max(max_alloc_lat[i],
				kstat_glob.alloc_lat[i].last.maxlat);
}

static void update_max_schedule_latency(void)
{
	max_sched_lat = max(max_sched_lat, kstat_glob.sched_lat.last.maxlat);
}

static void update_max_latencies(void)
{
	spin_lock_irq(&kstat_glb_lock);
	update_max_alloc_latency();
	update_max_schedule_latency();
	spin_unlock_irq(&kstat_glb_lock);
}

static void reset_max_latencies(void)
{
	max_sched_lat = 0;
	memset(max_alloc_lat, 0, sizeof(max_alloc_lat));
}

static void show_alloc_latency(void)
{
	static const char *alloc_descr[KSTAT_ALLOCSTAT_NR] = {
		"A0",
		"L0",
		"H0",
		"L1",
		"H1"
	};
	int i;

	printk("lat: ");
	for (i = 0; i < KSTAT_ALLOCSTAT_NR; i++) {
		struct kstat_lat_pcpu_struct *p;
		u64 maxlat, avg0, avg1, avg2;

		p = &kstat_glob.alloc_lat[i];
		spin_lock_irq(&kstat_glb_lock);
		maxlat = p->last.maxlat;
		avg0 = p->avg[0];
		avg1 = p->avg[1];
		avg2 = p->avg[2];
		spin_unlock_irq(&kstat_glb_lock);

		printk("%s %Lu %Lu (%Lu %Lu %Lu)",
				alloc_descr[i],
				(unsigned long long)max_alloc_lat[i],
				(unsigned long long)maxlat,
				(unsigned long long)avg0,
				(unsigned long long)avg1,
				(unsigned long long)avg2);
	}
	printk("\n");
}

static void show_schedule_latency(void)
{
	struct kstat_lat_pcpu_struct *p;
	cycles_t maxlat, totlat, avg0, avg1, avg2;
	unsigned long count;

	p = &kstat_glob.sched_lat;
	spin_lock_irq(&kstat_glb_lock);
	maxlat = p->last.maxlat;
	totlat = p->last.totlat;
	count = p->last.count;
	avg0 = p->avg[0];
	avg1 = p->avg[1];
	avg2 = p->avg[2];
	spin_unlock_irq(&kstat_glb_lock);

	printk("sched lat: %Lu/%Lu/%Lu/%lu (%Lu %Lu %Lu)\n",
			(unsigned long long)max_sched_lat,
			(unsigned long long)maxlat,
			(unsigned long long)totlat,
			count,
			(unsigned long long)avg0,
			(unsigned long long)avg1,
			(unsigned long long)avg2);
}

static void show_header(void)
{
	struct timeval tv;

	do_gettimeofday(&tv);
	preempt_disable();
	printk("*** VZWDOG 1.14: time %lu.%06lu uptime %Lu CPU %d ***\n",
			tv.tv_sec, (long)tv.tv_usec,
			(unsigned long long)get_jiffies_64(),
			smp_processor_id());
	printk("*** jiffies_per_second %u ***\n", HZ);
	preempt_enable();
}

static void show_pgdatinfo(void)
{
	pg_data_t *pgdat;

	printk("pgdat:");
	for_each_online_pgdat(pgdat) {
		printk(" %d: %lu,%lu,%lu",
				pgdat->node_id,
				pgdat->node_start_pfn,
				pgdat->node_present_pages,
				pgdat->node_spanned_pages);
#ifdef CONFIG_FLAT_NODE_MEM_MAP
		printk(",%p", pgdat->node_mem_map);
#endif
	}
	printk("\n");
}

static int show_partitions_io(struct gendisk *gp)
{
	struct disk_part_iter piter;
	struct hd_struct *hd;
	char buf[BDEVNAME_SIZE];
	unsigned int inflight[2];
	int cpu;

	/*
	if (&disk_to_dev(gp)->kobj.entry == block_class.devices.next)
		seq_puts(seqf,	"major minor name"
				"     rio rmerge rsect ruse wio wmerge "
				"wsect wuse running use aveq"
				"\n\n");
	*/
 
	disk_part_iter_init(&piter, gp, DISK_PITER_INCL_EMPTY_PART0);
	while ((hd = disk_part_iter_next(&piter))) {
		cpu = part_stat_lock();
		part_round_stats(gp->queue, cpu, hd);
		part_stat_unlock();
		part_in_flight(gp->queue, hd, inflight);
		printk("%4d %7d %s %lu %lu %llu "
			   "%u %lu %lu %llu %u %u %u %u\n",
			   MAJOR(part_devt(hd)), MINOR(part_devt(hd)),
			   disk_name(gp, hd->partno, buf),
			   part_stat_read(hd, ios[0]),
			   part_stat_read(hd, merges[0]),
			   (unsigned long long)part_stat_read(hd, sectors[0]),
			   jiffies_to_msecs(part_stat_read(hd, ticks[0])),
			   part_stat_read(hd, ios[1]),
			   part_stat_read(hd, merges[1]),
			   (unsigned long long)part_stat_read(hd, sectors[1]),
			   jiffies_to_msecs(part_stat_read(hd, ticks[1])),
			   inflight[0],
			   jiffies_to_msecs(part_stat_read(hd, io_ticks)),
			   jiffies_to_msecs(part_stat_read(hd, time_in_queue))
			);
	}
	disk_part_iter_exit(&piter);
 
	return 0;
}

static int show_one_disk_io(struct device *dev, void *x)
{
	char *name;
	char buf[BDEVNAME_SIZE];
	struct gendisk *gd;

	if (dev->type != &disk_type)
		return 0;

	gd = dev_to_disk(dev);

	name = disk_name(gd, 0, buf);
	if ((strlen(name) > 4) && (strncmp(name, "loop", 4) == 0) &&
			isdigit(name[4]))
		return 0;

	if ((strlen(name) > 3) && (strncmp(name, "ram", 3) == 0) &&
			isdigit(name[3]))
		return 0;

	show_partitions_io(gd);

	return 0;
}

static void show_diskio(void)
{
	printk("disk_io: ");
	class_for_each_device(&block_class, NULL, NULL, show_one_disk_io);
	printk("\n");
}

static void show_nrprocs(void)
{
	unsigned long _nr_running, _nr_sleeping,
			_nr_unint, _nr_zombie, _nr_dead, _nr_stopped;

	_nr_running = nr_running();
	_nr_unint = nr_uninterruptible();
	_nr_sleeping = nr_sleeping();
	_nr_zombie = nr_zombie;
	_nr_dead = atomic_read(&nr_dead);
	_nr_stopped = nr_stopped();

	printk("VEnum: %d, proc R %lu, S %lu, D %lu, "
		"Z %lu, X %lu, T %lu (tot %d)\n",
		nr_ve,	_nr_running, _nr_sleeping, _nr_unint,
		_nr_zombie, _nr_dead, _nr_stopped, nr_threads);
}

static void wdog_print(void)
{
	show_header();
	show_irq_list();
	show_pgdatinfo();
	show_mem(SHOW_MEM_FILTER_NODES);
	show_diskio();
	show_schedule_latency();
	show_alloc_latency();
	show_nrprocs();
}

static int wdog_loop(void* data)
{
	unsigned long next_print;
	long timeout;

	next_print = jiffies;
	while (1) {
		update_max_latencies();
		if (time_is_before_eq_jiffies(next_print)) {
			wdog_print();
			reset_max_latencies();
			next_print = jiffies + sleep_timeout * HZ;
		}
		try_to_freeze();

		set_current_state(TASK_UNINTERRUPTIBLE);
		if (kthread_should_stop())
			break;
		timeout = clamp_t(long, next_print - jiffies, 0, LOAD_FREQ);
		schedule_timeout(timeout);
	}
	return 0;
}

static int __init wdog_init(void)
{
	struct file *file;

	file = filp_open("/proc/interrupts", 0, 0);
	if (IS_ERR(file))
		return PTR_ERR(file);
	intr_file = file;

	wdog_thread_tsk = kthread_run(wdog_loop, NULL, "vzwdog");
	if (IS_ERR(wdog_thread_tsk)) {
		filp_close(intr_file, NULL);
		return -EBUSY;
	}
	return 0;
}

static void __exit wdog_exit(void)
{
	kthread_stop(wdog_thread_tsk);
	filp_close(intr_file, NULL);
}

module_param(sleep_timeout, int, 0660);
MODULE_AUTHOR("SWsoft <info@sw-soft.com>");
MODULE_DESCRIPTION("Virtuozzo WDOG");
MODULE_LICENSE("GPL v2");

module_init(wdog_init)
module_exit(wdog_exit)
