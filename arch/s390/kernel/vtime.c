/*
 *    Virtual cpu timer based timer functions.
 *
 *    Copyright IBM Corp. 2004, 2012
 *    Author(s): Jan Glauber <jan.glauber@de.ibm.com>
 */

#include <linux/kernel_stat.h>
#include <linux/notifier.h>
#include <linux/kprobes.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/timex.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/cpu.h>
#include <linux/smp.h>

#include <asm/irq_regs.h>
#include <asm/cputime.h>
#include <asm/vtimer.h>
#include <asm/vtime.h>
#include <asm/irq.h>
#include <asm/cpu_mf.h>
#include <asm/smp.h>
#include "entry.h"

static void virt_timer_expire(void);

DEFINE_PER_CPU(struct s390_idle_data, s390_idle);

static LIST_HEAD(virt_timer_list);
static DEFINE_SPINLOCK(virt_timer_lock);
static atomic64_t virt_timer_current;
static atomic64_t virt_timer_elapsed;

DEFINE_PER_CPU(u64, mt_cycles[8]);
static DEFINE_PER_CPU(u64, mt_scaling_mult) = { 1 };
static DEFINE_PER_CPU(u64, mt_scaling_div) = { 1 };
static DEFINE_PER_CPU(u64, mt_scaling_jiffies);

static inline u64 get_vtimer(void)
{
	u64 timer;

	asm volatile("stpt %0" : "=m" (timer));
	return timer;
}

static inline void set_vtimer(u64 expires)
{
	u64 timer;

	asm volatile(
		"	stpt	%0\n"	/* Store current cpu timer value */
		"	spt	%1"	/* Set new value imm. afterwards */
		: "=m" (timer) : "m" (expires));
	S390_lowcore.system_timer += S390_lowcore.last_update_timer - timer;
	S390_lowcore.last_update_timer = expires;
}

static inline int virt_timer_forward(u64 elapsed)
{
	BUG_ON(!irqs_disabled());

	if (list_empty(&virt_timer_list))
		return 0;
	elapsed = atomic64_add_return(elapsed, &virt_timer_elapsed);
	return elapsed >= atomic64_read(&virt_timer_current);
}

static void update_mt_scaling(void)
{
	u64 cycles_new[8], *cycles_old;
	u64 delta, fac, mult, div;
	int i;

	stcctm5(smp_cpu_mtid + 1, cycles_new);
	cycles_old = __get_cpu_var(mt_cycles);
	fac = 1;
	mult = div = 0;
	for (i = 0; i <= smp_cpu_mtid; i++) {
		delta = cycles_new[i] - cycles_old[i];
		div += delta;
		mult *= i + 1;
		mult += delta * fac;
		fac *= i + 1;
	}
	div *= fac;
	if (div > 0) {
		/* Update scaling factor */
		__this_cpu_write(mt_scaling_mult, mult);
		__this_cpu_write(mt_scaling_div, div);
		memcpy(cycles_old, cycles_new,
		       sizeof(u64) * (smp_cpu_mtid + 1));
	}
	__this_cpu_write(mt_scaling_jiffies, jiffies_64);
}

/*
 * Update process times based on virtual cpu times stored by entry.S
 * to the lowcore fields user_timer, system_timer & steal_clock.
 */
static int do_account_vtime(struct task_struct *tsk, int hardirq_offset)
{
	struct thread_info *ti = task_thread_info(tsk);
	u64 timer, clock, user, system, steal;
	u64 user_scaled, system_scaled;

	timer = S390_lowcore.last_update_timer;
	clock = S390_lowcore.last_update_clock;
	asm volatile(
		"	stpt	%0\n"	/* Store current cpu timer value */
#ifdef CONFIG_HAVE_MARCH_Z9_109_FEATURES
		"	stckf	%1"	/* Store current tod clock value */
#else
		"	stck	%1"	/* Store current tod clock value */
#endif
		: "=m" (S390_lowcore.last_update_timer),
		  "=m" (S390_lowcore.last_update_clock));
	S390_lowcore.system_timer += timer - S390_lowcore.last_update_timer;
	S390_lowcore.steal_timer += S390_lowcore.last_update_clock - clock;

	/* Update MT utilization calculation */
	if (smp_cpu_mtid &&
	    time_after64(jiffies_64, this_cpu_read(mt_scaling_jiffies)))
		update_mt_scaling();

	user = S390_lowcore.user_timer - ti->user_timer;
	S390_lowcore.steal_timer -= user;
	ti->user_timer = S390_lowcore.user_timer;

	system = S390_lowcore.system_timer - ti->system_timer;
	S390_lowcore.steal_timer -= system;
	ti->system_timer = S390_lowcore.system_timer;

	user_scaled = user;
	system_scaled = system;
	/* Do MT utilization scaling */
	if (smp_cpu_mtid) {
		u64 mult = __get_cpu_var(mt_scaling_mult);
		u64 div = __get_cpu_var(mt_scaling_div);

		user_scaled = (user_scaled * mult) / div;
		system_scaled = (system_scaled * mult) / div;
	}
	account_user_time(tsk, user, user_scaled);
	account_system_time(tsk, hardirq_offset, system, system_scaled);

	steal = S390_lowcore.steal_timer;
	if ((s64) steal > 0) {
		S390_lowcore.steal_timer = 0;
		account_steal_time(steal);
	}

	return virt_timer_forward(user + system);
}

void vtime_task_switch(struct task_struct *prev)
{
	struct thread_info *ti;

	do_account_vtime(prev, 0);
	ti = task_thread_info(prev);
	ti->user_timer = S390_lowcore.user_timer;
	ti->system_timer = S390_lowcore.system_timer;
	ti = task_thread_info(current);
	S390_lowcore.user_timer = ti->user_timer;
	S390_lowcore.system_timer = ti->system_timer;
}

/*
 * In s390, accounting pending user time also implies
 * accounting system time in order to correctly compute
 * the stolen time accounting.
 */
void vtime_account_user(struct task_struct *tsk)
{
	if (do_account_vtime(tsk, HARDIRQ_OFFSET))
		virt_timer_expire();
}

/*
 * Update process times based on virtual cpu times stored by entry.S
 * to the lowcore fields user_timer, system_timer & steal_clock.
 */
void vtime_account_irq_enter(struct task_struct *tsk)
{
	struct thread_info *ti = task_thread_info(tsk);
	u64 timer, system, system_scaled;

	WARN_ON_ONCE(!irqs_disabled());

	timer = S390_lowcore.last_update_timer;
	S390_lowcore.last_update_timer = get_vtimer();
	S390_lowcore.system_timer += timer - S390_lowcore.last_update_timer;

	/* Update MT utilization calculation */
	if (smp_cpu_mtid &&
	    time_after64(jiffies_64, this_cpu_read(mt_scaling_jiffies)))
		update_mt_scaling();

	system = S390_lowcore.system_timer - ti->system_timer;
	S390_lowcore.steal_timer -= system;
	ti->system_timer = S390_lowcore.system_timer;
	system_scaled = system;
	/* Do MT utilization scaling */
	if (smp_cpu_mtid) {
		u64 mult = __get_cpu_var(mt_scaling_mult);
		u64 div = __get_cpu_var(mt_scaling_div);

		system_scaled = (system_scaled * mult) / div;
	}
	account_system_time(tsk, 0, system, system_scaled);

	virt_timer_forward(system);
}
EXPORT_SYMBOL_GPL(vtime_account_irq_enter);

void vtime_account_system(struct task_struct *tsk)
__attribute__((alias("vtime_account_irq_enter")));
EXPORT_SYMBOL_GPL(vtime_account_system);

void __kprobes vtime_stop_cpu(void)
{
	struct s390_idle_data *idle = &__get_cpu_var(s390_idle);
	unsigned long long idle_time;
	unsigned long psw_mask;

	trace_hardirqs_on();

	/* Wait for external, I/O or machine check interrupt. */
	psw_mask = PSW_KERNEL_BITS | PSW_MASK_WAIT | PSW_MASK_DAT |
		PSW_MASK_IO | PSW_MASK_EXT | PSW_MASK_MCHECK;
	idle->nohz_delay = 0;

	/* Call the assembler magic in entry.S */
	psw_idle(idle, psw_mask);

	/* Account time spent with enabled wait psw loaded as idle time. */
	idle->sequence++;
	smp_wmb();
	idle_time = idle->clock_idle_exit - idle->clock_idle_enter;
	idle->clock_idle_enter = idle->clock_idle_exit = 0ULL;
	idle->idle_time += idle_time;
	idle->idle_count++;
	account_idle_time(idle_time);
	smp_wmb();
	idle->sequence++;
}

cputime64_t s390_get_idle_time(int cpu)
{
	struct s390_idle_data *idle = &per_cpu(s390_idle, cpu);
	unsigned long long now, idle_enter, idle_exit, in_idle;
	unsigned int sequence;

	do {
		sequence = ACCESS_ONCE(idle->sequence);
		idle_enter = ACCESS_ONCE(idle->clock_idle_enter);
		idle_exit = ACCESS_ONCE(idle->clock_idle_exit);
	} while ((sequence & 1) || (ACCESS_ONCE(idle->sequence) != sequence));
	in_idle = 0;
	now = get_tod_clock();
	if (idle_enter) {
		if (idle_exit) {
			in_idle = idle_exit - idle_enter;
		} else if (now > idle_enter) {
			in_idle = now - idle_enter;
		}
	}
	return in_idle;
}

/*
 * Sorted add to a list. List is linear searched until first bigger
 * element is found.
 */
static void list_add_sorted(struct vtimer_list *timer, struct list_head *head)
{
	struct vtimer_list *tmp;

	list_for_each_entry(tmp, head, entry) {
		if (tmp->expires > timer->expires) {
			list_add_tail(&timer->entry, &tmp->entry);
			return;
		}
	}
	list_add_tail(&timer->entry, head);
}

/*
 * Handler for expired virtual CPU timer.
 */
static void virt_timer_expire(void)
{
	struct vtimer_list *timer, *tmp;
	unsigned long elapsed;
	LIST_HEAD(cb_list);

	/* walk timer list, fire all expired timers */
	spin_lock(&virt_timer_lock);
	elapsed = atomic64_read(&virt_timer_elapsed);
	list_for_each_entry_safe(timer, tmp, &virt_timer_list, entry) {
		if (timer->expires < elapsed)
			/* move expired timer to the callback queue */
			list_move_tail(&timer->entry, &cb_list);
		else
			timer->expires -= elapsed;
	}
	if (!list_empty(&virt_timer_list)) {
		timer = list_first_entry(&virt_timer_list,
					 struct vtimer_list, entry);
		atomic64_set(&virt_timer_current, timer->expires);
	}
	atomic64_sub(elapsed, &virt_timer_elapsed);
	spin_unlock(&virt_timer_lock);

	/* Do callbacks and recharge periodic timers */
	list_for_each_entry_safe(timer, tmp, &cb_list, entry) {
		list_del_init(&timer->entry);
		timer->function(timer->data);
		if (timer->interval) {
			/* Recharge interval timer */
			timer->expires = timer->interval +
				atomic64_read(&virt_timer_elapsed);
			spin_lock(&virt_timer_lock);
			list_add_sorted(timer, &virt_timer_list);
			spin_unlock(&virt_timer_lock);
		}
	}
}

void init_virt_timer(struct vtimer_list *timer)
{
	timer->function = NULL;
	INIT_LIST_HEAD(&timer->entry);
}
EXPORT_SYMBOL(init_virt_timer);

static inline int vtimer_pending(struct vtimer_list *timer)
{
	return !list_empty(&timer->entry);
}

static void internal_add_vtimer(struct vtimer_list *timer)
{
	if (list_empty(&virt_timer_list)) {
		/* First timer, just program it. */
		atomic64_set(&virt_timer_current, timer->expires);
		atomic64_set(&virt_timer_elapsed, 0);
		list_add(&timer->entry, &virt_timer_list);
	} else {
		/* Update timer against current base. */
		timer->expires += atomic64_read(&virt_timer_elapsed);
		if (likely((s64) timer->expires <
			   (s64) atomic64_read(&virt_timer_current)))
			/* The new timer expires before the current timer. */
			atomic64_set(&virt_timer_current, timer->expires);
		/* Insert new timer into the list. */
		list_add_sorted(timer, &virt_timer_list);
	}
}

static void __add_vtimer(struct vtimer_list *timer, int periodic)
{
	unsigned long flags;

	timer->interval = periodic ? timer->expires : 0;
	spin_lock_irqsave(&virt_timer_lock, flags);
	internal_add_vtimer(timer);
	spin_unlock_irqrestore(&virt_timer_lock, flags);
}

/*
 * add_virt_timer - add an oneshot virtual CPU timer
 */
void add_virt_timer(struct vtimer_list *timer)
{
	__add_vtimer(timer, 0);
}
EXPORT_SYMBOL(add_virt_timer);

/*
 * add_virt_timer_int - add an interval virtual CPU timer
 */
void add_virt_timer_periodic(struct vtimer_list *timer)
{
	__add_vtimer(timer, 1);
}
EXPORT_SYMBOL(add_virt_timer_periodic);

static int __mod_vtimer(struct vtimer_list *timer, u64 expires, int periodic)
{
	unsigned long flags;
	int rc;

	BUG_ON(!timer->function);

	if (timer->expires == expires && vtimer_pending(timer))
		return 1;
	spin_lock_irqsave(&virt_timer_lock, flags);
	rc = vtimer_pending(timer);
	if (rc)
		list_del_init(&timer->entry);
	timer->interval = periodic ? expires : 0;
	timer->expires = expires;
	internal_add_vtimer(timer);
	spin_unlock_irqrestore(&virt_timer_lock, flags);
	return rc;
}

/*
 * returns whether it has modified a pending timer (1) or not (0)
 */
int mod_virt_timer(struct vtimer_list *timer, u64 expires)
{
	return __mod_vtimer(timer, expires, 0);
}
EXPORT_SYMBOL(mod_virt_timer);

/*
 * returns whether it has modified a pending timer (1) or not (0)
 */
int mod_virt_timer_periodic(struct vtimer_list *timer, u64 expires)
{
	return __mod_vtimer(timer, expires, 1);
}
EXPORT_SYMBOL(mod_virt_timer_periodic);

/*
 * Delete a virtual timer.
 *
 * returns whether the deleted timer was pending (1) or not (0)
 */
int del_virt_timer(struct vtimer_list *timer)
{
	unsigned long flags;

	if (!vtimer_pending(timer))
		return 0;
	spin_lock_irqsave(&virt_timer_lock, flags);
	list_del_init(&timer->entry);
	spin_unlock_irqrestore(&virt_timer_lock, flags);
	return 1;
}
EXPORT_SYMBOL(del_virt_timer);

/*
 * Start the virtual CPU timer on the current CPU.
 */
void init_cpu_vtimer(void)
{
	/* set initial cpu timer */
	set_vtimer(VTIMER_MAX_SLICE);
	/* Setup initial MT scaling values */
	if (smp_cpu_mtid) {
		__this_cpu_write(mt_scaling_jiffies, jiffies);
		__this_cpu_write(mt_scaling_mult, 1);
		__this_cpu_write(mt_scaling_div, 1);
		stcctm5(smp_cpu_mtid + 1, __get_cpu_var(mt_cycles));
	}
}

static int s390_nohz_notify(struct notifier_block *self, unsigned long action,
			    void *hcpu)
{
	struct s390_idle_data *idle;
	long cpu = (long) hcpu;

	idle = &per_cpu(s390_idle, cpu);
	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_DYING:
		idle->nohz_delay = 0;
	default:
		break;
	}
	return NOTIFY_OK;
}

void __init vtime_init(void)
{
	/* Enable cpu timer interrupts on the boot cpu. */
	init_cpu_vtimer();
	cpu_notifier(s390_nohz_notify, 0);
}
