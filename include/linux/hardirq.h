#ifndef LINUX_HARDIRQ_H
#define LINUX_HARDIRQ_H

#include <linux/preempt_mask.h>
#include <linux/lockdep.h>
#include <linux/ftrace_irq.h>
#include <linux/vtime.h>

#include <bc/task.h>
#include <linux/ve_task.h>

#if defined(CONFIG_SMP) || defined(CONFIG_GENERIC_HARDIRQS)
extern void synchronize_irq(unsigned int irq);
#else
# define synchronize_irq(irq)	barrier()
#endif

#if defined(CONFIG_TINY_RCU) || defined(CONFIG_TINY_PREEMPT_RCU)

static inline void rcu_nmi_enter(void)
{
}

static inline void rcu_nmi_exit(void)
{
}

#else
extern void rcu_nmi_enter(void);
extern void rcu_nmi_exit(void);
#endif

#define save_context()		do {				\
		struct task_struct *tsk;			\
		if (hardirq_count() == HARDIRQ_OFFSET) {	\
			tsk = current;				\
			ve_save_context(tsk);			\
			ub_save_context(tsk);			\
		}						\
	} while (0)

#define restore_context()		do {			\
		struct task_struct *tsk;			\
		if (hardirq_count() == HARDIRQ_OFFSET) {	\
			tsk = current;				\
			ve_restore_context(tsk);		\
			ub_restore_context(tsk);		\
		}						\
	} while (0)

/*
 * It is safe to do non-atomic ops on ->hardirq_context,
 * because NMI handlers may not preempt and the ops are
 * always balanced, so the interrupted value of ->hardirq_context
 * will always be restored.
 */
#define __irq_enter()					\
	do {						\
		account_irq_enter_time(current);	\
		add_preempt_count(HARDIRQ_OFFSET);	\
		save_context();				\
		trace_hardirq_enter();			\
	} while (0)

/*
 * Enter irq context (on NO_HZ, update jiffies):
 */
extern void irq_enter(void);

/*
 * Exit irq context without processing softirqs:
 */
#define __irq_exit()					\
	do {						\
		trace_hardirq_exit();			\
		account_irq_exit_time(current);		\
		restore_context();			\
		sub_preempt_count(HARDIRQ_OFFSET);	\
	} while (0)

/*
 * Exit irq context and process softirqs if needed:
 */
extern void irq_exit(void);

#define nmi_enter()						\
	do {							\
		lockdep_off();					\
		ftrace_nmi_enter();				\
		BUG_ON(in_nmi());				\
		add_preempt_count(NMI_OFFSET + HARDIRQ_OFFSET);	\
		rcu_nmi_enter();				\
		trace_hardirq_enter();				\
	} while (0)

#define nmi_exit()						\
	do {							\
		trace_hardirq_exit();				\
		rcu_nmi_exit();					\
		BUG_ON(!in_nmi());				\
		sub_preempt_count(NMI_OFFSET + HARDIRQ_OFFSET);	\
		ftrace_nmi_exit();				\
		lockdep_on();					\
	} while (0)

#endif /* LINUX_HARDIRQ_H */
