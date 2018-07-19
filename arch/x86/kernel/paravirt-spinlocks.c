/*
 * Split spinlock implementation out into its own file, so it can be
 * compiled in a FTRACE-compatible way.
 */
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/jump_label.h>

#include <asm/paravirt.h>

#ifdef CONFIG_QUEUED_SPINLOCKS
extern void __pv_ticket_unlock_slowpath(struct arch_spinlock *lock,
					__ticket_t ticket);

__visible void __native_queued_spin_unlock(struct qspinlock *lock)
{
	native_queued_spin_unlock(lock);
}

PV_CALLEE_SAVE_REGS_THUNK(__native_queued_spin_unlock);

bool pv_is_native_spin_unlock(void)
{
	return pv_lock_ops.queued_spin_unlock.func ==
		__raw_callee_save___native_queued_spin_unlock;
}
#endif

struct pv_lock_ops pv_lock_ops = {
#ifdef CONFIG_SMP
	.lock_spinning = __PV_IS_CALLEE_SAVE(paravirt_nop),
#ifdef CONFIG_QUEUED_SPINLOCKS
	.unlock_kick = __pv_ticket_unlock_slowpath,
	.queued_spin_unlock = PV_CALLEE_SAVE(__native_queued_spin_unlock),
	.queued_spin_lock_slowpath = native_queued_spin_lock_slowpath,
	.wait = paravirt_nop,
	.kick = paravirt_nop,
#else /* !CONFIG_QUEUED_SPINLOCKS */
	.unlock_kick = paravirt_nop,
#endif /* !CONFIG_QUEUED_SPINLOCKS */
#endif /* SMP */
};
EXPORT_SYMBOL(pv_lock_ops);

struct static_key paravirt_ticketlocks_enabled = STATIC_KEY_INIT_FALSE;
EXPORT_SYMBOL(paravirt_ticketlocks_enabled);

#ifdef CONFIG_QUEUED_SPINLOCKS
/*
 * Enable paravirt_ticketlocks_enabled call sites patching unless
 * 1) A hypervisor is running; and
 * 2) the .queued_spin_lock_slowpath method hasn't changed.
 *
 * In this case, the virt_spin_lock() function will be used. This
 * lock function is simple enough that we don't need the atomic add
 * guarantee of the unlock function. So paravirt_ticketlocks_enabled
 * does not need to be turned on.
 */
static int __init queued_enable_pv_ticketlock(void)
{
	if (!static_cpu_has(X86_FEATURE_HYPERVISOR) ||
	   (pv_lock_ops.queued_spin_lock_slowpath !=
	    native_queued_spin_lock_slowpath))
		static_key_slow_inc(&paravirt_ticketlocks_enabled);
	return 0;
}
pure_initcall(queued_enable_pv_ticketlock);
#endif
