#ifndef _ASM_X86_QSPINLOCK_H
#define _ASM_X86_QSPINLOCK_H

#include <asm/cpufeature.h>
#include <asm-generic/qspinlock_types.h>
#include <asm/paravirt.h>

#define	queued_spin_unlock queued_spin_unlock
/**
 * queued_spin_unlock - release a queued spinlock
 * @lock : Pointer to queued spinlock structure
 *
 * A smp_store_release() on the least-significant byte.
 */
static inline void native_queued_spin_unlock(struct qspinlock *lock)
{
	smp_store_release((u8 *)lock, 0);
}

#ifdef CONFIG_PARAVIRT_SPINLOCKS
extern void native_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val);
extern void __pv_init_lock_hash(void);
extern void __pv_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val);
extern void __raw_callee_save___pv_queued_spin_unlock(struct qspinlock *lock);

static inline void queued_spin_lock_slowpath(struct qspinlock *lock, u32 val)
{
	pv_queued_spin_lock_slowpath(lock, val);
}

static inline void queued_spin_unlock(struct qspinlock *lock)
{
	pv_queued_spin_unlock(lock);
}
#else
static inline void queued_spin_unlock(struct qspinlock *lock)
{
	native_queued_spin_unlock(lock);
}
#endif

#define virt_spin_lock virt_spin_lock

/*
 * RHEL7 specific:
 * To provide backward compatibility with pre-7.4 kernel modules that
 * inlines the ticket spinlock unlock code. The virt_spin_lock() function
 * will have to recognize both a lock value of 0 or _Q_UNLOCKED_VAL as
 * being in an unlocked state.
 */
static inline bool virt_spin_lock(struct qspinlock *lock)
{
	int lockval;

	if (!static_cpu_has(X86_FEATURE_HYPERVISOR))
		return false;

	/*
	 * On hypervisors without PARAVIRT_SPINLOCKS support we fall
	 * back to a Test-and-Set spinlock, because fair locks have
	 * horrible lock 'holder' preemption issues.
	 */

	do {
		while ((lockval = atomic_read(&lock->val)) &&
		       (lockval != _Q_UNLOCKED_VAL))
			cpu_relax();
	} while (atomic_cmpxchg(&lock->val, lockval, _Q_LOCKED_VAL) != lockval);

	return true;
}

#include <asm-generic/qspinlock.h>

#endif /* _ASM_X86_QSPINLOCK_H */
