#ifndef _ASM_X86_MWAIT_H
#define _ASM_X86_MWAIT_H

#include <linux/sched.h>
#include <asm/spec_ctrl.h>

#include <asm/cpufeature.h>
#include <asm/nospec-branch.h>

#define MWAIT_SUBSTATE_MASK		0xf
#define MWAIT_CSTATE_MASK		0xf
#define MWAIT_SUBSTATE_SIZE		4
#define MWAIT_HINT2CSTATE(hint)		(((hint) >> MWAIT_SUBSTATE_SIZE) & MWAIT_CSTATE_MASK)
#define MWAIT_HINT2SUBSTATE(hint)	((hint) & MWAIT_CSTATE_MASK)

#define CPUID_MWAIT_LEAF		5
#define CPUID5_ECX_EXTENSIONS_SUPPORTED 0x1
#define CPUID5_ECX_INTERRUPT_BREAK	0x2

#define MWAIT_ECX_INTERRUPT_BREAK	0x1

static __always_inline void __monitor(const void *eax, unsigned long ecx,
			     unsigned long edx)
{
	/* "monitor %eax, %ecx, %edx;" */
	asm volatile(".byte 0x0f, 0x01, 0xc8;"
		     :: "a" (eax), "c" (ecx), "d"(edx));
}

static __always_inline void __mwait(unsigned long eax, unsigned long ecx)
{
	mds_idle_clear_cpu_buffers();

	/* "mwait %eax, %ecx;" */
	asm volatile(".byte 0x0f, 0x01, 0xc9;"
		     :: "a" (eax), "c" (ecx));
}

/*
 * This uses new MONITOR/MWAIT instructions on P4 processors with PNI,
 * which can obviate IPI to trigger checking of need_resched.
 * We execute MONITOR against need_resched and enter optimized wait state
 * through MWAIT. Whenever someone changes need_resched, we would be woken
 * up from MWAIT (without an IPI).
 *
 * New with Core Duo processors, MWAIT can take some hints based on CPU
 * capability.
 */
static inline void mwait_idle_with_hints(unsigned long eax, unsigned long ecx)
{
	if (static_cpu_has_bug(X86_BUG_MONITOR) || !current_set_polling_and_test()) {
		if (this_cpu_has(X86_FEATURE_CLFLUSH_MONITOR))
			clflush((void *)&current_thread_info()->flags);

		/*
		 * IRQs must be disabled here and nmi uses the
		 * save_paranoid model which always enables ibrs on
		 * exception entry before any indirect jump can run.
		 */
		spec_ctrl_ibrs_off();
		__monitor((void *)&current_thread_info()->flags, 0, 0);
		if (!need_resched())
			__mwait(eax, ecx);
		spec_ctrl_ibrs_on();
	}
	__current_clr_polling();
}

#endif /* _ASM_X86_MWAIT_H */
