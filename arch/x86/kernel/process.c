#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/prctl.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/pm.h>
#include <linux/clockchips.h>
#include <linux/random.h>
#include <linux/user-return-notifier.h>
#include <linux/dmi.h>
#include <linux/utsname.h>
#include <linux/stackprotector.h>
#include <linux/tick.h>
#include <linux/cpuidle.h>
#include <trace/events/power.h>
#include <linux/hw_breakpoint.h>
#include <asm/cpu.h>
#include <asm/apic.h>
#include <asm/syscalls.h>
#include <asm/idle.h>
#include <asm/uaccess.h>
#include <asm/i387.h>
#include <asm/fpu-internal.h>
#include <asm/debugreg.h>
#include <asm/nmi.h>
#include <asm/mce.h>
#include <asm/prctl.h>
#include <asm/spec_ctrl.h>

/*
 * per-CPU TSS segments. Threads are completely 'soft' on Linux,
 * no more per-task TSS's. The TSS size is kept cacheline-aligned
 * so they are allowed to end up in the .data..cacheline_aligned
 * section. Since TSS's are completely CPU-local, we want them
 * on exact cacheline boundaries, to eliminate cacheline ping-pong.
 */
DEFINE_PER_CPU_PAGE_ALIGNED_USER_MAPPED(struct tss_struct, init_tss) = INIT_TSS;

#ifdef CONFIG_X86_64
static DEFINE_PER_CPU(unsigned char, is_idle);
static ATOMIC_NOTIFIER_HEAD(idle_notifier);

void idle_notifier_register(struct notifier_block *n)
{
	atomic_notifier_chain_register(&idle_notifier, n);
}
EXPORT_SYMBOL_GPL(idle_notifier_register);

void idle_notifier_unregister(struct notifier_block *n)
{
	atomic_notifier_chain_unregister(&idle_notifier, n);
}
EXPORT_SYMBOL_GPL(idle_notifier_unregister);
#endif

struct kmem_cache *task_xstate_cachep;
EXPORT_SYMBOL_GPL(task_xstate_cachep);

/*
 * this gets called so that we can store lazy state into memory and copy the
 * current task into the new thread.
 */
int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	int ret;

	*dst = *src;
	if (fpu_allocated(&src->thread.fpu)) {
		memset(&dst->thread.fpu, 0, sizeof(dst->thread.fpu));
		ret = fpu_alloc(&dst->thread.fpu);
		if (ret)
			return ret;
		fpu_copy(dst, src);
	}
	return 0;
}

void free_thread_xstate(struct task_struct *tsk)
{
	fpu_free(&tsk->thread.fpu);
}

void arch_release_task_struct(struct task_struct *tsk)
{
	free_thread_xstate(tsk);
}

void arch_task_cache_init(void)
{
        task_xstate_cachep =
        	kmem_cache_create("task_xstate", xstate_size,
				  __alignof__(union thread_xstate),
				  SLAB_PANIC | SLAB_NOTRACK, NULL);
	setup_xstate_comp();
}

/*
 * Free current thread data structures etc..
 */
void exit_thread(void)
{
	struct task_struct *me = current;
	struct thread_struct *t = &me->thread;
	unsigned long *bp = t->io_bitmap_ptr;

	if (bp) {
		struct tss_struct *tss = &per_cpu(init_tss, get_cpu());

		t->io_bitmap_ptr = NULL;
		clear_thread_flag(TIF_IO_BITMAP);
		/*
		 * Careful, clear this in the TSS too:
		 */
		memset(tss->io_bitmap, 0xff, t->io_bitmap_max);
		t->io_bitmap_max = 0;
		put_cpu();
		kfree(bp);
	}

	drop_fpu(me);
}

void flush_thread(void)
{
	struct task_struct *tsk = current;

	flush_ptrace_hw_breakpoint(tsk);
	memset(tsk->thread.tls_array, 0, sizeof(tsk->thread.tls_array));
	drop_init_fpu(tsk);
	/*
	 * Free the FPU state for non xsave platforms. They get reallocated
	 * lazily at the first use.
	 */
	if (!use_eager_fpu())
		free_thread_xstate(tsk);
}

static void hard_disable_TSC(void)
{
	write_cr4(read_cr4() | X86_CR4_TSD);
}

void disable_TSC(void)
{
	preempt_disable();
	if (!test_and_set_thread_flag(TIF_NOTSC))
		/*
		 * Must flip the CPU state synchronously with
		 * TIF_NOTSC in the current running context.
		 */
		hard_disable_TSC();
	preempt_enable();
}

static void hard_enable_TSC(void)
{
	write_cr4(read_cr4() & ~X86_CR4_TSD);
}

static void enable_TSC(void)
{
	preempt_disable();
	if (test_and_clear_thread_flag(TIF_NOTSC))
		/*
		 * Must flip the CPU state synchronously with
		 * TIF_NOTSC in the current running context.
		 */
		hard_enable_TSC();
	preempt_enable();
}

int get_tsc_mode(unsigned long adr)
{
	unsigned int val;

	if (test_thread_flag(TIF_NOTSC))
		val = PR_TSC_SIGSEGV;
	else
		val = PR_TSC_ENABLE;

	return put_user(val, (unsigned int __user *)adr);
}

int set_tsc_mode(unsigned int val)
{
	if (val == PR_TSC_SIGSEGV)
		disable_TSC();
	else if (val == PR_TSC_ENABLE)
		enable_TSC();
	else
		return -EINVAL;

	return 0;
}

#ifdef CONFIG_SMP

struct ssb_state {
	struct ssb_state	*shared_state;
	raw_spinlock_t		lock;
	unsigned int		disable_state;
	unsigned long		local_state;
};

#define LSTATE_SSB	0

static DEFINE_PER_CPU(struct ssb_state, ssb_state);

void speculative_store_bypass_ht_init(void)
{
	struct ssb_state *st = this_cpu_ptr(&ssb_state);
	unsigned int this_cpu = smp_processor_id();
	unsigned int cpu;

	st->local_state = 0;

	/*
	 * Shared state setup happens once on the first bringup
	 * of the CPU. It's not destroyed on CPU hotunplug.
	 */
	if (st->shared_state)
		return;

	raw_spin_lock_init(&st->lock);

	/*
	 * Go over HT siblings and check whether one of them has set up the
	 * shared state pointer already.
	 */
	for_each_cpu(cpu, topology_sibling_cpumask(this_cpu)) {
		if (cpu == this_cpu)
			continue;

		if (!per_cpu(ssb_state, cpu).shared_state)
			continue;

		/* Link it to the state of the sibling: */
		st->shared_state = per_cpu(ssb_state, cpu).shared_state;
		return;
	}

	/*
	 * First HT sibling to come up on the core.  Link shared state of
	 * the first HT sibling to itself. The siblings on the same core
	 * which come up later will see the shared state pointer and link
	 * themself to the state of this CPU.
	 */
	st->shared_state = st;
}

/*
 * Logic is: First HT sibling enables SSBD for both siblings in the core
 * and last sibling to disable it, disables it for the whole core. This how
 * MSR_SPEC_CTRL works in "hardware":
 *
 *  CORE_SPEC_CTRL = THREAD0_SPEC_CTRL | THREAD1_SPEC_CTRL
 */
static __always_inline void amd_set_core_ssb_state(unsigned long tifn)
{
	struct ssb_state *st = this_cpu_ptr(&ssb_state);
	u64 msr = x86_amd_ls_cfg_base;

	if (!static_cpu_has(X86_FEATURE_ZEN)) {
		msr |= ssbd_tif_to_amd_ls_cfg(tifn);
		wrmsrl(MSR_AMD64_LS_CFG, msr);
		return;
	}

	if (tifn & _TIF_SSBD) {
		/*
		 * Since this can race with prctl(), block reentry on the
		 * same CPU.
		 */
		if (__test_and_set_bit(LSTATE_SSB, &st->local_state))
			return;

		msr |= x86_amd_ls_cfg_ssbd_mask;

		raw_spin_lock(&st->shared_state->lock);
		/* First sibling enables SSBD: */
		if (!st->shared_state->disable_state)
			wrmsrl(MSR_AMD64_LS_CFG, msr);
		st->shared_state->disable_state++;
		raw_spin_unlock(&st->shared_state->lock);
	} else {
		if (!__test_and_clear_bit(LSTATE_SSB, &st->local_state))
			return;

		raw_spin_lock(&st->shared_state->lock);
		st->shared_state->disable_state--;
		if (!st->shared_state->disable_state)
			wrmsrl(MSR_AMD64_LS_CFG, msr);
		raw_spin_unlock(&st->shared_state->lock);
	}
}
#else
static __always_inline void amd_set_core_ssb_state(unsigned long tifn)
{
	u64 msr = x86_amd_ls_cfg_base | ssbd_tif_to_amd_ls_cfg(tifn);

	wrmsrl(MSR_AMD64_LS_CFG, msr);
}
#endif

static __always_inline void amd_set_ssb_virt_state(unsigned long tifn)
{
	/*
	 * SSBD has the same definition in SPEC_CTRL and VIRT_SPEC_CTRL,
	 * so ssbd_tif_to_spec_ctrl() just works.
	 */
	wrmsrl(MSR_AMD64_VIRT_SPEC_CTRL, ssbd_tif_to_spec_ctrl(tifn));
}

static __always_inline void __speculation_ctrl_update(unsigned long tifp,
						      unsigned long tifn)
{
	bool updmsr = false;

	if (!static_key_false(&ssbd_userset_key))
		return;	/* Don't do anything if not user settable */

	/* If TIF_SSBD is different, select the proper mitigation method */
	if ((tifp ^ tifn) & _TIF_SSBD) {
		if (static_cpu_has(X86_FEATURE_VIRT_SSBD)) {
			amd_set_ssb_virt_state(tifn);
		} else if (static_cpu_has(X86_FEATURE_LS_CFG_SSBD)) {
			amd_set_core_ssb_state(tifn);
		} else if (static_cpu_has(X86_FEATURE_SPEC_CTRL_SSBD) ||
			   static_cpu_has(X86_FEATURE_AMD_SSBD)) {
			spec_ctrl_set_ssbd(ssbd_tif_to_spec_ctrl(tifn));
			updmsr = true;
		}
	}

	if (updmsr)
		wrmsrl(MSR_IA32_SPEC_CTRL,
		       this_cpu_read(spec_ctrl_pcp.entry64));
}

static unsigned long speculation_ctrl_update_tif(struct task_struct *tsk)
{
	if (test_and_clear_tsk_thread_flag(tsk, TIF_SPEC_FORCE_UPDATE)) {
		if (task_spec_ssb_disable(tsk))
			set_tsk_thread_flag(tsk, TIF_SSBD);
		else
			clear_tsk_thread_flag(tsk, TIF_SSBD);
	}
	/* Return the updated threadinfo flags*/
	return task_thread_info(tsk)->flags;
}

void speculation_ctrl_update(unsigned long tif)
{
	unsigned long flags;

	/* Forced update. Make sure all relevant TIF flags are different */
	local_irq_save(flags);
	__speculation_ctrl_update(~tif, tif);
	local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(speculation_ctrl_update);

static inline void switch_to_bitmap(struct tss_struct *tss,
				    struct thread_struct *prev,
				    struct thread_struct *next,
				    unsigned long tifp, unsigned long tifn)
{
	if (tifn & _TIF_IO_BITMAP) {
		/*
		 * Copy the relevant range of the IO bitmap.
		 * Normally this is 128 bytes or less:
		 */
		memcpy(tss->io_bitmap, next->io_bitmap_ptr,
		       max(prev->io_bitmap_max, next->io_bitmap_max));
	} else if (tifp & _TIF_IO_BITMAP) {
		/*
		 * Clear any possible leftover bits:
		 */
		memset(tss->io_bitmap, 0xff, prev->io_bitmap_max);
	}
}

/* Called from seccomp/prctl update */
void speculation_ctrl_update_current(void)
{
	preempt_disable();
	speculation_ctrl_update(speculation_ctrl_update_tif(current));
	preempt_enable();
}

/*
 * Called immediately after a successful exec.
 */
void arch_setup_new_exec(void)
{
	/*
	 * Don't inherit TIF_SSBD across exec boundary when
	 * PR_SPEC_DISABLE_NOEXEC is used.
	 */
	if (test_thread_flag(TIF_SSBD) &&
	    task_spec_ssb_noexec(current)) {
		clear_thread_flag(TIF_SSBD);
		task_clear_spec_ssb_disable(current);
		task_clear_spec_ssb_noexec(current);
		speculation_ctrl_update(task_thread_info(current)->flags);
	}
}

void __switch_to_xtra(struct task_struct *prev_p, struct task_struct *next_p,
		      struct tss_struct *tss)
{
	struct thread_struct *prev, *next;
	unsigned long tifp, tifn;

	prev = &prev_p->thread;
	next = &next_p->thread;

	tifn = READ_ONCE(task_thread_info(next_p)->flags);
	tifp = READ_ONCE(task_thread_info(prev_p)->flags);
	switch_to_bitmap(tss, prev, next, tifp, tifn);

	propagate_user_return_notify(prev_p, next_p);

	if ((tifp ^ tifn) & _TIF_BLOCKSTEP) {
		unsigned long debugctl = get_debugctlmsr();

		debugctl &= ~DEBUGCTLMSR_BTF;
		if (tifn & _TIF_BLOCKSTEP)
			debugctl |= DEBUGCTLMSR_BTF;

		update_debugctlmsr(debugctl);
	}

	if ((tifp ^ tifn) & _TIF_NOTSC) {
		if (tifn & _TIF_NOTSC)
			hard_disable_TSC();
		else
			hard_enable_TSC();
	}

	if (likely(!((tifp | tifn) & _TIF_SPEC_FORCE_UPDATE))) {
		__speculation_ctrl_update(tifp, tifn);
	} else {
		speculation_ctrl_update_tif(prev_p);
		tifn = speculation_ctrl_update_tif(next_p);

		/* Enforce MSR update to ensure consistent state */
		__speculation_ctrl_update(~tifn, tifn);
	}
}

/*
 * Idle related variables and functions
 */
unsigned long boot_option_idle_override = IDLE_NO_OVERRIDE;
EXPORT_SYMBOL(boot_option_idle_override);

static void (*x86_idle)(void);

#ifndef CONFIG_SMP
static inline void play_dead(void)
{
	BUG();
}
#endif

#ifdef CONFIG_X86_64
void enter_idle(void)
{
	this_cpu_write(is_idle, 1);
	atomic_notifier_call_chain(&idle_notifier, IDLE_START, NULL);
}

static void __exit_idle(void)
{
	if (x86_test_and_clear_bit_percpu(0, is_idle) == 0)
		return;
	atomic_notifier_call_chain(&idle_notifier, IDLE_END, NULL);
}

/* Called from interrupts to signify idle end */
void exit_idle(void)
{
	/* idle loop has pid 0 */
	if (current->pid)
		return;
	__exit_idle();
}
#endif

void arch_cpu_idle_enter(void)
{
	tsc_verify_tsc_adjust();
	local_touch_nmi();
	enter_idle();
}

void arch_cpu_idle_exit(void)
{
	__exit_idle();
}

void arch_cpu_idle_dead(void)
{
	play_dead();
}

/*
 * Called from the generic idle code.
 */
void arch_cpu_idle(void)
{
	if (cpuidle_idle_call()) {
		/* The cpuidle call failed, fallback to a simpler idle */
		spec_ctrl_ibrs_off();
		x86_idle();
		spec_ctrl_ibrs_on();
	} else
		local_irq_enable();
}

/*
 * We use this if we don't have any better idle routine..
 */
void __cpuidle default_idle(void)
{
	trace_cpu_idle_rcuidle(1, smp_processor_id());
	safe_halt();
	trace_cpu_idle_rcuidle(PWR_EVENT_EXIT, smp_processor_id());
}
#if defined(CONFIG_APM_MODULE) || defined(CONFIG_HALTPOLL_CPUIDLE_MODULE)
EXPORT_SYMBOL(default_idle);
#endif

#ifdef CONFIG_XEN
bool xen_set_default_idle(void)
{
	bool ret = !!x86_idle;

	x86_idle = default_idle;

	return ret;
}
#endif

void stop_this_cpu(void *dummy)
{
	local_irq_disable();
	/*
	 * Remove this CPU:
	 */
	set_cpu_online(smp_processor_id(), false);
	disable_local_APIC();
	mcheck_cpu_clear(this_cpu_ptr(&cpu_info));

	/*
	 * Use wbinvd on processors that support SME. This provides support
	 * for performing a successful kexec when going from SME inactive
	 * to SME active (or vice-versa). The cache must be cleared so that
	 * if there are entries with the same physical address, both with and
	 * without the encryption bit, they don't race each other when flushed
	 * and potentially end up with the wrong entry being committed to
	 * memory.
	 */
	if (boot_cpu_has(X86_FEATURE_SME))
		native_wbinvd();
	for (;;) {
		/*
		 * Use native_halt() so that memory contents don't change
		 * (stack usage and variables) after possibly issuing the
		 * native_wbinvd() above.
		 */
		native_halt();
	}
}

bool amd_e400_c1e_detected;
EXPORT_SYMBOL(amd_e400_c1e_detected);

static cpumask_var_t amd_e400_c1e_mask;

void amd_e400_remove_cpu(int cpu)
{
	if (amd_e400_c1e_mask != NULL)
		cpumask_clear_cpu(cpu, amd_e400_c1e_mask);
}

/*
 * AMD Erratum 400 aware idle routine. We check for C1E active in the interrupt
 * pending message MSR. If we detect C1E, then we handle it the same
 * way as C3 power states (local apic timer and TSC stop)
 */
static void amd_e400_idle(void)
{
	if (!amd_e400_c1e_detected) {
		u32 lo, hi;

		rdmsr(MSR_K8_INT_PENDING_MSG, lo, hi);

		if (lo & K8_INTP_C1E_ACTIVE_MASK) {
			amd_e400_c1e_detected = true;
			if (!boot_cpu_has(X86_FEATURE_NONSTOP_TSC))
				mark_tsc_unstable("TSC halt in AMD C1E");
			pr_info("System has AMD C1E enabled\n");
		}
	}

	if (amd_e400_c1e_detected) {
		int cpu = smp_processor_id();

		if (!cpumask_test_cpu(cpu, amd_e400_c1e_mask)) {
			cpumask_set_cpu(cpu, amd_e400_c1e_mask);
			/*
			 * Force broadcast so ACPI can not interfere.
			 */
			clockevents_notify(CLOCK_EVT_NOTIFY_BROADCAST_FORCE,
					   &cpu);
			pr_info("Switch to broadcast mode on CPU%d\n", cpu);
		}
		clockevents_notify(CLOCK_EVT_NOTIFY_BROADCAST_ENTER, &cpu);

		default_idle();

		/*
		 * The switch back from broadcast mode needs to be
		 * called with interrupts disabled.
		 */
		local_irq_disable();
		clockevents_notify(CLOCK_EVT_NOTIFY_BROADCAST_EXIT, &cpu);
		local_irq_enable();
	} else
		default_idle();
}

void select_idle_routine(const struct cpuinfo_x86 *c)
{
#ifdef CONFIG_SMP
	if (boot_option_idle_override == IDLE_POLL && smp_num_siblings > 1)
		pr_warn_once("WARNING: polling idle and HT enabled, performance may degrade\n");
#endif
	if (x86_idle || boot_option_idle_override == IDLE_POLL)
		return;

	if (cpu_has_bug(c, X86_BUG_AMD_APIC_C1E)) {
		/* E400: APIC timer interrupt does not wake up CPU from C1e */
		pr_info("using AMD E400 aware idle routine\n");
		x86_idle = amd_e400_idle;
	} else
		x86_idle = default_idle;
}

void __init init_amd_e400_c1e_mask(void)
{
	/* If we're using amd_e400_idle, we need to allocate amd_e400_c1e_mask. */
	if (x86_idle == amd_e400_idle)
		zalloc_cpumask_var(&amd_e400_c1e_mask, GFP_KERNEL);
}

static int __init idle_setup(char *str)
{
	if (!str)
		return -EINVAL;

	if (!strcmp(str, "poll")) {
		pr_info("using polling idle threads\n");
		boot_option_idle_override = IDLE_POLL;
		cpu_idle_poll_ctrl(true);
	} else if (!strcmp(str, "halt")) {
		/*
		 * When the boot option of idle=halt is added, halt is
		 * forced to be used for CPU idle. In such case CPU C2/C3
		 * won't be used again.
		 * To continue to load the CPU idle driver, don't touch
		 * the boot_option_idle_override.
		 */
		x86_idle = default_idle;
		boot_option_idle_override = IDLE_HALT;
	} else if (!strcmp(str, "nomwait")) {
		/*
		 * If the boot option of "idle=nomwait" is added,
		 * it means that mwait will be disabled for CPU C2/C3
		 * states. In such case it won't touch the variable
		 * of boot_option_idle_override.
		 */
		boot_option_idle_override = IDLE_NOMWAIT;
	} else
		return -1;

	return 0;
}
early_param("idle", idle_setup);

unsigned long arch_align_stack(unsigned long sp)
{
	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		sp -= get_random_int() % 8192;
	return sp & ~0xf;
}

unsigned long arch_randomize_brk(struct mm_struct *mm)
{
	return randomize_page(mm->brk, 0x02000000);
}

