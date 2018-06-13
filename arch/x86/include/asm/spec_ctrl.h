#ifndef _ASM_X86_SPEC_CTRL_H
#define _ASM_X86_SPEC_CTRL_H

#define SPEC_CTRL_PCP_IBRS_ENTRY	(1<<0)
#define SPEC_CTRL_PCP_IBRS_EXIT 	(1<<1)

#define SPEC_CTRL_PCP_IBRS (SPEC_CTRL_PCP_IBRS_ENTRY|SPEC_CTRL_PCP_IBRS_EXIT)

#define IBRS_ENABLED_PCP	PER_CPU_VAR(spec_ctrl_pcp + \
				KERNEL_IBRS_SPEC_CTRL_enabled)
#define IBRS_ENTRY_PCP		PER_CPU_VAR(spec_ctrl_pcp + \
				KERNEL_IBRS_SPEC_CTRL_entry)
#define IBRS_EXIT_PCP		PER_CPU_VAR(spec_ctrl_pcp + \
				KERNEL_IBRS_SPEC_CTRL_exit)
#define IBRS_HI32_PCP		PER_CPU_VAR(spec_ctrl_pcp + \
				KERNEL_IBRS_SPEC_CTRL_hi32)

#ifdef __ASSEMBLY__

#include <asm/msr-index.h>

.macro __IBRS_ENTRY
	movl IBRS_HI32_PCP, %edx
	movl IBRS_ENTRY_PCP, %eax
	GET_THREAD_INFO(%rcx)
	bt   $TIF_SSBD, TI_flags(%rcx)
	jnc  .Lno_ssbd_\@
	orl  $FEATURE_ENABLE_SSBD, %eax
.Lno_ssbd_\@:
	movl $MSR_IA32_SPEC_CTRL, %ecx
	wrmsr
.endm

.macro IBRS_ENTRY
	testl $SPEC_CTRL_PCP_IBRS_ENTRY, IBRS_ENABLED_PCP
	jz .Lskip_\@

	pushq %rax
	pushq %rcx
	pushq %rdx
	__IBRS_ENTRY
	popq %rdx
	popq %rcx
	popq %rax
	jmp .Lend_\@

.Lskip_\@:
	lfence
.Lend_\@:
.endm

.macro IBRS_ENTRY_CLOBBER
	testl $SPEC_CTRL_PCP_IBRS_ENTRY, IBRS_ENABLED_PCP
	jz .Lskip_\@

	__IBRS_ENTRY
	jmp .Lend_\@

.Lskip_\@:
	lfence
.Lend_\@:
.endm

#define NO_IBRS_RESTORE		(-1)	/* No restore on exit */

/*
 * The save_reg is initialize to NO_IBRS_RESTORE just in case IBRS is
 * enabled in the middle of an exception, this avoids the very remote risk
 * of writing random save_reg content into the SPEC_CTRL MSR in such case.
 */
.macro IBRS_ENTRY_SAVE_AND_CLOBBER save_reg:req
	movl $NO_IBRS_RESTORE, \save_reg
	testl $SPEC_CTRL_PCP_IBRS_ENTRY, IBRS_ENABLED_PCP
	jz .Lskip_\@

	movl $MSR_IA32_SPEC_CTRL, %ecx
	rdmsr
	/*
	 * If the content of the MSR matches the kernel entry value,
	 * we should still rewrite the MSR anyway to enforce the
	 * barrier-like semantics in some IBRS implementations.
	 * Nowever, we can leave the save_reg as NO_IBRS_RESTORE
	 * so that we won't do a rewrite on exit,
	 *
	 * When the values don't match, the state of the SSBD bit in the
	 * MSR is transferred to new value.
	 *
	 * %edx is initialized by rdmsr above, and so it doesn't need
	 * to be touched.
	 */
	movl IBRS_ENTRY_PCP, %ecx
	cmpl %eax, %ecx
	je   .Lwrmsr_\@

	movl %eax, \save_reg
	andl $FEATURE_ENABLE_SSBD, %eax
	orl  %ecx, %eax
.Lwrmsr_\@:
	movl $MSR_IA32_SPEC_CTRL, %ecx
	wrmsr
	jmp .Lend_\@

.Lskip_\@:
	lfence
.Lend_\@:
.endm

.macro __IBRS_EXIT
	movl IBRS_HI32_PCP, %edx
	movl IBRS_EXIT_PCP, %eax
	GET_THREAD_INFO(%rcx)
	bt   $TIF_SSBD, TI_flags(%rcx)
	jnc  .Lno_ssbd_\@
	orl  $FEATURE_ENABLE_SSBD, %eax
.Lno_ssbd_\@:
	movl $MSR_IA32_SPEC_CTRL, %ecx
	wrmsr
.endm

.macro IBRS_EXIT
	testl $SPEC_CTRL_PCP_IBRS_EXIT, IBRS_ENABLED_PCP
	jz .Lskip_\@

	pushq %rax
	pushq %rcx
	pushq %rdx
	__IBRS_EXIT
	popq %rdx
	popq %rcx
	popq %rax

.Lskip_\@:
.endm

.macro IBRS_EXIT_RESTORE_CLOBBER save_reg:req
	testl $SPEC_CTRL_PCP_IBRS, IBRS_ENABLED_PCP
	jz .Lskip_\@

	cmpl $NO_IBRS_RESTORE, \save_reg
	je .Lskip_\@

	movl $MSR_IA32_SPEC_CTRL, %ecx
	movl IBRS_HI32_PCP, %edx
	movl \save_reg, %eax
	wrmsr

.Lskip_\@:
.endm

.macro IBRS_EXIT_CLOBBER
	testl $SPEC_CTRL_PCP_IBRS_EXIT, IBRS_ENABLED_PCP
	jz .Lskip_\@

	__IBRS_EXIT

.Lskip_\@:
.endm

.macro CLEAR_EXTRA_REGS
	xorq %r15, %r15
	xorq %r14, %r14
	xorq %r13, %r13
	xorq %r12, %r12
	xorq %rbp, %rbp
	xorq %rbx, %rbx
.endm

.macro CLEAR_R8_TO_R15
	xorq %r15, %r15
	xorq %r14, %r14
	xorq %r13, %r13
	xorq %r12, %r12
	xorq %r11, %r11
	xorq %r10, %r10
	xorq %r9, %r9
	xorq %r8, %r8
.endm

.macro CLEAR_R10_TO_R15
	xorq %r15, %r15
	xorq %r14, %r14
	xorq %r13, %r13
	xorq %r12, %r12
	xorq %r11, %r11
	xorq %r10, %r10
.endm

#else /* __ASSEMBLY__ */

#include <linux/ptrace.h>
#include <asm/microcode.h>
#include <asm/nospec-branch.h>

extern struct static_key retp_enabled_key;
extern struct static_key ibrs_present_key;

extern void spec_ctrl_rescan_cpuid(void);
extern void spec_ctrl_init(void);
extern void spec_ctrl_cpu_init(void);
extern void ssb_select_mitigation(void);

bool spec_ctrl_force_enable_ibrs(void);
bool spec_ctrl_cond_enable_ibrs(bool full_retpoline);
bool spec_ctrl_enable_ibrs_always(void);
bool spec_ctrl_force_enable_ibp_disabled(void);
bool spec_ctrl_cond_enable_ibp_disabled(void);
void spec_ctrl_enable_retpoline(void);
bool spec_ctrl_enable_retpoline_ibrs_user(void);

enum spectre_v2_mitigation spec_ctrl_get_mitigation(void);

bool unprotected_firmware_begin(void);
void unprotected_firmware_end(bool ibrs_on);

/*
 * Percpu IBRS kernel entry/exit control structure
 */
struct kernel_ibrs_spec_ctrl {
	unsigned int enabled;	/* Entry and exit enabled control bits */
	unsigned int entry;	/* Lower 32-bit of SPEC_CTRL MSR for entry */
	unsigned int exit;	/* Lower 32-bit of SPEC_CTRL MSR for exit */
	unsigned int hi32;	/* Upper 32-bit of SPEC_CTRL MSR */
};

DECLARE_PER_CPU_USER_MAPPED(struct kernel_ibrs_spec_ctrl, spec_ctrl_pcp);

extern void x86_amd_rds_enable(void);

/* The Intel SPEC CTRL MSR base value cache */
extern u64 x86_spec_ctrl_base;

static inline u64 rds_tif_to_spec_ctrl(u64 tifn)
{
	BUILD_BUG_ON(TIF_SSBD < FEATURE_ENABLE_SSBD_SHIFT);
	return (tifn & _TIF_SSBD) >> (TIF_SSBD - FEATURE_ENABLE_SSBD_SHIFT);
}

static inline u64 rds_tif_to_amd_ls_cfg(u64 tifn)
{
	return (tifn & _TIF_SSBD) ? x86_amd_ls_cfg_rds_mask : 0ULL;
}

extern void speculative_store_bypass_update(void);

enum {
	IBRS_DISABLED,

	/* in host kernel, disabled in guest and userland */
	IBRS_ENABLED,

	/* in host kernel and host userland, disabled in guest */
	IBRS_ENABLED_ALWAYS,

	/* in host userland, disabled in kernel and guest */
	IBRS_ENABLED_USER,

	IBRS_MAX = IBRS_ENABLED_USER,
};

static __always_inline int cpu_has_spec_ctrl(void)
{
	return static_key_false(&ibrs_present_key);
}

static __always_inline bool ibrs_enabled_kernel(void)
{
	if (cpu_has_spec_ctrl()) {
		unsigned int ibrs = __this_cpu_read(spec_ctrl_pcp.entry);

		return ibrs & FEATURE_ENABLE_IBRS;
	}

	return false;
}

static inline bool retp_enabled(void)
{
	return static_key_false(&retp_enabled_key);
}

static inline bool retp_enabled_full(void)
{
	return retp_enabled() && retp_compiler();
}

static inline bool ibpb_enabled(void)
{
	return (boot_cpu_has(X86_FEATURE_IBPB) &&
		(ibrs_enabled_kernel() || retp_enabled()));
}

/*
 * On VMENTER we must preserve whatever view of the SPEC_CTRL MSR
 * the guest has, while on VMEXIT we restore the kernel view. This
 * would be easier if SPEC_CTRL were architecturally maskable or
 * shadowable for guests but this is not (currently) the case.
 * Takes the guest view of SPEC_CTRL MSR as a parameter.
 */

/*
 * RHEL note: Upstream implements two new functions to handle this:
 *
 *	- extern void x86_spec_ctrl_set_guest(u64);
 *	- extern void x86_spec_ctrl_restore_host(u64);
 *
 * We already have the following two functions in RHEL so the
 * above are not included in the RHEL version of the backport.
 */

static __always_inline u64 spec_ctrl_vmenter_ibrs(u64 vcpu_ibrs)
{

	/*
	 * RHEL TODO: rename this function to just spec_ctrl_enter since
	 *            we actually are updating the whole SPEC_CTRL MSR
	 */

	/*
	 * If IBRS is enabled for host kernel mode or host always mode
	 * we must set FEATURE_ENABLE_IBRS at vmexit.  This is performance
	 * critical code so we pass host_ibrs back to KVM.  Preemption is
	 * disabled, so we cannot race with sysfs writes.
	 */

	u64 host_ibrs = ibrs_enabled_kernel() ? FEATURE_ENABLE_IBRS : 0;

	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
		host_ibrs |= rds_tif_to_spec_ctrl(current_thread_info()->flags);

	if (unlikely(vcpu_ibrs != host_ibrs))
		native_wrmsrl(MSR_IA32_SPEC_CTRL, vcpu_ibrs);

	/* rmb not needed when disabling IBRS */
	return host_ibrs;
}

static __always_inline void __spec_ctrl_vmexit_ibrs(u64 host_ibrs, u64 vcpu_ibrs)
{

	/*
	 * RHEL TODO: rename this function to just spec_ctrl_vmexit since
	 *            we actually are updating the whole SPEC_CTRL MSR
	 */

	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
		host_ibrs |= rds_tif_to_spec_ctrl(current_thread_info()->flags);

	/* IBRS may have barrier semantics so it must be set during vmexit.  */
	if (unlikely(host_ibrs || vcpu_ibrs != host_ibrs)) {
		native_wrmsrl(MSR_IA32_SPEC_CTRL,
			      x86_spec_ctrl_base|host_ibrs);
		return;
	}

	/* This is an unconditional jump, no wrong speculation is possible.  */
	if (retp_enabled_full())
		return;

	/* rmb to prevent wrong speculation for security */
	rmb();
}

static __always_inline void spec_ctrl_ibrs_on(void)
{
	/*
	 * IBRS may have barrier semantics so it must be set even for ALWAYS
	 * mode.
	 */
	if (ibrs_enabled_kernel()) {
		u64 spec_ctrl = x86_spec_ctrl_base|FEATURE_ENABLE_IBRS;

		if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
			spec_ctrl |= rds_tif_to_spec_ctrl(
					current_thread_info()->flags);

		native_wrmsrl(MSR_IA32_SPEC_CTRL, spec_ctrl);
		return;
	}

	/* This is an unconditional jump, no wrong speculation is possible.  */
	if (retp_enabled_full())
		return;

	/* rmb to prevent wrong speculation for security */
	rmb();
}

static __always_inline void spec_ctrl_ibrs_off(void)
{
	if (ibrs_enabled_kernel()) {
		u64 spec_ctrl = x86_spec_ctrl_base;

		if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
		spec_ctrl |= rds_tif_to_spec_ctrl(
				current_thread_info()->flags);

		native_wrmsrl(MSR_IA32_SPEC_CTRL, spec_ctrl);
	}
	/* rmb not needed when disabling IBRS */
}

/*
 * These functions are called before calling into firmware.  Firmware might
 * have indirect branches, so if we're running with retpolines, we need to
 * enable IBRS to protect the kernel from spectre v2.
 *
 * The 'ibrs_on' variable is used to prevent race conditions.  Otherwise, if
 * the admin disabled IBRS while a CPU was running in firmware, IBRS could get
 * stuck on indefinitely.
 *
 * There are still other race conditions possible, but they're generally not a
 * problem because they'll get corrected on the next kernel exit.
 */
static inline bool spec_ctrl_ibrs_on_firmware(void)
{
	bool ibrs_on = false;

	if (cpu_has_spec_ctrl() && retp_enabled() && !ibrs_enabled_kernel()) {
		u64 spec_ctrl = x86_spec_ctrl_base|FEATURE_ENABLE_IBRS;

		if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
			spec_ctrl |= rds_tif_to_spec_ctrl(
					current_thread_info()->flags);

		native_wrmsrl(MSR_IA32_SPEC_CTRL, spec_ctrl);
		ibrs_on = true;
	} else {
		/* rmb to prevent wrong speculation for security */
		rmb();
	}

	return ibrs_on;
}

static inline void spec_ctrl_ibrs_off_firmware(bool ibrs_on)
{
	if (ibrs_on) {
		u64 spec_ctrl = x86_spec_ctrl_base;

		if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
			spec_ctrl |= rds_tif_to_spec_ctrl(
					current_thread_info()->flags);

		native_wrmsrl(MSR_IA32_SPEC_CTRL, spec_ctrl);
	} else {
		/* rmb to prevent wrong speculation for security */
		rmb();
	}
}

static inline void __spec_ctrl_ibpb(void)
{
	native_wrmsrl(MSR_IA32_PRED_CMD, FEATURE_SET_IBPB);
}

static inline void spec_ctrl_ibpb(void)
{
	if (ibpb_enabled())
		__spec_ctrl_ibpb();
}

static inline void spec_ctrl_ibpb_if_different_creds(struct task_struct *next)
{
	if (ibpb_enabled() &&
	    (!next || __ptrace_may_access(next, PTRACE_MODE_IBPB))) {
		__spec_ctrl_ibpb();

		if (static_cpu_has(X86_FEATURE_SMEP))
			fill_RSB();
	}
}

extern enum ssb_mitigation ssb_mode;

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SPEC_CTRL_H */
