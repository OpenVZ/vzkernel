#ifndef _ASM_X86_SPEC_CTRL_H
#define _ASM_X86_SPEC_CTRL_H

#define SPEC_CTRL_PCP_IBRS_ENTRY	(1<<0)
#define SPEC_CTRL_PCP_IBRS_EXIT		(1<<1)

#define SPEC_CTRL_PCP_IBRS (SPEC_CTRL_PCP_IBRS_ENTRY|SPEC_CTRL_PCP_IBRS_EXIT)

#ifdef __ASSEMBLY__

#include <asm/msr-index.h>

.macro __IBRS_ENTRY
	movl $0, %edx
	movl $MSR_IA32_SPEC_CTRL, %ecx
	movl PER_CPU_VAR(spec_ctrl_pcp), %eax
	andl $1, %eax
	wrmsr
.endm

.macro IBRS_ENTRY
	testl $SPEC_CTRL_PCP_IBRS, PER_CPU_VAR(spec_ctrl_pcp)
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
	testl $SPEC_CTRL_PCP_IBRS, PER_CPU_VAR(spec_ctrl_pcp)
	jz .Lskip_\@

	__IBRS_ENTRY
	jmp .Lend_\@

.Lskip_\@:
	lfence
.Lend_\@:
.endm

.macro IBRS_ENTRY_SAVE_AND_CLOBBER save_reg:req
	testl $SPEC_CTRL_PCP_IBRS, PER_CPU_VAR(spec_ctrl_pcp)
	jz .Lskip_\@

	movl $MSR_IA32_SPEC_CTRL, %ecx
	rdmsr
	movl %eax, \save_reg

	__IBRS_ENTRY
	jmp .Lend_\@

.Lskip_\@:
	/*
	 * Simulate no IBRS just in case IBRS is enabled in the middle
	 * of an exception, this avoids the very remote risk of
	 * writing random save_reg content into the SPEC_CTRL MSR in
	 * such case.
	 */
	movl $FEATURE_ENABLE_IBRS, \save_reg

	lfence
.Lend_\@:
.endm

.macro __IBRS_EXIT
	movl $0, %edx
	movl $MSR_IA32_SPEC_CTRL, %ecx
	movl PER_CPU_VAR(spec_ctrl_pcp), %eax
	shrl $1, %eax
	andl $1, %eax
	wrmsr
.endm

.macro IBRS_EXIT
	testl $SPEC_CTRL_PCP_IBRS, PER_CPU_VAR(spec_ctrl_pcp)
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
	testl $SPEC_CTRL_PCP_IBRS, PER_CPU_VAR(spec_ctrl_pcp)
	jz .Lskip_\@

	cmpl $FEATURE_ENABLE_IBRS, \save_reg
	je .Lskip_\@

	movl $MSR_IA32_SPEC_CTRL, %ecx
	movl $0, %edx
	movl \save_reg, %eax
	wrmsr

.Lskip_\@:
.endm

.macro IBRS_EXIT_CLOBBER
	testl $SPEC_CTRL_PCP_IBRS, PER_CPU_VAR(spec_ctrl_pcp)
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

extern void spec_ctrl_rescan_cpuid(void);
extern void spec_ctrl_init(void);
extern void spec_ctrl_cpu_init(void);

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
	if (boot_cpu_has(X86_FEATURE_SPEC_CTRL))
		return 1;

	/* rmb to prevent wrong speculation for security */
	rmb();
	return 0;
}

static __always_inline unsigned int ibrs_enabled(void)
{
	if (cpu_has_spec_ctrl()) {
		unsigned int ibrs = __this_cpu_read(spec_ctrl_pcp);

		if ((ibrs & SPEC_CTRL_PCP_IBRS_ENTRY) &&
		    !(ibrs & SPEC_CTRL_PCP_IBRS_EXIT))
			return IBRS_ENABLED;

		if ((ibrs & SPEC_CTRL_PCP_IBRS_ENTRY) &&
		    (ibrs & SPEC_CTRL_PCP_IBRS_EXIT))
			return IBRS_ENABLED_ALWAYS;

		if (!(ibrs & SPEC_CTRL_PCP_IBRS_ENTRY) &&
		    (ibrs & SPEC_CTRL_PCP_IBRS_EXIT))
			return IBRS_ENABLED_USER;
	}

	 return IBRS_DISABLED;
}

static __always_inline bool ibrs_enabled_kernel(void)
{
	unsigned int ibrs = ibrs_enabled();

	return ibrs == IBRS_ENABLED || ibrs == IBRS_ENABLED_ALWAYS;
}

static inline bool retp_enabled(void)
{
	return static_key_enabled(&retp_enabled_key);
}

static inline bool ibpb_enabled(void)
{
	return (boot_cpu_has(X86_FEATURE_IBPB_SUPPORT) &&
		(ibrs_enabled_kernel() || retp_enabled()));
}

static __always_inline void __spec_ctrl_vm_ibrs(u64 vcpu_ibrs, bool vmenter)
{
	u64 host_ibrs = 0, val;
	bool write_spec_ctrl;

	if (ibrs_enabled_kernel()) {
		/*
		 * If IBRS is enabled for host kernel mode or
		 * host always mode we must set
		 * FEATURE_ENABLE_IBRS at vmexit.
		 */
		host_ibrs = FEATURE_ENABLE_IBRS;
	}

	val = vmenter ? vcpu_ibrs : host_ibrs;
	write_spec_ctrl = (!vmenter && host_ibrs) || (vcpu_ibrs != host_ibrs);

	/*
	 * IBRS may have barrier semantics so it must be set to
	 * satisfy those semantics during vmexit.
	 */
	if (write_spec_ctrl)
		native_wrmsrl(MSR_IA32_SPEC_CTRL, val);
	else
		/* rmb to prevent wrong speculation for security */
		rmb();
}

static __always_inline void spec_ctrl_vmenter_ibrs(u64 vcpu_ibrs)
{
	if (cpu_has_spec_ctrl())
		__spec_ctrl_vm_ibrs(vcpu_ibrs, true);
}

static __always_inline void __spec_ctrl_vmexit_ibrs(u64 vcpu_ibrs)
{
	__spec_ctrl_vm_ibrs(vcpu_ibrs, false);
}

static __always_inline void spec_ctrl_ibrs_on(void)
{
	if (ibrs_enabled_kernel())
		native_wrmsrl(MSR_IA32_SPEC_CTRL, FEATURE_ENABLE_IBRS);
	else
		/* rmb to prevent wrong speculation for security */
		rmb();
}

static __always_inline void spec_ctrl_ibrs_off(void)
{
	if (ibrs_enabled_kernel())
		native_wrmsrl(MSR_IA32_SPEC_CTRL, 0);
	else
		/* rmb to prevent wrong speculation for security */
		rmb();
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
		native_wrmsrl(MSR_IA32_SPEC_CTRL, FEATURE_ENABLE_IBRS);
		ibrs_on = true;
	} else {
		/* rmb to prevent wrong speculation for security */
		rmb();
	}

	return ibrs_on;
}

static inline void spec_ctrl_ibrs_off_firmware(bool ibrs_on)
{
	if (ibrs_on)
		native_wrmsrl(MSR_IA32_SPEC_CTRL, 0);
	else
		/* rmb to prevent wrong speculation for security */
		rmb();
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

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SPEC_CTRL_H */
