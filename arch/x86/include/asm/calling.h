/*

 x86 function call convention, 64-bit:
 -------------------------------------
  arguments           |  callee-saved      | extra caller-saved | return
 [callee-clobbered]   |                    | [callee-clobbered] |
 ---------------------------------------------------------------------------
 rdi rsi rdx rcx r8-9 | rbx rbp [*] r12-15 | r10-11             | rax, rdx [**]

 ( rsp is obviously invariant across normal function calls. (gcc can 'merge'
   functions when it sees tail-call optimization possibilities) rflags is
   clobbered. Leftover arguments are passed over the stack frame.)

 [*]  In the frame-pointers case rbp is fixed to the stack frame.

 [**] for struct return values wider than 64 bits the return convention is a
      bit more complex: up to 128 bits width we return small structures
      straight in rax, rdx. For structures larger than that (3 words or
      larger) the caller puts a pointer to an on-stack return struct
      [allocated in the caller's stack frame] into the first argument - i.e.
      into rdi. All other arguments shift up by one in this case.
      Fortunately this case is rare in the kernel.

For 32-bit we have the following conventions - kernel is built with
-mregparm=3 and -freg-struct-return:

 x86 function calling convention, 32-bit:
 ----------------------------------------
  arguments         | callee-saved        | extra caller-saved | return
 [callee-clobbered] |                     | [callee-clobbered] |
 -------------------------------------------------------------------------
 eax edx ecx        | ebx edi esi ebp [*] | <none>             | eax, edx [**]

 ( here too esp is obviously invariant across normal function calls. eflags
   is clobbered. Leftover arguments are passed over the stack frame. )

 [*]  In the frame-pointers case ebp is fixed to the stack frame.

 [**] We build with -freg-struct-return, which on 32-bit means similar
      semantics as on 64-bit: edx can be used for a second return value
      (i.e. covering integer and structure sizes up to 64 bits) - after that
      it gets more complex and more expensive: 3-word or larger struct returns
      get done in the caller's frame and the pointer to the return struct goes
      into regparm0, i.e. eax - the other arguments shift up and the
      function's register parameters degenerate to regparm=2 in essence.

*/

#include <asm/dwarf2.h>
#include <asm/cpufeatures.h>
#include <asm/nops.h>

/*
 * 64-bit system call stack frame layout defines and helpers,
 * for assembly code:
 */

#define R15		  0
#define R14		  8
#define R13		 16
#define R12		 24
#define RBP		 32
#define RBX		 40

/* arguments: interrupts/non tracing syscalls only save up to here: */
#define R11		 48
#define R10		 56
#define R9		 64
#define R8		 72
#define RAX		 80
#define RCX		 88
#define RDX		 96
#define RSI		104
#define RDI		112
#define ORIG_RAX	120       /* + error_code */
/* end of arguments */

/* cpu exception frame or undefined in case of fast syscall: */
#define RIP		128
#define CS		136
#define EFLAGS		144
#define RSP		152
#define SS		160

#define ARGOFFSET	R11
#define SWFRAME		ORIG_RAX

	.macro SAVE_ARGS addskip=0, save_rcx=1, save_r891011=1
	subq  $9*8+\addskip, %rsp
	CFI_ADJUST_CFA_OFFSET	9*8+\addskip
	movq_cfi rdi, 8*8
	movq_cfi rsi, 7*8
	movq_cfi rdx, 6*8

	.if \save_rcx
	movq_cfi rcx, 5*8
	.endif

	movq_cfi rax, 4*8

	.if \save_r891011
	movq_cfi r8,  3*8
	movq_cfi r9,  2*8
	movq_cfi r10, 1*8
	movq_cfi r11, 0*8
	.endif

	.endm

#define ARG_SKIP	(9*8)

	.macro RESTORE_ARGS rstor_rax=1, addskip=0, rstor_rcx=1, rstor_r11=1, \
			    rstor_r8910=1, rstor_rdx=1
	.if \rstor_r11
	movq_cfi_restore 0*8, r11
	.endif

	.if \rstor_r8910
	movq_cfi_restore 1*8, r10
	movq_cfi_restore 2*8, r9
	movq_cfi_restore 3*8, r8
	.endif

	.if \rstor_rax
	movq_cfi_restore 4*8, rax
	.endif

	.if \rstor_rcx
	movq_cfi_restore 5*8, rcx
	.endif

	.if \rstor_rdx
	movq_cfi_restore 6*8, rdx
	.endif

	movq_cfi_restore 7*8, rsi
	movq_cfi_restore 8*8, rdi

	.if ARG_SKIP+\addskip > 0
	addq $ARG_SKIP+\addskip, %rsp
	CFI_ADJUST_CFA_OFFSET	-(ARG_SKIP+\addskip)
	.endif
	.endm

	.macro LOAD_ARGS offset, skiprax=0
	movq \offset(%rsp),    %r11
	movq \offset+8(%rsp),  %r10
	movq \offset+16(%rsp), %r9
	movq \offset+24(%rsp), %r8
	movq \offset+40(%rsp), %rcx
	movq \offset+48(%rsp), %rdx
	movq \offset+56(%rsp), %rsi
	movq \offset+64(%rsp), %rdi
	.if \skiprax
	.else
	movq \offset+72(%rsp), %rax
	.endif
	.endm

#define REST_SKIP	(6*8)

	.macro SAVE_REST
	subq $REST_SKIP, %rsp
	CFI_ADJUST_CFA_OFFSET	REST_SKIP
	movq_cfi rbx, 5*8
	movq_cfi rbp, 4*8
	movq_cfi r12, 3*8
	movq_cfi r13, 2*8
	movq_cfi r14, 1*8
	movq_cfi r15, 0*8
	.endm

	.macro RESTORE_REST
	movq_cfi_restore 0*8, r15
	movq_cfi_restore 1*8, r14
	movq_cfi_restore 2*8, r13
	movq_cfi_restore 3*8, r12
	movq_cfi_restore 4*8, rbp
	movq_cfi_restore 5*8, rbx
	addq $REST_SKIP, %rsp
	CFI_ADJUST_CFA_OFFSET	-(REST_SKIP)
	.endm

	.macro SAVE_ALL
	SAVE_ARGS
	SAVE_REST
	.endm

	.macro RESTORE_ALL addskip=0
	RESTORE_REST
	RESTORE_ARGS 1, \addskip
	.endm

	.macro icebp
	.byte 0xf1
	.endm

	/*
	 * Must be called IMMEDIATELY after a branch to prevent speculation
	 * past the bounds of the syscall table.  Uses the carry flag from the
	 * most recent CMP instruction to set the scratch reg to -1 if the
	 * syscall was in bounds and 0 if it was out of bounds.  So RAX --
	 * which holds the syscall number -- is cleared to zero in the
	 * speculative out-of-bounds case.
	 */
	.macro ARRAY_INDEX_NOSPEC_SYSCALL clobber_reg
		sbb \clobber_reg, \clobber_reg
		and \clobber_reg, %rax
		/* prevent a data "leak" */
		xorq \clobber_reg, \clobber_reg
	.endm

.macro UNWIND_END_OF_STACK
	417:
	.pushsection __unwind_end_of_stack, "a"
		.quad 417b
	.popsection
.endm

.macro UNWIND_UNSAFE_STACK
	417:
	.pushsection __unwind_unsafe_stack, "a"
		.quad 417b
	.popsection
.endm

/*
 * Mitigate Spectre v1 for conditional swapgs code paths.
 *
 * FENCE_SWAPGS_USER_ENTRY is used in the user entry swapgs code path, to
 * prevent a speculative swapgs when coming from kernel space.
 *
 * FENCE_SWAPGS_KERNEL_ENTRY is used in the kernel entry non-swapgs code path,
 * to prevent the swapgs from getting speculatively skipped when coming from
 * user space.
 *
 * RHEL7 uses gs-indexed per-cpu variables for dynamic PTI enabling/disabling.
 * So that on/off state of PTI doesn't matter in determining if fencing should
 * be used or not. We have to properly fence swapgs before the invocation
 * of the PTI macros.
 *
 * RHEL7 also doesn't have the ALTERNATIVE asm macro. So we have to open-code
 * it. The lfence instruction is 3 bytes long.
 */
 .macro _FENCE_SWAPGS feature
	661: ASM_NOP3; 662:
	.pushsection .altinstr_replacement, "ax"
	663: lfence; 664:
	.popsection
	.pushsection .altinstructions, "a"
	altinstruction_entry 661b, 663b, \feature, 662b-661b, 664b-663b
	.popsection
.endm

.macro FENCE_SWAPGS_USER_ENTRY
	_FENCE_SWAPGS X86_FEATURE_FENCE_SWAPGS_USER
.endm

.macro FENCE_SWAPGS_KERNEL_ENTRY
	_FENCE_SWAPGS X86_FEATURE_FENCE_SWAPGS_KERNEL
.endm
