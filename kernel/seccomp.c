/*
 * linux/kernel/seccomp.c
 *
 * Copyright 2004-2005  Andrea Arcangeli <andrea@cpushare.com>
 *
 * Copyright (C) 2012 Google, Inc.
 * Will Drewry <wad@chromium.org>
 *
 * This defines a simple but solid secure-computing facility.
 *
 * Mode 1 uses a fixed list of allowed system calls.
 * Mode 2 allows user-defined system call filters in the form
 *        of Berkeley Packet Filters/Linux Socket Filters.
 */

#include <linux/refcount.h>
#include <linux/audit.h>
#include <linux/compat.h>
#include <linux/nospec.h>
#include <linux/prctl.h>
#include <linux/coredump.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/slab.h>
#include <linux/kmemleak.h>
#include <linux/syscalls.h>
#include <linux/sysctl.h>

#ifdef CONFIG_HAVE_ARCH_SECCOMP_FILTER
#include <asm/syscall.h>
#endif

#ifdef CONFIG_SECCOMP_FILTER
#include <linux/filter.h>
#include <linux/pid.h>
#include <linux/ptrace.h>
#include <linux/security.h>
#include <linux/tracehook.h>
#include <linux/uaccess.h>

/**
 * struct seccomp_filter - container for seccomp BPF programs
 *
 * @usage: reference count to manage the object lifetime.
 *         get/put helpers should be used when accessing an instance
 *         outside of a lifetime-guarded section.  In general, this
 *         is only needed for handling filters shared across tasks.
 * @prev: points to a previously installed, or inherited, filter
 * @len: the number of instructions in the program
 * @insns: the BPF program instructions to evaluate
 *
 * seccomp_filter objects are organized in a tree linked via the @prev
 * pointer.  For any task, it appears to be a singly-linked list starting
 * with current->seccomp.filter, the most recently attached or inherited filter.
 * However, multiple filters may share a @prev node, by way of fork(), which
 * results in a unidirectional tree existing in memory.  This is similar to
 * how namespaces work.
 *
 * seccomp_filter objects should never be modified after being attached
 * to a task_struct (other than @usage).
 */
struct seccomp_filter {
	refcount_t usage;
	struct seccomp_filter *prev;
#if CONFIG_VE
	struct sock_fprog orig_prog;
#endif
	unsigned short len;  /* Instruction count */
	struct sock_filter insns[];
};

/* Limit any path through the tree to 256KB worth of instructions. */
#define MAX_INSNS_PER_PATH ((1 << 18) / sizeof(struct sock_filter))

/**
 * get_u32 - returns a u32 offset into data
 * @data: a unsigned 64 bit value
 * @index: 0 or 1 to return the first or second 32-bits
 *
 * This inline exists to hide the length of unsigned long.  If a 32-bit
 * unsigned long is passed in, it will be extended and the top 32-bits will be
 * 0. If it is a 64-bit unsigned long, then whatever data is resident will be
 * properly returned.
 *
 * Endianness is explicitly ignored and left for BPF program authors to manage
 * as per the specific architecture.
 */
static inline u32 get_u32(u64 data, int index)
{
	return ((u32 *)&data)[index];
}

/* Helper for bpf_load below. */
#define BPF_DATA(_name) offsetof(struct seccomp_data, _name)
/**
 * bpf_load: checks and returns a pointer to the requested offset
 * @off: offset into struct seccomp_data to load from
 *
 * Returns the requested 32-bits of data.
 * seccomp_check_filter() should assure that @off is 32-bit aligned
 * and not out of bounds.  Failure to do so is a BUG.
 */
u32 seccomp_bpf_load(int off)
{
	struct pt_regs *regs = task_pt_regs(current);
	if (off == BPF_DATA(nr))
		return syscall_get_nr(current, regs);
	if (off == BPF_DATA(arch))
		return syscall_get_arch();
	if (off >= BPF_DATA(args[0]) && off < BPF_DATA(args[6])) {
		unsigned long value;
		int arg = (off - BPF_DATA(args[0])) / sizeof(u64);
		int index = !!(off % sizeof(u64));
		syscall_get_arguments(current, regs, arg, 1, &value);
		return get_u32(value, index);
	}
	if (off == BPF_DATA(instruction_pointer))
		return get_u32(KSTK_EIP(current), 0);
	if (off == BPF_DATA(instruction_pointer) + sizeof(u32))
		return get_u32(KSTK_EIP(current), 1);
	/* seccomp_check_filter should make this impossible. */
	BUG();
}

/**
 *	seccomp_check_filter - verify seccomp filter code
 *	@filter: filter to verify
 *	@flen: length of filter
 *
 * Takes a previously checked filter (by sk_chk_filter) and
 * redirects all filter code that loads struct sk_buff data
 * and related data through seccomp_bpf_load.  It also
 * enforces length and alignment checking of those loads.
 *
 * Returns 0 if the rule set is legal or -EINVAL if not.
 */
static int seccomp_check_filter(struct sock_filter *filter, unsigned int flen)
{
	int pc;
	for (pc = 0; pc < flen; pc++) {
		struct sock_filter *ftest = &filter[pc];
		u16 code = ftest->code;
		u32 k = ftest->k;

		switch (code) {
		case BPF_S_LD_W_ABS:
			ftest->code = BPF_S_ANC_SECCOMP_LD_W;
			/* 32-bit aligned and not out of bounds. */
			if (k >= sizeof(struct seccomp_data) || k & 3)
				return -EINVAL;
			continue;
		case BPF_S_LD_W_LEN:
			ftest->code = BPF_S_LD_IMM;
			ftest->k = sizeof(struct seccomp_data);
			continue;
		case BPF_S_LDX_W_LEN:
			ftest->code = BPF_S_LDX_IMM;
			ftest->k = sizeof(struct seccomp_data);
			continue;
		/* Explicitly include allowed calls. */
		case BPF_S_RET_K:
		case BPF_S_RET_A:
		case BPF_S_ALU_ADD_K:
		case BPF_S_ALU_ADD_X:
		case BPF_S_ALU_SUB_K:
		case BPF_S_ALU_SUB_X:
		case BPF_S_ALU_MUL_K:
		case BPF_S_ALU_MUL_X:
		case BPF_S_ALU_DIV_X:
		case BPF_S_ALU_AND_K:
		case BPF_S_ALU_AND_X:
		case BPF_S_ALU_OR_K:
		case BPF_S_ALU_OR_X:
		case BPF_S_ALU_XOR_K:
		case BPF_S_ALU_XOR_X:
		case BPF_S_ALU_LSH_K:
		case BPF_S_ALU_LSH_X:
		case BPF_S_ALU_RSH_K:
		case BPF_S_ALU_RSH_X:
		case BPF_S_ALU_NEG:
		case BPF_S_LD_IMM:
		case BPF_S_LDX_IMM:
		case BPF_S_MISC_TAX:
		case BPF_S_MISC_TXA:
		case BPF_S_ALU_DIV_K:
		case BPF_S_LD_MEM:
		case BPF_S_LDX_MEM:
		case BPF_S_ST:
		case BPF_S_STX:
		case BPF_S_JMP_JA:
		case BPF_S_JMP_JEQ_K:
		case BPF_S_JMP_JEQ_X:
		case BPF_S_JMP_JGE_K:
		case BPF_S_JMP_JGE_X:
		case BPF_S_JMP_JGT_K:
		case BPF_S_JMP_JGT_X:
		case BPF_S_JMP_JSET_K:
		case BPF_S_JMP_JSET_X:
			continue;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

/**
 * seccomp_run_filters - evaluates all seccomp filters against @syscall
 * @syscall: number of the current system call
 *
 * Returns valid seccomp BPF response codes.
 */
static u32 seccomp_run_filters(void)
{
	struct seccomp_filter *f = ACCESS_ONCE(current->seccomp.filter);
	u32 ret = SECCOMP_RET_ALLOW;

	/* Ensure unexpected behavior doesn't result in failing open. */
	if (unlikely(WARN_ON(f == NULL)))
		return SECCOMP_RET_KILL;

	smp_read_barrier_depends();

	/*
	 * All filters in the list are evaluated and the lowest BPF return
	 * value always takes priority (ignoring the DATA).
	 */
	for (; f; f = f->prev) {
		u32 cur_ret = sk_run_filter(NULL, f->insns);

		if ((cur_ret & SECCOMP_RET_ACTION) < (ret & SECCOMP_RET_ACTION))
			ret = cur_ret;
	}
	return ret;
}
#endif /* CONFIG_SECCOMP_FILTER */

static inline bool seccomp_may_assign_mode(unsigned long seccomp_mode)
{
	assert_spin_locked(&current->sighand->siglock);

	if (current->seccomp.mode && current->seccomp.mode != seccomp_mode)
		return false;

	return true;
}

void __weak arch_seccomp_spec_mitigate(struct task_struct *task) { }

static inline void seccomp_assign_mode(struct task_struct *task,
				       unsigned long seccomp_mode,
				       unsigned long flags)
{
	assert_spin_locked(&task->sighand->siglock);

	task->seccomp.mode = seccomp_mode;
	/*
	 * Make sure TIF_SECCOMP cannot be set before the mode (and
	 * filter) is set.
	 */
	smp_mb__before_atomic();
	/* Assume default seccomp processes want spec flaw mitigation. */
	if ((flags & SECCOMP_FILTER_FLAG_SPEC_ALLOW) == 0)
		arch_seccomp_spec_mitigate(task);
	set_tsk_thread_flag(task, TIF_SECCOMP);
}

#ifdef CONFIG_SECCOMP_FILTER
/* Returns 1 if the parent is an ancestor of the child. */
static int is_ancestor(struct seccomp_filter *parent,
		       struct seccomp_filter *child)
{
	/* NULL is the root ancestor. */
	if (parent == NULL)
		return 1;
	for (; child; child = child->prev)
		if (child == parent)
			return 1;
	return 0;
}

/**
 * seccomp_can_sync_threads: checks if all threads can be synchronized
 *
 * Expects sighand and cred_guard_mutex locks to be held.
 *
 * Returns 0 on success, -ve on error, or the pid of a thread which was
 * either not in the correct seccomp mode or it did not have an ancestral
 * seccomp filter.
 */
static inline pid_t seccomp_can_sync_threads(void)
{
	struct task_struct *thread, *caller;

	BUG_ON(!mutex_is_locked(&current->signal->cred_guard_mutex));
	assert_spin_locked(&current->sighand->siglock);

	/* Validate all threads being eligible for synchronization. */
	caller = current;
	for_each_thread(caller, thread) {
		pid_t failed;

		/* Skip current, since it is initiating the sync. */
		if (thread == caller)
			continue;

		if (thread->seccomp.mode == SECCOMP_MODE_DISABLED ||
		    (thread->seccomp.mode == SECCOMP_MODE_FILTER &&
		     is_ancestor(thread->seccomp.filter,
				 caller->seccomp.filter)))
			continue;

		/* Return the first thread that cannot be synchronized. */
		failed = task_pid_vnr(thread);
		/* If the pid cannot be resolved, then return -ESRCH */
		if (unlikely(WARN_ON(failed == 0)))
			failed = -ESRCH;
		return failed;
	}

	return 0;
}

/**
 * seccomp_sync_threads: sets all threads to use current's filter
 *
 * Expects sighand and cred_guard_mutex locks to be held, and for
 * seccomp_can_sync_threads() to have returned success already
 * without dropping the locks.
 *
 */
static inline void seccomp_sync_threads(unsigned long flags)
{
	struct task_struct *thread, *caller;

	BUG_ON(!mutex_is_locked(&current->signal->cred_guard_mutex));
	assert_spin_locked(&current->sighand->siglock);

	/* Synchronize all threads. */
	caller = current;
	for_each_thread(caller, thread) {
		/* Skip current, since it needs no changes. */
		if (thread == caller)
			continue;

		/* Get a task reference for the new leaf node. */
		get_seccomp_filter(caller);
		/*
		 * Drop the task reference to the shared ancestor since
		 * current's path will hold a reference.  (This also
		 * allows a put before the assignment.)
		 */
		put_seccomp_filter(thread);
		smp_store_release(&thread->seccomp.filter,
				  caller->seccomp.filter);
		/*
		 * Opt the other thread into seccomp if needed.
		 * As threads are considered to be trust-realm
		 * equivalent (see ptrace_may_access), it is safe to
		 * allow one thread to transition the other.
		 */
		if (thread->seccomp.mode == SECCOMP_MODE_DISABLED) {
			/*
			 * Don't let an unprivileged task work around
			 * the no_new_privs restriction by creating
			 * a thread that sets it up, enters seccomp,
			 * then dies.
			 */
			if (task_no_new_privs(caller))
				task_set_no_new_privs(thread);

			seccomp_assign_mode(thread, SECCOMP_MODE_FILTER,
					    flags);
		}
	}
}

/**
 * seccomp_prepare_filter: Prepares a seccomp filter for use.
 * @fprog: BPF program to install
 *
 * Returns filter on success or an ERR_PTR on failure.
 */
static struct seccomp_filter *seccomp_prepare_filter(struct sock_fprog *fprog)
{
	struct seccomp_filter *filter;
	unsigned long fp_size;
	long ret;

	if (fprog->len == 0 || fprog->len > BPF_MAXINSNS)
		return ERR_PTR(-EINVAL);
	BUG_ON(INT_MAX / fprog->len < sizeof(struct sock_filter));
	fp_size = fprog->len * sizeof(struct sock_filter);

	/*
	 * Installing a seccomp filter requires that the task have
	 * CAP_SYS_ADMIN in its namespace or be running with no_new_privs.
	 * This avoids scenarios where unprivileged tasks can affect the
	 * behavior of privileged children.
	 */
	if (!task_no_new_privs(current) &&
	    security_capable_noaudit(current_cred(), current_user_ns(),
				     CAP_SYS_ADMIN) != 0)
		return ERR_PTR(-EACCES);

	/* Allocate a new seccomp_filter */
	filter = kzalloc(sizeof(struct seccomp_filter) + fp_size,
			 GFP_KERNEL|__GFP_NOWARN);
	if (!filter)
		return ERR_PTR(-ENOMEM);
	refcount_set(&filter->usage, 1);
	filter->len = fprog->len;

	/* Copy the instructions from fprog. */
	ret = -EFAULT;
	if (copy_from_user(filter->insns, fprog->filter, fp_size))
		goto fail;

#if CONFIG_VE
	filter->orig_prog.len = fprog->len;
	filter->orig_prog.filter = kmemdup(filter->insns, fp_size,
					   GFP_KERNEL|__GFP_NOWARN);
	if (!filter->orig_prog.filter) {
		ret = -ENOMEM;
		goto fail;
	}
#endif

	/* Check and rewrite the fprog via the skb checker */
	ret = sk_chk_filter(filter->insns, filter->len);
	if (ret)
		goto fail;

	/* Check and rewrite the fprog for seccomp use */
	ret = seccomp_check_filter(filter->insns, filter->len);
	if (ret)
		goto fail;

	return filter;
fail:
#if CONFIG_VE
	kfree(filter->orig_prog.filter);
#endif
	kfree(filter);
	return ERR_PTR(ret);
}

/**
 * seccomp_prepare_user_filter - prepares a user-supplied sock_fprog
 * @user_filter: pointer to the user data containing a sock_fprog.
 *
 * Returns 0 on success and non-zero otherwise.
 */
static struct seccomp_filter *
seccomp_prepare_user_filter(const char __user *user_filter)
{
	struct sock_fprog fprog;
	struct seccomp_filter *filter = ERR_PTR(-EFAULT);

#ifdef CONFIG_COMPAT
	if (is_compat_task()) {
		struct compat_sock_fprog fprog32;
		if (copy_from_user(&fprog32, user_filter, sizeof(fprog32)))
			goto out;
		fprog.len = fprog32.len;
		fprog.filter = compat_ptr(fprog32.filter);
	} else /* falls through to the if below. */
#endif
	if (copy_from_user(&fprog, user_filter, sizeof(fprog)))
		goto out;
	filter = seccomp_prepare_filter(&fprog);
out:
	return filter;
}

/**
 * seccomp_attach_filter: validate and attach filter
 * @flags:  flags to change filter behavior
 * @filter: seccomp filter to add to the current process
 *
 * Caller must be holding current->sighand->siglock lock.
 *
 * Returns 0 on success, -ve on error.
 */
static long seccomp_attach_filter(unsigned int flags,
				  struct seccomp_filter *filter)
{
	unsigned long total_insns;
	struct seccomp_filter *walker;

	assert_spin_locked(&current->sighand->siglock);

	/* Validate resulting filter length. */
	total_insns = filter->len;
	for (walker = current->seccomp.filter; walker; walker = walker->prev)
		total_insns += walker->len + 4;  /* 4 instr penalty */
	if (total_insns > MAX_INSNS_PER_PATH)
		return -ENOMEM;

	/* If thread sync has been requested, check that it is possible. */
	if (flags & SECCOMP_FILTER_FLAG_TSYNC) {
		int ret;

		ret = seccomp_can_sync_threads();
		if (ret)
			return ret;
	}

	/*
	 * If there is an existing filter, make it the prev and don't drop its
	 * task reference.
	 */
	filter->prev = current->seccomp.filter;
	current->seccomp.filter = filter;

	/* Now that the new filter is in place, synchronize to all threads. */
	if (flags & SECCOMP_FILTER_FLAG_TSYNC)
		seccomp_sync_threads(flags);

	return 0;
}

/* get_seccomp_filter - increments the reference count of the filter on @tsk */
void get_seccomp_filter(struct task_struct *tsk)
{
	struct seccomp_filter *orig = tsk->seccomp.filter;
	if (!orig)
		return;
	/* Reference count is bounded by the number of total processes. */
	refcount_inc(&orig->usage);
}

static inline void seccomp_filter_free(struct seccomp_filter *filter)
{
	if (filter) {
		kfree(filter);
	}
}

/* put_seccomp_filter - decrements the ref count of tsk->seccomp.filter */
void put_seccomp_filter(struct task_struct *tsk)
{
	struct seccomp_filter *orig = tsk->seccomp.filter;
	/* Clean up single-reference branches iteratively. */
	while (orig && refcount_dec_and_test(&orig->usage)) {
		struct seccomp_filter *freeme = orig;
		orig = orig->prev;
#if CONFIG_VE
		kfree(freeme->orig_prog.filter);
#endif
		seccomp_filter_free(freeme);
	}
}

static void seccomp_init_siginfo(siginfo_t *info, int syscall, int reason)
{
	memset(info, 0, sizeof(*info));
	info->si_signo = SIGSYS;
	info->si_code = SYS_SECCOMP;
	info->si_call_addr = (void __user *)KSTK_EIP(current);
	info->si_errno = reason;
	info->si_arch = syscall_get_arch();
	info->si_syscall = syscall;
}

/**
 * seccomp_send_sigsys - signals the task to allow in-process syscall emulation
 * @syscall: syscall number to send to userland
 * @reason: filter-supplied reason code to send to userland (via si_errno)
 *
 * Forces a SIGSYS with a code of SYS_SECCOMP and related sigsys info.
 */
static void seccomp_send_sigsys(int syscall, int reason)
{
	struct siginfo info;
	seccomp_init_siginfo(&info, syscall, reason);
	force_sig_info(SIGSYS, &info, current);
}
#endif	/* CONFIG_SECCOMP_FILTER */

/* For use with seccomp_actions_logged */
#define SECCOMP_LOG_KILL		(1 << 0)
#define SECCOMP_LOG_TRAP		(1 << 2)
#define SECCOMP_LOG_ERRNO		(1 << 3)
#define SECCOMP_LOG_TRACE		(1 << 4)
#define SECCOMP_LOG_ALLOW		(1 << 5)

static u32 seccomp_actions_logged = SECCOMP_LOG_KILL  | SECCOMP_LOG_TRAP  |
				    SECCOMP_LOG_ERRNO | SECCOMP_LOG_TRACE;

static inline void seccomp_log(unsigned long syscall, long signr, u32 action)
{
	bool log = false;

	switch (action) {
	case SECCOMP_RET_ALLOW:
	case SECCOMP_RET_TRAP:
	case SECCOMP_RET_ERRNO:
	case SECCOMP_RET_TRACE:
		break;
	case SECCOMP_RET_KILL:
	default:
		log = seccomp_actions_logged & SECCOMP_LOG_KILL;
	}

	/*
	 * Force an audit message to be emitted when the action is RET_KILL and
	 * the action is allowed to be logged by the admin.
	 */
	if (log)
		return __audit_seccomp(syscall, signr, action);

	/*
	 * Let the audit subsystem decide if the action should be audited based
	 * on whether the current task itself is being audited.
	 */
	return audit_seccomp(syscall, signr, action);
}

/*
 * Secure computing mode 1 allows only read/write/exit/sigreturn.
 * To be fully secure this must be combined with rlimit
 * to limit the stack allocations too.
 */
static int mode1_syscalls[] = {
	__NR_seccomp_read, __NR_seccomp_write, __NR_seccomp_exit, __NR_seccomp_sigreturn,
	0, /* null terminated */
};

#ifdef CONFIG_COMPAT
static int mode1_syscalls_32[] = {
	__NR_seccomp_read_32, __NR_seccomp_write_32, __NR_seccomp_exit_32, __NR_seccomp_sigreturn_32,
	0, /* null terminated */
};
#endif

static void __secure_computing_strict(int this_syscall)
{
	int *syscall_whitelist = mode1_syscalls;
#ifdef CONFIG_COMPAT
	if (is_compat_task())
		syscall_whitelist = mode1_syscalls_32;
#endif
	do {
		if (*syscall_whitelist == this_syscall)
			return;
	} while (*++syscall_whitelist);

#ifdef SECCOMP_DEBUG
	dump_stack();
#endif
	seccomp_log(this_syscall, SIGKILL, SECCOMP_RET_KILL);
	do_exit(SIGKILL);
}

#ifndef CONFIG_HAVE_ARCH_SECCOMP_FILTER
void secure_computing_strict(int this_syscall)
{
	int mode = current->seccomp.mode;

	if (config_enabled(CONFIG_CHECKPOINT_RESTORE) &&
	    unlikely(current->ptrace & PT_SUSPEND_SECCOMP))
		return 0;

	if (mode == 0)
		return;
	else if (mode == SECCOMP_MODE_STRICT)
		__secure_computing_strict(this_syscall);
	else
		BUG();
}
#else
#ifdef CONFIG_SECCOMP_FILTER
static u32 __seccomp_filter(int this_syscall, struct pt_regs *regs)
{
	u32 filter_ret, action;
	int data;

	/*
	 * Make sure that any changes to mode from another thread have
	 * been seen after TIF_SECCOMP was seen.
	 */
	rmb();

	filter_ret = seccomp_run_filters();
	data = filter_ret & SECCOMP_RET_DATA;
	action = filter_ret & SECCOMP_RET_ACTION;

	switch (action) {
	case SECCOMP_RET_ERRNO:
		/* Set the low-order 16-bits as a errno. */
		syscall_set_return_value(current, regs,
					 -data, 0);
		goto skip;

	case SECCOMP_RET_TRAP:
		/* Show the handler the original registers. */
		syscall_rollback(current, regs);
		/* Let the filter pass back 16 bits of data. */
		seccomp_send_sigsys(this_syscall, data);
		goto skip;

	case SECCOMP_RET_TRACE:
		/* ENOSYS these calls if there is no tracer attached. */
		if (!ptrace_event_enabled(current, PTRACE_EVENT_SECCOMP)) {
			syscall_set_return_value(current,
						 task_pt_regs(current),
						 -ENOSYS, 0);
			goto skip;
		}

		/* Allow the BPF to provide the event message */
		ptrace_event(PTRACE_EVENT_SECCOMP, data);
		/*
		 * The delivery of a fatal signal during event
		 * notification may silently skip tracer notification,
		 * which could leave us with a potentially unmodified
		 * syscall that the tracer would have liked to have
		 * changed. Since the process is about to die, we just
		 * force the syscall to be skipped and let the signal
		 * kill the process and correctly handle any tracer exit
		 * notifications.
		 */
		if (fatal_signal_pending(current))
			goto skip;
		/* Check if the tracer forced the syscall to be skipped. */
		this_syscall = syscall_get_nr(current, task_pt_regs(current));
		if (this_syscall < 0)
			goto skip;

		return 0;

	case SECCOMP_RET_ALLOW:
		return 0;

	case SECCOMP_RET_KILL:
	default:
		seccomp_log(this_syscall, SIGSYS, action);
		/* Dump core only if this is the last remaining thread. */
		if (get_nr_threads(current) == 1) {
			siginfo_t info;

			/* Show the original registers in the dump. */
			syscall_rollback(current, task_pt_regs(current));
			/* Trigger a manual coredump since do_exit skips it. */
			seccomp_init_siginfo(&info, this_syscall, data);
			do_coredump(&info);
		}
		do_exit(SIGSYS);
	}

	unreachable();

skip:
	seccomp_log(this_syscall, 0, action);
	return -1;
}
#else
static int __seccomp_filter(int this_syscall, struct pt_regs *regs)
{
	BUG();
}
#endif

int __secure_computing(void)
{
	int mode = current->seccomp.mode;
	struct pt_regs *regs = task_pt_regs(current);
	int this_syscall = syscall_get_nr(current, regs);

	switch (mode) {
	case SECCOMP_MODE_STRICT:
		__secure_computing_strict(this_syscall);  /* may call do_exit */
		return 0;
	case SECCOMP_MODE_FILTER:
		return __seccomp_filter(this_syscall, regs);
	default:
		BUG();
	}
}
#endif /* CONFIG_HAVE_ARCH_SECCOMP_FILTER */

long prctl_get_seccomp(void)
{
	return current->seccomp.mode;
}

/**
 * seccomp_set_mode_strict: internal function for setting strict seccomp
 *
 * Once current->seccomp.mode is non-zero, it may not be changed.
 *
 * Returns 0 on success or -EINVAL on failure.
 */
static long seccomp_set_mode_strict(void)
{
	const unsigned long seccomp_mode = SECCOMP_MODE_STRICT;
	long ret = -EINVAL;

	spin_lock_irq(&current->sighand->siglock);

	if (!seccomp_may_assign_mode(seccomp_mode))
		goto out;

#ifdef TIF_NOTSC
	disable_TSC();
#endif
	seccomp_assign_mode(current, seccomp_mode, 0);
	ret = 0;

out:
	spin_unlock_irq(&current->sighand->siglock);

	return ret;
}

#ifdef CONFIG_SECCOMP_FILTER
/**
 * seccomp_set_mode_filter: internal function for setting seccomp filter
 * @flags:  flags to change filter behavior
 * @filter: struct sock_fprog containing filter
 *
 * This function may be called repeatedly to install additional filters.
 * Every filter successfully installed will be evaluated (in reverse order)
 * for each system call the task makes.
 *
 * Once current->seccomp.mode is non-zero, it may not be changed.
 *
 * Returns 0 on success or -EINVAL on failure.
 */
static long seccomp_set_mode_filter(unsigned int flags,
				    const char __user *filter)
{
	const unsigned long seccomp_mode = SECCOMP_MODE_FILTER;
	struct seccomp_filter *prepared = NULL;
	long ret = -EINVAL;

	/* Validate flags. */
	if (flags & ~SECCOMP_FILTER_FLAG_MASK)
		return -EINVAL;

	/* Prepare the new filter before holding any locks. */
	prepared = seccomp_prepare_user_filter(filter);
	if (IS_ERR(prepared))
		return PTR_ERR(prepared);

	/*
	 * Make sure we cannot change seccomp or nnp state via TSYNC
	 * while another thread is in the middle of calling exec.
	 */
	if (flags & SECCOMP_FILTER_FLAG_TSYNC &&
	    mutex_lock_killable(&current->signal->cred_guard_mutex))
		goto out_free;

	spin_lock_irq(&current->sighand->siglock);

	if (!seccomp_may_assign_mode(seccomp_mode))
		goto out;

	ret = seccomp_attach_filter(flags, prepared);
	if (ret)
		goto out;
	/* Do not free the successfully attached filter. */
	prepared = NULL;

	seccomp_assign_mode(current, seccomp_mode, flags);
out:
	spin_unlock_irq(&current->sighand->siglock);
	if (flags & SECCOMP_FILTER_FLAG_TSYNC)
		mutex_unlock(&current->signal->cred_guard_mutex);
out_free:
	seccomp_filter_free(prepared);
	return ret;
}
#else
static inline long seccomp_set_mode_filter(unsigned int flags,
					   const char __user *filter)
{
	return -EINVAL;
}
#endif

static long seccomp_get_action_avail(const char __user *uaction)
{
	u32 action;

	if (copy_from_user(&action, uaction, sizeof(action)))
		return -EFAULT;

	switch (action) {
	case SECCOMP_RET_KILL:
	case SECCOMP_RET_TRAP:
	case SECCOMP_RET_ERRNO:
	case SECCOMP_RET_TRACE:
	case SECCOMP_RET_ALLOW:
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

/* Common entry point for both prctl and syscall. */
static long do_seccomp(unsigned int op, unsigned int flags,
		       const char __user *uargs)
{
	switch (op) {
	case SECCOMP_SET_MODE_STRICT:
		if (flags != 0 || uargs != NULL)
			return -EINVAL;
		return seccomp_set_mode_strict();
	case SECCOMP_SET_MODE_FILTER:
		return seccomp_set_mode_filter(flags, uargs);
	case SECCOMP_GET_ACTION_AVAIL:
		if (flags != 0)
			return -EINVAL;

		return seccomp_get_action_avail(uargs);
	default:
		return -EINVAL;
	}
}

SYSCALL_DEFINE3(seccomp, unsigned int, op, unsigned int, flags,
			 const char __user *, uargs)
{
	return do_seccomp(op, flags, uargs);
}

/**
 * prctl_set_seccomp: configures current->seccomp.mode
 * @seccomp_mode: requested mode to use
 * @filter: optional struct sock_fprog for use with SECCOMP_MODE_FILTER
 *
 * Returns 0 on success or -EINVAL on failure.
 */
long prctl_set_seccomp(unsigned long seccomp_mode, char __user *filter)
{
	unsigned int op;
	char __user *uargs;

	switch (seccomp_mode) {
	case SECCOMP_MODE_STRICT:
		op = SECCOMP_SET_MODE_STRICT;
		/*
		 * Setting strict mode through prctl always ignored filter,
		 * so make sure it is always NULL here to pass the internal
		 * check in do_seccomp().
		 */
		uargs = NULL;
		break;
	case SECCOMP_MODE_FILTER:
		op = SECCOMP_SET_MODE_FILTER;
		uargs = filter;
		break;
	default:
		return -EINVAL;
	}

	/* prctl interface doesn't have flags, so they are always zero. */
	return do_seccomp(op, 0, uargs);
}

#ifdef CONFIG_SYSCTL

/* Human readable action names for friendly sysctl interaction */
#define SECCOMP_RET_KILL_NAME		"kill"
#define SECCOMP_RET_TRAP_NAME		"trap"
#define SECCOMP_RET_ERRNO_NAME		"errno"
#define SECCOMP_RET_TRACE_NAME		"trace"
#define SECCOMP_RET_ALLOW_NAME		"allow"

static const char seccomp_actions_avail[] = SECCOMP_RET_KILL_NAME	" "
					    SECCOMP_RET_TRAP_NAME	" "
					    SECCOMP_RET_ERRNO_NAME	" "
					    SECCOMP_RET_TRACE_NAME	" "
					    SECCOMP_RET_ALLOW_NAME;

struct seccomp_log_name {
	u32		log;
	const char	*name;
};

static const struct seccomp_log_name seccomp_log_names[] = {
	{ SECCOMP_LOG_KILL, SECCOMP_RET_KILL_NAME },
	{ SECCOMP_LOG_TRAP, SECCOMP_RET_TRAP_NAME },
	{ SECCOMP_LOG_ERRNO, SECCOMP_RET_ERRNO_NAME },
	{ SECCOMP_LOG_TRACE, SECCOMP_RET_TRACE_NAME },
	{ SECCOMP_LOG_ALLOW, SECCOMP_RET_ALLOW_NAME },
	{ }
};

static bool seccomp_names_from_actions_logged(char *names, size_t size,
					      u32 actions_logged)
{
	const struct seccomp_log_name *cur;
	bool append_space = false;

	for (cur = seccomp_log_names; cur->name && size; cur++) {
		ssize_t ret;

		if (!(actions_logged & cur->log))
			continue;

		if (append_space) {
			ret = strlcpy(names, " ", size);
			if (ret < 0)
				return false;

			names += ret;
			size -= ret;
		} else
			append_space = true;

		ret = strlcpy(names, cur->name, size);
		if (ret < 0)
			return false;

		names += ret;
		size -= ret;
	}

	return true;
}

static bool seccomp_action_logged_from_name(u32 *action_logged,
					    const char *name)
{
	const struct seccomp_log_name *cur;

	for (cur = seccomp_log_names; cur->name; cur++) {
		if (!strcmp(cur->name, name)) {
			*action_logged = cur->log;
			return true;
		}
	}

	return false;
}

static bool seccomp_actions_logged_from_names(u32 *actions_logged, char *names)
{
	char *name;

	*actions_logged = 0;
	while ((name = strsep(&names, " ")) && *name) {
		u32 action_logged = 0;

		if (!seccomp_action_logged_from_name(&action_logged, name))
			return false;

		*actions_logged |= action_logged;
	}

	return true;
}

static int seccomp_actions_logged_handler(struct ctl_table *ro_table, int write,
					  void __user *buffer, size_t *lenp,
					  loff_t *ppos)
{
	char names[sizeof(seccomp_actions_avail)];
	struct ctl_table table;
	int ret;

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	memset(names, 0, sizeof(names));

	if (!write) {
		if (!seccomp_names_from_actions_logged(names, sizeof(names),
						       seccomp_actions_logged))
			return -EINVAL;
	}

	table = *ro_table;
	table.data = names;
	table.maxlen = sizeof(names);
	ret = proc_dostring(&table, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	if (write) {
		u32 actions_logged;

		if (!seccomp_actions_logged_from_names(&actions_logged,
						       table.data))
			return -EINVAL;

		if (actions_logged & SECCOMP_LOG_ALLOW)
			return -EINVAL;

		seccomp_actions_logged = actions_logged;
	}

	return 0;
}

static struct ctl_path seccomp_sysctl_path[] = {
	{ .procname = "kernel", },
	{ .procname = "seccomp", },
	{ }
};

static struct ctl_table seccomp_sysctl_table[] = {
	{
		.procname	= "actions_avail",
		.data		= (void *) &seccomp_actions_avail,
		.maxlen		= sizeof(seccomp_actions_avail),
		.mode		= 0444,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "actions_logged",
		.mode		= 0644,
		.proc_handler	= seccomp_actions_logged_handler,
	},
	{ }
};

static int __init seccomp_sysctl_init(void)
{
	struct ctl_table_header *hdr;

	hdr = register_sysctl_paths(seccomp_sysctl_path, seccomp_sysctl_table);
	if (!hdr)
		pr_warn("seccomp: sysctl registration failed\n");
	else
		kmemleak_not_leak(hdr);

	return 0;
}

device_initcall(seccomp_sysctl_init);

#endif /* CONFIG_SYSCTL */

#if defined(CONFIG_SECCOMP_FILTER) && defined(CONFIG_CHECKPOINT_RESTORE)
long seccomp_get_filter(struct task_struct *task, unsigned long filter_off,
			void __user *data)
{
	struct seccomp_filter *filter;
	long ret;
	unsigned long count = 0;

	if (!capable(CAP_SYS_ADMIN) ||
	    current->seccomp.mode != SECCOMP_MODE_DISABLED) {
		return -EACCES;
	}

	spin_lock_irq(&task->sighand->siglock);
	if (task->seccomp.mode != SECCOMP_MODE_FILTER) {
		ret = -EINVAL;
		goto out;
	}

	filter = task->seccomp.filter;
	while (filter) {
		filter = filter->prev;
		count++;
	}

	if (filter_off >= count) {
		ret = -ENOENT;
		goto out;
	}
	count -= filter_off;

	filter = task->seccomp.filter;
	while (filter && count > 1) {
		filter = filter->prev;
		count--;
	}

	if (WARN_ON(count != 1 || !filter)) {
		/* The filter tree shouldn't shrink while we're using it. */
		ret = -ENOENT;
		goto out;
	}

	ret = filter->len;
	if (!data)
		goto out;

	get_seccomp_filter(task);
	spin_unlock_irq(&task->sighand->siglock);

#if CONFIG_VE
	if (copy_to_user(data, filter->orig_prog.filter,
			 filter->orig_prog.len * sizeof(filter->orig_prog.filter[0])))
		ret = -EFAULT;
#else
	if (copy_to_user(data, filter->insns, filter->len * sizeof(filter->insns[0])))
		ret = -EFAULT;
#endif

	put_seccomp_filter(task);
	return ret;

out:
	spin_unlock_irq(&task->sighand->siglock);
	return ret;
}
#endif
