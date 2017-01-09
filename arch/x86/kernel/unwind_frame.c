#include <linux/sched.h>
#include <asm/ptrace.h>
#include <asm/bitops.h>
#include <asm/stacktrace.h>
#include <asm/unwind.h>

#define FRAME_HEADER_SIZE (sizeof(long) * 2)

/*
 * This disables KASAN checking when reading a value from another task's stack,
 * since the other task could be running on another CPU and could have poisoned
 * the stack in the meantime.
 */
#define READ_ONCE_TASK_STACK(task, x)			\
({							\
	unsigned long val;				\
	if (task == current)				\
		val = READ_ONCE(x);			\
	else						\
		val = READ_ONCE_NOCHECK(x);		\
	val;						\
})

unsigned long unwind_get_return_address(struct unwind_state *state)
{
	if (unwind_done(state))
		return 0;

	return __kernel_text_address(state->ip) ? state->ip : 0;
}
EXPORT_SYMBOL_GPL(unwind_get_return_address);

static bool update_stack_state(struct unwind_state *state,
			       unsigned long *next_bp)
{
	struct stack_info *info = &state->stack_info;
	enum stack_type prev_type = info->type;
	unsigned long *prev_frame_end, *addr_p, addr;

	prev_frame_end = (void *)state->bp + FRAME_HEADER_SIZE;

	/*
	 * If the next bp isn't on the current stack, switch to the next one.
	 *
	 * We may have to traverse multiple stacks to deal with the possibility
	 * that info->next_sp could point to an empty stack and the next bp
	 * could be on a subsequent stack.
	 */
	while (!on_stack(info, next_bp, FRAME_HEADER_SIZE))
		if (get_stack_info(info->next_sp, state->task, info,
				   &state->stack_mask))
			return false;

	/* Make sure it only unwinds up and doesn't overlap the prev frame: */
	if (state->orig_sp && state->stack_info.type == prev_type &&
	    next_bp < prev_frame_end)
		return false;

	/* Move state to the next frame: */
	state->bp = next_bp;
	addr_p = state->bp + 1;
	addr = READ_ONCE_TASK_STACK(state->task, *addr_p);
	state->ip = ftrace_graph_ret_addr(state->task, &state->graph_idx,
					  addr, addr_p);

	/*
	 * Save the original stack pointer for unwind_dump():
	 *
	 * NOTE: RHEL doesn't have unwind_dump().  This variable is also used
	 * in this function as a "not first frame" bool check (see above).
	 */
	if (!state->orig_sp)
		state->orig_sp = next_bp;

	return true;
}

extern const unsigned long __start___unwind_unsafe_stack[],
			   __stop___unwind_unsafe_stack[];

static bool unwind_unsafe(struct unwind_state *state)
{
	const unsigned long *addr;

	for (addr = __start___unwind_unsafe_stack;
	     addr < __stop___unwind_unsafe_stack; addr++)
		if (*addr == state->ip)
			return true;

	return false;
}
extern const unsigned long __start___unwind_end_of_stack[],
			   __stop___unwind_end_of_stack[],
			   ret_from_fork_nospec_begin[],
			   ret_from_fork_nospec_end[];

static bool unwind_end(struct unwind_state *state)
{
	const unsigned long *addr;

	for (addr = __start___unwind_end_of_stack;
	     addr < __stop___unwind_end_of_stack; addr++)
		if (*addr == state->ip)
			return true;

	/*
	 * The UNWIND_END_OF_STACK macro doesn't work after CALL_NOSPEC in all
	 * cases (non-retpoline and AMD retpoline), so we need to manually
	 * check the end of stack location in ret_from_fork().
	 */
	if (state->ip > (unsigned long)ret_from_fork_nospec_begin &&
	    state->ip <= (unsigned long)ret_from_fork_nospec_end)
		return true;

	return false;
}

bool unwind_next_frame(struct unwind_state *state)
{
	unsigned long *next_bp;

	if (unwind_done(state))
		return false;

	if (unwind_unsafe(state))
		state->error = true;

	if (unwind_end(state))
		goto the_end;

	next_bp = (unsigned long *)READ_ONCE_TASK_STACK(state->task,*state->bp);

	/* make sure the next frame's data is accessible */
	if (!update_stack_state(state, next_bp)) {
		state->error = true;
		goto the_end;
	}

	/* move to the next frame */
	state->bp = next_bp;
	return true;

the_end:
	state->stack_info.type = STACK_TYPE_UNKNOWN;
	return false;
}
EXPORT_SYMBOL_GPL(unwind_next_frame);

void __unwind_start(struct unwind_state *state, struct task_struct *task,
		    struct pt_regs *regs, unsigned long *first_frame)
{
	memset(state, 0, sizeof(*state));
	state->task = task;

	/* don't even attempt to start from user mode regs */
	if (regs && user_mode(regs)) {
		state->stack_info.type = STACK_TYPE_UNKNOWN;
		return;
	}

	/* set up the starting stack frame */
	state->bp = get_frame_pointer(task, regs);

	/* initialize stack info and make sure the frame data is accessible */
	get_stack_info(state->bp, state->task, &state->stack_info,
		       &state->stack_mask);
	update_stack_state(state, state->bp);

	/*
	 * The caller can provide the address of the first frame directly
	 * (first_frame) or indirectly (regs->sp) to indicate which stack frame
	 * to start unwinding at.  Skip ahead until we reach it.
	 */
	while (!unwind_done(state) &&
	       (!on_stack(&state->stack_info, first_frame, sizeof(long)) ||
			state->bp < first_frame))
		unwind_next_frame(state);
}
EXPORT_SYMBOL_GPL(__unwind_start);
