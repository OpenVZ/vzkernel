#include <bc/decl.h>
#include <bc/task.h>
#include <bc/beancounter.h>

UB_DECLARE_FUNC(int, ub_oom_lock(struct oom_control *oom_ctrl))
UB_DECLARE_FUNC(struct user_beancounter *, ub_oom_select_worst(void))
UB_DECLARE_VOID_FUNC(ub_oom_unlock(struct oom_control *oom_ctrl))
static inline void ub_oom_mm_dead(struct mm_struct *mm) { }
UB_DECLARE_FUNC(int, ub_oom_task_skip(struct user_beancounter *ub,
			struct task_struct *tsk))
static inline unsigned long ub_oom_total_pages(struct user_beancounter *ub) { return 0; }
static inline int out_of_memory_in_ub(struct user_beancounter *ub,
					gfp_t gfp_mask) { return 0; }
UB_DECLARE_VOID_FUNC(ub_oom_start(struct oom_control *oom_ctrl))
UB_DECLARE_VOID_FUNC(ub_oom_mark_mm(struct mm_struct *mm,
			struct oom_control *oom_ctrl))

#ifdef CONFIG_BEANCOUNTERS
#endif
