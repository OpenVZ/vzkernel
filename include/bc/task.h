/*
 *  include/bc/task.h
 *
 *  Copyright (c) 2005-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *
 */

#ifndef __BC_TASK_H_
#define __BC_TASK_H_

struct user_beancounter;
struct callback_head;

#ifdef CONFIG_BEANCOUNTERS
struct task_beancounter {
	struct user_beancounter	*exec_ub;
	struct user_beancounter	*task_ub;
	struct callback_head cgroup_attach_work;
};

extern int ub_attach_task(struct user_beancounter *, struct task_struct *);

#define get_task_ub(__task)	((__task)->task_bc.task_ub)

extern struct user_beancounter ub0;
#define get_ub0()	(&ub0)

#define get_exec_ub()		(current->task_bc.exec_ub)
#define set_exec_ub(__newub)		\
({					\
	struct user_beancounter *old;	\
	struct task_beancounter *tbc;	\
 					\
	tbc = &current->task_bc;	\
	old = tbc->exec_ub;		\
	tbc->exec_ub = __newub;		\
	old;				\
})

#else /* CONFIG_BEANCOUNTERS */

#define get_ub0()		(NULL)
#define get_exec_ub()		(NULL)
#define get_task_ub(task)	(NULL)
#define set_exec_ub(__ub)	(NULL)

#endif /* CONFIG_BEANCOUNTERS */
#endif /* __task.h_ */
