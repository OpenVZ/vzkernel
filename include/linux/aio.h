/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX__AIO_H
#define __LINUX__AIO_H

#include <linux/aio_abi.h>

struct kioctx;
struct kiocb;
struct mm_struct;

typedef int (kiocb_cancel_fn)(struct kiocb *);

#define AIO_MAX_NR_DEFAULT	0x10000

struct ve_ioc_arg
{
	aio_context_t	ctx_id;
	unsigned	val;
};

#define VE_AIO_IOC_WAIT_ACTIVE	_IOW('a',  1, struct ve_ioc_arg)

/* prototypes */
#ifdef CONFIG_AIO
extern void exit_aio(struct mm_struct *mm);
void kiocb_set_cancel_fn(struct kiocb *req, kiocb_cancel_fn *cancel);
#ifdef CONFIG_VE
int ve_aio_ioctl(struct task_struct *, unsigned int, unsigned long);
#endif
#else
static inline void exit_aio(struct mm_struct *mm) { }
static inline void kiocb_set_cancel_fn(struct kiocb *req,
				       kiocb_cancel_fn *cancel) { }
static int ve_aio_ioctl(struct task_struct *task, unsigned int cmd,
			unsigned long arg) { return 0; }
#endif /* CONFIG_AIO */

#endif /* __LINUX__AIO_H */
