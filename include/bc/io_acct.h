/*
 *  include/ub/io_acct.h
 *
 *  Copyright (C) 2006 SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 *  Pavel Emelianov <xemul@openvz.org>
 *
 */

#ifndef __UB_IO_ACCT_H_
#define __UB_IO_ACCT_H_

#ifdef CONFIG_BC_IO_ACCOUNTING
#include <bc/beancounter.h>
#include <linux/virtinfo.h>

extern int ub_dirty_radio;
extern int ub_dirty_background_ratio;

/*
 * IO ub is required in task context only, so if exec_ub is set
 * to NULL this means that uses doesn't need to charge some
 * resources. nevertheless IO activity must be accounted, so we
 * account it to current's task beancounter.
 */

static inline struct user_beancounter *get_io_ub(void)
{
	struct user_beancounter *ub;

	ub = get_exec_ub();
	if (unlikely(ub == NULL))
		ub = get_task_ub(current);

	return ub;
}

static inline void ub_io_account_read(size_t bytes)
{
	ub_percpu_add(get_io_ub(), sync_read_bytes, bytes);
	virtinfo_notifier_call(VITYPE_IO, VIRTINFO_IO_ACCOUNT, &bytes);
}

static inline void ub_io_account_write(size_t bytes)
{
	ub_percpu_add(get_io_ub(), sync_write_bytes, bytes);
	virtinfo_notifier_call(VITYPE_IO, VIRTINFO_IO_ACCOUNT, &bytes);
}

extern void ub_io_account_dirty(struct address_space *mapping);
extern void ub_io_account_clean(struct address_space *mapping);
extern void ub_io_account_cancel(struct address_space *mapping);
extern void ub_io_writeback_inc(struct address_space *mapping);
extern void ub_io_writeback_dec(struct address_space *mapping);

#define ub_dirty_pages(ub)	ub_stat_get(ub, dirty_pages)

extern int ub_dirty_limits(unsigned long *pbackground,
			   long *pdirty, struct user_beancounter *ub);

extern bool ub_should_skip_writeback(struct user_beancounter *ub,
				     struct inode *inode);

static inline void ub_writeback_io(unsigned long requests, unsigned long sectors)
{
	struct user_beancounter *ub = get_exec_ub();
	ub_stat_add(ub, wb_requests, requests);
	ub_stat_add(ub, wb_sectors, sectors);
}

#else /* UBC_IO_ACCT */

static inline void ub_io_account_read(size_t bytes)
{
}

static inline void ub_io_account_write(size_t bytes)
{
}

static inline void ub_io_account_dirty(struct address_space *mapping)
{
}

static inline void ub_io_account_clean(struct address_space *mapping)
{
}

static inline void ub_io_account_cancel(struct address_space *mapping)
{
}

static inline void ub_io_writeback_inc(struct address_space *mapping)
{
}

static inline void ub_io_writeback_dec(struct address_space *mapping)
{
}

static inline unsigned long ub_dirty_pages(struct user_beancounter *ub)
{
	return 0;
}

static inline int ub_dirty_limits(unsigned long *pbackground,
				  long *pdirty, struct user_beancounter *ub)
{
	return 0;
}

static inline bool ub_should_skip_writeback(struct user_beancounter *ub,
				     struct inode *inode)
{
	return false;
}

static inline struct user_beancounter *get_io_ub(void)
{
	return NULL;
}

#endif /* UBC_IO_ACCT */

#endif
