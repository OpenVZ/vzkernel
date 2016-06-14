/*
 *  include/bc/proc.h
 *
 *  Copyright (c) 2006-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *
 */

#ifndef __UB_PROC_H_
#define __UB_PROC_H_

#include <linux/seq_file.h>

struct bc_proc_entry {
	char *name;
	union {
		int (*show)(struct seq_file *, void *);
		struct file_operations *fops;
	} u;
	struct bc_proc_entry *next;
	int cookie;
};

struct user_beancounter;

void bc_register_proc_entry(struct bc_proc_entry *);
void bc_register_proc_root_entry(struct bc_proc_entry *);

static inline struct user_beancounter *seq_beancounter(struct seq_file *f)
{
	return (struct user_beancounter *)(f->private);
}

extern const char *bc_proc_lu_fmt;
extern const char *bc_proc_lu_lfmt;
extern const char *bc_proc_llu_fmt;
extern const char *bc_proc_lu_lu_fmt;
#endif
