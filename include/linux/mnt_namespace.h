#ifndef _NAMESPACE_H_
#define _NAMESPACE_H_
#ifdef __KERNEL__

#include <linux/mount.h>
#include <linux/poll.h>

#include <linux/types.h>
#include <linux/wait.h>

struct mnt_namespace {
	atomic_t		count;
	unsigned int		proc_inum;
	struct mount *	root;
	struct list_head	list;
	struct user_namespace	*user_ns;
	u64			seq;	/* Sequence number to prevent loops */
	wait_queue_head_t poll;
	int event;
};

struct fs_struct;
struct user_namespace;

extern struct mnt_namespace *copy_mnt_ns(unsigned long, struct mnt_namespace *,
		struct user_namespace *, struct fs_struct *);
extern void put_mnt_ns(struct mnt_namespace *ns);

struct task_struct;
struct mnt_namespace *get_task_mnt_ns(struct task_struct *tsk);

extern const struct file_operations proc_mounts_operations;
extern const struct file_operations proc_mountinfo_operations;
extern const struct file_operations proc_mountstats_operations;

static inline void get_mnt_ns(struct mnt_namespace *ns)
{
	atomic_inc(&ns->count);
}

extern struct rw_semaphore namespace_sem;
extern struct lglock vfsmount_lock;

#endif
#endif
