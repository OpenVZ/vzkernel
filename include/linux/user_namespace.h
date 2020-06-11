#ifndef _LINUX_USER_NAMESPACE_H
#define _LINUX_USER_NAMESPACE_H

#include <linux/kref.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <linux/rh_kabi.h>

#define UIDHASH_BITS   (CONFIG_BASE_SMALL ? 3 : 7)
#define UIDHASH_SZ     (1 << UIDHASH_BITS)

#define UID_GID_MAP_MAX_EXTENTS 5

struct uid_gid_map {	/* 64 bytes -- 1 cache line */
	u32 nr_extents;
	struct uid_gid_extent {
		u32 first;
		u32 lower_first;
		u32 count;
	} extent[UID_GID_MAP_MAX_EXTENTS];
};

#define USERNS_SETGROUPS_ALLOWED 1UL

#define USERNS_INIT_FLAGS USERNS_SETGROUPS_ALLOWED

struct ucounts;

enum ucount_type {
	UCOUNT_USER_NAMESPACES,
	UCOUNT_PID_NAMESPACES,
	UCOUNT_UTS_NAMESPACES,
	UCOUNT_IPC_NAMESPACES,
	UCOUNT_NET_NAMESPACES,
	UCOUNT_MNT_NAMESPACES,
	UCOUNT_KABI_RESERVE_6,
	UCOUNT_KABI_RESERVE_7,
	UCOUNT_KABI_RESERVE_8,
	UCOUNT_KABI_RESERVE_9,
	UCOUNT_KABI_RESERVE_10,
	UCOUNT_KABI_RESERVE_11,
	UCOUNT_KABI_RESERVE_12,
	UCOUNT_KABI_RESERVE_13,
	UCOUNT_KABI_RESERVE_14,
	UCOUNT_KABI_RESERVE_15,
	UCOUNT_COUNTS,
};

struct user_namespace {
	struct uid_gid_map	uid_map;
	struct uid_gid_map	gid_map;
	struct uid_gid_map	projid_map;
	atomic_t		count;
	struct hlist_head       uidhash_table[UIDHASH_SZ];
	struct user_namespace	*parent;
	kuid_t			owner;
	kgid_t			group;
	struct ns_common	ns;
	RH_KABI_DEPRECATE(bool,	may_mount_sysfs)
	RH_KABI_DEPRECATE(bool, may_mount_proc)

	/* Register of per-UID persistent keyrings for this namespace */
#ifdef CONFIG_PERSISTENT_KEYRINGS
	struct key		*persistent_keyring_register;
	struct rw_semaphore	persistent_keyring_register_sem;
#endif
	RH_KABI_EXTEND(int level)
	RH_KABI_EXTEND(unsigned long flags)
	RH_KABI_EXTEND(struct work_struct work)
	RH_KABI_EXTEND(struct ctl_table_set set)
	RH_KABI_EXTEND(struct ctl_table_header *sysctls)
	RH_KABI_EXTEND(struct ucounts *ucounts)
	RH_KABI_EXTEND(int ucount_max[UCOUNT_COUNTS])
};

struct ucounts {
	struct hlist_node node;
	struct user_namespace *ns;
	kuid_t uid;
	int count;
	atomic_t ucount[UCOUNT_COUNTS];
};

extern struct user_namespace init_user_ns;

bool setup_userns_sysctls(struct user_namespace *ns);
void retire_userns_sysctls(struct user_namespace *ns);
struct ucounts *inc_ucount(struct user_namespace *ns, kuid_t uid, enum ucount_type type);
void dec_ucount(struct ucounts *ucounts, enum ucount_type type);

#ifdef CONFIG_USER_NS

static inline struct user_namespace *get_user_ns(struct user_namespace *ns)
{
	if (ns)
		atomic_inc(&ns->count);
	return ns;
}

extern int create_user_ns(struct cred *new);
extern int unshare_userns(unsigned long unshare_flags, struct cred **new_cred);
extern void __put_user_ns(struct user_namespace *ns);

static inline void put_user_ns(struct user_namespace *ns)
{
	if (ns && atomic_dec_and_test(&ns->count))
		__put_user_ns(ns);
}

struct seq_operations;
extern struct seq_operations proc_uid_seq_operations;
extern struct seq_operations proc_gid_seq_operations;
extern struct seq_operations proc_projid_seq_operations;
extern ssize_t proc_uid_map_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t proc_gid_map_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t proc_projid_map_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t proc_setgroups_write(struct file *, const char __user *, size_t, loff_t *);
extern int proc_setgroups_show(struct seq_file *m, void *v);
extern bool userns_may_setgroups(const struct user_namespace *ns);
extern bool current_in_userns(const struct user_namespace *target_ns);

struct ns_common *ns_get_owner(struct ns_common *ns);
#else

static inline struct user_namespace *get_user_ns(struct user_namespace *ns)
{
	return &init_user_ns;
}

static inline int create_user_ns(struct cred *new)
{
	return -EINVAL;
}

static inline int unshare_userns(unsigned long unshare_flags,
				 struct cred **new_cred)
{
	if (unshare_flags & CLONE_NEWUSER)
		return -EINVAL;
	return 0;
}

static inline void put_user_ns(struct user_namespace *ns)
{
}

static inline bool userns_may_setgroups(const struct user_namespace *ns)
{
	return true;
}

static inline bool current_in_userns(const struct user_namespace *target_ns)
{
	return true;
}

static inline struct ns_common *ns_get_owner(struct ns_common *ns)
{
	return ERR_PTR(-EPERM);
}
#endif

#endif /* _LINUX_USER_H */
