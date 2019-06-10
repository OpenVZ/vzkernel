/*
 *  kernel/bc/sys.c
 *
 *  Copyright (c) 2005-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/virtinfo.h>
#include <linux/compat.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

#include <bc/beancounter.h>

/*
 *	The (rather boring) getluid syscall
 */
SYSCALL_DEFINE0(getluid)
{
	struct user_beancounter *ub;
	uid_t uid;

	ub = get_exec_ub();
	if (ub == NULL)
		return -EINVAL;

	uid = ub_legacy_id(ub);
	if (uid == -1)
		return -EINVAL;

	return uid;
}

/*
 *	The setluid syscall
 */
SYSCALL_DEFINE1(setluid, uid_t, uid)
{
	struct user_beancounter *ub;
	int error;

	/* You may not disown a setluid */
	error = -EINVAL;
	if (uid == (uid_t)-1)
		goto out;

	/* You may only set an ub as root */
	error = -EPERM;
	if (!capable(CAP_SETUID))
		goto out;

	/* Ok - set up a beancounter entry for this user */
	error = -ENOBUFS;
	ub = get_beancounter_byuid(uid, 1);
	if (ub == NULL)
		goto out;
	error = ub_attach_task(ub, current);
	put_beancounter(ub);
out:
	return error;
}

long do_setublimit(uid_t uid, unsigned long resource,
		unsigned long *new_limits)
{
	int error;
	unsigned long flags;
	struct user_beancounter *ub;

	error = -EINVAL;
	if (resource >= UB_RESOURCES)
		goto out;

	error = -EINVAL;
	if (new_limits[0] > UB_MAXVALUE || new_limits[1] > UB_MAXVALUE)
		goto out;

	error = -ENOENT;
	ub = get_beancounter_byuid(uid, 0);
	if (ub == NULL)
		goto out;

	ub_sync_memcg(ub);

	spin_lock_irqsave(&ub->ub_lock, flags);
	ub->ub_parms[resource].barrier = new_limits[0];
	ub->ub_parms[resource].limit = new_limits[1];
	init_beancounter_precharge(ub, resource);
	spin_unlock_irqrestore(&ub->ub_lock, flags);

	error = ub_update_memcg(ub);

	put_beancounter(ub);
out:
	return error;
}

/*
 *	The setbeanlimit syscall
 */
SYSCALL_DEFINE3(setublimit, uid_t, uid, unsigned long, resource,
		unsigned long __user *, limits)
{
	unsigned long new_limits[2];

	if (!capable(CAP_SYS_RESOURCE))
		return -EPERM;

	if (copy_from_user(&new_limits, limits, sizeof(new_limits)))
		return -EFAULT;

	return do_setublimit(uid, resource, new_limits);
}

extern long do_ubstat(int func, unsigned long arg1, unsigned long arg2, 
		void __user *buf, long size);

SYSCALL_DEFINE5(ubstat, int, func, unsigned long, arg1, unsigned long, arg2,
		void __user *, buf, long, size)
{
	if (!capable(CAP_DAC_OVERRIDE) && !capable(CAP_DAC_READ_SEARCH))
		return -EPERM;

	return do_ubstat(func, arg1, arg2, buf, size);
}

#ifdef CONFIG_COMPAT
#define UB_MAXVALUE_COMPAT ((1UL << (sizeof(compat_long_t) * 8 - 1)) - 1)

asmlinkage long compat_sys_setublimit(uid_t uid,
		compat_long_t resource,
		compat_long_t __user *limits)
{
	compat_long_t u_new_limits[2];
	unsigned long new_limits[2];

	if (!capable(CAP_SYS_RESOURCE))
		return -EPERM;

	if (copy_from_user(&u_new_limits, limits, sizeof(u_new_limits)))
		return -EFAULT;

	new_limits[0] = u_new_limits[0];
	new_limits[1] = u_new_limits[1];

	if (u_new_limits[0] == UB_MAXVALUE_COMPAT)
		new_limits[0] = UB_MAXVALUE;
	if (u_new_limits[1] == UB_MAXVALUE_COMPAT)
		new_limits[1] = UB_MAXVALUE;

	return do_setublimit(uid, resource, new_limits);
}

asmlinkage long compat_sys_ubstat(int func, unsigned int arg1,
		unsigned int arg2, compat_uptr_t *buf, long size)
{
	return sys_ubstat(func, arg1, arg2, buf, size);
}
#endif
