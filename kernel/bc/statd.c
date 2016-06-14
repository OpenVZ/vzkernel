/*
 *  kernel/bc/statd.c
 *
 *  Copyright (c) 2005-2008 SWsoft
 *  Copyright (c) 2009-2015 Parallels IP Holdings GmbH
 *
 */

#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/suspend.h>
#include <linux/freezer.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <asm/uaccess.h>
#include <asm/param.h>

#include <bc/beancounter.h>
#include <uapi/linux/bc/statd.h>

static DEFINE_SPINLOCK(ubs_notify_lock);
static LIST_HEAD(ubs_notify_list);
static long ubs_min_interval;
static ubstattime_t ubs_start_time, ubs_end_time;
static struct timer_list ubs_timer;

struct ub_stat_notify {
	struct list_head	list;
	struct task_struct	*task;
	int			signum;
};

static int ubstat_get_list(void __user *buf, long size)
{
	int retval;
	struct user_beancounter *ub, *ubp;
	long *page, *ptr, *end;
	int len;

	page = (long *)__get_free_page(GFP_KERNEL);
	if (page == NULL)
		return -ENOMEM;

	retval = 0;
	ubp = NULL;
	ptr = page;
	end = page + PAGE_SIZE / sizeof(*ptr);

	rcu_read_lock();
	for_each_beancounter(ub) {
		uid_t uid = ub_legacy_id(ub);

		if (uid == -1)
			continue;

		*ptr++ = uid;
		if (ptr != end)
			continue;

		if (!get_beancounter_rcu(ub)) {
			ptr--;
			continue;
		}
		rcu_read_unlock();

		put_beancounter(ubp);
		ubp = ub;

		len = min_t(long, (ptr - page) * sizeof(*ptr), size);
		if (copy_to_user(buf, page, len)) {
			retval = -EFAULT;
			goto out_put;
		}
		retval += len;
		if (len < PAGE_SIZE)
			goto out_put;
		buf += len;
		size -= len;

		ptr = page;
		end = page + PAGE_SIZE / sizeof(*ptr);

		rcu_read_lock();
	}
	rcu_read_unlock();

	size = min_t(long, (ptr - page) * sizeof(*ptr), size);
	if (size > 0 && copy_to_user(buf, page, size)) {
		retval = -EFAULT;
		goto out_put;
	}
	retval += size;

out_put:
	put_beancounter(ubp);
	free_page((unsigned long)page);
	return retval;
}

static int ubstat_gettime(void __user *buf, long size)
{
	ubgettime_t data;
	int retval;

	spin_lock(&ubs_notify_lock);
	data.start_time = ubs_start_time;
	data.end_time = ubs_end_time;
	data.cur_time = ubs_start_time + (jiffies - ubs_start_time * HZ) / HZ;
	spin_unlock(&ubs_notify_lock);

	retval = min_t(long, sizeof(data), size);
	if (copy_to_user(buf, &data, retval))
		retval = -EFAULT;
	return retval;
}

static int ubstat_do_read_one(struct user_beancounter *ub, int res, void *kbuf)
{
	struct {
		ubstattime_t	start_time;
		ubstattime_t	end_time;
		ubstatparm_t	param[1];
	} *data;

	data = kbuf;
	data->start_time = ubs_start_time;
	data->end_time = ubs_end_time;

	data->param[0].maxheld = ub->ub_store[res].maxheld;
	data->param[0].failcnt = ub->ub_store[res].failcnt;

	return sizeof(*data);
}

static int ubstat_do_read_all(struct user_beancounter *ub, void *kbuf, int size)
{
	int wrote;
	struct {
		ubstattime_t	start_time;
		ubstattime_t	end_time;
		ubstatparm_t	param[UB_RESOURCES];
	} *data;
	int resource;

	data = kbuf;
	data->start_time = ubs_start_time;
	data->end_time = ubs_end_time;
	wrote = sizeof(data->start_time) + sizeof(data->end_time);

	for (resource = 0; resource < UB_RESOURCES; resource++) {
		if (size < wrote + sizeof(data->param[resource]))
			break;
		data->param[resource].maxheld = ub->ub_store[resource].maxheld;
		data->param[resource].failcnt = ub->ub_store[resource].failcnt;
		wrote += sizeof(data->param[resource]); 
	}

	return wrote;
}

static int ubstat_do_read_full(struct user_beancounter *ub, void *kbuf,
		int size)
{
	int wrote;
	struct {
		ubstattime_t	start_time;
		ubstattime_t	end_time;
		ubstatparmf_t	param[UB_RESOURCES];
	} *data;
	int resource;

	data = kbuf;
	data->start_time = ubs_start_time;
	data->end_time = ubs_end_time;
	wrote = sizeof(data->start_time) + sizeof(data->end_time);

	for (resource = 0; resource < UB_RESOURCES; resource++) {
		ubstatparmf_t *p = &data->param[resource];
		struct ubparm *s = &ub->ub_store[resource];

		if (size < wrote + sizeof(data->param[resource]))
			break;

		p->barrier	= s->barrier;
		p->limit	= s->limit;
		p->held		= s->held;
		p->maxheld	= s->maxheld;
		p->minheld	= s->minheld;
		p->failcnt	= s->failcnt;
		p->__unused1	= 0;
		p->__unused2	= 0;

		wrote += sizeof(data->param[resource]);
	}
	return wrote;
}

int ubstat_alloc_store(struct user_beancounter *ub)
{
	if (ub->ub_store == NULL) {
		struct ubparm *store;

		store = kmemdup(ub->ub_parms,
				UB_RESOURCES * sizeof(struct ubparm),
				GFP_KERNEL);
		if (store == NULL)
			return -ENOMEM;

		spin_lock(&ubs_notify_lock);
		if (ub->ub_store != NULL)
			kfree(store);
		else
			ub->ub_store = store;
		spin_unlock(&ubs_notify_lock);
	}
	return 0;
}
EXPORT_SYMBOL(ubstat_alloc_store);

static bool ubstat_need_memcg_sync(long cmd)
{
	if (UBSTAT_CMD(cmd) != UBSTAT_READ_ONE)
		return true;

	switch (UBSTAT_PARMID(cmd)) {
		case UB_KMEMSIZE:
		case UB_DCACHESIZE:
		case UB_PHYSPAGES:
		case UB_SWAPPAGES:
		case UB_OOMGUARPAGES:
			return true;
	}
	return false;
}

static int ubstat_check_cmd(long cmd)
{
	switch (UBSTAT_CMD(cmd)) {
		case UBSTAT_READ_ONE:
			if (UBSTAT_PARMID(cmd) >= UB_RESOURCES)
				break;
		case UBSTAT_READ_ALL:
		case UBSTAT_READ_FULL:
			return 0;
	}
	return -EINVAL;
}

static int ubstat_get_stat(struct user_beancounter *ub, long cmd,
		void __user *buf, long size)
{
	void *kbuf;
	int retval;

	retval = ubstat_check_cmd(cmd);
	if (retval)
		return retval;

	kbuf = (void *)__get_free_page(GFP_KERNEL);
	if (kbuf == NULL)
		return -ENOMEM;

	retval = ubstat_alloc_store(ub);
	if (retval)
		goto out;

	if (ubstat_need_memcg_sync(cmd))
		ub_sync_memcg(ub);

	spin_lock(&ubs_notify_lock);
	switch (UBSTAT_CMD(cmd)) {
		case UBSTAT_READ_ONE:
			retval = ubstat_do_read_one(ub,
					UBSTAT_PARMID(cmd), kbuf);
			break;
		case UBSTAT_READ_ALL:
			retval = ubstat_do_read_all(ub, kbuf, PAGE_SIZE);
			break;
		case UBSTAT_READ_FULL:
			retval = ubstat_do_read_full(ub, kbuf, PAGE_SIZE);
			break;
		default:
			retval = -EINVAL;
			__WARN_printf("%s: we shouldn't get there\ncmd: %ld\n",
					__func__, UBSTAT_CMD(cmd));
	}
	spin_unlock(&ubs_notify_lock);

	if (retval > 0) {
		retval = min_t(long, retval, size);
		if (copy_to_user(buf, kbuf, retval))
			retval = -EFAULT;
	}
out:
	free_page((unsigned long)kbuf);
	return retval;
}

static int ubstat_handle_notifrq(ubnotifrq_t *req)
{
	int retval;
	struct ub_stat_notify *new_notify;
	struct list_head *entry;
	struct task_struct *tsk_to_free;

	new_notify = kmalloc(sizeof(*new_notify), GFP_KERNEL);
	if (new_notify == NULL)
		return -ENOMEM;

	tsk_to_free = NULL;
	INIT_LIST_HEAD(&new_notify->list);

	spin_lock(&ubs_notify_lock);
	list_for_each(entry, &ubs_notify_list) {
		struct ub_stat_notify *notify;

		notify = list_entry(entry, struct ub_stat_notify, list);
		if (notify->task == current) {
			kfree(new_notify);
			new_notify = notify;
			break;
		}
	}

	retval = -EINVAL;
	if (req->maxinterval < 1)
		goto out_unlock;
	if (req->maxinterval > TIME_MAX_SEC)
		req->maxinterval = TIME_MAX_SEC;
	if (req->maxinterval < ubs_min_interval) {
		unsigned long dif;

		ubs_min_interval = req->maxinterval;
		dif = (ubs_timer.expires - jiffies + HZ - 1) / HZ;
		if (dif > req->maxinterval)
			mod_timer(&ubs_timer,
					ubs_timer.expires -
					(dif - req->maxinterval) * HZ);
	}

	if (entry != &ubs_notify_list) {
		list_del(&new_notify->list);
		tsk_to_free = new_notify->task;
	}
	if (req->signum) {
		new_notify->task = current;
		get_task_struct(new_notify->task);
		new_notify->signum = req->signum;
		list_add(&new_notify->list, &ubs_notify_list);
	} else
		kfree(new_notify);
	retval = 0;
out_unlock:
	spin_unlock(&ubs_notify_lock);
	if (tsk_to_free != NULL)
		put_task_struct(tsk_to_free);
	return retval;
}

/*
 * former sys_ubstat
 */
long do_ubstat(int func, unsigned long arg1, unsigned long arg2,
		void __user *buf, long size)
{
	int retval;
	struct user_beancounter *ub;

	if (func == UBSTAT_UBPARMNUM)
		return UB_RESOURCES;
	if (func == UBSTAT_UBLIST)
		return ubstat_get_list(buf, size);

	if (func == UBSTAT_GETTIME) {
		retval = ubstat_gettime(buf, size);
		goto notify;
	}

	ub = get_exec_ub();
	if (ub != NULL && ub_legacy_id(ub) == arg1 && (uid_t)arg1 != -1)
		get_beancounter(ub);
	else /* FIXME must be if (ve_is_super) */
		ub = get_beancounter_byuid(arg1, 0);

	if (ub == NULL)
		return -ESRCH;

	retval = ubstat_get_stat(ub, func, buf, size);
	put_beancounter(ub);
notify:
	/* Handle request for notification */
	if (retval >= 0) {
		ubnotifrq_t notifrq;
		int err;

		err = -EFAULT;
		if (!copy_from_user(&notifrq, (void __user *)arg2,
					sizeof(notifrq)))
			err = ubstat_handle_notifrq(&notifrq);
		if (err)
			retval = err;
	}

	return retval;
}

static void ubstat_save_onestat(struct user_beancounter *ub)
{
	int resource;

	if (ub->ub_store == NULL)
		return;

	/* called with local irq disabled */
	spin_lock(&ub->ub_lock);
	for (resource = 0; resource < UB_RESOURCES; resource++) {
		memcpy(&ub->ub_store[resource], &ub->ub_parms[resource],
			sizeof(struct ubparm));
		ub->ub_parms[resource].minheld = 
			ub->ub_parms[resource].maxheld =
			ub->ub_parms[resource].held;
	}
	spin_unlock(&ub->ub_lock);
}

static void ubstat_save_statistics(void)
{
	unsigned long flags;
	struct user_beancounter *ub;

	local_irq_save(flags);
	for_each_beancounter (ub)
		ubstat_save_onestat(ub);
	local_irq_restore(flags);
}

static void ubstatd_timeout(unsigned long __data)
{
	struct task_struct *p;

	p = (struct task_struct *) __data;
	wake_up_process(p);
}

/*
 * Safe wrapper for send_sig. It prevents a race with release_task
 * for sighand.
 * Should be called under tasklist_lock.
 */
static void task_send_sig(struct ub_stat_notify *notify)
{
	if (likely(notify->task->sighand != NULL))
		send_sig(notify->signum, notify->task, 1);
}

static inline void do_notifies(void)
{
	LIST_HEAD(notif_free_list);
	struct ub_stat_notify *notify;
	struct ub_stat_notify *tmp;

	spin_lock(&ubs_notify_lock);
	ubs_start_time = ubs_end_time;
	/*
	 * the expression below relies on time being unsigned long and
	 * arithmetic promotion rules
	 */
	ubs_end_time += (ubs_timer.expires - ubs_start_time * HZ) / HZ;
	mod_timer(&ubs_timer, ubs_timer.expires + ubs_min_interval * HZ);
	ubs_min_interval = TIME_MAX_SEC;
	/* save statistics accumulated for the interval */
	ubstat_save_statistics();
	/* send signals */
	qread_lock(&tasklist_lock);
	list_for_each_entry_safe(notify, tmp, &ubs_notify_list, list) {
		task_send_sig(notify);
		list_move(&notify->list, &notif_free_list);
	}
	qread_unlock(&tasklist_lock);
	spin_unlock(&ubs_notify_lock);

	list_for_each_entry_safe(notify, tmp, &notif_free_list, list) {
		put_task_struct(notify->task);
		list_del(&notify->list);
		kfree(notify);
	}
}

/*
 * Kernel thread
 */
static int ubstatd(void *unused)
{
	ubs_timer.data = (unsigned long)current;
	ubs_timer.function = ubstatd_timeout;
	add_timer(&ubs_timer);

	while (1) {
		set_task_state(current, TASK_INTERRUPTIBLE);
		if (time_after(ubs_timer.expires, jiffies)) {
			schedule();
			try_to_freeze();
			continue;
		}

		__set_task_state(current, TASK_RUNNING);
		do_notifies();
	}
	return 0;
}

static int __init ubstatd_init(void)
{
	init_timer(&ubs_timer);
	ubs_timer.expires = TIME_MAX_JIF;
	ubs_min_interval = TIME_MAX_SEC;
	ubs_start_time = ubs_end_time = 0;
	kthread_run(ubstatd, NULL, "ubstatd");
	return 0;
}

module_init(ubstatd_init);
