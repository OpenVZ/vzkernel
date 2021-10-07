// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cn_proc.c - process events connector
 *
 * Copyright (C) Matt Helsley, IBM Corp. 2005
 * Based on cn_fork.c by Guillaume Thouvenin <guillaume.thouvenin@bull.net>
 * Original copyright notice follows:
 * Copyright (C) 2005 BULL SA.
 */

#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/init.h>
#include <linux/connector.h>
#include <linux/gfp.h>
#include <linux/ptrace.h>
#include <linux/atomic.h>
#include <linux/pid_namespace.h>
#include <linux/ve.h>

#include <linux/cn_proc.h>
#include <linux/local_lock.h>

/*
 * Size of a cn_msg followed by a proc_event structure.  Since the
 * sizeof struct cn_msg is a multiple of 4 bytes, but not 8 bytes, we
 * add one 4-byte word to the size here, and then start the actual
 * cn_msg structure 4 bytes into the stack buffer.  The result is that
 * the immediately following proc_event structure is aligned to 8 bytes.
 */
#define CN_PROC_MSG_SIZE (sizeof(struct cn_msg) + sizeof(struct proc_event) + 4)

/* See comment above; we test our assumption about sizeof struct cn_msg here. */
static inline struct cn_msg *buffer_to_cn_msg(__u8 *buffer)
{
	BUILD_BUG_ON(sizeof(struct cn_msg) != 20);
	return (struct cn_msg *)(buffer + 4);
}

static struct cb_id cn_proc_event_id = { CN_IDX_PROC, CN_VAL_PROC };

/* local_event.count is used as the sequence number of the netlink message */
struct local_event {
	local_lock_t lock;
	__u32 count;
};

static inline void send_msg_ve(struct ve_struct *ve, struct cn_msg *msg)
{
	struct local_event *le_ptr;

	/*
	 * The following hack with local_event->lock address works only
	 * till the "lock" is the first field in the local_event struct,
	 * so be of the safe side.
	 */
	BUILD_BUG_ON(offsetof(struct local_event, lock) != 0);
	local_lock(&ve->cn->local_event->lock);

	le_ptr = this_cpu_ptr(ve->cn->local_event);
	msg->seq = le_ptr->count++;
	((struct proc_event *)msg->data)->cpu = smp_processor_id();

	/*
	 * local_lock() disables preemption during send to ensure the messages
	 * are ordered according to their sequence numbers.
	 *
	 * If cn_netlink_send() fails, the data is not sent.
	 */
	cn_netlink_send(msg, 0, CN_IDX_PROC, GFP_NOWAIT);

	local_unlock(&ve->cn->local_event->lock);
}

static struct cn_msg *cn_msg_fill(__u8 *buffer, struct ve_struct *ve,
				  struct task_struct *task,
				  int what, int cookie,
				  bool (*fill_event)(struct proc_event *ev,
						     struct ve_struct *ve,
						     struct task_struct *task,
						     int cookie))
{
	struct cn_msg *msg;
	struct proc_event *ev;

	msg = buffer_to_cn_msg(buffer);
	ev = (struct proc_event *)msg->data;

	memset(&ev->event_data, 0, sizeof(ev->event_data));
	ev->timestamp_ns = ktime_get_ns();
	ev->what = what;

	memcpy(&msg->id, &cn_proc_event_id, sizeof(msg->id));
	msg->ack = 0; /* not used */
	msg->len = sizeof(*ev);
	msg->flags = 0; /* not used */

	return fill_event(ev, ve, task, cookie) ? msg : NULL;
}

static int proc_event_num_listeners(struct ve_struct *ve)
{
	if (ve->cn)
		return atomic_read(&ve->cn->proc_event_num_listeners);
	return 0;
}

static void proc_event_connector(struct task_struct *task,
				 int what, int cookie,
				 bool (*fill_event)(struct proc_event *ev,
						    struct ve_struct *ve,
						    struct task_struct *task,
						    int cookie))
{
	struct cn_msg *msg;
	__u8 buffer[CN_PROC_MSG_SIZE] __aligned(8);
	struct ve_struct *ve = task->task_ve;

	if (proc_event_num_listeners(ve) < 1)
		return;

	msg = cn_msg_fill(buffer, ve, task, what, cookie, fill_event);
	if (!msg)
		return;

	/*  If cn_netlink_send() failed, the data is not sent */
	send_msg_ve(ve, msg);
}

static bool fill_fork_event(struct proc_event *ev, struct ve_struct *ve,
			    struct task_struct *task, int unused)
{
	struct task_struct *parent;
	struct pid_namespace *pid_ns = ve->ve_ns->pid_ns_for_children;

	rcu_read_lock();
	parent = rcu_dereference(task->real_parent);
	ev->event_data.fork.parent_pid = task_pid_nr_ns(parent, pid_ns);
	ev->event_data.fork.parent_tgid = task_tgid_nr_ns(parent, pid_ns);
	rcu_read_unlock();
	ev->event_data.fork.child_pid = task_pid_nr_ns(task, pid_ns);
	ev->event_data.fork.child_tgid = task_tgid_nr_ns(task, pid_ns);
	return true;
}

void proc_fork_connector(struct task_struct *task)
{
	proc_event_connector(task, PROC_EVENT_FORK, 0, fill_fork_event);
}

static bool fill_exec_event(struct proc_event *ev, struct ve_struct *ve,
			    struct task_struct *task, int unused)
{
	struct pid_namespace *pid_ns = ve->ve_ns->pid_ns_for_children;

	ev->event_data.exec.process_pid = task_pid_nr_ns(task, pid_ns);
	ev->event_data.exec.process_tgid = task_tgid_nr_ns(task, pid_ns);
	return true;
}

void proc_exec_connector(struct task_struct *task)
{
	proc_event_connector(task, PROC_EVENT_EXEC, 0, fill_exec_event);
}

static bool fill_id_event(struct proc_event *ev, struct ve_struct *ve,
			  struct task_struct *task, int which_id)
{
	const struct cred *cred;
	struct pid_namespace *pid_ns = ve->ve_ns->pid_ns_for_children;
	struct user_namespace *user_ns = ve->init_cred->user_ns;

	ev->event_data.id.process_pid = task_pid_nr_ns(task, pid_ns);
	ev->event_data.id.process_tgid = task_tgid_nr_ns(task, pid_ns);
	rcu_read_lock();
	cred = __task_cred(task);
	if (which_id == PROC_EVENT_UID) {
		ev->event_data.id.r.ruid = from_kuid_munged(user_ns, cred->uid);
		ev->event_data.id.e.euid = from_kuid_munged(user_ns, cred->euid);
	} else if (which_id == PROC_EVENT_GID) {
		ev->event_data.id.r.rgid = from_kgid_munged(user_ns, cred->gid);
		ev->event_data.id.e.egid = from_kgid_munged(user_ns, cred->egid);
	} else {
		rcu_read_unlock();
		return false;
	}
	rcu_read_unlock();
	return true;
}

void proc_id_connector(struct task_struct *task, int which_id)
{
	proc_event_connector(task, which_id, which_id, fill_id_event);
}

static bool fill_sid_event(struct proc_event *ev, struct ve_struct *ve,
			   struct task_struct *task, int unused)
{
	struct pid_namespace *pid_ns = ve->ve_ns->pid_ns_for_children;

	ev->event_data.sid.process_pid = task_pid_nr_ns(task, pid_ns);
	ev->event_data.sid.process_tgid = task_tgid_nr_ns(task, pid_ns);
	return true;
}

void proc_sid_connector(struct task_struct *task)
{
	proc_event_connector(task, PROC_EVENT_SID, 0, fill_sid_event);
}

static bool fill_ptrace_event(struct proc_event *ev, struct ve_struct *ve,
			      struct task_struct *task, int ptrace_id)
{
	struct pid_namespace *pid_ns = ve->ve_ns->pid_ns_for_children;

	ev->event_data.ptrace.process_pid  = task_pid_nr_ns(task, pid_ns);
	ev->event_data.ptrace.process_tgid = task_tgid_nr_ns(task, pid_ns);
	if (ptrace_id == PTRACE_ATTACH) {
		ev->event_data.ptrace.tracer_pid  = task_pid_nr_ns(current, pid_ns);
		ev->event_data.ptrace.tracer_tgid = task_tgid_nr_ns(current, pid_ns);
	} else if (ptrace_id == PTRACE_DETACH) {
		ev->event_data.ptrace.tracer_pid  = 0;
		ev->event_data.ptrace.tracer_tgid = 0;
	} else
		return false;
	return true;
}

void proc_ptrace_connector(struct task_struct *task, int ptrace_id)
{
	proc_event_connector(task, PROC_EVENT_PTRACE, ptrace_id,
			     fill_ptrace_event);
}

static bool fill_comm_event(struct proc_event *ev, struct ve_struct *ve,
			    struct task_struct *task, int unused)
{
	struct pid_namespace *pid_ns = ve->ve_ns->pid_ns_for_children;

	ev->event_data.comm.process_pid  = task_pid_nr_ns(task, pid_ns);
	ev->event_data.comm.process_tgid = task_tgid_nr_ns(task, pid_ns);
	get_task_comm(ev->event_data.comm.comm, task);
	return true;
}

void proc_comm_connector(struct task_struct *task)
{
	proc_event_connector(task, PROC_EVENT_COMM, 0, fill_comm_event);
}

static bool fill_coredump_event(struct proc_event *ev, struct ve_struct *ve,
				struct task_struct *task, int unused)
{
	struct pid_namespace *pid_ns = ve->ve_ns->pid_ns_for_children;
	struct task_struct *parent;

	ev->event_data.coredump.process_pid =
		task_pid_nr_ns(task, pid_ns);
	ev->event_data.coredump.process_tgid =
		task_tgid_nr_ns(task, pid_ns);

	rcu_read_lock();
	if (pid_alive(task)) {
		parent = rcu_dereference(task->real_parent);
		ev->event_data.coredump.parent_pid =
			task_pid_nr_ns(parent, pid_ns);
		ev->event_data.coredump.parent_tgid =
			task_tgid_nr_ns(parent, pid_ns);
	}
	rcu_read_unlock();
	return true;
}

void proc_coredump_connector(struct task_struct *task)
{
	proc_event_connector(task, PROC_EVENT_COREDUMP, 0, fill_coredump_event);
}

static bool fill_exit_event(struct proc_event *ev, struct ve_struct *ve,
			    struct task_struct *task, int unused)
{
	struct pid_namespace *pid_ns = ve->ve_ns->pid_ns_for_children;
	struct task_struct *parent;

	ev->event_data.exit.process_pid = task_pid_nr_ns(task, pid_ns);
	ev->event_data.exit.process_tgid = task_tgid_nr_ns(task, pid_ns);
	ev->event_data.exit.exit_code = task->exit_code;
	ev->event_data.exit.exit_signal = task->exit_signal;

	rcu_read_lock();
	if (pid_alive(task)) {
		parent = rcu_dereference(task->real_parent);
		ev->event_data.exit.parent_pid = task_pid_nr_ns(parent,
								pid_ns);
		ev->event_data.exit.parent_tgid = task_tgid_nr_ns(parent,
								  pid_ns);
	}
	rcu_read_unlock();
	return true;
}

void proc_exit_connector(struct task_struct *task)
{
	proc_event_connector(task, PROC_EVENT_EXIT, 0, fill_exit_event);
}

/*
 * Send an acknowledgement message to userspace
 *
 * Use 0 for success, EFOO otherwise.
 * Note: this is the negative of conventional kernel error
 * values because it's not being returned via syscall return
 * mechanisms.
 */
static void cn_proc_ack(struct ve_struct *ve, int err, int rcvd_seq, int rcvd_ack)
{
	struct cn_msg *msg;
	struct proc_event *ev;
	__u8 buffer[CN_PROC_MSG_SIZE] __aligned(8);

	if (proc_event_num_listeners(ve) < 1)
		return;

	msg = buffer_to_cn_msg(buffer);
	ev = (struct proc_event *)msg->data;
	memset(&ev->event_data, 0, sizeof(ev->event_data));
	msg->seq = rcvd_seq;
	ev->timestamp_ns = ktime_get_ns();
	ev->cpu = -1;
	ev->what = PROC_EVENT_NONE;
	ev->event_data.ack.err = err;
	memcpy(&msg->id, &cn_proc_event_id, sizeof(msg->id));
	msg->ack = rcvd_ack + 1;
	msg->len = sizeof(*ev);
	msg->flags = 0; /* not used */
	send_msg_ve(ve, msg);
}

/**
 * cn_proc_mcast_ctl
 * @data: message sent from userspace via the connector
 */
static void cn_proc_mcast_ctl(struct cn_msg *msg,
			      struct netlink_skb_parms *nsp)
{
	enum proc_cn_mcast_op *mc_op = NULL;
	struct ve_struct *ve = get_exec_env();
	struct nsproxy *ve_ns;
	int err = 0;

	if (msg->len != sizeof(*mc_op))
		return;

	/* 
	 * Events are reported with respect to the initial pid
	 * and user namespaces so ignore requestors from
	 * other namespaces.
	 */
	rcu_read_lock();
	ve_ns = rcu_dereference(ve->ve_ns);
	if (!current_user_ns_initial() || !ve_ns ||
	    (task_active_pid_ns(current) != ve_ns->pid_ns_for_children)) {
		rcu_read_unlock();
		return;
	}
	rcu_read_unlock();

	/* Can only change if privileged. */
	if (!__netlink_ns_capable(nsp, ve_init_user_ns(), CAP_NET_ADMIN)) {
		err = EPERM;
		goto out;
	}

	mc_op = (enum proc_cn_mcast_op *)msg->data;
	switch (*mc_op) {
	case PROC_CN_MCAST_LISTEN:
		atomic_inc(&ve->cn->proc_event_num_listeners);
		break;
	case PROC_CN_MCAST_IGNORE:
		atomic_dec(&ve->cn->proc_event_num_listeners);
		break;
	default:
		err = EINVAL;
		break;
	}

out:
	cn_proc_ack(ve, err, msg->seq, msg->ack);
}

int cn_proc_init_ve(struct ve_struct *ve)
{
	int err, cpu;
	struct local_event *le_ptr;

	ve->cn->local_event = alloc_percpu(struct local_event);
	if (!ve->cn->local_event)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		le_ptr = per_cpu_ptr(ve->cn->local_event, cpu);
		local_lock_init(&le_ptr->lock);
	}

	err = cn_add_callback_ve(ve, &cn_proc_event_id,
				  "cn_proc",
				  &cn_proc_mcast_ctl);
	if (err) {
		pr_warn("VE#%d: cn_proc failed to register\n", ve->veid);
		free_percpu(ve->cn->local_event);
		return err;
	}
	atomic_set(&ve->cn->proc_event_num_listeners, 0);
	return 0;
}

void cn_proc_fini_ve(struct ve_struct *ve)
{
	cn_del_callback_ve(ve, &cn_proc_event_id);
	free_percpu(ve->cn->local_event);
}
