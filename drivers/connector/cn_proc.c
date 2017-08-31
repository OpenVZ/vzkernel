/*
 * cn_proc.c - process events connector
 *
 * Copyright (C) Matt Helsley, IBM Corp. 2005
 * Based on cn_fork.c by Guillaume Thouvenin <guillaume.thouvenin@bull.net>
 * Original copyright notice follows:
 * Copyright (C) 2005 BULL SA.
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ktime.h>
#include <linux/init.h>
#include <linux/connector.h>
#include <linux/gfp.h>
#include <linux/ptrace.h>
#include <linux/atomic.h>
#include <linux/pid_namespace.h>

#include <linux/cn_proc.h>

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

static inline void get_seq(struct ve_struct *ve, __u32 *ts, int *cpu)
{
	preempt_disable();
	*ts = __this_cpu_inc_return(*ve->cn->proc_event_counts) - 1;
	*cpu = smp_processor_id();
	preempt_enable();
}

static struct cn_msg *cn_msg_fill(__u8 *buffer, struct ve_struct *ve,
				  struct task_struct *task,
				  int what, int cookie,
				  bool (*fill_event)(struct proc_event *ev,
						     struct task_struct *task,
						     int cookie))
{
	struct cn_msg *msg;
	struct proc_event *ev;
	struct timespec ts;

	msg = buffer_to_cn_msg(buffer);
	ev = (struct proc_event *)msg->data;

	get_seq(ve, &msg->seq, &ev->cpu);
	memcpy(&msg->id, &cn_proc_event_id, sizeof(msg->id));
	msg->ack = 0; /* not used */
	msg->len = sizeof(*ev);
	msg->flags = 0; /* not used */

	memset(&ev->event_data, 0, sizeof(ev->event_data));
	ktime_get_ts(&ts); /* get high res monotonic timestamp */
	ev->timestamp_ns = timespec_to_ns(&ts);
	ev->what = what;

	return fill_event(ev, task, cookie) ? msg : NULL;
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
	cn_netlink_send(msg, CN_IDX_PROC, GFP_KERNEL);
}

static bool fill_fork_event(struct proc_event *ev, struct task_struct *task,
			    int unused)
{
	struct task_struct *parent;

	rcu_read_lock();
	parent = rcu_dereference(task->real_parent);
	ev->event_data.fork.parent_pid = task_pid_nr_ns(parent, &init_pid_ns);
	ev->event_data.fork.parent_tgid = task_tgid_nr_ns(parent, &init_pid_ns);
	rcu_read_unlock();
	ev->event_data.fork.child_pid = task_pid_nr_ns(task, &init_pid_ns);
	ev->event_data.fork.child_tgid = task_tgid_nr_ns(task, &init_pid_ns);
	return true;
}

void proc_fork_connector(struct task_struct *task)
{
	proc_event_connector(task, PROC_EVENT_FORK, 0, fill_fork_event);
}

static bool fill_exec_event(struct proc_event *ev, struct task_struct *task,
			    int unused)
{
	ev->event_data.exec.process_pid = task_pid_nr_ns(task, &init_pid_ns);
	ev->event_data.exec.process_tgid = task_tgid_nr_ns(task, &init_pid_ns);
	return true;
}

void proc_exec_connector(struct task_struct *task)
{
	proc_event_connector(task, PROC_EVENT_EXEC, 0, fill_exec_event);
}

static bool fill_id_event(struct proc_event *ev, struct task_struct *task,
			  int which_id)
{
	const struct cred *cred;

	ev->event_data.id.process_pid = task_pid_nr_ns(task, &init_pid_ns);
	ev->event_data.id.process_tgid = task_tgid_nr_ns(task, &init_pid_ns);
	rcu_read_lock();
	cred = __task_cred(task);
	if (which_id == PROC_EVENT_UID) {
		ev->event_data.id.r.ruid = from_kuid_munged(&init_user_ns, cred->uid);
		ev->event_data.id.e.euid = from_kuid_munged(&init_user_ns, cred->euid);
	} else if (which_id == PROC_EVENT_GID) {
		ev->event_data.id.r.rgid = from_kgid_munged(&init_user_ns, cred->gid);
		ev->event_data.id.e.egid = from_kgid_munged(&init_user_ns, cred->egid);
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

static bool fill_sid_event(struct proc_event *ev, struct task_struct *task,
			   int unused)
{
	ev->event_data.sid.process_pid = task_pid_nr_ns(task, &init_pid_ns);
	ev->event_data.sid.process_tgid = task_tgid_nr_ns(task, &init_pid_ns);
	return true;
}

void proc_sid_connector(struct task_struct *task)
{
	proc_event_connector(task, PROC_EVENT_SID, 0, fill_sid_event);
}

static bool fill_ptrace_event(struct proc_event *ev, struct task_struct *task,
			   int ptrace_id)
{
	ev->event_data.ptrace.process_pid  = task_pid_nr_ns(task, &init_pid_ns);
	ev->event_data.ptrace.process_tgid = task_tgid_nr_ns(task, &init_pid_ns);
	if (ptrace_id == PTRACE_ATTACH) {
		ev->event_data.ptrace.tracer_pid  = task_pid_nr_ns(current, &init_pid_ns);
		ev->event_data.ptrace.tracer_tgid = task_tgid_nr_ns(current, &init_pid_ns);
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

static bool fill_comm_event(struct proc_event *ev, struct task_struct *task,
			    int unused)
{
	ev->event_data.comm.process_pid  = task_pid_nr_ns(task, &init_pid_ns);
	ev->event_data.comm.process_tgid = task_tgid_nr_ns(task, &init_pid_ns);
	get_task_comm(ev->event_data.comm.comm, task);
	return true;
}

void proc_comm_connector(struct task_struct *task)
{
	proc_event_connector(task, PROC_EVENT_COMM, 0, fill_comm_event);
}

static bool fill_coredump_event(struct proc_event *ev, struct task_struct *task,
				int unused)
{
	ev->event_data.coredump.process_pid = task_pid_nr_ns(task, &init_pid_ns);
	ev->event_data.coredump.process_tgid = task_tgid_nr_ns(task, &init_pid_ns);
	return true;
}

void proc_coredump_connector(struct task_struct *task)
{
	proc_event_connector(task, PROC_EVENT_COREDUMP, 0, fill_coredump_event);
}

static bool fill_exit_event(struct proc_event *ev, struct task_struct *task,
			    int unused)
{
	ev->event_data.exit.process_pid = task_pid_nr_ns(task, &init_pid_ns);
	ev->event_data.exit.process_tgid = task_tgid_nr_ns(task, &init_pid_ns);
	ev->event_data.exit.exit_code = task->exit_code;
	ev->event_data.exit.exit_signal = task->exit_signal;
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
	struct timespec ts;

	if (proc_event_num_listeners(ve) < 1)
		return;

	msg = buffer_to_cn_msg(buffer);
	ev = (struct proc_event *)msg->data;
	memset(&ev->event_data, 0, sizeof(ev->event_data));
	msg->seq = rcvd_seq;
	ktime_get_ts(&ts); /* get high res monotonic timestamp */
	ev->timestamp_ns = timespec_to_ns(&ts);
	ev->cpu = -1;
	ev->what = PROC_EVENT_NONE;
	ev->event_data.ack.err = err;
	memcpy(&msg->id, &cn_proc_event_id, sizeof(msg->id));
	msg->ack = rcvd_ack + 1;
	msg->len = sizeof(*ev);
	msg->flags = 0; /* not used */
	cn_netlink_send(msg, CN_IDX_PROC, GFP_KERNEL);
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
	int err = 0;

	if (msg->len != sizeof(*mc_op))
		return;

	/* 
	 * Events are reported with respect to the initial pid
	 * and user namespaces so ignore requestors from
	 * other namespaces.
	 */
	if ((current_user_ns() != &init_user_ns) ||
	    (task_active_pid_ns(current) != &init_pid_ns))
		return;

	/* Can only change if privileged. */
	if (!__netlink_ns_capable(nsp, &init_user_ns, CAP_NET_ADMIN)) {
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
	int err;

	ve->cn->proc_event_counts = alloc_percpu(u32);
	if (!ve->cn->proc_event_counts)
		return -ENOMEM;

	err = cn_add_callback_ve(ve, &cn_proc_event_id,
				  "cn_proc",
				  &cn_proc_mcast_ctl);
	if (err) {
		pr_warn("VE#%d: cn_proc failed to register\n", ve->veid);
		free_percpu(ve->cn->proc_event_counts);
		return err;
	}
	atomic_set(&ve->cn->proc_event_num_listeners, 0);
	return 0;
}

void cn_proc_fini_ve(struct ve_struct *ve)
{
	cn_del_callback_ve(ve, &cn_proc_event_id);
	free_percpu(ve->cn->proc_event_counts);
}
