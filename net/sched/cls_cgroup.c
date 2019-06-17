/*
 * net/sched/cls_cgroup.c	Control Group Classifier
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Thomas Graf <tgraf@suug.ch>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/cgroup.h>
#include <linux/rcupdate.h>
#include <linux/fdtable.h>
#include <net/rtnetlink.h>
#include <net/pkt_cls.h>
#include <net/sock.h>
#include <net/cls_cgroup.h>

static inline struct cgroup_cls_state *cgrp_cls_state(struct cgroup *cgrp)
{
	return container_of(cgroup_subsys_state(cgrp, net_cls_subsys_id),
			    struct cgroup_cls_state, css);
}

static inline struct cgroup_cls_state *task_cls_state(struct task_struct *p)
{
	return container_of(task_subsys_state(p, net_cls_subsys_id),
			    struct cgroup_cls_state, css);
}

static struct cgroup_subsys_state *cgrp_css_alloc(struct cgroup *cgrp)
{
	struct cgroup_cls_state *cs;

	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs)
		return ERR_PTR(-ENOMEM);
	return &cs->css;
}

static int cgrp_css_online(struct cgroup *cgrp)
{
	if (cgrp->parent)
		cgrp_cls_state(cgrp)->classid =
			cgrp_cls_state(cgrp->parent)->classid;
	return 0;
}

static void cgrp_css_free(struct cgroup *cgrp)
{
	kfree(cgrp_cls_state(cgrp));
}

static int update_classid(const void *v, struct file *file, unsigned n)
{
	int err;
	struct socket *sock = sock_from_file(file, &err);
	if (sock)
		sock->sk->sk_classid = (u32)(unsigned long)v;
	return 0;
}

static void cgrp_attach(struct cgroup *cgrp, struct cgroup_taskset *tset)
{
	struct task_struct *p;
	void *v;

	cgroup_taskset_for_each(p, cgrp, tset) {
		task_lock(p);
		v = (void *)(unsigned long)task_cls_classid(p);
		iterate_fd(p->files, 0, update_classid, v);
		task_unlock(p);
	}
}

static u64 read_classid(struct cgroup *cgrp, struct cftype *cft)
{
	return cgrp_cls_state(cgrp)->classid;
}

static int write_classid(struct cgroup *cgrp, struct cftype *cft, u64 value)
{
	cgrp_cls_state(cgrp)->classid = (u32) value;
	return 0;
}

static struct cftype ss_files[] = {
	{
		.name = "classid",
		.read_u64 = read_classid,
		.write_u64 = write_classid,
	},
	{ }	/* terminate */
};

struct cgroup_subsys net_cls_subsys = {
	.name		= "net_cls",
	.css_alloc	= cgrp_css_alloc,
	.css_online	= cgrp_css_online,
	.css_free	= cgrp_css_free,
	.attach		= cgrp_attach,
	.subsys_id	= net_cls_subsys_id,
	.base_cftypes	= ss_files,
	.module		= THIS_MODULE,
};

struct cls_cgroup_head {
	u32			handle;
	struct tcf_exts		exts;
	struct tcf_ematch_tree	ematches;
	struct tcf_proto	*tp;
	struct rcu_work		rwork;
};

static int cls_cgroup_classify(struct sk_buff *skb, const struct tcf_proto *tp,
			       struct tcf_result *res)
{
	struct cls_cgroup_head *head = rcu_dereference_bh(tp->root);
	u32 classid;

	classid = task_cls_state(current)->classid;

	/*
	 * Due to the nature of the classifier it is required to ignore all
	 * packets originating from softirq context as accessing `current'
	 * would lead to false results.
	 *
	 * This test assumes that all callers of dev_queue_xmit() explicitely
	 * disable bh. Knowing this, it is possible to detect softirq based
	 * calls by looking at the number of nested bh disable calls because
	 * softirqs always disables bh.
	 */
	if (in_serving_softirq()) {
		/* If there is an sk_classid we'll use that. */
		if (!skb->sk)
			return -1;
		classid = skb->sk->sk_classid;
	}

	if (!classid)
		return -1;

	if (!tcf_em_tree_match(skb, &head->ematches, NULL))
		return -1;

	res->classid = classid;
	res->class = 0;
	return tcf_exts_exec(skb, &head->exts, res);
}

static void *cls_cgroup_get(struct tcf_proto *tp, u32 handle)
{
	return NULL;
}

static int cls_cgroup_init(struct tcf_proto *tp)
{
	return 0;
}

static const struct nla_policy cgroup_policy[TCA_CGROUP_MAX + 1] = {
	[TCA_CGROUP_EMATCHES]	= { .type = NLA_NESTED },
};

static void __cls_cgroup_destroy(struct cls_cgroup_head *head)
{
	tcf_exts_destroy(&head->exts);
	tcf_em_tree_destroy(&head->ematches);
	tcf_exts_put_net(&head->exts);
	kfree(head);
}

static void cls_cgroup_destroy_work(struct work_struct *work)
{
	struct cls_cgroup_head *head = container_of(to_rcu_work(work),
						    struct cls_cgroup_head,
						    rwork);
	rtnl_lock();
	__cls_cgroup_destroy(head);
	rtnl_unlock();
}

static int cls_cgroup_change(struct net *net, struct sk_buff *in_skb,
			     struct tcf_proto *tp, unsigned long base,
			     u32 handle, struct nlattr **tca,
			     void **arg, bool ovr)
{
	struct nlattr *tb[TCA_CGROUP_MAX + 1];
	struct cls_cgroup_head *head = rtnl_dereference(tp->root);
	struct cls_cgroup_head *new;
	int err;

	if (!tca[TCA_OPTIONS])
		return -EINVAL;

	if (!head && !handle)
		return -EINVAL;

	if (head && handle != head->handle)
		return -ENOENT;

	new = kzalloc(sizeof(*head), GFP_KERNEL);
	if (!new)
		return -ENOBUFS;

	err = tcf_exts_init(&new->exts, TCA_CGROUP_ACT, TCA_CGROUP_POLICE);
	if (err < 0)
		goto errout;
	new->handle = handle;
	new->tp = tp;
	err = nla_parse_nested(tb, TCA_CGROUP_MAX, tca[TCA_OPTIONS],
			       cgroup_policy);
	if (err < 0)
		goto errout;

	err = tcf_exts_validate(net, tp, tb, tca[TCA_RATE], &new->exts, ovr);
	if (err < 0)
		goto errout;

	err = tcf_em_tree_validate(tp, tb[TCA_CGROUP_EMATCHES], &new->ematches);
	if (err < 0)
		goto errout;

	rcu_assign_pointer(tp->root, new);
	if (head) {
		tcf_exts_get_net(&head->exts);
		tcf_queue_work(&head->rwork, cls_cgroup_destroy_work);
	}
	return 0;
errout:
	tcf_exts_destroy(&new->exts);
	kfree(new);
	return err;
}

static void cls_cgroup_destroy(struct tcf_proto *tp)
{
	struct cls_cgroup_head *head = rtnl_dereference(tp->root);

	/* Head can still be NULL due to cls_cgroup_init(). */
	if (head) {
		if (tcf_exts_get_net(&head->exts))
			tcf_queue_work(&head->rwork, cls_cgroup_destroy_work);
		else
			__cls_cgroup_destroy(head);
	}
}

static int cls_cgroup_delete(struct tcf_proto *tp, void *arg, bool *last)
{
	return -EOPNOTSUPP;
}

static void cls_cgroup_walk(struct tcf_proto *tp, struct tcf_walker *arg)
{
	struct cls_cgroup_head *head = rtnl_dereference(tp->root);

	if (arg->count < arg->skip)
		goto skip;

	if (arg->fn(tp, head, arg) < 0) {
		arg->stop = 1;
		return;
	}
skip:
	arg->count++;
}

static int cls_cgroup_dump(struct net *net, struct tcf_proto *tp, void *fh,
			   struct sk_buff *skb, struct tcmsg *t)
{
	struct cls_cgroup_head *head = rtnl_dereference(tp->root);
	struct nlattr *nest;

	t->tcm_handle = head->handle;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;

	if (tcf_exts_dump(skb, &head->exts) < 0 ||
	    tcf_em_tree_dump(skb, &head->ematches, TCA_CGROUP_EMATCHES) < 0)
		goto nla_put_failure;

	nla_nest_end(skb, nest);

	if (tcf_exts_dump_stats(skb, &head->exts) < 0)
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static struct tcf_proto_ops cls_cgroup_ops __read_mostly = {
	.kind		=	"cgroup",
	.init		=	cls_cgroup_init,
	.change		=	cls_cgroup_change,
	.classify	=	cls_cgroup_classify,
	.destroy	=	cls_cgroup_destroy,
	.get		=	cls_cgroup_get,
	.delete		=	cls_cgroup_delete,
	.walk		=	cls_cgroup_walk,
	.dump		=	cls_cgroup_dump,
	.owner		=	THIS_MODULE,
};

static int __init init_cgroup_cls(void)
{
	int ret;

	ret = cgroup_load_subsys(&net_cls_subsys);
	if (ret)
		goto out;

	ret = register_tcf_proto_ops(&cls_cgroup_ops);
	if (ret)
		cgroup_unload_subsys(&net_cls_subsys);

out:
	return ret;
}

static void __exit exit_cgroup_cls(void)
{
	unregister_tcf_proto_ops(&cls_cgroup_ops);

	cgroup_unload_subsys(&net_cls_subsys);
}

module_init(init_cgroup_cls);
module_exit(exit_cgroup_cls);
MODULE_LICENSE("GPL");
