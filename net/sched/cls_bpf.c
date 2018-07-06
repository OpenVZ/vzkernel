/*
 * Berkeley Packet Filter based traffic classifier
 *
 * Might be used to classify traffic through flexible, user-defined and
 * possibly JIT-ed BPF filters for traffic control as an alternative to
 * ematches.
 *
 * (C) 2013 Daniel Borkmann <dborkman@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/filter.h>
#include <net/rtnetlink.h>
#include <net/pkt_cls.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Borkmann <dborkman@redhat.com>");
MODULE_DESCRIPTION("TC BPF based classifier");

struct cls_bpf_head {
	struct list_head plist;
	u32 hgen;
	struct rcu_head rcu;
};

struct cls_bpf_prog {
	struct sk_filter *filter;
	struct sock_filter *bpf_ops;
	struct tcf_exts exts;
	struct tcf_result res;
	struct list_head link;
	u32 handle;
	u16 bpf_len;
	struct tcf_proto *tp;
	union {
		struct work_struct work;
		struct rcu_head rcu;
	};
};

static const struct nla_policy bpf_policy[TCA_BPF_MAX + 1] = {
	[TCA_BPF_CLASSID]	= { .type = NLA_U32 },
	[TCA_BPF_OPS_LEN]	= { .type = NLA_U16 },
	[TCA_BPF_OPS]		= { .type = NLA_BINARY,
				    .len = sizeof(struct sock_filter) * BPF_MAXINSNS },
};

static int cls_bpf_classify(struct sk_buff *skb, const struct tcf_proto *tp,
			    struct tcf_result *res)
{
	struct cls_bpf_head *head = rcu_dereference_bh(tp->root);
	struct cls_bpf_prog *prog;
	int ret;

	list_for_each_entry_rcu(prog, &head->plist, link) {
		int filter_res = SK_RUN_FILTER(prog->filter, skb);

		if (filter_res == 0)
			continue;

		*res = prog->res;
		if (filter_res != -1)
			res->classid = filter_res;

		ret = tcf_exts_exec(skb, &prog->exts, res);
		if (ret < 0)
			continue;

		return ret;
	}

	return -1;
}


static void cls_bpf_offload(struct tcf_proto *tp, struct cls_bpf_prog *prog,
			    struct cls_bpf_prog *oldprog)
{
	return;
}

static void cls_bpf_stop_offload(struct tcf_proto *tp,
				 struct cls_bpf_prog *prog)
{
	return;
}

static int cls_bpf_init(struct tcf_proto *tp)
{
	struct cls_bpf_head *head;

	head = kzalloc(sizeof(*head), GFP_KERNEL);
	if (head == NULL)
		return -ENOBUFS;

	INIT_LIST_HEAD_RCU(&head->plist);
	rcu_assign_pointer(tp->root, head);

	return 0;
}

static void cls_bpf_delete_prog(struct tcf_proto *tp, struct cls_bpf_prog *prog)
{
	tcf_exts_destroy(&prog->exts);
	tcf_exts_put_net(&prog->exts);

	sk_unattached_filter_destroy(prog->filter);

	kfree(prog->bpf_ops);
	kfree(prog);
}

static void cls_bpf_delete_prog_work(struct work_struct *work)
{
	struct cls_bpf_prog *prog = container_of(work, struct cls_bpf_prog, work);

	rtnl_lock();
	cls_bpf_delete_prog(prog->tp, prog);
	rtnl_unlock();
}

static void __cls_bpf_delete_prog(struct rcu_head *rcu)
{
	struct cls_bpf_prog *prog = container_of(rcu, struct cls_bpf_prog, rcu);

	INIT_WORK(&prog->work, cls_bpf_delete_prog_work);
	tcf_queue_work(&prog->work);
}

static int cls_bpf_delete(struct tcf_proto *tp, void *arg, bool *last)
{
	struct cls_bpf_head *head = rtnl_dereference(tp->root);
	struct cls_bpf_prog *prog = (struct cls_bpf_prog *) arg;

	cls_bpf_stop_offload(tp, prog);
	list_del_rcu(&prog->link);
	tcf_unbind_filter(tp, &prog->res);
	if (tcf_exts_get_net(&prog->exts))
		call_rcu(&prog->rcu, __cls_bpf_delete_prog);
	else
		cls_bpf_delete_prog(prog->tp, prog);
	*last = list_empty(&head->plist);
	return 0;
}

static void cls_bpf_destroy(struct tcf_proto *tp)
{
	struct cls_bpf_head *head = rtnl_dereference(tp->root);
	struct cls_bpf_prog *prog, *tmp;

	list_for_each_entry_safe(prog, tmp, &head->plist, link) {
		cls_bpf_stop_offload(tp, prog);
		list_del_rcu(&prog->link);
		tcf_unbind_filter(tp, &prog->res);
		tcf_exts_get_net(&prog->exts);
		call_rcu(&prog->rcu, __cls_bpf_delete_prog);
	}

	kfree_rcu(head, rcu);
}

static void *cls_bpf_get(struct tcf_proto *tp, u32 handle)
{
	struct cls_bpf_head *head = rtnl_dereference(tp->root);
	struct cls_bpf_prog *prog;

	list_for_each_entry(prog, &head->plist, link) {
		if (prog->handle == handle)
			return prog;
	}

	return NULL;
}

static int cls_bpf_set_parms(struct net *net, struct tcf_proto *tp,
			     struct cls_bpf_prog *prog, unsigned long base,
			     struct nlattr **tb, struct nlattr *est, bool ovr)
{
	struct sock_filter *bpf_ops;
	struct sock_fprog tmp;
	struct sk_filter *fp;
	u16 bpf_size, bpf_len;
	u32 classid;
	int ret;

	if (!tb[TCA_BPF_OPS_LEN] || !tb[TCA_BPF_OPS] || !tb[TCA_BPF_CLASSID])
		return -EINVAL;

	ret = tcf_exts_validate(net, tp, tb, est, &prog->exts, ovr);
	if (ret < 0)
		return ret;

	classid = nla_get_u32(tb[TCA_BPF_CLASSID]);
	bpf_len = nla_get_u16(tb[TCA_BPF_OPS_LEN]);
	if (bpf_len > BPF_MAXINSNS || bpf_len == 0)
		return -EINVAL;

	bpf_size = bpf_len * sizeof(*bpf_ops);
	if (bpf_size != nla_len(tb[TCA_BPF_OPS]))
		return -EINVAL;

	bpf_ops = kzalloc(bpf_size, GFP_KERNEL);
	if (bpf_ops == NULL)
		return -ENOMEM;

	memcpy(bpf_ops, nla_data(tb[TCA_BPF_OPS]), bpf_size);

	tmp.len = bpf_len;
	tmp.filter = (struct sock_filter __user *) bpf_ops;

	ret = sk_unattached_filter_create(&fp, &tmp);
	if (ret)
		goto errout_free;

	prog->bpf_len = bpf_len;
	prog->bpf_ops = bpf_ops;
	prog->filter = fp;
	prog->res.classid = classid;

	tcf_bind_filter(tp, &prog->res, base);

	return 0;
errout_free:
	kfree(bpf_ops);
	return ret;
}

static u32 cls_bpf_grab_new_handle(struct tcf_proto *tp,
				   struct cls_bpf_head *head)
{
	unsigned int i = 0x80000000;
	u32 handle;

	do {
		if (++head->hgen == 0x7FFFFFFF)
			head->hgen = 1;
	} while (--i > 0 && cls_bpf_get(tp, head->hgen));

	if (unlikely(i == 0)) {
		pr_err("Insufficient number of handles\n");
		handle = 0;
	} else {
		handle = head->hgen;
	}

	return handle;
}

static int cls_bpf_change(struct net *net, struct sk_buff *in_skb,
			  struct tcf_proto *tp, unsigned long base,
			  u32 handle, struct nlattr **tca,
			  void **arg, bool ovr)
{
	struct cls_bpf_head *head = rtnl_dereference(tp->root);
	struct cls_bpf_prog *oldprog = *arg;
	struct nlattr *tb[TCA_BPF_MAX + 1];
	struct cls_bpf_prog *prog;
	int ret;

	if (tca[TCA_OPTIONS] == NULL)
		return -EINVAL;

	ret = nla_parse_nested(tb, TCA_BPF_MAX, tca[TCA_OPTIONS], bpf_policy);
	if (ret < 0)
		return ret;

	prog = kzalloc(sizeof(*prog), GFP_KERNEL);
	if (!prog)
		return -ENOBUFS;

	ret = tcf_exts_init(&prog->exts, TCA_BPF_ACT, TCA_BPF_POLICE);
	if (ret < 0)
		goto errout;

	if (oldprog) {
		if (handle && oldprog->handle != handle) {
			ret = -EINVAL;
			goto errout;
		}
	}

	if (handle == 0)
		prog->handle = cls_bpf_grab_new_handle(tp, head);
	else
		prog->handle = handle;
	if (prog->handle == 0) {
		ret = -EINVAL;
		goto errout;
	}

	ret = cls_bpf_set_parms(net, tp, prog, base, tb, tca[TCA_RATE], ovr);
	if (ret < 0)
		goto errout;

	cls_bpf_offload(tp, prog, oldprog);

	if (oldprog) {
		list_replace_rcu(&oldprog->link, &prog->link);
		tcf_unbind_filter(tp, &oldprog->res);
		call_rcu(&oldprog->rcu, __cls_bpf_delete_prog);
	} else {
		list_add_rcu(&prog->link, &head->plist);
	}

	*arg = prog;
	return 0;

errout:
	tcf_exts_destroy(&prog->exts);
	kfree(prog);
	return ret;
}

static int cls_bpf_dump(struct net *net, struct tcf_proto *tp, void *fh,
			struct sk_buff *skb, struct tcmsg *tm)
{
	struct cls_bpf_prog *prog = (struct cls_bpf_prog *) fh;
	struct nlattr *nest, *nla;

	if (prog == NULL)
		return skb->len;

	tm->tcm_handle = prog->handle;

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_BPF_CLASSID, prog->res.classid))
		goto nla_put_failure;
	if (nla_put_u16(skb, TCA_BPF_OPS_LEN, prog->bpf_len))
		goto nla_put_failure;

	nla = nla_reserve(skb, TCA_BPF_OPS, prog->bpf_len *
			  sizeof(struct sock_filter));
	if (nla == NULL)
		goto nla_put_failure;

	memcpy(nla_data(nla), prog->bpf_ops, nla_len(nla));

	if (tcf_exts_dump(skb, &prog->exts) < 0)
		goto nla_put_failure;

	nla_nest_end(skb, nest);

	if (tcf_exts_dump_stats(skb, &prog->exts) < 0)
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static void cls_bpf_bind_class(void *fh, u32 classid, unsigned long cl)
{
	struct cls_bpf_prog *prog = fh;

	if (prog && prog->res.classid == classid)
		prog->res.class = cl;
}

static void cls_bpf_walk(struct tcf_proto *tp, struct tcf_walker *arg)
{
	struct cls_bpf_head *head = rtnl_dereference(tp->root);
	struct cls_bpf_prog *prog;

	list_for_each_entry(prog, &head->plist, link) {
		if (arg->count < arg->skip)
			goto skip;
		if (arg->fn(tp, prog, arg) < 0) {
			arg->stop = 1;
			break;
		}
skip:
		arg->count++;
	}
}

static struct tcf_proto_ops cls_bpf_ops __read_mostly = {
	.kind		=	"bpf",
	.owner		=	THIS_MODULE,
	.classify	=	cls_bpf_classify,
	.init		=	cls_bpf_init,
	.destroy	=	cls_bpf_destroy,
	.get		=	cls_bpf_get,
	.change		=	cls_bpf_change,
	.delete		=	cls_bpf_delete,
	.walk		=	cls_bpf_walk,
	.dump		=	cls_bpf_dump,
	.bind_class	=	cls_bpf_bind_class,
};

static int __init cls_bpf_init_mod(void)
{
	return register_tcf_proto_ops(&cls_bpf_ops);
}

static void __exit cls_bpf_exit_mod(void)
{
	unregister_tcf_proto_ops(&cls_bpf_ops);
}

module_init(cls_bpf_init_mod);
module_exit(cls_bpf_exit_mod);
