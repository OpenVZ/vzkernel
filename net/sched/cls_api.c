/*
 * net/sched/cls_api.c	Packet classifier API.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Changes:
 *
 * Eduardo J. Blanco <ejbs@netlabs.com.uy> :990222: kmod support
 *
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/idr_ext.h>
#include <linux/rhashtable.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

/* The list of all installed classifier types */
static LIST_HEAD(tcf_proto_base);

/* Protects list of registered TC modules. It is pure SMP lock. */
static DEFINE_RWLOCK(cls_mod_lock);

/* Find classifier type by string name */

static const struct tcf_proto_ops *tcf_proto_lookup_ops(const char *kind)
{
	const struct tcf_proto_ops *t, *res = NULL;

	if (kind) {
		read_lock(&cls_mod_lock);
		list_for_each_entry(t, &tcf_proto_base, head) {
			if (strcmp(kind, t->kind) == 0) {
				if (try_module_get(t->owner))
					res = t;
				break;
			}
		}
		read_unlock(&cls_mod_lock);
	}
	return res;
}

/* Register(unregister) new classifier type */

int register_tcf_proto_ops(struct tcf_proto_ops *ops)
{
	struct tcf_proto_ops *t;
	int rc = -EEXIST;

	write_lock(&cls_mod_lock);
	list_for_each_entry(t, &tcf_proto_base, head)
		if (!strcmp(ops->kind, t->kind))
			goto out;

	list_add_tail(&ops->head, &tcf_proto_base);
	rc = 0;
out:
	write_unlock(&cls_mod_lock);
	return rc;
}
EXPORT_SYMBOL(register_tcf_proto_ops);

static struct workqueue_struct *tc_filter_wq;

int unregister_tcf_proto_ops(struct tcf_proto_ops *ops)
{
	struct tcf_proto_ops *t;
	int rc = -ENOENT;

	/* Wait for outstanding call_rcu()s, if any, from a
	 * tcf_proto_ops's destroy() handler.
	 */
	rcu_barrier();
	flush_workqueue(tc_filter_wq);

	write_lock(&cls_mod_lock);
	list_for_each_entry(t, &tcf_proto_base, head) {
		if (t == ops) {
			list_del(&t->head);
			rc = 0;
			break;
		}
	}
	write_unlock(&cls_mod_lock);
	return rc;
}
EXPORT_SYMBOL(unregister_tcf_proto_ops);

bool tcf_queue_work(struct rcu_work *rwork, work_func_t func)
{
	INIT_RCU_WORK(rwork, func);
	return queue_rcu_work(tc_filter_wq, rwork);
}
EXPORT_SYMBOL(tcf_queue_work);

/* Select new prio value from the range, managed by kernel. */

static inline u32 tcf_auto_prio(struct tcf_proto *tp)
{
	u32 first = TC_H_MAKE(0xC0000000U, 0U);

	if (tp)
		first = tp->prio - 1;

	return TC_H_MAJ(first);
}

static struct tcf_proto *tcf_proto_create(const char *kind, u32 protocol,
					  u32 prio, struct tcf_chain *chain)
{
	struct tcf_proto *tp;
	int err;

	tp = kzalloc(sizeof(*tp), GFP_KERNEL);
	if (!tp)
		return ERR_PTR(-ENOBUFS);

	err = -ENOENT;
	tp->ops = tcf_proto_lookup_ops(kind);
	if (!tp->ops) {
#ifdef CONFIG_MODULES
		rtnl_unlock();
		request_module("cls_%s", kind);
		rtnl_lock();
		tp->ops = tcf_proto_lookup_ops(kind);
		/* We dropped the RTNL semaphore in order to perform
		 * the module load. So, even if we succeeded in loading
		 * the module we have to replay the request. We indicate
		 * this using -EAGAIN.
		 */
		if (tp->ops) {
			module_put(tp->ops->owner);
			err = -EAGAIN;
		} else {
			err = -ENOENT;
		}
#endif
		goto errout;
	}
	tp->classify = tp->ops->classify;
	tp->protocol = protocol;
	tp->prio = prio;
	tp->chain = chain;

	err = tp->ops->init(tp);
	if (err) {
		module_put(tp->ops->owner);
		goto errout;
	}
	return tp;

errout:
	kfree(tp);
	return ERR_PTR(err);
}

static void tcf_proto_destroy(struct tcf_proto *tp)
{
	tp->ops->destroy(tp);
	module_put(tp->ops->owner);
	kfree_rcu(tp, rcu);
}

struct tcf_filter_chain_list_item {
	struct list_head list;
	tcf_chain_head_change_t *chain_head_change;
	void *chain_head_change_priv;
};

static struct tcf_chain *tcf_chain_create(struct tcf_block *block,
					  u32 chain_index)
{
	struct tcf_chain *chain;

	chain = kzalloc(sizeof(*chain), GFP_KERNEL);
	if (!chain)
		return NULL;
	INIT_LIST_HEAD(&chain->filter_chain_list);
	list_add_tail(&chain->list, &block->chain_list);
	chain->block = block;
	chain->index = chain_index;
	chain->refcnt = 1;
	return chain;
}

static void tcf_chain_head_change_item(struct tcf_filter_chain_list_item *item,
				       struct tcf_proto *tp_head)
{
	if (item->chain_head_change)
		item->chain_head_change(tp_head, item->chain_head_change_priv);
}
static void tcf_chain_head_change(struct tcf_chain *chain,
				  struct tcf_proto *tp_head)
{
	struct tcf_filter_chain_list_item *item;

	list_for_each_entry(item, &chain->filter_chain_list, list)
		tcf_chain_head_change_item(item, tp_head);
}

static void tcf_chain_flush(struct tcf_chain *chain)
{
	struct tcf_proto *tp = rtnl_dereference(chain->filter_chain);

	tcf_chain_head_change(chain, NULL);
	while (tp) {
		RCU_INIT_POINTER(chain->filter_chain, tp->next);
		tcf_proto_destroy(tp);
		tp = rtnl_dereference(chain->filter_chain);
		tcf_chain_put(chain);
	}
}

static void tcf_chain_destroy(struct tcf_chain *chain)
{
	struct tcf_block *block = chain->block;

	list_del(&chain->list);
	kfree(chain);
	if (list_empty(&block->chain_list))
		kfree(block);
}

static void tcf_chain_hold(struct tcf_chain *chain)
{
	++chain->refcnt;
}

struct tcf_chain *tcf_chain_get(struct tcf_block *block, u32 chain_index,
				bool create)
{
	struct tcf_chain *chain;

	list_for_each_entry(chain, &block->chain_list, list) {
		if (chain->index == chain_index) {
			tcf_chain_hold(chain);
			return chain;
		}
	}

	return create ? tcf_chain_create(block, chain_index) : NULL;
}
EXPORT_SYMBOL(tcf_chain_get);

void tcf_chain_put(struct tcf_chain *chain)
{
	if (--chain->refcnt == 0)
		tcf_chain_destroy(chain);
}
EXPORT_SYMBOL(tcf_chain_put);

static struct tcf_block *tc_dev_ingress_block(struct net_device *dev)
{
	const struct Qdisc_class_ops *cops;
	struct Qdisc *qdisc;

	if (!dev_ingress_queue(dev))
		return NULL;

	qdisc = dev_ingress_queue(dev)->qdisc_sleeping;
	if (!qdisc)
		return NULL;

	cops = qdisc->ops->cl_ops;
	if (!cops)
		return NULL;

	if (!cops->tcf_block)
		return NULL;

	return cops->tcf_block(qdisc, TC_H_MIN_INGRESS);
}

static struct rhashtable indr_setup_block_ht;

struct tc_indr_block_dev {
	struct rhash_head ht_node;
	struct net_device *dev;
	unsigned int refcnt;
	struct list_head cb_list;
	struct tcf_block *block;
};

struct tc_indr_block_cb {
	struct list_head list;
	void *cb_priv;
	tc_indr_block_bind_cb_t *cb;
	void *cb_ident;
};

static const struct rhashtable_params tc_indr_setup_block_ht_params = {
	.key_offset	= offsetof(struct tc_indr_block_dev, dev),
	.head_offset	= offsetof(struct tc_indr_block_dev, ht_node),
	.key_len	= sizeof(struct net_device *),
};

static struct tc_indr_block_dev *
tc_indr_block_dev_lookup(struct net_device *dev)
{
	return rhashtable_lookup_fast(&indr_setup_block_ht, &dev,
				      tc_indr_setup_block_ht_params);
}

static struct tc_indr_block_dev *tc_indr_block_dev_get(struct net_device *dev)
{
	struct tc_indr_block_dev *indr_dev;

	indr_dev = tc_indr_block_dev_lookup(dev);
	if (indr_dev)
		goto inc_ref;

	indr_dev = kzalloc(sizeof(*indr_dev), GFP_KERNEL);
	if (!indr_dev)
		return NULL;

	INIT_LIST_HEAD(&indr_dev->cb_list);
	indr_dev->dev = dev;
	indr_dev->block = tc_dev_ingress_block(dev);
	if (rhashtable_insert_fast(&indr_setup_block_ht, &indr_dev->ht_node,
				   tc_indr_setup_block_ht_params)) {
		kfree(indr_dev);
		return NULL;
	}

inc_ref:
	indr_dev->refcnt++;
	return indr_dev;
}

static void tc_indr_block_dev_put(struct tc_indr_block_dev *indr_dev)
{
	if (--indr_dev->refcnt)
		return;

	rhashtable_remove_fast(&indr_setup_block_ht, &indr_dev->ht_node,
			       tc_indr_setup_block_ht_params);
	kfree(indr_dev);
}

static struct tc_indr_block_cb *
tc_indr_block_cb_lookup(struct tc_indr_block_dev *indr_dev,
			tc_indr_block_bind_cb_t *cb, void *cb_ident)
{
	struct tc_indr_block_cb *indr_block_cb;

	list_for_each_entry(indr_block_cb, &indr_dev->cb_list, list)
		if (indr_block_cb->cb == cb &&
		    indr_block_cb->cb_ident == cb_ident)
			return indr_block_cb;
	return NULL;
}

static struct tc_indr_block_cb *
tc_indr_block_cb_add(struct tc_indr_block_dev *indr_dev, void *cb_priv,
		     tc_indr_block_bind_cb_t *cb, void *cb_ident)
{
	struct tc_indr_block_cb *indr_block_cb;

	indr_block_cb = tc_indr_block_cb_lookup(indr_dev, cb, cb_ident);
	if (indr_block_cb)
		return ERR_PTR(-EEXIST);

	indr_block_cb = kzalloc(sizeof(*indr_block_cb), GFP_KERNEL);
	if (!indr_block_cb)
		return ERR_PTR(-ENOMEM);

	indr_block_cb->cb_priv = cb_priv;
	indr_block_cb->cb = cb;
	indr_block_cb->cb_ident = cb_ident;
	list_add(&indr_block_cb->list, &indr_dev->cb_list);

	return indr_block_cb;
}

static void tc_indr_block_cb_del(struct tc_indr_block_cb *indr_block_cb)
{
	list_del(&indr_block_cb->list);
	kfree(indr_block_cb);
}

static void tc_indr_block_ing_cmd(struct tc_indr_block_dev *indr_dev,
				  struct tc_indr_block_cb *indr_block_cb,
				  enum tc_block_command command)
{
	struct tc_block_offload bo = {
		.command	= command,
		.binder_type	= TCF_BLOCK_BINDER_TYPE_CLSACT_INGRESS,
		.block		= indr_dev->block,
	};

	if (!indr_dev->block)
		return;

	indr_block_cb->cb(indr_dev->dev, indr_block_cb->cb_priv, TC_SETUP_BLOCK,
			  &bo);
}

int __tc_indr_block_cb_register(struct net_device *dev, void *cb_priv,
				tc_indr_block_bind_cb_t *cb, void *cb_ident)
{
	struct tc_indr_block_cb *indr_block_cb;
	struct tc_indr_block_dev *indr_dev;
	int err;

	indr_dev = tc_indr_block_dev_get(dev);
	if (!indr_dev)
		return -ENOMEM;

	indr_block_cb = tc_indr_block_cb_add(indr_dev, cb_priv, cb, cb_ident);
	err = PTR_ERR_OR_ZERO(indr_block_cb);
	if (err)
		goto err_dev_put;

	tc_indr_block_ing_cmd(indr_dev, indr_block_cb, TC_BLOCK_BIND);
	return 0;

err_dev_put:
	tc_indr_block_dev_put(indr_dev);
	return err;
}
EXPORT_SYMBOL_GPL(__tc_indr_block_cb_register);

int tc_indr_block_cb_register(struct net_device *dev, void *cb_priv,
			      tc_indr_block_bind_cb_t *cb, void *cb_ident)
{
	int err;

	rtnl_lock();
	err = __tc_indr_block_cb_register(dev, cb_priv, cb, cb_ident);
	rtnl_unlock();

	return err;
}
EXPORT_SYMBOL_GPL(tc_indr_block_cb_register);

void __tc_indr_block_cb_unregister(struct net_device *dev,
				   tc_indr_block_bind_cb_t *cb, void *cb_ident)
{
	struct tc_indr_block_cb *indr_block_cb;
	struct tc_indr_block_dev *indr_dev;

	indr_dev = tc_indr_block_dev_lookup(dev);
	if (!indr_dev)
		return;

	indr_block_cb = tc_indr_block_cb_lookup(indr_dev, cb, cb_ident);
	if (!indr_block_cb)
		return;

	/* Send unbind message if required to free any block cbs. */
	tc_indr_block_ing_cmd(indr_dev, indr_block_cb, TC_BLOCK_UNBIND);
	tc_indr_block_cb_del(indr_block_cb);
	tc_indr_block_dev_put(indr_dev);
}
EXPORT_SYMBOL_GPL(__tc_indr_block_cb_unregister);

void tc_indr_block_cb_unregister(struct net_device *dev,
				 tc_indr_block_bind_cb_t *cb, void *cb_ident)
{
	rtnl_lock();
	__tc_indr_block_cb_unregister(dev, cb, cb_ident);
	rtnl_unlock();
}
EXPORT_SYMBOL_GPL(tc_indr_block_cb_unregister);

static void tc_indr_block_call(struct tcf_block *block, struct net_device *dev,
			       struct tcf_block_ext_info *ei,
			       enum tc_block_command command)
{
	struct tc_indr_block_cb *indr_block_cb;
	struct tc_indr_block_dev *indr_dev;
	struct tc_block_offload bo = {
		.command	= command,
		.binder_type	= ei->binder_type,
		.block		= block,
	};

	indr_dev = tc_indr_block_dev_lookup(dev);
	if (!indr_dev)
		return;

	indr_dev->block = command == TC_BLOCK_BIND ? block : NULL;

	list_for_each_entry(indr_block_cb, &indr_dev->cb_list, list)
		indr_block_cb->cb(dev, indr_block_cb->cb_priv, TC_SETUP_BLOCK,
				  &bo);
}

static bool tcf_block_offload_in_use(struct tcf_block *block)
{
	return block->offloadcnt;
}

static int tcf_block_offload_cmd(struct tcf_block *block,
				 struct net_device *dev,
				 struct tcf_block_ext_info *ei,
				 enum tc_block_command command)
{
	struct tc_block_offload bo = {};

	bo.command = command;
	bo.binder_type = ei->binder_type;
	bo.block = block;
	return __rh_call_ndo_setup_tc(dev, 0, TC_SETUP_BLOCK, &bo);
}

static int tcf_block_offload_bind(struct tcf_block *block, struct Qdisc *q,
				  struct tcf_block_ext_info *ei)
{
	struct net_device *dev = q->dev_queue->dev;
	int err;

	if (!__rh_has_ndo_setup_tc(dev))
		goto no_offload_dev_inc;

	/* If tc offload feature is disabled and the block we try to bind
	 * to already has some offloaded filters, forbid to bind.
	 */
	if (!tc_can_offload(dev) && tcf_block_offload_in_use(block))
		return -EOPNOTSUPP;

	err = tcf_block_offload_cmd(block, dev, ei, TC_BLOCK_BIND);
	if (err == -EOPNOTSUPP)
		goto no_offload_dev_inc;
	if (err)
		return err;

	tc_indr_block_call(block, dev, ei, TC_BLOCK_BIND);
	return 0;

no_offload_dev_inc:
	if (tcf_block_offload_in_use(block))
		return -EOPNOTSUPP;
	block->nooffloaddevcnt++;
	tc_indr_block_call(block, dev, ei, TC_BLOCK_BIND);
	return 0;
}

static void tcf_block_offload_unbind(struct tcf_block *block, struct Qdisc *q,
				     struct tcf_block_ext_info *ei)
{
	struct net_device *dev = q->dev_queue->dev;
	int err;

	tc_indr_block_call(block, dev, ei, TC_BLOCK_UNBIND);

	if (!__rh_has_ndo_setup_tc(dev))
		goto no_offload_dev_dec;
	err = tcf_block_offload_cmd(block, dev, ei, TC_BLOCK_UNBIND);
	if (err == -EOPNOTSUPP)
		goto no_offload_dev_dec;
	return;

no_offload_dev_dec:
	WARN_ON(block->nooffloaddevcnt-- == 0);
}

static int
tcf_chain_head_change_cb_add(struct tcf_chain *chain,
			     struct tcf_block_ext_info *ei)
{
	struct tcf_filter_chain_list_item *item;

	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (!item) {
		return -ENOMEM;
	}
	item->chain_head_change = ei->chain_head_change;
	item->chain_head_change_priv = ei->chain_head_change_priv;
	if (chain->filter_chain)
		tcf_chain_head_change_item(item, chain->filter_chain);
	list_add(&item->list, &chain->filter_chain_list);
	return 0;
}

static void
tcf_chain_head_change_cb_del(struct tcf_chain *chain,
			     struct tcf_block_ext_info *ei)
{
	struct tcf_filter_chain_list_item *item;

	list_for_each_entry(item, &chain->filter_chain_list, list) {
		if ((!ei->chain_head_change && !ei->chain_head_change_priv) ||
		    (item->chain_head_change == ei->chain_head_change &&
		     item->chain_head_change_priv == ei->chain_head_change_priv)) {
			tcf_chain_head_change_item(item, NULL);
			list_del(&item->list);
			kfree(item);
			return;
		}
	}
	WARN_ON(1);
}

struct tcf_net {
	struct idr_ext idr;
};

static unsigned int tcf_net_id;

static int tcf_block_insert(struct tcf_block *block, struct net *net)
{
	struct tcf_net *tn = net_generic(net, tcf_net_id);

	return idr_alloc_ext(&tn->idr, block, NULL, block->index,
			     block->index + 1, GFP_KERNEL);
}

static void tcf_block_remove(struct tcf_block *block, struct net *net)
{
	struct tcf_net *tn = net_generic(net, tcf_net_id);

	idr_remove_ext(&tn->idr, block->index);
}

static struct tcf_block *tcf_block_create(struct net *net, struct Qdisc *q,
					  u32 block_index)
{
	struct tcf_block *block;
	struct tcf_chain *chain;
	int err;

	block = kzalloc(sizeof(*block), GFP_KERNEL);
	if (!block) {
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&block->chain_list);
	INIT_LIST_HEAD(&block->cb_list);
	INIT_LIST_HEAD(&block->owner_list);

	/* Create chain 0 by default, it has to be always present. */
	chain = tcf_chain_create(block, 0);
	if (!chain) {
		err = -ENOMEM;
		goto err_chain_create;
	}
	block->refcnt = 1;
	block->net = net;
	block->index = block_index;

	/* Don't store q pointer for blocks which are shared */
	if (!tcf_block_shared(block))
		block->q = q;
	return block;

err_chain_create:
	kfree(block);
	return ERR_PTR(err);
}

static struct tcf_block *tcf_block_lookup(struct net *net, u32 block_index)
{
	struct tcf_net *tn = net_generic(net, tcf_net_id);

	return idr_find_ext(&tn->idr, block_index);
}

static struct tcf_chain *tcf_block_chain_zero(struct tcf_block *block)
{
	return list_first_entry(&block->chain_list, struct tcf_chain, list);
}

struct tcf_block_owner_item {
	struct list_head list;
	struct Qdisc *q;
	enum tcf_block_binder_type binder_type;
};

static void
tcf_block_owner_netif_keep_dst(struct tcf_block *block,
			       struct Qdisc *q,
			       enum tcf_block_binder_type binder_type)
{
	if (block->keep_dst &&
	    binder_type != TCF_BLOCK_BINDER_TYPE_CLSACT_INGRESS &&
	    binder_type != TCF_BLOCK_BINDER_TYPE_CLSACT_EGRESS)
		netif_keep_dst(qdisc_dev(q));
}

void tcf_block_netif_keep_dst(struct tcf_block *block)
{
	struct tcf_block_owner_item *item;

	block->keep_dst = true;
	list_for_each_entry(item, &block->owner_list, list)
		tcf_block_owner_netif_keep_dst(block, item->q,
					       item->binder_type);
}
EXPORT_SYMBOL(tcf_block_netif_keep_dst);

static int tcf_block_owner_add(struct tcf_block *block,
			       struct Qdisc *q,
			       enum tcf_block_binder_type binder_type)
{
	struct tcf_block_owner_item *item;

	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (!item)
		return -ENOMEM;
	item->q = q;
	item->binder_type = binder_type;
	list_add(&item->list, &block->owner_list);
	return 0;
}

static void tcf_block_owner_del(struct tcf_block *block,
				struct Qdisc *q,
				enum tcf_block_binder_type binder_type)
{
	struct tcf_block_owner_item *item;

	list_for_each_entry(item, &block->owner_list, list) {
		if (item->q == q && item->binder_type == binder_type) {
			list_del(&item->list);
			kfree(item);
			return;
		}
	}
	WARN_ON(1);
}

int tcf_block_get_ext(struct tcf_block **p_block, struct Qdisc *q,
		      struct tcf_block_ext_info *ei)
{
	struct net *net = qdisc_net(q);
	struct tcf_block *block = NULL;
	bool created = false;
	int err;

	if (ei->block_index) {
		/* block_index not 0 means the shared block is requested */
		block = tcf_block_lookup(net, ei->block_index);
		if (block)
			block->refcnt++;
	}

	if (!block) {
		block = tcf_block_create(net, q, ei->block_index);
		if (IS_ERR(block))
			return PTR_ERR(block);
		created = true;
		if (tcf_block_shared(block)) {
			err = tcf_block_insert(block, net);
			if (err)
				goto err_block_insert;
		}
	}

	err = tcf_block_owner_add(block, q, ei->binder_type);
	if (err)
		goto err_block_owner_add;

	tcf_block_owner_netif_keep_dst(block, q, ei->binder_type);

	err = tcf_chain_head_change_cb_add(tcf_block_chain_zero(block),
					   ei);
	if (err)
		goto err_chain_head_change_cb_add;

	err = tcf_block_offload_bind(block, q, ei);
	if (err)
		goto err_block_offload_bind;

	*p_block = block;
	return 0;

err_block_offload_bind:
	tcf_chain_head_change_cb_del(tcf_block_chain_zero(block), ei);
err_chain_head_change_cb_add:
	tcf_block_owner_del(block, q, ei->binder_type);
err_block_owner_add:
	if (created) {
		if (tcf_block_shared(block))
			tcf_block_remove(block, net);
err_block_insert:
		kfree(tcf_block_chain_zero(block));
		kfree(block);
	} else {
		block->refcnt--;
	}
	return err;
}
EXPORT_SYMBOL(tcf_block_get_ext);

static void tcf_chain_head_change_dflt(struct tcf_proto *tp_head, void *priv)
{
	struct tcf_proto __rcu **p_filter_chain = priv;

	rcu_assign_pointer(*p_filter_chain, tp_head);
}

int tcf_block_get(struct tcf_block **p_block,
		  struct tcf_proto __rcu **p_filter_chain, struct Qdisc *q)
{
	struct tcf_block_ext_info ei = {
		.chain_head_change = tcf_chain_head_change_dflt,
		.chain_head_change_priv = p_filter_chain,
	};

	WARN_ON(!p_filter_chain);
	return tcf_block_get_ext(p_block, q, &ei);
}
EXPORT_SYMBOL(tcf_block_get);

/* XXX: Standalone actions are not allowed to jump to any chain, and bound
 * actions should be all removed after flushing.
 */
void tcf_block_put_ext(struct tcf_block *block, struct Qdisc *q,
		       struct tcf_block_ext_info *ei)
{
	struct tcf_chain *chain, *tmp;

	if (!block)
		return;
	tcf_chain_head_change_cb_del(tcf_block_chain_zero(block), ei);
	tcf_block_owner_del(block, q, ei->binder_type);

	if (--block->refcnt == 0) {
		if (tcf_block_shared(block))
			tcf_block_remove(block, block->net);

		/* Hold a refcnt for all chains, so that they don't disappear
		 * while we are iterating.
		 */
		list_for_each_entry(chain, &block->chain_list, list)
			tcf_chain_hold(chain);

		list_for_each_entry(chain, &block->chain_list, list)
			tcf_chain_flush(chain);
	}

	tcf_block_offload_unbind(block, q, ei);

	if (block->refcnt == 0) {
		/* At this point, all the chains should have refcnt >= 1. */
		list_for_each_entry_safe(chain, tmp, &block->chain_list, list)
			tcf_chain_put(chain);

		/* Finally, put chain 0 and allow block to be freed. */
		tcf_chain_put(tcf_block_chain_zero(block));
	}
}
EXPORT_SYMBOL(tcf_block_put_ext);

void tcf_block_put(struct tcf_block *block)
{
	struct tcf_block_ext_info ei = {0, };

	if (!block)
		return;
	tcf_block_put_ext(block, block->q, &ei);
}
EXPORT_SYMBOL(tcf_block_put);

struct tcf_block_cb {
	struct list_head list;
	tc_setup_cb_t *cb;
	void *cb_ident;
	void *cb_priv;
	unsigned int refcnt;
};

void *tcf_block_cb_priv(struct tcf_block_cb *block_cb)
{
	return block_cb->cb_priv;
}
EXPORT_SYMBOL(tcf_block_cb_priv);

struct tcf_block_cb *tcf_block_cb_lookup(struct tcf_block *block,
					 tc_setup_cb_t *cb, void *cb_ident)
{	struct tcf_block_cb *block_cb;

	list_for_each_entry(block_cb, &block->cb_list, list)
		if (block_cb->cb == cb && block_cb->cb_ident == cb_ident)
			return block_cb;
	return NULL;
}
EXPORT_SYMBOL(tcf_block_cb_lookup);

void tcf_block_cb_incref(struct tcf_block_cb *block_cb)
{
	block_cb->refcnt++;
}
EXPORT_SYMBOL(tcf_block_cb_incref);

unsigned int tcf_block_cb_decref(struct tcf_block_cb *block_cb)
{
	return --block_cb->refcnt;
}
EXPORT_SYMBOL(tcf_block_cb_decref);

struct tcf_block_cb *__tcf_block_cb_register(struct tcf_block *block,
					     tc_setup_cb_t *cb, void *cb_ident,
					     void *cb_priv)
{
	struct tcf_block_cb *block_cb;

	/* At this point, playback of previous block cb calls is not supported,
	 * so forbid to register to block which already has some offloaded
	 * filters present.
	 */
	if (tcf_block_offload_in_use(block))
		return ERR_PTR(-EOPNOTSUPP);

	block_cb = kzalloc(sizeof(*block_cb), GFP_KERNEL);
	if (!block_cb)
		return ERR_PTR(-ENOMEM);
	block_cb->cb = cb;
	block_cb->cb_ident = cb_ident;
	block_cb->cb_priv = cb_priv;
	list_add(&block_cb->list, &block->cb_list);
	return block_cb;
}
EXPORT_SYMBOL(__tcf_block_cb_register);

int tcf_block_cb_register(struct tcf_block *block,
			  tc_setup_cb_t *cb, void *cb_ident,
			  void *cb_priv)
{
	struct tcf_block_cb *block_cb;

	block_cb = __tcf_block_cb_register(block, cb, cb_ident, cb_priv);
	return IS_ERR(block_cb) ? PTR_ERR(block_cb) : 0;
}
EXPORT_SYMBOL(tcf_block_cb_register);

void __tcf_block_cb_unregister(struct tcf_block_cb *block_cb)
{
	list_del(&block_cb->list);
	kfree(block_cb);
}
EXPORT_SYMBOL(__tcf_block_cb_unregister);

void tcf_block_cb_unregister(struct tcf_block *block,
			     tc_setup_cb_t *cb, void *cb_ident)
{
	struct tcf_block_cb *block_cb;

	block_cb = tcf_block_cb_lookup(block, cb, cb_ident);
	if (!block_cb)
		return;
	__tcf_block_cb_unregister(block_cb);
}
EXPORT_SYMBOL(tcf_block_cb_unregister);

/* Main classifier routine: scans classifier chain attached
 * to this qdisc, (optionally) tests for protocol and asks
 * specific classifiers.
 */
int tcf_classify(struct sk_buff *skb, const struct tcf_proto *tp,
		 struct tcf_result *res, bool compat_mode)
{
	__be16 protocol = tc_skb_protocol(skb);
#ifdef CONFIG_NET_CLS_ACT
	const int max_reclassify_loop = 4;
	const struct tcf_proto *orig_tp = tp;
	const struct tcf_proto *first_tp;
	int limit = 0;

reclassify:
#endif
	for (; tp; tp = rcu_dereference_bh(tp->next)) {
		int err;

		if (tp->protocol != protocol &&
		    tp->protocol != htons(ETH_P_ALL))
			continue;

		err = tp->classify(skb, tp, res);
#ifdef CONFIG_NET_CLS_ACT
		if (unlikely(err == TC_ACT_RECLASSIFY && !compat_mode)) {
			first_tp = orig_tp;
			goto reset;
		} else if (unlikely(TC_ACT_EXT_CMP(err, TC_ACT_GOTO_CHAIN))) {
			first_tp = res->goto_tp;
			goto reset;
		}
#endif
		if (err >= 0)
			return err;
	}

	return TC_ACT_UNSPEC; /* signal: continue lookup */
#ifdef CONFIG_NET_CLS_ACT
reset:
	if (unlikely(limit++ >= max_reclassify_loop)) {
		net_notice_ratelimited("%u: reclassify loop, rule prio %u, protocol %02x\n",
				       tp->chain->block->index,
				       tp->prio & 0xffff,
				       ntohs(tp->protocol));
		return TC_ACT_SHOT;
	}

	tp = first_tp;
	protocol = tc_skb_protocol(skb);
	goto reclassify;
#endif
}
EXPORT_SYMBOL(tcf_classify);

struct tcf_chain_info {
	struct tcf_proto __rcu **pprev;
	struct tcf_proto __rcu *next;
};

static struct tcf_proto *tcf_chain_tp_prev(struct tcf_chain_info *chain_info)
{
	return rtnl_dereference(*chain_info->pprev);
}

static void tcf_chain_tp_insert(struct tcf_chain *chain,
				struct tcf_chain_info *chain_info,
				struct tcf_proto *tp)
{
	if (*chain_info->pprev == chain->filter_chain)
		tcf_chain_head_change(chain, tp);
	RCU_INIT_POINTER(tp->next, tcf_chain_tp_prev(chain_info));
	rcu_assign_pointer(*chain_info->pprev, tp);
	tcf_chain_hold(chain);
}

static void tcf_chain_tp_remove(struct tcf_chain *chain,
				struct tcf_chain_info *chain_info,
				struct tcf_proto *tp)
{
	struct tcf_proto *next = rtnl_dereference(chain_info->next);

	if (tp == chain->filter_chain)
		tcf_chain_head_change(chain, next);
	RCU_INIT_POINTER(*chain_info->pprev, next);
	tcf_chain_put(chain);
}

static struct tcf_proto *tcf_chain_tp_find(struct tcf_chain *chain,
					   struct tcf_chain_info *chain_info,
					   u32 protocol, u32 prio,
					   bool prio_allocate)
{
	struct tcf_proto **pprev;
	struct tcf_proto *tp;

	/* Check the chain for existence of proto-tcf with this priority */
	for (pprev = &chain->filter_chain;
	     (tp = rtnl_dereference(*pprev)); pprev = &tp->next) {
		if (tp->prio >= prio) {
			if (tp->prio == prio) {
				if (prio_allocate ||
				    (tp->protocol != protocol && protocol))
					return ERR_PTR(-EINVAL);
			} else {
				tp = NULL;
			}
			break;
		}
	}
	chain_info->pprev = pprev;
	chain_info->next = tp ? tp->next : NULL;
	return tp;
}

static int tcf_fill_node(struct net *net, struct sk_buff *skb,
			 struct tcf_proto *tp, struct tcf_block *block,
			 struct Qdisc *q, u32 parent, void *fh,
			 u32 portid, u32 seq, u16 flags, int event)
{
	struct tcmsg *tcm;
	struct nlmsghdr  *nlh;
	unsigned char *b = skb_tail_pointer(skb);

	nlh = nlmsg_put(skb, portid, seq, event, sizeof(*tcm), flags);
	if (!nlh)
		goto out_nlmsg_trim;
	tcm = nlmsg_data(nlh);
	tcm->tcm_family = AF_UNSPEC;
	tcm->tcm__pad1 = 0;
	tcm->tcm__pad2 = 0;
	if (q) {
		tcm->tcm_ifindex = qdisc_dev(q)->ifindex;
		tcm->tcm_parent = parent;
	} else {
		tcm->tcm_ifindex = TCM_IFINDEX_MAGIC_BLOCK;
		tcm->tcm_block_index = block->index;
	}
	tcm->tcm_info = TC_H_MAKE(tp->prio, tp->protocol);
	if (nla_put_string(skb, TCA_KIND, tp->ops->kind))
		goto nla_put_failure;
	if (nla_put_u32(skb, TCA_CHAIN, tp->chain->index))
		goto nla_put_failure;
	if (!fh) {
		tcm->tcm_handle = 0;
	} else {
		if (tp->ops->dump && tp->ops->dump(net, tp, fh, skb, tcm) < 0)
			goto nla_put_failure;
	}
	nlh->nlmsg_len = skb_tail_pointer(skb) - b;
	return skb->len;

out_nlmsg_trim:
nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int tfilter_notify(struct net *net, struct sk_buff *oskb,
			  struct nlmsghdr *n, struct tcf_proto *tp,
			  struct tcf_block *block, struct Qdisc *q,
			  u32 parent, void *fh, int event, bool unicast)
{
	struct sk_buff *skb;
	u32 portid = oskb ? NETLINK_CB(oskb).portid : 0;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;

	if (tcf_fill_node(net, skb, tp, block, q, parent, fh, portid,
			  n->nlmsg_seq, n->nlmsg_flags, event) <= 0) {
		kfree_skb(skb);
		return -EINVAL;
	}

	if (unicast)
		return netlink_unicast(net->rtnl, skb, portid, MSG_DONTWAIT);

	return rtnetlink_send(skb, net, portid, RTNLGRP_TC,
			      n->nlmsg_flags & NLM_F_ECHO);
}

static int tfilter_del_notify(struct net *net, struct sk_buff *oskb,
			      struct nlmsghdr *n, struct tcf_proto *tp,
			      struct tcf_block *block, struct Qdisc *q,
			      u32 parent, void *fh, bool unicast, bool *last)
{
	struct sk_buff *skb;
	u32 portid = oskb ? NETLINK_CB(oskb).portid : 0;
	int err;

	skb = alloc_skb(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb)
		return -ENOBUFS;

	if (tcf_fill_node(net, skb, tp, block, q, parent, fh, portid,
			  n->nlmsg_seq, n->nlmsg_flags, RTM_DELTFILTER) <= 0) {
		kfree_skb(skb);
		return -EINVAL;
	}

	err = tp->ops->delete(tp, fh, last);
	if (err) {
		kfree_skb(skb);
		return err;
	}

	if (unicast)
		return netlink_unicast(net->rtnl, skb, portid, MSG_DONTWAIT);

	return rtnetlink_send(skb, net, portid, RTNLGRP_TC,
			      n->nlmsg_flags & NLM_F_ECHO);
}

static void tfilter_notify_chain(struct net *net, struct sk_buff *oskb,
				 struct tcf_block *block, struct Qdisc *q,
				 u32 parent, struct nlmsghdr *n,
				 struct tcf_chain *chain, int event)
{
	struct tcf_proto *tp;

	for (tp = rtnl_dereference(chain->filter_chain);
	     tp; tp = rtnl_dereference(tp->next))
		tfilter_notify(net, oskb, n, tp, block,
			       q, parent, 0, event, false);
}

/* Add/change/delete/get a filter node */

static int tc_ctl_tfilter(struct sk_buff *skb, struct nlmsghdr *n)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr *tca[TCA_MAX + 1];
	struct tcmsg *t;
	u32 protocol;
	u32 prio;
	bool prio_allocate;
	u32 parent;
	u32 chain_index;
	struct Qdisc *q = NULL;
	struct tcf_chain_info chain_info;
	struct tcf_chain *chain = NULL;
	struct tcf_block *block;
	struct tcf_proto *tp;
	unsigned long cl;
	void *fh;
	int err;
	int tp_created;

	if ((n->nlmsg_type != RTM_GETTFILTER) &&
	    !netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN))
		return -EPERM;

replay:
	tp_created = 0;

	err = nlmsg_parse(n, sizeof(*t), tca, TCA_MAX, NULL);
	if (err < 0)
		return err;

	t = nlmsg_data(n);
	protocol = TC_H_MIN(t->tcm_info);
	prio = TC_H_MAJ(t->tcm_info);
	prio_allocate = false;
	parent = t->tcm_parent;
	cl = 0;

	if (prio == 0) {
		switch (n->nlmsg_type) {
		case RTM_DELTFILTER:
			if (protocol || t->tcm_handle || tca[TCA_KIND])
				return -ENOENT;
			break;
		case RTM_NEWTFILTER:
			/* If no priority is provided by the user,
			 * we allocate one.
			 */
			if (n->nlmsg_flags & NLM_F_CREATE) {
				prio = TC_H_MAKE(0x80000000U, 0U);
				prio_allocate = true;
				break;
			}
			/* fall-through */
		default:
			return -ENOENT;
		}
	}

	/* Find head of filter chain. */

	if (t->tcm_ifindex == TCM_IFINDEX_MAGIC_BLOCK) {
		block = tcf_block_lookup(net, t->tcm_block_index);
		if (!block) {
			err = -EINVAL;
			goto errout;
		}
	} else {
		const struct Qdisc_class_ops *cops;
		struct net_device *dev;

		/* Find link */
		dev = __dev_get_by_index(net, t->tcm_ifindex);
		if (!dev)
			return -ENODEV;

		/* Find qdisc */
		if (!parent) {
			q = dev->qdisc;
			parent = q->handle;
		} else {
			q = qdisc_lookup(dev, TC_H_MAJ(t->tcm_parent));
			if (!q)
				return -EINVAL;
		}

		/* Is it classful? */
		cops = q->ops->cl_ops;
		if (!cops)
			return -EINVAL;

		if (!cops->tcf_block)
			return -EOPNOTSUPP;

		/* Do we search for filter, attached to class? */
		if (TC_H_MIN(parent)) {
			cl = cops->find(q, parent);
			if (cl == 0)
				return -ENOENT;
		}

		/* And the last stroke */
		block = cops->tcf_block(q, cl);
		if (!block) {
			err = -EINVAL;
			goto errout;
		}
		if (tcf_block_shared(block)) {
			err = -EOPNOTSUPP;
			goto errout;
		}
	}

	chain_index = tca[TCA_CHAIN] ? nla_get_u32(tca[TCA_CHAIN]) : 0;
	if (chain_index > TC_ACT_EXT_VAL_MASK) {
		err = -EINVAL;
		goto errout;
	}
	chain = tcf_chain_get(block, chain_index,
			      n->nlmsg_type == RTM_NEWTFILTER);
	if (!chain) {
		err = n->nlmsg_type == RTM_NEWTFILTER ? -ENOMEM : -EINVAL;
		goto errout;
	}

	if (n->nlmsg_type == RTM_DELTFILTER && prio == 0) {
		tfilter_notify_chain(net, skb, block, q, parent, n,
				     chain, RTM_DELTFILTER);
		tcf_chain_flush(chain);
		err = 0;
		goto errout;
	}

	tp = tcf_chain_tp_find(chain, &chain_info, protocol,
			       prio, prio_allocate);
	if (IS_ERR(tp)) {
		err = PTR_ERR(tp);
		goto errout;
	}

	if (tp == NULL) {
		/* Proto-tcf does not exist, create new one */

		if (tca[TCA_KIND] == NULL || !protocol) {
			err = -EINVAL;
			goto errout;
		}

		if (n->nlmsg_type != RTM_NEWTFILTER ||
		    !(n->nlmsg_flags & NLM_F_CREATE)) {
			err = -ENOENT;
			goto errout;
		}

		if (prio_allocate)
			prio = tcf_auto_prio(tcf_chain_tp_prev(&chain_info));

		tp = tcf_proto_create(nla_data(tca[TCA_KIND]),
				      protocol, prio, chain);
		if (IS_ERR(tp)) {
			err = PTR_ERR(tp);
			goto errout;
		}
		tp_created = 1;
	} else if (tca[TCA_KIND] && nla_strcmp(tca[TCA_KIND], tp->ops->kind)) {
		err = -EINVAL;
		goto errout;
	}

	fh = tp->ops->get(tp, t->tcm_handle);

	if (!fh) {
		if (n->nlmsg_type == RTM_DELTFILTER && t->tcm_handle == 0) {
			tcf_chain_tp_remove(chain, &chain_info, tp);
			tfilter_notify(net, skb, n, tp, block, q, parent, fh,
				       RTM_DELTFILTER, false);
			tcf_proto_destroy(tp);
			err = 0;
			goto errout;
		}

		if (n->nlmsg_type != RTM_NEWTFILTER ||
		    !(n->nlmsg_flags & NLM_F_CREATE)) {
			err = -ENOENT;
			goto errout;
		}
	} else {
		bool last;

		switch (n->nlmsg_type) {
		case RTM_NEWTFILTER:
			if (n->nlmsg_flags & NLM_F_EXCL) {
				if (tp_created)
					tcf_proto_destroy(tp);
				err = -EEXIST;
				goto errout;
			}
			break;
		case RTM_DELTFILTER:
			err = tfilter_del_notify(net, skb, n, tp, block,
						 q, parent, fh, false, &last);
			if (err)
				goto errout;
			if (last) {
				tcf_chain_tp_remove(chain, &chain_info, tp);
				tcf_proto_destroy(tp);
			}
			goto errout;
		case RTM_GETTFILTER:
			err = tfilter_notify(net, skb, n, tp, block, q, parent,
					     fh, RTM_NEWTFILTER, true);
			goto errout;
		default:
			err = -EINVAL;
			goto errout;
		}
	}

	err = tp->ops->change(net, skb, tp, cl, t->tcm_handle, tca, &fh,
			      n->nlmsg_flags & NLM_F_CREATE ? TCA_ACT_NOREPLACE : TCA_ACT_REPLACE);
	if (err == 0) {
		if (tp_created)
			tcf_chain_tp_insert(chain, &chain_info, tp);
		tfilter_notify(net, skb, n, tp, block, q, parent, fh,
			       RTM_NEWTFILTER, false);
	} else {
		if (tp_created)
			tcf_proto_destroy(tp);
	}

errout:
	if (chain)
		tcf_chain_put(chain);
	if (err == -EAGAIN)
		/* Replay the request. */
		goto replay;
	return err;
}

struct tcf_dump_args {
	struct tcf_walker w;
	struct sk_buff *skb;
	struct netlink_callback *cb;
	struct tcf_block *block;
	struct Qdisc *q;
	u32 parent;
};

static int tcf_node_dump(struct tcf_proto *tp, void *n, struct tcf_walker *arg)
{
	struct tcf_dump_args *a = (void *)arg;
	struct net *net = sock_net(a->skb->sk);

	return tcf_fill_node(net, a->skb, tp, a->block, a->q, a->parent,
			     n, NETLINK_CB(a->cb->skb).portid,
			     a->cb->nlh->nlmsg_seq, NLM_F_MULTI,
			     RTM_NEWTFILTER);
}

static bool tcf_chain_dump(struct tcf_chain *chain, struct Qdisc *q, u32 parent,
			   struct sk_buff *skb, struct netlink_callback *cb,
			   long index_start, long *p_index)
{
	struct net *net = sock_net(skb->sk);
	struct tcf_block *block = chain->block;
	struct tcmsg *tcm = nlmsg_data(cb->nlh);
	struct tcf_dump_args arg;
	struct tcf_proto *tp;

	for (tp = rtnl_dereference(chain->filter_chain);
	     tp; tp = rtnl_dereference(tp->next), (*p_index)++) {
		if (*p_index < index_start)
			continue;
		if (TC_H_MAJ(tcm->tcm_info) &&
		    TC_H_MAJ(tcm->tcm_info) != tp->prio)
			continue;
		if (TC_H_MIN(tcm->tcm_info) &&
		    TC_H_MIN(tcm->tcm_info) != tp->protocol)
			continue;
		if (*p_index > index_start)
			memset(&cb->args[1], 0,
			       sizeof(cb->args) - sizeof(cb->args[0]));
		if (cb->args[1] == 0) {
			if (tcf_fill_node(net, skb, tp, block, q, parent, 0,
					  NETLINK_CB(cb->skb).portid,
					  cb->nlh->nlmsg_seq, NLM_F_MULTI,
					  RTM_NEWTFILTER) <= 0)
				return false;

			cb->args[1] = 1;
		}
		if (!tp->ops->walk)
			continue;
		arg.w.fn = tcf_node_dump;
		arg.skb = skb;
		arg.cb = cb;
		arg.block = block;
		arg.q = q;
		arg.parent = parent;
		arg.w.stop = 0;
		arg.w.skip = cb->args[1] - 1;
		arg.w.count = 0;
		arg.w.cookie = cb->args[2];
		tp->ops->walk(tp, &arg.w);
		cb->args[2] = arg.w.cookie;
		cb->args[1] = arg.w.count + 1;
		if (arg.w.stop)
			return false;
	}
	return true;
}

/* called with RTNL */
static int tc_dump_tfilter(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct nlattr *tca[TCA_MAX + 1];
	struct Qdisc *q = NULL;
	struct tcf_block *block;
	struct tcf_chain *chain;
	struct tcmsg *tcm = nlmsg_data(cb->nlh);
	long index_start;
	long index;
	u32 parent;
	int err;

	if (nlmsg_len(cb->nlh) < sizeof(*tcm))
		return skb->len;

	err = nlmsg_parse(cb->nlh, sizeof(*tcm), tca, TCA_MAX, NULL);
	if (err)
		return err;

	if (tcm->tcm_ifindex == TCM_IFINDEX_MAGIC_BLOCK) {
		block = tcf_block_lookup(net, tcm->tcm_block_index);
		if (!block)
			goto out;
		/* If we work with block index, q is NULL and parent value
		 * will never be used in the following code. The check
		 * in tcf_fill_node prevents it. However, compiler does not
		 * see that far, so set parent to zero to silence the warning
		 * about parent being uninitialized.
		 */
		parent = 0;
	} else {
		const struct Qdisc_class_ops *cops;
		struct net_device *dev;
		unsigned long cl = 0;

		dev = __dev_get_by_index(net, tcm->tcm_ifindex);
		if (!dev)
			return skb->len;

		parent = tcm->tcm_parent;
		if (!parent) {
			q = dev->qdisc;
			parent = q->handle;
		} else {
			q = qdisc_lookup(dev, TC_H_MAJ(tcm->tcm_parent));
		}
		if (!q)
			goto out;
		cops = q->ops->cl_ops;
		if (!cops)
			goto out;
		if (!cops->tcf_block)
			goto out;
		if (TC_H_MIN(tcm->tcm_parent)) {
			cl = cops->find(q, tcm->tcm_parent);
			if (cl == 0)
				goto out;
		}
		block = cops->tcf_block(q, cl);
		if (!block)
			goto out;
		if (tcf_block_shared(block))
			q = NULL;
	}

	index_start = cb->args[0];
	index = 0;

	list_for_each_entry(chain, &block->chain_list, list) {
		if (tca[TCA_CHAIN] &&
		    nla_get_u32(tca[TCA_CHAIN]) != chain->index)
			continue;
		if (!tcf_chain_dump(chain, q, parent, skb, cb,
				    index_start, &index))
			break;
	}

	cb->args[0] = index;

out:
	return skb->len;
}

void tcf_exts_destroy(struct tcf_exts *exts)
{
#ifdef CONFIG_NET_CLS_ACT
	LIST_HEAD(actions);

	ASSERT_RTNL();
	tcf_exts_to_list(exts, &actions);
	tcf_action_destroy(&actions, TCA_ACT_UNBIND);
	kfree(exts->actions);
	exts->nr_actions = 0;
#endif
}
EXPORT_SYMBOL(tcf_exts_destroy);

int tcf_exts_validate(struct net *net, struct tcf_proto *tp, struct nlattr **tb,
		      struct nlattr *rate_tlv, struct tcf_exts *exts, bool ovr)
{
#ifdef CONFIG_NET_CLS_ACT
	{
		struct tc_action *act;

		if (exts->police && tb[exts->police]) {
			act = tcf_action_init_1(net, tp, tb[exts->police],
						rate_tlv, "police", ovr,
						TCA_ACT_BIND);
			if (IS_ERR(act))
				return PTR_ERR(act);

			act->type = exts->type = TCA_OLD_COMPAT;
			exts->actions[0] = act;
			exts->nr_actions = 1;
		} else if (exts->action && tb[exts->action]) {
			LIST_HEAD(actions);
			int err, i = 0;

			err = tcf_action_init(net, tp, tb[exts->action],
					      rate_tlv, NULL, ovr, TCA_ACT_BIND,
					      &actions);
			if (err)
				return err;
			list_for_each_entry(act, &actions, list)
				exts->actions[i++] = act;
			exts->nr_actions = i;
		}
		exts->net = net;
	}
#else
	if ((exts->action && tb[exts->action]) ||
	    (exts->police && tb[exts->police]))
		return -EOPNOTSUPP;
#endif

	return 0;
}
EXPORT_SYMBOL(tcf_exts_validate);

void tcf_exts_change(struct tcf_exts *dst, struct tcf_exts *src)
{
#ifdef CONFIG_NET_CLS_ACT
	struct tcf_exts old = *dst;

	*dst = *src;
	tcf_exts_destroy(&old);
#endif
}
EXPORT_SYMBOL(tcf_exts_change);

#ifdef CONFIG_NET_CLS_ACT
static struct tc_action *tcf_exts_first_act(struct tcf_exts *exts)
{
	if (exts->nr_actions == 0)
		return NULL;
	else
		return exts->actions[0];
}
#endif

int tcf_exts_dump(struct sk_buff *skb, struct tcf_exts *exts)
{
#ifdef CONFIG_NET_CLS_ACT
	struct nlattr *nest;

	if (exts->action && tcf_exts_has_actions(exts)) {
		/*
		 * again for backward compatible mode - we want
		 * to work with both old and new modes of entering
		 * tc data even if iproute2  was newer - jhs
		 */
		if (exts->type != TCA_OLD_COMPAT) {
			LIST_HEAD(actions);

			nest = nla_nest_start(skb, exts->action);
			if (nest == NULL)
				goto nla_put_failure;

			tcf_exts_to_list(exts, &actions);
			if (tcf_action_dump(skb, &actions, 0, 0) < 0)
				goto nla_put_failure;
			nla_nest_end(skb, nest);
		} else if (exts->police) {
			struct tc_action *act = tcf_exts_first_act(exts);
			nest = nla_nest_start(skb, exts->police);
			if (nest == NULL || !act)
				goto nla_put_failure;
			if (tcf_action_dump_old(skb, act, 0, 0) < 0)
				goto nla_put_failure;
			nla_nest_end(skb, nest);
		}
	}
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
#else
	return 0;
#endif
}
EXPORT_SYMBOL(tcf_exts_dump);


int tcf_exts_dump_stats(struct sk_buff *skb, struct tcf_exts *exts)
{
#ifdef CONFIG_NET_CLS_ACT
	struct tc_action *a = tcf_exts_first_act(exts);
	if (a != NULL && tcf_action_copy_stats(skb, a, 1) < 0)
		return -1;
#endif
	return 0;
}
EXPORT_SYMBOL(tcf_exts_dump_stats);

int tc_setup_cb_call(struct tcf_block *block, enum tc_setup_type type,
		     void *type_data, bool err_stop)
{
	struct tcf_block_cb *block_cb;
	int ok_count = 0;
	int err;

	/*
	 * RHEL: Older drivers compiled against RHEL 7.4 and older don't
	 * use TC setup callback infrastructure. We need to call their
	 * .ndo_setup_tc() callback for types used by classifiers in RHEL 7.4
	 * TC_SETUP_{MQPRIO,CLS*}.
	 * For newer drivers and such types the __rh_call_ndo_setup_tc()
	 * does nothing and immediately returns 0.
	 *
	 * Note that the compatibility for older external drivers is preserved
	 * only when TC block is not shared. For such drivers we need to
	 * provide qdisc handle but only non-shared blocks have exactly one
	 * qdisc.
	 */
	if (!tcf_block_shared(block)) {
		err = __rh_call_ndo_setup_tc(tcf_block_dev(block),
					     tcf_block_q(block)->handle, type,
					     type_data);
		if (err < 0 && err_stop)
			return err;
	}

	/* Make sure all netdevs sharing this block are offload-capable. */
	if (block->nooffloaddevcnt && err_stop)
		return -EOPNOTSUPP;

	list_for_each_entry(block_cb, &block->cb_list, list) {
		err = block_cb->cb(type, type_data, block_cb->cb_priv);
		if (err) {
			if (err_stop)
				return err;
		} else {
			ok_count++;
		}
	}
	return ok_count;
}
EXPORT_SYMBOL(tc_setup_cb_call);

static __net_init int tcf_net_init(struct net *net)
{
	struct tcf_net *tn = net_generic(net, tcf_net_id);

	idr_init_ext(&tn->idr);
	return 0;
}

static void __net_exit tcf_net_exit(struct net *net)
{
	struct tcf_net *tn = net_generic(net, tcf_net_id);

	idr_destroy_ext(&tn->idr);
}

static struct pernet_operations tcf_net_ops = {
	.init = tcf_net_init,
	.exit = tcf_net_exit,
	.id   = &tcf_net_id,
	.size = sizeof(struct tcf_net),
};

static int __init tc_filter_init(void)
{
	int err;

	tc_filter_wq = alloc_ordered_workqueue("tc_filter_workqueue", 0);
	if (!tc_filter_wq)
		return -ENOMEM;

	err = register_pernet_subsys(&tcf_net_ops);
	if (err)
		goto err_register_pernet_subsys;

	err = rhashtable_init(&indr_setup_block_ht,
			      &tc_indr_setup_block_ht_params);
	if (err)
		goto err_rhash_setup_block_ht;

	rtnl_register(PF_UNSPEC, RTM_NEWTFILTER, tc_ctl_tfilter, NULL, NULL);
	rtnl_register(PF_UNSPEC, RTM_DELTFILTER, tc_ctl_tfilter, NULL, NULL);
	rtnl_register(PF_UNSPEC, RTM_GETTFILTER, tc_ctl_tfilter,
		      tc_dump_tfilter, NULL);

	return 0;

err_rhash_setup_block_ht:
	unregister_pernet_subsys(&tcf_net_ops);
err_register_pernet_subsys:
	destroy_workqueue(tc_filter_wq);
	return err;
}

subsys_initcall(tc_filter_init);
