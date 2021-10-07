// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *	connector.c
 *
 * 2004+ Copyright (c) Evgeniy Polyakov <zbr@ioremap.net>
 * All rights reserved.
 */

#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <linux/moduleparam.h>
#include <linux/connector.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/ve.h>

#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Evgeniy Polyakov <zbr@ioremap.net>");
MODULE_DESCRIPTION("Generic userspace <-> kernelspace connector.");
MODULE_ALIAS_NET_PF_PROTO(PF_NETLINK, NETLINK_CONNECTOR);

static int cn_already_initialized;

static struct cn_dev *get_cdev(struct ve_struct *ve)
{
	return &ve->cn->cdev;
}

/*
 * Sends mult (multiple) cn_msg at a time.
 *
 * msg->seq and msg->ack are used to determine message genealogy.
 * When someone sends message it puts there locally unique sequence
 * and random acknowledge numbers.  Sequence number may be copied into
 * nlmsghdr->nlmsg_seq too.
 *
 * Sequence number is incremented with each message to be sent.
 *
 * If we expect a reply to our message then the sequence number in
 * received message MUST be the same as in original message, and
 * acknowledge number MUST be the same + 1.
 *
 * If we receive a message and its sequence number is not equal to the
 * one we are expecting then it is a new message.
 *
 * If we receive a message and its sequence number is the same as one
 * we are expecting but it's acknowledgement number is not equal to
 * the acknowledgement number in the original message + 1, then it is
 * a new message.
 *
 * If msg->len != len, then additional cn_msg messages are expected following
 * the first msg.
 *
 * The message is sent to, the portid if given, the group if given, both if
 * both, or if both are zero then the group is looked up and sent there.
 */
int cn_netlink_send_mult_ve(struct ve_struct *ve, struct cn_msg *msg, u16 len,
			    u32 portid, u32 __group, gfp_t gfp_mask)
{
	struct cn_callback_entry *__cbq;
	unsigned int size;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct cn_msg *data;
	struct cn_dev *dev = get_cdev(ve);
	u32 group = 0;
	int found = 0;

	if (portid || __group) {
		group = __group;
	} else {
		spin_lock_bh(&dev->cbdev->queue_lock);
		list_for_each_entry(__cbq, &dev->cbdev->queue_list,
				    callback_entry) {
			if (cn_cb_equal(&__cbq->id.id, &msg->id)) {
				found = 1;
				group = __cbq->group;
				break;
			}
		}
		spin_unlock_bh(&dev->cbdev->queue_lock);

		if (!found)
			return -ENODEV;
	}

	if (!portid && !netlink_has_listeners(dev->nls, group))
		return -ESRCH;

	size = sizeof(*msg) + len;

	skb = nlmsg_new(size, gfp_mask);
	if (!skb)
		return -ENOMEM;

	nlh = nlmsg_put(skb, 0, msg->seq, NLMSG_DONE, size, 0);
	if (!nlh) {
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	data = nlmsg_data(nlh);

	memcpy(data, msg, size);

	NETLINK_CB(skb).dst_group = group;

	if (group)
		return netlink_broadcast(dev->nls, skb, portid, group,
					 gfp_mask);
	return netlink_unicast(dev->nls, skb, portid,
			!gfpflags_allow_blocking(gfp_mask));
}

int cn_netlink_send_mult(struct cn_msg *msg, u16 len, u32 portid, u32 __group,
	gfp_t gfp_mask)
{
	return cn_netlink_send_mult_ve(get_ve0(), msg, len, portid,
				       __group, gfp_mask);
}
EXPORT_SYMBOL_GPL(cn_netlink_send_mult);

int cn_netlink_send_ve(struct ve_struct *ve, struct cn_msg *msg, u32 portid,
		       u32 __group, gfp_t gfp_mask)
{
	return cn_netlink_send_mult_ve(ve, msg, msg->len, portid,
				       __group, gfp_mask);
}

/* same as cn_netlink_send_mult except msg->len is used for len */
int cn_netlink_send(struct cn_msg *msg, u32 portid, u32 __group,
	gfp_t gfp_mask)
{
	return cn_netlink_send_mult(msg, msg->len, portid, __group, gfp_mask);
}
EXPORT_SYMBOL_GPL(cn_netlink_send);

/*
 * Callback helper - queues work and setup destructor for given data.
 */
static int cn_call_callback(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	struct cn_callback_entry *i, *cbq = NULL;
	struct cn_dev *dev = get_cdev(get_ve0());
	struct cn_msg *msg = nlmsg_data(nlmsg_hdr(skb));
	struct netlink_skb_parms *nsp = &NETLINK_CB(skb);
	int err = -ENODEV;

	/* verify msg->len is within skb */
	nlh = nlmsg_hdr(skb);
	if (nlh->nlmsg_len < NLMSG_HDRLEN + sizeof(struct cn_msg) + msg->len)
		return -EINVAL;

	spin_lock_bh(&dev->cbdev->queue_lock);
	list_for_each_entry(i, &dev->cbdev->queue_list, callback_entry) {
		if (cn_cb_equal(&i->id.id, &msg->id)) {
			refcount_inc(&i->refcnt);
			cbq = i;
			break;
		}
	}
	spin_unlock_bh(&dev->cbdev->queue_lock);

	if (cbq != NULL) {
		cbq->callback(msg, nsp);
		kfree_skb(skb);
		cn_queue_release_callback(cbq);
		err = 0;
	}

	return err;
}

/*
 * Main netlink receiving function.
 *
 * It checks skb, netlink header and msg sizes, and calls callback helper.
 */
static void cn_rx_skb(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int len, err;

	if (skb->len >= NLMSG_HDRLEN) {
		nlh = nlmsg_hdr(skb);
		len = nlmsg_len(nlh);

		if (len < (int)sizeof(struct cn_msg) ||
		    skb->len < nlh->nlmsg_len ||
		    len > CONNECTOR_MAX_MSG_SIZE)
			return;

		err = cn_call_callback(skb_get(skb));
		if (err < 0)
			kfree_skb(skb);
	}
}

int cn_add_callback_ve(struct ve_struct *ve,
		       const struct cb_id *id, const char *name,
		       void (*callback)(struct cn_msg *,
					struct netlink_skb_parms *))
{
	struct cn_dev *dev = get_cdev(ve);

	if (!cn_already_initialized)
		return -EAGAIN;

	return cn_queue_add_callback(dev->cbdev, name, id, callback);
}

/*
 * Callback add routing - adds callback with given ID and name.
 * If there is registered callback with the same ID it will not be added.
 *
 * May sleep.
 */
int cn_add_callback(const struct cb_id *id, const char *name,
		    void (*callback)(struct cn_msg *,
				     struct netlink_skb_parms *))
{
	return cn_add_callback_ve(get_ve0(), id, name, callback);
}
EXPORT_SYMBOL_GPL(cn_add_callback);

void cn_del_callback_ve(struct ve_struct *ve, const struct cb_id *id)
{
	struct cn_dev *dev = get_cdev(ve);

	cn_queue_del_callback(dev->cbdev, id);
}

/*
 * Callback remove routing - removes callback
 * with given ID.
 * If there is no registered callback with given
 * ID nothing happens.
 *
 * May sleep while waiting for reference counter to become zero.
 */
void cn_del_callback(const struct cb_id *id)
{
	cn_del_callback_ve(get_ve0(), id);
}
EXPORT_SYMBOL_GPL(cn_del_callback);

static int __maybe_unused cn_proc_show(struct seq_file *m, void *v)
{
	struct cn_queue_dev *dev = get_cdev(get_ve0())->cbdev;
	struct cn_callback_entry *cbq;

	seq_printf(m, "Name            ID\n");

	spin_lock_bh(&dev->queue_lock);

	list_for_each_entry(cbq, &dev->queue_list, callback_entry) {
		seq_printf(m, "%-15s %u:%u\n",
			   cbq->id.name,
			   cbq->id.id.idx,
			   cbq->id.id.val);
	}

	spin_unlock_bh(&dev->queue_lock);

	return 0;
}

static int cn_init_ve(struct ve_struct *ve)
{
	struct cn_dev *dev;
	struct netlink_kernel_cfg cfg = {
		.groups	= CN_NETLINK_USERS + 0xf,
		.input	= cn_rx_skb,
	};
	struct net *net;
	int err;

	ve->cn = kzalloc(sizeof(*ve->cn), GFP_KERNEL);
	if (!ve->cn)
		return -ENOMEM;

	dev = &ve->cn->cdev;

	/*
	 * This is a hook, hooks are called under a single lock, so ve_ns will
	 * not disappear, so rcu_read_lock()/unlock is not needed here.
	 */
	net = rcu_dereference_check(ve->ve_ns, 1)->net_ns;

	err = -EIO;
	dev->nls = netlink_kernel_create(net, NETLINK_CONNECTOR, &cfg);
	if (!dev->nls)
		goto net_unlock;

	err = -EINVAL;
	dev->cbdev = cn_queue_alloc_dev("cqueue", dev->nls);
	if (!dev->cbdev) {
		netlink_kernel_release(dev->nls);
		goto net_unlock;
	}

	cn_already_initialized = 1;

	proc_create_single("connector", S_IRUGO, net->proc_net, cn_proc_show);
	err = 0;

net_unlock:
	return err;
}

static void cn_fini_ve(struct ve_struct *ve)
{
	struct cn_dev *dev = get_cdev(ve);
	struct net *net;

	cn_already_initialized = 0;

	/*
	 * This is a hook called on ve stop, ve->ve_ns will be destroyed
	 * later in the same thread, parallel ve stop is impossible,
	 * so rcu_read_lock()/unlock is not needed here.
	 */
	net = rcu_dereference_check(ve->ve_ns, 1)->net_ns;
	remove_proc_entry("connector", net->proc_net);

	cn_queue_free_dev(dev->cbdev);
	netlink_kernel_release(dev->nls);

	kfree(ve->cn);
	ve->cn = NULL;
}

static int cn_init(void)
{
	return cn_init_ve(get_ve0());
}

static void cn_fini(void)
{
	return cn_fini_ve(get_ve0());
}

subsys_initcall(cn_init);
module_exit(cn_fini);
