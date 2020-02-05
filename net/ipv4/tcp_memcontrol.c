#include <net/tcp.h>
#include <net/tcp_memcontrol.h>
#include <net/sock.h>
#include <net/ip.h>
#include <linux/nsproxy.h>
#include <linux/memcontrol.h>
#include <linux/module.h>

static inline struct tcp_memcontrol *tcp_from_cgproto(struct cg_proto *cg_proto)
{
	return container_of(cg_proto, struct tcp_memcontrol, cg_proto);
}

static void memcg_tcp_enter_memory_pressure(struct sock *sk)
{
	if (sk->sk_cgrp->memory_pressure)
		*sk->sk_cgrp->memory_pressure = 1;
}
EXPORT_SYMBOL(memcg_tcp_enter_memory_pressure);

int tcp_init_cgroup(struct mem_cgroup *memcg, struct cgroup_subsys *ss)
{
	/*
	 * The root cgroup does not use page_counters, but rather,
	 * rely on the data already collected by the network
	 * subsystem
	 */
	struct tcp_memcontrol *tcp;
	struct mem_cgroup *parent = parent_mem_cgroup(memcg);
	struct net *net = current->nsproxy->net_ns;
	struct page_counter *counter_parent = NULL;
	struct cg_proto *cg_proto, *parent_cg;

	cg_proto = tcp_prot.proto_cgroup(memcg);
	if (!cg_proto)
		return 0;

	tcp = tcp_from_cgproto(cg_proto);

	tcp->tcp_prot_mem[0] = net->ipv4.sysctl_tcp_mem[0];
	tcp->tcp_prot_mem[1] = net->ipv4.sysctl_tcp_mem[1];
	tcp->tcp_prot_mem[2] = net->ipv4.sysctl_tcp_mem[2];
	tcp->tcp_memory_pressure = 0;

	parent_cg = tcp_prot.proto_cgroup(parent);
	if (parent_cg)
		counter_parent = parent_cg->memory_allocated;

	page_counter_init(&tcp->tcp_memory_allocated, counter_parent);
	percpu_counter_init(&tcp->tcp_sockets_allocated, 0, GFP_KERNEL);

	cg_proto->enter_memory_pressure = memcg_tcp_enter_memory_pressure;
	cg_proto->memory_pressure = &tcp->tcp_memory_pressure;
	cg_proto->sysctl_mem = tcp->tcp_prot_mem;
	cg_proto->memory_allocated = &tcp->tcp_memory_allocated;
	cg_proto->memcg = memcg;

	return 0;
}
EXPORT_SYMBOL(tcp_init_cgroup);

void tcp_destroy_cgroup(struct mem_cgroup *memcg)
{
	struct cg_proto *cg_proto;
	struct tcp_memcontrol *tcp;

	cg_proto = tcp_prot.proto_cgroup(memcg);
	if (!cg_proto)
		return;

	tcp = tcp_from_cgproto(cg_proto);
	percpu_counter_destroy(&tcp->tcp_sockets_allocated);
}
EXPORT_SYMBOL(tcp_destroy_cgroup);

static int tcp_update_limit(struct mem_cgroup *memcg, unsigned long nr_pages)
{
	struct net *net = current->nsproxy->net_ns;
	struct tcp_memcontrol *tcp;
	struct cg_proto *cg_proto;
	int i;
	int ret;

	cg_proto = tcp_prot.proto_cgroup(memcg);
	if (!cg_proto)
		return -EINVAL;

	tcp = tcp_from_cgproto(cg_proto);

	ret = page_counter_limit(&tcp->tcp_memory_allocated, nr_pages);
	if (ret)
		return ret;

	for (i = 0; i < 3; i++)
		tcp->tcp_prot_mem[i] = min_t(long, nr_pages,
					     net->ipv4.sysctl_tcp_mem[i]);

	if (nr_pages == PAGE_COUNTER_MAX)
		clear_bit(MEMCG_SOCK_ACTIVE, &cg_proto->flags);
	else {
		/*
		 * The active bit needs to be written after the static_key
		 * update. This is what guarantees that the socket activation
		 * function is the last one to run. See sock_update_memcg() for
		 * details, and note that we don't mark any socket as belonging
		 * to this memcg until that flag is up.
		 *
		 * We need to do this, because static_keys will span multiple
		 * sites, but we can't control their order. If we mark a socket
		 * as accounted, but the accounting functions are not patched in
		 * yet, we'll lose accounting.
		 *
		 * We never race with the readers in sock_update_memcg(),
		 * because when this value change, the code to process it is not
		 * patched in yet.
		 *
		 * The activated bit is used to guarantee that no two writers
		 * will do the update in the same memcg. Without that, we can't
		 * properly shutdown the static key.
		 */
		if (!test_and_set_bit(MEMCG_SOCK_ACTIVATED, &cg_proto->flags))
			static_key_slow_inc(&memcg_socket_limit_enabled);
		set_bit(MEMCG_SOCK_ACTIVE, &cg_proto->flags);
	}

	return 0;
}

enum {
	RES_USAGE,
	RES_LIMIT,
	RES_MAX_USAGE,
	RES_FAILCNT,
};

static DEFINE_MUTEX(tcp_limit_mutex);

static int tcp_cgroup_write(struct cgroup *cont, struct cftype *cft,
			    const char *buffer)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	unsigned long nr_pages;
	int ret = 0;

	switch (cft->private) {
	case RES_LIMIT:
		/* see memcontrol.c */
		ret = page_counter_memparse(buffer, &nr_pages);
		if (ret)
			break;
		mutex_lock(&tcp_limit_mutex);
		ret = tcp_update_limit(memcg, nr_pages);
		mutex_unlock(&tcp_limit_mutex);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static u64 tcp_cgroup_read(struct cgroup *cont, struct cftype *cft)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	struct cg_proto *cg_proto = tcp_prot.proto_cgroup(memcg);
	u64 val;

	switch (cft->private) {
	case RES_LIMIT:
		if (!cg_proto)
			return PAGE_COUNTER_MAX;
		val = cg_proto->memory_allocated->limit;
		val *= PAGE_SIZE;
		break;
	case RES_USAGE:
		if (!cg_proto)
			val = atomic_long_read(&tcp_memory_allocated);
		else
			val = page_counter_read(cg_proto->memory_allocated);
		val *= PAGE_SIZE;
		break;
	case RES_FAILCNT:
		if (!cg_proto)
			return 0;
		val = cg_proto->memory_allocated->failcnt;
		break;
	case RES_MAX_USAGE:
		if (!cg_proto)
			return 0;
		val = cg_proto->memory_allocated->watermark;
		val *= PAGE_SIZE;
		break;
	default:
		BUG();
	}
	return val;
}

static int tcp_cgroup_reset(struct cgroup *cont, unsigned int event)
{
	struct mem_cgroup *memcg;
	struct tcp_memcontrol *tcp;
	struct cg_proto *cg_proto;

	memcg = mem_cgroup_from_cont(cont);
	cg_proto = tcp_prot.proto_cgroup(memcg);
	if (!cg_proto)
		return 0;
	tcp = tcp_from_cgproto(cg_proto);

	switch (event) {
	case RES_MAX_USAGE:
		page_counter_reset_watermark(&tcp->tcp_memory_allocated);
		break;
	case RES_FAILCNT:
		tcp->tcp_memory_allocated.failcnt = 0;
		break;
	}

	return 0;
}

void tcp_prot_mem(struct mem_cgroup *memcg, long val, int idx)
{
	struct tcp_memcontrol *tcp;
	struct cg_proto *cg_proto;

	cg_proto = tcp_prot.proto_cgroup(memcg);
	if (!cg_proto)
		return;

	tcp = tcp_from_cgproto(cg_proto);

	tcp->tcp_prot_mem[idx] = val;
}

static struct cftype tcp_files[] = {
	{
		.name = "kmem.tcp.limit_in_bytes",
		.write_string = tcp_cgroup_write,
		.read_u64 = tcp_cgroup_read,
		.private = RES_LIMIT,
	},
	{
		.name = "kmem.tcp.usage_in_bytes",
		.read_u64 = tcp_cgroup_read,
		.private = RES_USAGE,
	},
	{
		.name = "kmem.tcp.failcnt",
		.private = RES_FAILCNT,
		.trigger = tcp_cgroup_reset,
		.read_u64 = tcp_cgroup_read,
	},
	{
		.name = "kmem.tcp.max_usage_in_bytes",
		.private = RES_MAX_USAGE,
		.trigger = tcp_cgroup_reset,
		.read_u64 = tcp_cgroup_read,
	},
	{ }	/* terminate */
};

static int __init tcp_memcontrol_init(void)
{
	WARN_ON(cgroup_add_cftypes(&mem_cgroup_subsys, tcp_files));
	return 0;
}
__initcall(tcp_memcontrol_init);
