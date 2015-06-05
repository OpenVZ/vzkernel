#include <net/udp.h>
#include <net/udp_memcontrol.h>
#include <net/sock.h>
#include <net/ip.h>
#include <linux/nsproxy.h>
#include <linux/memcontrol.h>
#include <linux/module.h>

/*
 * The below code is copied from tcp_memcontrol.c with
 * s/tcp/udp/g and knowledge that udp doesn't need mem
 * pressure state and sockets_allocated counter.
 */

static inline struct udp_memcontrol *udp_from_cgproto(struct cg_proto *cg_proto)
{
	return container_of(cg_proto, struct udp_memcontrol, cg_proto);
}

int udp_init_cgroup(struct mem_cgroup *memcg, struct cgroup_subsys *ss)
{
	/*
	 * The root cgroup does not use res_counters, but rather,
	 * rely on the data already collected by the network
	 * subsystem
	 */
	struct res_counter *res_parent = NULL;
	struct cg_proto *cg_proto, *parent_cg;
	struct udp_memcontrol *udp;
	struct mem_cgroup *parent = parent_mem_cgroup(memcg);

	cg_proto = udp_prot.proto_cgroup(memcg);
	if (!cg_proto)
		return 0;

	udp = udp_from_cgproto(cg_proto);

	udp->udp_prot_mem[0] = sysctl_udp_mem[0];
	udp->udp_prot_mem[1] = sysctl_udp_mem[1];
	udp->udp_prot_mem[2] = sysctl_udp_mem[2];

	parent_cg = udp_prot.proto_cgroup(parent);
	if (parent_cg)
		res_parent = parent_cg->memory_allocated;

	res_counter_init(&udp->udp_memory_allocated, res_parent);

	cg_proto->sysctl_mem = udp->udp_prot_mem;
	cg_proto->memory_allocated = &udp->udp_memory_allocated;
	cg_proto->memcg = memcg;

	return 0;
}

void udp_destroy_cgroup(struct mem_cgroup *memcg)
{
}

static int udp_update_limit(struct mem_cgroup *memcg, u64 val)
{
	struct udp_memcontrol *udp;
	struct cg_proto *cg_proto;
	u64 old_lim;
	int i;
	int ret;

	cg_proto = udp_prot.proto_cgroup(memcg);
	if (!cg_proto)
		return -EINVAL;

	if (val > RESOURCE_MAX)
		val = RESOURCE_MAX;

	udp = udp_from_cgproto(cg_proto);

	old_lim = res_counter_read_u64(&udp->udp_memory_allocated, RES_LIMIT);
	ret = res_counter_set_limit(&udp->udp_memory_allocated, val);
	if (ret)
		return ret;

	for (i = 0; i < 3; i++)
		udp->udp_prot_mem[i] = min_t(long, val >> PAGE_SHIFT, sysctl_udp_mem[i]);

	if (val == RESOURCE_MAX)
		clear_bit(MEMCG_SOCK_ACTIVE, &cg_proto->flags);
	else if (val != RESOURCE_MAX) {
		if (!test_and_set_bit(MEMCG_SOCK_ACTIVATED, &cg_proto->flags))
			static_key_slow_inc(&memcg_socket_limit_enabled);
		set_bit(MEMCG_SOCK_ACTIVE, &cg_proto->flags);
	}

	return 0;
}

static int udp_cgroup_write(struct cgroup *cont, struct cftype *cft,
			    const char *buffer)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	unsigned long long val;
	int ret = 0;

	switch (cft->private) {
	case RES_LIMIT:
		/* see memcontrol.c */
		ret = res_counter_memparse_write_strategy(buffer, &val);
		if (ret)
			break;
		ret = udp_update_limit(memcg, val);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static u64 udp_read_stat(struct mem_cgroup *memcg, int type, u64 default_val)
{
	struct udp_memcontrol *udp;
	struct cg_proto *cg_proto;

	cg_proto = udp_prot.proto_cgroup(memcg);
	if (!cg_proto)
		return default_val;

	udp = udp_from_cgproto(cg_proto);
	return res_counter_read_u64(&udp->udp_memory_allocated, type);
}

static u64 udp_read_usage(struct mem_cgroup *memcg)
{
	struct udp_memcontrol *udp;
	struct cg_proto *cg_proto;

	cg_proto = udp_prot.proto_cgroup(memcg);
	if (!cg_proto)
		return atomic_long_read(&udp_memory_allocated) << PAGE_SHIFT;

	udp = udp_from_cgproto(cg_proto);
	return res_counter_read_u64(&udp->udp_memory_allocated, RES_USAGE);
}

static u64 udp_cgroup_read(struct cgroup *cont, struct cftype *cft)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	u64 val;

	switch (cft->private) {
	case RES_LIMIT:
		val = udp_read_stat(memcg, RES_LIMIT, RESOURCE_MAX);
		break;
	case RES_USAGE:
		val = udp_read_usage(memcg);
		break;
	case RES_FAILCNT:
	case RES_MAX_USAGE:
		val = udp_read_stat(memcg, cft->private, 0);
		break;
	default:
		BUG();
	}
	return val;
}

static int udp_cgroup_reset(struct cgroup *cont, unsigned int event)
{
	struct mem_cgroup *memcg;
	struct udp_memcontrol *udp;
	struct cg_proto *cg_proto;

	memcg = mem_cgroup_from_cont(cont);
	cg_proto = udp_prot.proto_cgroup(memcg);
	if (!cg_proto)
		return 0;
	udp = udp_from_cgproto(cg_proto);

	switch (event) {
	case RES_MAX_USAGE:
		res_counter_reset_max(&udp->udp_memory_allocated);
		break;
	case RES_FAILCNT:
		res_counter_reset_failcnt(&udp->udp_memory_allocated);
		break;
	}

	return 0;
}

static struct cftype udp_files[] = {
	{
		.name = "kmem.udp.limit_in_bytes",
		.write_string = udp_cgroup_write,
		.read_u64 = udp_cgroup_read,
		.private = RES_LIMIT,
	},
	{
		.name = "kmem.udp.usage_in_bytes",
		.read_u64 = udp_cgroup_read,
		.private = RES_USAGE,
	},
	{
		.name = "kmem.udp.failcnt",
		.private = RES_FAILCNT,
		.trigger = udp_cgroup_reset,
		.read_u64 = udp_cgroup_read,
	},
	{
		.name = "kmem.udp.max_usage_in_bytes",
		.private = RES_MAX_USAGE,
		.trigger = udp_cgroup_reset,
		.read_u64 = udp_cgroup_read,
	},
	{ }	/* terminate */
};

static int __init udp_memcontrol_init(void)
{
	WARN_ON(cgroup_add_cftypes(&mem_cgroup_subsys, udp_files));
	return 0;
}
__initcall(udp_memcontrol_init);
