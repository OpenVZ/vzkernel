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
	 * The root cgroup does not use page_counters, but rather,
	 * rely on the data already collected by the network
	 * subsystem
	 */
	struct page_counter *counter_parent = NULL;
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
		counter_parent = parent_cg->memory_allocated;

	page_counter_init(&udp->udp_memory_allocated, counter_parent);

	cg_proto->sysctl_mem = udp->udp_prot_mem;
	cg_proto->memory_allocated = &udp->udp_memory_allocated;
	cg_proto->memcg = memcg;

	return 0;
}

void udp_destroy_cgroup(struct mem_cgroup *memcg)
{
}

static int udp_update_limit(struct mem_cgroup *memcg, unsigned long nr_pages)
{
	struct udp_memcontrol *udp;
	struct cg_proto *cg_proto;
	u64 old_lim;
	int i;
	int ret;

	cg_proto = udp_prot.proto_cgroup(memcg);
	if (!cg_proto)
		return -EINVAL;

	udp = udp_from_cgproto(cg_proto);

	old_lim = udp->udp_memory_allocated.limit;
	ret = page_counter_limit(&udp->udp_memory_allocated, nr_pages);
	if (ret)
		return ret;

	for (i = 0; i < 3; i++)
		udp->udp_prot_mem[i] = min_t(long, nr_pages, sysctl_udp_mem[i]);

	if (nr_pages == PAGE_COUNTER_MAX)
		clear_bit(MEMCG_SOCK_ACTIVE, &cg_proto->flags);
	else {
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

static DEFINE_MUTEX(udp_limit_mutex);

static int udp_cgroup_write(struct cgroup *cont, struct cftype *cft,
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

		mutex_lock(&udp_limit_mutex);
		ret = udp_update_limit(memcg, nr_pages);
		mutex_unlock(&udp_limit_mutex);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static u64 udp_cgroup_read(struct cgroup *cont, struct cftype *cft)
{
	struct mem_cgroup *memcg = mem_cgroup_from_cont(cont);
	struct cg_proto *cg_proto = udp_prot.proto_cgroup(memcg);

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
			val = atomic_long_read(&udp_memory_allocated);
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
		page_counter_reset_watermark(&udp->udp_memory_allocated);
		break;
	case RES_FAILCNT:
		cg_proto->memory_allocated->failcnt = 0;
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
