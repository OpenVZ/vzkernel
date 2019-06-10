/*
 *  include/net/udp_memcontrol.h
 *
 *  Copyright (c) 2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 */

#ifndef _UDP_MEMCG_H
#define _UDP_MEMCG_H

struct udp_memcontrol {
	struct cg_proto cg_proto;
	struct page_counter udp_memory_allocated;
	long udp_prot_mem[3];
};

struct cg_proto *udp_proto_cgroup(struct mem_cgroup *memcg);
int udp_init_cgroup(struct mem_cgroup *memcg, struct cgroup_subsys *ss);
void udp_destroy_cgroup(struct mem_cgroup *memcg);
#endif /* _UDP_MEMCG_H */
