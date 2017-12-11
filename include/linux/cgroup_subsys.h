/* Add subsystem definitions of the form SUBSYS(<name>) in this
 * file. Surround each one by a line of comment markers so that
 * patches don't collide
 */

/*
 * This file *must* be included with SUBSYS() defined.
 * SUBSYS_TAG() is a noop if undefined.
 */

#ifndef SUBSYS_TAG
#define __TMP_SUBSYS_TAG
#define SUBSYS_TAG(_x)
#endif

/* */

/* */

#if IS_SUBSYS_ENABLED(CONFIG_CPUSETS)
SUBSYS(cpuset)
#endif

/* */

#if IS_SUBSYS_ENABLED(CONFIG_CGROUP_DEBUG)
SUBSYS(debug)
#endif

/* */

#if IS_SUBSYS_ENABLED(CONFIG_CGROUP_SCHED)
SUBSYS(cpu_cgroup)
#endif

/* */

#if IS_SUBSYS_ENABLED(CONFIG_CGROUP_CPUACCT)
SUBSYS(cpuacct)
#endif

/* */

#if IS_SUBSYS_ENABLED(CONFIG_MEMCG)
SUBSYS(mem_cgroup)
#endif

/* */

#if IS_SUBSYS_ENABLED(CONFIG_CGROUP_DEVICE)
SUBSYS(devices)
#endif

/* */

#if IS_SUBSYS_ENABLED(CONFIG_CGROUP_FREEZER)
SUBSYS(freezer)
#endif

/* */

#if IS_SUBSYS_ENABLED(CONFIG_NET_CLS_CGROUP)
SUBSYS(net_cls)
#endif

/* */

#if IS_SUBSYS_ENABLED(CONFIG_BLK_CGROUP)
SUBSYS(blkio)
#endif

/* */

#if IS_SUBSYS_ENABLED(CONFIG_CGROUP_PERF)
SUBSYS(perf)
#endif

/* */

#ifdef ENABLE_NETPRIO_NOW
SUBSYS(net_prio)
#endif

/* */

#if IS_SUBSYS_ENABLED(CONFIG_CGROUP_HUGETLB)
SUBSYS(hugetlb)
#endif

/* */

#ifdef CONFIG_CGROUP_BCACHE
SUBSYS(bcache)
#endif

#ifndef __GENKSYMS__
SUBSYS_TAG(CANFORK_START)

#if IS_SUBSYS_ENABLED(CONFIG_CGROUP_PIDS)
SUBSYS(pids)
#endif

SUBSYS_TAG(CANFORK_END)
#endif
/* */

#if IS_SUBSYS_ENABLED(CONFIG_VE)
SUBSYS(ve)
#endif

/* */

#ifdef __TMP_SUBSYS_TAG
#undef __TMP_SUBSYS_TAG
#undef SUBSYS_TAG
#endif
