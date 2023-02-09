==================================
mm: Memory cgroup page cache limit
==================================

The feature enhances memory cgroup to be able to limit its page cache
usage.

Feature exposes two memory cgroup files to set limit and to check
usage::

  memory::memory.cache.limit_in_bytes
  memory::memory.cache.usage_in_bytes

Background:
===========

Imagine a system service which anon memory you don't want to limit.
In our case it's a vStorage cgroup which hosts CSes and MDSes:

 * they can consume memory in some range
 * we don't want to set a limit for max possible consumption - too high
 * we don't know the number of CSes on the node - admin can add CSes
   dynamically
 * we don't want to dynamically increase/decrease the limit

If the cgroup is "unlimited" it produces permanent memory pressure on
the Node because it generates a lot of pagecache and other cgroups on
the Node are affected (even taking into account the fact of proportional
fair reclaim).

=> the solution is to limit pagecache only, so this is implemented.

Implementation details:
=======================

 * Reclaiming memory above memory.cache.limit_in_bytes always in direct
   reclaim mode adds too much of a cost for vStorage. Instead of direct
   Thus the code allows to overflow memory.cache.limit_in_bytes but
   launches the reclaim in background task.

 * Per-cpu stock precharges are used for ->cache counter to decrease the
   contention on this counter.

Differences in vz7/vz9 implementation:
--------------------------------------

 * vz9 does not use the page vz extensions in favor of using a memcg_data
   bit to mark a page as cache. The benefit is that the implementation
   and porting got more simple. If we require new flags then the newly
   introduced folio can be used.

Testing:
========

Simple test::

  # dd if=/dev/random of=testfile.bin bs=1M count=1000
  # mkdir /sys/fs/cgroup/memory/pagecache_limiter
  # tee /sys/fs/cgroup/memory/pagecache_limiter/memory.cache.limit_in_bytes <<< $[2**24]
  # bash
  # echo $$ > /sys/fs/cgroup/memory/pagecache_limiter/tasks
  # cat /sys/fs/cgroup/memory/pagecache_limiter/memory.cache.usage_in_bytes
  # time wc -l testfile.bin
  # cat /sys/fs/cgroup/memory/pagecache_limiter/memory.cache.usage_in_bytes
  # echo 3 > /proc/sys/vm/drop_caches
  # cat /sys/fs/cgroup/memory/pagecache_limiter/memory.cache.usage_in_bytes


https://jira.sw.ru/browse/PSBM-77547 - initial problem
https://jira.sw.ru/browse/PSBM-78244 - feature jira ID
