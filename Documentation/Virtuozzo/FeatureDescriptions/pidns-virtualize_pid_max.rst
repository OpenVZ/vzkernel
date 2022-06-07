=========================
pidns: virtualize pid_max
=========================

This feature makes ``kernel.pid_max`` sysctl be per pid namespace
(instead of a global sysctl by default).

**Q:** Why do we need this feature at all?
**A:**

1. historically is was implemented to support 32bit containers (pids with the
   value greater than 2^32 make 32bit userspace go mad)
2. this feature is needed for Containers online migration: if someone tries to
   migrate a process with pid XXX to the Hardware Node with pid_max < XXX, the
   migration will fail without iper-pidns pid_max support

https://jira.sw.ru/browse/PSBM-140308
