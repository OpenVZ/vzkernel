===================================
fs: per-CT sync behavior management
===================================

This feature makes it possible to tweak the effect of sync operations executed
by a Container. Possible options:

  * sync operations executed by a Container are noop
  * sync operations executed by a Container work like they are executed on Host
  * sync operations executed by a Container affect only filesystems mounted
    inside the Container, either in the Container root or nested mount
    namespaces

The behavior of sync operations executed by a Container is configured by
Virtuozzo specific ``fs.fsync-enable`` sysctl. The sysctl is virtualized
(its value is per-CT) and is writeable both on Host and inside Containers.

  * sync operations executed by Host do not depend on the sysctl value

  * sysctl values set on Host and inside a Container affect following syscalls
    executed in a Container:

     - sync(2), fsync(2), fdatasync(2), sync_file_range(2), msync(2)
     - open(2) and fcntl(2) (they silently clear O_SYNC flag if syncs should be
       ignored according to sysctl values)

Operation of AIO is not affected.

Changing this sysctl does not affect O_SYNC flag of already opened file
descriptors.

``fs.fsync-enable`` sysctl values
=================================

Host configuration
------------------

``fs.fsync-enable`` sysctl Host's value defines the default sync behavior inside
Containers on the Node. Possible values are:

  * 0 (FSYNC_DISABLED):
       sync operations inside Containers are no-ops
  * 1 (FSYNC_ALWAYS):
       sync operations inside Containers are fully executed, as if given on the
       Host itself
  * 2 (FSYNC_FILTERED), the default:
       sync operations inside Containers cause only writing dirty data to
       filesystems mounted anywhere inside Container, and don't affect any other
       dirty data existing on the Host.

Container configuration
-----------------------
  * 0 (FSYNC_DISABLED):
       sync operations inside this Container are no-ops, despite of setting on
       Host
  * 2 (FSYNC_FILTERED), the default:
       sync settings are taken from Host's sysctl value
  * 1 (FSYNC_ALWAYS) and other values:
       sync operations cause only writing dirty data to filesystems mounted
       anywhere inside Container, and don't affect any other dirty data existing
       on the Host/in other Containers.

  +-----------+---------+------------------------------------+
  |Host sysctl|CT sysctl|sync behavior inside CT             |
  +===========+=========+====================================+
  |     0     |    0    | noop                               |
  +-----------+---------+------------------------------------+
  |     1     |    0    | noop                               |
  +-----------+---------+------------------------------------+
  |     2     |    0    | noop                               |
  +-----------+---------+------------------------------------+
  |     0     |    1    | "filtered"                         |
  +-----------+---------+------------------------------------+
  |     1     |    1    | "filtered"                         |
  +-----------+---------+------------------------------------+
  |     2     |    1    | "filtered"                         |
  +-----------+---------+------------------------------------+
  |     0     |    2    | noop                               |
  +-----------+---------+------------------------------------+
  |     1     |    2    | syncs behave like executed on Host |
  +-----------+---------+------------------------------------+
  |     2     |    2    | "filtered" (default)               |
  +-----------+---------+------------------------------------+


https://jira.sw.ru/browse/PSBM-44684
