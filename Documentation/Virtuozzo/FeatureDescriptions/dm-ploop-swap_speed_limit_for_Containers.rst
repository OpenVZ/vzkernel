=========================================
dm-ploop: swap speed limit for Containers
=========================================

DRAFT. Userspace part not implemented yet.

Background:
===========

The idea of this feature: limit the Container swap speed limit to mitigate
possible Hardware Node DDoS.

What if a Container creates a nested memory cgroup and configures it as
following:

  * memory.limit_in_bytes = 1Mb
  * memory.memsw.limit_in_bytes = $CT_MEM_SIZE_LIMIT

and run memeaters inside it. This usecase will result in significant physical
swap usage on the Node, slowing down the Hardware Node.

If there are several such Container - they might influence significantly on the
overall Hardware Node performance.

High level implementation description:
======================================

Userspace (vzctl) on a Container start should find block devices where swap
resides (there could be multiple devices) and configure blkio cgroup of a
Container being started - to limit IO for that block device.

IO/IOPS limits is suggested to set as 1/4th of average SSD total throughput.

Note 1: we need to set limit for CT swap speed for the top block device, not
for a partition which is normally used for swap device, this is a kernel
limitation.

Note 2: we've hacked kernel so if ploop images reside on the same block device
(on a different partition, for example), blkio cgroup settings available on the
top block device do not affect io to ploop device.

As we understand the default 1/4th of io/iops of an average SSD throughput can
be easily not applicable for some nodes, there should be some settings in
vz.conf and in per-CT config for tweaking Containers swap speed limits,
including global option "on/off" per-CT.

Kernel changes:
===============

ploop: allow to disable css inheritance in kthread

We want to control swap and ploop i/o rate even if they are sharing
same physical disk. For this sake we need to disable css association
when pio is sent to kthread for further processing.

Usual schema is the following:

 # [root@vzl ~]# lsblk
 # NAME             MAJ:MIN  RM  SIZE RO TYPE MOUNTPOINTS
 # vda              253:0     0   60G  0 disk
 # ├─vda1           253:1     0    1M  0 part
 # ├─vda2           253:2     0    1G  0 part /boot
 # ├─vda3           253:3     0  3.9G  0 part [SWAP]
 # └─vda4           253:4     0   55G  0 part
 #   ├─vhs_vzl-root 250:0     0 15.7G  0 lvm  /
 #   └─vhs_vzl-vz   250:1     0 39.3G  0 lvm  /vz
 # ploop7186        250:7186  0   10G  0 dm
 # └─ploop7186p1    250:2     0   10G  0 dm   /vz/root/100

Since we can't setup limit for vda3 partition only (due to kernel
architecture), instead we assign a limit for the whole vda disk
from inside of container's block cgroup. Without the patch the
same limit applies to ploop7186 device as well. Thus to break
a tie we drop kthread's association and may setup a separate
limit for ploop device in a similar way (ie from inside container
block cgroup).

Note: for backward compatibility reason this feature is turned off
by default and "nokblkcg" argument is required for dmsetup utility
to untie the association.
Command line example::

  # dmsetup create dm_ploop -j $major -m 5 --table "0 $sectors ploop 11 nokblkcg ${fds}"

Once set up one can adjust io limits for $veid container executing
the following commands on the Node::

  #
  # #swap 1 mbs
  # echo “253:0 1000000” > \
      /sys/fs/cgroup/blkio/machine.slice/$veid/blkio.throttle.read_bps_device
  # echo “253:0 1000000” > \
      /sys/fs/cgroup/blkio/machine.slice/$veid/blkio.throttle.write_bps_device
  #
  # #ploop 10 mbs
  # echo “250:7186 10000000” > \
      /sys/fs/cgroup/blkio/machine.slice/$veid/blkio.throttle.read_bps_device
  # echo “250:7186 10000000” > \
      /sys/fs/cgroup/blkio/machine.slice/$veid/blkio.throttle.write_bps_device

Testing:
========

Useful script for making a ploop device for testing::

  #!/bin/bash

  set -x

  major=`cat /proc/devices | grep device-mapper | awk '{print $1}'`

  top_delta="${@:$#}"

  sectors=`dd if=$top_delta skip=36 bs=1 count=8 status=none | \
           hexdump -n 8 -e '2/4 "%08X " "\n"' | \
           awk '{print $2$1}'`
  sectors=$(( 16#$sectors ))
  echo sectors=$sectors

  for file in "$@"; do
          if [ ! -f "$file" ]; then
                  echo "$file does not exist"
                  exit 1
          fi

          exec {fd}<>$file || exit 1
          fds+="$fd "
  done

  dmsetup create dm_ploop -j $major -m 5 --table "0 $sectors ploop 11 nokblkcg ${fds}"

Script argument - path to the ploop image file, for example::

  /vz/private/100/root.hdd/root.hds

https://jira.sw.ru/browse/PSBM-139285
