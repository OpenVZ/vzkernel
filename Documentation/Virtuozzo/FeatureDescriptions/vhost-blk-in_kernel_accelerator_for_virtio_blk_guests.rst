======================================================
vhost-blk: in-kernel accelerator for virtio-blk guests
======================================================

Background:
===========

Right now each IO request from the guest goes in the following way:

* guest kernel puts IO request into virtio queue
* guest kernel performs VM exit
* host (in the context of VCPU thread) kicks IOthread in QEMU via
  ioevent fd and performs VM enter
* IOthread wakeups
* IO thread serves the request through
  - VirtIO BLK driver
  - QCOW2 format driver
  - host kernel
* once the request is completed (again, wakeup of userspace process) one
  should inject IRQ into the guest (one more context switch, syscall)

This process in lengthy and it is not scalable by the amount of guest
CPUs.

Disk latency can be reduced if we handle virtio-blk requests in Host
kernel (like it's done in VirtIO Net aka vhost_net module) so we avoid a
lot of syscalls and context switches.

The main problem with this approach *was* the absence of the
thin-provisioned virtual disk in the kernel and inability to perform the
backup.

The idea is quite simple - QEMU gives us block device and we translate
any incoming virtio requests into bio and push them into bdev.
The biggest disadvantage of this vhost-blk flavor is raw format.

Luckily Kirill Thai proposed device mapper driver for QCOW2 format to
attach files as block devices:
https://www.spinics.net/lists/kernel/msg4292965.html

Also by using kernel modules we can bypass iothread limitation and
finaly scale block requests with cpus for high-performance devices.


Implementation details:
=======================

There have already been several attempts to write vhost-blk:

- Asias'   version: https://lkml.org/lkml/2012/12/1/174
- Badari's version: https://lwn.net/Articles/379864/
- Vitaly's version: https://lwn.net/Articles/770965/

The main difference between them is API to access backend file. The
fastest one is Asias's version with bio flavor. It is also the most
reviewed and have the most features. So vhost_blk module is partially
based on it. Multiple virtqueue support was addded, some places
reworked. Added support for several vhost workers.

Test setup::

  fio --direct=1 --rw=randread  --bs=4k  --ioengine=libaio --iodepth=128
  QEMU drive options: cache=none
  filesystem: xfs

Test results::

  SSD:
                 | randread, IOPS  | randwrite, IOPS |
  Host           |      95.8k      |      85.3k      |
  QEMU virtio    |      57.5k      |      79.4k      |
  QEMU vhost-blk |      95.6k      |      84.3k      |

  RAMDISK (vq == vcpu):
                   | randread, IOPS | randwrite, IOPS |
  virtio, 1vcpu    |      123k      |      129k       |
  virtio, 2vcpu    |      253k (??) |      250k (??)  |
  virtio, 4vcpu    |      158k      |      154k       |
  vhost-blk, 1vcpu |      110k      |      113k       |
  vhost-blk, 2vcpu |      247k      |      252k       |
  vhost-blk, 8vcpu |      497k      |      469k       | single kernel thread
  vhost-blk, 8vcpu |      730k      |      701k       | two kernel threads


https://jira.sw.ru/browse/PSBM-139414

