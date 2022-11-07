======================
dm-ploop: standby mode
======================

Applicable configuration:
=========================

Currently the only example of a configuration which supports ploop
standby mode is the following:
 - vStorage is mounted on the Host
 - ploop device which image is stored on the vStorage
 - vStorage provides an iSCSI target which is built on that ploop
   device, the target is handled by the SCST kernel module

Background:
===========

Under certain circumstances vStorage can return -EBUSY/-ENOTCONN/-EIO on
a request handling.

Once this happens the ploop is switched to "standby mode" in which it
does not process userspace requests anymore, and vStorage userspace may
recover the ploop device by replacing the top delta, and after that the
ploop device may be functional again.

Implementation details:
=======================

Switching a ploop to the standby mode is implented via setting the
QUEUE_FLAG_STANDBY bit to the ploops request queue flags.

ploop standby mode should work only on devices that handle it.
To achieve this we have introduced a static key to enable the flag
handling only when key is enabled - checks are at the start and at the
end of every request and we want to avoid performance impact from these
checks.

How these static key/standby queue flag are going to be used:
 - The global "ploop_standby_check" static key is enabled in
   the SCST module init
 - SCST sets the QUEUE_STANDBY_EN bit when a ploop device is
   added to SCST, and clears it when it is deleted from SCST

On systems where we are in mixed mode, meaning we have both devices that
support the standby flag and devices that do not, a QUEUE_FLAG_STANDBY_EN
is introduced to indicate the standby support from the device.

Setting the QUEUE_FLAG_STANDBY_EN means the device promises to clear
QUEUE_FLAG_STANDBY flag when it recovers, so ploop can continue
processing requests.

To protect from errors we use the static key and the standby_en bit
as two fuses - if one is off we do not touch anything on the queue.
If we detect inconsistency at key or bits usage - we just warn
so it can be fixed.

The state of the flags is exported via /sys/block/*/queue/standby, or
at /sys/devices/virtual/block/*/queue/standby depending on the device.
 * not supported - no enabled on the queue
 * on  - queue is in standby mode, not processing requests
 * off - queue is processing requests

Differences in vz7/vz9 implementation:
--------------------------------------

When a ploop is switched to standby mode, its request queue flag
QUEUE_FLAG_STANDBY is set.

 * Once the bit is detected by SCST, the userspace will initiate
   recovery by replacing the top delta file without destroying the
   device, which is why the bit is cleared in ploop_replace_delta()
   in vz7.

 * In vz9, replace delta is achieved by table reload, which reallocates
   a new ploop instance, but keeps underlying mapped_device unchanged,
   thus request_queue unchanged, so we have to clear the bit in
   ploop_ctr().

https://jira.sw.ru/browse/PSBM-143049
