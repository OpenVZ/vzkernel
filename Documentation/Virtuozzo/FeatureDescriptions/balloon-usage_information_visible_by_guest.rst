===========================================
balloon: usage information visible by guest
===========================================

Background:
===========

The ballooning mechanism allows VM guests to reduce their memory size
(thus relinquishing memory to the Host) and to increase it back (thus
taking memory from the Host).

During OOM guest issues or even just Guest low performance issues
investigations it is important to know if the Host grabs some Guest
memory via ballooning mechanism.

Implementation description:
===========================

KVM     balloon guest file: /sys/kernel/debug/virtio-balloon
Hyper-V balloon guest file: /sys/kernel/debug/hv-balloon
VMware  balloon guest file: /sys/kernel/debug/vmmemctl

VMware balloon guest file presents for a long time already,
while Hyper-V and KVM balloon guest files were added recently.


The balloon statistics now is also printed by show_mem() function, which
in particular is called when OOM happens or Alt+SysRQ+m is pressed.

The show_mem() string looks like::

  Balloon InflatedTotal:XXXkB InflatedFree:YYYkB

- Non-zero "InflatedTotal" counter means the provided amount of memory
  is subtracted from total RAM reported inside the Guest.

- Non-zero "InflatedFree" counter means the provided amount of memory
  is accounted as "used" inside the Guest.

KVM balloon
-----------

The ballooning is implemented via virtio balloon device.

Depending on options the ballooned memory is accounted in two ways:

1. If deflate on OOM is enabled - ballooned memory is accounted as used.
2. If deflate on OOM is not enabled - ballooned memory is subtracted
   from total RAM.

Q: How to check if "deflate on OOM" feature is enabled?
A: Check balloon "features" file content.

To decipher balloon bits are defined in include/uapi/linux/virtio_balloon.h
Currently "deflate on OOM" feature is stored in the 2nd bit::

  #define VIRTIO_BALLOON_F_DEFLATE_ON_OOM 2 /* Deflate balloon on OOM */

Examples::

  Without deflate on OOM:
  # cat /sys/devices/pci0000:00/0000:00:03.0/virtio0/features
  0100000000000000000000000000110010000000000000000000000000000000

  With deflate on OOM:
  # cat /sys/devices/pci0000:00/0000:00:03.0/virtio0/features
  0110000000000000000000000000110010000000000000000000000000000000

How to find virtio balloon device among other virtio devices?
(check if the "virtio_balloon" module is loaded)::

  # ls -l /sys/bus/virtio/drivers/virtio_balloon/virtio*
    /sys/bus/virtio/drivers/virtio_balloon/virtio3 ->
        ../../../../devices/pci0000:00/0000:00:07.0/virtio3

To check virtio_balloon features::

  # cat /sys/bus/virtio/drivers/virtio_balloon/virtio*/features
  0110000000000000000000000000110010000000000000000000000000000000

Balloon guest statistics output example::

  # cat /sys/kernel/debug/virtio-balloon
  InflatedTotal: 0 kB
  InflatedFree: 0 kB

- If "InflatedTotal" is not zero, it means the "deflate on OOM" feature is
  **not** set and the provided amount of memory is subtracted from total RAM
  inside the Guest.

- If "InflatedFree" is not zero, it means "deflate on OOM" feature is set and
  the provided amount of memory is accounted as "used" inside the Guest.

- Both "InflatedTotal" and "InflatedFree" cannot be non-zero at the same time.

Hyper-V balloon
---------------

Balloon guest statistics output example::

  # cat /sys/kernel/debug/hv-balloon
  host_version : 2.0                // Hyper-V version the Guest is running under
  capabilities : enabled hot_add
  state : 1 (Initialized)
  page_size : 4096
  pages_added : 0                   // pages that are hot_add-ed to the Guest
  pages_onlined : 0                 // pages that are added and then put online
                                    // as available/used
  pages_ballooned_out : 0           // pages the Host have taken back
  vm_pages_commited : 795365        // total pages used by the Guest userspace
  total_pages_commited : 977790     // total pages used by the Guest user+kernel
  max_dynamic_page_count: 268435456 // maximum pages the Guest can have added
                                    // via hot_add

Hyper-V balloon driver changes TOTAL RAM size reported by the Guest,
thus the "InflatedTotal" counter will be non-zero in memory statistic
reported during OOM or upon Alt+SysRQ+m.

Hyper-V balloon
---------------

Balloon guest statistics output example::

  # cat /sys/kernel/debug/vmmemctl
  balloon capabilities: 0x1e
  used capabilities: 0x6
  is resetting: n
  target: 0 pages
  current: 0 pages
  rateSleepAlloc: 2048 pages/sec

  timer: 118
  doorbell: 0
  start: 1 ( 0 failed)
  guestType: 1 ( 0 failed)
  2m-lock: 0 ( 0 failed)
  lock: 0 ( 0 failed)
  2m-unlock: 0 ( 0 failed)
  unlock: 0 ( 0 failed)
  target: 118 ( 0 failed)
  prim2mAlloc: 0 ( 0 failed)
  primNoSleepAlloc: 0 ( 0 failed)
  primCanSleepAlloc: 0 ( 0 failed)
  prim2mFree: 0
  primFree: 0
  err2mAlloc: 0
  errAlloc: 0
  err2mFree: 0
  errFree: 0
  doorbellSet: 0
  doorbellUnset: 1

VMware balloon driver makes ballooned pages accounted as "used" in the
Guest OS thus the "InflatedFree" counter will be non-zero in memory
statistic reported during OOM or upon Alt+SysRQ+m.

https://jira.sw.ru/browse/PSBM-140408
https://jira.sw.ru/browse/PSBM-140409
https://jira.sw.ru/browse/PSBM-140407
https://jira.sw.ru/browse/PSBM-142436
