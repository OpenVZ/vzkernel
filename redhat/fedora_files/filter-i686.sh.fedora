#! /bin/bash

# This is the i686 override file for the core/drivers package split.  The
# module directories listed here and in the generic list in filter-modules.sh
# will be moved to the resulting kernel-modules package for this arch.
# Anything not listed in those files will be in the kernel-core package.
#
# Please review the default list in filter-modules.sh before making
# modifications to the overrides below.  If something should be removed across
# all arches, remove it in the default instead of per-arch.

driverdirs="atm auxdisplay bcma bluetooth firewire fpga infiniband leds media memstick mfd mmc mtd nfc ntb pcmcia platform power ssb soundwire staging tty uio w1"

singlemods="ntb_netdev iscsi_ibft iscsi_boot_sysfs megaraid pmcraid qedi qla1280 9pnet_rdma rpcrdma nvmet-rdma nvme-rdma hid-picolcd hid-prodikeys hwpoison-inject hid-sensor-hub hid-sensor-magn-3d hid-sensor-incl-3d hid-sensor-gyro-3d hid-sensor-iio-common hid-sensor-accel-3d hid-sensor-trigger hid-sensor-als hid-sensor-rotation hid-sensor-temperature hid-sensor-humidity target_core_user sbp_target cxgbit chcr parport_serial regmap-sdw hid-asus"
