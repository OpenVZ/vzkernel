#! /bin/bash

# This is the armv7hl override file for the core/drivers package split.  The
# module directories listed here and in the generic list in filter-modules.sh
# will be moved to the resulting kernel-modules package for this arch.
# Anything not listed in those files will be in the kernel-core package.
#
# Please review the default list in filter-modules.sh before making
# modifications to the overrides below.  If something should be removed across
# all arches, remove it in the default instead of per-arch.

driverdirs="atm auxdisplay bcma bluetooth firewire fpga infiniband media memstick message nfc ntb pcmcia ssb soundwire staging tty uio w1"

ethdrvs="3com adaptec alteon altera amd atheros broadcom cadence chelsio cisco dec dlink emulex mellanox micrel myricom natsemi neterion nvidia packetengines qlogic rdc sfc silan sis sun tehuti via wiznet xircom"

drmdrvs="amd arm armada bridge ast exynos etnaviv hisilicon i2c imx meson mgag200 msm nouveau omapdrm panel pl111 radeon rockchip sti stm sun4i tegra tilcdc tiny vc4"

singlemods="ntb_netdev iscsi_ibft iscsi_boot_sysfs megaraid pmcraid qedi qla1280 9pnet_rdma rpcrdma nvmet-rdma nvme-rdma hid-picolcd hid-prodikeys hwpoison-inject target_core_user sbp_target cxgbit chcr bq27xxx_battery_hdq mlx5_vdpa dfl-emif spi-altera-dfl"
