#
# Makefile for the kernel block layer
#

obj-$(CONFIG_BLOCK) := elevator.o blk-core.o blk-tag.o blk-sysfs.o \
			blk-flush.o blk-settings.o blk-ioc.o blk-map.o \
			blk-exec.o blk-merge.o blk-softirq.o blk-timeout.o \
			blk-lib.o blk-mq.o blk-mq-tag.o blk-stat.o \
			blk-mq-sysfs.o blk-mq-cpu.o blk-mq-cpumap.o blk-mq-sched.o ioctl.o \
			genhd.o scsi_ioctl.o partition-generic.o partitions/ \
			badblocks.o

obj-$(CONFIG_BLK_DEV_BSG)	+= bsg.o
obj-$(CONFIG_BLK_DEV_BSGLIB)	+= bsg-lib.o
obj-$(CONFIG_BLK_CGROUP)	+= blk-cgroup.o
obj-$(CONFIG_BLK_DEV_THROTTLING)	+= blk-throttle.o
obj-$(CONFIG_IOSCHED_NOOP)	+= noop-iosched.o
obj-$(CONFIG_IOSCHED_DEADLINE)	+= deadline-iosched.o
obj-$(CONFIG_IOSCHED_CFQ)	+= cfq-iosched.o
obj-$(CONFIG_MQ_IOSCHED_DEADLINE)	+= mq-deadline.o
obj-$(CONFIG_MQ_IOSCHED_KYBER)	+= kyber-iosched.o

obj-$(CONFIG_BLOCK_COMPAT)	+= compat_ioctl.o
obj-$(CONFIG_BLK_DEV_INTEGRITY)	+= blk-integrity.o
obj-$(CONFIG_BLK_MQ_PCI)	+= blk-mq-pci.o
obj-$(CONFIG_BLK_DEBUG_FS)	+= blk-mq-debugfs.o
obj-$(CONFIG_BLK_DEV_CBT)	+= blk-cbt.o
obj-$(CONFIG_BLK_WBT)		+= blk-wbt.o
