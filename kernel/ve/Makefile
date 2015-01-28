#
# kernel/ve/Makefile
#
# Copyright (c) 2000-2015 Parallels IP Holdings GmbH
#

obj-$(CONFIG_VE) = ve.o veowner.o hooks.o vzstat_core.o ve-kobject.o
obj-$(CONFIG_VZ_WDOG) += vzwdog.o
obj-$(CONFIG_VE_CALLS) += vzmon.o

vzmon-objs = vecalls.o

obj-$(CONFIG_VZ_DEV) += vzdev.o
obj-$(CONFIG_VZ_EVENT) += vzevent.o

obj-m += vznetstat/vznetstat.o
obj-m += vznetstat/ip_vznetstat.o
obj-m += vznetstat/ip6_vznetstat.o

obj-m += vzlist.o
obj-m += vzstat.o

obj-m += dummy/ip6_vzprivnet.o
obj-m += dummy/ip_vzprivnet.o
obj-m += dummy/pio_nfs.o
obj-m += dummy/vzcompat.o
obj-m += dummy/vzcon.o
obj-m += dummy/vzdquota.o
obj-m += dummy/vziolimit.o
obj-m += dummy/vzlinkdev.o
obj-m += dummy/vzsnap.o
obj-m += dummy/vzcpt.o
obj-m += dummy/vzrst.o
