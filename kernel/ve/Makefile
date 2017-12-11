#
#
#  kernel/ve/Makefile
#
#  Copyright (C) 2000-2005  SWsoft
#  All rights reserved.
#
#  Licensing governed by "linux/COPYING.SWsoft" file.

obj-$(CONFIG_VE) = ve.o veowner.o hooks.o
obj-$(CONFIG_VZ_WDOG) += vzwdog.o
obj-$(CONFIG_VE_CALLS) += vzmon.o

vzmon-objs = vecalls.o

obj-$(CONFIG_VZ_DEV) += vzdev.o
obj-$(CONFIG_VZ_EVENT) += vzevent.o
