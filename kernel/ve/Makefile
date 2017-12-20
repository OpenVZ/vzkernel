#
# kernel/ve/Makefile
#
# Copyright (c) 2000-2017 Virtuozzo International GmbH.  All rights reserved.
#

obj-$(CONFIG_VE) = ve.o hooks.o veowner.o vzstat_core.o

obj-$(CONFIG_VZ_DEV) += vzdev.o
obj-$(CONFIG_VZ_EVENT) += vzevent.o

obj-$(CONFIG_VE_CALLS) += vzmon.o
vzmon-objs = vecalls.o

obj-$(CONFIG_VE_CALLS) += vzstat.o
