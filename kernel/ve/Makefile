#
# kernel/ve/Makefile
#
# Copyright (c) 2000-2008 SWsoft
# Copyright (c) 2009-2015 Parallels IP Holdings GmbH
# Copyright (c) 2017-2021 Virtuozzo International GmbH. All rights reserved.
#

obj-$(CONFIG_VE) = ve.o hooks.o veowner.o

obj-$(CONFIG_VZ_DEV) += vzdev.o
obj-$(CONFIG_VZ_EVENT) += vzevent.o

obj-$(CONFIG_VE_CALLS) += vzmon.o
vzmon-objs = vecalls.o
