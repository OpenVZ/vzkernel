#
# User resources part (UBC)
#
# Copyright (C) 2005  SWsoft
# All rights reserved.
#
# Licensing governed by "linux/COPYING.SWsoft" file.

obj-y := sys.o beancounter.o misc.o \
	 vm_pages.o statd.o

obj-$(CONFIG_BC_PROC)  += proc.o
obj-$(CONFIG_BC_IO_ACCOUNTING) += io_acct.o

CFLAGS_io_prio.o := -Iblock
obj-$(CONFIG_BC_IO_PRIORITY) += io_prio.o
