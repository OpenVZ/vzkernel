#
# Makefile for the ia32 kernel emulation subsystem.
#

OBJECT_FILES_NON_STANDARD_ia32entry.o	:= y

obj-$(CONFIG_IA32_EMULATION) := ia32entry.o sys_ia32.o ia32_signal.o
obj-$(CONFIG_IA32_EMULATION) += nosyscall.o syscall_ia32.o

obj-$(CONFIG_IA32_AOUT) += ia32_aout.o

audit-class-$(CONFIG_AUDIT) := audit.o
obj-$(CONFIG_IA32_EMULATION) += $(audit-class-y)
