#
# Makefile for the FUSE filesystem.
#

obj-$(CONFIG_FUSE_FS) += fuse.o
obj-$(CONFIG_CUSE) += cuse.o

obj-$(CONFIG_FUSE_KIO_NOOP)	+= fuse_kio_noop.o
fuse_kio_noop-objs := kio/kio_noop.o

fuse-objs := dev.o dir.o file.o inode.o control.o
