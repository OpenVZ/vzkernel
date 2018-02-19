#
# Makefile for the FUSE filesystem.
#

obj-$(CONFIG_FUSE_FS) += fuse.o
obj-$(CONFIG_CUSE) += cuse.o

obj-$(CONFIG_FUSE_KIO_NOOP)	+= fuse_kio_noop.o
fuse_kio_noop-objs := kio/kio_noop.o

obj-$(CONFIG_FUSE_KIO_NULLIO)	+= fuse_kio_nullio.o
fuse_kio_nullio-objs := kio/kio_nullio.o

fuse-objs := dev.o dir.o file.o inode.o control.o
