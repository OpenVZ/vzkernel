# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the FUSE filesystem.
#

obj-$(CONFIG_FUSE_FS) += fuse.o
obj-$(CONFIG_CUSE) += cuse.o
obj-$(CONFIG_VIRTIO_FS) += virtiofs.o

fuse-y := dev.o dir.o file.o inode.o control.o xattr.o acl.o readdir.o ioctl.o
fuse-$(CONFIG_FUSE_DAX) += dax.o

obj-$(CONFIG_FUSE_KIO_NOOP)	+= fuse_kio_noop.o
fuse_kio_noop-objs := kio/kio_noop.o

obj-$(CONFIG_FUSE_KIO_NULLIO)	+= fuse_kio_nullio.o
fuse_kio_nullio-objs := kio/kio_nullio.o

obj-$(CONFIG_FUSE_KIO_PCS)	+= fuse_kio_pcs.o
fuse_kio_pcs-objs := kio/pcs/pcs_fuse_kdirect.o \
	kio/pcs/pcs_sock_io.o \
	kio/pcs/pcs_rpc.o \
	kio/pcs/pcs_req.o \
	kio/pcs/pcs_map.o \
	kio/pcs/pcs_cluster.o \
	kio/pcs/pcs_cluster_core.o \
	kio/pcs/pcs_cs.o \
	kio/pcs/fuse_io.o \
	kio/pcs/fuse_stat.o \
	kio/pcs/pcs_sock_conn.o \
	kio/pcs/pcs_auth.o \
	kio/pcs/pcs_rdma_io.o \
	kio/pcs/pcs_rdma_rw.o \
	kio/pcs/pcs_rdma_conn.o \
	kio/pcs/pcs_net_addr.o \
	kio/pcs/pcs_cs_accel.o

virtiofs-y := virtio_fs.o
