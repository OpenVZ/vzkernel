#ifndef _FUSE_KTRACE_PROT_H_
#define _FUSE_KTRACE_PROT_H_ 1

#define FUSE_TRACE_MAGIC 0xf59c
#define FUSE_KTRACE_SIZE (512 * 1024)
#define FUSE_KTRACE_NR   (4)

struct fuse_trace_hdr
{
	__u16	magic;
	__u16	type;
	__u16	pdu_len;
	__u16	ovfl;
	__u64	time;
};

#define FUSE_KTRACE_STRING	1
#define FUSE_KTRACE_IOTIMES	2

struct fuse_tr_iotimes_hdr
{
	__u64	chunk;
	__u64	offset;
	__u64	size;
	__u64	start_time;
	__u32	local_delay;
	__u32	lat;
	__u64	ino;
	__u16	type;
	__u8	cses;
	__u8	__pad;
	__u32	__pad1;
};

struct fuse_tr_iotimes_cs
{
	__u64	csid;
	__u64	misc;
	__u32	ts_net;
	__u32	ts_io;
};

#endif /* _FUSE_KTRACE_PROT_H_ */
