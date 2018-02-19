#ifndef _PCS_IOCTL_H_
#define _PCS_IOCTL_H_ 1

#include <linux/ioctl.h>


#include "pcs_prot_types.h"
#include "pcs_mds_prot.h"
#include "pcs_error.h"
#include "pcs_map.h"
#include "pcs_rpc.h"

#define PCS_FUSE_INO_SPECIAL_ ((unsigned long long)-0x1000)

struct pcs_client_lease_info
{
	u32				type;
	u32				pad;
	struct pcs_pc_lease_info	info;
};

struct pcs_getleases_resp {
	u32				nleases;
	u32				nleases_total;
	struct pcs_client_lease_info	leases[0];
};

union pcs_getleases_ioc
{
	char				path[4096];
	struct pcs_getleases_resp	resp;
};

struct pcs_ioc_init_kdirect
{
	PCS_NODE_ID_T node_id;
	PCS_CLUSTER_ID_T cluster_id;
};

struct pcs_ioc_fileinfo
{
	struct pcs_mds_fileinfo fileinfo;
};

struct pcs_ioc_getmap
{
	PCS_CHUNK_UID_T		uid;		/* chunk unique id on out */
	PCS_MAP_VERSION_T	version;	/* in (on retry) / out */
	u64			chunk_start;	/* in / out */
	u64			chunk_end;	/* out */
	u32			state;		/* in/out: PCS_IOC_MAP_S_XXX */
#define PCS_IOC_MAP_S_READ	0x1
#define PCS_IOC_MAP_S_WRITE	0x2
#define PCS_IOC_MAP_S_NEW	0x4
#define PCS_IOC_MAP_S_ERROR	0x8
	pcs_error_t		error;		/* in/out */
	u16			mds_flags;	/* in/out */
	u32			psize_ret;	/* length of chunk on CS (out) */
	u32			chunk_psize;	/* physical size of chunk on CS on in */
	u32			read_tout;	/* read	 timeout (msec) on out */
	u32			write_tout;	/* write timeout (msec) on out */
	/* TODO: cs array is only for OUT ? */
	u32			cs_cnt;		/* The number of CS (including root) entries that follows */
	u32			cs_max;		/* Max number of CS (including root) entries requested */
	struct pcs_cs_info	cs[0];		/* Array of CS including root */
};

struct pcs_ioc_csconn
{
	PCS_NODE_ID_T		id;
	PCS_NET_ADDR_T		address;
	u32			flags;
#define PCS_IOC_CS_OPEN		0x1
#define PCS_IOC_CS_CLOSE	0x2
#define PCS_IOC_CS_REOPEN	(PCS_IOC_CS_OPEN|PCS_IOC_CS_CLOSE)
};

#define PCS_IOC_INIT_KDIRECT	_IOR('V',32, struct pcs_ioc_init_kdirect)
#define PCS_IOC_CSCONN		_IOR('V',33, struct pcs_ioc_csconn)
#define PCS_IOC_GETFILEINFO	_IOR('V',34, struct pcs_ioc_fileinfo)
#define PCS_IOC_KDIRECT_CLAIM	_IO('V',35)
#define PCS_IOC_KDIRECT_RELEASE _IO('V',36)
#define PCS_IOC_GETMAP		_IOWR('V',37, struct pcs_ioc_getmap)

#endif /* _PCS_IOCTL_H_ */
