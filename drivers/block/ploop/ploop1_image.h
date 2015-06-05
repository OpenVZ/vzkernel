#ifndef __PLOOP1_IMAGE_H__
#define __PLOOP1_IMAGE_H__ 1

/* Definition of PVD (Parallels Virtual Disk) format
 *
 * 1. All the data are in ?little-endian? format.
 * 2. All the data except for the first cluster are aligned and padded
 *    to size of cluster. First cluster is exception - it combines
 *    PVD header (first 64 bytes of the cluster) with L2 index table
 *    (L2 index table is an array of indices of blocks)
 * 3. Image size must be multiple of cluster size. If it is not,
 *    we assume it is the result of image extension failed in the
 *    middle of transaction, therefore new allocations start at
 *    size rounded down to cluster size.
 * 4. Update of indices must be done only after data clusters
 *    are committed to reliable storage. If we fail to update index,
 *    we can get an unused and, maybe, uninitialized or partially
 *    initialized data cluster. It is lost, forgotten and ignored
 *    until repair or image rebuild.
 */

/*
 * copy/paste of IMAGE_PARAMETERS from DiskImageComp.h
 */
#pragma pack(push,1)
struct ploop_pvd_header
{
	__u8  m_Sig[16];          /* Signature */
	__u32 m_Type;             /* Disk type */
	__u32 m_Heads;            /* heads count */
	__u32 m_Cylinders;        /* tracks count */
	__u32 m_Sectors;          /* Sectors per track count */
	__u32 m_Size;             /* Size of disk in tracks */
	union {                   /* Size of disk in 512-byte sectors */
		struct {
			__u32 m_SizeInSectors_v1;
			__u32 Unused;
		};
		__u64 m_SizeInSectors_v2;
	};
	__u32 m_DiskInUse;        /* Disk in use */
	__u32 m_FirstBlockOffset; /* First data block offset (in sectors) */
	__u32 m_Flags;            /* Misc flags */
	__u8  m_Reserved[8];      /* Reserved */
};
#pragma pack(pop)

/* Compressed disk (version 1) */
#define PRL_IMAGE_COMPRESSED            2

/* Compressed disk v1 signature */
#define SIGNATURE_STRUCTURED_DISK_V1 "WithoutFreeSpace"

/* Compressed disk v2 signature */
#define SIGNATURE_STRUCTURED_DISK_V2 "WithouFreSpacExt"

/* Sign that the disk is in "using" state */
#define SIGNATURE_DISK_IN_USE		0x746F6E59

/* Disk was closed by software which conformed specification 2.0 */
#define SIGNATURE_DISK_CLOSED_V20	0x0

/* Disk disk was closed by software which conformed specification 2.1 */
#define SIGNATURE_DISK_CLOSED_V21	0x312e3276

/**
 * Compressed disk image flags
 */
#define	CIF_NoFlags		0x00000000 /* No any flags */
#define	CIF_Empty		0x00000001 /* No any data was written */
#define	CIF_Invalid		0xFFFFFFFF /* Invalid flag */


#define PLOOP1_SECTOR_LOG	9
#define PLOOP1_DEF_CLUSTER_LOG	9 /* 256K cluster-block */
#define CLUSTER (1UL << (PLOOP1_DEF_CLUSTER_LOG + PLOOP1_SECTOR_LOG))

/* Helpers to generate PVD-header based on requested bdsize */

#define DEFAULT_HEADS_COUNT   16
#define DEFAULT_SECTORS_COUNT 63
#define SECTOR_SIZE (1 << 9)

struct CHSData
{
	__u32 Sectors;
	__u32 Heads;
	__u32 Cylinders;
};

#ifdef __KERNEL__
# define ploop_do_div(n, base) do_div(n, base)
#else
# define ploop_do_div(n, base) ({		\
	__u32 __rem = n % base;			\
	n /= base;				\
	__rem;					\
 })
#endif
/*
 * Try to count disk sectors per track value
 */
static inline __u32
CalcSectors(const __u64 uiSize)
{
	__u64 size = uiSize;

	/* Try to determine sector count */
	if (!ploop_do_div(size, DEFAULT_SECTORS_COUNT))
		return DEFAULT_SECTORS_COUNT;

	if (!(uiSize % 32))
		return 32;

	if (!(uiSize % 16))
		return 16;

	if (!(uiSize % 8))
		return 8;

	return ~0;
}

/*
 * Try to count disk heads value
 */
static inline __u32
CalcHeads(const __u64 uiSize)
{
	__u64 size = uiSize;

	/* Try to determine heads count */
	if (!ploop_do_div(size, DEFAULT_HEADS_COUNT))
		return DEFAULT_HEADS_COUNT;

	if (!(uiSize % 8))
		return 8;

	if (!(uiSize % 4))
		return 4;

	if (!(uiSize % 2))
		return 2;

	return ~0;
}

/*
 * Convert size to CHS for disks from 504 Mb to 8 Gb
 */
static inline void
ConvertToCHSLow(__u64 From, struct CHSData *chs)
{
	chs->Sectors = DEFAULT_SECTORS_COUNT;
	chs->Heads = DEFAULT_HEADS_COUNT;
	ploop_do_div(From, DEFAULT_SECTORS_COUNT * DEFAULT_HEADS_COUNT);
	chs->Cylinders = From;
}

/*
 * Convert size to pure LBA config
 */
static inline void
ConvertToPureLBA(__u64 From, struct CHSData *chs)
{
	chs->Sectors = 1;
	chs->Heads = 1;
	chs->Cylinders = From;
}

static inline void
ConvertToCHS(__u64 From, struct CHSData *chs)
{
	__u64 Size;

	/*
	 * According to ATA2 specs:
	 *  - If the device is above 1,032,192 sectors then the value should be 63.
	 *    This value does not exceed 63 (3Fh). But note, that if device size
	 *    above 16,777,216 the HDD reports proper 'magic' number in CHS values,
	 *    so the situation in the middle must be handled separately
	 */
	if ((From > 1032192) && (From < 16777216))
	{
		ConvertToCHSLow(From, chs);
		return;
	}

	Size = From;

	/* Store size */
	chs->Sectors = CalcSectors(Size);

	if (chs->Sectors == (__u32)~0)
		goto PureLBA;

	ploop_do_div(Size, chs->Sectors);

	chs->Heads = CalcHeads(Size);

	if (chs->Heads == (__u32)~0)
		goto PureLBA;

	ploop_do_div(Size, chs->Heads);

	chs->Cylinders = Size;

	return;

PureLBA:
	ConvertToPureLBA(From, chs);
}

static inline __u32
GetHeaderSize(__u32 m_Size)
{
	__u32 Size = sizeof(struct ploop_pvd_header);

	/* Add BAT */
	Size += m_Size * sizeof(__u32);
	/* Align to size of sector */
	Size = (Size + SECTOR_SIZE - 1) & ~(SECTOR_SIZE - 1);

	return Size;
}

static inline char *
ploop1_signature(int version)
{
	switch (version) {
	case PLOOP_FMT_V1:
		return SIGNATURE_STRUCTURED_DISK_V1;
	case PLOOP_FMT_V2:
		return SIGNATURE_STRUCTURED_DISK_V2;
#ifdef __KERNEL__
	default:
		BUG();
#endif
	}

	return NULL;
}

static inline int
ploop1_version(struct ploop_pvd_header *vh)
{
	if (!memcmp(vh->m_Sig, SIGNATURE_STRUCTURED_DISK_V1, sizeof(vh->m_Sig)))
		return PLOOP_FMT_V1;

	if (!memcmp(vh->m_Sig, SIGNATURE_STRUCTURED_DISK_V2, sizeof(vh->m_Sig)))
		return PLOOP_FMT_V2;

	return -1;
}

static inline __u64
ploop1_max_size(__u32 blocksize, int version)
{
	switch (version) {
	case PLOOP_FMT_V1:
		return (__u32)-1;
	case PLOOP_FMT_V2:
		return 0xffffffffUL * blocksize;
	}

	return 0;
}

#ifdef __KERNEL__
static inline u64
get_SizeInSectors_from_le(struct ploop_pvd_header *vh, int version)
{
	switch (version) {
	case PLOOP_FMT_V1:
		return le32_to_cpu(vh->m_SizeInSectors_v1);
	case PLOOP_FMT_V2:
		return le64_to_cpu(vh->m_SizeInSectors_v2);
	default:
		BUG();
	}

	return 0;
}

static inline void
put_SizeInSectors(u64 SizeInSectors, struct ploop_pvd_header *vh,
		  int version)
{
	switch (version) {
	case PLOOP_FMT_V1:
		vh->m_SizeInSectors_v1 = SizeInSectors;
		break;
	case PLOOP_FMT_V2:
		vh->m_SizeInSectors_v2 = SizeInSectors;
		break;
	default:
		BUG();
	}
}

static inline void
cpu_to_le_SizeInSectors(struct ploop_pvd_header *vh, int version)
{
	switch (version) {
	case PLOOP_FMT_V1:
		vh->m_SizeInSectors_v1 = cpu_to_le32(vh->m_SizeInSectors_v1);
		break;
	case PLOOP_FMT_V2:
		vh->m_SizeInSectors_v2 = cpu_to_le64(vh->m_SizeInSectors_v2);
		break;
	default:
		BUG();
	}
}
#endif

/*
 * Returns: "size to fill" (in bytes)
 *
 * NB: m_Flags and m_DiskInUse are being kept as is; our caller
 * should take care of them.
 *
 * NB: Both bdsize and blocksize are measured in sectors.
 */
static inline __u32
generate_pvd_header(struct ploop_pvd_header *vh, __u64 bdsize, __u32 blocksize,
		    int version)
{
	struct CHSData chs;
	__u32 SizeToFill;
	__u32 uiAlignmentSize;
	__u64 SizeInSectors;

	memcpy(vh->m_Sig, ploop1_signature(version) , sizeof(vh->m_Sig));
	vh->m_Type = PRL_IMAGE_COMPRESSED;

	/* Round up to block size */
	SizeInSectors = bdsize + blocksize - 1;
	ploop_do_div(SizeInSectors, blocksize);
	SizeInSectors *= blocksize;
	put_SizeInSectors(SizeInSectors, vh, version);

	ConvertToCHS(SizeInSectors, &chs);

	vh->m_Sectors = blocksize;
	vh->m_Heads = chs.Heads;
	vh->m_Cylinders = chs.Cylinders;

	ploop_do_div(SizeInSectors, blocksize);
	vh->m_Size = SizeInSectors;

	uiAlignmentSize = blocksize << 9;
	SizeToFill = GetHeaderSize(vh->m_Size);
	/* Align to block size */
	if (SizeToFill % uiAlignmentSize)
		SizeToFill += uiAlignmentSize - (SizeToFill % uiAlignmentSize);

	vh->m_FirstBlockOffset = SizeToFill >> 9;

	return SizeToFill;
}

static inline bool pvd_header_is_disk_in_use(struct ploop_pvd_header *vh)
{
	return (vh->m_DiskInUse == cpu_to_le32(SIGNATURE_DISK_IN_USE)) ?
		true : false;
}

static inline void pvd_header_set_disk_in_use(struct ploop_pvd_header *vh)
{
	vh->m_DiskInUse = cpu_to_le32(SIGNATURE_DISK_IN_USE);
}

static inline void pvd_header_set_disk_closed(struct ploop_pvd_header *vh)
{
	vh->m_DiskInUse = cpu_to_le32(SIGNATURE_DISK_CLOSED_V20);
}

/* Translation of sector number to offset in image */

#if 0

/* Those function are not really used */

/* Calculate virtual cluster number from virtual sector number */

static inline __u32
ploop1_cluster(struct ploop_img_header * info, __u64 sector)
{
	return sector >> info->cluster_log;
}

/* Get amount of clusters covered by one L2 table, 32K by default,
 * which can map 4G of data
 */
static inline __u32
ploop1_clusters_per_l2(struct ploop_img_header * info)
{
	return 1 << (info->cluster_log + info->sector_log - 2);
}

/* Calculate index in L1 table mapping a cluster. */

static inline __u32
ploop1_l1_index(struct ploop_img_header * info, __u32 cluster)
{
	return cluster >> (info->cluster_log + info->sector_log - 2);
}

/* Calculate index in L2 table mapping a cluster. */

static inline __u32
ploop1_l2_index(struct ploop_img_header * info, __u32 cluster)
{
	return cluster & (ploop1_clusters_per_l2(info) - 1);
}

/* That's all, simple and stupid */

#endif

#endif /* __PLOOP1_IMAGE_H__ */
