/*
 * Arch specific extensions to struct device
 *
 * This file is released under the GPLv2
 */
#ifndef _ASM_POWERPC_DEVICE_H
#define _ASM_POWERPC_DEVICE_H

struct dma_map_ops;
struct device_node;
struct iommu_table;

struct dev_arch_dmadata {
	/*
	 * These two used to be a union. However, with the hybrid ops we need
	 * both so here we store both a DMA offset for direct mappings and
	 * an iommu_table for remapped DMA.
	 */
	dma_addr_t		dma_offset;

#ifdef CONFIG_PPC64
	struct iommu_table	*iommu_table_base;
#endif
};

/*
 * Arch extensions to struct device.
 *
 * When adding fields, consider macio_add_one_device in
 * drivers/macintosh/macio_asic.c
 */
struct dev_archdata {
	/* DMA operations on that device */
	RH_KABI_DEPRECATE(struct dma_map_ops *, dma_ops)

	RH_KABI_REPLACE(union { dma_addr_t dma_offset; void *iommu_table_base; }dma_data,
	                struct dev_arch_dmadata *hybrid_dma_data)

#ifdef CONFIG_SWIOTLB
	dma_addr_t		max_direct_dma_addr;
#endif
#ifdef CONFIG_EEH
	struct eeh_dev		*edev;
#endif
#ifdef CONFIG_FAIL_IOMMU
	int fail_iommu;
#endif
#ifdef CONFIG_CXL_BASE
	RH_KABI_EXTEND(struct cxl_context       *cxl_ctx)
#endif
};

struct pdev_archdata {
	u64 dma_mask;
};

#define ARCH_HAS_DMA_GET_REQUIRED_MASK

#endif /* _ASM_POWERPC_DEVICE_H */
