#ifndef _ASM_S390_DMA_MAPPING_H
#define _ASM_S390_DMA_MAPPING_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/dma-attrs.h>
#include <linux/dma-debug.h>
#include <linux/io.h>

#define DMA_ERROR_CODE		(~(dma_addr_t) 0x0)

extern struct dma_map_ops s390_pci_dma_ops;
extern struct dma_map_ops *s390_dma_ops;

static inline struct dma_map_ops *get_arch_dma_ops(struct bus_type *bus)
{
	return s390_dma_ops;
}

static inline dma_addr_t phys_to_dma(struct device *dev, phys_addr_t paddr)
{
	return paddr;
}

static inline phys_addr_t dma_to_phys(struct device *dev, dma_addr_t daddr)
{
	return daddr;
}

#define HAVE_ARCH_DMA_SET_MASK 1
extern int dma_set_mask(struct device *dev, u64 mask);

static inline void dma_cache_sync(struct device *dev, void *vaddr, size_t size,
				  enum dma_data_direction direction)
{
}

static inline bool dma_capable(struct device *dev, dma_addr_t addr, size_t size)
{
	if (!dev->dma_mask)
		return false;
	return addr + size - 1 <= *dev->dma_mask;
}

static inline void dma_mark_clean(void *addr, size_t size)
{
}

#endif /* _ASM_S390_DMA_MAPPING_H */
