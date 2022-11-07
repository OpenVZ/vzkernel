#ifndef _POWERNV_H
#define _POWERNV_H

#ifdef CONFIG_SMP
extern void pnv_smp_init(void);
#else
static inline void pnv_smp_init(void) { }
#endif

struct pci_dev;

#ifdef CONFIG_PCI
extern void pnv_pci_init(void);
extern void pnv_pci_shutdown(void);
extern u64 pnv_pci_dma_get_required_mask(struct pci_dev *pdev);
#else
static inline void pnv_pci_init(void) { }
static inline void pnv_pci_shutdown(void) { }

static inline u64 pnv_pci_dma_get_required_mask(struct pci_dev *pdev)
{
	return 0;
}
#endif

extern u32 pnv_get_supported_cpuidle_states(void);

extern void pnv_lpc_init(void);

extern void opal_handle_events(void);
extern bool opal_have_pending_events(void);
extern void opal_event_shutdown(void);

bool cpu_core_split_required(void);

#endif /* _POWERNV_H */
