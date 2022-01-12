// SPDX-License-Identifier: GPL-2.0

/*
 * Hyper-V stub IOMMU driver.
 *
 * Copyright (C) 2019, Microsoft, Inc.
 *
 * Author : Lan Tianyu <Tianyu.Lan@microsoft.com>
 */

#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/iommu.h>
#include <linux/module.h>

#include <asm/hw_irq.h>
#include <asm/io_apic.h>
#include <asm/irq_remapping.h>
#include <asm/hypervisor.h>

#include "irq_remapping.h"

#ifdef CONFIG_IRQ_REMAP

/*
 * According 82093AA IO-APIC spec , IO APIC has a 24-entry Interrupt
 * Redirection Table. Hyper-V exposes one single IO-APIC and so define
 * 24 IO APIC remmapping entries.
 */
#define IOAPIC_REMAPPING_ENTRY 24

static cpumask_t ioapic_max_cpumask = { CPU_BITS_NONE };

static int hyperv_ir_set_affinity(struct irq_data *data,
		const struct cpumask *mask, bool force)
{
	struct irq_cfg *cfg = data->chip_data;
	cpumask_t affinity_mask;
	int ret;

	/* Return error If new irq affinity is out of ioapic_max_cpumask. */
	if (!cpumask_subset(mask, &ioapic_max_cpumask))
		return -EINVAL;

	cpumask_and(&affinity_mask, mask, &ioapic_max_cpumask);
	ret = native_ioapic_set_affinity(data, &affinity_mask, force);
	if (ret)
		return ret;

	send_cleanup_vector(cfg);

	return 0;
}

static int hyperv_ir_setup_ioapic_entry(int irq,
				    struct IO_APIC_route_entry *route_entry,
				    unsigned int destination, int vector,
				    struct io_apic_irq_attr *attr)
{
	struct irq_cfg *cfg = irq_get_chip_data(irq);
	struct irq_data *irq_data = irq_get_irq_data(irq);
	unsigned int dest;
	int ret = 0;

	if (!irq_data || !cfg)
		return -EINVAL;

	/*
	 * Hypver-V IO APIC irq affinity should be in the scope of
	 * ioapic_max_cpumask because no irq remapping support.
	 */
	ret = __ioapic_set_affinity(irq_data, &ioapic_max_cpumask, &dest);
	if (ret)
		return ret;

	native_setup_ioapic_entry(irq, route_entry, dest, vector, attr);

	cfg->remapped = 1;

	return 0;
}


static int __init hyperv_prepare_irq_remapping(void)
{
	int i;

	if (x86_hyper != &x86_hyper_ms_hyperv ||
	    !x2apic_supported())
		return -ENODEV;

	/*
	 * Hyper-V doesn't provide irq remapping function for
	 * IO-APIC and so IO-APIC only accepts 8-bit APIC ID.
	 * Cpu's APIC ID is read from ACPI MADT table and APIC IDs
	 * in the MADT table on Hyper-v are sorted monotonic increasingly.
	 * APIC ID reflects cpu topology. There maybe some APIC ID
	 * gaps when cpu number in a socket is not power of two. Prepare
	 * max cpu affinity for IOAPIC irqs. Scan cpu 0-255 and set cpu
	 * into ioapic_max_cpumask if its APIC ID is less than 256.
	 */
	for (i = min_t(unsigned int, num_possible_cpus() - 1, 255); i >= 0; i--)
		if (cpu_physical_id(i) < 256)
			cpumask_set_cpu(i, &ioapic_max_cpumask);

	return 0;
}

static int __init hyperv_enable_irq_remapping(void)
{
	irq_remapping_enabled = 1;
	return IRQ_REMAP_X2APIC_MODE;
}

static int hyperv_msi_setup_irq(struct pci_dev *pdev, unsigned int irq,
				int index, int sub_handle)
{
	return 0;
}

static int hyperv_msi_alloc_irq(struct pci_dev *dev, int irq, int nvec)
{
	return 0;
}

struct irq_remap_ops hyperv_irq_remap_ops = {
	.prepare		= hyperv_prepare_irq_remapping,
	.enable			= hyperv_enable_irq_remapping,
	.set_affinity		= hyperv_ir_set_affinity,
	.setup_ioapic_entry	= hyperv_ir_setup_ioapic_entry,
	.msi_setup_irq          = hyperv_msi_setup_irq,
	.msi_alloc_irq          = hyperv_msi_alloc_irq,
};

#endif
