/*
 * X86 specific Hyper-V initialization code.
 *
 * Copyright (C) 2016, Microsoft, Inc.
 *
 * Author : K. Y. Srinivasan <kys@microsoft.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE, GOOD TITLE or
 * NON INFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 */

#include <linux/efi.h>
#include <linux/types.h>
#include <asm/hypervisor.h>
#include <asm/hyperv.h>
#include <asm/mshyperv.h>
#include <asm/fixmap.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/clockchips.h>
#include <linux/hyperv.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/kaiser.h>
#include <linux/kernel.h>

#ifdef CONFIG_HYPERV_TSCPAGE

static struct ms_hyperv_tsc_page *tsc_pg;

struct ms_hyperv_tsc_page *hv_get_tsc_page(void)
{
	return tsc_pg;
}

static u64 read_hv_clock_tsc(struct clocksource *arg)
{
	u64 current_tick = hv_read_tsc_page(tsc_pg);

	if (current_tick == U64_MAX)
		rdmsrl(HV_X64_MSR_TIME_REF_COUNT, current_tick);

	return current_tick;
}

static struct clocksource hyperv_cs_tsc = {
		.name		= "hyperv_clocksource_tsc_page",
		.rating		= 400,
		.read		= read_hv_clock_tsc,
		.mask		= CLOCKSOURCE_MASK(64),
		.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};
#endif

static u64 read_hv_clock_msr(struct clocksource *arg)
{
	u64 current_tick;
	/*
	 * Read the partition counter to get the current tick count. This count
	 * is set to 0 when the partition is created and is incremented in
	 * 100 nanosecond units.
	 */
	rdmsrl(HV_X64_MSR_TIME_REF_COUNT, current_tick);
	return current_tick;
}

static struct clocksource hyperv_cs_msr = {
	.name		= "hyperv_clocksource_msr",
	.rating		= 400,
	.read		= read_hv_clock_msr,
	.mask		= CLOCKSOURCE_MASK(64),
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};

void *hv_hypercall_pg;
EXPORT_SYMBOL_GPL(hv_hypercall_pg);
struct clocksource *hyperv_cs;
EXPORT_SYMBOL_GPL(hyperv_cs);

u32 *hv_vp_index;
EXPORT_SYMBOL_GPL(hv_vp_index);

u32 hv_max_vp_index;
EXPORT_SYMBOL_GPL(hv_max_vp_index);

static void hv_cpu_init(void *arg)
{
	u64 msr_vp_index;

	hv_get_vp_index(msr_vp_index);

	hv_vp_index[smp_processor_id()] = msr_vp_index;

	if (msr_vp_index > hv_max_vp_index)
		hv_max_vp_index = msr_vp_index;
}

/* RHEL-only: old CPUHP infrastructure */
static int hv_newcpu_cb(struct notifier_block *nfb,
			unsigned long action, void *hcpu)
{
	switch (action & ~CPU_TASKS_FROZEN) {
	case CPU_STARTING:
		hv_cpu_init(hcpu);
		break;
	default:
		break;
	}

	return NOTIFY_OK;
}

static struct notifier_block hv_newcpu_notifier __refdata = {
       .notifier_call = hv_newcpu_cb,
       .priority = INT_MAX,
};

static int __init hv_pci_init(void)
{
	int gen2vm = efi_enabled(EFI_BOOT);

	/*
	 * For Generation-2 VM, we exit from pci_arch_init() by returning 0.
	 * The purpose is to suppress the harmless warning:
	 * "PCI: Fatal: No config space access function found"
	 */
	if (gen2vm)
		return 0;

	/* For Generation-1 VM, we'll proceed in pci_arch_init().  */
	return 1;
}

/*
 * This function is to be invoked early in the boot sequence after the
 * hypervisor has been detected.
 *
 * 1. Setup the hypercall page.
 * 2. Register Hyper-V specific clocksource.
 */
void __init hyperv_init(void)
{
	u64 guest_id;
	union hv_x64_msr_hypercall_contents hypercall_msr;
	int  i;

	if (x86_hyper != &x86_hyper_ms_hyperv)
		return;

	/* Allocate percpu VP index */
	hv_vp_index = kmalloc_array(num_possible_cpus(), sizeof(*hv_vp_index),
				    GFP_KERNEL);
	if (!hv_vp_index)
		return;

	for (i = 0; i < num_possible_cpus(); i++)
		hv_vp_index[i] = VP_INVAL;

	cpu_notifier_register_begin();
	on_each_cpu(hv_cpu_init, NULL, 1);
	__register_hotcpu_notifier(&hv_newcpu_notifier);
	cpu_notifier_register_done();

	/*
	 * Setup the hypercall page and enable hypercalls.
	 * 1. Register the guest ID
	 * 2. Enable the hypercall and register the hypercall page
	 */
	guest_id = generate_guest_id(0, LINUX_VERSION_CODE, 0);
	wrmsrl(HV_X64_MSR_GUEST_OS_ID, guest_id);

	hv_hypercall_pg  = __vmalloc(PAGE_SIZE, GFP_KERNEL, PAGE_KERNEL_RX);
	if (hv_hypercall_pg == NULL) {
		wrmsrl(HV_X64_MSR_GUEST_OS_ID, 0);
		goto free_vp_index;
	}

	rdmsrl(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64);
	hypercall_msr.enable = 1;
	hypercall_msr.guest_physical_address = vmalloc_to_pfn(hv_hypercall_pg);
	wrmsrl(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64);

	hyper_alloc_mmu();

	x86_init.pci.arch_init = hv_pci_init;

	/*
	 * Register Hyper-V specific clocksource.
	 */
#ifdef CONFIG_HYPERV_TSCPAGE
	if (ms_hyperv.features & HV_X64_MSR_REFERENCE_TSC_AVAILABLE) {
		union hv_x64_msr_hypercall_contents tsc_msr;

		tsc_pg = __vmalloc(PAGE_SIZE, GFP_KERNEL, PAGE_KERNEL);
		if (!tsc_pg)
			goto register_msr_cs;

		hyperv_cs = &hyperv_cs_tsc;

		rdmsrl(HV_X64_MSR_REFERENCE_TSC, tsc_msr.as_uint64);

		tsc_msr.enable = 1;
		tsc_msr.guest_physical_address = vmalloc_to_pfn(tsc_pg);

		wrmsrl(HV_X64_MSR_REFERENCE_TSC, tsc_msr.as_uint64);

		__set_fixmap(HVCLOCK_TSC_PAGE,
			     tsc_msr.guest_physical_address << PAGE_SHIFT,
			     PAGE_KERNEL_VVAR);
		kaiser_add_mapping(__fix_to_virt(HVCLOCK_TSC_PAGE), PAGE_SIZE,
				   __PAGE_KERNEL_VVAR | _PAGE_GLOBAL);
		/* set fixmap before switching vclock mode */
		wmb();
		hyperv_cs_tsc.archdata.vclock_mode = VCLOCK_HVCLOCK;

		clocksource_register_hz(&hyperv_cs_tsc, NSEC_PER_SEC/100);
		return;
	}
register_msr_cs:
#endif
	/*
	 * For 32 bit guests just use the MSR based mechanism for reading
	 * the partition counter.
	 */

	hyperv_cs = &hyperv_cs_msr;
	if (ms_hyperv.features & HV_X64_MSR_TIME_REF_COUNT_AVAILABLE)
		clocksource_register_hz(&hyperv_cs_msr, NSEC_PER_SEC/100);

	return;

free_vp_index:
	kfree(hv_vp_index);
	hv_vp_index = NULL;
}

/*
 * This routine is called before kexec/kdump, it does the required cleanup.
 */
void hyperv_cleanup(void)
{
	union hv_x64_msr_hypercall_contents hypercall_msr;

	/* Reset our OS id */
	wrmsrl(HV_X64_MSR_GUEST_OS_ID, 0);

	/* Reset the hypercall page */
	hypercall_msr.as_uint64 = 0;
	wrmsrl(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64);

	/* Reset the TSC page */
	hypercall_msr.as_uint64 = 0;
	wrmsrl(HV_X64_MSR_REFERENCE_TSC, hypercall_msr.as_uint64);
}
EXPORT_SYMBOL_GPL(hyperv_cleanup);

void hyperv_report_panic(struct pt_regs *regs, long err, bool in_die)
{
	static bool panic_reported;
	u64 guest_id;

	if (in_die && !panic_on_oops)
		return;

	/*
	 * We prefer to report panic on 'die' chain as we have proper
	 * registers to report, but if we miss it (e.g. on BUG()) we need
	 * to report it on 'panic'.
	 */
	if (panic_reported)
		return;
	panic_reported = true;

	rdmsrl(HV_X64_MSR_GUEST_OS_ID, guest_id);

	wrmsrl(HV_X64_MSR_CRASH_P0, err);
	wrmsrl(HV_X64_MSR_CRASH_P1, guest_id);
	wrmsrl(HV_X64_MSR_CRASH_P2, regs->ip);
	wrmsrl(HV_X64_MSR_CRASH_P3, regs->ax);
	wrmsrl(HV_X64_MSR_CRASH_P4, regs->sp);

	/*
	 * Let Hyper-V know there is crash data available
	 */
	wrmsrl(HV_X64_MSR_CRASH_CTL, HV_CRASH_CTL_CRASH_NOTIFY);
}
EXPORT_SYMBOL_GPL(hyperv_report_panic);

/**
 * hyperv_report_panic_msg - report panic message to Hyper-V
 * @pa: physical address of the panic page containing the message
 * @size: size of the message in the page
 */
void hyperv_report_panic_msg(phys_addr_t pa, size_t size)
{
	/*
	 * P3 to contain the physical address of the panic page & P4 to
	 * contain the size of the panic data in that page. Rest of the
	 * registers are no-op when the NOTIFY_MSG flag is set.
	 */
	wrmsrl(HV_X64_MSR_CRASH_P0, 0);
	wrmsrl(HV_X64_MSR_CRASH_P1, 0);
	wrmsrl(HV_X64_MSR_CRASH_P2, 0);
	wrmsrl(HV_X64_MSR_CRASH_P3, pa);
	wrmsrl(HV_X64_MSR_CRASH_P4, size);

	/*
	 * Let Hyper-V know there is crash data available along with
	 * the panic message.
	 */
	wrmsrl(HV_X64_MSR_CRASH_CTL,
	       (HV_CRASH_CTL_CRASH_NOTIFY | HV_CRASH_CTL_CRASH_NOTIFY_MSG));
}
EXPORT_SYMBOL_GPL(hyperv_report_panic_msg);

bool hv_is_hyperv_initialized(void)
{
	union hv_x64_msr_hypercall_contents hypercall_msr;

	/*
	 * Ensure that we're really on Hyper-V, and not a KVM or Xen
	 * emulation of Hyper-V
	 */
	if (x86_hyper != &x86_hyper_ms_hyperv)
		return false;

	/*
	 * Verify that earlier initialization succeeded by checking
	 * that the hypercall page is setup
	 */
	hypercall_msr.as_uint64 = 0;
	rdmsrl(HV_X64_MSR_HYPERCALL, hypercall_msr.as_uint64);

	return hypercall_msr.enable;
}
EXPORT_SYMBOL_GPL(hv_is_hyperv_initialized);
