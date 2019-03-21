/*
 *  Copyright (C) 2018  Red Hat, Inc.
 *
 *  This work is licensed under the terms of the GNU GPL, version 2. See
 *  the COPYING file in the top-level directory.
 */

#include <linux/cpu.h>
#include <linux/percpu.h>
#include <linux/uaccess.h>
#include <asm/spec_ctrl.h>
#include <asm/cpufeature.h>
#include <asm/nospec-branch.h>
#include <asm/intel-family.h>
#include <asm/cpu.h>

/*
 * Kernel IBRS speculation control structure
 */
DEFINE_PER_CPU(struct kernel_ibrs_spec_ctrl, spec_ctrl_pcp);

static bool __initdata noibrs_cmdline;
unsigned int ibrs_mode __read_mostly;
unsigned int spec_ctrl_mask __read_mostly;

static void set_spec_ctrl_pcp(bool entry, bool exit)
{
	unsigned int hi32_val, entry_val, exit_val;
	int cpu;

	/*
	 * For ibrs_always, we only need to write the MSR at kernel entry
	 * to fulfill the barrier semantics for some CPUs.
	 */
	if (entry && exit) {
		setup_force_cpu_cap(X86_FEATURE_SPEC_CTRL_ENTRY);
	} else {
		setup_force_cpu_cap(X86_FEATURE_SPEC_CTRL_ENTRY);
		setup_force_cpu_cap(X86_FEATURE_SPEC_CTRL_EXIT);
	}

	/*
	 * The x86_spec_ctrl_base is set to the state of SPEC_CTRL MSR
	 * in kernel mode.
	 */
	if (entry)
		x86_spec_ctrl_base |= spec_ctrl_mask;

	if (exit)
		exit_val = (unsigned int)x86_spec_ctrl_base | spec_ctrl_mask;
	else
		exit_val = (unsigned int)x86_spec_ctrl_base & ~spec_ctrl_mask;

	hi32_val  = (unsigned int)(x86_spec_ctrl_base >> 32);
	entry_val = (unsigned int)x86_spec_ctrl_base;

	for_each_possible_cpu(cpu) {
		WRITE_ONCE(per_cpu(spec_ctrl_pcp.hi32, cpu), hi32_val);
		WRITE_ONCE(per_cpu(spec_ctrl_pcp.entry, cpu), entry_val);
		WRITE_ONCE(per_cpu(spec_ctrl_pcp.exit, cpu), exit_val);
	}
}

/*
 * The following values are written to IBRS on kernel entry/exit:
 *
 *		entry	exit
 * ibrs		  1	 0
 * ibrs_always	  1	 1
 * ibrs_user	  0	 1
 */

static inline void set_spec_ctrl_pcp_ibrs(void)
{
	set_spec_ctrl_pcp(true, false);
	ibrs_mode = IBRS_ENABLED;
}

static inline void set_spec_ctrl_pcp_ibrs_always(void)
{
	set_spec_ctrl_pcp(true, true);
	ibrs_mode = IBRS_ENABLED_ALWAYS;
}

static inline void set_spec_ctrl_pcp_ibrs_user(void)
{
	set_spec_ctrl_pcp(false, true);
	ibrs_mode = IBRS_ENABLED_USER;
}

bool __init spec_ctrl_enable_ibrs(void)
{
	if (cpu_has_ibrs() && !noibrs_cmdline) {
		set_spec_ctrl_pcp_ibrs();
		return true;
	}

	return false;
}

bool __init spec_ctrl_enable_ibrs_always(void)
{
	if (cpu_has_ibrs() && !noibrs_cmdline) {
		set_spec_ctrl_pcp_ibrs_always();
		/*
		 * Make sure the boot CPU has IBRS bit set.
		 */
		spec_ctrl_cpu_init();
		return true;
	}

	return false;
}

bool __init spec_ctrl_enable_retpoline_ibrs_user(void)
{
	if (!cpu_has_ibrs() || noibrs_cmdline)
		return false;

	set_spec_ctrl_pcp_ibrs_user();
	return true;
}

static int __init noibrs(char *str)
{
	noibrs_cmdline = true;

	return 0;
}
early_param("noibrs", noibrs);

static __init void spec_ctrl_print_features(void)
{
	if (boot_cpu_has(X86_FEATURE_IBRS))
		printk_once(KERN_INFO "FEATURE SPEC_CTRL Present\n");
	else
		printk_once(KERN_INFO "FEATURE SPEC_CTRL Not Present\n");

	if (boot_cpu_has(X86_FEATURE_IBPB))
		printk_once(KERN_INFO "FEATURE IBPB_SUPPORT Present\n");
	else
		printk_once(KERN_INFO "FEATURE IBPB_SUPPORT Not Present\n");
}

void spec_ctrl_cpu_init(void)
{
	if (ibrs_mode == IBRS_ENABLED_ALWAYS)
		native_wrmsrl(MSR_IA32_SPEC_CTRL, x86_spec_ctrl_base);
}

void __init spec_ctrl_init(const u64 spec_mask)
{
	spec_ctrl_mask = spec_mask & (SPEC_CTRL_IBRS|SPEC_CTRL_STIBP);
	spec_ctrl_print_features();
}

/* Check for Skylake-like CPUs */
bool is_skylake_era(void)
{
	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL &&
	    boot_cpu_data.x86 == 6) {
		switch (boot_cpu_data.x86_model) {
		case INTEL_FAM6_SKYLAKE_MOBILE:
		case INTEL_FAM6_SKYLAKE_DESKTOP:
		case INTEL_FAM6_SKYLAKE_X:
		case INTEL_FAM6_KABYLAKE_MOBILE:
		case INTEL_FAM6_KABYLAKE_DESKTOP:
			return true;
		}
	}
	return false;
}

/*
 * Set the right SSBD bit for the current CPU.
 */
void spec_ctrl_set_ssbd(u64 tifn)
{
	if (tifn) {
		this_cpu_or(spec_ctrl_pcp.entry, SPEC_CTRL_SSBD);
		this_cpu_or(spec_ctrl_pcp.exit,  SPEC_CTRL_SSBD);
	} else {
		this_cpu_and(spec_ctrl_pcp.entry, ~SPEC_CTRL_SSBD);
		this_cpu_and(spec_ctrl_pcp.exit,  ~SPEC_CTRL_SSBD);
	}
}
