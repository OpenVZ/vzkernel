/*
 *  Copyright (C) 1994  Linus Torvalds
 *
 *  Cyrix stuff, June 1998 by:
 *	- Rafael R. Reilova (moved everything from head.S),
 *        <rreilova@ececs.uc.edu>
 *	- Channing Corn (tests & fixes),
 *	- Andrew D. Balsa (code cleanup).
 */
#include <linux/init.h>
#include <linux/utsname.h>
#include <linux/cpu.h>

#include <asm/nospec-branch.h>
#include <asm/cmdline.h>
#include <asm/bugs.h>
#include <asm/processor.h>
#include <asm/processor-flags.h>
#include <asm/i387.h>
#include <asm/msr.h>
#include <asm/paravirt.h>
#include <asm/alternative.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/spec_ctrl.h>
#include <linux/prctl.h>

static void __init spectre_v2_select_mitigation(void);
static void __init ssb_parse_cmdline(void);
void ssb_select_mitigation(void);
extern void spec_ctrl_save_msr(void);

void __init check_bugs(void)
{
	identify_boot_cpu();

	spec_ctrl_save_msr();

	if (!IS_ENABLED(CONFIG_SMP)) {
		pr_info("CPU: ");
		print_cpu_info(&boot_cpu_data);
	}

	/*
	 * Select proper mitigation for any exposure to the Speculative Store
	 * Bypass vulnerability (exposed as a bug in "Memory Disambiguation")
	 * This has to be done before spec_ctrl_init() to make sure that its
	 * SPEC_CTRL MSR value is properly set up.
	 */
	ssb_parse_cmdline();
	ssb_select_mitigation();

	spec_ctrl_init();
	spectre_v2_select_mitigation();

	spec_ctrl_cpu_init();

#ifdef CONFIG_X86_32
	/*
	 * Check whether we are able to run this kernel safely on SMP.
	 *
	 * - i386 is no longer supported.
	 * - In order to run on anything without a TSC, we need to be
	 *   compiled for a i486.
	 */
	if (boot_cpu_data.x86 < 4)
		panic("Kernel requires i486+ for 'invlpg' and other features");

	init_utsname()->machine[1] =
		'0' + (boot_cpu_data.x86 > 6 ? 6 : boot_cpu_data.x86);
	alternative_instructions();

	/*
	 * kernel_fpu_begin/end() in check_fpu() relies on the patched
	 * alternative instructions.
	 */
	check_fpu();
#else /* CONFIG_X86_64 */
	alternative_instructions();

	/*
	 * Make sure the first 2MB area is not mapped by huge pages
	 * There are typically fixed size MTRRs in there and overlapping
	 * MTRRs into large pages causes slow downs.
	 *
	 * Right now we don't do that with gbpages because there seems
	 * very little benefit for that case.
	 */
	if (!direct_gbpages)
		set_memory_4k((unsigned long)__va(0), 1);
#endif
}

void x86_amd_rds_enable(void)
{
	u64 msrval = x86_amd_ls_cfg_base | x86_amd_ls_cfg_rds_mask;

	if (boot_cpu_has(X86_FEATURE_AMD_SSBD))
		wrmsrl(MSR_AMD64_LS_CFG, msrval);
}

/* The kernel command line selection */
enum spectre_v2_mitigation_cmd {
	SPECTRE_V2_CMD_NONE,
	SPECTRE_V2_CMD_FORCE,
	SPECTRE_V2_CMD_AUTO,
	SPECTRE_V2_CMD_RETPOLINE,
	SPECTRE_V2_CMD_RETPOLINE_IBRS_USER,
	SPECTRE_V2_CMD_IBRS,
	SPECTRE_V2_CMD_IBRS_ALWAYS,
};

static const char *spectre_v2_strings[] = {
	[SPECTRE_V2_NONE]			= "Vulnerable",
	[SPECTRE_V2_RETPOLINE_MINIMAL]		= "Vulnerable: Minimal ASM retpoline",
	[SPECTRE_V2_RETPOLINE_NO_IBPB]		= "Vulnerable: Retpoline without IBPB",
	[SPECTRE_V2_RETPOLINE_SKYLAKE]		= "Vulnerable: Retpoline on Skylake+",
	[SPECTRE_V2_RETPOLINE_UNSAFE_MODULE]	= "Vulnerable: Retpoline with unsafe module(s)",
	[SPECTRE_V2_RETPOLINE]			= "Mitigation: Full retpoline",
	[SPECTRE_V2_RETPOLINE_IBRS_USER]	= "Mitigation: Full retpoline and IBRS (user space)",
	[SPECTRE_V2_IBRS]			= "Mitigation: IBRS (kernel)",
	[SPECTRE_V2_IBRS_ALWAYS]		= "Mitigation: IBRS (kernel and user space)",
	[SPECTRE_V2_IBP_DISABLED]		= "Mitigation: IBP disabled",
};

enum spectre_v2_mitigation_cmd spectre_v2_cmd = SPECTRE_V2_CMD_AUTO;

#undef pr_fmt
#define pr_fmt(fmt)     "Spectre V2 : " fmt

static inline bool match_option(const char *arg, int arglen, const char *opt)
{
	int len = strlen(opt);

	return len == arglen && !strncmp(arg, opt, len);
}

static enum spectre_v2_mitigation_cmd spectre_v2_parse_cmdline(void)
{
	char arg[20];
	int ret;

	ret = cmdline_find_option(boot_command_line, "spectre_v2", arg,
				  sizeof(arg));
	if (ret > 0)  {
		if (match_option(arg, ret, "off")) {
			goto disable;
		} else if (match_option(arg, ret, "on")) {
			return SPECTRE_V2_CMD_FORCE;
		} else if (match_option(arg, ret, "retpoline")) {
			return SPECTRE_V2_CMD_RETPOLINE;
		} else if (match_option(arg, ret, "retpoline,ibrs_user")) {
			return SPECTRE_V2_CMD_RETPOLINE_IBRS_USER;
		} else if (match_option(arg, ret, "ibrs")) {
			return SPECTRE_V2_CMD_IBRS;
		} else if (match_option(arg, ret, "ibrs_always")) {
			return SPECTRE_V2_CMD_IBRS_ALWAYS;
		} else if (match_option(arg, ret, "auto")) {
			return SPECTRE_V2_CMD_AUTO;
		}
	}

	if (!cmdline_find_option_bool(boot_command_line, "nospectre_v2"))
		return SPECTRE_V2_CMD_AUTO;
disable:
	return SPECTRE_V2_CMD_NONE;
}

void __spectre_v2_select_mitigation(void)
{
	const bool full_retpoline = IS_ENABLED(CONFIG_RETPOLINE) && retp_compiler();
	enum spectre_v2_mitigation_cmd cmd = spectre_v2_cmd;

	switch (cmd) {
	case SPECTRE_V2_CMD_NONE:
		return;

	case SPECTRE_V2_CMD_FORCE:
	case SPECTRE_V2_CMD_AUTO:
		break;

	case SPECTRE_V2_CMD_RETPOLINE:
		spec_ctrl_enable_retpoline();
		return;

	case SPECTRE_V2_CMD_IBRS:
		if (spec_ctrl_force_enable_ibrs())
			return;
		break;

	case SPECTRE_V2_CMD_IBRS_ALWAYS:
		if (spec_ctrl_enable_ibrs_always() ||
		    spec_ctrl_force_enable_ibp_disabled())
			return;
		break;

	case SPECTRE_V2_CMD_RETPOLINE_IBRS_USER:
		if (spec_ctrl_enable_retpoline_ibrs_user())
			return;
		break;
	}

	if (spec_ctrl_cond_enable_ibrs(full_retpoline))
		return;

	if (spec_ctrl_cond_enable_ibp_disabled())
		return;

	spec_ctrl_enable_retpoline();
}

void spectre_v2_print_mitigation(void)
{

	pr_info("%s\n", spectre_v2_strings[spec_ctrl_get_mitigation()]);
}

static void __init spectre_v2_select_mitigation(void)
{
	spectre_v2_cmd = spectre_v2_parse_cmdline();
	__spectre_v2_select_mitigation();
	spectre_v2_print_mitigation();
}

#undef pr_fmt

#define pr_fmt(fmt)    "Speculative Store Bypass: " fmt

enum ssb_mitigation ssb_mode = SPEC_STORE_BYPASS_NONE;

/* The kernel command line selection */
enum ssb_mitigation_cmd {
	SPEC_STORE_BYPASS_CMD_NONE,
	SPEC_STORE_BYPASS_CMD_AUTO,
	SPEC_STORE_BYPASS_CMD_ON,
	SPEC_STORE_BYPASS_CMD_PRCTL,
};

static enum ssb_mitigation_cmd ssb_cmd = SPEC_STORE_BYPASS_CMD_NONE;

static const char *ssb_strings[] = {
	[SPEC_STORE_BYPASS_NONE]			= "Vulnerable",
	[SPEC_STORE_BYPASS_DISABLE]			= "Mitigation: Speculative Store Bypass disabled",
	[SPEC_STORE_BYPASS_PRCTL]			= "Mitigation: Speculative Store Bypass disabled via prctl"
};

static const struct {
	const char *option;
	enum ssb_mitigation_cmd cmd;
} ssb_mitigation_options[] = {
	{ "auto",	SPEC_STORE_BYPASS_CMD_AUTO },  /* Platform decides */
	{ "on",		SPEC_STORE_BYPASS_CMD_ON },    /* Disable Speculative Store Bypass */
	{ "off",	SPEC_STORE_BYPASS_CMD_NONE },  /* Don't touch Speculative Store Bypass */
	{ "prctl",	SPEC_STORE_BYPASS_CMD_PRCTL }, /* Disable Speculative Store Bypass via prctl */
};

static enum ssb_mitigation_cmd __init __ssb_parse_cmdline(void)
{
	enum ssb_mitigation_cmd cmd = SPEC_STORE_BYPASS_CMD_AUTO;
	char arg[20];
	int ret, i;

	if (cmdline_find_option_bool(boot_command_line, "nospec_store_bypass_disable"))
		return SPEC_STORE_BYPASS_CMD_NONE;
	else {
		ret = cmdline_find_option(boot_command_line, "spec_store_bypass_disable",
					  arg, sizeof(arg));
		if (ret < 0)
			return SPEC_STORE_BYPASS_CMD_AUTO;

		for (i = 0; i < ARRAY_SIZE(ssb_mitigation_options); i++) {
			if (!match_option(arg, ret, ssb_mitigation_options[i].option))
				continue;

			cmd = ssb_mitigation_options[i].cmd;
			break;
		}

		if (i >= ARRAY_SIZE(ssb_mitigation_options)) {
			pr_err("unknown option (%s). Switching to AUTO select\n", arg);
			return SPEC_STORE_BYPASS_CMD_AUTO;
		}
	}

	return cmd;
}

/*
 * The SSB command line parsing is now separated from SSB mitigation
 * selection as the boot command line buffer will not be available after
 * init and so could not be used with late microcode update.
 */
static void  __init ssb_parse_cmdline(void)
{
	ssb_cmd = __ssb_parse_cmdline();
}

static enum ssb_mitigation __ssb_select_mitigation(void)
{
	enum ssb_mitigation mode = SPEC_STORE_BYPASS_NONE;
	enum ssb_mitigation_cmd cmd = ssb_cmd;

	if (!boot_cpu_has(X86_FEATURE_SSBD))
		return mode;

	if (!boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS) &&
	    (cmd == SPEC_STORE_BYPASS_CMD_NONE ||
	     cmd == SPEC_STORE_BYPASS_CMD_AUTO))
		return mode;

	switch (cmd) {
	case SPEC_STORE_BYPASS_CMD_AUTO:
		/* Choose prctl as the default mode */
		mode = SPEC_STORE_BYPASS_PRCTL;
		break;
	case SPEC_STORE_BYPASS_CMD_ON:
		mode = SPEC_STORE_BYPASS_DISABLE;
		break;
	case SPEC_STORE_BYPASS_CMD_PRCTL:
		mode = SPEC_STORE_BYPASS_PRCTL;
		break;
	case SPEC_STORE_BYPASS_CMD_NONE:
		break;
	}

	/*
	 * We have three CPU feature flags that are in play here:
	 *  - X86_BUG_SPEC_STORE_BYPASS - CPU is susceptible.
	 *  - X86_FEATURE_SSBD - CPU is able to turn off speculative store bypass
	 *  - X86_FEATURE_SPEC_STORE_BYPASS_DISABLE - engage the mitigation
	 */
	if (mode == SPEC_STORE_BYPASS_DISABLE) {
		setup_force_cpu_cap(X86_FEATURE_SPEC_STORE_BYPASS_DISABLE);
		/*
		 * Intel uses the SPEC CTRL MSR Bit(2) for this, while AMD uses
		 * a completely different MSR and bit dependent on family.
		 */
		switch (boot_cpu_data.x86_vendor) {
		case X86_VENDOR_INTEL:
			x86_spec_ctrl_base |= FEATURE_ENABLE_SSBD;
			break;
		case X86_VENDOR_AMD:
			x86_amd_rds_enable();
			break;
		}
	}

	return mode;
}

void ssb_select_mitigation()
{
	ssb_mode = __ssb_select_mitigation();

	if (boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS))
		pr_info("%s\n", ssb_strings[ssb_mode]);
}

#undef pr_fmt

static int ssb_prctl_set(struct task_struct *task, unsigned long ctrl)
{
	bool ssbd = !!test_tsk_thread_flag(task, TIF_SSBD);

	if (ssb_mode != SPEC_STORE_BYPASS_PRCTL)
		return -ENXIO;

	if (ctrl == PR_SPEC_ENABLE)
		clear_tsk_thread_flag(task, TIF_SSBD);
	else
		set_tsk_thread_flag(task, TIF_SSBD);

	/*
	 * If being set on non-current task, delay setting the CPU
	 * mitigation until it is next scheduled.
	 */
	if (task == current && ssbd != !!test_tsk_thread_flag(task, TIF_SSBD))
		speculative_store_bypass_update();

	return 0;
}

static int ssb_prctl_get(struct task_struct *task)
{
	switch (ssb_mode) {
	case SPEC_STORE_BYPASS_DISABLE:
		return PR_SPEC_DISABLE;
	case SPEC_STORE_BYPASS_PRCTL:
		if (test_tsk_thread_flag(task, TIF_SSBD))
			return PR_SPEC_PRCTL | PR_SPEC_DISABLE;
		return PR_SPEC_PRCTL | PR_SPEC_ENABLE;
	default:
		if (boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS))
			return PR_SPEC_ENABLE;
		return PR_SPEC_NOT_AFFECTED;
	}
}

int arch_prctl_spec_ctrl_set(struct task_struct *task, unsigned long which,
			     unsigned long ctrl)
{
	if (ctrl != PR_SPEC_ENABLE && ctrl != PR_SPEC_DISABLE)
		return -ERANGE;

	switch (which) {
	case PR_SPEC_STORE_BYPASS:
		return ssb_prctl_set(task, ctrl);
	default:
		return -ENODEV;
	}
}

int arch_prctl_spec_ctrl_get(struct task_struct *task, unsigned long which)
{
	switch (which) {
	case PR_SPEC_STORE_BYPASS:
		return ssb_prctl_get(task);
	default:
		return -ENODEV;
	}
}

#ifdef CONFIG_SYSFS
ssize_t cpu_show_meltdown(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD)
		return sprintf(buf, "Not affected\n");
	if (kaiser_enabled)
		return sprintf(buf, "Mitigation: PTI\n");
	return sprintf(buf, "Vulnerable\n");
}

ssize_t cpu_show_spectre_v1(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "Mitigation: Load fences\n");
}

ssize_t cpu_show_spectre_v2(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", spectre_v2_strings[spec_ctrl_get_mitigation()]);
}

ssize_t cpu_show_spec_store_bypass(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	if (!boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS))
		return sprintf(buf, "Not affected\n");
	return sprintf(buf, "%s\n", ssb_strings[ssb_mode]);
}
#endif
