/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2000, 2001, 2002 Andi Kleen, SuSE Labs
 */
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/hardirq.h>
#include <linux/kdebug.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/kexec.h>
#include <linux/sysfs.h>
#include <linux/bug.h>
#include <linux/nmi.h>

#include <asm/stacktrace.h>


void show_regs(struct pt_regs *regs)
{
	int i;

	show_regs_print_info(KERN_EMERG);
	__show_regs(regs, !user_mode_vm(regs));

	/*
	 * When in-kernel, we also print out the stack and code at the
	 * time of the fault..
	 */
	if (!user_mode_vm(regs)) {
		unsigned int code_prologue = code_bytes * 43 / 64;
		unsigned int code_len = code_bytes;
		unsigned char c;
		u8 *ip;

		show_trace_log_lvl(current, regs, NULL, KERN_EMERG);

		pr_emerg("Code:");

		ip = (u8 *)regs->ip - code_prologue;
		if (ip < (u8 *)PAGE_OFFSET || probe_kernel_address(ip, c)) {
			/* try starting at IP */
			ip = (u8 *)regs->ip;
			code_len = code_len - code_prologue + 1;
		}
		for (i = 0; i < code_len; i++, ip++) {
			if (ip < (u8 *)PAGE_OFFSET ||
					probe_kernel_address(ip, c)) {
				pr_cont("  Bad EIP value.");
				break;
			}
			if (ip == (u8 *)regs->ip)
				pr_cont(" <%02x>", c);
			else
				pr_cont(" %02x", c);
		}
	}
	pr_cont("\n");
}

int is_valid_bugaddr(unsigned long ip)
{
	unsigned short ud2;

	if (ip < PAGE_OFFSET)
		return 0;
	if (probe_kernel_address((unsigned short *)ip, ud2))
		return 0;

	return ud2 == 0x0b0f;
}
