/*
 * Jump label s390 support
 *
 * Copyright IBM Corp. 2011
 * Author(s): Jan Glauber <jang@linux.vnet.ibm.com>
 */
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/stop_machine.h>
#include <linux/jump_label.h>
#include <asm/ipl.h>

#ifdef HAVE_JUMP_LABEL

struct insn {
	u16 opcode;
	s32 offset;
} __packed;

struct insn_args {
	struct jump_entry *entry;
	enum jump_label_type type;
};

static void __jump_label_transform(struct jump_entry *entry,
				   enum jump_label_type type)
{
	struct insn insn;
	int rc;

	if (type == JUMP_LABEL_ENABLE) {
		/* brcl 15,offset */
		insn.opcode = 0xc0f4;
		insn.offset = (entry->target - entry->code) >> 1;
	} else {
		/* brcl 0,offset */
		insn.opcode = 0xc004;
		insn.offset = (entry->target - entry->code) >> 1;
	}

	rc = probe_kernel_write((void *)entry->code, &insn, JUMP_LABEL_NOP_SIZE);
	WARN_ON_ONCE(rc < 0);
}

static void __jump_label_sync(void *dummy)
{
}

void arch_jump_label_transform(struct jump_entry *entry,
			       enum jump_label_type type)
{
	__jump_label_transform(entry, type);
	smp_call_function(__jump_label_sync, NULL, 1);
}

void arch_jump_label_transform_static(struct jump_entry *entry,
				      enum jump_label_type type)
{
	__jump_label_transform(entry, type);
}

#endif
