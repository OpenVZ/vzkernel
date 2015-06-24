/*
 * This supplies .note.* sections to go into the PT_NOTE inside the vDSO text.
 * Here we can supply some information useful to userland.
 */

#include <linux/uts.h>
#include <linux/version.h>
#include <linux/elfnote.h>

	.globl VDSO64_linux_version_code
ELFNOTE_START(Linux, 0, "a")
VDSO64_linux_version_code:
	.long LINUX_VERSION_CODE
ELFNOTE_END
