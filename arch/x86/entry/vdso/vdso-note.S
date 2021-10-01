/*
 * This supplies .note.* sections to go into the PT_NOTE inside the vDSO text.
 * Here we can supply some information useful to userland.
 */

#include <linux/build-salt.h>
#include <linux/uts.h>
#include <linux/version.h>
#include <linux/elfnote.h>

	.globl linux_version_code
ELFNOTE_START(Linux, 0, "a")
linux_version_code:
	.long LINUX_VERSION_CODE
ELFNOTE_END

BUILD_SALT
