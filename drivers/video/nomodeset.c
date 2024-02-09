// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/types.h>

#include <video/nomodeset.h>

static bool video_nomodeset = true;

bool video_firmware_drivers_only(void)
{
	return video_nomodeset;
}
EXPORT_SYMBOL(video_firmware_drivers_only);

static int __init disable_modeset(char *str)
{
	video_nomodeset = true;

	pr_warn("Booted with the nomodeset parameter. Only the system framebuffer will be available\n");

	return 1;
}

static int __init enable_modeset(char *str)
{
	video_nomodeset = false;

	pr_warn("Booted with the modeset parameter. Full framebuffer support is enabled\n");

	return 1;
}

/* Disable kernel modesetting */
__setup("nomodeset", disable_modeset);
/* Enable kernel modesetting */
__setup("modeset", enable_modeset);
