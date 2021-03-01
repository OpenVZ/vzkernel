#ifndef __ACPI_VIDEO_H
#define __ACPI_VIDEO_H

#include <linux/errno.h> /* for ENODEV */

struct acpi_device;

#define ACPI_VIDEO_CLASS	"video"

#define ACPI_VIDEO_DISPLAY_CRT  1
#define ACPI_VIDEO_DISPLAY_TV   2
#define ACPI_VIDEO_DISPLAY_DVI  3
#define ACPI_VIDEO_DISPLAY_LCD  4

#define ACPI_VIDEO_DISPLAY_LEGACY_MONITOR 0x0100
#define ACPI_VIDEO_DISPLAY_LEGACY_PANEL   0x0110
#define ACPI_VIDEO_DISPLAY_LEGACY_TV      0x0200

#define ACPI_VIDEO_NOTIFY_SWITCH		0x80
#define ACPI_VIDEO_NOTIFY_PROBE			0x81
#define ACPI_VIDEO_NOTIFY_CYCLE			0x82
#define ACPI_VIDEO_NOTIFY_NEXT_OUTPUT		0x83
#define ACPI_VIDEO_NOTIFY_PREV_OUTPUT		0x84
#define ACPI_VIDEO_NOTIFY_CYCLE_BRIGHTNESS	0x85
#define ACPI_VIDEO_NOTIFY_INC_BRIGHTNESS	0x86
#define ACPI_VIDEO_NOTIFY_DEC_BRIGHTNESS	0x87
#define ACPI_VIDEO_NOTIFY_ZERO_BRIGHTNESS	0x88
#define ACPI_VIDEO_NOTIFY_DISPLAY_OFF		0x89

#if IS_ENABLED(CONFIG_ACPI_VIDEO)
extern int acpi_video_register(void);
extern void acpi_video_unregister(void);
extern void acpi_video_unregister_backlight(void);
extern int acpi_video_get_edid(struct acpi_device *device, int type,
			       int device_id, void **edid);
extern bool acpi_video_verify_backlight_support(void);
#else
static inline int acpi_video_register(void) { return 0; }
static inline void acpi_video_unregister(void) { return; }
static inline void acpi_video_unregister_backlight(void) { return; }
static inline int acpi_video_get_edid(struct acpi_device *device, int type,
				      int device_id, void **edid)
{
	return -ENODEV;
}
static inline bool acpi_video_verify_backlight_support(void) { return false; }
#endif

#endif
