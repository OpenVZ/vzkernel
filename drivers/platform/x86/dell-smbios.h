/*
 *  Common functions for kernel modules using Dell SMBIOS
 *
 *  Copyright (c) Red Hat <mjg@redhat.com>
 *  Copyright (c) 2014 Gabriele Mazzotta <gabriele.mzt@gmail.com>
 *  Copyright (c) 2014 Pali Rohár <pali.rohar@gmail.com>
 *
 *  Based on documentation in the libsmbios package:
 *  Copyright (C) 2005-2014 Dell Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#ifndef _DELL_SMBIOS_H_
#define _DELL_SMBIOS_H_

#include <uapi/linux/wmi.h>

#include <linux/device.h>

/* Classes and selects used in kernel drivers */
#define CLASS_TOKEN_READ 0
#define CLASS_TOKEN_WRITE 1
#define SELECT_TOKEN_STD 0
#define SELECT_TOKEN_BAT 1
#define SELECT_TOKEN_AC 2
#define CLASS_KBD_BACKLIGHT 4
#define SELECT_KBD_BACKLIGHT 11
#define CLASS_FLASH_INTERFACE 7
#define SELECT_FLASH_INTERFACE 3
#define CLASS_ADMIN_PROP 10
#define SELECT_ADMIN_PROP 3
#define CLASS_INFO 17
#define SELECT_RFKILL 11
#define SELECT_APP_REGISTRATION	3
#define SELECT_DOCK 22

/* Tokens used in kernel drivers, any of these
 * should be filtered from userspace access
 */
#define BRIGHTNESS_TOKEN	0x007d
#define KBD_LED_AC_TOKEN	0x0451
#define KBD_LED_OFF_TOKEN	0x01E1
#define KBD_LED_ON_TOKEN	0x01E2
#define KBD_LED_AUTO_TOKEN	0x01E3
#define KBD_LED_AUTO_25_TOKEN	0x02EA
#define KBD_LED_AUTO_50_TOKEN	0x02EB
#define KBD_LED_AUTO_75_TOKEN	0x02EC
#define KBD_LED_AUTO_100_TOKEN	0x02F6
#define GLOBAL_MIC_MUTE_ENABLE	0x0364
#define GLOBAL_MIC_MUTE_DISABLE	0x0365

/* tokens whitelisted to userspace use */
#define CAPSULE_EN_TOKEN	0x0461
#define CAPSULE_DIS_TOKEN	0x0462
#define WSMT_EN_TOKEN		0x04EC
#define WSMT_DIS_TOKEN		0x04ED

struct notifier_block;

struct calling_interface_token {
	u16 tokenID;
	u16 location;
	union {
		u16 value;
		u16 stringlength;
	};
};

struct calling_interface_structure {
	struct dmi_header header;
	u16 cmdIOAddress;
	u8 cmdIOCode;
	u32 supportedCmds;
	struct calling_interface_token tokens[];
} __packed;

int dell_smbios_register_device(struct device *d, void *call_fn);
void dell_smbios_unregister_device(struct device *d);

int dell_smbios_error(int value);
int dell_smbios_call_filter(struct device *d,
	struct calling_interface_buffer *buffer);
int dell_smbios_call(struct calling_interface_buffer *buffer);

struct calling_interface_token *dell_smbios_find_token(int tokenid);

enum dell_laptop_notifier_actions {
	DELL_LAPTOP_KBD_BACKLIGHT_BRIGHTNESS_CHANGED,
};

int dell_laptop_register_notifier(struct notifier_block *nb);
int dell_laptop_unregister_notifier(struct notifier_block *nb);
void dell_laptop_call_notifier(unsigned long action, void *data);

/* for the supported backends */
#ifdef CONFIG_DELL_SMBIOS_WMI
int init_dell_smbios_wmi(void);
void exit_dell_smbios_wmi(void);
#else /* CONFIG_DELL_SMBIOS_WMI */
static inline int init_dell_smbios_wmi(void)
{
	return -ENODEV;
}
static inline void exit_dell_smbios_wmi(void)
{}
#endif /* CONFIG_DELL_SMBIOS_WMI */

#ifdef CONFIG_DELL_SMBIOS_SMM
int init_dell_smbios_smm(void);
void exit_dell_smbios_smm(void);
#else /* CONFIG_DELL_SMBIOS_SMM */
static inline int init_dell_smbios_smm(void)
{
	return -ENODEV;
}
static inline void exit_dell_smbios_smm(void)
{}
#endif /* CONFIG_DELL_SMBIOS_SMM */

#endif /* _DELL_SMBIOS_H_ */
