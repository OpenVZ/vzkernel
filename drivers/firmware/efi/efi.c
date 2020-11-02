/*
 * efi.c - EFI subsystem
 *
 * Copyright (C) 2001,2003,2004 Dell <Matt_Domsch@dell.com>
 * Copyright (C) 2004 Intel Corporation <matthew.e.tolentino@intel.com>
 * Copyright (C) 2013 Tom Gundersen <teg@jklm.no>
 *
 * This code registers /sys/firmware/efi{,/efivars} when EFI is supported,
 * allowing the efivarfs to be mounted or the efivars module to be loaded.
 * The existance of /sys/firmware/efi may also be used by userspace to
 * determine that the system supports EFI.
 *
 * This file is released under the GPLv2.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/efi.h>
#include <linux/io.h>

struct efi __read_mostly efi = {
	.mps        = EFI_INVALID_TABLE_ADDR,
	.acpi       = EFI_INVALID_TABLE_ADDR,
	.acpi20     = EFI_INVALID_TABLE_ADDR,
	.smbios     = EFI_INVALID_TABLE_ADDR,
	.smbios3    = EFI_INVALID_TABLE_ADDR,
	.sal_systab = EFI_INVALID_TABLE_ADDR,
	.boot_info  = EFI_INVALID_TABLE_ADDR,
	.hcdp       = EFI_INVALID_TABLE_ADDR,
	.uga        = EFI_INVALID_TABLE_ADDR,
	.uv_systab  = EFI_INVALID_TABLE_ADDR,
	.fw_vendor  = EFI_INVALID_TABLE_ADDR,
	.runtime    = EFI_INVALID_TABLE_ADDR,
	.config_table  = EFI_INVALID_TABLE_ADDR,
	.esrt       = EFI_INVALID_TABLE_ADDR,
#ifdef CONFIG_MODULE_SIG_UEFI
	.mokvar_config = EFI_INVALID_TABLE_ADDR,
#endif
};
EXPORT_SYMBOL(efi);

static unsigned long *efi_tables[] = {
	&efi.mps,
	&efi.acpi,
	&efi.acpi20,
	&efi.smbios,
	&efi.smbios3,
	&efi.sal_systab,
	&efi.boot_info,
	&efi.hcdp,
	&efi.uga,
	&efi.uv_systab,
	&efi.fw_vendor,
	&efi.runtime,
	&efi.config_table,
	&efi.esrt,
#ifdef CONFIG_MODULE_SIG_UEFI
	&efi.mokvar_config,
#endif
};

struct kobject *efi_kobj;

struct workqueue_struct *efi_rts_wq;

struct mm_struct efi_mm = {
	.mm_rb			= RB_ROOT,
	.mm_users		= ATOMIC_INIT(2),
	.mm_count		= ATOMIC_INIT(1),
	.mmap_sem		= __RWSEM_INITIALIZER(efi_mm.mmap_sem),
	.page_table_lock	= __SPIN_LOCK_UNLOCKED(efi_mm.page_table_lock),
	.mmlist			= LIST_HEAD_INIT(efi_mm.mmlist),
};

static bool disable_runtime;
static int __init setup_noefi(char *arg)
{
	disable_runtime = true;
	return 0;
}
early_param("noefi", setup_noefi);

bool efi_runtime_disabled(void)
{
	return disable_runtime;
}

/*
 * Let's not leave out systab information that snuck into
 * the efivars driver
 */
static ssize_t systab_show(struct kobject *kobj,
			   struct kobj_attribute *attr, char *buf)
{
	char *str = buf;

	if (!kobj || !buf)
		return -EINVAL;

	if (efi.mps != EFI_INVALID_TABLE_ADDR)
		str += sprintf(str, "MPS=0x%lx\n", efi.mps);
	if (efi.acpi20 != EFI_INVALID_TABLE_ADDR)
		str += sprintf(str, "ACPI20=0x%lx\n", efi.acpi20);
	if (efi.acpi != EFI_INVALID_TABLE_ADDR)
		str += sprintf(str, "ACPI=0x%lx\n", efi.acpi);
	/*
	 * If both SMBIOS and SMBIOS3 entry points are implemented, the
	 * SMBIOS3 entry point shall be preferred, so we list it first to
	 * let applications stop parsing after the first match.
	 */
	if (efi.smbios3 != EFI_INVALID_TABLE_ADDR)
		str += sprintf(str, "SMBIOS3=0x%lx\n", efi.smbios3);
	if (efi.smbios != EFI_INVALID_TABLE_ADDR)
		str += sprintf(str, "SMBIOS=0x%lx\n", efi.smbios);
	if (efi.hcdp != EFI_INVALID_TABLE_ADDR)
		str += sprintf(str, "HCDP=0x%lx\n", efi.hcdp);
	if (efi.boot_info != EFI_INVALID_TABLE_ADDR)
		str += sprintf(str, "BOOTINFO=0x%lx\n", efi.boot_info);
	if (efi.uga != EFI_INVALID_TABLE_ADDR)
		str += sprintf(str, "UGA=0x%lx\n", efi.uga);

	return str - buf;
}

static struct kobj_attribute efi_attr_systab =
			__ATTR(systab, 0400, systab_show, NULL);

#define EFI_FIELD(var) efi.var

#define EFI_ATTR_SHOW(name) \
static ssize_t name##_show(struct kobject *kobj, \
				struct kobj_attribute *attr, char *buf) \
{ \
	return sprintf(buf, "0x%lx\n", EFI_FIELD(name)); \
}

EFI_ATTR_SHOW(fw_vendor);
EFI_ATTR_SHOW(runtime);
EFI_ATTR_SHOW(config_table);

static ssize_t fw_platform_size_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", efi_enabled(EFI_64BIT) ? 64 : 32);
}

static struct kobj_attribute efi_attr_fw_vendor = __ATTR_RO(fw_vendor);
static struct kobj_attribute efi_attr_runtime = __ATTR_RO(runtime);
static struct kobj_attribute efi_attr_config_table = __ATTR_RO(config_table);
static struct kobj_attribute efi_attr_fw_platform_size =
	__ATTR_RO(fw_platform_size);

static struct attribute *efi_subsys_attrs[] = {
	&efi_attr_systab.attr,
	&efi_attr_fw_vendor.attr,
	&efi_attr_runtime.attr,
	&efi_attr_config_table.attr,
	&efi_attr_fw_platform_size.attr,
	NULL,
};

static umode_t efi_attr_is_visible(struct kobject *kobj,
				   struct attribute *attr, int n)
{
	umode_t mode = attr->mode;

	if (attr == &efi_attr_fw_vendor.attr)
		return (efi.fw_vendor == EFI_INVALID_TABLE_ADDR) ? 0 : mode;
	else if (attr == &efi_attr_runtime.attr)
		return (efi.runtime == EFI_INVALID_TABLE_ADDR) ? 0 : mode;
	else if (attr == &efi_attr_config_table.attr)
		return (efi.config_table == EFI_INVALID_TABLE_ADDR) ? 0 : mode;

	return mode;
}

static struct attribute_group efi_subsys_attr_group = {
	.attrs = efi_subsys_attrs,
	.is_visible = efi_attr_is_visible,
};

static struct efivars generic_efivars;
static struct efivar_operations generic_ops;

static int generic_ops_register(void)
{
	generic_ops.get_variable = efi.get_variable;
	generic_ops.set_variable = efi.set_variable;
	generic_ops.get_next_variable = efi.get_next_variable;
	generic_ops.query_variable_store = efi_query_variable_store;

	return efivars_register(&generic_efivars, &generic_ops, efi_kobj);
}

static void generic_ops_unregister(void)
{
	efivars_unregister(&generic_efivars);
}

/*
 * We register the efi subsystem with the firmware subsystem and the
 * efivars subsystem with the efi subsystem, if the system was booted with
 * EFI.
 */
static int __init efisubsys_init(void)
{
	int error;

	if (!efi_enabled(EFI_BOOT))
		return 0;

	/*
	 * Since we process only one efi_runtime_service() at a time, an
	 * ordered workqueue (which creates only one execution context)
	 * should suffice all our needs.
	 */
	efi_rts_wq = alloc_ordered_workqueue("efi_rts_wq", 0);
	if (!efi_rts_wq) {
		pr_err("Creating efi_rts_wq failed, EFI runtime services disabled.\n");
		clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
		return 0;
	}

	/* We register the efi directory at /sys/firmware/efi */
	efi_kobj = kobject_create_and_add("efi", firmware_kobj);
	if (!efi_kobj) {
		pr_err("efi: Firmware registration failed.\n");
		return -ENOMEM;
	}

	error = generic_ops_register();
	if (error)
		goto err_put;

	error = sysfs_create_group(efi_kobj, &efi_subsys_attr_group);
	if (error) {
		pr_err("efi: Sysfs attribute export failed with error %d.\n",
		       error);
		goto err_unregister;
	}

	error = efi_runtime_map_init(efi_kobj);
	if (error)
		goto err_remove_group;

	/* and the standard mountpoint for efivarfs */
	error = sysfs_create_mount_point(efi_kobj, "efivars");
	if (error) {
		pr_err("efivars: Subsystem registration failed.\n");
		goto err_remove_group;
	}

	return 0;

err_remove_group:
	sysfs_remove_group(efi_kobj, &efi_subsys_attr_group);
err_unregister:
	generic_ops_unregister();
err_put:
	kobject_put(efi_kobj);
	return error;
}

subsys_initcall(efisubsys_init);

/*
 * Find the efi memory descriptor for a given physical address.  Given a
 * physicall address, determine if it exists within an EFI Memory Map entry,
 * and if so, populate the supplied memory descriptor with the appropriate
 * data.
 */
int __init efi_mem_desc_lookup(u64 phys_addr, efi_memory_desc_t *out_md)
{
	struct efi_memory_map *map = efi.memmap;
	void *memmap, *p, *e;
	int ret;

	if (!efi_enabled(EFI_MEMMAP)) {
		pr_err_once("EFI_MEMMAP is not enabled.\n");
		return -EINVAL;
	}

	if (!map) {
		pr_err_once("efi.memmap is not set.\n");
		return -EINVAL;
	}
	if (!out_md) {
		pr_err_once("out_md is null.\n");
		return -EINVAL;
        }
	if (WARN_ON_ONCE(!map->phys_map))
		return -EINVAL;
	if (WARN_ON_ONCE(map->nr_map == 0) || WARN_ON_ONCE(map->desc_size == 0))
		return -EINVAL;

	/*
	 * If a driver calls this after efi_free_boot_services,
	 * ->map will be NULL, and the target may also not be mapped.
	 * So just always get our own virtual map on the CPU.
	 */
	memmap = early_memremap((phys_addr_t)map->phys_map,
				map->nr_map * map->desc_size);
	if (!memmap) {
		pr_err_once("early_memremap(%#llx, %zu) failed.\n",
			    (unsigned long long) map->phys_map, map->nr_map * map->desc_size);
		return -ENOMEM;
	}

	ret = -ENOENT;
	e = memmap + (map->nr_map * map->desc_size);
	for (p = memmap; p < e; p += map->desc_size) {
		efi_memory_desc_t *md = p;
		u64 size;
		u64 end;

		if (!(md->attribute & EFI_MEMORY_RUNTIME) &&
		    md->type != EFI_BOOT_SERVICES_DATA &&
		    md->type != EFI_RUNTIME_SERVICES_DATA) {
			continue;
		}

		size = md->num_pages << EFI_PAGE_SHIFT;
		end = md->phys_addr + size;
		if (phys_addr >= md->phys_addr && phys_addr < end) {
			memcpy(out_md, md, sizeof(*out_md));
			ret = 0;
			break;
		}
	}

	early_memunmap(memmap, map->nr_map * map->desc_size);

	return ret;
}

/*
 * Calculate the highest address of an efi memory descriptor.
 */
u64 __init efi_mem_desc_end(efi_memory_desc_t *md)
{
	u64 size = md->num_pages << EFI_PAGE_SHIFT;
	u64 end = md->phys_addr + size;
	return end;
}

static __initdata efi_config_table_type_t common_tables[] = {
	{ACPI_20_TABLE_GUID, "ACPI 2.0", &efi.acpi20},
	{ACPI_TABLE_GUID, "ACPI", &efi.acpi},
	{HCDP_TABLE_GUID, "HCDP", &efi.hcdp},
	{MPS_TABLE_GUID, "MPS", &efi.mps},
	{SAL_SYSTEM_TABLE_GUID, "SALsystab", &efi.sal_systab},
	{SMBIOS_TABLE_GUID, "SMBIOS", &efi.smbios},
	{SMBIOS3_TABLE_GUID, "SMBIOS 3.0", &efi.smbios3},
	{UGA_IO_PROTOCOL_GUID, "UGA", &efi.uga},
	{EFI_SYSTEM_RESOURCE_TABLE_GUID, "ESRT", &efi.esrt},
#ifdef CONFIG_MODULE_SIG_UEFI
	{LINUX_EFI_MOK_VARIABLE_STORE, "MOKvar", &efi.mokvar_config},
#endif
	{NULL_GUID, NULL, NULL},
};

static __init int match_config_table(efi_guid_t *guid,
				     unsigned long table,
				     efi_config_table_type_t *table_types)
{
	u8 str[EFI_VARIABLE_GUID_LEN + 1];
	int i;

	if (table_types) {
		efi_guid_to_str(guid, str);

		for (i = 0; efi_guidcmp(table_types[i].guid, NULL_GUID); i++) {
			efi_guid_to_str(&table_types[i].guid, str);

			if (!efi_guidcmp(*guid, table_types[i].guid)) {
				*(table_types[i].ptr) = table;
				pr_cont(" %s=0x%lx ",
					table_types[i].name, table);
				return 1;
			}
		}
	}

	return 0;
}

int __init efi_config_init(efi_config_table_type_t *arch_tables)
{
	void *config_tables, *tablep;
	int i, sz;

	if (efi_enabled(EFI_64BIT))
		sz = sizeof(efi_config_table_64_t);
	else
		sz = sizeof(efi_config_table_32_t);

	/*
	 * Let's see what config tables the firmware passed to us.
	 */
	config_tables = early_memremap(efi.systab->tables,
				       efi.systab->nr_tables * sz);
	if (config_tables == NULL) {
		pr_err("Could not map Configuration table!\n");
		return -ENOMEM;
	}

	tablep = config_tables;
	pr_info("");
	for (i = 0; i < efi.systab->nr_tables; i++) {
		efi_guid_t guid;
		unsigned long table;

		if (efi_enabled(EFI_64BIT)) {
			u64 table64;
			guid = ((efi_config_table_64_t *)tablep)->guid;
			table64 = ((efi_config_table_64_t *)tablep)->table;
			table = table64;
#ifndef CONFIG_64BIT
			if (table64 >> 32) {
				pr_cont("\n");
				pr_err("Table located above 4GB, disabling EFI.\n");
				early_memunmap(config_tables,
					       efi.systab->nr_tables * sz);
				return -EINVAL;
			}
#endif
		} else {
			guid = ((efi_config_table_32_t *)tablep)->guid;
			table = ((efi_config_table_32_t *)tablep)->table;
		}

		if (!match_config_table(&guid, table, common_tables))
			match_config_table(&guid, table, arch_tables);

		tablep += sz;
	}
	pr_cont("\n");
	early_memunmap(config_tables, efi.systab->nr_tables * sz);

	return 0;
}

bool efi_is_table_address(unsigned long phys_addr)
{
	unsigned int i;

	if (phys_addr == EFI_INVALID_TABLE_ADDR)
		return false;

	for (i = 0; i < ARRAY_SIZE(efi_tables); i++)
		if (*(efi_tables[i]) == phys_addr)
			return true;

	return false;
}
