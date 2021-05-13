#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/efi.h>
#include <linux/io.h>
#include <linux/kobject.h>
#include <linux/memblock.h>
#include <linux/slab.h>
#include <keys/asymmetric-type.h>
#include <keys/system_keyring.h>
#include "module-internal.h"

/*
 * The LINUX_EFI_MOK_VARIABLE_STORE config table can be provided
 * to the kernel by an EFI boot loader. The table contains a packed
 * sequence of these entries, one for each named MOK variable.
 * The sequence is terminated by an entry with a completely NULL
 * name and 0 data size.
 */
struct efi_mokvar_config_entry {
	char name[256];
	u64 data_size;
	u8 data[];
} __attribute((packed));

static struct efi_mokvar_config_entry *efi_mokvar_config_va;
static size_t efi_mokvar_config_size;

/*
 * The kernel makes the data associated with an EFI MOK config table
 * entry available to user space via sysfs as a binary file under
 * /sys/firmware/efi/mok-variables/.
 * Each such sysfs file is represented by an instance of struct
 * efi_mokvar_sysfs_attr on efi_mokvar_sysfs_list.
 * bin_attr.private points to the associated EFI MOK config table
 * entry.
 */
struct efi_mokvar_sysfs_attr {
	struct bin_attribute bin_attr;
	struct list_head node;
};

static struct kobject *mokvar_kobj;
static LIST_HEAD(efi_mokvar_sysfs_list);

static bool efi_mokvar_config_disabled;

static int __init setup_nomokvarconfig(char *arg)
{
	efi_mokvar_config_disabled = true;
	return 0;
}
early_param("nomokvarconfig", setup_nomokvarconfig);


/*
 * efi_mokvar_config_init() - Early boot validation of EFI MOK config table
 *
 * If present, validate and compute the size of the EFI MOK variable
 * configuration table. This table may be provided by an EFI boot loader
 * as an alternative to ordinary UEFI variables, due to platform-dependent
 * limitations. The memory occupied by this table is marked as reserved.
 *
 * This routine must be called very early during boot while the EFI memory
 * map is still available.
 *
 * Implicit inputs:
 * efi.mokvar_config:	Physical address of EFI MOK variable config table
 *			or special value that indicates no such table.
 *
 * Implicit outputs:
 * efi_mokvar_config_size: Computed size of EFI MOK variable config table.
 *			The table is considered present and valid if this
 *			is non-zero.
 */
void __init efi_mokvar_config_init(void)
{
	efi_memory_desc_t md;
	u64 end_pa;
	void *va = NULL;
	size_t cur_offset = 0;
	size_t offset_limit;
	size_t map_size = 0;
	size_t map_size_needed = 0;
	size_t size;
	struct efi_mokvar_config_entry *mokvar_config_e;
	int rc = -EINVAL;

	if (!efi_is_table_address(efi.mokvar_config))
		return;

	if (efi_mokvar_config_disabled) {
		pr_info("EFI MOKvar config table disabled via kernel parameter\n");
		return;
	}

	/* The EFI MOK config table must fit within a single EFI memory
	 * descriptor range.
	 */
	rc = efi_mem_desc_lookup(efi.mokvar_config, &md);
	if (rc) {
		pr_warn("EFI MOKvar config table is not within the EFI memory map\n");
		return;
	}
	end_pa = efi_mem_desc_end(&md);
	if (efi.mokvar_config >= end_pa) {
		pr_err("EFI memory descriptor containing MOKvar config table is invalid\n");
		return;
	}
	offset_limit = end_pa - efi.mokvar_config;

	/* Validate entry by entry, which are variable in size, remapping
	 * as necessary, and computing the total size of the config table.
	 */
	while (cur_offset + sizeof(*mokvar_config_e) <= offset_limit) {
		mokvar_config_e = va + cur_offset;
		map_size_needed = cur_offset + sizeof(*mokvar_config_e);
		if (map_size_needed > map_size) {
			if (va)
				early_memunmap(va, map_size);

			/* Map a little more than the fixed size entry
			 * header, anticipating some data. It's safe to
			 * do so as long as we stay within current memory
			 * descriptor.
			 */
			map_size = min(map_size_needed + 2*EFI_PAGE_SIZE,
				       offset_limit);
			va = early_memremap(efi.mokvar_config, map_size);
			if (!va) {
				pr_err("Failed to map EFI MOKvar config table pa=%p, size=%zu.\n",
				       (void *)efi.mokvar_config, map_size);
				return;
			}
			mokvar_config_e = va + cur_offset;
		}

		/* Check for last sentinel entry */
		if (mokvar_config_e->name[0] == '\0') {
			if (mokvar_config_e->data_size != 0)
				break;
			rc = 0;
			break;
		}

		/* Sanity check that the name is null terminated */
		size = strnlen(mokvar_config_e->name,
			       sizeof(mokvar_config_e->name));
		if (size >= sizeof(mokvar_config_e->name))
			break;

		/* Advance to the next entry */
		cur_offset = map_size_needed + mokvar_config_e->data_size;
	}

	if (va)
		early_memunmap(va, map_size);
	if (rc) {
		pr_err("EFI MOKvar config table is not valid\n");
		return;
	}
	rc = memblock_reserve(efi.mokvar_config, map_size_needed);
	if (rc) {
		pr_err("Failed to reserve EFI MOKvar config table pa=%p, size=%zu.\n",
		       (void *)efi.mokvar_config, map_size_needed);
		return;
	}
	efi_mokvar_config_size = map_size_needed;
}

/*
 * efi_mokvar_config_next() - Get next entry in the EFI MOK config table
 *
 * mokvar_config_e:	Pointer to current EFI MOK config table entry
 *			or null. Null indicates get first entry.
 *			Passed by reference. This is updated to the
 *			same value as the return value.
 *
 * Returns:		Pointer to next EFI MOK config table entry
 *			or null, if there are no more entries.
 *			Same value is returned in the mokvar_config_e
 *			parameter.
 */
static struct efi_mokvar_config_entry *efi_mokvar_config_next(
		struct efi_mokvar_config_entry **mokvar_config_e)
{
	struct efi_mokvar_config_entry *mokvar_cur;
	struct efi_mokvar_config_entry *mokvar_next;
	size_t size_cur;

	mokvar_cur = *mokvar_config_e;
	*mokvar_config_e = NULL;

	if (efi_mokvar_config_va == NULL)
		return NULL;

	if (mokvar_cur == NULL) {
		mokvar_next = efi_mokvar_config_va;
	} else {
		if (mokvar_cur->name[0] == '\0')
			return NULL;
		size_cur = sizeof(*mokvar_cur) + mokvar_cur->data_size;
		mokvar_next = (void *)mokvar_cur + size_cur;
	}

	if (mokvar_next->name[0] == '\0')
		return NULL;

	*mokvar_config_e = mokvar_next;
	return mokvar_next;
}

/*
 * efi_mokvar_config_find() - Find EFI MOK config entry by name
 *
 * name:	Name of the entry to look for.
 *
 * Returns:	Pointer to EFI MOK config table entry if found;
 *		null otherwise.
 *
 * This routine depends on the EFI MOK config table being entirely
 * mapped with it's starting virtual address in efi_mokvar_config_va.
 */
static struct efi_mokvar_config_entry *efi_mokvar_config_find(
			const char *name)
{
	struct efi_mokvar_config_entry *mokvar_e = NULL;

	while (efi_mokvar_config_next(&mokvar_e)) {
		if (!strncmp(name, mokvar_e->name, sizeof(mokvar_e->name)))
			return mokvar_e;
	}
	return NULL;
}

/*
 * efi_mokvar_sysfs_read() - sysfs binary file read routine
 *
 * Returns:	Count of bytes read.
 *
 * Copy EFI MOK config entry data to the supplied buffer, starting
 * at the specified offset into config data, for the specified
 * count bytes. Limited by the amount of data in this config entry.
 */
static ssize_t efi_mokvar_sysfs_read(struct file *file, struct kobject *kobj,
				 struct bin_attribute *bin_attr, char *buf,
				 loff_t off, size_t count)
{
	struct efi_mokvar_config_entry *mokvar_e = bin_attr->private;

	if (!capable(CAP_SYS_ADMIN))
		return 0;

	if (off >= mokvar_e->data_size)
		return 0;
	if (count >  mokvar_e->data_size - off)
		count = mokvar_e->data_size - off;

	memcpy(buf, mokvar_e->data + off, count);
	return count;
}

/*
 * efi_mokvar_sysfs_init() - Map EFI MOK config table and create sysfs
 *
 * Map the EFI MOK variable config table for run-time use by the kernel
 * and create the sysfs entries in /sys/firmware/efi/mok-variables/
 *
 * This routine just returns if a valid EFI MOK variable config table
 * was not found earlier during boot.
 *
 * This routine must be called during a "middle" initcall phase, i.e.
 * after efi_mokvar_config_init() but before UEFI certs are loaded
 * during late init.
 *
 * Implicit inputs:
 * efi.mokvar_config:	Physical address of EFI MOK variable config table
 *			or special value that indicates no such table.
 *
 * efi_mokvar_config_size: Computed size of EFI MOK variable config table.
 *			The table is considered present and valid if this
 *			is non-zero.
 *
 * Implicit outputs:
 * efi_mokvar_config_va: Start virtual address of the EFI MOK config table.
 */
static int __init efi_mokvar_sysfs_init(void)
{
	void *config_va;
	struct efi_mokvar_config_entry *mokvar_e = NULL;
	struct efi_mokvar_sysfs_attr *mokvar_sysfs = NULL;
	int rc = 0;

	if (efi_mokvar_config_size == 0)
		return -ENOENT;

	config_va = memremap(efi.mokvar_config, efi_mokvar_config_size,
			     MEMREMAP_WB);
	if (!config_va) {
		pr_err("Failed to map EFI MOKvar config table\n");
		return -ENOMEM;
	}
	efi_mokvar_config_va = config_va;

	mokvar_kobj = kobject_create_and_add("mok-variables", efi_kobj);
	if (!mokvar_kobj) {
		pr_err("Failed to create EFI mok-variables sysfs entry\n");
		return -ENOMEM;
	}

	while (efi_mokvar_config_next(&mokvar_e)) {
		mokvar_sysfs = kzalloc(sizeof(*mokvar_sysfs), GFP_KERNEL);
		if (!mokvar_sysfs) {
			rc = -ENOMEM;
			break;
		}

		sysfs_bin_attr_init(&mokvar_sysfs->bin_attr);
		mokvar_sysfs->bin_attr.private = mokvar_e;
		mokvar_sysfs->bin_attr.attr.name = mokvar_e->name;
		mokvar_sysfs->bin_attr.attr.mode = 0400;
		mokvar_sysfs->bin_attr.size = mokvar_e->data_size;
		mokvar_sysfs->bin_attr.read = efi_mokvar_sysfs_read;

		rc = sysfs_create_bin_file(mokvar_kobj,
					   &mokvar_sysfs->bin_attr);
		if (rc)
			break;

		list_add_tail(&mokvar_sysfs->node, &efi_mokvar_sysfs_list);
	}

	if (rc) {
		pr_err("Failed to create some EFI mok-variables sysfs entries\n");
		kfree(mokvar_sysfs);
	}
	return rc;
}
device_initcall(efi_mokvar_sysfs_init);

static __init int check_ignore_db(void)
{
	efi_status_t status;
	unsigned int db = 0;
	unsigned long size = sizeof(db);
	efi_guid_t guid = EFI_SHIM_LOCK_GUID;

	/* Check and see if the MokIgnoreDB variable exists.  If that fails
	 * then we don't ignore DB.  If it succeeds, we do.
	 */
	status = efi.get_variable(L"MokIgnoreDB", &guid, NULL, &size, &db);
	if (status != EFI_SUCCESS)
		return 0;

	return 1;
}

static __init void *get_cert_list(efi_char16_t *name, efi_guid_t *guid, unsigned long *size)
{
	efi_status_t status;
	unsigned long lsize = 4;
	unsigned long tmpdb[4];
	void *db = NULL;

	status = efi.get_variable(name, guid, NULL, &lsize, &tmpdb);
	if (status == EFI_NOT_FOUND)
		return NULL;
	if (status != EFI_BUFFER_TOO_SMALL) {
		pr_err("Couldn't get size: 0x%lx\n", status);
		return NULL;
	}

	db = kmalloc(lsize, GFP_KERNEL);
	if (!db) {
		pr_err("Couldn't allocate memory for uefi cert list\n");
		goto out;
	}

	status = efi.get_variable(name, guid, NULL, &lsize, db);
	if (status != EFI_SUCCESS) {
		kfree(db);
		db = NULL;
		pr_err("Error reading db var: 0x%lx\n", status);
	}
out:
	*size = lsize;
	return db;
}

/*
 * load_moklist_certs() - Load MokList certs
 *
 * Returns:	Summary error status
 *
 * Load the certs contained in the UEFI MokListRT databases into the
 * system trusted keyring.
 *
 * This routine checks the EFI MOK config table first. If and only if
 * that fails, this routine uses the MokListRT ordinary UEFI variables.
 */
static int __init load_moklist_certs(void)
{
	efi_guid_t mok_var = EFI_SHIM_LOCK_GUID;
	void *mok = NULL;
	unsigned long moksize = 0;
	int rc = 0;
	int mok_i;
	static efi_char16_t mok_name[] = L"MokListRT0";
	struct efi_mokvar_config_entry *mokvar_e = NULL;

	/* Index of last non-terminating efi_char16_t in mok_name */
	const int mok_x = ARRAY_SIZE(mok_name) - 2;

	/* First try to load certs from the EFI MOKvar config table. */
	mokvar_e = efi_mokvar_config_find("MokListRT");
	if (mokvar_e) {
		rc = parse_efi_signature_list(mokvar_e->data,
					      mokvar_e->data_size,
					      system_trusted_keyring);
		/* All done if that worked. */
		if (!rc) {
			pr_info("MokListRT signatures loaded from EFI MOKvar config table\n");
			return rc;
		}
		pr_err("Couldn't parse MokListRT signatures from EFI MOKvar config table: %d\n",
		       rc);
	}

	mok_name[mok_x] = L'\0';

	/* Get MokListRT and MokListRT[1-9]. They might not exist,
	 * so it isn't an error if we can't get them.
	 */
	for (mok_i = 0; mok_i <= 9; mok_i++) {
		mok = get_cert_list(mok_name, &mok_var, &moksize);
		if (!mok) {
			if (mok_i == 0)
				pr_info("MODSIGN: Couldn't get UEFI MokListRT\n");
			break;
		}
		rc = parse_efi_signature_list(mok, moksize,
					      system_trusted_keyring);
		if (rc)
			pr_err("Couldn't parse MokListRT%c signatures: %d\n",
			       (mok_i == 0) ? ' ' : ('0' + mok_i), rc);
		kfree(mok);
		mok_name[mok_x] = L'1' + mok_i;
	}
	return rc;
}

/*
 * Load the certs contained in the UEFI databases
 */
static int __init load_uefi_certs(void)
{
	efi_guid_t secure_var = EFI_IMAGE_SECURITY_DATABASE_GUID;
	void *db = NULL, *dbx = NULL;
	unsigned long dbsize = 0, dbxsize = 0;
	int ignore_db, rc = 0;

	/* Check if SB is enabled and just return if not */
	if (!efi_enabled(EFI_SECURE_BOOT))
		return 0;

	/* See if the user has setup Ignore DB mode */
	ignore_db = check_ignore_db();

	 /* Get db and dbx. They might not exist, so it isn't an error
	  * if we can't get them.
	  */
	if (!ignore_db) {
		db = get_cert_list(L"db", &secure_var, &dbsize);
		if (!db) {
			pr_err("MODSIGN: Couldn't get UEFI db list\n");
		} else {
			rc = parse_efi_signature_list(db, dbsize, system_trusted_keyring);
			if (rc)
				pr_err("Couldn't parse db signatures: %d\n", rc);
			kfree(db);
		}
	}

	dbx = get_cert_list(L"dbx", &secure_var, &dbxsize);
	if (!dbx) {
		pr_info("MODSIGN: Couldn't get UEFI dbx list\n");
	} else {
		rc = parse_efi_signature_list(dbx, dbxsize,
			system_blacklist_keyring);
		if (rc)
			pr_err("Couldn't parse dbx signatures: %d\n", rc);
		kfree(dbx);
	}

	/* Load the MokListRT certs */
	rc = load_moklist_certs();

	return rc;
}
late_initcall(load_uefi_certs);
