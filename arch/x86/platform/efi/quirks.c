#define pr_fmt(fmt) "efi: " fmt

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/efi.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/bootmem.h>
#include <linux/acpi.h>
#include <linux/dmi.h>
#include <linux/mem_encrypt.h>
#include <linux/mm.h>
#include <asm/efi.h>
#include <asm/uv/uv.h>
#include <asm/reboot.h>

#define EFI_MIN_RESERVE 5120

#define EFI_DUMMY_GUID \
	EFI_GUID(0x4424ac57, 0xbe4b, 0x47dd, 0x9e, 0x97, 0xed, 0x50, 0xf0, 0x9f, 0x92, 0xa9)

static efi_char16_t efi_dummy_name[6] = { 'D', 'U', 'M', 'M', 'Y', 0 };

static bool efi_no_storage_paranoia;

/*
 * Some firmware implementations refuse to boot if there's insufficient
 * space in the variable store. The implementation of garbage collection
 * in some FW versions causes stale (deleted) variables to take up space
 * longer than intended and space is only freed once the store becomes
 * almost completely full.
 *
 * Enabling this option disables the space checks in
 * efi_query_variable_store() and forces garbage collection.
 *
 * Only enable this option if deleting EFI variables does not free up
 * space in your variable store, e.g. if despite deleting variables
 * you're unable to create new ones.
 */
static int __init setup_storage_paranoia(char *arg)
{
	efi_no_storage_paranoia = true;
	return 0;
}
early_param("efi_no_storage_paranoia", setup_storage_paranoia);

/*
 * Deleting the dummy variable which kicks off garbage collection
*/
void efi_delete_dummy_variable(void)
{
	efi.set_variable_nonblocking((efi_char16_t *)efi_dummy_name,
				     &EFI_DUMMY_GUID,
				     EFI_VARIABLE_NON_VOLATILE |
				     EFI_VARIABLE_BOOTSERVICE_ACCESS |
				     EFI_VARIABLE_RUNTIME_ACCESS, 0, NULL);
}

/*
 * In the nonblocking case we do not attempt to perform garbage
 * collection if we do not have enough free space. Rather, we do the
 * bare minimum check and give up immediately if the available space
 * is below EFI_MIN_RESERVE.
 *
 * This function is intended to be small and simple because it is
 * invoked from crash handler paths.
 */
static efi_status_t
query_variable_store_nonblocking(u32 attributes, unsigned long size)
{
	efi_status_t status;
	u64 storage_size, remaining_size, max_size;

	status = efi.query_variable_info_nonblocking(attributes, &storage_size,
						     &remaining_size,
						     &max_size);
	if (status != EFI_SUCCESS)
		return status;

	if (remaining_size - size < EFI_MIN_RESERVE)
		return EFI_OUT_OF_RESOURCES;

	return EFI_SUCCESS;
}

/*
 * Some firmware implementations refuse to boot if there's insufficient space
 * in the variable store. Ensure that we never use more than a safe limit.
 *
 * Return EFI_SUCCESS if it is safe to write 'size' bytes to the variable
 * store.
 */
efi_status_t efi_query_variable_store(u32 attributes, unsigned long size,
				      bool nonblocking)
{
	efi_status_t status;
	u64 storage_size, remaining_size, max_size;

	if (!(attributes & EFI_VARIABLE_NON_VOLATILE))
		return 0;

	if (nonblocking)
		return query_variable_store_nonblocking(attributes, size);

	status = efi.query_variable_info(attributes, &storage_size,
					 &remaining_size, &max_size);
	if (status != EFI_SUCCESS)
		return status;

	/*
	 * We account for that by refusing the write if permitting it would
	 * reduce the available space to under 5KB. This figure was provided by
	 * Samsung, so should be safe.
	 */
	if ((remaining_size - size < EFI_MIN_RESERVE) &&
		!efi_no_storage_paranoia) {

		/*
		 * Triggering garbage collection may require that the firmware
		 * generate a real EFI_OUT_OF_RESOURCES error. We can force
		 * that by attempting to use more space than is available.
		 */
		unsigned long dummy_size = remaining_size + 1024;
		void *dummy = kzalloc(dummy_size, GFP_ATOMIC);

		if (!dummy)
			return EFI_OUT_OF_RESOURCES;

		status = efi.set_variable(efi_dummy_name, &EFI_DUMMY_GUID,
					  EFI_VARIABLE_NON_VOLATILE |
					  EFI_VARIABLE_BOOTSERVICE_ACCESS |
					  EFI_VARIABLE_RUNTIME_ACCESS,
					  dummy_size, dummy);

		if (status == EFI_SUCCESS) {
			/*
			 * This should have failed, so if it didn't make sure
			 * that we delete it...
			 */
			efi_delete_dummy_variable();
		}

		kfree(dummy);

		/*
		 * The runtime code may now have triggered a garbage collection
		 * run, so check the variable info again
		 */
		status = efi.query_variable_info(attributes, &storage_size,
						 &remaining_size, &max_size);

		if (status != EFI_SUCCESS)
			return status;

		/*
		 * There still isn't enough room, so return an error
		 */
		if (remaining_size - size < EFI_MIN_RESERVE)
			return EFI_OUT_OF_RESOURCES;
	}

	return EFI_SUCCESS;
}
EXPORT_SYMBOL_GPL(efi_query_variable_store);

/*
 * Helper function for efi_reserve_boot_services() to figure out if we
 * can free regions in efi_free_boot_services().
 *
 * Use this function to ensure we do not free regions owned by somebody
 * else. We must only reserve (and then free) regions:
 *
 * - Not within any part of the kernel
 * - Not the BIOS reserved area (E820_RESERVED, E820_NVS, etc)
 */
static bool can_free_region(u64 start, u64 size)
{
	if (start + size > __pa_symbol(_text) && start <= __pa_symbol(_end))
		return false;

	if (!e820_all_mapped(start, start+size, E820_RAM))
		return false;

	return true;
}

/*
 * The UEFI specification makes it clear that the operating system is free to do
 * whatever it wants with boot services code after ExitBootServices() has been
 * called. Ignoring this recommendation a significant bunch of EFI implementations
 * continue calling into boot services code (SetVirtualAddressMap). In order to
 * work around such buggy implementations we reserve boot services region during
 * EFI init and make sure it stays executable. Then, after SetVirtualAddressMap(), it
* is discarded.
*/
void __init efi_reserve_boot_services(void)
{
	void *p;

	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		efi_memory_desc_t *md = p;
		u64 start = md->phys_addr;
		u64 size = md->num_pages << EFI_PAGE_SHIFT;
		bool already_reserved;

		if (md->type != EFI_BOOT_SERVICES_CODE &&
		    md->type != EFI_BOOT_SERVICES_DATA)
			continue;

		already_reserved = memblock_is_region_reserved(start, size);

		/*
		 * Because the following memblock_reserve() is paired
		 * with free_bootmem_late() for this region in
		 * efi_free_boot_services(), we must be extremely
		 * careful not to reserve, and subsequently free,
		 * critical regions of memory (like the kernel image) or
		 * those regions that somebody else has already
		 * reserved.
		 *
		 * A good example of a critical region that must not be
		 * freed is page zero (first 4Kb of memory), which may
		 * contain boot services code/data but is marked
		 * E820_RESERVED by trim_bios_range().
		 */
		if (!already_reserved) {
			memblock_reserve(start, size);

			/*
			 * If we are the first to reserve the region, no
			 * one else cares about it. We own it and can
			 * free it later.
			 */
			if (can_free_region(start, size))
				continue;
		}

		/*
		 * We don't own the region. We must not free it.
		 *
		 * Setting this bit for a boot services region really
		 * doesn't make sense as far as the firmware is
		 * concerned, but it does provide us with a way to tag
		 * those regions that must not be paired with
		 * free_bootmem_late().
		 */
		md->attribute |= EFI_MEMORY_RUNTIME;
	}
}

void __init efi_free_boot_services(void)
{
	void *p;

	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		efi_memory_desc_t *md = p;
		unsigned long long start = md->phys_addr;
		unsigned long long size = md->num_pages << EFI_PAGE_SHIFT;

		if (md->type != EFI_BOOT_SERVICES_CODE &&
		    md->type != EFI_BOOT_SERVICES_DATA)
			continue;

		set_memory_encrypted((unsigned long)__va(start), md->num_pages);

		/* Do not free, someone else owns it: */
		if (md->attribute & EFI_MEMORY_RUNTIME)
			continue;

		free_bootmem_late(start, size);
	}

	efi_unmap_memmap();
}

/*
 * RHEL7-ONLY
 *
 * Test if the specified BGRT image physical address range is,
 * or can be made, eligible for memremap().
 *
 * If memory encryption is not active, memremap() can use the
 * direct mapping and imposes no additional constraints on the
 * pages in the physical address range. Therefore this routine
 * returns true when that applies.
 *
 * However, if memory encryption is active, the direct map cannot
 * be used for the BGRT image since the image is not encrypted and
 * the direct map is an encrypting/decrypting mapping. Instead, a
 * new mapping needs to be created for the BGRT image without
 * encryption enabled. The creation of a such a new mapping imposes
 * the additional requirement that the pages within that range must
 * have been previously marked as reserved.
 *
 * If memory encryption is active, this routine expects that the
 * BGRT image is within an EFI boot services data or code memory
 * range which has already been marked as needed at runtime.
 * If that's the case, this routine can safely mark the pages
 * within the specified physical memory range as reserved and
 * returns true. Otherwise, it returns false.
 *
 * This routine must be called after efi_reserve_boot_services()
 * and before efi_free_boot_services(). It is patterned after
 * efi_free_boot_services().
 */
bool __init efi_bgrt_image_remappable(u64 pa, size_t pa_size)
{
	void *p;

	/*
	 * The direct map can be used for the BGRT image by
	 * memremap() when memory encryption is not active.
	 */
	if (!mem_encrypt_active())
		return true;

	/*
	 * This routine must be called before efi_free_boot_services()
	 * unmaps the EFI memory map. If called too late, just assume
	 * that the BGRT image can't be mapped.
	 */
	if (memmap.map == NULL)
		return false;

	/*
	 * Find the EFI memory descriptor which contains the physical
	 * address of the BGRT image. That memory descriptor:
	 * (a) Must entirely contain the pa_size range;
	 * (b) Must be of type boot services code or data;
	 * (c) Must be marked as needed at runtime.
	 * If all of these are true, then efi_free_boot_services()
	 * is not going to make this memory available for normal use.
	 * Therefore there is no loss in explicitly marking these pages
	 * as reserved. The pages need to be marked as reserved to be
	 * eligible for memremap() to create a new remapping when memory
	 * encryption is active.
	 */
	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		efi_memory_desc_t *md = p;
		unsigned long long start = md->phys_addr;
		unsigned long long size = md->num_pages << EFI_PAGE_SHIFT;

		if (pa < start || pa >= (start + size))
			continue;

		if (pa + pa_size > start + size)
			break;

		if (md->type != EFI_BOOT_SERVICES_CODE &&
		    md->type != EFI_BOOT_SERVICES_DATA)
			break;

		if (!(md->attribute & EFI_MEMORY_RUNTIME))
			break;

		reserve_bootmem_region(pa, pa + pa_size);

		return true;
	}

	/* Can't guarantee that the memory range is remappable */
	return false;
}

/*
 * A number of config table entries get remapped to virtual addresses
 * after entering EFI virtual mode. However, the kexec kernel requires
 * their physical addresses therefore we pass them via setup_data and
 * correct those entries to their respective physical addresses here.
 *
 * Currently only handles smbios which is necessary for some firmware
 * implementation.
 */
int __init efi_reuse_config(u64 tables, int nr_tables)
{
	int i, sz, ret = 0;
	void *p, *tablep;
	struct efi_setup_data *data;

	if (!efi_setup)
		return 0;

	if (!efi_enabled(EFI_64BIT))
		return 0;

	data = early_memremap(efi_setup, sizeof(*data));
	if (!data) {
		ret = -ENOMEM;
		goto out;
	}

	if (!data->smbios)
		goto out_memremap;

	sz = sizeof(efi_config_table_64_t);

	p = tablep = early_memremap(tables, nr_tables * sz);
	if (!p) {
		pr_err("Could not map Configuration table!\n");
		ret = -ENOMEM;
		goto out_memremap;
	}

	for (i = 0; i < efi.systab->nr_tables; i++) {
		efi_guid_t guid;

		guid = ((efi_config_table_64_t *)p)->guid;

		if (!efi_guidcmp(guid, SMBIOS_TABLE_GUID))
			((efi_config_table_64_t *)p)->table = data->smbios;
		p += sz;
	}
	early_memunmap(tablep, nr_tables * sz);

out_memremap:
	early_memunmap(data, sizeof(*data));
out:
	return ret;
}

static const struct dmi_system_id sgi_uv1_dmi[] = {
	{ NULL, "SGI UV1",
		{	DMI_MATCH(DMI_PRODUCT_NAME,	"Stoutland Platform"),
			DMI_MATCH(DMI_PRODUCT_VERSION,	"1.0"),
			DMI_MATCH(DMI_BIOS_VENDOR,	"SGI.COM"),
		}
	},
	{ } /* NULL entry stops DMI scanning */
};

void __init efi_apply_memmap_quirks(void)
{
	/*
	 * Once setup is done earlier, unmap the EFI memory map on mismatched
	 * firmware/kernel architectures since there is no support for runtime
	 * services.
	 */
	if (!efi_runtime_supported()) {
		pr_info("Setup done, disabling due to 32/64-bit mismatch\n");
		efi_unmap_memmap();
	}

	/* UV2+ BIOS has a fix for this issue.  UV1 still needs the quirk. */
	if (dmi_check_system(sgi_uv1_dmi))
		set_bit(EFI_OLD_MEMMAP, &efi.flags);
}

/*
 * If any access by any efi runtime service causes a page fault, then,
 * 1. If it's efi_reset_system(), reboot through BIOS.
 * 2. If any other efi runtime service, then
 *    a. Return error status to the efi caller process.
 *    b. Disable EFI Runtime Services forever and
 *    c. Freeze efi_rts_wq and schedule new process.
 *
 * @return: Returns, if the page fault is not handled. This function
 * will never return if the page fault is handled successfully.
 */
void efi_recover_from_page_fault(unsigned long phys_addr)
{
	bool ibrs_on;

	if (!IS_ENABLED(CONFIG_X86_64))
		return;

	/*
	 * Make sure that an efi runtime service caused the page fault.
	 * "efi_mm" cannot be used to check if the page fault had occurred
	 * in the firmware context because efi=old_map doesn't use efi_pgd.
	 */
	if (efi_rts_work.efi_rts_id == NONE)
		return;

	/*
	 * Address range 0x0000 - 0x0fff is always mapped in the efi_pgd, so
	 * page faulting on these addresses isn't expected.
	 */
	if (phys_addr >= 0x0000 && phys_addr <= 0x0fff)
		return;

	/*
	 * Print stack trace as it might be useful to know which EFI Runtime
	 * Service is buggy.
	 */
	WARN(1, FW_BUG "Page fault caused by firmware at PA: 0x%lx\n",
	     phys_addr);

	/*
	 * Buggy efi_reset_system() is handled differently from other EFI
	 * Runtime Services as it doesn't use efi_rts_wq. Although,
	 * native_machine_emergency_restart() says that machine_real_restart()
	 * could fail, it's better not to compilcate this fault handler
	 * because this case occurs *very* rarely and hence could be improved
	 * on a need by basis.
	 */
	if (efi_rts_work.efi_rts_id == RESET_SYSTEM) {
		pr_info("efi_reset_system() buggy! Reboot through BIOS\n");
		machine_real_restart(MRR_BIOS);
		return;
	}

	/*
	 * Before calling EFI Runtime Service, the kernel has switched the
	 * calling process to efi_mm. Hence, switch back to task_mm.
	 */
	ibrs_on = arch_efi_call_virt_setup();
	arch_efi_call_virt_teardown(ibrs_on);

	/* Signal error status to the efi caller process */
	efi_rts_work.status = EFI_ABORTED;
	complete(&efi_rts_work.efi_rts_comp);

	clear_bit(EFI_RUNTIME_SERVICES, &efi.flags);
	pr_info("Froze efi_rts_wq and disabled EFI Runtime Services\n");

	/*
	 * Call schedule() in an infinite loop, so that any spurious wake ups
	 * will never run efi_rts_wq again.
	 */
	for (;;) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule();
	}

	return;
}
