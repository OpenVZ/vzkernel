/*
 * Helper functions used by the EFI stub on multiple
 * architectures. This should be #included by the EFI stub
 * implementation files.
 *
 * Copyright 2011 Intel Corporation; author Matt Fleming
 *
 * This file is part of the Linux kernel, and is made available
 * under the terms of the GNU General Public License version 2.
 *
 */
#define EFI_READ_CHUNK_SIZE	(1024 * 1024)

struct initrd {
	efi_file_handle_t *handle;
	u64 size;
};

static void efi_printk(efi_system_table_t *sys_table_arg, char *str)
{
	char *s8;

	for (s8 = str; *s8; s8++) {
		efi_char16_t ch[2] = { 0 };

		ch[0] = *s8;
		if (*s8 == '\n') {
			efi_char16_t nl[2] = { '\r', 0 };
			efi_char16_printk(sys_table_arg, nl);
		}

		efi_char16_printk(sys_table_arg, ch);
	}
}

#define pr_efi(sys_table, msg)     efi_printk(sys_table, "EFI stub: "msg)
#define pr_efi_err(sys_table, msg) efi_printk(sys_table, "EFI stub: ERROR: "msg)


static efi_status_t efi_get_memory_map(efi_system_table_t *sys_table_arg,
				       efi_memory_desc_t **map,
				       unsigned long *map_size,
				       unsigned long *desc_size,
				       u32 *desc_ver,
				       unsigned long *key_ptr)
{
	efi_memory_desc_t *m = NULL;
	efi_status_t status;
	unsigned long key;
	u32 desc_version;

	*map_size = sizeof(*m) * 32;
again:
	/*
	 * Add an additional efi_memory_desc_t because we're doing an
	 * allocation which may be in a new descriptor region.
	 */
	*map_size += sizeof(*m);
	status = efi_call_early(allocate_pool, EFI_LOADER_DATA,
				*map_size, (void **)&m);
	if (status != EFI_SUCCESS)
		goto fail;

	*desc_size = 0;
	key = 0;
	status = efi_call_early(get_memory_map, map_size, m,
				&key, desc_size, &desc_version);
	if (status == EFI_BUFFER_TOO_SMALL) {
		efi_call_early(free_pool, m);
		goto again;
	}

	if (status != EFI_SUCCESS)
		efi_call_early(free_pool, m);

	if (key_ptr && status == EFI_SUCCESS)
		*key_ptr = key;
	if (desc_ver && status == EFI_SUCCESS)
		*desc_ver = desc_version;

fail:
	*map = m;
	return status;
}

/*
 * Allocate at the highest possible address that is not above 'max'.
 */
static efi_status_t efi_high_alloc(efi_system_table_t *sys_table_arg,
			       unsigned long size, unsigned long align,
			       unsigned long *addr, unsigned long max)
{
	unsigned long map_size, desc_size;
	efi_memory_desc_t *map;
	efi_status_t status;
	unsigned long nr_pages;
	u64 max_addr = 0;
	int i;

	status = efi_get_memory_map(sys_table_arg, &map, &map_size, &desc_size,
				    NULL, NULL);
	if (status != EFI_SUCCESS)
		goto fail;

	nr_pages = round_up(size, EFI_PAGE_SIZE) / EFI_PAGE_SIZE;
again:
	for (i = 0; i < map_size / desc_size; i++) {
		efi_memory_desc_t *desc;
		unsigned long m = (unsigned long)map;
		u64 start, end;

		desc = efi_early_memdesc_ptr(m, desc_size, i);
		if (desc->type != EFI_CONVENTIONAL_MEMORY)
			continue;

		if (desc->num_pages < nr_pages)
			continue;

		start = desc->phys_addr;
		end = start + desc->num_pages * (1UL << EFI_PAGE_SHIFT);

		if ((start + size) > end || (start + size) > max)
			continue;

		if (end - size > max)
			end = max;

		if (round_down(end - size, align) < start)
			continue;

		start = round_down(end - size, align);

		/*
		 * Don't allocate at 0x0. It will confuse code that
		 * checks pointers against NULL.
		 */
		if (start == 0x0)
			continue;

		if (start > max_addr)
			max_addr = start;
	}

	if (!max_addr)
		status = EFI_NOT_FOUND;
	else {
		status = efi_call_early(allocate_pages,
					EFI_ALLOCATE_ADDRESS, EFI_LOADER_DATA,
					nr_pages, &max_addr);
		if (status != EFI_SUCCESS) {
			max = max_addr;
			max_addr = 0;
			goto again;
		}

		*addr = max_addr;
	}

	efi_call_early(free_pool, map);
fail:
	return status;
}

/*
 * Allocate at the lowest possible address that is not below 'min'.
 */
static efi_status_t efi_low_alloc_above(efi_system_table_t *sys_table_arg,
					unsigned long size, unsigned long align,
					unsigned long *addr, unsigned long min)
{
	unsigned long map_size, desc_size;
	efi_memory_desc_t *map;
	efi_status_t status;
	unsigned long nr_pages;
	int i;

	status = efi_get_memory_map(sys_table_arg, &map, &map_size, &desc_size,
				    NULL, NULL);
	if (status != EFI_SUCCESS)
		goto fail;

	nr_pages = round_up(size, EFI_PAGE_SIZE) / EFI_PAGE_SIZE;
	for (i = 0; i < map_size / desc_size; i++) {
		efi_memory_desc_t *desc;
		unsigned long m = (unsigned long)map;
		u64 start, end;

		desc = efi_early_memdesc_ptr(m, desc_size, i);

		if (desc->type != EFI_CONVENTIONAL_MEMORY)
			continue;

		if (desc->num_pages < nr_pages)
			continue;

		start = desc->phys_addr;
		end = start + desc->num_pages * (1UL << EFI_PAGE_SHIFT);

		if (start < min)
			start = min;

		start = round_up(start, align);
		if ((start + size) > end)
			continue;

		status = efi_call_early(allocate_pages,
					EFI_ALLOCATE_ADDRESS, EFI_LOADER_DATA,
					nr_pages, &start);
		if (status == EFI_SUCCESS) {
			*addr = start;
			break;
		}
	}

	if (i == map_size / desc_size)
		status = EFI_NOT_FOUND;

	efi_call_early(free_pool, map);
fail:
	return status;
}

static inline
efi_status_t efi_low_alloc(efi_system_table_t *sys_table_arg,
			   unsigned long size, unsigned long align,
			   unsigned long *addr)
{
	/*
	 * Don't allocate at 0x0. It will confuse code that
	 * checks pointers against NULL. Skip the first 8
	 * bytes so we start at a nice even number.
	 */
	return efi_low_alloc_above(sys_table_arg, size, align, addr, 0x8);
}

static void efi_free(efi_system_table_t *sys_table_arg, unsigned long size,
		     unsigned long addr)
{
	unsigned long nr_pages;

	if (!size)
		return;

	nr_pages = round_up(size, EFI_PAGE_SIZE) / EFI_PAGE_SIZE;
	efi_call_early(free_pages, addr, nr_pages);
}


/*
 * Check the cmdline for a LILO-style initrd= arguments.
 *
 * We only support loading an initrd from the same filesystem as the
 * kernel image.
 */
static efi_status_t handle_cmdline_files(efi_system_table_t *sys_table_arg,
					 efi_loaded_image_t *image,
					 char *cmd_line, char *option_string,
					 unsigned long max_addr,
					 unsigned long *load_addr,
					 unsigned long *load_size)
{
	struct initrd *initrds;
	unsigned long initrd_addr;
	u64 initrd_total;
	efi_file_handle_t *fh = NULL;
	efi_status_t status;
	int nr_initrds;
	char *str;
	int i, j, k;

	initrd_addr = 0;
	initrd_total = 0;

	str = cmd_line;

	j = 0;			/* See close_handles */

	if (!load_addr || !load_size)
		return EFI_INVALID_PARAMETER;

	*load_addr = 0;
	*load_size = 0;

	if (!str || !*str)
		return EFI_SUCCESS;

	for (nr_initrds = 0; *str; nr_initrds++) {
		str = strstr(str, option_string);
		if (!str)
			break;

		str += strlen(option_string);

		/* Skip any leading slashes */
		while (*str == '/' || *str == '\\')
			str++;

		while (*str && *str != ' ' && *str != '\n')
			str++;
	}

	if (!nr_initrds)
		return EFI_SUCCESS;

	status = efi_call_early(allocate_pool, EFI_LOADER_DATA,
				nr_initrds * sizeof(*initrds),
				(void **)&initrds);
	if (status != EFI_SUCCESS) {
		pr_efi_err(sys_table_arg, "Failed to alloc mem for file load\n");
		goto fail;
	}

	str = cmd_line;
	for (i = 0; i < nr_initrds; i++) {
		struct initrd *initrd;
		efi_char16_t filename_16[256];
		efi_char16_t *p;

		str = strstr(str, option_string);
		if (!str)
			break;

		str += strlen(option_string);

		initrd = &initrds[i];
		p = filename_16;

		/* Skip any leading slashes */
		while (*str == '/' || *str == '\\')
			str++;

		while (*str && *str != ' ' && *str != '\n') {
			if ((u8 *)p >= (u8 *)filename_16 + sizeof(filename_16))
				break;

			if (*str == '/') {
				*p++ = '\\';
				str++;
			} else {
				*p++ = *str++;
			}
		}

		*p = '\0';

		/* Only open the volume once. */
		if (!i) {
			status = efi_open_volume(sys_table_arg, image,
						 (void **)&fh);
			if (status != EFI_SUCCESS)
				goto free_initrds;
		}

		status = efi_file_size(sys_table_arg, fh, filename_16,
				       (void **)&initrd->handle, &initrd->size);
		if (status != EFI_SUCCESS)
			goto close_handles;

		initrd_total += initrd->size;
	}

	if (initrd_total) {
		unsigned long addr;

		/*
		 * Multiple initrd's need to be at consecutive
		 * addresses in memory, so allocate enough memory for
		 * all the initrd's.
		 */
		status = efi_high_alloc(sys_table_arg, initrd_total, 0x1000,
				    &initrd_addr, max_addr);
		if (status != EFI_SUCCESS) {
			pr_efi_err(sys_table_arg, "Failed to alloc highmem for initrds\n");
			goto close_handles;
		}

		/* We've run out of free low memory. */
		if (initrd_addr > max_addr) {
			pr_efi_err(sys_table_arg, "We've run out of free low memory\n");
			status = EFI_INVALID_PARAMETER;
			goto free_initrd_total;
		}

		addr = initrd_addr;
		for (j = 0; j < nr_initrds; j++) {
			unsigned long size;

			size = initrds[j].size;
			while (size) {
				unsigned long chunksize;
				if (size > EFI_READ_CHUNK_SIZE)
					chunksize = EFI_READ_CHUNK_SIZE;
				else
					chunksize = size;

				status = efi_file_read(initrds[j].handle,
						       &chunksize,
						       (void *)addr);
				if (status != EFI_SUCCESS) {
					pr_efi_err(sys_table_arg, "Failed to read file\n");
					goto free_initrd_total;
				}
				addr += chunksize;
				size -= chunksize;
			}

			efi_file_close(initrds[j].handle);
		}

	}

	efi_call_early(free_pool, initrds);

	*load_addr = initrd_addr;
	*load_size = initrd_total;

	return status;

free_initrd_total:
	efi_free(sys_table_arg, initrd_total, initrd_addr);

close_handles:
	for (k = j; k < i; k++)
		efi_file_close(initrds[k].handle);
free_initrds:
	efi_call_early(free_pool, initrds);
fail:
	*load_addr = 0;
	*load_size = 0;

	return status;
}

static efi_status_t relocate_kernel(struct setup_header *hdr,
				    unsigned long min_addr)
{
	unsigned long start, nr_pages;
	efi_status_t status;

	/*
	 * The EFI firmware loader could have placed the kernel image
	 * anywhere in memory, but the kernel has various restrictions
	 * on the max physical address it can run at. Attempt to move
	 * the kernel to boot_params.pref_address, or as low as
	 * possible.
	 */
	start = hdr->pref_address;
	nr_pages = round_up(hdr->init_size, EFI_PAGE_SIZE) / EFI_PAGE_SIZE;

	status = efi_call_early(allocate_pages,
				EFI_ALLOCATE_ADDRESS, EFI_LOADER_DATA,
				nr_pages, &start);
	if (status != EFI_SUCCESS) {
		status = efi_low_alloc_above(sys_table, hdr->init_size,
					     hdr->kernel_alignment,
					     &start, min_addr);
		if (status != EFI_SUCCESS)
			pr_efi_err(sys_table, "Failed to alloc mem for kernel\n");
	}

	if (status == EFI_SUCCESS)
		memcpy((void *)start, (void *)(unsigned long)hdr->code32_start,
		       hdr->init_size);

	hdr->pref_address = hdr->code32_start;
	hdr->code32_start = (__u32)start;

	return status;
}

/*
 * Convert the unicode UEFI command line to ASCII to pass to kernel.
 * Size of memory allocated return in *cmd_line_len.
 * Returns NULL on error.
 */
static char *efi_convert_cmdline_to_ascii(efi_system_table_t *sys_table_arg,
				      efi_loaded_image_t *image,
				      int *cmd_line_len)
{
	u16 *s2;
	u8 *s1 = NULL;
	unsigned long cmdline_addr = 0;
	int load_options_size = image->load_options_size / 2; /* ASCII */
	void *options = image->load_options;
	int options_size = 0;
	efi_status_t status;
	int i;
	u16 zero = 0;

	if (options) {
		s2 = options;
		while (*s2 && *s2 != '\n' && options_size < load_options_size) {
			s2++;
			options_size++;
		}
	}

	if (options_size == 0) {
		/* No command line options, so return empty string*/
		options_size = 1;
		options = &zero;
	}

	options_size++;  /* NUL termination */

	/* RHEL7-ONLY: alignment must not be zero. */
	status = efi_low_alloc(sys_table_arg, options_size, 1, &cmdline_addr);
	if (status != EFI_SUCCESS)
		return NULL;

	s1 = (u8 *)cmdline_addr;
	s2 = (u16 *)options;

	for (i = 0; i < options_size - 1; i++)
		*s1++ = *s2++;

	*s1 = '\0';

	*cmd_line_len = options_size;
	return (char *)cmdline_addr;
}
