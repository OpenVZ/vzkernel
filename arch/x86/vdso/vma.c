/*
 * Set up the VMAs to tell the VM about the vDSO.
 * Copyright 2007 Andi Kleen, SUSE Labs.
 * Subject to the GPL, v.2
 */
#include <linux/mm.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/elf.h>
#include <asm/vsyscall.h>
#include <asm/vgtod.h>
#include <asm/proto.h>
#include <asm/vdso.h>
#include <asm/page.h>

#include <linux/utsname.h>
#include <linux/version.h>
#include <linux/ve.h>

unsigned int __read_mostly vdso_enabled = 1;

extern char vdso_start[], vdso_end[];
extern unsigned short vdso_sync_cpuid;

extern struct page *vdso_pages[];
static unsigned vdso_size;

#ifdef CONFIG_X86_X32_ABI
extern char vdsox32_start[], vdsox32_end[];
extern struct page *vdsox32_pages[];
static unsigned vdsox32_size;

static void __init patch_vdsox32(void *vdso, size_t len)
{
	Elf32_Ehdr *hdr = vdso;
	Elf32_Shdr *sechdrs, *alt_sec = 0;
	char *secstrings;
	void *alt_data;
	int i;

	BUG_ON(len < sizeof(Elf32_Ehdr));
	BUG_ON(memcmp(hdr->e_ident, ELFMAG, SELFMAG) != 0);

	sechdrs = (void *)hdr + hdr->e_shoff;
	secstrings = (void *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;

	for (i = 1; i < hdr->e_shnum; i++) {
		Elf32_Shdr *shdr = &sechdrs[i];
		if (!strcmp(secstrings + shdr->sh_name, ".altinstructions")) {
			alt_sec = shdr;
			goto found;
		}
	}

	/* If we get here, it's probably a bug. */
	pr_warning("patch_vdsox32: .altinstructions not found\n");
	return;  /* nothing to patch */

found:
	alt_data = (void *)hdr + alt_sec->sh_offset;
	apply_alternatives(alt_data, alt_data + alt_sec->sh_size);
}
#endif

static void __init patch_vdso64(void *vdso, size_t len)
{
	Elf64_Ehdr *hdr = vdso;
	Elf64_Shdr *sechdrs, *alt_sec = 0;
	char *secstrings;
	void *alt_data;
	int i;

	BUG_ON(len < sizeof(Elf64_Ehdr));
	BUG_ON(memcmp(hdr->e_ident, ELFMAG, SELFMAG) != 0);

	sechdrs = (void *)hdr + hdr->e_shoff;
	secstrings = (void *)hdr + sechdrs[hdr->e_shstrndx].sh_offset;

	for (i = 1; i < hdr->e_shnum; i++) {
		Elf64_Shdr *shdr = &sechdrs[i];
		if (!strcmp(secstrings + shdr->sh_name, ".altinstructions")) {
			alt_sec = shdr;
			goto found;
		}
	}

	/* If we get here, it's probably a bug. */
	pr_warning("patch_vdso64: .altinstructions not found\n");
	return;  /* nothing to patch */

found:
	alt_data = (void *)hdr + alt_sec->sh_offset;
	apply_alternatives(alt_data, alt_data + alt_sec->sh_size);
}

static int __init init_vdso(void)
{
	int npages = (vdso_end - vdso_start + PAGE_SIZE - 1) / PAGE_SIZE;
	int i;

	patch_vdso64(vdso_start, vdso_end - vdso_start);

	vdso_size = npages << PAGE_SHIFT;
	for (i = 0; i < npages; i++)
		vdso_pages[i] = virt_to_page(vdso_start + i*PAGE_SIZE);

#ifdef CONFIG_X86_X32_ABI
	patch_vdsox32(vdsox32_start, vdsox32_end - vdsox32_start);
	npages = (vdsox32_end - vdsox32_start + PAGE_SIZE - 1) / PAGE_SIZE;
	vdsox32_size = npages << PAGE_SHIFT;
	for (i = 0; i < npages; i++)
		vdsox32_pages[i] = virt_to_page(vdsox32_start + i*PAGE_SIZE);
#endif

	init_uts_ns.vdso.addr		= vdso_start;
	init_uts_ns.vdso.pages		= vdso_pages;
	init_uts_ns.vdso.nr_pages	= npages;
	init_uts_ns.vdso.size		= vdso_size;
	init_uts_ns.vdso.version_off	= (unsigned long)VDSO64_SYMBOL(0, linux_version_code);

	return 0;
}
subsys_initcall(init_vdso);

struct linux_binprm;

/* 
 * Put the vdso above the (randomized) stack with another randomized
 * offset.  This way there is no hole in the middle of address space.
 * To save memory make sure it is still in the same PTE as the stack
 * top.  This doesn't give that many random bits.
 *
 * Note that this algorithm is imperfect: the distribution of the vdso
 * start address within a PMD is biased toward the end.
 *
 * Only used for the 64-bit and x32 vdsos.
 */
static unsigned long vdso_addr(unsigned long start, unsigned len)
{
	unsigned long addr, end;
	unsigned offset;

	/*
	 * Round up the start address.  It can start out unaligned as a result
	 * of stack start randomization.
	 */
	start = PAGE_ALIGN(start);

	/* Round the lowest possible end address up to a PMD boundary. */
	end = (start + len + PMD_SIZE - 1) & PMD_MASK;
	if (end >= TASK_SIZE_MAX)
		end = TASK_SIZE_MAX;
	end -= len;

	if (end > start) {
		offset = get_random_int() % (((end - start) >> PAGE_SHIFT) + 1);
		addr = start + (offset << PAGE_SHIFT);
	} else {
		addr = start;
	}

	/*
	 * Forcibly align the final address in case we have a hardware
	 * issue that requires alignment for performance reasons.
	 */
	addr = align_vdso_addr(addr);

	return addr;
}

bool vdso_or_vvar_present(struct mm_struct *mm)
{
	struct vm_area_struct *vma;

	for (vma = mm->mmap; vma; vma = vma->vm_next)
		if (vma_is_vdso_or_vvar(vma, mm))
			return true;
	return false;
}

/* Setup a VMA at program startup for the vsyscall page.
   Not called for compat tasks */
static int setup_additional_pages(struct linux_binprm *bprm,
				  int uses_interp,
				  struct page **pages,
				  unsigned size,
				  unsigned long req_addr)
{
	struct mm_struct *mm = current->mm;
	unsigned long addr = req_addr;
	int ret;

	if (!vdso_enabled)
		return 0;

	down_write(&mm->mmap_sem);

	if (vdso_or_vvar_present(mm)) {
		ret = -EEXIST;
		goto up_fail;
	}

	if (!req_addr)
		addr = vdso_addr(mm->start_stack, size);

	addr = get_unmapped_area(NULL, addr, size, 0, 0);
	if (IS_ERR_VALUE(addr)) {
		ret = addr;
		goto up_fail;
	}

	if (req_addr && req_addr != addr) {
		ret = -EFAULT;
		goto up_fail;
	}

	current->mm->context.vdso = (void *)addr;

	ret = install_special_mapping(mm, addr, size,
				      VM_READ|VM_EXEC|
				      VM_MAYREAD|VM_MAYWRITE|VM_MAYEXEC,
				      pages);
	if (ret) {
		current->mm->context.vdso = NULL;
		goto up_fail;
	}

up_fail:
	up_write(&mm->mmap_sem);
	return ret;
}

static DEFINE_MUTEX(vdso_mutex);

static int uts_arch_setup_additional_pages(struct linux_binprm *bprm,
		int uses_interp, unsigned long addr)
{
	struct uts_namespace *uts_ns = current->nsproxy->uts_ns;
	struct ve_struct *ve = get_exec_env();
	int i, n1, n2, n3, new_version;
	struct page **new_pages, **p;

	/*
	 * For node or in case we've not changed UTS simply
	 * map preallocated original vDSO.
	 *
	 * In turn if we already allocated one for this UTS
	 * simply reuse it. It improves speed significantly.
	 */
	if (uts_ns == &init_uts_ns)
		goto map_init_uts;
	/*
	 * Dirty lockless hack. Strictly speaking
	 * we need to return @p here if it's non-nil,
	 * but since there only one trasition possible
	 * { =0 ; !=0 } we simply return @uts_ns->vdso.pages
	 */
	p = ACCESS_ONCE(uts_ns->vdso.pages);
	smp_read_barrier_depends();
	if (p)
		goto map_uts;

	if (sscanf(uts_ns->name.release, "%d.%d.%d", &n1, &n2, &n3) == 3) {
		/*
		 * If there were no changes on version simply reuse
		 * preallocated one.
		 */
		new_version = KERNEL_VERSION(n1, n2, n3);
	} else {
		/*
		 * If admin is passed malformed string here
		 * lets warn him once but continue working
		 * not using vDSO virtualization at all. It's
		 * better than walk out with error.
		 */
		pr_warn_once("Wrong release uts name format detected."
			     " Using host's uts name.\n");
		new_version = LINUX_VERSION_CODE;
	}

	mutex_lock(&vdso_mutex);
	if (uts_ns->vdso.pages) {
		mutex_unlock(&vdso_mutex);
		goto map_uts;
	}

	uts_ns->vdso.nr_pages	= init_uts_ns.vdso.nr_pages;
	uts_ns->vdso.size	= init_uts_ns.vdso.size;
	uts_ns->vdso.version_off= init_uts_ns.vdso.version_off;
	new_pages		= kmalloc(sizeof(struct page *) * init_uts_ns.vdso.nr_pages, GFP_KERNEL);
	if (!new_pages) {
		pr_err("Can't allocate vDSO pages array for VE %d\n", ve->veid);
		goto out_unlock;
	}

	for (i = 0; i < uts_ns->vdso.nr_pages; i++) {
		struct page *p = alloc_page(GFP_KERNEL);
		if (!p) {
			pr_err("Can't allocate page for VE %d\n", ve->veid);
			for (; i > 0; i--)
				put_page(new_pages[i - 1]);
			kfree(new_pages);
			goto out_unlock;
		}
		new_pages[i] = p;
		copy_page(page_address(p), page_address(init_uts_ns.vdso.pages[i]));
	}

	uts_ns->vdso.addr = vmap(new_pages, uts_ns->vdso.nr_pages, 0, PAGE_KERNEL);
	if (!uts_ns->vdso.addr) {
		pr_err("Can't map vDSO pages for VE %d\n", ve->veid);
		for (i = 0; i < uts_ns->vdso.nr_pages; i++)
			put_page(new_pages[i]);
		kfree(new_pages);
		goto out_unlock;
	}

	*((int *)(uts_ns->vdso.addr + uts_ns->vdso.version_off)) = new_version;
	*((struct timespec*)(VDSO64_SYMBOL(uts_ns->vdso.addr, ve_start_timespec))) = ve->start_timespec;
	smp_wmb();
	uts_ns->vdso.pages = new_pages;
	mutex_unlock(&vdso_mutex);

	pr_debug("vDSO version transition %d -> %d for VE %d\n",
		 LINUX_VERSION_CODE, new_version, ve->veid);

map_uts:
	return setup_additional_pages(bprm, uses_interp, uts_ns->vdso.pages,
		uts_ns->vdso.size, addr);
map_init_uts:
	return setup_additional_pages(bprm, uses_interp, init_uts_ns.vdso.pages,
		init_uts_ns.vdso.size, addr);
out_unlock:
	mutex_unlock(&vdso_mutex);
	return -ENOMEM;
}

int arch_setup_additional_pages(struct linux_binprm *bprm, int uses_interp)
{
	return uts_arch_setup_additional_pages(bprm, uses_interp, 0);
}

int do_map_vdso_64(unsigned long req_addr)
{
	return uts_arch_setup_additional_pages(0, 0, req_addr);
}

#ifdef CONFIG_X86_X32_ABI
int x32_setup_additional_pages(struct linux_binprm *bprm, int uses_interp)
{
	return setup_additional_pages(bprm, uses_interp, vdsox32_pages,
				      vdsox32_size, 0);
}
#endif

static __init int vdso_setup(char *s)
{
	vdso_enabled = simple_strtoul(s, NULL, 0);
	return 0;
}
__setup("vdso=", vdso_setup);
