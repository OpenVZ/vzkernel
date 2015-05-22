/*
 *  kernel/bc/vm_pages.c
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/virtinfo.h>
#include <linux/module.h>
#include <linux/shmem_fs.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/ve.h>

#include <asm/pgtable.h>
#include <asm/page.h>

#include <bc/beancounter.h>
#include <bc/vmpages.h>
#include <bc/proc.h>
#include <bc/oom_kill.h>

void __ub_update_oomguarpages(struct user_beancounter *ub)
{
	ub->ub_parms[UB_OOMGUARPAGES].held =
		ub->ub_parms[UB_PRIVVMPAGES].held +
		ub->ub_parms[UB_LOCKEDPAGES].held +
		ub->ub_parms[UB_PHYSPAGES].held +
		ub->ub_parms[UB_SWAPPAGES].held;

	ub_adjust_maxheld(ub, UB_OOMGUARPAGES);
}

long ub_oomguarpages_left(struct user_beancounter *ub)
{
	unsigned long flags;
	long left;
	int precharge[UB_RESOURCES];

	spin_lock_irqsave(&ub->ub_lock, flags);
	__ub_update_oomguarpages(ub);
	left = ub->ub_parms[UB_OOMGUARPAGES].barrier -
		ub->ub_parms[UB_OOMGUARPAGES].held;
	spin_unlock_irqrestore(&ub->ub_lock, flags);

	ub_precharge_snapshot(ub, precharge);
	left += precharge[UB_OOMGUARPAGES];

	return left;
}

void ub_update_resources_locked(struct user_beancounter *ub)
{
	__ub_update_oomguarpages(ub);
}
EXPORT_SYMBOL(ub_update_resources_locked);

void ub_update_resources(struct user_beancounter *ub)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	ub_update_resources_locked(ub);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}
EXPORT_SYMBOL(ub_update_resources);

int ub_memory_charge(struct mm_struct *mm, unsigned long size,
		unsigned vm_flags, struct file *vm_file, int sv)
{
	struct user_beancounter *ub;

	ub = mm->mm_ub;
	if (ub == NULL)
		return 0;

	size >>= PAGE_SHIFT;
	if (size > UB_MAXVALUE)
		return -EINVAL;

	BUG_ON(sv != UB_SOFT && sv != UB_HARD);

	if (vm_flags & VM_LOCKED) {
		if (charge_beancounter(ub, UB_LOCKEDPAGES, size, sv))
			goto out_err;
	}
	if (VM_UB_PRIVATE(vm_flags, vm_file)) {
               if (charge_beancounter_fast(ub, UB_PRIVVMPAGES, size, sv))
			goto out_private;
	}
	return 0;

out_private:
	if (vm_flags & VM_LOCKED)
		uncharge_beancounter(ub, UB_LOCKEDPAGES, size);
out_err:
	return -ENOMEM;
}

void ub_memory_uncharge(struct mm_struct *mm, unsigned long size,
		unsigned vm_flags, struct file *vm_file)
{
	struct user_beancounter *ub;

	ub = mm->mm_ub;
	if (ub == NULL)
		return;

	size >>= PAGE_SHIFT;

	if (vm_flags & VM_LOCKED)
		uncharge_beancounter(ub, UB_LOCKEDPAGES, size);
	if (VM_UB_PRIVATE(vm_flags, vm_file))
		uncharge_beancounter_fast(ub, UB_PRIVVMPAGES, size);
}

int ub_locked_charge(struct mm_struct *mm, unsigned long size)
{
	struct user_beancounter *ub;

	ub = mm->mm_ub;
	if (ub == NULL)
		return 0;

	return charge_beancounter(ub, UB_LOCKEDPAGES,
			size >> PAGE_SHIFT, UB_HARD);
}

void ub_locked_uncharge(struct mm_struct *mm, unsigned long size)
{
	struct user_beancounter *ub;

	ub = mm->mm_ub;
	if (ub == NULL)
		return;

	uncharge_beancounter(ub, UB_LOCKEDPAGES, size >> PAGE_SHIFT);
}

int ub_lockedshm_charge(struct shmem_inode_info *shi, unsigned long size)
{
	struct user_beancounter *ub;

	ub = shi->shmi_ub;
	if (ub == NULL)
		return 0;

	return charge_beancounter(ub, UB_LOCKEDPAGES,
			size >> PAGE_SHIFT, UB_HARD);
}

void ub_lockedshm_uncharge(struct shmem_inode_info *shi, unsigned long size)
{
	struct user_beancounter *ub;

	ub = shi->shmi_ub;
	if (ub == NULL)
		return;

	uncharge_beancounter(ub, UB_LOCKEDPAGES, size >> PAGE_SHIFT);
}

static inline void do_ub_tmpfs_respages_sub(struct user_beancounter *ub,
		unsigned long size)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	/* catch possible overflow */
	if (ub->ub_tmpfs_respages < size) {
		uncharge_warn(ub, "tmpfs_respages",
				size, ub->ub_tmpfs_respages);
		size = ub->ub_tmpfs_respages;
	}
	ub->ub_tmpfs_respages -= size;
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

static int bc_fill_sysinfo(struct user_beancounter *ub,
		unsigned long meminfo_val, struct sysinfo *si)
{
	unsigned long used, total;
	unsigned long totalram, totalswap;
	struct ubparm physpages, swappages;

	/* No virtualization */
	if (meminfo_val == VE_MEMINFO_SYSTEM)
		return NOTIFY_DONE | NOTIFY_STOP_MASK;

	totalram = si->totalram;
	totalswap = si->totalswap;

	memset(si, 0, sizeof(*si));

	ub_get_mem_cgroup_parms(ub, &physpages, &swappages, NULL);

	total = physpages.limit;
	used = physpages.held;

	if (total == UB_MAXVALUE)
		total = totalram;

	si->totalram = total;
	si->freeram = (total > used ? total - used : 0);

	total = swappages.limit;
	used = swappages.held;

	if (total == UB_MAXVALUE)
		total = totalswap;

	si->totalswap = total;
	si->freeswap = (total > used ? total - used : 0);

	si->mem_unit = PAGE_SIZE;

	return NOTIFY_OK;
}

static int bc_fill_meminfo(struct user_beancounter *ub,
		unsigned long meminfo_val, struct meminfo *mi)
{
	int cpu, ret;
	long dcache;
	struct ubparm kmemsize;

	ret = bc_fill_sysinfo(ub, meminfo_val, mi->si);
	if (ret & NOTIFY_STOP_MASK)
		goto out;

	ub_get_mem_cgroup_parms(ub, NULL, NULL, &kmemsize);
	ub_page_stat(ub, &node_online_map, mi->pages);

	mi->cached = min(mi->si->totalram - mi->si->freeram,
			mi->pages[LRU_INACTIVE_FILE] +
			mi->pages[LRU_ACTIVE_FILE]);
	mi->locked = ub->ub_parms[UB_LOCKEDPAGES].held;
	mi->shmem = ub->ub_parms[UB_SHMPAGES].held;
	dcache = ub->ub_parms[UB_DCACHESIZE].held;

	mi->dirty_pages = __ub_stat_get(ub, dirty_pages);
	mi->writeback_pages = __ub_stat_get(ub, writeback_pages);
	for_each_possible_cpu(cpu) {
		struct ub_percpu_struct *pcpu = ub_percpu(ub, cpu);

		mi->dirty_pages	+= pcpu->dirty_pages;
		mi->writeback_pages	+= pcpu->writeback_pages;
		dcache		-= pcpu->precharge[UB_DCACHESIZE];
	}

	mi->dirty_pages = max_t(long, 0, mi->dirty_pages);
	mi->writeback_pages = max_t(long, 0, mi->writeback_pages);

	mi->slab_reclaimable = DIV_ROUND_UP(max(0L, dcache), PAGE_SIZE);
	mi->slab_unreclaimable =
		DIV_ROUND_UP(max(0L, (long)kmemsize.held - dcache), PAGE_SIZE);
out:
	return ret;
}

static int bc_fill_vmstat(struct user_beancounter *ub, unsigned long *stat)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct ub_percpu_struct *pcpu = ub_percpu(ub, cpu);

		stat[NR_VM_ZONE_STAT_ITEMS + PSWPIN]	+= pcpu->swapin;
		stat[NR_VM_ZONE_STAT_ITEMS + PSWPOUT]	+= pcpu->swapout;

		stat[NR_VM_ZONE_STAT_ITEMS + PSWPIN]	+= pcpu->vswapin;
		stat[NR_VM_ZONE_STAT_ITEMS + PSWPOUT]	+= pcpu->vswapout;
	}

	return NOTIFY_OK;
}

static int bc_mem_notify(struct vnotifier_block *self,
		unsigned long event, void *arg, int old_ret)
{
	switch (event) {
	case VIRTINFO_MEMINFO: {
		struct meminfo *mi = arg;
		return bc_fill_meminfo(mi->ub, mi->meminfo_val, mi);
	}
	case VIRTINFO_SYSINFO:
		return bc_fill_sysinfo(get_exec_ub(),
				get_exec_env()->meminfo_val, arg);
	case VIRTINFO_VMSTAT:
		return bc_fill_vmstat(get_exec_ub(), arg);
	};

	return old_ret;
}

static struct vnotifier_block bc_mem_notifier_block = {
	.notifier_call = bc_mem_notify,
};

static int __init init_vmguar_notifier(void)
{
	virtinfo_notifier_register(VITYPE_GENERAL, &bc_mem_notifier_block);
	return 0;
}

static void __exit fini_vmguar_notifier(void)
{
	virtinfo_notifier_unregister(VITYPE_GENERAL, &bc_mem_notifier_block);
}

module_init(init_vmguar_notifier);
module_exit(fini_vmguar_notifier);

static void __show_one_resource(const char *name, struct ubparm *parm)
{
	if (parm->limit == UB_MAXVALUE)
		printk("%s: %lu / inf [%lu] ", name,
				parm->held, parm->failcnt);
	else
		printk("%s: %lu / %lu [%lu] ", name,
				parm->held, parm->limit, parm->failcnt);
}

void __show_ub_mem(struct user_beancounter *ub)
{
	__show_one_resource("RAM", ub->ub_parms + UB_PHYSPAGES);
	__show_one_resource("SWAP", ub->ub_parms + UB_SWAPPAGES);
	__show_one_resource("KMEM", ub->ub_parms + UB_KMEMSIZE);
	__show_one_resource("DCSZ", ub->ub_parms + UB_DCACHESIZE);
	__show_one_resource("OOMG", ub->ub_parms + UB_OOMGUARPAGES);

	printk("Dirty %lu Wback %lu\n",
			ub_stat_get(ub, dirty_pages),
			ub_stat_get(ub, writeback_pages));
}

void show_ub_mem(struct user_beancounter *ub)
{
	printk(KERN_INFO "UB-%s-Mem-Info:\n", ub->ub_name);
	__show_ub_mem(ub);
}

#ifdef CONFIG_PROC_FS
static int bc_vmaux_show(struct seq_file *f, void *v)
{
	struct user_beancounter *ub;
	struct ub_percpu_struct *ub_pcpu;
	unsigned long swapin, swapout, vswapin, vswapout;
	struct ubparm physpages;
	int i;

	ub = seq_beancounter(f);

	ub_get_mem_cgroup_parms(ub, &physpages, NULL, NULL);

	swapin = swapout = vswapin = vswapout = 0;
	for_each_possible_cpu(i) {
		ub_pcpu = ub_percpu(ub, i);
		swapin += ub_pcpu->swapin;
		swapout += ub_pcpu->swapout;
		vswapin += ub_pcpu->vswapin;
		vswapout += ub_pcpu->vswapout;
	}

	seq_printf(f, bc_proc_lu_fmt, "tmpfs_respages",
			ub->ub_tmpfs_respages);

	seq_printf(f, bc_proc_lu_fmt, "swapin", swapin);
	seq_printf(f, bc_proc_lu_fmt, "swapout", swapout);

	seq_printf(f, bc_proc_lu_fmt, "vswapin", vswapin);
	seq_printf(f, bc_proc_lu_fmt, "vswapout", vswapout);

	seq_printf(f, bc_proc_lu_fmt, "ram", physpages.held);

	return 0;
}
static struct bc_proc_entry bc_vmaux_entry = {
	.name = "vmaux",
	.u.show = bc_vmaux_show,
};

static int __init bc_vmaux_init(void)
{
	bc_register_proc_entry(&bc_vmaux_entry);
	return 0;
}

late_initcall(bc_vmaux_init);
#endif
