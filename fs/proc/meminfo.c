// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/mmzone.h>
#include <linux/proc_fs.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/atomic.h>
#include <linux/vmalloc.h>
#include <linux/virtinfo.h>
#include <linux/memcontrol.h>
#include <linux/ve.h>
#ifdef CONFIG_CMA
#include <linux/cma.h>
#endif
#include <asm/page.h>
#include "internal.h"

void __attribute__((weak)) arch_report_meminfo(struct seq_file *m)
{
}

static void show_val_kb(struct seq_file *m, const char *s, unsigned long num)
{
	seq_put_decimal_ull_width(m, s, num << (PAGE_SHIFT - 10), 8);
	seq_write(m, " kB\n", 4);
}

#ifdef CONFIG_TCACHE
extern unsigned long get_nr_tcache_pages(void);
#else
static inline unsigned long get_nr_tcache_pages(void) { return 0; }
#endif

static int meminfo_proc_show_mi(struct seq_file *m, struct meminfo *mi)
{
	unsigned long *pages;

	pages = mi->pages;

	show_val_kb(m, "MemTotal:       ", mi->si->totalram);
	show_val_kb(m, "MemFree:        ", mi->si->freeram);
	show_val_kb(m, "MemAvailable:	", mi->available);
	show_val_kb(m, "Buffers:        ", 0);
	show_val_kb(m, "Cached:         ", mi->cached);

	show_val_kb(m, "Active:         ", pages[LRU_ACTIVE_ANON] +
					   pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive:       ", pages[LRU_INACTIVE_ANON] +
					   pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Active(anon):   ", pages[LRU_ACTIVE_ANON]);
	show_val_kb(m, "Inactive(anon): ", pages[LRU_INACTIVE_ANON]);
	show_val_kb(m, "Active(file):   ", pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive(file): ", pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Unevictable:    ", pages[LRU_UNEVICTABLE]);
	show_val_kb(m, "Mlocked:        ", 0);

	show_val_kb(m, "SwapTotal:      ", mi->si->totalswap);
	show_val_kb(m, "SwapFree:       ", mi->si->freeswap);
	show_val_kb(m, "Dirty:          ", mi->dirty_pages);
	show_val_kb(m, "Writeback:      ", mi->writeback_pages);

	show_val_kb(m, "AnonPages:      ", pages[LRU_ACTIVE_ANON] +
					   pages[LRU_INACTIVE_ANON]);
	show_val_kb(m, "Shmem:          ", mi->si->sharedram);
	show_val_kb(m, "Slab:           ", mi->slab_reclaimable +
					   mi->slab_unreclaimable);
	show_val_kb(m, "SReclaimable:   ", mi->slab_reclaimable);
	show_val_kb(m, "SUnreclaim:     ", mi->slab_unreclaimable);

       return 0;
}

void si_meminfo_ve(struct sysinfo *si, struct ve_struct *ve)
{
	unsigned long memtotal, memused, swaptotal, swapused;
	struct mem_cgroup *memcg;
	struct cgroup_subsys_state *css;

	memset(si, 0, sizeof(*si));

	css = ve_get_init_css(ve, memory_cgrp_id);
	memcg = mem_cgroup_from_css(css);

	si->sharedram = memcg_page_state(memcg, NR_SHMEM);

	memtotal = READ_ONCE(memcg->memory.max);
	memused = page_counter_read(&memcg->memory);
	si->totalram = memtotal;

	swaptotal = READ_ONCE(memcg->memsw.max) - memtotal;
	swapused = page_counter_read(&memcg->memsw) - memused;
	si->totalswap = swaptotal;
	/* Due to global reclaim, memory.memsw.usage can be greater than
	 * (memory.memsw.max - memory.max). */
	if (swaptotal >= swapused) {
		si->freeswap = swaptotal - swapused;
	} else {
		si->freeswap = 0;
		memused += swapused - swaptotal;
	}

	si->freeram = (memtotal > memused ? memtotal - memused : 0);
	si->mem_unit = PAGE_SIZE;

	css_put(css);

	/* bufferram, totalhigh and freehigh left 0 */
}

static void fill_meminfo_ve(struct meminfo *mi, struct ve_struct *ve)
{
	struct cgroup_subsys_state *css;

	si_meminfo_ve(mi->si, ve);

	css = ve_get_init_css(ve, memory_cgrp_id);
	mem_cgroup_fill_meminfo(mem_cgroup_from_css(css), mi);
	css_put(css);

}

static int meminfo_proc_show_ve(struct seq_file *m, void *v,
				struct ve_struct *ve)
{
	struct sysinfo i;
	struct meminfo mi;
	unsigned long committed;
	long cached;
	long available;
	unsigned long pages[NR_LRU_LISTS];
	unsigned long sreclaimable, sunreclaim;
	int lru;

	si_meminfo(&i);
	si_swapinfo(&i);

        memset(&mi, 0, sizeof(mi));
        mi.si = &i;
        mi.ve = ve;

	if (!ve_is_super(ve) && ve->meminfo_val == VE_MEMINFO_DEFAULT) {
		fill_meminfo_ve(&mi, ve);

		return meminfo_proc_show_mi(m, &mi);
	}

	committed = vm_memory_committed();

	cached = global_node_page_state(NR_FILE_PAGES) -
			total_swapcache_pages() - i.bufferram;
	if (cached < 0)
		cached = 0;

	for (lru = LRU_BASE; lru < NR_LRU_LISTS; lru++)
		pages[lru] = global_node_page_state(NR_LRU_BASE + lru);

	available = si_mem_available();
	sreclaimable = global_node_page_state_pages(NR_SLAB_RECLAIMABLE_B);
	sunreclaim = global_node_page_state_pages(NR_SLAB_UNRECLAIMABLE_B);

	show_val_kb(m, "MemTotal:       ", i.totalram);
	show_val_kb(m, "MemFree:        ", i.freeram);
	show_val_kb(m, "MemAvailable:   ", available);
	show_val_kb(m, "Buffers:        ", i.bufferram);
	show_val_kb(m, "Cached:         ", cached);
	show_val_kb(m, "SwapCached:     ", total_swapcache_pages());
	show_val_kb(m, "Active:         ", pages[LRU_ACTIVE_ANON] +
					   pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive:       ", pages[LRU_INACTIVE_ANON] +
					   pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Active(anon):   ", pages[LRU_ACTIVE_ANON]);
	show_val_kb(m, "Inactive(anon): ", pages[LRU_INACTIVE_ANON]);
	show_val_kb(m, "Active(file):   ", pages[LRU_ACTIVE_FILE]);
	show_val_kb(m, "Inactive(file): ", pages[LRU_INACTIVE_FILE]);
	show_val_kb(m, "Unevictable:    ", pages[LRU_UNEVICTABLE]);
	show_val_kb(m, "Mlocked:        ", global_zone_page_state(NR_MLOCK));

#ifdef CONFIG_HIGHMEM
	show_val_kb(m, "HighTotal:      ", i.totalhigh);
	show_val_kb(m, "HighFree:       ", i.freehigh);
	show_val_kb(m, "LowTotal:       ", i.totalram - i.totalhigh);
	show_val_kb(m, "LowFree:        ", i.freeram - i.freehigh);
#endif

#ifndef CONFIG_MMU
	show_val_kb(m, "MmapCopy:       ",
		    (unsigned long)atomic_long_read(&mmap_pages_allocated));
#endif

	show_val_kb(m, "SwapTotal:      ", i.totalswap);
	show_val_kb(m, "SwapFree:       ", i.freeswap);
#ifdef CONFIG_ZSWAP
	seq_printf(m,  "Zswap:          %8lu kB\n",
		   (unsigned long)(zswap_pool_total_size >> 10));
	seq_printf(m,  "Zswapped:       %8lu kB\n",
		   (unsigned long)atomic_read(&zswap_stored_pages) <<
		   (PAGE_SHIFT - 10));
#endif
	show_val_kb(m, "Dirty:          ",
		    global_node_page_state(NR_FILE_DIRTY));
	show_val_kb(m, "Writeback:      ",
		    global_node_page_state(NR_WRITEBACK));
	show_val_kb(m, "AnonPages:      ",
		    global_node_page_state(NR_ANON_MAPPED));
	show_val_kb(m, "Mapped:         ",
		    global_node_page_state(NR_FILE_MAPPED));
	show_val_kb(m, "Shmem:          ", i.sharedram);
	show_val_kb(m, "KReclaimable:   ", sreclaimable +
		    global_node_page_state(NR_KERNEL_MISC_RECLAIMABLE));
	show_val_kb(m, "Slab:           ", sreclaimable + sunreclaim);
	show_val_kb(m, "SReclaimable:   ", sreclaimable);
	show_val_kb(m, "SUnreclaim:     ", sunreclaim);
	seq_printf(m, "KernelStack:    %8lu kB\n",
		   global_node_page_state(NR_KERNEL_STACK_KB));
#ifdef CONFIG_SHADOW_CALL_STACK
	seq_printf(m, "ShadowCallStack:%8lu kB\n",
		   global_node_page_state(NR_KERNEL_SCS_KB));
#endif
	show_val_kb(m, "PageTables:     ",
		    global_node_page_state(NR_PAGETABLE));
	show_val_kb(m, "SecPageTables:  ",
		    global_node_page_state(NR_SECONDARY_PAGETABLE));

	show_val_kb(m, "NFS_Unstable:   ", 0);
	show_val_kb(m, "Bounce:         ",
		    global_zone_page_state(NR_BOUNCE));
	show_val_kb(m, "WritebackTmp:   ",
		    global_node_page_state(NR_WRITEBACK_TEMP));
	show_val_kb(m, "CommitLimit:    ", vm_commit_limit());
	show_val_kb(m, "Committed_AS:   ", committed);
	seq_printf(m, "VmallocTotal:   %8lu kB\n",
		   (unsigned long)VMALLOC_TOTAL >> 10);
	show_val_kb(m, "VmallocUsed:    ", vmalloc_nr_pages());
	show_val_kb(m, "VmallocChunk:   ", 0ul);
	show_val_kb(m, "Percpu:         ", pcpu_nr_pages());

#ifdef CONFIG_MEMORY_FAILURE
	seq_printf(m, "HardwareCorrupted: %5lu kB\n",
		   atomic_long_read(&num_poisoned_pages) << (PAGE_SHIFT - 10));
#endif

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	show_val_kb(m, "AnonHugePages:  ",
		    global_node_page_state(NR_ANON_THPS));
	show_val_kb(m, "ShmemHugePages: ",
		    global_node_page_state(NR_SHMEM_THPS));
	show_val_kb(m, "ShmemPmdMapped: ",
		    global_node_page_state(NR_SHMEM_PMDMAPPED));
	show_val_kb(m, "FileHugePages:  ",
		    global_node_page_state(NR_FILE_THPS));
	show_val_kb(m, "FilePmdMapped:  ",
		    global_node_page_state(NR_FILE_PMDMAPPED));
#endif

	if (IS_ENABLED(CONFIG_TCACHE))
		show_val_kb(m, "Tcache:         ", get_nr_tcache_pages());

#ifdef CONFIG_CMA
	show_val_kb(m, "CmaTotal:       ", totalcma_pages);
	show_val_kb(m, "CmaFree:        ",
		    global_zone_page_state(NR_FREE_CMA_PAGES));
#endif

	hugetlb_report_meminfo(m);

	arch_report_meminfo(m);

	return 0;
}

static int meminfo_proc_show(struct seq_file *m, void *v)
{
	return meminfo_proc_show_ve(m, v, get_exec_env());
}

static int __init proc_meminfo_init(void)
{
	proc_ve_create_single("meminfo", 0, NULL, meminfo_proc_show);
	return 0;
}
fs_initcall(proc_meminfo_init);
