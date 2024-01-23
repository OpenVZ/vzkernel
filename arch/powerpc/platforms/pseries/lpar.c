/*
 * pSeries_lpar.c
 * Copyright (C) 2001 Todd Inglett, IBM Corporation
 *
 * pSeries LPAR support.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

/* Enables debugging of low-level hash table routines - careful! */
#undef DEBUG
#define pr_fmt(fmt) "lpar: " fmt

#include <linux/kernel.h>
#include <linux/dma-mapping.h>
#include <linux/console.h>
#include <linux/export.h>
#include <linux/delay.h>
#include <linux/stop_machine.h>
#include <asm/processor.h>
#include <asm/mmu.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/machdep.h>
#include <asm/mmu_context.h>
#include <asm/iommu.h>
#include <asm/tlbflush.h>
#include <asm/tlb.h>
#include <asm/prom.h>
#include <asm/cputable.h>
#include <asm/udbg.h>
#include <asm/smp.h>
#include <asm/trace.h>
#include <asm/firmware.h>
#include <asm/plpar_wrappers.h>
#include <asm/kexec.h>
#include <asm/fadump.h>
#include <asm/asm-prototypes.h>

#include "pseries.h"

/* Flag bits for H_BULK_REMOVE */
#define HBR_REQUEST	0x4000000000000000UL
#define HBR_RESPONSE	0x8000000000000000UL
#define HBR_END		0xc000000000000000UL
#define HBR_AVPN	0x0200000000000000UL
#define HBR_ANDCOND	0x0100000000000000UL


/* in hvCall.S */
EXPORT_SYMBOL(plpar_hcall);
EXPORT_SYMBOL(plpar_hcall9);
EXPORT_SYMBOL(plpar_hcall_norets);

/*
 * H_BLOCK_REMOVE supported block size for this page size in segment who's base
 * page size is that page size.
 *
 * The first index is the segment base page size, the second one is the actual
 * page size.
 */
static int hblkrm_size[MMU_PAGE_COUNT][MMU_PAGE_COUNT];

/*
 * Due to the involved complexity, and that the current hypervisor is only
 * returning this value or 0, we are limiting the support of the H_BLOCK_REMOVE
 * buffer size to 8 size block.
 */
#define HBLKRM_SUPPORTED_BLOCK_SIZE 8

extern void pSeries_find_serial_port(void);

void vpa_init(int cpu)
{
	int hwcpu = get_hard_smp_processor_id(cpu);
	unsigned long addr;
	long ret;
	struct paca_struct *pp;
	struct dtl_entry *dtl;

	/*
	 * The spec says it "may be problematic" if CPU x registers the VPA of
	 * CPU y. We should never do that, but wail if we ever do.
	 */
	WARN_ON(cpu != smp_processor_id());

	if (cpu_has_feature(CPU_FTR_ALTIVEC))
		lppaca_of(cpu).vmxregs_in_use = 1;

	if (cpu_has_feature(CPU_FTR_ARCH_207S))
		lppaca_of(cpu).ebb_regs_in_use = 1;

	addr = __pa(&lppaca_of(cpu));
	ret = register_vpa(hwcpu, addr);

	if (ret) {
		pr_err("WARNING: VPA registration for cpu %d (hw %d) of area "
		       "%lx failed with %ld\n", cpu, hwcpu, addr, ret);
		return;
	}
	/*
	 * PAPR says this feature is SLB-Buffer but firmware never
	 * reports that.  All SPLPAR support SLB shadow buffer.
	 */
	addr = __pa(paca[cpu].slb_shadow_ptr);
	if (firmware_has_feature(FW_FEATURE_SPLPAR)) {
		ret = register_slb_shadow(hwcpu, addr);
		if (ret)
			pr_err("WARNING: SLB shadow buffer registration for "
			       "cpu %d (hw %d) of area %lx failed with %ld\n",
			       cpu, hwcpu, addr, ret);
	}

	/*
	 * Register dispatch trace log, if one has been allocated.
	 */
	pp = &paca[cpu];
	dtl = pp->dispatch_log;
	if (dtl) {
		pp->dtl_ridx = 0;
		pp->dtl_curr = dtl;
		lppaca_of(cpu).dtl_idx = 0;

		/* hypervisor reads buffer length from this field */
		dtl->enqueue_to_dispatch_time = cpu_to_be32(DISPATCH_LOG_BYTES);
		ret = register_dtl(hwcpu, __pa(dtl));
		if (ret)
			pr_err("WARNING: DTL registration of cpu %d (hw %d) "
			       "failed with %ld\n", smp_processor_id(),
			       hwcpu, ret);
		lppaca_of(cpu).dtl_enable_mask = 2;
	}
}

static long pSeries_lpar_hpte_insert(unsigned long hpte_group,
				     unsigned long vpn, unsigned long pa,
				     unsigned long rflags, unsigned long vflags,
				     int psize, int apsize, int ssize)
{
	unsigned long lpar_rc;
	unsigned long flags;
	unsigned long slot;
	unsigned long hpte_v, hpte_r;

	if (!(vflags & HPTE_V_BOLTED))
		pr_devel("hpte_insert(group=%lx, vpn=%016lx, "
			 "pa=%016lx, rflags=%lx, vflags=%lx, psize=%d)\n",
			 hpte_group, vpn,  pa, rflags, vflags, psize);

	hpte_v = hpte_encode_v(vpn, psize, apsize, ssize) | vflags | HPTE_V_VALID;
	hpte_r = hpte_encode_r(pa, psize, apsize) | rflags;

	if (!(vflags & HPTE_V_BOLTED))
		pr_devel(" hpte_v=%016lx, hpte_r=%016lx\n", hpte_v, hpte_r);

	/* Now fill in the actual HPTE */
	/* Set CEC cookie to 0         */
	/* Zero page = 0               */
	/* I-cache Invalidate = 0      */
	/* I-cache synchronize = 0     */
	/* Exact = 0                   */
	flags = 0;

	/* Make pHyp happy */
	if ((rflags & _PAGE_NO_CACHE) && !(rflags & _PAGE_WRITETHRU))
		hpte_r &= ~HPTE_R_M;

	if (firmware_has_feature(FW_FEATURE_XCMO) && !(hpte_r & HPTE_R_N))
		flags |= H_COALESCE_CAND;

	lpar_rc = plpar_pte_enter(flags, hpte_group, hpte_v, hpte_r, &slot);
	if (unlikely(lpar_rc == H_PTEG_FULL)) {
		if (!(vflags & HPTE_V_BOLTED))
			pr_devel(" full\n");
		return -1;
	}

	/*
	 * Since we try and ioremap PHBs we don't own, the pte insert
	 * will fail. However we must catch the failure in hash_page
	 * or we will loop forever, so return -2 in this case.
	 */
	if (unlikely(lpar_rc != H_SUCCESS)) {
		if (!(vflags & HPTE_V_BOLTED))
			pr_devel(" lpar err %ld\n", lpar_rc);
		return -2;
	}
	if (!(vflags & HPTE_V_BOLTED))
		pr_devel(" -> slot: %lu\n", slot & 7);

	/* Because of iSeries, we have to pass down the secondary
	 * bucket bit here as well
	 */
	return (slot & 7) | (!!(vflags & HPTE_V_SECONDARY) << 3);
}

static DEFINE_SPINLOCK(pSeries_lpar_tlbie_lock);

static long pSeries_lpar_hpte_remove(unsigned long hpte_group)
{
	unsigned long slot_offset;
	unsigned long lpar_rc;
	int i;
	unsigned long dummy1, dummy2;

	/* pick a random slot to start at */
	slot_offset = mftb() & 0x7;

	for (i = 0; i < HPTES_PER_GROUP; i++) {

		/* don't remove a bolted entry */
		lpar_rc = plpar_pte_remove(H_ANDCOND, hpte_group + slot_offset,
					   (0x1UL << 4), &dummy1, &dummy2);
		if (lpar_rc == H_SUCCESS)
			return i;

		/*
		 * The test for adjunct partition is performed before the
		 * ANDCOND test.  H_RESOURCE may be returned, so we need to
		 * check for that as well.
		 */
		BUG_ON(lpar_rc != H_NOT_FOUND && lpar_rc != H_RESOURCE);

		slot_offset++;
		slot_offset &= 0x7;
	}

	return -1;
}

static void manual_hpte_clear_all(void)
{
	unsigned long size_bytes = 1UL << ppc64_pft_size;
	unsigned long hpte_count = size_bytes >> 4;
	struct {
		unsigned long pteh;
		unsigned long ptel;
	} ptes[4];
	long lpar_rc;
	unsigned long i, j;

	/* Read in batches of 4,
	 * invalidate only valid entries not in the VRMA
	 * hpte_count will be a multiple of 4
         */
	for (i = 0; i < hpte_count; i += 4) {
		lpar_rc = plpar_pte_read_4_raw(0, i, (void *)ptes);
		if (lpar_rc != H_SUCCESS)
			continue;
		for (j = 0; j < 4; j++){
			if ((ptes[j].pteh & HPTE_V_VRMA_MASK) ==
				HPTE_V_VRMA_MASK)
				continue;
			if (ptes[j].pteh & HPTE_V_VALID)
				plpar_pte_remove_raw(0, i + j, 0,
					&(ptes[j].pteh), &(ptes[j].ptel));
		}
	}
}

static int hcall_hpte_clear_all(void)
{
	int rc;

	do {
		rc = plpar_hcall_norets(H_CLEAR_HPT);
	} while (rc == H_CONTINUE);

	return rc;
}

static void pseries_hpte_clear_all(void)
{
	int rc;

	rc = hcall_hpte_clear_all();
	if (rc != H_SUCCESS)
		manual_hpte_clear_all();

#ifdef __LITTLE_ENDIAN__
	/*
	 * Reset exceptions to big endian.
	 *
	 * FIXME this is a hack for kexec, we need to reset the exception
	 * endian before starting the new kernel and this is a convenient place
	 * to do it.
	 *
	 * This is also called on boot when a fadump happens. In that case we
	 * must not change the exception endian mode.
	 */
	if (firmware_has_feature(FW_FEATURE_SET_MODE) && !is_fadump_active()) {
		long rc;

		rc = pseries_big_endian_exceptions();
		/*
		 * At this point it is unlikely panic() will get anything
		 * out to the user, but at least this will stop us from
		 * continuing on further and creating an even more
		 * difficult to debug situation.
		 *
		 * There is a known problem when kdump'ing, if cpus are offline
		 * the above call will fail. Rather than panicking again, keep
		 * going and hope the kdump kernel is also little endian, which
		 * it usually is.
		 */
		if (rc && !kdump_in_progress())
			panic("Could not enable big endian exceptions");
	}
#endif
}

/*
 * NOTE: for updatepp ops we are fortunate that the linux "newpp" bits and
 * the low 3 bits of flags happen to line up.  So no transform is needed.
 * We can probably optimize here and assume the high bits of newpp are
 * already zero.  For now I am paranoid.
 */
static long pSeries_lpar_hpte_updatepp(unsigned long slot,
				       unsigned long newpp,
				       unsigned long vpn,
				       int psize, int apsize,
				       int ssize, unsigned long inv_flags)
{
	unsigned long lpar_rc;
	unsigned long flags = (newpp & 7) | H_AVPN;
	unsigned long want_v;

	want_v = hpte_encode_avpn(vpn, psize, ssize);

	pr_devel("    update: avpnv=%016lx, hash=%016lx, f=%lx, psize: %d ...",
		 want_v, slot, flags, psize);

	lpar_rc = plpar_pte_protect(flags, slot, want_v);

	if (lpar_rc == H_NOT_FOUND) {
		pr_devel("not found !\n");
		return -1;
	}

	pr_devel("ok\n");

	BUG_ON(lpar_rc != H_SUCCESS);

	return 0;
}

static unsigned long pSeries_lpar_hpte_getword0(unsigned long slot)
{
	unsigned long dword0;
	unsigned long lpar_rc;
	unsigned long dummy_word1;
	unsigned long flags;

	/* Read 1 pte at a time                        */
	/* Do not need RPN to logical page translation */
	/* No cross CEC PFT access                     */
	flags = 0;

	lpar_rc = plpar_pte_read(flags, slot, &dword0, &dummy_word1);

	BUG_ON(lpar_rc != H_SUCCESS);

	return dword0;
}

static long pSeries_lpar_hpte_find(unsigned long vpn, int psize, int ssize)
{
	unsigned long hash;
	unsigned long i;
	long slot;
	unsigned long want_v, hpte_v;

	hash = hpt_hash(vpn, mmu_psize_defs[psize].shift, ssize);
	want_v = hpte_encode_avpn(vpn, psize, ssize);

	/* Bolted entries are always in the primary group */
	slot = (hash & htab_hash_mask) * HPTES_PER_GROUP;
	for (i = 0; i < HPTES_PER_GROUP; i++) {
		hpte_v = pSeries_lpar_hpte_getword0(slot);

		if (HPTE_V_COMPARE(hpte_v, want_v) && (hpte_v & HPTE_V_VALID))
			/* HPTE matches */
			return slot;
		++slot;
	}

	return -1;
} 

static void pSeries_lpar_hpte_updateboltedpp(unsigned long newpp,
					     unsigned long ea,
					     int psize, int ssize)
{
	unsigned long vpn;
	unsigned long lpar_rc, slot, vsid, flags;

	vsid = get_kernel_vsid(ea, ssize);
	vpn = hpt_vpn(ea, vsid, ssize);

	slot = pSeries_lpar_hpte_find(vpn, psize, ssize);
	BUG_ON(slot == -1);

	flags = newpp & 7;
	lpar_rc = plpar_pte_protect(flags, slot, 0);

	BUG_ON(lpar_rc != H_SUCCESS);
}

static void pSeries_lpar_hpte_invalidate(unsigned long slot, unsigned long vpn,
					 int psize, int apsize,
					 int ssize, int local)
{
	unsigned long want_v;
	unsigned long lpar_rc;
	unsigned long dummy1, dummy2;

	pr_devel("    inval : slot=%lx, vpn=%016lx, psize: %d, local: %d\n",
		 slot, vpn, psize, local);

	want_v = hpte_encode_avpn(vpn, psize, ssize);
	lpar_rc = plpar_pte_remove(H_AVPN, slot, want_v, &dummy1, &dummy2);
	if (lpar_rc == H_NOT_FOUND)
		return;

	BUG_ON(lpar_rc != H_SUCCESS);
}


/*
 * As defined in the PAPR's section 14.5.4.1.8
 * The control mask doesn't include the returned reference and change bit from
 * the processed PTE.
 */
#define HBLKR_AVPN		0x0100000000000000UL
#define HBLKR_CTRL_MASK		0xf800000000000000UL
#define HBLKR_CTRL_SUCCESS	0x8000000000000000UL
#define HBLKR_CTRL_ERRNOTFOUND	0x8800000000000000UL
#define HBLKR_CTRL_ERRBUSY	0xa000000000000000UL

/*
 * Returned true if we are supporting this block size for the specified segment
 * base page size and actual page size.
 *
 * Currently, we only support 8 size block.
 */
static inline bool is_supported_hlbkrm(int bpsize, int psize)
{
	return (hblkrm_size[bpsize][psize] == HBLKRM_SUPPORTED_BLOCK_SIZE);
}

/**
 * H_BLOCK_REMOVE caller.
 * @idx should point to the latest @param entry set with a PTEX.
 * If PTE cannot be processed because another CPUs has already locked that
 * group, those entries are put back in @param starting at index 1.
 * If entries has to be retried and @retry_busy is set to true, these entries
 * are retried until success. If @retry_busy is set to false, the returned
 * is the number of entries yet to process.
 */
static unsigned long call_block_remove(unsigned long idx, unsigned long *param,
				       bool retry_busy)
{
	unsigned long i, rc, new_idx;
	unsigned long retbuf[PLPAR_HCALL9_BUFSIZE];

	if (idx < 2) {
		pr_warn("Unexpected empty call to H_BLOCK_REMOVE");
		return 0;
	}
again:
	new_idx = 0;
	if (idx > PLPAR_HCALL9_BUFSIZE) {
		pr_err("Too many PTEs (%lu) for H_BLOCK_REMOVE", idx);
		idx = PLPAR_HCALL9_BUFSIZE;
	} else if (idx < PLPAR_HCALL9_BUFSIZE)
		param[idx] = HBR_END;

	rc = plpar_hcall9(H_BLOCK_REMOVE, retbuf,
			  param[0], /* AVA */
			  param[1],  param[2],  param[3],  param[4], /* TS0-7 */
			  param[5],  param[6],  param[7],  param[8]);
	if (rc == H_SUCCESS)
		return 0;

	BUG_ON(rc != H_PARTIAL);

	/* Check that the unprocessed entries were 'not found' or 'busy' */
	for (i = 0; i < idx-1; i++) {
		unsigned long ctrl = retbuf[i] & HBLKR_CTRL_MASK;

		if (ctrl == HBLKR_CTRL_ERRBUSY) {
			param[++new_idx] = param[i+1];
			continue;
		}

		BUG_ON(ctrl != HBLKR_CTRL_SUCCESS
		       && ctrl != HBLKR_CTRL_ERRNOTFOUND);
	}

	/*
	 * If there were entries found busy, retry these entries if requested,
	 * of if all the entries have to be retried.
	 */
	if (new_idx && (retry_busy || new_idx == (PLPAR_HCALL9_BUFSIZE-1))) {
		idx = new_idx + 1;
		goto again;
	}

	return new_idx;
}

/*
 * Limit iterations holding pSeries_lpar_tlbie_lock to 3. We also need
 * to make sure that we avoid bouncing the hypervisor tlbie lock.
 */
#define PPC64_HUGE_HPTE_BATCH 12

static void hugepage_block_invalidate(unsigned long *slot, unsigned long *vpn,
				      int count, int psize, int ssize)
{
	unsigned long param[PLPAR_HCALL9_BUFSIZE];
	unsigned long shift, current_vpgb, vpgb;
	int i, pix = 0;

	shift = mmu_psize_defs[psize].shift;

	for (i = 0; i < count; i++) {
		/*
		 * Shifting 3 bits more on the right to get a
		 * 8 pages aligned virtual addresse.
		 */
		vpgb = (vpn[i] >> (shift - VPN_SHIFT + 3));
		if (!pix || vpgb != current_vpgb) {
			/*
			 * Need to start a new 8 pages block, flush
			 * the current one if needed.
			 */
			if (pix)
				(void)call_block_remove(pix, param, true);
			current_vpgb = vpgb;
			param[0] = hpte_encode_avpn(vpn[i], psize, ssize);
			pix = 1;
		}

		param[pix++] = HBR_REQUEST | HBLKR_AVPN | slot[i];
		if (pix == PLPAR_HCALL9_BUFSIZE) {
			pix = call_block_remove(pix, param, false);
			/*
			 * pix = 0 means that all the entries were
			 * removed, we can start a new block.
			 * Otherwise, this means that there are entries
			 * to retry, and pix points to latest one, so
			 * we should increment it and try to continue
			 * the same block.
			 */
			if (pix)
				pix++;
		}
	}
	if (pix)
		(void)call_block_remove(pix, param, true);
}

static void hugepage_bulk_invalidate(unsigned long *slot, unsigned long *vpn,
				     int count, int psize, int ssize)
{
	unsigned long param[PLPAR_HCALL9_BUFSIZE];
	int i = 0, pix = 0, rc;

	for (i = 0; i < count; i++) {

		if (!firmware_has_feature(FW_FEATURE_BULK_REMOVE)) {
			pSeries_lpar_hpte_invalidate(slot[i], vpn[i], psize, 0,
						     ssize, 0);
		} else {
			param[pix] = HBR_REQUEST | HBR_AVPN | slot[i];
			param[pix+1] = hpte_encode_avpn(vpn[i], psize, ssize);
			pix += 2;
			if (pix == 8) {
				rc = plpar_hcall9(H_BULK_REMOVE, param,
						  param[0], param[1], param[2],
						  param[3], param[4], param[5],
						  param[6], param[7]);
				BUG_ON(rc != H_SUCCESS);
				pix = 0;
			}
		}
	}
	if (pix) {
		param[pix] = HBR_END;
		rc = plpar_hcall9(H_BULK_REMOVE, param, param[0], param[1],
				  param[2], param[3], param[4], param[5],
				  param[6], param[7]);
		BUG_ON(rc != H_SUCCESS);
	}
}

static inline void __pSeries_lpar_hugepage_invalidate(unsigned long *slot,
						      unsigned long *vpn,
						      int count, int psize,
						      int ssize)
{
	unsigned long flags = 0;
	int lock_tlbie = !mmu_has_feature(MMU_FTR_LOCKLESS_TLBIE);

	if (lock_tlbie)
		spin_lock_irqsave(&pSeries_lpar_tlbie_lock, flags);

	/* Assuming THP size is 16M */
	if (is_supported_hlbkrm(psize, MMU_PAGE_16M))
		hugepage_block_invalidate(slot, vpn, count, psize, ssize);
	else
		hugepage_bulk_invalidate(slot, vpn, count, psize, ssize);

	if (lock_tlbie)
		spin_unlock_irqrestore(&pSeries_lpar_tlbie_lock, flags);
}

static void pSeries_lpar_hugepage_invalidate(unsigned long vsid,
					     unsigned long addr,
					     unsigned char *hpte_slot_array,
					     int psize, int ssize)
{
	int i, index = 0;
	unsigned long s_addr = addr;
	unsigned int max_hpte_count, valid;
	unsigned long vpn_array[PPC64_HUGE_HPTE_BATCH];
	unsigned long slot_array[PPC64_HUGE_HPTE_BATCH];
	unsigned long shift, hidx, vpn = 0, hash, slot;

	shift = mmu_psize_defs[psize].shift;
	max_hpte_count = 1U << (PMD_SHIFT - shift);

	for (i = 0; i < max_hpte_count; i++) {
		valid = hpte_valid(hpte_slot_array, i);
		if (!valid)
			continue;
		hidx =  hpte_hash_index(hpte_slot_array, i);

		/* get the vpn */
		addr = s_addr + (i * (1ul << shift));
		vpn = hpt_vpn(addr, vsid, ssize);
		hash = hpt_hash(vpn, shift, ssize);
		if (hidx & _PTEIDX_SECONDARY)
			hash = ~hash;

		slot = (hash & htab_hash_mask) * HPTES_PER_GROUP;
		slot += hidx & _PTEIDX_GROUP_IX;

		slot_array[index] = slot;
		vpn_array[index] = vpn;
		if (index == PPC64_HUGE_HPTE_BATCH - 1) {
			/*
			 * Now do a bluk invalidate
			 */
			__pSeries_lpar_hugepage_invalidate(slot_array,
							   vpn_array,
							   PPC64_HUGE_HPTE_BATCH,
							   psize, ssize);
			index = 0;
		} else
			index++;
	}
	if (index)
		__pSeries_lpar_hugepage_invalidate(slot_array, vpn_array,
						   index, psize, ssize);
}

static void pSeries_lpar_hpte_removebolted(unsigned long ea,
					   int psize, int ssize)
{
	unsigned long vpn;
	unsigned long slot, vsid;

	vsid = get_kernel_vsid(ea, ssize);
	vpn = hpt_vpn(ea, vsid, ssize);

	slot = pSeries_lpar_hpte_find(vpn, psize, ssize);
	BUG_ON(slot == -1);
	/*
	 * lpar doesn't use the passed actual page size
	 */
	pSeries_lpar_hpte_invalidate(slot, vpn, psize, 0, ssize, 0);
}


static inline unsigned long compute_slot(real_pte_t pte,
					 unsigned long vpn,
					 unsigned long index,
					 unsigned long shift,
					 int ssize)
{
	unsigned long slot, hash, hidx;

	hash = hpt_hash(vpn, shift, ssize);
	hidx = __rpte_to_hidx(pte, index);
	if (hidx & _PTEIDX_SECONDARY)
		hash = ~hash;
	slot = (hash & htab_hash_mask) * HPTES_PER_GROUP;
	slot += hidx & _PTEIDX_GROUP_IX;
	return slot;
}

/**
 * The hcall H_BLOCK_REMOVE implies that the virtual pages to processed are
 * "all within the same naturally aligned 8 page virtual address block".
 */
static void do_block_remove(unsigned long number, struct ppc64_tlb_batch *batch,
			    unsigned long *param)
{
	unsigned long vpn;
	unsigned long i, pix = 0;
	unsigned long index, shift, slot, current_vpgb, vpgb;
	real_pte_t pte;
	int psize, ssize;

	psize = batch->psize;
	ssize = batch->ssize;

	for (i = 0; i < number; i++) {
		vpn = batch->vpn[i];
		pte = batch->pte[i];
		pte_iterate_hashed_subpages(pte, psize, vpn, index, shift) {
			/*
			 * Shifting 3 bits more on the right to get a
			 * 8 pages aligned virtual addresse.
			 */
			vpgb = (vpn >> (shift - VPN_SHIFT + 3));
			if (!pix || vpgb != current_vpgb) {
				/*
				 * Need to start a new 8 pages block, flush
				 * the current one if needed.
				 */
				if (pix)
					(void)call_block_remove(pix, param,
								true);
				current_vpgb = vpgb;
				param[0] = hpte_encode_avpn(vpn, psize,
							    ssize);
				pix = 1;
			}

			slot = compute_slot(pte, vpn, index, shift, ssize);
			param[pix++] = HBR_REQUEST | HBLKR_AVPN | slot;

			if (pix == PLPAR_HCALL9_BUFSIZE) {
				pix = call_block_remove(pix, param, false);
				/*
				 * pix = 0 means that all the entries were
				 * removed, we can start a new block.
				 * Otherwise, this means that there are entries
				 * to retry, and pix points to latest one, so
				 * we should increment it and try to continue
				 * the same block.
				 */
				if (pix)
					pix++;
			}
		} pte_iterate_hashed_end();
	}

	if (pix)
		(void)call_block_remove(pix, param, true);
}

/*
 * TLB Block Invalidate Characteristics
 *
 * These characteristics define the size of the block the hcall H_BLOCK_REMOVE
 * is able to process for each couple segment base page size, actual page size.
 *
 * The ibm,get-system-parameter properties is returning a buffer with the
 * following layout:
 *
 * [ 2 bytes size of the RTAS buffer (excluding these 2 bytes) ]
 * -----------------
 * TLB Block Invalidate Specifiers:
 * [ 1 byte LOG base 2 of the TLB invalidate block size being specified ]
 * [ 1 byte Number of page sizes (N) that are supported for the specified
 *          TLB invalidate block size ]
 * [ 1 byte Encoded segment base page size and actual page size
 *          MSB=0 means 4k segment base page size and actual page size
 *          MSB=1 the penc value in mmu_psize_def ]
 * ...
 * -----------------
 * Next TLB Block Invalidate Specifiers...
 * -----------------
 * [ 0 ]
 */
static inline void set_hblkrm_bloc_size(int bpsize, int psize,
					unsigned int block_size)
{
	if (block_size > hblkrm_size[bpsize][psize])
		hblkrm_size[bpsize][psize] = block_size;
}

/*
 * Decode the Encoded segment base page size and actual page size.
 * PAPR specifies:
 *   - bit 7 is the L bit
 *   - bits 0-5 are the penc value
 * If the L bit is 0, this means 4K segment base page size and actual page size
 * otherwise the penc value should be read.
 */
#define HBLKRM_L_MASK		0x80
#define HBLKRM_PENC_MASK	0x3f
static inline void __init check_lp_set_hblkrm(unsigned int lp,
					      unsigned int block_size)
{
	unsigned int bpsize, psize;

	/* First, check the L bit, if not set, this means 4K */
	if ((lp & HBLKRM_L_MASK) == 0) {
		set_hblkrm_bloc_size(MMU_PAGE_4K, MMU_PAGE_4K, block_size);
		return;
	}

	lp &= HBLKRM_PENC_MASK;
	for (bpsize = 0; bpsize < MMU_PAGE_COUNT; bpsize++) {
		struct mmu_psize_def *def = &mmu_psize_defs[bpsize];

		for (psize = 0; psize < MMU_PAGE_COUNT; psize++) {
			if (def->penc[psize] == lp) {
				set_hblkrm_bloc_size(bpsize, psize, block_size);
				return;
			}
		}
	}
}

#define SPLPAR_TLB_BIC_TOKEN		50

/*
 * The size of the TLB Block Invalidate Characteristics is variable. But at the
 * maximum it will be the number of possible page sizes *2 + 10 bytes.
 * Currently MMU_PAGE_COUNT is 16, which means 42 bytes. Use a cache line size
 * (128 bytes) for the buffer to get plenty of space.
 */
#define SPLPAR_TLB_BIC_MAXLENGTH	128

void __init pseries_lpar_read_hblkrm_characteristics(void)
{
	unsigned char local_buffer[SPLPAR_TLB_BIC_MAXLENGTH];
	int call_status, len, idx, bpsize;

	if (!firmware_has_feature(FW_FEATURE_BLOCK_REMOVE))
		return;

	spin_lock(&rtas_data_buf_lock);
	memset(rtas_data_buf, 0, RTAS_DATA_BUF_SIZE);
	call_status = rtas_call(rtas_token("ibm,get-system-parameter"), 3, 1,
				NULL,
				SPLPAR_TLB_BIC_TOKEN,
				__pa(rtas_data_buf),
				RTAS_DATA_BUF_SIZE);
	memcpy(local_buffer, rtas_data_buf, SPLPAR_TLB_BIC_MAXLENGTH);
	local_buffer[SPLPAR_TLB_BIC_MAXLENGTH - 1] = '\0';
	spin_unlock(&rtas_data_buf_lock);

	if (call_status != 0) {
		pr_warn("%s %s Error calling get-system-parameter (0x%x)\n",
			__FILE__, __func__, call_status);
		return;
	}

	/*
	 * The first two (2) bytes of the data in the buffer are the length of
	 * the returned data, not counting these first two (2) bytes.
	 */
	len = be16_to_cpu(*((u16 *)local_buffer)) + 2;
	if (len > SPLPAR_TLB_BIC_MAXLENGTH) {
		pr_warn("%s too large returned buffer %d", __func__, len);
		return;
	}

	idx = 2;
	while (idx < len) {
		u8 block_shift = local_buffer[idx++];
		u32 block_size;
		unsigned int npsize;

		if (!block_shift)
			break;

		block_size = 1 << block_shift;

		for (npsize = local_buffer[idx++];
		     npsize > 0 && idx < len; npsize--)
			check_lp_set_hblkrm((unsigned int) local_buffer[idx++],
					    block_size);
	}

	for (bpsize = 0; bpsize < MMU_PAGE_COUNT; bpsize++)
		for (idx = 0; idx < MMU_PAGE_COUNT; idx++)
			if (hblkrm_size[bpsize][idx])
				pr_info("H_BLOCK_REMOVE supports base psize:%d psize:%d block size:%d",
					bpsize, idx, hblkrm_size[bpsize][idx]);
}

/*
 * Take a spinlock around flushes to avoid bouncing the hypervisor tlbie
 * lock.
 */
static void pSeries_lpar_flush_hash_range(unsigned long number, int local)
{
	unsigned long vpn;
	unsigned long i, pix, rc;
	unsigned long flags = 0;
	struct ppc64_tlb_batch *batch = &__get_cpu_var(ppc64_tlb_batch);
	int lock_tlbie = !mmu_has_feature(MMU_FTR_LOCKLESS_TLBIE);
	unsigned long param[PLPAR_HCALL9_BUFSIZE];
	unsigned long index, shift, slot;
	real_pte_t pte;
	int psize, ssize;

	if (lock_tlbie)
		spin_lock_irqsave(&pSeries_lpar_tlbie_lock, flags);

	if (is_supported_hlbkrm(batch->psize, batch->psize)) {
		do_block_remove(number, batch, param);
		goto out;
	}

	psize = batch->psize;
	ssize = batch->ssize;
	pix = 0;
	for (i = 0; i < number; i++) {
		vpn = batch->vpn[i];
		pte = batch->pte[i];
		pte_iterate_hashed_subpages(pte, psize, vpn, index, shift) {
			slot = compute_slot(pte, vpn, index, shift, ssize);
			if (!firmware_has_feature(FW_FEATURE_BULK_REMOVE)) {
				/*
				 * lpar doesn't use the passed actual page size
				 */
				pSeries_lpar_hpte_invalidate(slot, vpn, psize,
							     0, ssize, local);
			} else {
				param[pix] = HBR_REQUEST | HBR_AVPN | slot;
				param[pix+1] = hpte_encode_avpn(vpn, psize,
								ssize);
				pix += 2;
				if (pix == 8) {
					rc = plpar_hcall9(H_BULK_REMOVE, param,
						param[0], param[1], param[2],
						param[3], param[4], param[5],
						param[6], param[7]);
					BUG_ON(rc != H_SUCCESS);
					pix = 0;
				}
			}
		} pte_iterate_hashed_end();
	}
	if (pix) {
		param[pix] = HBR_END;
		rc = plpar_hcall9(H_BULK_REMOVE, param, param[0], param[1],
				  param[2], param[3], param[4], param[5],
				  param[6], param[7]);
		BUG_ON(rc != H_SUCCESS);
	}

out:
	if (lock_tlbie)
		spin_unlock_irqrestore(&pSeries_lpar_tlbie_lock, flags);
}

static int __init disable_bulk_remove(char *str)
{
	if (strcmp(str, "off") == 0 &&
	    firmware_has_feature(FW_FEATURE_BULK_REMOVE)) {
		pr_info("Disabling BULK_REMOVE firmware feature");
		powerpc_firmware_features &= ~FW_FEATURE_BULK_REMOVE;
	}
	return 1;
}

__setup("bulk_remove=", disable_bulk_remove);

#define HPT_RESIZE_TIMEOUT	10000 /* ms */

struct hpt_resize_state {
	unsigned long shift;
	int commit_rc;
};

static int pseries_lpar_resize_hpt_commit(void *data)
{
	struct hpt_resize_state *state = data;

	state->commit_rc = plpar_resize_hpt_commit(0, state->shift);
	if (state->commit_rc != H_SUCCESS)
		return -EIO;

	/* Hypervisor has transitioned the HTAB, update our globals */
	ppc64_pft_size = state->shift;
	htab_size_bytes = 1UL << ppc64_pft_size;
	htab_hash_mask = (htab_size_bytes >> 7) - 1;

	return 0;
}

/* Must be called in user context */
static int pseries_lpar_resize_hpt(unsigned long shift)
{
	struct hpt_resize_state state = {
		.shift = shift,
		.commit_rc = H_FUNCTION,
	};
	unsigned int delay, total_delay = 0;
	int rc;
	ktime_t t0, t1, t2;

	might_sleep();

	if (!firmware_has_feature(FW_FEATURE_HPT_RESIZE))
		return -ENODEV;

	pr_info("Attempting to resize HPT to shift %lu\n", shift);

	t0 = ktime_get();

	rc = plpar_resize_hpt_prepare(0, shift);
	while (H_IS_LONG_BUSY(rc)) {
		delay = get_longbusy_msecs(rc);
		total_delay += delay;
		if (total_delay > HPT_RESIZE_TIMEOUT) {
			/* prepare with shift==0 cancels an in-progress resize */
			rc = plpar_resize_hpt_prepare(0, 0);
			if (rc != H_SUCCESS)
				pr_warn("Unexpected error %d cancelling timed out HPT resize\n",
				       rc);
			return -ETIMEDOUT;
		}
		msleep(delay);
		rc = plpar_resize_hpt_prepare(0, shift);
	};

	switch (rc) {
	case H_SUCCESS:
		/* Continue on */
		break;

	case H_PARAMETER:
		pr_warn("Invalid argument from H_RESIZE_HPT_PREPARE\n");
		return -EINVAL;
	case H_RESOURCE:
		pr_warn("Operation not permitted from H_RESIZE_HPT_PREPARE\n");
		return -EPERM;
	default:
		pr_warn("Unexpected error %d from H_RESIZE_HPT_PREPARE\n", rc);
		return -EIO;
	}

	t1 = ktime_get();

	rc = stop_machine(pseries_lpar_resize_hpt_commit, &state, NULL);

	t2 = ktime_get();

	if (rc != 0) {
		switch (state.commit_rc) {
		case H_PTEG_FULL:
			return -ENOSPC;

		default:
			pr_warn("Unexpected error %d from H_RESIZE_HPT_COMMIT\n",
				state.commit_rc);
			return -EIO;
		};
	}

	pr_info("HPT resize to shift %lu complete (%lld ms / %lld ms)\n",
		shift, (long long) ktime_ms_delta(t1, t0),
		(long long) ktime_ms_delta(t2, t1));

	return 0;
}

void __init hpte_init_lpar(void)
{
	ppc_md.hpte_invalidate	= pSeries_lpar_hpte_invalidate;
	ppc_md.hpte_updatepp	= pSeries_lpar_hpte_updatepp;
	ppc_md.hpte_updateboltedpp = pSeries_lpar_hpte_updateboltedpp;
	ppc_md.hpte_insert	= pSeries_lpar_hpte_insert;
	ppc_md.hpte_remove	= pSeries_lpar_hpte_remove;
	ppc_md.hpte_removebolted = pSeries_lpar_hpte_removebolted;
	ppc_md.flush_hash_range	= pSeries_lpar_flush_hash_range;
	ppc_md.hpte_clear_all   = pseries_hpte_clear_all;
	ppc_md.hugepage_invalidate = pSeries_lpar_hugepage_invalidate;

	if (firmware_has_feature(FW_FEATURE_HPT_RESIZE))
		ppc_md.resize_hpt =  pseries_lpar_resize_hpt;
}

#ifdef CONFIG_PPC_SMLPAR
#define CMO_FREE_HINT_DEFAULT 1
static int cmo_free_hint_flag = CMO_FREE_HINT_DEFAULT;

static int __init cmo_free_hint(char *str)
{
	char *parm;
	parm = strstrip(str);

	if (strcasecmp(parm, "no") == 0 || strcasecmp(parm, "off") == 0) {
		pr_info("%s: CMO free page hinting is not active.\n", __func__);
		cmo_free_hint_flag = 0;
		return 1;
	}

	cmo_free_hint_flag = 1;
	pr_info("%s: CMO free page hinting is active.\n", __func__);

	if (strcasecmp(parm, "yes") == 0 || strcasecmp(parm, "on") == 0)
		return 1;

	return 0;
}

__setup("cmo_free_hint=", cmo_free_hint);

static void pSeries_set_page_state(struct page *page, int order,
				   unsigned long state)
{
	int i, j;
	unsigned long cmo_page_sz, addr;

	cmo_page_sz = cmo_get_page_size();
	addr = __pa((unsigned long)page_address(page));

	for (i = 0; i < (1 << order); i++, addr += PAGE_SIZE) {
		for (j = 0; j < PAGE_SIZE; j += cmo_page_sz)
			plpar_hcall_norets(H_PAGE_INIT, state, addr + j, 0);
	}
}

void arch_free_page(struct page *page, int order)
{
	if (!cmo_free_hint_flag || !firmware_has_feature(FW_FEATURE_CMO))
		return;

	pSeries_set_page_state(page, order, H_PAGE_SET_UNUSED);
}
EXPORT_SYMBOL(arch_free_page);

#endif

#ifdef CONFIG_TRACEPOINTS
/*
 * We optimise our hcall path by placing hcall_tracepoint_refcount
 * directly in the TOC so we can check if the hcall tracepoints are
 * enabled via a single load.
 */

/* NB: reg/unreg are called while guarded with the tracepoints_mutex */
extern long hcall_tracepoint_refcount;

/* 
 * Since the tracing code might execute hcalls we need to guard against
 * recursion. One example of this are spinlocks calling H_YIELD on
 * shared processor partitions.
 */
static DEFINE_PER_CPU(unsigned int, hcall_trace_depth);

void hcall_tracepoint_regfunc(void)
{
	hcall_tracepoint_refcount++;
}

void hcall_tracepoint_unregfunc(void)
{
	hcall_tracepoint_refcount--;
}

void __trace_hcall_entry(unsigned long opcode, unsigned long *args)
{
	unsigned long flags;
	unsigned int *depth;

	/*
	 * We cannot call tracepoints inside RCU idle regions which
	 * means we must not trace H_CEDE.
	 */
	if (opcode == H_CEDE)
		return;

	local_irq_save(flags);

	depth = &__get_cpu_var(hcall_trace_depth);

	if (*depth)
		goto out;

	(*depth)++;
	preempt_disable();
	trace_hcall_entry(opcode, args);
	(*depth)--;

out:
	local_irq_restore(flags);
}

void __trace_hcall_exit(long opcode, unsigned long retval,
			unsigned long *retbuf)
{
	unsigned long flags;
	unsigned int *depth;

	if (opcode == H_CEDE)
		return;

	local_irq_save(flags);

	depth = &__get_cpu_var(hcall_trace_depth);

	if (*depth)
		goto out;

	(*depth)++;
	trace_hcall_exit(opcode, retval, retbuf);
	preempt_enable();
	(*depth)--;

out:
	local_irq_restore(flags);
}
#endif

/**
 * h_get_mpp
 * H_GET_MPP hcall returns info in 7 parms
 */
int h_get_mpp(struct hvcall_mpp_data *mpp_data)
{
	int rc;
	unsigned long retbuf[PLPAR_HCALL9_BUFSIZE];

	rc = plpar_hcall9(H_GET_MPP, retbuf);

	mpp_data->entitled_mem = retbuf[0];
	mpp_data->mapped_mem = retbuf[1];

	mpp_data->group_num = (retbuf[2] >> 2 * 8) & 0xffff;
	mpp_data->pool_num = retbuf[2] & 0xffff;

	mpp_data->mem_weight = (retbuf[3] >> 7 * 8) & 0xff;
	mpp_data->unallocated_mem_weight = (retbuf[3] >> 6 * 8) & 0xff;
	mpp_data->unallocated_entitlement = retbuf[3] & 0xffffffffffffUL;

	mpp_data->pool_size = retbuf[4];
	mpp_data->loan_request = retbuf[5];
	mpp_data->backing_mem = retbuf[6];

	return rc;
}
EXPORT_SYMBOL(h_get_mpp);

int h_get_mpp_x(struct hvcall_mpp_x_data *mpp_x_data)
{
	int rc;
	unsigned long retbuf[PLPAR_HCALL9_BUFSIZE] = { 0 };

	rc = plpar_hcall9(H_GET_MPP_X, retbuf);

	mpp_x_data->coalesced_bytes = retbuf[0];
	mpp_x_data->pool_coalesced_bytes = retbuf[1];
	mpp_x_data->pool_purr_cycles = retbuf[2];
	mpp_x_data->pool_spurr_cycles = retbuf[3];

	return rc;
}
