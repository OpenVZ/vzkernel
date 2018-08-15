#ifndef _LINUX_HUGE_MM_H
#define _LINUX_HUGE_MM_H

#ifndef __GENKSYMS__
#include <linux/fs.h> /* only for vma_is_dax() */
#endif

extern int do_huge_pmd_anonymous_page(struct vm_fault *vmf);
extern int copy_huge_pmd(struct mm_struct *dst_mm, struct mm_struct *src_mm,
			 pmd_t *dst_pmd, pmd_t *src_pmd, unsigned long addr,
			 struct vm_area_struct *vma);
extern void huge_pmd_set_accessed(struct vm_fault *vmf, pmd_t orig_pmd);
extern int copy_huge_pud(struct mm_struct *dst_mm, struct mm_struct *src_mm,
			 pud_t *dst_pud, pud_t *src_pud, unsigned long addr,
			 struct vm_area_struct *vma);

#ifdef CONFIG_HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD
extern void huge_pud_set_accessed(struct vm_fault *vmf, pud_t orig_pud);
#else
static inline void huge_pud_set_accessed(struct vm_fault *vmf, pud_t orig_pud)
{
}
#endif
extern int do_huge_pmd_wp_page(struct vm_fault *vmf, pmd_t orig_pmd);
extern struct page *follow_trans_huge_pmd(struct vm_area_struct *vma,
					  unsigned long addr,
					  pmd_t *pmd,
					  unsigned int flags);
extern int zap_huge_pmd(struct mmu_gather *tlb,
			struct vm_area_struct *vma,
			pmd_t *pmd, unsigned long addr);
extern int zap_huge_pud(struct mmu_gather *tlb,
			struct vm_area_struct *vma,
			pud_t *pud, unsigned long addr);
extern int mincore_huge_pmd(struct vm_area_struct *vma, pmd_t *pmd,
			unsigned long addr, unsigned long end,
			unsigned char *vec);
extern int move_huge_pmd(struct vm_area_struct *vma,
			 struct vm_area_struct *new_vma,
			 unsigned long old_addr,
			 unsigned long new_addr, unsigned long old_end,
			 pmd_t *old_pmd, pmd_t *new_pmd);
extern int change_huge_pmd(struct vm_area_struct *vma, pmd_t *pmd,
			unsigned long addr, pgprot_t newprot,
			int prot_numa);
int vmf_insert_pfn_pmd(struct vm_area_struct *vma, unsigned long addr,
			pmd_t *pmd, pfn_t pfn, bool write);
int vmf_insert_pfn_pud(struct vm_area_struct *vma, unsigned long addr,
			pud_t *pud, pfn_t pfn, bool write);
extern void put_huge_zero_page(void);

enum transparent_hugepage_flag {
	TRANSPARENT_HUGEPAGE_FLAG,
	TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG,
	TRANSPARENT_HUGEPAGE_DEFRAG_FLAG,
	TRANSPARENT_HUGEPAGE_DEFRAG_REQ_MADV_FLAG,
	TRANSPARENT_HUGEPAGE_DEFRAG_KHUGEPAGED_FLAG,
	TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_FLAG,
#ifdef CONFIG_DEBUG_VM
	TRANSPARENT_HUGEPAGE_DEBUG_COW_FLAG,
#endif
};

enum page_check_address_pmd_flag {
	PAGE_CHECK_ADDRESS_PMD_FLAG,
	PAGE_CHECK_ADDRESS_PMD_NOTSPLITTING_FLAG,
	PAGE_CHECK_ADDRESS_PMD_SPLITTING_FLAG,
};
extern pmd_t *page_check_address_pmd(struct page *page,
				     struct mm_struct *mm,
				     unsigned long address,
				     enum page_check_address_pmd_flag flag,
				     spinlock_t **ptl);

#define HPAGE_PMD_ORDER (HPAGE_PMD_SHIFT-PAGE_SHIFT)
#define HPAGE_PMD_NR (1<<HPAGE_PMD_ORDER)

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
#define HPAGE_PMD_SHIFT PMD_SHIFT
#define HPAGE_PMD_SIZE	((1UL) << HPAGE_PMD_SHIFT)
#define HPAGE_PMD_MASK	(~(HPAGE_PMD_SIZE - 1))

#define HPAGE_PUD_SHIFT PUD_SHIFT
#define HPAGE_PUD_SIZE	((1UL) << HPAGE_PUD_SHIFT)
#define HPAGE_PUD_MASK	(~(HPAGE_PUD_SIZE - 1))

extern bool is_vma_temporary_stack(struct vm_area_struct *vma);

extern unsigned long transparent_hugepage_flags;

static inline bool transparent_hugepage_enabled(struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_NOHUGEPAGE)
		return false;

	if (is_vma_temporary_stack(vma))
		return false;

	if (transparent_hugepage_flags & (1 << TRANSPARENT_HUGEPAGE_FLAG))
		return true;

	if (vma_is_dax(vma))
		return true;

	if (transparent_hugepage_flags &
				(1 << TRANSPARENT_HUGEPAGE_REQ_MADV_FLAG))
		return !!(vma->vm_flags & VM_HUGEPAGE);

	return false;
}

#define transparent_hugepage_defrag(__vma)				\
	((transparent_hugepage_flags &					\
	  (1<<TRANSPARENT_HUGEPAGE_DEFRAG_FLAG)) ||			\
	 (transparent_hugepage_flags &					\
	  (1<<TRANSPARENT_HUGEPAGE_DEFRAG_REQ_MADV_FLAG) &&		\
	  (__vma)->vm_flags & VM_HUGEPAGE))
#define transparent_hugepage_use_zero_page()				\
	(transparent_hugepage_flags &					\
	 (1<<TRANSPARENT_HUGEPAGE_USE_ZERO_PAGE_FLAG))
#ifdef CONFIG_DEBUG_VM
#define transparent_hugepage_debug_cow()				\
	(transparent_hugepage_flags &					\
	 (1<<TRANSPARENT_HUGEPAGE_DEBUG_COW_FLAG))
#else /* CONFIG_DEBUG_VM */
#define transparent_hugepage_debug_cow() 0
#endif /* CONFIG_DEBUG_VM */

extern unsigned long thp_get_unmapped_area(struct file *filp,
		unsigned long addr, unsigned long len, unsigned long pgoff,
		unsigned long flags);
extern int copy_pte_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
			  pmd_t *dst_pmd, pmd_t *src_pmd,
			  struct vm_area_struct *vma,
			  unsigned long addr, unsigned long end);
extern int split_huge_page_to_list(struct page *page, struct list_head *list);
static inline int split_huge_page(struct page *page)
{
	return split_huge_page_to_list(page, NULL);
}
extern void __split_huge_page_pmd(struct vm_area_struct *vma,
		unsigned long address, pmd_t *pmd);
#define split_huge_page_pmd(__vma, __address, __pmd)			\
	do {								\
		pmd_t *____pmd = (__pmd);				\
		if (unlikely(pmd_trans_huge(*____pmd)			\
					|| pmd_devmap(*____pmd)))	\
			__split_huge_page_pmd(__vma, __address,		\
					____pmd);			\
	}  while (0)
#define wait_split_huge_page(__anon_vma, __pmd)				\
	do {								\
		pmd_t *____pmd = (__pmd);				\
		anon_vma_lock_write(__anon_vma);			\
		anon_vma_unlock_write(__anon_vma);			\
		BUG_ON(pmd_trans_splitting(*____pmd) ||			\
		       pmd_trans_huge(*____pmd) ||			\
		       pmd_devmap(*____pmd));				\
	} while (0)

extern void __split_huge_page_pud(struct vm_area_struct *vma,
		unsigned long address, pud_t *pud);
#define split_huge_page_pud(__vma, __address, __pud)				\
	do {								\
		pud_t *____pud = (__pud);				\
		if (pud_trans_huge(*____pud)				\
					|| pud_devmap(*____pud))	\
			__split_huge_page_pud(__vma, __address, __pud);	\
	}  while (0)

extern void split_huge_page_pmd_mm(struct mm_struct *mm,
		unsigned long address, pmd_t *pmd);
#if HPAGE_PMD_ORDER > MAX_ORDER
#error "hugepages can't be allocated by the buddy allocator"
#endif
extern int hugepage_madvise(struct vm_area_struct *vma,
			    unsigned long *vm_flags, int advice);
extern void vma_adjust_trans_huge(struct vm_area_struct *vma,
				    unsigned long start,
				    unsigned long end,
				    long adjust_next);
extern int __pmd_trans_huge_lock(pmd_t *pmd, struct vm_area_struct *vma,
		spinlock_t **ptl);
extern int __pud_trans_huge_lock(pud_t *pud, struct vm_area_struct *vma,
		spinlock_t **ptl);

/* mmap_sem must be held on entry */
static inline int pmd_trans_huge_lock(pmd_t *pmd, struct vm_area_struct *vma,
		spinlock_t **ptl)
{
	VM_BUG_ON(!rwsem_is_locked(&vma->vm_mm->mmap_sem));
	if (pmd_trans_huge(*pmd) || pmd_devmap(*pmd))
		return __pmd_trans_huge_lock(pmd, vma, ptl);
	else
		return 0;
}
static inline int pud_trans_huge_lock(pud_t *pud, struct vm_area_struct *vma,
		spinlock_t **ptl)
{
	VM_BUG_ON(!rwsem_is_locked(&vma->vm_mm->mmap_sem));
	if (pud_trans_huge(*pud) || pud_devmap(*pud))
		return __pud_trans_huge_lock(pud, vma, ptl);
	else
		return 0;
}
static inline int hpage_nr_pages(struct page *page)
{
	if (unlikely(PageTransHuge(page)))
		return HPAGE_PMD_NR;
	return 1;
}

struct page *follow_devmap_pmd(struct vm_area_struct *vma, unsigned long addr,
		pmd_t *pmd, int flags);
struct page *follow_devmap_pud(struct vm_area_struct *vma, unsigned long addr,
		pud_t *pud, int flags);

extern int do_huge_pmd_numa_page(struct vm_fault *vmf, pmd_t orig_pmd);

static inline bool is_trans_huge_page_release(struct page *page)
{
	return (unsigned long) page & 1;
}

extern struct page *huge_zero_page;

static inline bool is_huge_zero_page(struct page *page)
{
	return ACCESS_ONCE(huge_zero_page) == page;
}

static inline bool is_huge_zero_page_release(struct page *page)
{
	return (unsigned long) page == ~0UL;
}

static inline struct page *trans_huge_page_release_decode(struct page *page)
{
	return (struct page *) ((unsigned long)page & ~1UL);
}

static inline struct page *trans_huge_page_release_encode(struct page *page)
{
	return (struct page *) ((unsigned long)page | 1UL);
}

static inline struct page *huge_zero_page_release_encode(void)
{
	/* NOTE: is_trans_huge_page_release() must return true */
	return (struct page *) (~0UL);
}

static inline atomic_t *__trans_huge_mmu_gather_count(struct page *page)
{
	return &(page + 1)->thp_mmu_gather;
}

static inline void init_trans_huge_mmu_gather_count(struct page *page)
{
	atomic_t *thp_mmu_gather = __trans_huge_mmu_gather_count(page);
	atomic_set(thp_mmu_gather, 0);
}

static inline void inc_trans_huge_mmu_gather_count(struct page *page)
{
	atomic_t *thp_mmu_gather = __trans_huge_mmu_gather_count(page);
	VM_BUG_ON(atomic_read(thp_mmu_gather) < 0);
	atomic_inc(thp_mmu_gather);
}

static inline void dec_trans_huge_mmu_gather_count(struct page *page)
{
	atomic_t *thp_mmu_gather = __trans_huge_mmu_gather_count(page);
	VM_BUG_ON(atomic_read(thp_mmu_gather) <= 0);
	atomic_dec(thp_mmu_gather);
}

static inline int trans_huge_mmu_gather_count(struct page *page)
{
	atomic_t *thp_mmu_gather = __trans_huge_mmu_gather_count(page);
	int ret = atomic_read(thp_mmu_gather);
	VM_BUG_ON(ret < 0);
	return ret;
}

/*
 * free_trans_huge_page_list() is used to free THP pages (if still
 * PageTransHuge()) in release_pages().
 */
extern void free_trans_huge_page_list(struct list_head *list);

static inline bool is_huge_zero_pmd(pmd_t pmd)
{
	return is_huge_zero_page(pmd_page(pmd));
}

static inline bool is_huge_zero_pud(pud_t pud)
{
	return false;
}

struct page *get_huge_zero_page(void);

#else /* CONFIG_TRANSPARENT_HUGEPAGE */
#define HPAGE_PMD_SHIFT ({ BUILD_BUG(); 0; })
#define HPAGE_PMD_MASK ({ BUILD_BUG(); 0; })
#define HPAGE_PMD_SIZE ({ BUILD_BUG(); 0; })

#define HPAGE_PUD_SHIFT ({ BUILD_BUG(); 0; })
#define HPAGE_PUD_MASK ({ BUILD_BUG(); 0; })
#define HPAGE_PUD_SIZE ({ BUILD_BUG(); 0; })

#define hpage_nr_pages(x) 1

static inline bool transparent_hugepage_enabled(struct vm_area_struct *vma)
{
	return false;
}

#define transparent_hugepage_flags 0UL

#define thp_get_unmapped_area	NULL

static inline int
split_huge_page_to_list(struct page *page, struct list_head *list)
{
	return 0;
}
static inline int split_huge_page(struct page *page)
{
	return 0;
}
#define split_huge_page_pmd(__vma, __address, __pmd)	\
	do { } while (0)
#define wait_split_huge_page(__anon_vma, __pmd)	\
	do { } while (0)
#define split_huge_page_pmd_mm(__mm, __address, __pmd)	\
	do { } while (0)
#define split_huge_page_pud(__vma, __address, __pud)	\
	do { } while (0)

static inline int hugepage_madvise(struct vm_area_struct *vma,
				   unsigned long *vm_flags, int advice)
{
	BUG();
	return 0;
}
static inline void vma_adjust_trans_huge(struct vm_area_struct *vma,
					 unsigned long start,
					 unsigned long end,
					 long adjust_next)
{
}
static inline int pmd_trans_huge_lock(pmd_t *pmd, struct vm_area_struct *vma,
		spinlock_t **ptl)
{
	return 0;
}
static inline int pud_trans_huge_lock(pud_t *pud, struct vm_area_struct *vma,
		spinlock_t **ptl)
{
	return 0;
}

static inline int do_huge_pmd_numa_page(struct vm_fault *vmf, pmd_t orig_pmd);
{
	return 0;
}

static inline bool is_trans_huge_page_release(struct page *page)
{
	return false;
}

static inline struct page *trans_huge_page_release_encode(struct page *page)
{
	return page;
}

static inline struct page *trans_huge_page_release_decode(struct page *page)
{
	return page;
}

extern void dec_trans_huge_mmu_gather_count(struct page *page);
extern bool is_huge_zero_page_release(struct page *page);

static inline bool is_huge_zero_page(struct page *page)
{
	return false;
}

static inline bool is_huge_zero_pud(pud_t pud)
{
	return false;
}

static inline struct page *follow_devmap_pmd(struct vm_area_struct *vma,
		unsigned long addr, pmd_t *pmd, int flags)
{
	return NULL;
}

static inline struct page *follow_devmap_pud(struct vm_area_struct *vma,
		unsigned long addr, pud_t *pud, int flags)
{
	return NULL;
}

#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

#endif /* _LINUX_HUGE_MM_H */
