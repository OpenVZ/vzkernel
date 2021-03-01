#ifndef _ASM_X86_UV_UV_H
#define _ASM_X86_UV_UV_H

enum uv_system_type {UV_NONE, UV_LEGACY_APIC, UV_X2APIC, UV_NON_UNIQUE_APIC};

struct cpumask;
struct mm_struct;

#ifdef CONFIG_X86_UV

#define	UV_PROC_NODE	"sgi_uv"

static inline int uv(int uvtype)
{
	/* uv(0) is "any" */
	if (uvtype >= 0 && uvtype <= 30)
		return 1 << uvtype;
	return 1;
}


extern enum uv_system_type get_uv_system_type(void);
extern int is_uv_system(void);
extern int is_uv_hubbed(int uvtype);
extern int is_uv_hubless(int uvtype);
extern void uv_cpu_init(void);
extern void uv_nmi_init(void);
extern void uv_system_init(void);
extern const struct cpumask *uv_flush_tlb_others(const struct cpumask *cpumask,
						 struct mm_struct *mm,
						 unsigned long start,
						 unsigned long end,
						 unsigned int cpu);
#ifndef __GENKSYMS__
#include <linux/efi.h>
#endif
static inline int is_early_uv_system(void)
{
	return !((efi.uv_systab == EFI_INVALID_TABLE_ADDR) || !efi.uv_systab);
}

#else	/* X86_UV */

static inline enum uv_system_type get_uv_system_type(void) { return UV_NONE; }
static inline int is_uv_system(void)	{ return 0; }
static inline int is_uv_hubbed(int uv)	{ return 0; }
static inline int is_uv_hubless(int uv) { return 0; }
static inline void uv_cpu_init(void)	{ }
static inline void uv_system_init(void)	{ }
static inline const struct cpumask *
uv_flush_tlb_others(const struct cpumask *cpumask, struct mm_struct *mm,
		    unsigned long start, unsigned long end, unsigned int cpu)
{ return cpumask; }
static inline int is_early_uv_system(void)	{ return 0; }

#endif	/* X86_UV */

#endif	/* _ASM_X86_UV_UV_H */
