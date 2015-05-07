#ifndef __UB_DCACHE_H__
#define __UB_DCACHE_H__

#include <bc/decl.h>

extern unsigned int ub_dcache_threshold;

UB_DECLARE_FUNC(int, ub_dcache_charge(struct user_beancounter *ub, int name_len))
UB_DECLARE_VOID_FUNC(ub_dcache_uncharge(struct user_beancounter *ub, int name_len))
UB_DECLARE_VOID_FUNC(ub_dcache_set_owner(struct dentry *d, struct user_beancounter *ub))
UB_DECLARE_VOID_FUNC(ub_dcache_change_owner(struct dentry *dentry, struct user_beancounter *ub))
UB_DECLARE_VOID_FUNC(ub_dcache_clear_owner(struct dentry *dentry))
UB_DECLARE_VOID_FUNC(ub_dcache_unuse(struct user_beancounter *ub))
UB_DECLARE_VOID_FUNC(ub_dcache_reclaim(struct user_beancounter *ub, unsigned long numerator, unsigned long denominator))
UB_DECLARE_FUNC(int, ub_dcache_shrink(struct user_beancounter *ub, unsigned long size, gfp_t gfp_mask))
UB_DECLARE_FUNC(unsigned long, ub_dcache_get_size(struct dentry *dentry))

#endif
