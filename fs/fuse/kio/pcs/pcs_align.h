#ifndef __PCS_ALIGN_H__
#define __PCS_ALIGN_H__

#include "pcs_types.h"

/* ----- helpers ----- */

#if defined(__GNUC__) || defined(__clang__)

#define __pre_aligned(x)
#define __pre_packed
#define __unaligned		__attribute__((packed, may_alias))
#endif

#define PCS_ALIGN_TO(sz, align) (((sz)+(align)-1)&~((align)-1))
#define PCS_ALIGN(sz) PCS_ALIGN_TO(sz, 8)

#endif /* __PCS_ALIGN_H__ */
