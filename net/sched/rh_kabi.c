/*
 * We need to see the real struct Qdisc and not the fake one.
 * We cannot simply undefine __GENKSYMS__ here because we need
 * RH_KABI_ macros.
 */
#define __RH_KABI_PROTECT_QDISC
#include <net/sch_generic.h>

void __rh_kabi_protect_Qdisc(struct Qdisc *param)
{
}
EXPORT_SYMBOL(__rh_kabi_protect_Qdisc);
