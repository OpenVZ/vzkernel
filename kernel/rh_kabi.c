/*
 * The current implementation of RH's KABI only protects functions.  There are
 * some cases where we would like to protect a struct.  In order to protect
 * a struct it must be included as a parameter to a function.
 *
 * Every release we will add the appropriate rh_kabi_* struct to the kabi
 * whitelists.
 *
 * I don't care if this file gets cluttered with #ifdef CONFIG_ARCHes
 * which prevents us from having to have a rh_kabi.c in each arch directory.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>

struct rh_kabi_structs_7_0 {
	int pad; /* avoid an empty struct */
};

struct rh_kabi_structs_7_2 {
	struct nf_hook_state *nf_hook_state;
};

void rh_kabi_7_0(struct rh_kabi_structs_7_0 *rh_kabi_structs_7_0)
{
	/* No one should ever call this function */
	panic("Problem exists between keyboard and your seat.");
}
EXPORT_SYMBOL_GPL(rh_kabi_7_0);

void rh_kabi_7_2(struct rh_kabi_structs_7_2 *rh_kabi_structs_7_2)
{
	/* No need to duplicate the string above */
	rh_kabi_7_0(NULL);
}
EXPORT_SYMBOL_GPL(rh_kabi_7_2);
