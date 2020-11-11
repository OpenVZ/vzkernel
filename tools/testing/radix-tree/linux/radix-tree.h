#define RH_KABI_REPLACE2(orig, _new1, _new2)	\
	struct{ _new1; _new2;};
#define RH_KABI_DEPRECATE(_type, _orig)

#include "../../../../include/linux/radix-tree.h"
