#ifndef __CPUID_OVERRIDE_H
#define __CPUID_OVERRIDE_H

#include <linux/rcupdate.h>

struct cpuid_override_entry {
	unsigned int op;
	unsigned int count;
	bool has_count;
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
};

#define MAX_CPUID_OVERRIDE_ENTRIES	16

struct cpuid_override_table {
	struct rcu_head rcu_head;
	int size;
	struct cpuid_override_entry entries[MAX_CPUID_OVERRIDE_ENTRIES];
};

extern struct cpuid_override_table __rcu *cpuid_override;

static inline bool cpuid_override_on(void)
{
	return rcu_access_pointer(cpuid_override);
}
#endif
