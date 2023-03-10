#ifndef ARCH_X86_CPU_H
#define ARCH_X86_CPU_H

struct cpu_model_info {
	int		vendor;
	int		family;
	const char	*model_names[16];
};

/* attempt to consolidate cpu attributes */
struct cpu_dev {
	const char	*c_vendor;

	/* some have two possibilities for cpuid string */
	const char	*c_ident[2];

	struct		cpu_model_info c_models[4];

	void            (*c_early_init)(struct cpuinfo_x86 *);
	void		(*c_bsp_init)(struct cpuinfo_x86 *);
	void		(*c_init)(struct cpuinfo_x86 *);
	void		(*c_identify)(struct cpuinfo_x86 *);
	void		(*c_detect_tlb)(struct cpuinfo_x86 *);
	unsigned int	(*c_size_cache)(struct cpuinfo_x86 *, unsigned int);
	int		c_x86_vendor;
};

struct _tlb_table {
	unsigned char descriptor;
	char tlb_type;
	unsigned int entries;
	/* unsigned int ways; */
	char info[128];
};

#define cpu_dev_register(cpu_devX) \
	static const struct cpu_dev *const __cpu_dev_##cpu_devX __used \
	__attribute__((__section__(".x86_cpu_dev.init"))) = \
	&cpu_devX;

extern const struct cpu_dev *const __x86_cpu_dev_start[],
			    *const __x86_cpu_dev_end[];

#ifdef CONFIG_CPU_SUP_INTEL
enum tsx_ctrl_states {
	TSX_CTRL_ENABLE,
	TSX_CTRL_DISABLE,
	TSX_CTRL_NOT_SUPPORTED,
};

extern enum tsx_ctrl_states tsx_ctrl_state __read_mostly;

extern void __init tsx_init(void);
extern void tsx_enable(void);
extern void tsx_disable(void);
#else
static inline void tsx_init(void) { }
#endif /* CONFIG_CPU_SUP_INTEL */

extern void get_cpu_cap(struct cpuinfo_x86 *c);
extern void cpu_detect_cache_sizes(struct cpuinfo_x86 *c);
extern int detect_extended_topology_early(struct cpuinfo_x86 *c);
extern int detect_ht_early(struct cpuinfo_x86 *c);

extern void update_srbds_msr(void);

extern u64 x86_read_arch_cap_msr(void);
#endif /* ARCH_X86_CPU_H */
