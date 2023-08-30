obj-y := core.o

obj-$(CONFIG_BPF_SYSCALL) += syscall.o verifier.o inode.o helpers.o tnum.o
obj-$(CONFIG_BPF_SYSCALL) += hashtab.o arraymap.o percpu_freelist.o bpf_lru_list.o lpm_trie.o map_in_map.o
obj-$(CONFIG_BPF_SYSCALL) += disasm.o
obj-$(CONFIG_BPF_SYSCALL) += socket_filter.o
obj-$(CONFIG_BPF_SYSCALL) += sched_cls_act.o
ifeq ($(CONFIG_NET),y)
obj-$(CONFIG_BPF_SYSCALL) += devmap.o
endif
ifeq ($(CONFIG_PERF_EVENTS),y)
obj-$(CONFIG_BPF_SYSCALL) += stackmap.o
endif
