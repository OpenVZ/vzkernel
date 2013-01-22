/*
 *  include/linux/ve.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef _LINUX_VE_H
#define _LINUX_VE_H

#include <linux/types.h>
#include <linux/capability.h>
#include <linux/sysctl.h>
#include <linux/net.h>
#include <linux/vzstat.h>
#include <linux/kobject.h>
#include <linux/pid.h>
#include <linux/path.h>
#include <linux/socket.h>
#include <net/inet_frag.h>

#ifdef VZMON_DEBUG
#  define VZTRACE(fmt,args...) \
	printk(KERN_DEBUG fmt, ##args)
#else
#  define VZTRACE(fmt,args...)
#endif /* VZMON_DEBUG */

struct tty_driver;
struct task_struct;
struct new_utsname;
struct file_system_type;
struct icmp_mib;
struct ip_mib;
struct tcp_mib;
struct udp_mib;
struct linux_mib;
struct fib_info;
struct fib_rule;
struct veip_struct;
struct ve_monitor;
struct nsproxy;

#if defined(CONFIG_VE) && defined(CONFIG_INET)
struct fib_table;
#ifdef CONFIG_VE_IPTABLES
struct xt_table;
struct nf_conn;

#define FRAG6Q_HASHSZ   64

struct ve_nf_conntrack {
	struct hlist_head		*_bysource;
	struct nf_nat_protocol		**_nf_nat_protos;
	int				_nf_nat_vmalloced;
	struct xt_table			*_nf_nat_table;
	struct nf_conntrack_l3proto	*_nf_nat_l3proto;
	atomic_t			_nf_conntrack_count;
	int				_nf_conntrack_max;
	struct hlist_head		*_nf_conntrack_hash;
	int				_nf_conntrack_checksum;
	int				_nf_conntrack_vmalloc;
	struct hlist_head		_unconfirmed;
	struct hlist_head		*_nf_ct_expect_hash;
	unsigned int			_nf_ct_expect_vmalloc;
	unsigned int			_nf_ct_expect_count;
	unsigned int			_nf_ct_expect_max;
	struct hlist_head		*_nf_ct_helper_hash;
	unsigned int			_nf_ct_helper_vmalloc;
#ifdef CONFIG_SYSCTL
	/* l4 stuff: */
	unsigned long			_nf_ct_icmp_timeout;
	unsigned long			_nf_ct_icmpv6_timeout;
	unsigned int			_nf_ct_udp_timeout;
	unsigned int			_nf_ct_udp_timeout_stream;
	unsigned int			_nf_ct_generic_timeout;
	unsigned int			_nf_ct_log_invalid;
	unsigned int			_nf_ct_tcp_timeout_max_retrans;
	unsigned int			_nf_ct_tcp_timeout_unacknowledged;
	int				_nf_ct_tcp_be_liberal;
	int				_nf_ct_tcp_loose;
	int				_nf_ct_tcp_max_retrans;
	unsigned int			_nf_ct_tcp_timeouts[10];
	struct ctl_table_header		*_icmp_sysctl_header;
	unsigned int			_tcp_sysctl_table_users;
	struct ctl_table_header		*_tcp_sysctl_header;
	unsigned int			_udp_sysctl_table_users;
	struct ctl_table_header		*_udp_sysctl_header;
	struct ctl_table_header		*_icmpv6_sysctl_header;
	struct ctl_table_header		*_generic_sysctl_header;
#ifdef CONFIG_NF_CONNTRACK_PROC_COMPAT
	struct ctl_table_header		*_icmp_compat_sysctl_header;
	struct ctl_table_header		*_tcp_compat_sysctl_header;
	struct ctl_table_header		*_udp_compat_sysctl_header;
	struct ctl_table_header		*_generic_compat_sysctl_header;
#endif
	/* l4 protocols sysctl tables: */
	struct nf_conntrack_l4proto	*_nf_conntrack_l4proto_icmp;
	struct nf_conntrack_l4proto	*_nf_conntrack_l4proto_tcp4;
	struct nf_conntrack_l4proto	*_nf_conntrack_l4proto_icmpv6;
	struct nf_conntrack_l4proto	*_nf_conntrack_l4proto_tcp6;
	struct nf_conntrack_l4proto	*_nf_conntrack_l4proto_udp4;
	struct nf_conntrack_l4proto	*_nf_conntrack_l4proto_udp6;
	struct nf_conntrack_l4proto	*_nf_conntrack_l4proto_generic;
	struct nf_conntrack_l4proto	**_nf_ct_protos[PF_MAX];
	/* l3 protocols sysctl tables: */
	struct nf_conntrack_l3proto	*_nf_conntrack_l3proto_ipv4;
	struct nf_conntrack_l3proto	*_nf_conntrack_l3proto_ipv6;
	struct nf_conntrack_l3proto	*_nf_ct_l3protos[AF_MAX];
	/* sysctl standalone stuff: */
	struct ctl_table_header		*_nf_ct_sysctl_header;
	ctl_table			*_nf_ct_sysctl_table;
	ctl_table			*_nf_ct_netfilter_table;
	ctl_table			*_nf_ct_net_table;
	ctl_table			*_ip_ct_netfilter_table;
	struct ctl_table_header		*_ip_ct_sysctl_header;
	int				_nf_ct_log_invalid_proto_min;
	int				_nf_ct_log_invalid_proto_max;
#endif /* CONFIG_SYSCTL */
};
#endif
#endif

struct ve_ipt_recent;
struct ve_xt_hashlimit;
struct svc_rqst;

struct cgroup;
struct css_set;

struct ve_struct {
	struct list_head	ve_list;

	envid_t			veid;
	/* capability bounding set */
	kernel_cap_t		ve_cap_bset;
	unsigned int		pcounter;
	/* ref counter to ve from ipc */
	atomic_t		counter;
	unsigned int		class_id;
	struct rw_semaphore	op_sem;
	int			is_running;
	int			is_locked;
	atomic_t		suspend;
	unsigned long		flags;
	/* see vzcalluser.h for VE_FEATURE_XXX definitions */
	__u64			features;

/* VE's root */
	struct path		root_path;

#ifdef CONFIG_UNIX98_PTYS
	struct vfsmount		*devpts_mnt;
#endif

#define	MAX_NR_VTTY		12
	struct tty_struct	*vtty[MAX_NR_VTTY];

	struct list_head	devices;

#ifdef CONFIG_INET
	unsigned long		rt_flush_required;
#endif
#if defined(CONFIG_VE_NETDEV) || defined (CONFIG_VE_NETDEV_MODULE)
	struct veip_struct	*veip;
	struct net_device	*_venet_dev;
#endif

/* per VE CPU stats*/
	struct timespec		start_timespec;		/* monotonic time */
	struct timespec		real_start_timespec;	/* boot based time */
	u64			start_jiffies;	/* Deprecated */

	struct kstat_lat_pcpu_struct	sched_lat_ve;

#ifdef CONFIG_INET
	struct venet_stat       *stat;
#ifdef CONFIG_VE_IPTABLES
/* core/netfilter.c virtualization */
	__u64			ipt_mask;
	__u64			_iptables_modules;
	struct ve_ipt_recent	*_ipt_recent;
	struct ve_xt_hashlimit	*_xt_hashlimit;
#endif /* CONFIG_VE_IPTABLES */
#endif
	wait_queue_head_t	*_log_wait;
	unsigned		*_log_start;
	unsigned		*_log_end;
	unsigned		*_logged_chars;
	char			*log_buf;
#define VE_DEFAULT_LOG_BUF_LEN	4096

	unsigned long		down_at;
	struct list_head	cleanup_list;
#if defined(CONFIG_FUSE_FS) || defined(CONFIG_FUSE_FS_MODULE)
	struct list_head	_fuse_conn_list;
	struct super_block	*_fuse_control_sb;

	struct file_system_type	*fuse_fs_type;
	struct file_system_type	*fuse_ctl_fs_type;
#endif
	unsigned long		jiffies_fixup;
	unsigned char		disable_net;
	struct ve_monitor	*monitor;
	struct proc_dir_entry	*monitor_proc;
	unsigned long		meminfo_val;
	int _randomize_va_space;

	int 			odirect_enable;

#if defined(CONFIG_LOCKD) || defined(CONFIG_LOCKD_MODULE)
	struct ve_nlm_data	*nlm_data;
#endif
#if defined(CONFIG_NFS_FS) || defined(CONFIG_NFS_FS_MODULE)
	struct ve_nfs_data	*nfs_data;
#endif
#if defined(CONFIG_NFSD) || defined(CONFIG_NFSD_MODULE)
	struct ve_nfsd_data	*nfsd_data;
#endif
#if defined(CONFIG_SUNRPC) || defined(CONFIG_SUNRPC_MODULE)
	struct ve_rpc_data	*rpc_data;
#endif
#if defined(CONFIG_BINFMT_MISC) || defined(CONFIG_BINFMT_MISC_MODULE)
	struct file_system_type	*bm_fs_type;
	struct vfsmount		*bm_mnt;
	int			bm_enabled;
	int			bm_entry_count;
	struct list_head	bm_entries;
#endif

	struct nsproxy		*ve_ns;
	struct user_namespace	*user_ns;
	struct cred		*init_cred;
	struct net		*ve_netns;
	struct cgroup		*ve_cgroup;
#if defined(CONFIG_HOTPLUG)
	u64 _uevent_seqnum;
#endif
	struct mutex		sync_mutex;
};

#define VE_MEMINFO_DEFAULT      1       /* default behaviour */
#define VE_MEMINFO_SYSTEM       0       /* disable meminfo virtualization */

enum {
	VE_REBOOT,
};

extern int nr_ve;
extern struct proc_dir_entry *proc_vz_dir;
extern struct proc_dir_entry *glob_proc_vz_dir;

#ifdef CONFIG_VE

void do_update_load_avg_ve(void);
void do_env_free(struct ve_struct *ptr);

static inline struct ve_struct *get_ve(struct ve_struct *ptr)
{
	if (ptr != NULL)
		atomic_inc(&ptr->counter);
	return ptr;
}

static inline void put_ve(struct ve_struct *ptr)
{
	if (ptr && atomic_dec_and_test(&ptr->counter))
		do_env_free(ptr);
}

void ve_cleanup_schedule(struct ve_struct *);

extern spinlock_t ve_cleanup_lock;
extern struct list_head ve_cleanup_list;
extern struct task_struct *ve_cleanup_thread;

extern int (*do_ve_enter_hook)(struct ve_struct *ve, unsigned int flags);
extern void (*do_env_free_hook)(struct ve_struct *ve);

extern unsigned long long ve_relative_clock(struct timespec * ts);

#ifdef CONFIG_VTTYS
extern int vtty_open_master(int veid, int idx);
extern struct tty_driver *vtty_driver;
#else
static inline int vtty_open_master(int veid, int idx) { return -ENODEV; }
#endif

#else	/* CONFIG_VE */
#define ve_utsname	system_utsname
#define get_ve(ve)	(NULL)
#define put_ve(ve)	do { } while (0)
#define pget_ve(ve)	do { } while (0)
#define pput_ve(ve)	do { } while (0)
#endif	/* CONFIG_VE */

#endif /* _LINUX_VE_H */
