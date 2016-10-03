/*
	kmod, the new module loader (replaces kerneld)
	Kirk Petersen

	Reorganized not to be a daemon by Adam Richter, with guidance
	from Greg Zornetzer.

	Modified to avoid chroot and file sharing problems.
	Mikael Pettersson

	Limit the concurrent number of kmod modprobes to catch loops from
	"modprobe needs a service that is in a module".
	Keith Owens <kaos@ocs.com.au> December 1999

	Unblock all signals when we exec a usermode process.
	Shuu Yamaguchi <shuu@wondernetworkresources.com> December 2000

	call_usermodehelper wait flag, and remove exec_usermodehelper.
	Rusty Russell <rusty@rustcorp.com.au>  Jan 2003
*/
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/kthread.h>
#include <linux/security.h>
#include <linux/mount.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/resource.h>
#include <linux/notifier.h>
#include <linux/suspend.h>
#include <linux/rwsem.h>
#include <linux/ptrace.h>
#include <linux/async.h>
#include <linux/ve.h>
#include <linux/netfilter.h>
#include <linux/sysctl.h>
#include <asm/uaccess.h>

#include <trace/events/module.h>

extern int max_threads;

static DEFINE_KTHREAD_WORKER(khelper_worker);

/*
 * kmod_thread_locker is used for deadlock avoidance.  There is no explicit
 * locking to protect this global - it is private to the singleton khelper
 * thread and should only ever be modified by that thread.
 */
static const struct task_struct *kmod_thread_locker;

#define CAP_BSET	(void *)1
#define CAP_PI		(void *)2

static kernel_cap_t usermodehelper_bset = CAP_FULL_SET;
static kernel_cap_t usermodehelper_inheritable = CAP_FULL_SET;
static DEFINE_SPINLOCK(umh_sysctl_lock);
static DECLARE_RWSEM(umhelper_sem);

#ifdef CONFIG_MODULES

/*
	modprobe_path is set via /proc/sys.
*/
char modprobe_path[KMOD_PATH_LEN] = "/sbin/modprobe";

static void free_modprobe_argv(struct subprocess_info *info)
{
	kfree(info->argv[4]); /* check call_modprobe() */
	kfree(info->argv);
}

static int __call_usermodehelper_exec(struct kthread_worker *worker,
		struct subprocess_info *sub_info, int wait);

static int call_modprobe(char *module_name, int wait, int blacklist)
{
	struct subprocess_info *info;
	static char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
		NULL
	};

	char **argv = kmalloc(sizeof(char *[6]), GFP_KERNEL);
	if (!argv)
		goto out;

	module_name = kstrdup(module_name, GFP_KERNEL);
	if (!module_name)
		goto free_argv;

	argv[0] = modprobe_path;
	argv[1] = "-q";
	if (blacklist)
		argv[2] = "-b";
	else
		argv[2] = "-q"; /* just repeat argv[1] */
	argv[3] = "--";
	argv[4] = module_name;	/* check free_modprobe_argv() */
	argv[5] = NULL;

	info = call_usermodehelper_setup(modprobe_path, argv, envp, GFP_KERNEL,
					 NULL, free_modprobe_argv, NULL);
	if (!info)
		goto free_module_name;

	/*
	 * We enter to this function with the right permittions, so
	 * it's possible to directly call __call_usermodehelper_exec()
	 */
	return __call_usermodehelper_exec(&khelper_worker, info, wait | UMH_KILLABLE);

free_module_name:
	kfree(module_name);
free_argv:
	kfree(argv);
out:
	return -ENOMEM;
}

/**
 * ___request_module - try to load a kernel module
 * @wait: wait (or not) for the operation to complete
 * @blacklist: say usermodehelper to ignore blacklisted modules
 * @module_name: name of requested module
 *
 * Load a module using the user mode module loader. The function returns
 * zero on success or a negative errno code on failure. Note that a
 * successful module load does not mean the module did not then unload
 * and exit on an error of its own. Callers must check that the service
 * they requested is now available not blindly invoke it.
 *
 * If module auto-loading support is disabled then this function
 * becomes a no-operation.
 */
static int ___request_module(bool wait, bool blacklist, char *module_name)
{
	unsigned int max_modprobes;
	int ret;
	static atomic_t kmod_concurrent = ATOMIC_INIT(0);
#define MAX_KMOD_CONCURRENT 50	/* Completely arbitrary value - KAO */
	static int kmod_loop_msg;

	/*
	 * We don't allow synchronous module loading from async.  Module
	 * init may invoke async_synchronize_full() which will end up
	 * waiting for this task which already is waiting for the module
	 * loading to complete, leading to a deadlock.
	 */
	WARN_ON_ONCE(wait && current_is_async());

	ret = security_kernel_module_request(module_name);
	if (ret)
		return ret;

	/* If modprobe needs a service that is in a module, we get a recursive
	 * loop.  Limit the number of running kmod threads to max_threads/2 or
	 * MAX_KMOD_CONCURRENT, whichever is the smaller.  A cleaner method
	 * would be to run the parents of this process, counting how many times
	 * kmod was invoked.  That would mean accessing the internals of the
	 * process tables to get the command line, proc_pid_cmdline is static
	 * and it is not worth changing the proc code just to handle this case. 
	 * KAO.
	 *
	 * "trace the ppid" is simple, but will fail if someone's
	 * parent exits.  I think this is as good as it gets. --RR
	 */
	max_modprobes = min(max_threads/2, MAX_KMOD_CONCURRENT);
	atomic_inc(&kmod_concurrent);
	if (atomic_read(&kmod_concurrent) > max_modprobes) {
		/* We may be blaming an innocent here, but unlikely */
		if (kmod_loop_msg < 5) {
			printk(KERN_ERR
			       "request_module: runaway loop modprobe %s\n",
			       module_name);
			kmod_loop_msg++;
		}
		atomic_dec(&kmod_concurrent);
		return -ENOMEM;
	}

	trace_module_request(module_name, wait, _RET_IP_);

	ret = call_modprobe(module_name, wait ? UMH_WAIT_PROC : UMH_WAIT_EXEC, blacklist);

	atomic_dec(&kmod_concurrent);
	return ret;
}

#ifdef CONFIG_VE_IPTABLES

/* ve0 allowed iptables modules */
static struct {
	const char *name;
	u64 perm;
} ve0_ipt_am[] = {
	{ "ip_tables",		VE_IP_IPTABLES	},
	{ "ip6_tables",		VE_IP_IPTABLES6	},
	{ "iptable_filter",	VE_IP_FILTER	},
	{ "iptable_raw",	VE_IP_IPTABLES	},
	{ "iptable_nat",	VE_IP_NAT	},
	{ "iptable_mangle",	VE_IP_MANGLE	},
	{ "ip6table_filter",	VE_IP_FILTER6	},
	{ "ip6table_nat",	VE_IP_NAT	},
	{ "ip6table_mangle",	VE_IP_MANGLE6	},

	{ "xt_CONNMARK",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "xt_CONNSECMARK",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "xt_NOTRACK",		VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "xt_cluster",		VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "xt_connbytes",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "xt_connlimit",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "xt_connmark",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "xt_conntrack",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "xt_helper",		VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "xt_state",		VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "xt_socket",		VE_NF_CONNTRACK|VE_IP_CONNTRACK|
				VE_IP_IPTABLES6			},
	{ "xt_connlabel",	VE_NF_CONNTRACK|VE_IP_CONNTRACK|
				VE_IP_IPTABLES6			},

	{ "ipt_CLUSTERIP",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ipt_CONNMARK",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ipt_CONNSECMARK",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ipt_NOTRACK",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ipt_cluster",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ipt_connbytes",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ipt_connlimit",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ipt_connmark",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ipt_conntrack",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ipt_helper",		VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ipt_state",		VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ipt_socket",		VE_NF_CONNTRACK|VE_IP_CONNTRACK|
				VE_IP_IPTABLES6			},
	{ "ipt_MASQUERADE",	VE_NF_CONNTRACK|VE_IP_CONNTRACK|
				VE_IP_NAT			},
	{ "ipt_NETMAP",		VE_NF_CONNTRACK|VE_IP_CONNTRACK|
				VE_IP_NAT			},
	{ "ipt_REDIRECT",	VE_NF_CONNTRACK|VE_IP_CONNTRACK|
				VE_IP_NAT			},
	{ "ipt_connlabel",	VE_NF_CONNTRACK|VE_IP_CONNTRACK|
				VE_IP_IPTABLES6			},
	{ "ipt_SYNPROXY",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },

	{ "ip6t_CONNMARK",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ip6t_CONNSECMARK",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ip6t_NOTRACK",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ip6t_cluster",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ip6t_connbytes",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ip6t_connlimit",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ip6t_connmark",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ip6t_conntrack",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ip6t_helper",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ip6t_state",		VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ip6t_socket",	VE_NF_CONNTRACK|VE_IP_CONNTRACK|
				VE_IP_IPTABLES6			},
	{ "ip6t_MASQUERADE",	VE_NF_CONNTRACK|VE_IP_CONNTRACK|
				VE_IP_NAT|VE_IP_IPTABLES6	},
	{ "ip6t_connlabel",	VE_NF_CONNTRACK|VE_IP_CONNTRACK|
				VE_IP_IPTABLES6			},
	{ "ip6t_SYNPROXY",	VE_NF_CONNTRACK|VE_IP_CONNTRACK|
				VE_IP_IPTABLES6			},

	{ "nf-nat-ipv4",	VE_NF_CONNTRACK|VE_IP_CONNTRACK|
				VE_IP_NAT			},
	{ "nf-nat",		VE_NF_CONNTRACK|VE_IP_CONNTRACK|
				VE_IP_NAT			},
	{ "nf_conntrack-2",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "nf_conntrack_ipv4",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "ip_conntrack",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "nf_conntrack-10",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },
	{ "nf_conntrack_ipv6",	VE_NF_CONNTRACK|VE_IP_CONNTRACK },

	{ "nft-set",		VE_IP_IPTABLES			},
	{ "nft-afinfo-2",	VE_IP_IPTABLES			}, /* IPV4 */
	{ "nft-afinfo-3",	VE_IP_IPTABLES			}, /* ARP  */
	{ "nft-afinfo-10",	VE_IP_IPTABLES6			}, /* IPV6 */

	{ "nft-chain-2-nat",	VE_IP_IPTABLES|VE_IP_NAT	},
	{ "nft-chain-2-route",	VE_IP_IPTABLES			},

	{ "nft-chain-10-nat",	VE_IP_IPTABLES6|VE_IP_NAT	},
	{ "nft-chain-10-route",	VE_IP_IPTABLES6		},

	{ "nft-expr-2-reject",	VE_IP_IPTABLES			},
	{ "nft-expr-10-reject",	VE_IP_IPTABLES6			},
	{ "nf-logger-2-0",	VE_IP_IPTABLES			},
	{ "nf-logger-10-0",	VE_IP_IPTABLES6			},
};

/*
 *  Check if module named nft-expr-name is allowed.
 *  We pass only tail name part to this function.
 */
static bool nft_expr_allowed(const char *name)
{
	u64 permitted = get_exec_env()->ipt_mask;

	if (!name[0])
		return false;

	if (!strcmp(name, "ct"))
		return mask_ipt_allow(permitted, VE_IP_CONNTRACK);

	if (!strcmp(name, "nat"))
		return mask_ipt_allow(permitted, VE_IP_NAT);

	/*
	 * We are interested in modules like nft-expr-xxx.
	 * Expressions like nft-expr-xxx-yyy currently are
	 * handled in ve0_ipt_am table. So expr does not contain
	 * minus
	 */
	if (!strchr(name, '-'))
		return mask_ipt_allow(permitted, VE_IP_IPTABLES) |
		       mask_ipt_allow(permitted, VE_IP_IPTABLES6);
	return false;
}

/*
 * module_payload_iptable_allowed - check if iptables functionality is allowed
 *			    to be used inside current virtual environment.
 *
 * Returns:
 *   0 if iptable module is disallowed to load
 *   1 if it is allowed or we're in ve0
 *   -1 if module isn't iptables module
 */
static inline int module_payload_iptable_allowed(const char *module)
{
	u64 permitted = get_exec_env()->ipt_mask;
	int i;

	/* Look for full module name in ve0_ipt_am table */
	for (i = 0; i < ARRAY_SIZE(ve0_ipt_am); i++) {
		if (!strcmp(ve0_ipt_am[i].name, module))
			return mask_ipt_allow(permitted, ve0_ipt_am[i].perm);
	}

	/* The rest of xt_* modules is allowed in both ipv4 and ipv6 modes */
	if (!strncmp("xt_", module, 3))
		return mask_ipt_allow(permitted, VE_IP_IPTABLES) ||
		       mask_ipt_allow(permitted, VE_IP_IPTABLES6);

	/* The rest of ipt_* modules */
	if (!strncmp("ipt_", module, 4))
		return mask_ipt_allow(permitted, VE_IP_IPTABLES);

	/* The rest of ip6t_* modules */
	if (!strncmp("ip6t_", module, 5))
		return mask_ipt_allow(permitted, VE_IP_IPTABLES6);

	/* The rest of arpt_* modules */
	if (!strncmp("arpt_", module, 5))
		return 1;

	/* The rest of ebt_* modules */
	if (!strncmp("ebt_", module, 4))
		return 1;

	/* The rest of nft- modules */
	if (!strncmp("nft-expr-", module, 9))
		return nft_expr_allowed(module + 9);

	return -1;
}

/* ve0 allowed modules */
static const char * const ve0_allowed_mod[] = {
	"fs-binfmt_misc",
	"fs-overlay",

	/* inet_diag, inet6_diag  */
	"net-pf-16-proto-4-type-2",	/* PF_NETLINK, NETLINK_SOCK_DIAG, AF_INET */
	"net-pf-16-proto-4-type-10",	/* PF_NETLINK, NETLINK_SOCK_DIAG, AF_INET6 */

	/* tcp_diag */
	"net-pf-16-proto-4-type-2-6",	/* PF_NETLINK, NETLINK_SOCK_DIAG, AF_INET - IPPROTO_TCP */

	/* udp_diag */
	"net-pf-16-proto-4-type-2-17",	/* PF_NETLINK, NETLINK_SOCK_DIAG, AF_INET - IPPROTO_UDP */
	"net-pf-16-proto-4-type-2-136",	/* PF_NETLINK, NETLINK_SOCK_DIAG, AF_INET - IPPROTO_UDPLITE */

	/* nfnetlink  */
	"net-pf-16-proto-12",		/* PF_NETLINK, NETLINK_NETFILTER */
	"nfnetlink-subsys-1",		/* NFNL_SUBSYS_CTNETLINK */
	"nfnetlink-subsys-2",		/* NFNL_SUBSYS_CTNETLINK_EXP */

	/* unix_diag */
	"net-pf-16-proto-4-type-1",	/* PF_NETLINK, NETLINK_SOCK_DIAG, AF_LOCAL */

	/* af_packet_diag */
	"net-pf-16-proto-4-type-17",	/* PF_NETLINK, NETLINK_SOCK_DIAG, AF_PACKET */

	/* netlink_diag */
	"net-pf-16-proto-4-type-16",	/* PF_NETLINK, NETLINK_SOCK_DIAG, AF_NETLINK */

	"rtnl-link-dummy",
};

/*
 * module_payload_allowed - check if module functionality is allowed
 *			    to be used inside current virtual environment.
 *
 * Returns true if it is allowed or we're in ve0, false otherwise.
 */
bool module_payload_allowed(const char *module)
{
	int i;
	int ret;

	if (ve_is_super(get_exec_env()))
		return true;

	ret = module_payload_iptable_allowed(module);
	if (ret >= 0)
		return !!ret;

	for (i = 0; i < ARRAY_SIZE(ve0_allowed_mod); i++) {
		if (!strcmp(ve0_allowed_mod[i], module))
			return true;
	}

	return false;
}

#endif

int __request_module(bool wait, const char *fmt, ...)
{
	char module_name[MODULE_NAME_LEN];
	bool blacklist;
	va_list args;
	int ret;

	va_start(args, fmt);
	ret = vsnprintf(module_name, MODULE_NAME_LEN, fmt, args);
	va_end(args);

	if (ret >= MODULE_NAME_LEN)
		return -ENAMETOOLONG;

	/* Check that autoload is not prohobited using /proc interface */
	if (!ve_is_super(get_exec_env()) &&
	    !ve_allow_module_load)
		return -EPERM;

	/* Check that module functionality is permitted */
	if (!module_payload_allowed(module_name))
		return -EPERM;

	/*
	 * This function may be called from ve0, where standard behaviour
	 * is not to use blacklist. So, we request blacklist reading only
	 * if we're inside CT.
	 */
	blacklist = !ve_is_super(get_exec_env());

	return ___request_module(wait, blacklist, module_name);
}
EXPORT_SYMBOL(__request_module);
#endif /* CONFIG_MODULES */

/*
 * This is the task which runs the usermode application
 */
static int ____call_usermodehelper(void *data)
{
	struct subprocess_info *sub_info = data;
	struct cred *new;
	int retval;

	spin_lock_irq(&current->sighand->siglock);
	flush_signal_handlers(current, 1);
	spin_unlock_irq(&current->sighand->siglock);

	/*
	 * Our parent is keventd, which runs with elevated scheduling priority.
	 * Avoid propagating that into the userspace child.
	 */
	set_user_nice(current, 0);

	retval = -ENOMEM;
	new = prepare_kernel_cred(current);
	if (!new)
		goto fail;

	spin_lock(&umh_sysctl_lock);
	new->cap_bset = cap_intersect(usermodehelper_bset, new->cap_bset);
	new->cap_inheritable = cap_intersect(usermodehelper_inheritable,
					     new->cap_inheritable);
	spin_unlock(&umh_sysctl_lock);

	if (sub_info->init) {
		retval = sub_info->init(sub_info, new);
		if (retval) {
			abort_creds(new);
			goto fail;
		}
	}

	commit_creds(new);

	retval = do_execve(getname_kernel(sub_info->path),
			   (const char __user *const __user *)sub_info->argv,
			   (const char __user *const __user *)sub_info->envp);
	if (!retval)
		return 0;

	/* Exec failed? */
fail:
	sub_info->retval = retval;
	do_exit(0);
}

static int call_helper(void *data)
{
	/* Worker thread started blocking khelper thread. */
	kmod_thread_locker = current;
	return ____call_usermodehelper(data);
}

static void call_usermodehelper_freeinfo(struct subprocess_info *info)
{
	if (info->cleanup)
		(*info->cleanup)(info);
	kfree(info);
}

static void umh_complete(struct subprocess_info *sub_info)
{
	struct completion *comp = xchg(&sub_info->complete, NULL);
	/*
	 * See call_usermodehelper_exec(). If xchg() returns NULL
	 * we own sub_info, the UMH_KILLABLE caller has gone away.
	 */
	if (comp)
		complete(comp);
	else
		call_usermodehelper_freeinfo(sub_info);
}

/* Keventd can't block, but this (a child) can. */
static int wait_for_helper(void *data)
{
	struct subprocess_info *sub_info = data;
	pid_t pid;

	/* If SIGCLD is ignored sys_wait4 won't populate the status. */
	spin_lock_irq(&current->sighand->siglock);
	current->sighand->action[SIGCHLD-1].sa.sa_handler = SIG_DFL;
	spin_unlock_irq(&current->sighand->siglock);

	pid = kernel_thread(____call_usermodehelper, sub_info, SIGCHLD);
	if (pid < 0) {
		sub_info->retval = pid;
	} else {
		int ret = -ECHILD;
		/*
		 * Normally it is bogus to call wait4() from in-kernel because
		 * wait4() wants to write the exit code to a userspace address.
		 * But wait_for_helper() always runs as keventd, and put_user()
		 * to a kernel address works OK for kernel threads, due to their
		 * having an mm_segment_t which spans the entire address space.
		 *
		 * Thus the __user pointer cast is valid here.
		 */
		sys_wait4(pid, (int __user *)&ret, 0, NULL);

		/*
		 * If ret is 0, either ____call_usermodehelper failed and the
		 * real error code is already in sub_info->retval or
		 * sub_info->retval is 0 anyway, so don't mess with it then.
		 */
		if (ret)
			sub_info->retval = ret;
	}

	umh_complete(sub_info);
	do_exit(0);
}

/* This is run by khelper thread  */
static void __call_usermodehelper(struct kthread_work *work)
{
	struct subprocess_info *sub_info =
		container_of(work, struct subprocess_info, work);
	int wait = sub_info->wait & ~UMH_KILLABLE;
	pid_t pid;

	/* CLONE_VFORK: wait until the usermode helper has execve'd
	 * successfully We need the data structures to stay around
	 * until that is done.  */
	if (wait == UMH_WAIT_PROC)
		pid = kernel_thread(wait_for_helper, sub_info,
				    CLONE_FS | CLONE_FILES | SIGCHLD);
	else {
		pid = kernel_thread(call_helper, sub_info,
				    CLONE_VFORK | SIGCHLD);
		/* Worker thread stopped blocking khelper thread. */
		kmod_thread_locker = NULL;
	}

	switch (wait) {
	case UMH_NO_WAIT:
		call_usermodehelper_freeinfo(sub_info);
		break;

	case UMH_WAIT_PROC:
		if (pid > 0)
			break;
		/* FALLTHROUGH */
	case UMH_WAIT_EXEC:
		if (pid < 0)
			sub_info->retval = pid;
		umh_complete(sub_info);
	}
}

/*
 * If set, call_usermodehelper_exec() will exit immediately returning -EBUSY
 * (used for preventing user land processes from being created after the user
 * land has been frozen during a system-wide hibernation or suspend operation).
 * Should always be manipulated under umhelper_sem acquired for write.
 */
static enum umh_disable_depth usermodehelper_disabled = UMH_DISABLED;

/* Number of helpers running */
static atomic_t running_helpers = ATOMIC_INIT(0);

/*
 * Wait queue head used by usermodehelper_disable() to wait for all running
 * helpers to finish.
 */
static DECLARE_WAIT_QUEUE_HEAD(running_helpers_waitq);

/*
 * Used by usermodehelper_read_lock_wait() to wait for usermodehelper_disabled
 * to become 'false'.
 */
static DECLARE_WAIT_QUEUE_HEAD(usermodehelper_disabled_waitq);

/*
 * Time to wait for running_helpers to become zero before the setting of
 * usermodehelper_disabled in usermodehelper_disable() fails
 */
#define RUNNING_HELPERS_TIMEOUT	(5 * HZ)

int usermodehelper_read_trylock(void)
{
	DEFINE_WAIT(wait);
	int ret = 0;

	down_read(&umhelper_sem);
	for (;;) {
		prepare_to_wait(&usermodehelper_disabled_waitq, &wait,
				TASK_INTERRUPTIBLE);
		if (!usermodehelper_disabled)
			break;

		if (usermodehelper_disabled == UMH_DISABLED)
			ret = -EAGAIN;

		up_read(&umhelper_sem);

		if (ret)
			break;

		schedule();
		try_to_freeze();

		down_read(&umhelper_sem);
	}
	finish_wait(&usermodehelper_disabled_waitq, &wait);
	return ret;
}
EXPORT_SYMBOL_GPL(usermodehelper_read_trylock);

long usermodehelper_read_lock_wait(long timeout)
{
	DEFINE_WAIT(wait);

	if (timeout < 0)
		return -EINVAL;

	down_read(&umhelper_sem);
	for (;;) {
		prepare_to_wait(&usermodehelper_disabled_waitq, &wait,
				TASK_UNINTERRUPTIBLE);
		if (!usermodehelper_disabled)
			break;

		up_read(&umhelper_sem);

		timeout = schedule_timeout(timeout);
		if (!timeout)
			break;

		down_read(&umhelper_sem);
	}
	finish_wait(&usermodehelper_disabled_waitq, &wait);
	return timeout;
}
EXPORT_SYMBOL_GPL(usermodehelper_read_lock_wait);

void usermodehelper_read_unlock(void)
{
	up_read(&umhelper_sem);
}
EXPORT_SYMBOL_GPL(usermodehelper_read_unlock);

/**
 * __usermodehelper_set_disable_depth - Modify usermodehelper_disabled.
 * @depth: New value to assign to usermodehelper_disabled.
 *
 * Change the value of usermodehelper_disabled (under umhelper_sem locked for
 * writing) and wakeup tasks waiting for it to change.
 */
void __usermodehelper_set_disable_depth(enum umh_disable_depth depth)
{
	down_write(&umhelper_sem);
	usermodehelper_disabled = depth;
	wake_up(&usermodehelper_disabled_waitq);
	up_write(&umhelper_sem);
}

/**
 * __usermodehelper_disable - Prevent new helpers from being started.
 * @depth: New value to assign to usermodehelper_disabled.
 *
 * Set usermodehelper_disabled to @depth and wait for running helpers to exit.
 */
int __usermodehelper_disable(enum umh_disable_depth depth)
{
	long retval;

	if (!depth)
		return -EINVAL;

	down_write(&umhelper_sem);
	usermodehelper_disabled = depth;
	up_write(&umhelper_sem);

	/*
	 * From now on call_usermodehelper_exec() won't start any new
	 * helpers, so it is sufficient if running_helpers turns out to
	 * be zero at one point (it may be increased later, but that
	 * doesn't matter).
	 */
	retval = wait_event_timeout(running_helpers_waitq,
					atomic_read(&running_helpers) == 0,
					RUNNING_HELPERS_TIMEOUT);
	if (retval)
		return 0;

	__usermodehelper_set_disable_depth(UMH_ENABLED);
	return -EAGAIN;
}

static void helper_lock(void)
{
	atomic_inc(&running_helpers);
	smp_mb__after_atomic_inc();
}

static void helper_unlock(void)
{
	if (atomic_dec_and_test(&running_helpers))
		wake_up(&running_helpers_waitq);
}

/**
 * call_usermodehelper_setup - prepare to call a usermode helper
 * @path: path to usermode executable
 * @argv: arg vector for process
 * @envp: environment for process
 * @gfp_mask: gfp mask for memory allocation
 * @cleanup: a cleanup function
 * @init: an init function
 * @data: arbitrary context sensitive data
 *
 * Returns either %NULL on allocation failure, or a subprocess_info
 * structure.  This should be passed to call_usermodehelper_exec to
 * exec the process and free the structure.
 *
 * The init function is used to customize the helper process prior to
 * exec.  A non-zero return code causes the process to error out, exit,
 * and return the failure to the calling process
 *
 * The cleanup function is just before ethe subprocess_info is about to
 * be freed.  This can be used for freeing the argv and envp.  The
 * Function must be runnable in either a process context or the
 * context in which call_usermodehelper_exec is called.
 */
struct subprocess_info *call_usermodehelper_setup(char *path, char **argv,
		char **envp, gfp_t gfp_mask,
		int (*init)(struct subprocess_info *info, struct cred *new),
		void (*cleanup)(struct subprocess_info *info),
		void *data)
{
	struct subprocess_info *sub_info;
	sub_info = kzalloc(sizeof(struct subprocess_info), gfp_mask);
	if (!sub_info)
		goto out;

	init_kthread_work(&sub_info->work, __call_usermodehelper);
	sub_info->path = path;
	sub_info->argv = argv;
	sub_info->envp = envp;

	sub_info->cleanup = cleanup;
	sub_info->init = init;
	sub_info->data = data;
  out:
	return sub_info;
}
EXPORT_SYMBOL(call_usermodehelper_setup);

/**
 * call_usermodehelper_exec - start a usermode application
 * @sub_info: information about the subprocessa
 * @wait: wait for the application to finish and return status.
 *        when UMH_NO_WAIT don't wait at all, but you get no useful error back
 *        when the program couldn't be exec'ed. This makes it safe to call
 *        from interrupt context.
 *
 * Runs a user-space application.  The application is started
 * asynchronously if wait is not set, and runs as a child of keventd.
 * (ie. it runs with full root capabilities).
 */
static int __call_usermodehelper_exec(struct kthread_worker *worker,
		struct subprocess_info *sub_info, int wait)
{
	DECLARE_COMPLETION_ONSTACK(done);
	int retval = 0;

	helper_lock();
	if (!sub_info->path) {
		retval = -EINVAL;
		goto out;
	}

	if (sub_info->path[0] == '\0')
		goto out;

	if (usermodehelper_disabled) {
		retval = -EBUSY;
		goto out;
	}
	/*
	 * Worker thread must not wait for khelper thread at below
	 * wait_for_completion() if the thread was created with CLONE_VFORK
	 * flag, for khelper thread is already waiting for the thread at
	 * wait_for_completion() in do_fork().
	 */
	if (wait != UMH_NO_WAIT && current == kmod_thread_locker) {
		retval = -EBUSY;
		goto out;
	}

	sub_info->complete = &done;
	sub_info->wait = wait;

	queue_kthread_work(worker, &sub_info->work);
	if (wait == UMH_NO_WAIT)	/* task has freed sub_info */
		goto unlock;

	if (wait & UMH_KILLABLE) {
		retval = wait_for_completion_killable(&done);
		if (!retval)
			goto wait_done;

		/* umh_complete() will see NULL and free sub_info */
		if (xchg(&sub_info->complete, NULL))
			goto unlock;
		/* fallthrough, umh_complete() was already called */
	}

	wait_for_completion(&done);
wait_done:
	retval = sub_info->retval;
out:
	call_usermodehelper_freeinfo(sub_info);
unlock:
	helper_unlock();
	return retval;
}

int call_usermodehelper_exec(struct subprocess_info *sub_info, int wait)
{
	if (!ve_is_super(get_exec_env()))
		return -EPERM;

	return __call_usermodehelper_exec(&khelper_worker, sub_info, wait);
}
EXPORT_SYMBOL(call_usermodehelper_exec);

/**
 * call_usermodehelper() - prepare and start a usermode application
 * @path: path to usermode executable
 * @argv: arg vector for process
 * @envp: environment for process
 * @wait: wait for the application to finish and return status.
 *        when UMH_NO_WAIT don't wait at all, but you get no useful error back
 *        when the program couldn't be exec'ed. This makes it safe to call
 *        from interrupt context.
 *
 * This function is the equivalent to use call_usermodehelper_setup() and
 * call_usermodehelper_exec().
 */
int call_usermodehelper(char *path, char **argv, char **envp, int wait)
{
	return call_usermodehelper_by(&khelper_worker, path, argv, envp,
			wait, NULL, NULL, NULL);
}
EXPORT_SYMBOL(call_usermodehelper);

#ifdef CONFIG_VE
int call_usermodehelper_fns_ve(struct ve_struct *ve,
	char *path, char **argv, char **envp, int wait,
	int (*init)(struct subprocess_info *info, struct cred *new),
	void (*cleanup)(struct subprocess_info *), void *data)
{
	int err;
	struct kthread_worker *khelper;

	ve = get_ve(ve);
	if (!ve)
		return -EFAULT;

	khelper = ve_is_super(ve) ? &khelper_worker : &ve->ve_umh_worker;

	if (ve_is_super(ve) || (get_exec_env() == ve)) {
		err = call_usermodehelper_by(khelper, path, argv, envp, wait, init,
					     cleanup, data);
		goto out_put;
	}

	if (wait > UMH_WAIT_EXEC) {
		printk(KERN_ERR "VE#%s: Sleeping call for containers UMH is "
				"not supported\n", ve->ve_name);
		err = -EINVAL;
		goto out_put;
	}

	down_read(&ve->op_sem);
	err = -EPIPE;
	if (!ve->is_running)
		goto out;

	err = call_usermodehelper_by(khelper, path, argv, envp, wait, init,
				     cleanup, data);

out:
	up_read(&ve->op_sem);
out_put:
	put_ve(ve);
	return err;
}
EXPORT_SYMBOL(call_usermodehelper_fns_ve);
#endif

int call_usermodehelper_by(struct kthread_worker *worker,
	char *path, char **argv, char **envp, int wait,
	int (*init)(struct subprocess_info *info, struct cred *new),
	void (*cleanup)(struct subprocess_info *), void *data)
{
	struct subprocess_info *info;
	gfp_t gfp_mask = (wait == UMH_NO_WAIT) ? GFP_ATOMIC : GFP_KERNEL;

	if (worker == &khelper_worker && !ve_is_super(get_exec_env()))
		return -EPERM;

	info = call_usermodehelper_setup(path, argv, envp, gfp_mask,
					 init, cleanup, data);
	if (info == NULL)
		return -ENOMEM;

	return __call_usermodehelper_exec(worker, info, wait);
}
EXPORT_SYMBOL(call_usermodehelper_by);

static int proc_cap_handler(struct ctl_table *table, int write,
			 void __user *buffer, size_t *lenp, loff_t *ppos)
{
	struct ctl_table t;
	unsigned long cap_array[_KERNEL_CAPABILITY_U32S];
	kernel_cap_t new_cap;
	int err, i;

	if (write && (!capable(CAP_SETPCAP) ||
		      !capable(CAP_SYS_MODULE)))
		return -EPERM;

	/*
	 * convert from the global kernel_cap_t to the ulong array to print to
	 * userspace if this is a read.
	 */
	spin_lock(&umh_sysctl_lock);
	for (i = 0; i < _KERNEL_CAPABILITY_U32S; i++)  {
		if (table->data == CAP_BSET)
			cap_array[i] = usermodehelper_bset.cap[i];
		else if (table->data == CAP_PI)
			cap_array[i] = usermodehelper_inheritable.cap[i];
		else
			BUG();
	}
	spin_unlock(&umh_sysctl_lock);

	t = *table;
	t.data = &cap_array;

	/*
	 * actually read or write and array of ulongs from userspace.  Remember
	 * these are least significant 32 bits first
	 */
	err = proc_doulongvec_minmax(&t, write, buffer, lenp, ppos);
	if (err < 0)
		return err;

	/*
	 * convert from the sysctl array of ulongs to the kernel_cap_t
	 * internal representation
	 */
	for (i = 0; i < _KERNEL_CAPABILITY_U32S; i++)
		new_cap.cap[i] = cap_array[i];

	/*
	 * Drop everything not in the new_cap (but don't add things)
	 */
	spin_lock(&umh_sysctl_lock);
	if (write) {
		if (table->data == CAP_BSET)
			usermodehelper_bset = cap_intersect(usermodehelper_bset, new_cap);
		if (table->data == CAP_PI)
			usermodehelper_inheritable = cap_intersect(usermodehelper_inheritable, new_cap);
	}
	spin_unlock(&umh_sysctl_lock);

	return 0;
}

struct ctl_table usermodehelper_table[] = {
	{
		.procname	= "bset",
		.data		= CAP_BSET,
		.maxlen		= _KERNEL_CAPABILITY_U32S * sizeof(unsigned long),
		.mode		= 0600,
		.proc_handler	= proc_cap_handler,
	},
	{
		.procname	= "inheritable",
		.data		= CAP_PI,
		.maxlen		= _KERNEL_CAPABILITY_U32S * sizeof(unsigned long),
		.mode		= 0600,
		.proc_handler	= proc_cap_handler,
	},
	{ }
};

void __init usermodehelper_init(void)
{
	struct task_struct *t;

	t = kthread_run(kthread_worker_fn, &khelper_worker, "khelper");
	BUG_ON(IS_ERR(t));
}
