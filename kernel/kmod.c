/*
 * kmod - the kernel module loader
 */
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/binfmts.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/workqueue.h>
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
#include <linux/uaccess.h>
#include <linux/ve.h>
#include <linux/sysctl.h>

#include <trace/events/module.h>

/*
 * Assuming:
 *
 * threads = div64_u64((u64) totalram_pages * (u64) PAGE_SIZE,
 *		       (u64) THREAD_SIZE * 8UL);
 *
 * If you need less than 50 threads would mean we're dealing with systems
 * smaller than 3200 pages. This assumes you are capable of having ~13M memory,
 * and this would only be an upper limit, after which the OOM killer would take
 * effect. Systems like these are very unlikely if modules are enabled.
 */
#define MAX_KMOD_CONCURRENT 50
static atomic_t kmod_concurrent_max = ATOMIC_INIT(MAX_KMOD_CONCURRENT);
static DECLARE_WAIT_QUEUE_HEAD(kmod_wq);

/*
 * This is a restriction on having *all* MAX_KMOD_CONCURRENT threads
 * running at the same time without returning. When this happens we
 * believe you've somehow ended up with a recursive module dependency
 * creating a loop.
 *
 * We have no option but to fail.
 *
 * Userspace should proactively try to detect and prevent these.
 */
#define MAX_KMOD_ALL_BUSY_TIMEOUT 5

/*
	modprobe_path is set via /proc/sys.
*/
char modprobe_path[KMOD_PATH_LEN] = CONFIG_MODPROBE_PATH;

static void free_modprobe_argv(struct subprocess_info *info)
{
	kfree(info->argv[4]); /* check call_modprobe() */
	kfree(info->argv);
}

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

	return call_usermodehelper_exec(info, wait | UMH_KILLABLE);

free_module_name:
	kfree(module_name);
free_argv:
	kfree(argv);
out:
	return -ENOMEM;
}

/**
 * __request_module - try to load a kernel module
 * @wait: wait (or not) for the operation to complete
 * @fmt: printf style format string for the name of the module
 * @...: arguments as specified in the format string
 *
 * Load a module using the user mode module loader. The function returns
 * zero on success or a negative errno code or positive exit code from
 * "modprobe" on failure. Note that a successful module load does not mean
 * the module did not then unload and exit on an error of its own. Callers
 * must check that the service they requested is now available not blindly
 * invoke it.
 *
 * If module auto-loading support is disabled then this function
 * simply returns -ENOENT.
 */
int __request_module(bool wait, const char *fmt, ...)
{
	va_list args;
	char module_name[MODULE_NAME_LEN];
	bool blacklist;
	int ret;

	/*
	 * We don't allow synchronous module loading from async.  Module
	 * init may invoke async_synchronize_full() which will end up
	 * waiting for this task which already is waiting for the module
	 * loading to complete, leading to a deadlock.
	 */
	WARN_ON_ONCE(wait && current_is_async());

	if (!modprobe_path[0])
		return -ENOENT;

	va_start(args, fmt);
	ret = vsnprintf(module_name, MODULE_NAME_LEN, fmt, args);
	va_end(args);
	if (ret >= MODULE_NAME_LEN)
		return -ENAMETOOLONG;

	/* Check that autoload is not prohibited using /proc interface */
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

	ret = security_kernel_module_request(module_name);
	if (ret)
		return ret;

	if (atomic_dec_if_positive(&kmod_concurrent_max) < 0) {
		pr_warn_ratelimited("request_module: kmod_concurrent_max (%u) close to 0 (max_modprobes: %u), for module %s, throttling...",
				    atomic_read(&kmod_concurrent_max),
				    MAX_KMOD_CONCURRENT, module_name);
		ret = wait_event_killable_timeout(kmod_wq,
						  atomic_dec_if_positive(&kmod_concurrent_max) >= 0,
						  MAX_KMOD_ALL_BUSY_TIMEOUT * HZ);
		if (!ret) {
			pr_warn_ratelimited("request_module: modprobe %s cannot be processed, kmod busy with %d threads for more than %d seconds now",
					    module_name, MAX_KMOD_CONCURRENT, MAX_KMOD_ALL_BUSY_TIMEOUT);
			return -ETIME;
		} else if (ret == -ERESTARTSYS) {
			pr_warn_ratelimited("request_module: sigkill sent for modprobe %s, giving up", module_name);
			return ret;
		}
	}

	trace_module_request(module_name, wait, _RET_IP_);

	ret = call_modprobe(module_name, wait ? UMH_WAIT_PROC : UMH_WAIT_EXEC, blacklist);

	atomic_inc(&kmod_concurrent_max);
	wake_up(&kmod_wq);

	return ret;
}
EXPORT_SYMBOL(__request_module);

#ifdef CONFIG_VE

/* ve0 allowed modules */
static const char * const ve0_allowed_mod[] = {
	"ip_tables",
	"ip6_tables",
	"iptable_filter",
	"iptable_raw",
	"iptable_nat",
	"iptable_mangle",
	"ip6table_filter",
	"ip6table_raw",
	"ip6table_nat",
	"ip6table_mangle",

	"nf-nat",
	"nf_conncount",
	"nf_defrag_ipv4",
	"nf_defrag_ipv6",
	"nf_dup_ipv4",
	"nf_dup_ipv6",
	"nf_dup_netdev",
	"nf_flow_table",
	"nf-flowtable-1",
	"nf_flow_table_inet",
	"nf_osf",
	"nf_reject_ipv6",
	"nf_socket_ipv4",
	"nf_socket_ipv6",
	"nf_synproxy_core",

	"nft-set",
	"nf_tproxy_ipv4",
	"nf_tproxy_ipv6",

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
	"nfnetlink-subsys-3",		/* NFNL_SUBSYS_QUEUE */

	/* unix_diag */
	"net-pf-16-proto-4-type-1",	/* PF_NETLINK, NETLINK_SOCK_DIAG, AF_LOCAL */

	/* af_packet_diag */
	"net-pf-16-proto-4-type-17",	/* PF_NETLINK, NETLINK_SOCK_DIAG, AF_PACKET */

	/* netlink_diag */
	"net-pf-16-proto-4-type-16",	/* PF_NETLINK, NETLINK_SOCK_DIAG, AF_NETLINK */

	/* ip_set */
	"nfnetlink-subsys-6",		/* NFNL_SUBSYS_IPSET */
	"ip_set_bitmap:ip",
	"ip_set_bitmap:ip,mac",
	"ip_set_bitmap:port",
	"ip_set_hash:ip",
	"ip_set_hash:ip,port",
	"ip_set_hash:ip,port,ip",
	"ip_set_hash:net",
	"ip_set_hash:net,port",
	"ip_set_hash:ip,port,net",
	"ip_set_hash:net,iface",
	"ip_set_list:set",

	"rtnl-link-dummy",
	"rtnl-link-vxlan",

	/* NFS */
	"nfsv3",
	"nfsv4",

	/* IPVS */
	"ip_vs_ftp",
	"ip_vs_nq",
	"ip_vs_wlc",
	"ip6t_ipvs",
	"ipt_ipvs",
	"ip_vs_rr",
	"ip_vs_pe_sip",
	"ip_vs_lblc",
	"ip_vs_wrr",
	"ip_vs_sed",
	"ip_vs_dh",
	"ip_vs_sh",
	"ip_vs_lblcr",
	"ip_vs_lc",

	/* string */
	"ts_kmp",
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

	if (ve_is_super(get_exec_env()))
		return true;

	/* Look for full module name in ve0_allowed_mod table */
	for (i = 0; i < ARRAY_SIZE(ve0_allowed_mod); i++) {
		if (!strcmp(ve0_allowed_mod[i], module))
			return true;
	}

	/* modules allowed by name/alias masks */
	if (!strncmp("xt_",		module,  3) ||
	    !strncmp("ip_conntrack",	module, 12) ||
	    !strncmp("ip_nat_",		module,  7) ||
	    !strncmp("ipt_",		module,  4) ||
	    !strncmp("ip6t_",		module,  5) ||
	    !strncmp("arpt_",		module,  5) ||
	    !strncmp("ebt",		module,  4) ||
	    !strncmp("nft-chain-",	module, 10) ||
	    !strncmp("nft-expr-",	module,  9) ||
	    !strncmp("nf_nat",		module,  6) ||
	    !strncmp("nf_log_",		module,  7) ||
	    !strncmp("nf-logger-",	module, 10) ||
	    !strncmp("nf_conntrack",	module, 12) ||
	    !strncmp("nfct-helper-",	module, 12))
		return true;

	/* nfct-helper-* modules */
	if (!strncmp("nfct-helper-", module, 12))
		return true;

	return false;
}
#endif /* CONFIG_VE */
