#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/trace.h>

#include "pcs_types.h"
#include "log.h"

static void _fuse_printk_plugin(unsigned long ip, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	__ftrace_vbprintk(ip, fmt, args);
	va_end(args);
}

static int __init kpcs_printk_mod_init(void)
{
	trace_printk_init_buffers();
	rcu_assign_pointer(fuse_printk_plugin, _fuse_printk_plugin);
	return 0;
}

static void __exit kpcs_printk_mod_exit(void)
{
	rcu_assign_pointer(fuse_printk_plugin, NULL);
	synchronize_rcu();
}

module_init(kpcs_printk_mod_init);
module_exit(kpcs_printk_mod_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Virtuozzo <devel@openvz.org>");
