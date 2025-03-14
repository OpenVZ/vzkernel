/*
 *  arch/x86/kernel/cpuid_fault.c
 *
 *  Copyright (c) 2010-2015 Parallels IP Holdings GmbH
 *  Copyright (c) 2017-2021 Virtuozzo International GmbH. All rights reserved.
 *
 */

#include <linux/cpuid_override.h>
#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/ratelimit.h>
#include <linux/ve.h>
#include <linux/veowner.h>
#include <asm/uaccess.h>

struct cpuid_override_table __rcu *cpuid_override __read_mostly;
static DEFINE_SPINLOCK(cpuid_override_lock);

static void cpuid_override_info(struct cpuid_override_table  *t)
{
	char buf[128];
	size_t pos;

	if (!t) {
		pr_info_ratelimited("cpuid_override: flushed\n");
		return;
	}

	rcu_read_lock();
	for (pos = 0; pos < t->size; pos++) {
		struct cpuid_override_entry *e = &t->entries[pos];
		if (e->has_count) {
			snprintf(buf, sizeof(buf),
				 "cpuid_override: 0x%08x 0x%08x: "
				 "0x%08x 0x%08x 0x%08x 0x%08x",
				 e->op, e->count, e->eax, e->ebx, e->ecx, e->edx);
		} else {
			snprintf(buf, sizeof(buf),
				 "cpuid_override: 0x%08x: "
				 "0x%08x 0x%08x 0x%08x 0x%08x",
				 e->op, e->eax, e->ebx, e->ecx, e->edx);
		}
		printk(KERN_INFO "%s\n", buf);
	}
	rcu_read_unlock();
}

static void cpuid_override_update(struct cpuid_override_table *new_table)
{
	struct cpuid_override_table *old_table;

	spin_lock(&cpuid_override_lock);
	old_table = rcu_access_pointer(cpuid_override);
	rcu_assign_pointer(cpuid_override, new_table);
	spin_unlock(&cpuid_override_lock);

	cpuid_override_info(new_table);

	if (old_table)
		kfree_rcu(old_table, rcu_head);
}

static bool cpuid_override_match(unsigned int op, unsigned int count,
				 unsigned int *eax, unsigned int *ebx,
				 unsigned int *ecx, unsigned int *edx)
{
	bool ret = false;
	struct cpuid_override_table *t;
	struct cpuid_override_entry *e;
	int i;

	rcu_read_lock();
	t = rcu_dereference(cpuid_override);
	if (!t)
		goto out;

	for (i = 0; i < t->size; i++) {
		e = &t->entries[i];
		if (e->op != op)
			continue;
		if (e->has_count && e->count != count)
			continue;
		*eax = e->eax;
		*ebx = e->ebx;
		*ecx = e->ecx;
		*edx = e->edx;
		ret = true;
		break;
	}
out:
	rcu_read_unlock();
	return ret;
}

void __do_cpuid_fault(unsigned int op, unsigned int count,
		      unsigned int *eax, unsigned int *ebx,
		      unsigned int *ecx, unsigned int *edx)
{
	/* check if op is overridden */
	if (cpuid_override_match(op, count, eax, ebx, ecx, edx))
		return;

	/* fallback to real cpuid */
	cpuid_count(op, count, eax, ebx, ecx, edx);
}

void do_cpuid_fault(struct pt_regs *regs)
{
	unsigned int eax, ebx, ecx, edx;

	__do_cpuid_fault(regs->ax, regs->cx, &eax, &ebx, &ecx, &edx);

	regs->ax = eax;
	regs->bx = ebx;
	regs->cx = ecx;
	regs->dx = edx;
}

/*
 * CPUID override entry format:
 *
 * op[ count]: eax ebx ecx edx
 *
 * All values are in HEX.
 */
static int cpuid_override_entry_parse(const char *s, char **endp,
				      struct cpuid_override_entry *e)
{
	int taken;
	char *end;

	if (sscanf(s, "%x %x: %x %x %x %x%n",
		   &e->op, &e->count, &e->eax, &e->ebx, &e->ecx, &e->edx,
		   &taken) == 6)
		e->has_count = true;
	else if (sscanf(s, "%x: %x %x %x %x%n",
			&e->op, &e->eax, &e->ebx, &e->ecx, &e->edx,
			&taken) == 5)
		e->has_count = false;
	else
		return -EINVAL;

	end = (char *)s + taken;
	if (*end) {
		if (*end != '\n')
			return -EINVAL;
		++end;
	}
	*endp = end;
	return 0;
}

static ssize_t cpuid_override_write(struct file *file, const char __user *buf,
				    size_t count, loff_t *ppos)
{
	struct cpuid_override_table *t = NULL;
	void *page = NULL;
	char *s;
	int err;

	err = -E2BIG;
	if (count >= PAGE_SIZE)
		goto out;

	err = -ENOMEM;
	t = kmalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		goto out;

	page = (void *)__get_free_pages(GFP_KERNEL, 1);
	if (!page)
		goto out;

	err = copy_from_user(page, buf, count);
	if (err)
		goto out;

	s = page;
	s[count] = '\0';
	t->size = 0;
	while (*(s = skip_spaces(s))) {
		err = -E2BIG;
		if (t->size == MAX_CPUID_OVERRIDE_ENTRIES)
			goto out;
		err = -EINVAL;
		if (cpuid_override_entry_parse(s, &s, &t->entries[t->size++]))
			goto out;
	}
	if (!t->size) {
		kfree(t);
		t = NULL;
	}
	err = 0;
out:
	free_pages((unsigned long)page, 1);

	if (!err)
		cpuid_override_update(t);
	else
		kfree(t);

	return err ?: count;
}

static void *__cpuid_override_seq_start(loff_t pos)
{
	struct cpuid_override_table *t = rcu_dereference(cpuid_override);
	return t && pos < t->size ? &t->entries[pos] : NULL;
}

static void *cpuid_override_seq_start(struct seq_file *seq, loff_t *ppos)
{
	rcu_read_lock();
	return __cpuid_override_seq_start(*ppos);
}

static void *cpuid_override_seq_next(struct seq_file *seq,
				     void *v, loff_t *ppos)
{
	++*ppos;
	return __cpuid_override_seq_start(*ppos);
}

static void cpuid_override_seq_stop(struct seq_file *s, void *v)
{
	rcu_read_unlock();
}

static int cpuid_override_seq_show(struct seq_file *s, void *v)
{
	struct cpuid_override_entry *e = v;

	seq_printf(s, "0x%08x", e->op);
	if (e->has_count)
		seq_printf(s, " 0x%08x", e->count);
	seq_printf(s, ": 0x%08x 0x%08x 0x%08x 0x%08x\n",
		   e->eax, e->ebx, e->ecx, e->edx);
	return 0;
}

static struct seq_operations cpuid_override_seq_ops = {
	.start = cpuid_override_seq_start,
	.next  = cpuid_override_seq_next,
	.stop  = cpuid_override_seq_stop,
	.show  = cpuid_override_seq_show,
};

static int cpuid_override_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &cpuid_override_seq_ops);
}

static struct proc_ops proc_cpuid_override_ops = {
	.proc_open    = cpuid_override_seq_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = seq_release,
	.proc_write   = cpuid_override_write,
};

static int __init cpuid_fault_init(void)
{
	struct proc_dir_entry *proc;

	if (!static_cpu_has(X86_FEATURE_CPUID_FAULT))
		return 0;

	proc = proc_create("cpuid_override", 0644, proc_vz_dir,
			   &proc_cpuid_override_ops);
	if (!proc)
		return -ENOMEM;

	return 0;
}
module_init(cpuid_fault_init);
