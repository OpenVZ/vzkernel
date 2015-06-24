/*
 *  Copyright (C) 2004 IBM Corporation
 *
 *  Author: Serge Hallyn <serue@us.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation, version 2 of the
 *  License.
 */

#include <linux/export.h>
#include <linux/uts.h>
#include <linux/utsname.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/user_namespace.h>
#include <linux/proc_ns.h>

static struct ucounts *inc_uts_namespaces(struct user_namespace *ns)
{
	return inc_ucount(ns, current_euid(), UCOUNT_UTS_NAMESPACES);
}

static void dec_uts_namespaces(struct ucounts *ucounts)
{
	dec_ucount(ucounts, UCOUNT_UTS_NAMESPACES);
}

static struct uts_namespace *create_uts_ns(void)
{
	struct uts_namespace *uts_ns;

	uts_ns = kmalloc(sizeof(struct uts_namespace), GFP_KERNEL);
	if (uts_ns) {
#ifdef CONFIG_X86
		memset(&uts_ns->vdso, 0, sizeof(uts_ns->vdso));
#endif
		kref_init(&uts_ns->kref);
	}
	return uts_ns;
}

/*
 * Clone a new ns copying an original utsname, setting refcount to 1
 * @old_ns: namespace to clone
 * Return ERR_PTR(-ENOMEM) on error (failure to kmalloc), new ns otherwise
 */
static struct uts_namespace *clone_uts_ns(struct user_namespace *user_ns,
					  struct uts_namespace *old_ns)
{
	struct uts_namespace *ns;
	struct ucounts *ucounts;
	int err;

	err = -ENOSPC;
	ucounts = inc_uts_namespaces(user_ns);
	if (!ucounts)
		goto fail;

	err = -ENOMEM;
	ns = create_uts_ns();
	if (!ns)
		goto fail_dec;

	err = proc_alloc_inum(&ns->proc_inum);
	if (err)
		goto fail_free;

	ns->ucounts = ucounts;

	down_read(&uts_sem);
	memcpy(&ns->name, &old_ns->name, sizeof(ns->name));
	ns->user_ns = get_user_ns(user_ns);
	up_read(&uts_sem);
	return ns;

fail_free:
	kfree(ns);
fail_dec:
	dec_uts_namespaces(ucounts);
fail:
	return ERR_PTR(err);
}

/*
 * Copy task tsk's utsname namespace, or clone it if flags
 * specifies CLONE_NEWUTS.  In latter case, changes to the
 * utsname of this process won't be seen by parent, and vice
 * versa.
 */
struct uts_namespace *copy_utsname(unsigned long flags,
	struct user_namespace *user_ns, struct uts_namespace *old_ns)
{
	struct uts_namespace *new_ns;

	BUG_ON(!old_ns);
	get_uts_ns(old_ns);

	if (!(flags & CLONE_NEWUTS))
		return old_ns;

	new_ns = clone_uts_ns(user_ns, old_ns);

	put_uts_ns(old_ns);
	return new_ns;
}

void free_uts_ns(struct kref *kref)
{
	struct uts_namespace *ns;

	ns = container_of(kref, struct uts_namespace, kref);
	dec_uts_namespaces(ns->ucounts);
	put_user_ns(ns->user_ns);
	proc_free_inum(ns->proc_inum);
#ifdef CONFIG_X86
	if (ns->vdso.pages) {
		int i;
		vunmap(ns->vdso.addr);
		for (i = 0; i < ns->vdso.nr_pages; i++)
			put_page(ns->vdso.pages[i]);
		kfree(ns->vdso.pages);
	}
#endif
	kfree(ns);
}

static void *utsns_get(struct task_struct *task)
{
	struct uts_namespace *ns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy) {
		ns = nsproxy->uts_ns;
		get_uts_ns(ns);
	}
	task_unlock(task);

	return ns;
}

static void utsns_put(void *ns)
{
	put_uts_ns(ns);
}

static int utsns_install(struct nsproxy *nsproxy, void *new)
{
	struct uts_namespace *ns = new;

	if (!ns_capable(ns->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
		return -EPERM;

	get_uts_ns(ns);
	put_uts_ns(nsproxy->uts_ns);
	nsproxy->uts_ns = ns;
	return 0;
}

static unsigned int utsns_inum(void *vp)
{
	struct uts_namespace *ns = vp;

	return ns->proc_inum;
}

const struct proc_ns_operations utsns_operations = {
	.name		= "uts",
	.type		= CLONE_NEWUTS,
	.get		= utsns_get,
	.put		= utsns_put,
	.install	= utsns_install,
	.inum		= utsns_inum,
};
