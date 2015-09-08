/*
 * device_cgroup.c - device cgroup subsystem
 *
 * Copyright 2007 IBM Corp
 */

#include <linux/device_cgroup.h>
#include <linux/cgroup.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <uapi/linux/vzcalluser.h>
#include <linux/major.h>
#include <linux/module.h>
#include <linux/capability.h>
#include <linux/ve.h>

#define ACC_MKNOD 1
#define ACC_READ  2
#define ACC_WRITE 4
#define ACC_QUOTA 8
#define ACC_HIDDEN 16
#define ACC_MOUNT 64
#define ACC_MASK (ACC_MKNOD | ACC_READ | ACC_WRITE | ACC_QUOTA | ACC_MOUNT)

#define DEV_BLOCK 1
#define DEV_CHAR  2
#define DEV_ALL   4  /* this represents all devices */

static DEFINE_MUTEX(devcgroup_mutex);

enum devcg_behavior {
	DEVCG_DEFAULT_NONE,
	DEVCG_DEFAULT_ALLOW,
	DEVCG_DEFAULT_DENY,
};

/*
 * exception list locking rules:
 * hold devcgroup_mutex for update/read.
 * hold rcu_read_lock() for read.
 */

struct dev_exception_item {
	u32 major, minor;
	short type;
	short access;
	struct list_head list;
	struct rcu_head rcu;
};

struct dev_cgroup {
	struct cgroup_subsys_state css;
	struct list_head exceptions;
	enum devcg_behavior behavior;
	/* temporary list for pending propagation operations */
	struct list_head propagate_pending;
};

static inline struct dev_cgroup *css_to_devcgroup(struct cgroup_subsys_state *s)
{
	return container_of(s, struct dev_cgroup, css);
}

static inline struct dev_cgroup *cgroup_to_devcgroup(struct cgroup *cgroup)
{
	return css_to_devcgroup(cgroup_subsys_state(cgroup, devices_subsys_id));
}

static inline struct dev_cgroup *task_devcgroup(struct task_struct *task)
{
	return css_to_devcgroup(task_subsys_state(task, devices_subsys_id));
}

struct cgroup_subsys devices_subsys;

static int devcgroup_can_attach(struct cgroup *new_cgrp,
				struct cgroup_taskset *set)
{
	struct task_struct *task = cgroup_taskset_first(set);

	if (current != task && !ve_capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

/*
 * called under devcgroup_mutex
 */
static int dev_exceptions_copy(struct list_head *dest, struct list_head *orig)
{
	struct dev_exception_item *ex, *tmp, *new;

	lockdep_assert_held(&devcgroup_mutex);

	list_for_each_entry(ex, orig, list) {
		new = kmemdup(ex, sizeof(*ex), GFP_KERNEL);
		if (!new)
			goto free_and_exit;
		list_add_tail(&new->list, dest);
	}

	return 0;

free_and_exit:
	list_for_each_entry_safe(ex, tmp, dest, list) {
		list_del(&ex->list);
		kfree(ex);
	}
	return -ENOMEM;
}

/*
 * called under devcgroup_mutex
 */
static int dev_exception_add(struct dev_cgroup *dev_cgroup,
			     struct dev_exception_item *ex)
{
	struct dev_exception_item *excopy, *walk;

	lockdep_assert_held(&devcgroup_mutex);

	excopy = kmemdup(ex, sizeof(*ex), GFP_KERNEL);
	if (!excopy)
		return -ENOMEM;

	list_for_each_entry(walk, &dev_cgroup->exceptions, list) {
		if (walk->type != ex->type)
			continue;
		if (walk->major != ex->major)
			continue;
		if (walk->minor != ex->minor)
			continue;

		walk->access |= ex->access;
		kfree(excopy);
		excopy = NULL;
	}

	if (excopy != NULL)
		list_add_tail_rcu(&excopy->list, &dev_cgroup->exceptions);
	return 0;
}

/*
 * called under devcgroup_mutex
 */
static void dev_exception_rm(struct dev_cgroup *dev_cgroup,
			     struct dev_exception_item *ex)
{
	struct dev_exception_item *walk, *tmp;

	lockdep_assert_held(&devcgroup_mutex);

	list_for_each_entry_safe(walk, tmp, &dev_cgroup->exceptions, list) {
		if (walk->type != ex->type)
			continue;
		if (walk->major != ex->major)
			continue;
		if (walk->minor != ex->minor)
			continue;

		walk->access &= ~ex->access;
		if (!walk->access) {
			list_del_rcu(&walk->list);
			kfree_rcu(walk, rcu);
		}
	}
}

static void __dev_exception_clean(struct dev_cgroup *dev_cgroup)
{
	struct dev_exception_item *ex, *tmp;

	list_for_each_entry_safe(ex, tmp, &dev_cgroup->exceptions, list) {
		list_del_rcu(&ex->list);
		kfree_rcu(ex, rcu);
	}
}

/**
 * dev_exception_clean - frees all entries of the exception list
 * @dev_cgroup: dev_cgroup with the exception list to be cleaned
 *
 * called under devcgroup_mutex
 */
static void dev_exception_clean(struct dev_cgroup *dev_cgroup)
{
	lockdep_assert_held(&devcgroup_mutex);

	__dev_exception_clean(dev_cgroup);
}

static inline bool is_devcg_online(const struct dev_cgroup *devcg)
{
	return (devcg->behavior != DEVCG_DEFAULT_NONE);
}

/**
 * devcgroup_online - initializes devcgroup's behavior and exceptions based on
 * 		      parent's
 * @cgroup: cgroup getting online
 * returns 0 in case of success, error code otherwise
 */
static int devcgroup_online(struct cgroup *cgroup)
{
	struct dev_cgroup *dev_cgroup, *parent_dev_cgroup = NULL;
	int ret = 0;

	mutex_lock(&devcgroup_mutex);
	dev_cgroup = cgroup_to_devcgroup(cgroup);
	if (cgroup->parent)
		parent_dev_cgroup = cgroup_to_devcgroup(cgroup->parent);

	if (parent_dev_cgroup == NULL)
		dev_cgroup->behavior = DEVCG_DEFAULT_ALLOW;
	else {
		ret = dev_exceptions_copy(&dev_cgroup->exceptions,
					  &parent_dev_cgroup->exceptions);
		if (!ret)
			dev_cgroup->behavior = parent_dev_cgroup->behavior;
	}
	mutex_unlock(&devcgroup_mutex);

	return ret;
}

static void devcgroup_offline(struct cgroup *cgroup)
{
	struct dev_cgroup *dev_cgroup = cgroup_to_devcgroup(cgroup);

	mutex_lock(&devcgroup_mutex);
	dev_cgroup->behavior = DEVCG_DEFAULT_NONE;
	mutex_unlock(&devcgroup_mutex);
}

/*
 * called from kernel/cgroup.c with cgroup_lock() held.
 */
static struct cgroup_subsys_state *devcgroup_css_alloc(struct cgroup *cgroup)
{
	struct dev_cgroup *dev_cgroup;

	dev_cgroup = kzalloc(sizeof(*dev_cgroup), GFP_KERNEL);
	if (!dev_cgroup)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&dev_cgroup->exceptions);
	INIT_LIST_HEAD(&dev_cgroup->propagate_pending);
	dev_cgroup->behavior = DEVCG_DEFAULT_NONE;

	return &dev_cgroup->css;
}

static void devcgroup_css_free(struct cgroup *cgroup)
{
	struct dev_cgroup *dev_cgroup;

	dev_cgroup = cgroup_to_devcgroup(cgroup);
	__dev_exception_clean(dev_cgroup);
	kfree(dev_cgroup);
}

#define DEVCG_ALLOW 1
#define DEVCG_DENY 2
#define DEVCG_LIST 3

#define MAJMINLEN 13
#define ACCLEN 4

static void set_access(char *acc, short access)
{
	int idx = 0;
	memset(acc, 0, ACCLEN);
	if (access & ACC_READ)
		acc[idx++] = 'r';
	if (access & ACC_WRITE)
		acc[idx++] = 'w';
	if (access & ACC_MKNOD)
		acc[idx++] = 'm';
}

static char type_to_char(short type)
{
	if (type == DEV_ALL)
		return 'a';
	if (type == DEV_CHAR)
		return 'c';
	if (type == DEV_BLOCK)
		return 'b';
	return 'X';
}

static void set_majmin(char *str, unsigned m)
{
	if (m == ~0)
		strcpy(str, "*");
	else
		sprintf(str, "%u", m);
}

static int devcgroup_seq_read(struct cgroup *cgroup, struct cftype *cft,
				struct seq_file *m)
{
	struct dev_cgroup *devcgroup = cgroup_to_devcgroup(cgroup);
	struct dev_exception_item *ex;
	char maj[MAJMINLEN], min[MAJMINLEN], acc[ACCLEN];

	rcu_read_lock();
	/*
	 * To preserve the compatibility:
	 * - Only show the "all devices" when the default policy is to allow
	 * - List the exceptions in case the default policy is to deny
	 * This way, the file remains as a "whitelist of devices"
	 */
	if (devcgroup->behavior == DEVCG_DEFAULT_ALLOW) {
		set_access(acc, ACC_MASK);
		set_majmin(maj, ~0);
		set_majmin(min, ~0);
		seq_printf(m, "%c %s:%s %s\n", type_to_char(DEV_ALL),
			   maj, min, acc);
	} else {
		list_for_each_entry_rcu(ex, &devcgroup->exceptions, list) {
			set_access(acc, ex->access);
			set_majmin(maj, ex->major);
			set_majmin(min, ex->minor);
			seq_printf(m, "%c %s:%s %s\n", type_to_char(ex->type),
				   maj, min, acc);
		}
	}
	rcu_read_unlock();

	return 0;
}

/**
 * match_exception	- iterates the exception list trying to match a rule
 * 			  based on type, major, minor and access type. It is
 * 			  considered a match if an exception is found that
 * 			  will contain the entire range of provided parameters.
 * @exceptions: list of exceptions
 * @type: device type (DEV_BLOCK or DEV_CHAR)
 * @major: device file major number, ~0 to match all
 * @minor: device file minor number, ~0 to match all
 * @access: permission mask (ACC_READ, ACC_WRITE, ACC_MKNOD)
 *
 * returns: true in case it matches an exception completely
 */
static bool match_exception(struct list_head *exceptions, short type,
			    u32 major, u32 minor, short access)
{
	struct dev_exception_item *ex;

	list_for_each_entry_rcu(ex, exceptions, list) {
		short mismatched_bits;
		bool allowed_mount;

		if ((type & DEV_BLOCK) && !(ex->type & DEV_BLOCK))
			continue;
		if ((type & DEV_CHAR) && !(ex->type & DEV_CHAR))
			continue;
		if (ex->major != ~0 && ex->major != major)
			continue;
		if (ex->minor != ~0 && ex->minor != minor)
			continue;
		/* provided access cannot have more than the exception rule */
		mismatched_bits = access & (~ex->access) & ~ACC_MOUNT;
		allowed_mount = !(mismatched_bits & ~ACC_WRITE) &&
				(ex->access & ACC_MOUNT) &&
				(access & ACC_MOUNT);

		if (mismatched_bits && !allowed_mount)
			continue;
		return true;
	}
	return false;
}

/**
 * match_exception_partial - iterates the exception list trying to match a rule
 * 			     based on type, major, minor and access type. It is
 * 			     considered a match if an exception's range is
 * 			     found to contain *any* of the devices specified by
 * 			     provided parameters. This is used to make sure no
 * 			     extra access is being granted that is forbidden by
 * 			     any of the exception list.
 * @exceptions: list of exceptions
 * @type: device type (DEV_BLOCK or DEV_CHAR)
 * @major: device file major number, ~0 to match all
 * @minor: device file minor number, ~0 to match all
 * @access: permission mask (ACC_READ, ACC_WRITE, ACC_MKNOD)
 *
 * returns: true in case the provided range mat matches an exception completely
 */
static bool match_exception_partial(struct list_head *exceptions, short type,
				    u32 major, u32 minor, short access)
{
	struct dev_exception_item *ex;

	list_for_each_entry_rcu(ex, exceptions, list) {
		if ((type & DEV_BLOCK) && !(ex->type & DEV_BLOCK))
			continue;
		if ((type & DEV_CHAR) && !(ex->type & DEV_CHAR))
			continue;
		/*
		 * We must be sure that both the exception and the provided
		 * range aren't masking all devices
		 */
		if (ex->major != ~0 && major != ~0 && ex->major != major)
			continue;
		if (ex->minor != ~0 && minor != ~0 && ex->minor != minor)
			continue;
		/*
		 * In order to make sure the provided range isn't matching
		 * an exception, all its access bits shouldn't match the
		 * exception's access bits
		 */
		if (!(access & ex->access))
			continue;
		return true;
	}
	return false;
}

/**
 * verify_new_ex - verifies if a new exception is part of what is allowed
 *		   by a dev cgroup based on the default policy +
 *		   exceptions. This is used to make sure a child cgroup
 *		   won't have more privileges than its parent
 * @dev_cgroup: dev cgroup to be tested against
 * @refex: new exception
 * @behavior: behavior of the exception's dev_cgroup
 */
static bool verify_new_ex(struct dev_cgroup *dev_cgroup,
		          struct dev_exception_item *refex,
		          enum devcg_behavior behavior)
{
	bool match = false;

	rcu_lockdep_assert(rcu_read_lock_held() ||
			   lockdep_is_held(&devcgroup_mutex),
			   "device_cgroup:verify_new_ex called without proper synchronization");

	if (dev_cgroup->behavior == DEVCG_DEFAULT_ALLOW) {
		if (behavior == DEVCG_DEFAULT_ALLOW) {
			/*
			 * new exception in the child doesn't matter, only
			 * adding extra restrictions
			 */ 
			return true;
		} else {
			/*
			 * new exception in the child will add more devices
			 * that can be acessed, so it can't match any of
			 * parent's exceptions, even slightly
			 */ 
			match = match_exception_partial(&dev_cgroup->exceptions,
							refex->type,
							refex->major,
							refex->minor,
							refex->access);

			if (match)
				return false;
			return true;
		}
	} else {
		/*
		 * Only behavior == DEVCG_DEFAULT_DENY allowed here, therefore
		 * the new exception will add access to more devices and must
		 * be contained completely in an parent's exception to be
		 * allowed
		 */
		match = match_exception(&dev_cgroup->exceptions, refex->type,
					refex->major, refex->minor,
					refex->access);

		if (match)
			/* parent has an exception that matches the proposed */
			return true;
		else
			return false;
	}
	return false;
}

/*
 * parent_has_perm:
 * when adding a new allow rule to a device exception list, the rule
 * must be allowed in the parent device
 */
static int parent_has_perm(struct dev_cgroup *childcg,
				  struct dev_exception_item *ex)
{
	struct cgroup *pcg = childcg->css.cgroup->parent;
	struct dev_cgroup *parent;

	if (!pcg)
		return 1;
	parent = cgroup_to_devcgroup(pcg);
	return verify_new_ex(parent, ex, childcg->behavior);
}

/*
 * parent_allows_removal - check if the parent cgroup allows an exception to
 *			   be removed
 * @childcg: child cgroup from where the exception will be removed
 * @ex: exception being removed
 */
static bool parent_allows_removal(struct dev_cgroup *childcg,
				  struct dev_exception_item *ex)
{
	struct cgroup *pcg = childcg->css.cgroup->parent;
	struct dev_cgroup *parent;

	if (!pcg)
		return true;
	parent = cgroup_to_devcgroup(pcg);

	if (childcg->behavior == DEVCG_DEFAULT_DENY)
		/* It's always allowed to remove access to devices */
		return true;

	/*
	 * Make sure you're not removing part or a whole exception existing in
	 * the parent cgroup
	 */
	return !match_exception_partial(&parent->exceptions, ex->type,
					ex->major, ex->minor, ex->access);
}

/**
 * may_allow_all - checks if it's possible to change the behavior to
 *		   allow based on parent's rules.
 * @parent: device cgroup's parent
 * returns: != 0 in case it's allowed, 0 otherwise
 */
static inline int may_allow_all(struct dev_cgroup *parent)
{
	if (!parent)
		return 1;
	return parent->behavior == DEVCG_DEFAULT_ALLOW;
}

/**
 * revalidate_active_exceptions - walks through the active exception list and
 * 				  revalidates the exceptions based on parent's
 * 				  behavior and exceptions. The exceptions that
 * 				  are no longer valid will be removed.
 * 				  Called with devcgroup_mutex held.
 * @devcg: cgroup which exceptions will be checked
 *
 * This is one of the three key functions for hierarchy implementation.
 * This function is responsible for re-evaluating all the cgroup's active
 * exceptions due to a parent's exception change.
 * Refer to Documentation/cgroups/devices.txt for more details.
 */
static void revalidate_active_exceptions(struct dev_cgroup *devcg)
{
	struct dev_exception_item *ex;
	struct list_head *this, *tmp;

	list_for_each_safe(this, tmp, &devcg->exceptions) {
		ex = container_of(this, struct dev_exception_item, list);
		if (!parent_has_perm(devcg, ex))
			dev_exception_rm(devcg, ex);
	}
}

/**
 * get_online_devcg - walks the cgroup tree and fills a list with the online
 * 		      groups
 * @root: cgroup used as starting point
 * @online: list that will be filled with online groups
 *
 * Must be called with devcgroup_mutex held. Grabs RCU lock.
 * Because devcgroup_mutex is held, no devcg will become online or offline
 * during the tree walk (see devcgroup_online, devcgroup_offline)
 * A separated list is needed because propagate_behavior() and
 * propagate_exception() need to allocate memory and can block.
 */
static void get_online_devcg(struct cgroup *root, struct list_head *online)
{
	struct cgroup *pos;
	struct dev_cgroup *devcg;

	lockdep_assert_held(&devcgroup_mutex);

	rcu_read_lock();
	cgroup_for_each_descendant_pre(pos, root) {
		devcg = cgroup_to_devcgroup(pos);
		if (is_devcg_online(devcg))
			list_add_tail(&devcg->propagate_pending, online);
	}
	rcu_read_unlock();
}

/**
 * propagate_exception - propagates a new exception to the children
 * @devcg_root: device cgroup that added a new exception
 * @ex: new exception to be propagated
 *
 * returns: 0 in case of success, != 0 in case of error
 */
static int propagate_exception(struct dev_cgroup *devcg_root,
			       struct dev_exception_item *ex)
{
	struct cgroup *root = devcg_root->css.cgroup;
	struct dev_cgroup *devcg, *parent, *tmp;
	int rc = 0;
	LIST_HEAD(pending);

	get_online_devcg(root, &pending);

	list_for_each_entry_safe(devcg, tmp, &pending, propagate_pending) {
		parent = cgroup_to_devcgroup(devcg->css.cgroup->parent);

		/*
		 * in case both root's behavior and devcg is allow, a new
		 * restriction means adding to the exception list
		 */
		if (devcg_root->behavior == DEVCG_DEFAULT_ALLOW &&
		    devcg->behavior == DEVCG_DEFAULT_ALLOW) {
			rc = dev_exception_add(devcg, ex);
			if (rc)
				break;
		} else {
			/*
			 * in the other possible cases:
			 * root's behavior: allow, devcg's: deny
			 * root's behavior: deny, devcg's: deny
			 * the exception will be removed
			 */
			dev_exception_rm(devcg, ex);
		}
		revalidate_active_exceptions(devcg);

		list_del_init(&devcg->propagate_pending);
	}
	return rc;
}

static inline bool has_children(struct dev_cgroup *devcgroup)
{
	struct cgroup *cgrp = devcgroup->css.cgroup;

	return !list_empty(&cgrp->children);
}

/*
 * Modify the exception list using allow/deny rules.
 * CAP_SYS_ADMIN is needed for this.  It's at least separate from CAP_MKNOD
 * so we can give a container CAP_MKNOD to let it create devices but not
 * modify the exception list.
 * It seems likely we'll want to add a CAP_CONTAINER capability to allow
 * us to also grant CAP_SYS_ADMIN to containers without giving away the
 * device exception list controls, but for now we'll stick with CAP_SYS_ADMIN
 *
 * Taking rules away is always allowed (given CAP_SYS_ADMIN).  Granting
 * new access is only allowed if you're in the top-level cgroup, or your
 * parent cgroup has the access you're asking for.
 */
static int devcgroup_update_access(struct dev_cgroup *devcgroup,
				   int filetype, const char *buffer)
{
	const char *b;
	char temp[12];		/* 11 + 1 characters needed for a u32 */
	int count, rc = 0;
	struct dev_exception_item ex;
	struct cgroup *p = devcgroup->css.cgroup;
	struct dev_cgroup *parent = NULL;

	if (!ve_capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (p->parent)
		parent = cgroup_to_devcgroup(p->parent);

	memset(&ex, 0, sizeof(ex));
	b = buffer;

	switch (*b) {
	case 'a':
		switch (filetype) {
		case DEVCG_ALLOW:
			if (has_children(devcgroup))
				return -EINVAL;

			if (!may_allow_all(parent))
				return -EPERM;
			dev_exception_clean(devcgroup);
			devcgroup->behavior = DEVCG_DEFAULT_ALLOW;
			if (!parent)
				break;

			rc = dev_exceptions_copy(&devcgroup->exceptions,
						 &parent->exceptions);
			if (rc)
				return rc;
			break;
		case DEVCG_DENY:
			if (has_children(devcgroup))
				return -EINVAL;

			dev_exception_clean(devcgroup);
			devcgroup->behavior = DEVCG_DEFAULT_DENY;
			break;
		default:
			return -EINVAL;
		}
		return 0;
	case 'b':
		ex.type = DEV_BLOCK;
		break;
	case 'c':
		ex.type = DEV_CHAR;
		break;
	default:
		return -EINVAL;
	}
	b++;
	if (!isspace(*b))
		return -EINVAL;
	b++;
	if (*b == '*') {
		ex.major = ~0;
		b++;
	} else if (isdigit(*b)) {
		memset(temp, 0, sizeof(temp));
		for (count = 0; count < sizeof(temp) - 1; count++) {
			temp[count] = *b;
			b++;
			if (!isdigit(*b))
				break;
		}
		rc = kstrtou32(temp, 10, &ex.major);
		if (rc)
			return -EINVAL;
	} else {
		return -EINVAL;
	}
	if (*b != ':')
		return -EINVAL;
	b++;

	/* read minor */
	if (*b == '*') {
		ex.minor = ~0;
		b++;
	} else if (isdigit(*b)) {
		memset(temp, 0, sizeof(temp));
		for (count = 0; count < sizeof(temp) - 1; count++) {
			temp[count] = *b;
			b++;
			if (!isdigit(*b))
				break;
		}
		rc = kstrtou32(temp, 10, &ex.minor);
		if (rc)
			return -EINVAL;
	} else {
		return -EINVAL;
	}
	if (!isspace(*b))
		return -EINVAL;
	for (b++, count = 0; count < 3; count++, b++) {
		switch (*b) {
		case 'r':
			ex.access |= ACC_READ;
			break;
		case 'w':
			ex.access |= ACC_WRITE;
			break;
		case 'm':
			ex.access |= ACC_MKNOD;
			break;
		case '\n':
		case '\0':
			count = 3;
			break;
		default:
			return -EINVAL;
		}
	}

	switch (filetype) {
	case DEVCG_ALLOW:
		/*
		 * If the default policy is to allow by default, try to remove
		 * an matching exception instead. And be silent about it: we
		 * don't want to break compatibility
		 */
		if (devcgroup->behavior == DEVCG_DEFAULT_ALLOW) {
			/* Check if the parent allows removing it first */
			if (!parent_allows_removal(devcgroup, &ex))
				return -EPERM;
			dev_exception_rm(devcgroup, &ex);
			break;
		}

		if (!parent_has_perm(devcgroup, &ex))
			return -EPERM;
		rc = dev_exception_add(devcgroup, &ex);
		break;
	case DEVCG_DENY:
		/*
		 * If the default policy is to deny by default, try to remove
		 * an matching exception instead. And be silent about it: we
		 * don't want to break compatibility
		 */
		if (devcgroup->behavior == DEVCG_DEFAULT_DENY)
			dev_exception_rm(devcgroup, &ex);
		else
			rc = dev_exception_add(devcgroup, &ex);

		if (rc)
			break;
		/* we only propagate new restrictions */
		rc = propagate_exception(devcgroup, &ex);
		break;
	default:
		rc = -EINVAL;
	}
	return rc;
}

static int devcgroup_access_write(struct cgroup *cgrp, struct cftype *cft,
				  const char *buffer)
{
	int retval;

	mutex_lock(&devcgroup_mutex);
	retval = devcgroup_update_access(cgroup_to_devcgroup(cgrp),
					 cft->private, buffer);
	mutex_unlock(&devcgroup_mutex);
	return retval;
}

static struct cftype dev_cgroup_files[] = {
	{
		.name = "allow",
		.write_string  = devcgroup_access_write,
		.private = DEVCG_ALLOW,
	},
	{
		.name = "deny",
		.write_string = devcgroup_access_write,
		.private = DEVCG_DENY,
	},
	{
		.name = "list",
		.read_seq_string = devcgroup_seq_read,
		.private = DEVCG_LIST,
	},
	{ }	/* terminate */
};

struct cgroup_subsys devices_subsys = {
	.name = "devices",
	.can_attach = devcgroup_can_attach,
	.css_alloc = devcgroup_css_alloc,
	.css_free = devcgroup_css_free,
	.css_online = devcgroup_online,
	.css_offline = devcgroup_offline,
	.subsys_id = devices_subsys_id,
	.base_cftypes = dev_cgroup_files,
};

/**
 * __devcgroup_check_permission - checks if an inode operation is permitted
 * @dev_cgroup: the dev cgroup to be tested against
 * @type: device type
 * @major: device major number
 * @minor: device minor number
 * @access: combination of ACC_WRITE, ACC_READ and ACC_MKNOD
 *
 * returns 0 on success, -EPERM case the operation is not permitted
 */
static int __devcgroup_check_permission(short type, u32 major, u32 minor,
				        short access)
{
	struct dev_cgroup *dev_cgroup;
	bool rc;

	rcu_read_lock();
	dev_cgroup = task_devcgroup(current);
	if (dev_cgroup->behavior == DEVCG_DEFAULT_ALLOW)
		/* Can't match any of the exceptions, even partially */
		rc = !match_exception_partial(&dev_cgroup->exceptions,
					      type, major, minor, access);
	else
		/* Need to match completely one exception to be allowed */
		rc = match_exception(&dev_cgroup->exceptions, type, major,
				     minor, access);
	rcu_read_unlock();

	if (!rc)
		return -EPERM;

	return 0;
}

int __devcgroup_inode_permission(struct inode *inode, int mask)
{
	short type, access = 0;

	if (S_ISBLK(inode->i_mode))
		type = DEV_BLOCK;
	if (S_ISCHR(inode->i_mode))
		type = DEV_CHAR;
	if (mask & MAY_WRITE)
		access |= ACC_WRITE;
	if (mask & MAY_READ)
		access |= ACC_READ;
	if (mask & MAY_QUOTACTL)
		access |= ACC_QUOTA;
	if (mask & MAY_MOUNT)
		access |= ACC_MOUNT;

	return __devcgroup_check_permission(type, imajor(inode), iminor(inode),
			access);
}

int devcgroup_device_permission(umode_t mode, dev_t dev, int mask)
{
	short type, access = 0;

	if (S_ISBLK(mode))
		type = DEV_BLOCK;
	if (S_ISCHR(mode))
		type = DEV_CHAR;
	if (mask & MAY_WRITE)
		access |= ACC_WRITE;
	if (mask & MAY_READ)
		access |= ACC_READ;
	if (mask & MAY_QUOTACTL)
		access |= ACC_QUOTA;

	return __devcgroup_check_permission(type, MAJOR(dev), MINOR(dev), access);
}

int devcgroup_device_visible(umode_t mode, int major, int start_minor, int nr_minors)
{
	struct dev_cgroup *dev_cgroup;
	struct dev_exception_item *ex;
	short access = ACC_READ | ACC_WRITE | ACC_QUOTA;
	bool match = false;

	rcu_read_lock();
	dev_cgroup = task_devcgroup(current);

	if (dev_cgroup->behavior == DEVCG_DEFAULT_ALLOW) {
		match = true;
		goto out;
	}

	list_for_each_entry_rcu(ex, &dev_cgroup->exceptions, list) {
		if ((ex->type & DEV_BLOCK) && !S_ISBLK(mode))
			continue;
		if ((ex->type & DEV_CHAR) && !S_ISCHR(mode))
			continue;
		if (ex->major != ~0 && ex->major != major)
			continue;
		if (ex->minor != ~0 && (ex->minor < start_minor ||
					ex->minor >= start_minor + nr_minors))
			continue;
		if (!(access & ex->access))
			continue;
		match = true;
		break;
	}
out:
	rcu_read_unlock();
	return match;
}

int devcgroup_inode_mknod(int mode, dev_t dev)
{
	short type;

	if (!S_ISBLK(mode) && !S_ISCHR(mode))
		return 0;

	if (S_ISBLK(mode))
		type = DEV_BLOCK;
	else
		type = DEV_CHAR;

	return __devcgroup_check_permission(type, MAJOR(dev), MINOR(dev),
			ACC_MKNOD);

}

#ifdef CONFIG_VE

static struct dev_exception_item default_whitelist_items[] = {
	{ ~0,				~0,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD },
	{ ~0,				~0,	DEV_BLOCK,	ACC_HIDDEN | ACC_MKNOD },
	{ UNIX98_PTY_MASTER_MAJOR,	~0,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD | ACC_READ | ACC_WRITE },
	{ UNIX98_PTY_SLAVE_MAJOR,	~0,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD | ACC_READ | ACC_WRITE },
	{ PTY_MASTER_MAJOR,		~0,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD | ACC_READ | ACC_WRITE },
	{ PTY_SLAVE_MAJOR,		~0,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD | ACC_READ | ACC_WRITE },
	{ MEM_MAJOR,			3,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD | ACC_READ | ACC_WRITE }, /* null */
	{ MEM_MAJOR,			5,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD | ACC_READ | ACC_WRITE }, /* zero */
	{ MEM_MAJOR,			7,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD | ACC_READ | ACC_WRITE }, /* full */
	{ TTYAUX_MAJOR,			0,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD | ACC_READ | ACC_WRITE }, /* tty */
	{ TTYAUX_MAJOR,			1,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD | ACC_READ | ACC_WRITE }, /* console */
	{ TTYAUX_MAJOR,			2,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD | ACC_READ | ACC_WRITE }, /* ptmx */
	{ MEM_MAJOR,			8,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD | ACC_READ | ACC_WRITE }, /* random */
	{ MEM_MAJOR,			9,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD | ACC_READ | ACC_WRITE }, /* urandom */
	{ MEM_MAJOR,			11,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD | ACC_WRITE },            /* kmsg */
	{ MISC_MAJOR,			200,	DEV_CHAR,	ACC_HIDDEN | ACC_MKNOD | ACC_READ | ACC_WRITE }, /* tun */
};

static LIST_HEAD(default_whitelist);

int devcgroup_default_perms_ve(struct cgroup *cgroup)
{
	struct dev_cgroup *dev_cgroup = cgroup_to_devcgroup(cgroup);
	struct dev_exception_item *wl, *tmp;
	int i, err;

	mutex_lock(&devcgroup_mutex);
	if (list_empty(&default_whitelist)) {
		for (i = 0; i < ARRAY_SIZE(default_whitelist_items); i++)
			list_add_tail(&default_whitelist_items[i].list,
					&default_whitelist);
	}
	list_for_each_entry_safe(wl, tmp, &dev_cgroup->exceptions, list) {
		wl->access = 0;
		list_del_rcu(&wl->list);
		kfree_rcu(wl, rcu);
	}
	err = dev_exceptions_copy(&dev_cgroup->exceptions, &default_whitelist);
	dev_cgroup->behavior = DEVCG_DEFAULT_DENY;
	mutex_unlock(&devcgroup_mutex);

	return err;
}
EXPORT_SYMBOL(devcgroup_default_perms_ve);

static unsigned decode_ve_perms(unsigned perm)
{
	unsigned mask = 0;

	if (perm & S_IROTH)
		mask |= ACC_READ;
	if (perm & S_IWOTH)
		mask |= ACC_WRITE;
	if (perm & S_IXGRP)
		mask |= ACC_QUOTA;
	if (perm & S_IXUSR)
		mask |= ACC_MOUNT;

	return mask;
}

static unsigned encode_ve_perms(unsigned mask)
{
	unsigned perm = 0;

	if (mask & ACC_READ)
		perm |= S_IROTH;
	if (mask & ACC_WRITE)
		perm |= S_IWOTH;
	if (mask & ACC_QUOTA)
		perm |= S_IXGRP;
	if (mask & ACC_MOUNT)
		perm |= S_IXUSR;

	return perm;
}

int devcgroup_set_perms_ve(struct cgroup *cgroup,
		unsigned type, dev_t dev, unsigned mask)
{
	int err = -EINVAL;
	struct dev_exception_item new;

	if ((type & S_IFMT) == S_IFBLK)
		new.type = DEV_BLOCK;
	else if ((type & S_IFMT) == S_IFCHR)
		new.type = DEV_CHAR;
	else
		return -EINVAL;

	new.access = decode_ve_perms(mask) | (mask ? ACC_MKNOD : 0);
	new.major = new.minor = ~0;

	switch (type & VE_USE_MASK) {
	default:
		new.minor = MINOR(dev);
	case VE_USE_MAJOR:
		new.major = MAJOR(dev);
	case 0:
		;
	}

	mutex_lock(&devcgroup_mutex);
	err = dev_exception_add(cgroup_to_devcgroup(cgroup), &new);
	mutex_unlock(&devcgroup_mutex);

	return err;
}
EXPORT_SYMBOL(devcgroup_set_perms_ve);

int devcgroup_seq_show_ve(struct cgroup *devices_root, struct ve_struct *ve, struct seq_file *m)
{
	struct dev_exception_item *wh;
	struct dev_cgroup *devcgroup;
	struct cgroup *cgroup;

	cgroup = cgroup_kernel_open(devices_root, 0, ve_name(ve));
	if (IS_ERR(cgroup))
		return PTR_ERR(cgroup);
	devcgroup = cgroup_to_devcgroup(cgroup);

	rcu_read_lock();
	list_for_each_entry_rcu(wh, &devcgroup->exceptions, list) {
		char maj[MAJMINLEN], min[MAJMINLEN];
		unsigned perm;

		if (wh->access & ACC_HIDDEN)
			continue;

		set_majmin(maj, wh->major);
		set_majmin(min, wh->minor);

		perm = encode_ve_perms(wh->access);
		if (perm & (S_IROTH | S_IWOTH))
			perm |= S_IXOTH;

		seq_printf(m, "%10u %c %03o %s:%s\n",
				ve->veid,
				type_to_char(wh->type),
				perm, maj, min);
	}
	rcu_read_unlock();

	cgroup_kernel_close(cgroup);
	return 0;
}
EXPORT_SYMBOL(devcgroup_seq_show_ve);

#endif /* CONFIG_VE */
