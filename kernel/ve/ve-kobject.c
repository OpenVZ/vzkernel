#include <linux/ve.h>
#include <linux/kobject_ns.h>

static const struct kobj_ns_type_operations *ve_child_ns_type(struct kobject *kobj)
{
	return &ve_ns_type_operations;
}

static void ve_kobj_release(struct kobject *kobj)
{
	kfree(kobj);
}

static struct kobj_type ve_kobj_ktype = {
	.release	= ve_kobj_release,
	.sysfs_ops	= &kobj_sysfs_ops,
	.child_ns_type	= ve_child_ns_type,
};

struct kobject *kobject_create_and_add_ve(const char *name, struct kobject *parent)
{
	struct kobject *kobj;
	int retval;

	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	if (!kobj)
		return NULL;

	kobject_init(kobj, &ve_kobj_ktype);

	retval = kobject_add(kobj, parent, "%s", name);
	if (retval) {
		printk(KERN_WARNING "%s: kobject_add error: %d\n",
		       __func__, retval);
		kobject_put(kobj);
		kobj = NULL;
	}
	return kobj;
}


