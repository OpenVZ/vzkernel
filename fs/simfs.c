#include <linux/fs.h>
#include <linux/module.h>

static struct dentry * sim_fs_mount(struct file_system_type *type, int flags,
				   const char *dev_name, void *data)
{
	return ERR_PTR(-ENODEV);
}

static struct file_system_type sim_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "simfs",
	.mount		= sim_fs_mount,
};

static int __init init_simfs(void)
{
	int err;

	err = register_filesystem(&sim_fs_type);
	if (err)
		return err;

	return 0;
}

static void __exit exit_simfs(void)
{
	unregister_filesystem(&sim_fs_type);
}

MODULE_DESCRIPTION("simfs stub");
MODULE_LICENSE("GPL v2");

module_init(init_simfs);
module_exit(exit_simfs);
