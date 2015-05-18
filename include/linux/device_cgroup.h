#include <linux/fs.h>

#ifdef CONFIG_CGROUP_DEVICE
extern int __devcgroup_inode_permission(struct inode *inode, int mask);
extern int devcgroup_inode_mknod(int mode, dev_t dev);
static inline int devcgroup_inode_permission(struct inode *inode, int mask)
{
	if (likely(!inode->i_rdev))
		return 0;
	if (!S_ISBLK(inode->i_mode) && !S_ISCHR(inode->i_mode))
		return 0;
	return __devcgroup_inode_permission(inode, mask);
}

extern int devcgroup_device_permission(umode_t mode, dev_t dev, int mask);
extern int devcgroup_device_visible(umode_t mode, int major,
		int start_minor, int nr_minors);

struct cgroup;
int devcgroup_default_perms_ve(struct cgroup *cgroup);
int devcgroup_set_perms_ve(struct cgroup *cgroup, unsigned, dev_t, unsigned);
struct ve_struct;
int devcgroup_seq_show_ve(struct cgroup *devices_root, struct ve_struct *ve, struct seq_file *m);

#else
static inline int devcgroup_inode_permission(struct inode *inode, int mask)
{ return 0; }
static inline int devcgroup_inode_mknod(int mode, dev_t dev)
{ return 0; }
static inline int devcgroup_device_permission(umode_t mode, dev_t dev, int mask)
{ return 0; }
static inline int devcgroup_device_visible(umode_t mode, int major,
		int start_minor, int nr_minors)
{ return 0; }
#endif
