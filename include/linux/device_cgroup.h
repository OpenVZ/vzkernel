#include <linux/fs.h>

#ifdef CONFIG_CGROUP_DEVICE
extern int __devcgroup_inode_permission(int blk, dev_t device, int mask);
extern int devcgroup_inode_mknod(int mode, dev_t dev);
static inline int devcgroup_inode_permission(struct inode *inode, int mask)
{
	if (likely(!inode->i_rdev))
		return 0;
	if (!S_ISBLK(inode->i_mode) && !S_ISCHR(inode->i_mode))
		return 0;

	return __devcgroup_inode_permission(S_ISBLK(inode->i_mode),
			inode->i_rdev, mask);
}

extern int devcgroup_device_visible(int type, int major,
		int start_minor, int nr_minors);
#else
static inline int devcgroup_inode_permission(struct inode *inode, int mask)
{ return 0; }
static inline int devcgroup_inode_mknod(int mode, dev_t dev)
{ return 0; }
static inline int devcgroup_device_visible(int type, int major,
		int start_minor, int nr_minors)
{ return 0; }
#endif
