/*
 * Copyright (c) 2001-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write the Free Software Foundation,
 * Inc.,  51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef __XFS_ACL_H__
#define __XFS_ACL_H__

struct inode;
struct posix_acl;

#ifdef CONFIG_XFS_POSIX_ACL
extern struct posix_acl *xfs_get_acl(struct inode *inode, int type);
extern int xfs_inherit_acl(struct inode *inode, struct posix_acl *default_acl);
extern int xfs_acl_chmod(struct inode *inode);

extern const struct xattr_handler xfs_xattr_acl_access_handler;
extern const struct xattr_handler xfs_xattr_acl_default_handler;
#else
static inline struct posix_acl *xfs_get_acl(struct inode *inode, int type)
{
	return NULL;
}
# define xfs_inherit_acl(inode, default_acl)		0
# define xfs_acl_chmod(inode)				0
#endif /* CONFIG_XFS_POSIX_ACL */

extern void xfs_forget_acl(struct inode *inode, const char *name, int xflags);

#endif	/* __XFS_ACL_H__ */
