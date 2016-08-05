/*
 * Copyright (C) 2014 Anna Schumaker.
 *
 * NFSv3-specific filesystem definitions and declarations
 */
#ifndef __LINUX_FS_NFS_NFS3_FS_H
#define __LINUX_FS_NFS_NFS3_FS_H

/*
 * nfs3acl.c
 */
#ifdef CONFIG_NFS_V3_ACL
extern ssize_t nfs3_listxattr(struct dentry *, char *, size_t);
extern ssize_t nfs3_getxattr(struct dentry *, const char *, void *, size_t);
extern int nfs3_setxattr(struct dentry *, const char *,
            const void *, size_t, int);
			extern int nfs3_removexattr (struct dentry *, const char *name);

extern struct posix_acl *nfs3_get_acl(struct inode *inode, int type);
extern struct posix_acl *nfs3_proc_getacl(struct inode *inode, int type);
extern int nfs3_set_acl(struct inode *inode, struct posix_acl *acl, int type);
extern ssize_t nfs3_listxattr(struct dentry *, char *, size_t);
extern const struct xattr_handler *nfs3_xattr_handlers[];
extern int nfs3_proc_set_default_acl(struct inode *dir, struct inode *inode,
               umode_t mode);
extern void nfs3_forget_cached_acls(struct inode *inode);
extern int nfs3_proc_setacl(struct inode *inode, int type, struct posix_acl *acl);
#else
static inline int nfs3_proc_set_default_acl(struct inode *dir,
                                           struct inode *inode,
                                           umode_t mode)
{
       return 0;
}
static inline void nfs3_forget_cached_acls(struct inode *inode)
{
}
static inline int nfs3_proc_setacl(struct inode *inode, int type, struct posix_acl *acl)
{
	return 0;
}
#define nfs3_listxattr NULL
#define nfs3_getxattr NULL
#define nfs3_setxattr NULL
#define nfs3_removexattr NULL

#endif /* CONFIG_NFS_V3_ACL */

/* nfs3client.c */
struct nfs_server *nfs3_create_server(struct nfs_mount_info *, struct nfs_subversion *);
struct nfs_server *nfs3_clone_server(struct nfs_server *, struct nfs_fh *,
				     struct nfs_fattr *, rpc_authflavor_t);

/* nfs3super.c */
extern struct nfs_subversion nfs_v3;

#endif /* __LINUX_FS_NFS_NFS3_FS_H */
