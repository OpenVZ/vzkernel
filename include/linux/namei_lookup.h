#ifndef _LINUX_NAMEI_LOOKUP_H
#define _LINUX_NAMEI_LOOKUP_H

/*
 * The bitmask for a lookup event:
 *  - follow links at the end
 *  - require a directory
 *  - ending slashes ok even for nonexistent files
 *  - internal "there are more path components" flag
 *  - dentry cache is untrusted; force a real lookup
 *  - suppress terminal automount
 *  - skip revalidation
 *  - don't fetch xattrs on audit_inode
 */
#define LOOKUP_FOLLOW		0x0001
#define LOOKUP_DIRECTORY	0x0002
#define LOOKUP_AUTOMOUNT	0x0004

#define LOOKUP_PARENT		0x0010
#define LOOKUP_REVAL		0x0020
#define LOOKUP_RCU		0x0040
#define LOOKUP_NO_EVAL		0x0100

/*
 * Intent data
 */
#define LOOKUP_OPEN		0x0100
#define LOOKUP_CREATE		0x0200
#define LOOKUP_EXCL		0x0400
#define LOOKUP_RENAME_TARGET	0x0800

#define LOOKUP_JUMPED		0x1000
#define LOOKUP_ROOT		0x2000
#define LOOKUP_EMPTY		0x4000
#define LOOKUP_DOWN		0x8000

#endif /* _LINUX_NAMEI_LOOKUP_H */
