#ifndef _LINUX_PLOOP_COMPAT_H_
#define _LINUX_PLOOP_COMPAT_H_

#include <linux/version.h>

/* Macros to provide compatibility layer for 2.6.18, where bio layer
 * was different
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define DEFINE_BIO_CB(func) \
static int func(struct bio *bio, unsigned int bytes_done, int err) { \
	if (bio->bi_size) return 1;

#define END_BIO_CB(func) return 0; }


#define BIO_ENDIO(_bio, _err)  bio_endio((_bio), (_bio)->bi_size, (_err))

int pagecache_write_begin(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata);
int pagecache_write_end(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata);


#define F_DENTRY(file)	(file)->f_dentry
#define F_MNT(file)	(file)->f_vfsmnt

#define KOBJECT_INIT(_kobj, _ktype) do { \
	(_kobj)->ktype = (_ktype); kobject_init(_kobj); } while (0)

#define KOBJECT_ADD(_kobj, _parent, fmt, arg...) ({ \
	struct kobject * _tmp = (_kobj); \
	_tmp->parent = _parent; \
	snprintf(_tmp->name, KOBJ_NAME_LEN, fmt, arg); \
	kobject_add(_tmp); })

#else

#define DEFINE_BIO_CB(func) \
static void func(struct bio *bio, int err) {

#define END_BIO_CB(func)  }

#define BIO_ENDIO(_queue, _bio, _err)					\
	do {								\
		trace_block_bio_complete((_queue), (_bio), (_err));	\
		bio_endio((_bio), (_err));				\
	} while (0);

#define F_DENTRY(file)	(file)->f_path.dentry
#define F_MNT(file)	(file)->f_path.mnt

#define KOBJECT_INIT(kobj, ktype) kobject_init(kobj, ktype)
#define KOBJECT_ADD(kobj, parent, fmt, arg...) kobject_add(kobj, parent, fmt, arg)

#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
#define FOP_FSYNC(file, datasync) fsync(file, 0, LLONG_MAX, datasync)
#else
#define FOP_FSYNC(file, datasync) fsync(file, F_DENTRY(file), datasync)
#endif

#endif
