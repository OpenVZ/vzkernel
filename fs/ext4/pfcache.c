/*
 * linux/fs/ext4/pfcache.c
 *
 * Automatic SHA-1 (FIPS 180-1) data checksummig
 *
 * Copyright (C) 2013 Parallels, inc.
 *
 * Author: Konstantin Khlebnikov
 *
 */

#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/cryptohash.h>
#include <linux/namei.h>
#include <linux/exportfs.h>
#include <linux/init_task.h>	/* for init_cred */
#include <linux/memcontrol.h>
#include "ext4.h"
#include "xattr.h"
#include "../internal.h"

#define PFCACHE_MAX_PATH	(EXT4_DATA_CSUM_SIZE * 2 + 2)
static void pfcache_path(struct inode *inode, char *path)
{
	char *p;
	int i;

	/* like .git/objects hex[0]/hex[1..] */
	p = pack_hex_byte(path, EXT4_I(inode)->i_data_csum[0]);
	*p++ = '/';
	for ( i = 1 ; i < EXT4_DATA_CSUM_SIZE ; i++ )
		p = pack_hex_byte(p, EXT4_I(inode)->i_data_csum[i]);
	*p = 0;
}

/* require inode->i_mutex held or unreachable inode */
int ext4_open_pfcache(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	const struct cred *cur_cred;
	char name[PFCACHE_MAX_PATH];
	struct path root, path;
	int ret;

	if (inode->i_mapping->i_peer_file)
		return -EBUSY;

	if (!(ext4_test_inode_state(inode, EXT4_STATE_PFCACHE_CSUM) &&
	      EXT4_I(inode)->i_data_csum_end < 0))
		return -ENODATA;

	if (!EXT4_SB(sb)->s_pfcache_root.mnt)
		return -ENODEV;

	spin_lock(&EXT4_SB(sb)->s_pfcache_lock);
	root = EXT4_SB(sb)->s_pfcache_root;
	path_get(&root);
	spin_unlock(&EXT4_SB(sb)->s_pfcache_lock);

	if (!root.mnt)
		return -ENODEV;

	pfcache_path(inode, name);

	/*
	 * Lookups over shared area shouldn't be accounted to any particular
	 * memory cgroup, otherwise a cgroup can be pinned for indefinitely
	 * long after destruction, because a file or directory located in this
	 * area is likely to be in use by another containers or host.
	 */
	memcg_stop_kmem_account();

	cur_cred = override_creds(&init_cred);
	/*
	 * Files in cache area must not have csum attributes or
	 * pfcache must be disabled for underlain filesystem,
	 * otherwise real lock-recursion can happens for i_mutex.
	 * Here we disable lockdep to avoid false-positive reports.
	 */
	lockdep_off();
	ret = vfs_path_lookup(root.dentry, root.mnt, name, 0, &path);
	lockdep_on();
	revert_creds(cur_cred);
	path_put(&root);
	if (ret)
		goto out;

	ret = open_mapping_peer(inode->i_mapping, &path, &init_cred);
	if (!ret)
		percpu_counter_inc(&EXT4_SB(inode->i_sb)->s_pfcache_peers);
	path_put(&path);
out:
	memcg_resume_kmem_account();
	return ret;
}

/* require inode->i_mutex held or unreachable inode */
int ext4_close_pfcache(struct inode *inode)
{
	if (!inode->i_mapping->i_peer_file)
		return -ENOENT;
	close_mapping_peer(inode->i_mapping);
	percpu_counter_dec(&EXT4_SB(inode->i_sb)->s_pfcache_peers);
	return 0;
}

/* under sb->s_umount write lock */
int ext4_relink_pfcache(struct super_block *sb, char *new_root, bool new_sb)
{
	int old_root = !!EXT4_SB(sb)->s_pfcache_root.mnt;
	struct inode *inode, *old_inode = NULL;
	struct file *file;
	long nr_opened = 0, nr_closed = 0, nr_total;
	bool reload_csum = false;
	struct path root, path;

	if (new_root) {
		int err;

		err = kern_path(new_root, LOOKUP_DIRECTORY, &root);
		if (err) {
			printk(KERN_ERR"PFCache: lookup \"%s\" failed %d\n",
					new_root, err);
			return new_sb ? 0 : err;
		}
		if (!test_opt2(sb, PFCACHE_CSUM)) {
			set_opt2(sb, PFCACHE_CSUM);
			reload_csum = true;
		}
	} else {
		root.mnt = NULL;
		root.dentry = NULL;
	}

	if (new_sb) {
		path_put(&EXT4_SB(sb)->s_pfcache_root);
		EXT4_SB(sb)->s_pfcache_root = root;
		return 0;
	}

	path_get(&root);
	spin_lock(&EXT4_SB(sb)->s_pfcache_lock);
	path = EXT4_SB(sb)->s_pfcache_root;
	EXT4_SB(sb)->s_pfcache_root = root;
	spin_unlock(&EXT4_SB(sb)->s_pfcache_lock);
	path_put(&path);

	spin_lock(&sb->s_inode_list_lock);

	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		if (inode->i_state & (I_FREEING|I_CLEAR|I_WILL_FREE|I_NEW))
			continue;
		if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
			continue;
		if (!ext4_test_inode_state(inode, EXT4_STATE_PFCACHE_CSUM)) {
			if (!reload_csum)
				continue;
		} else if (!(EXT4_I(inode)->i_data_csum_end < 0))
			continue;
		__iget(inode);
		spin_unlock(&sb->s_inode_list_lock);
		iput(old_inode);
		old_inode = inode;

		path.mnt = NULL;
		path.dentry = NULL;

		mutex_lock(&inode->i_mutex);

		if (!ext4_test_inode_state(inode, EXT4_STATE_PFCACHE_CSUM)) {
			if (!reload_csum)
				goto next;
			if (S_ISDIR(inode->i_mode)) {
				ext4_load_dir_csum(inode);
				goto next;
			}
			if (ext4_load_data_csum(inode))
				goto next;
		} else if (!(EXT4_I(inode)->i_data_csum_end < 0) ||
				S_ISDIR(inode->i_mode))
			goto next;

		if (new_root) {
			char name[PFCACHE_MAX_PATH];
			const struct cred *cur_cred;
			int err;

			pfcache_path(inode, name);
			cur_cred = override_creds(&init_cred);
			err = vfs_path_lookup(root.dentry, root.mnt,
					name, 0, &path);
			revert_creds(cur_cred);
			if (err) {
				path.mnt = NULL;
				path.dentry = NULL;
			}
		}

		file = inode->i_mapping->i_peer_file;
		if ((!path.mnt && !file) || (path.mnt && file &&
		     file->f_mapping == path.dentry->d_inode->i_mapping))
			goto next;

		if (file) {
			close_mapping_peer(inode->i_mapping);
			nr_closed++;
		}

		if (path.mnt) {
			if (!open_mapping_peer(inode->i_mapping,
						&path, &init_cred))
				nr_opened++;
		}
next:
		mutex_unlock(&inode->i_mutex);
		path_put(&path);
		cond_resched();
		spin_lock(&sb->s_inode_list_lock);
	}
	spin_unlock(&sb->s_inode_list_lock);
	iput(old_inode);

	percpu_counter_add(&EXT4_SB(sb)->s_pfcache_peers,
			   nr_opened - nr_closed);
	nr_total = percpu_counter_sum(&EXT4_SB(sb)->s_pfcache_peers);

	if (new_root && (old_root || nr_total))
		printk(KERN_INFO"PFCache: relink %u:%u to \"%s\""
				" +%ld -%ld =%ld peers\n",
				MAJOR(sb->s_dev), MINOR(sb->s_dev), new_root,
				nr_opened, nr_closed, nr_total);
	if (!new_root && nr_total)
		printk(KERN_ERR"PFCache: %ld peers lost", nr_total);

	path_put(&root);

	return 0;
}

#define MAX_LOCK_BATCH	256

long ext4_dump_pfcache(struct super_block *sb,
		      struct pfcache_dump_request __user *user_req)
{
	struct inode *inode, *old_inode = NULL;
	struct pfcache_dump_request req;
	u8 __user *user_buffer;
	u64 state, *x;
	void *buffer, *p;
	long ret, size;
	int lock_batch = 0;

	if (copy_from_user(&req, user_req, sizeof(req)))
		return -EFAULT;

	if (!access_ok(VERIFY_WRITE, user_req,
		       req.header_size + req.buffer_size))
		return -EFAULT;

	/* check for unknown flags */
	if ((req.filter & ~PFCACHE_FILTER_MASK) ||
	    (req.payload & ~PFCACHE_PAYLOAD_MASK))
		return -EINVAL;

	buffer = kzalloc(PFCACHE_PAYLOAD_MAX_SIZE, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	ret = 0;
	/* skip all new fields in the user request header */
	user_buffer = (void*)user_req + req.header_size;

	spin_lock(&sb->s_inode_list_lock);
	list_for_each_entry(inode, &sb->s_inodes, i_sb_list) {
		if (inode->i_state & (I_FREEING|I_CLEAR|I_WILL_FREE|I_NEW))
			continue;
		if (!S_ISREG(inode->i_mode) ||
		    inode == EXT4_SB(sb)->s_balloon_ino)
			goto next;

		/* evaluate the inode state */
		state = 0;

		if (ext4_test_inode_state(inode, EXT4_STATE_PFCACHE_CSUM) &&
		    EXT4_I(inode)->i_data_csum_end < 0)
			state |= PFCACHE_FILTER_WITH_CSUM;
		else
			state |= PFCACHE_FILTER_WITHOUT_CSUM;

		if (inode->i_mapping->i_peer_file)
			state |= PFCACHE_FILTER_WITH_PEER;
		else
			state |= PFCACHE_FILTER_WITHOUT_PEER;

		/* check state-filter */
		if (req.filter & state)
			goto next;

		/* check csum-filter */
		if ((req.filter & PFCACHE_FILTER_COMPARE_CSUM) &&
		    memcmp(EXT4_I(inode)->i_data_csum,
			    req.csum_filter, EXT4_DATA_CSUM_SIZE))
			goto next;

		/* -- add new filters above this line -- */

		/* check offset-filter at the last */
		if (req.offset > 0) {
			req.offset--;
			goto next;
		}

		/* construct the payload */
		p = buffer;

		if (req.payload & PFCACHE_PAYLOAD_CSUM) {
			BUILD_BUG_ON(PFCACHE_CSUM_SIZE != EXT4_DATA_CSUM_SIZE);
			if (state & PFCACHE_FILTER_WITH_CSUM)
				memcpy(p, EXT4_I(inode)->i_data_csum,
						EXT4_DATA_CSUM_SIZE);
			else
				memset(p, 0, EXT4_DATA_CSUM_SIZE);
			p += ALIGN(PFCACHE_CSUM_SIZE, sizeof(u64));
		}

		if (req.payload & PFCACHE_PAYLOAD_FHANDLE) {
			unsigned *x = p;

			*x++ = 8;
			*x++ = FILEID_INO32_GEN;
			*x++ = inode->i_ino;
			*x++ = inode->i_generation;
			p += 16;
		}

		if (req.payload & PFCACHE_PAYLOAD_STATE) {
			x = p;
			*x = state;
			p += sizeof(u64);
		}

		if (req.payload & PFCACHE_PAYLOAD_FSIZE) {
			x = p;
			*x = i_size_read(inode);
			p += sizeof(u64);
		}

		if (req.payload & PFCACHE_PAYLOAD_PAGES) {
			x = p;
			*x = inode->i_mapping->nrpages;
			p += sizeof(u64);
		}

		/* -- add new payloads above this line -- */

		size = p - buffer;
		BUG_ON(!IS_ALIGNED(size, sizeof(u64)));
		BUG_ON(size > PFCACHE_PAYLOAD_MAX_SIZE);

		if (size > req.buffer_size)
			goto out;

		pagefault_disable();
		if (!__copy_to_user_inatomic(user_buffer, buffer, size)) {
			pagefault_enable();
		} else {
			pagefault_enable();
			__iget(inode);
			spin_unlock(&sb->s_inode_list_lock);
			iput(old_inode);
			old_inode = inode;
			if (copy_to_user(user_buffer, buffer, size)) {
				ret = -EFAULT;
				goto out_nolock;
			}
			cond_resched();
			lock_batch = 0;
			spin_lock(&sb->s_inode_list_lock);
		}

		ret++;
		user_buffer += size;
		req.buffer_size -= size;
next:
		if (signal_pending(current)) {
			if (!ret)
				ret = -EINTR;
			goto out;
		}
		if (++lock_batch > MAX_LOCK_BATCH || need_resched() ||
				spin_needbreak(&sb->s_inode_list_lock)) {
			__iget(inode);
			spin_unlock(&sb->s_inode_list_lock);
			iput(old_inode);
			old_inode = inode;
			cond_resched();
			lock_batch = 0;
			spin_lock(&sb->s_inode_list_lock);
		}
	}
out:
	spin_unlock(&sb->s_inode_list_lock);
out_nolock:
	iput(old_inode);

	kfree(buffer);

	return ret;
}

static void ext4_init_data_csum(struct inode *inode)
{
	EXT4_I(inode)->i_data_csum_end = 0;
	sha_init((__u32 *)EXT4_I(inode)->i_data_csum);
	ext4_set_inode_state(inode, EXT4_STATE_PFCACHE_CSUM);
	percpu_counter_inc(&EXT4_SB(inode->i_sb)->s_csum_partial);
}

void ext4_clear_data_csum(struct inode *inode)
{
	ext4_clear_inode_state(inode, EXT4_STATE_PFCACHE_CSUM);
	if (!S_ISREG(inode->i_mode))
		return;
	if (EXT4_I(inode)->i_data_csum_end < 0)
		percpu_counter_dec(&EXT4_SB(inode->i_sb)->s_csum_complete);
	else
		percpu_counter_dec(&EXT4_SB(inode->i_sb)->s_csum_partial);
}

void ext4_start_data_csum(struct inode *inode)
{
	if (!ext4_test_inode_state(inode, EXT4_STATE_PFCACHE_CSUM)) {
		spin_lock(&inode->i_lock);
		if (!ext4_test_inode_state(inode, EXT4_STATE_PFCACHE_CSUM))
			ext4_init_data_csum(inode);
		spin_unlock(&inode->i_lock);
	}
}

int ext4_load_data_csum(struct inode *inode)
{
	int ret;

	ret = ext4_xattr_get(inode, EXT4_XATTR_INDEX_TRUSTED,
			EXT4_DATA_CSUM_NAME, EXT4_I(inode)->i_data_csum,
			EXT4_DATA_CSUM_SIZE);
	if (ret < 0)
		return ret;
	if (ret != EXT4_DATA_CSUM_SIZE)
		return -EIO;

	EXT4_I(inode)->i_data_csum_end = -1;
	ext4_set_inode_state(inode, EXT4_STATE_PFCACHE_CSUM);
	percpu_counter_inc(&EXT4_SB(inode->i_sb)->s_csum_complete);
	return 0;
}

static int ext4_save_data_csum(struct inode *inode, u8 *csum)
{
	int ret;

	WARN_ON(journal_current_handle());

	if (ext4_test_inode_state(inode, EXT4_STATE_PFCACHE_CSUM) &&
	    EXT4_I(inode)->i_data_csum_end < 0 &&
	    memcmp(EXT4_I(inode)->i_data_csum, csum, EXT4_DATA_CSUM_SIZE))
		ext4_close_pfcache(inode);

	spin_lock(&inode->i_lock);
	if (ext4_test_inode_state(inode, EXT4_STATE_PFCACHE_CSUM))
		ext4_clear_data_csum(inode);
	memcpy(EXT4_I(inode)->i_data_csum, csum, EXT4_DATA_CSUM_SIZE);
	EXT4_I(inode)->i_data_csum_end = -1;
	ext4_set_inode_state(inode, EXT4_STATE_PFCACHE_CSUM);
	percpu_counter_inc(&EXT4_SB(inode->i_sb)->s_csum_complete);
	spin_unlock(&inode->i_lock);

	ext4_open_pfcache(inode);

	/* In order to guarantie csum consistenty force block allocation first */
	ret = ext4_alloc_da_blocks(inode);
	if (ret)
		return ret;

	return ext4_xattr_set(inode, EXT4_XATTR_INDEX_TRUSTED,
			EXT4_DATA_CSUM_NAME, EXT4_I(inode)->i_data_csum,
			EXT4_DATA_CSUM_SIZE, 0);
}

void ext4_load_dir_csum(struct inode *inode)
{
	char value[EXT4_DIR_CSUM_VALUE_LEN];
	int ret;

	ret = ext4_xattr_get(inode, EXT4_XATTR_INDEX_TRUSTED,
			     EXT4_DATA_CSUM_NAME, value, sizeof(value));
	if (ret == EXT4_DIR_CSUM_VALUE_LEN &&
	    !strncmp(value, EXT4_DIR_CSUM_VALUE, sizeof(value)))
		ext4_set_inode_state(inode, EXT4_STATE_PFCACHE_CSUM);
}

void ext4_save_dir_csum(struct inode *inode)
{
	ext4_set_inode_state(inode, EXT4_STATE_PFCACHE_CSUM);
	ext4_xattr_set(inode, EXT4_XATTR_INDEX_TRUSTED,
			EXT4_DATA_CSUM_NAME,
			EXT4_DIR_CSUM_VALUE,
			EXT4_DIR_CSUM_VALUE_LEN, 0);
}

void ext4_truncate_data_csum(struct inode *inode, loff_t pos)
{

	if (!S_ISREG(inode->i_mode))
		return;

	if (EXT4_I(inode)->i_data_csum_end < 0) {
		WARN_ON(journal_current_handle());
		ext4_xattr_set(inode, EXT4_XATTR_INDEX_TRUSTED,
				EXT4_DATA_CSUM_NAME, NULL, 0, 0);
		ext4_close_pfcache(inode);
	}
	spin_lock(&inode->i_lock);
	ext4_clear_data_csum(inode);
	if (!pos && test_opt2(inode->i_sb, PFCACHE_CSUM))
		ext4_init_data_csum(inode);
	spin_unlock(&inode->i_lock);
}

void ext4_check_pos_data_csum(struct inode *inode, loff_t pos)
{
	if ((pos & ~(loff_t)(SHA_MESSAGE_BYTES-1)) !=
	    EXT4_I(inode)->i_data_csum_end)
		ext4_truncate_data_csum(inode, pos);
}

static void sha_batch_transform(__u32 *digest, const char *data, unsigned rounds)
{
	__u32 temp[SHA_WORKSPACE_WORDS];

	while (rounds--) {
		sha_transform(digest, data, temp);
		data += SHA_MESSAGE_BYTES;
	}
}

void ext4_update_data_csum(struct inode *inode, loff_t pos,
			   unsigned len, struct page* page)
{
	__u32 *digest = (__u32 *)EXT4_I(inode)->i_data_csum;
	u8 *kaddr, *data;

	if (!len)
		return;

	len += pos & (SHA_MESSAGE_BYTES-1);
	len &= ~(SHA_MESSAGE_BYTES-1);
	pos &= ~(loff_t)(SHA_MESSAGE_BYTES-1);

	BUG_ON(pos != EXT4_I(inode)->i_data_csum_end);
	EXT4_I(inode)->i_data_csum_end += len;

	kaddr = kmap_atomic(page);
	data = kaddr + (pos & (PAGE_CACHE_SIZE - 1));
	sha_batch_transform(digest, data, len / SHA_MESSAGE_BYTES);
	kunmap_atomic(kaddr);
}

static int ext4_finish_data_csum(struct inode *inode, u8 *csum)
{
	__u32 *digest = (__u32 *)csum;
	__u8 data[SHA_MESSAGE_BYTES * 2];
	loff_t end;
	unsigned tail;
	__be64 bits;

	BUILD_BUG_ON(EXT4_DATA_CSUM_SIZE != SHA_DIGEST_WORDS * 4);

	memcpy(csum, EXT4_I(inode)->i_data_csum, EXT4_DATA_CSUM_SIZE);

	end = EXT4_I(inode)->i_data_csum_end;
	if (end < 0)
		return 0;

	if (!inode->i_size)
		return -ENODATA;

	tail = inode->i_size - end;
	if (tail >= SHA_MESSAGE_BYTES)
		return -EIO;

	if (tail) {
		struct page *page;
		u8 *kaddr;

		page = read_cache_page_gfp(inode->i_mapping,
					   end >> PAGE_CACHE_SHIFT,
					   GFP_NOFS);
		if (IS_ERR(page))
			return PTR_ERR(page);

		kaddr = kmap_atomic(page);
		memcpy(data, kaddr + (end & (PAGE_CACHE_SIZE-1)), tail);
		kunmap_atomic(kaddr);
		page_cache_release(page);
	}

	memset(data + tail, 0, sizeof(data) - tail);
	data[tail] = 0x80;

	bits = cpu_to_be64((end + tail) << 3);
	if (tail >= SHA_MESSAGE_BYTES - sizeof(bits)) {
		memcpy(data + SHA_MESSAGE_BYTES * 2 - sizeof(bits),
				&bits, sizeof(bits));
		sha_batch_transform(digest, data, 2);
	} else {
		memcpy(data + SHA_MESSAGE_BYTES - sizeof(bits),
				&bits, sizeof(bits));
		sha_batch_transform(digest, data, 1);
	}

	for (tail = 0; tail < SHA_DIGEST_WORDS ; tail++)
		digest[tail] = cpu_to_be32(digest[tail]);

	return 0;
}

void ext4_commit_data_csum(struct inode *inode)
{
	u8 csum[EXT4_DATA_CSUM_SIZE];

	if (!S_ISREG(inode->i_mode) || EXT4_I(inode)->i_data_csum_end < 0)
		return;

	mutex_lock(&inode->i_mutex);
	if (ext4_test_inode_state(inode, EXT4_STATE_PFCACHE_CSUM) &&
	    !ext4_finish_data_csum(inode, csum))
		ext4_save_data_csum(inode, csum);
	else
		ext4_truncate_data_csum(inode, 0);
	mutex_unlock(&inode->i_mutex);
}

static int ext4_xattr_trusted_csum_get(struct dentry *dentry, const char *name,
				       void *buffer, size_t size, int handler_flags)
{
	struct inode *inode = dentry->d_inode;
	u8 csum[EXT4_DATA_CSUM_SIZE];
	int i;

	if (strcmp(name, ""))
		return -ENODATA;

	if (!test_opt2(inode->i_sb, PFCACHE_CSUM))
		return -EOPNOTSUPP;

	if (S_ISDIR(inode->i_mode))
		return ext4_xattr_get(inode, EXT4_XATTR_INDEX_TRUSTED,
				      EXT4_DATA_CSUM_NAME, buffer, size);

	if (!S_ISREG(inode->i_mode))
		return -ENODATA;

	if (!buffer)
		return EXT4_DATA_CSUM_SIZE * 2;

	spin_lock(&inode->i_lock);
	if (ext4_test_inode_state(inode, EXT4_STATE_PFCACHE_CSUM) &&
	    EXT4_I(inode)->i_data_csum_end < 0) {
		memcpy(csum, EXT4_I(inode)->i_data_csum, EXT4_DATA_CSUM_SIZE);
	} else {
		spin_unlock(&inode->i_lock);
		return -ENODATA;
	}
	spin_unlock(&inode->i_lock);

	if (size == EXT4_DATA_CSUM_SIZE) {
		memcpy(buffer, csum, EXT4_DATA_CSUM_SIZE);
		return EXT4_DATA_CSUM_SIZE;
	}

	if (size >= EXT4_DATA_CSUM_SIZE * 2) {
		for ( i = 0 ; i < EXT4_DATA_CSUM_SIZE ; i++ )
			buffer = pack_hex_byte(buffer, csum[i]);
		return EXT4_DATA_CSUM_SIZE * 2;
	}

	return -ERANGE;
}

static int ext4_xattr_trusted_csum_set(struct dentry *dentry, const char *name,
				const void *value, size_t size, int flags, int handler_flags)
{
	struct inode *inode = dentry->d_inode;
	const char *text = value;
	u8 csum[EXT4_DATA_CSUM_SIZE];
	int i;

	if (strcmp(name, ""))
		return -ENODATA;

	if (!test_opt2(inode->i_sb, PFCACHE_CSUM))
		return -EOPNOTSUPP;

	if (S_ISDIR(inode->i_mode)) {
		if (!value)
			ext4_clear_inode_state(inode, EXT4_STATE_PFCACHE_CSUM);
		else if (size == EXT4_DIR_CSUM_VALUE_LEN &&
			 !strncmp(value, EXT4_DIR_CSUM_VALUE, size))
			ext4_set_inode_state(inode, EXT4_STATE_PFCACHE_CSUM);
		else
			return -EINVAL;

		return ext4_xattr_set(inode, EXT4_XATTR_INDEX_TRUSTED,
				      EXT4_DATA_CSUM_NAME, value, size, flags);
	}

	if (!S_ISREG(inode->i_mode))
		return -ENODATA;

	if (ext4_test_inode_state(inode, EXT4_STATE_PFCACHE_CSUM)) {
		if (flags & XATTR_CREATE)
			return -EEXIST;
	} else {
		if (flags & XATTR_REPLACE)
			return -ENODATA;
	}

	if (!value) {
		ext4_truncate_data_csum(inode, 1);
		return 0;
	}

	if (size == EXT4_DATA_CSUM_SIZE) {
		memcpy(csum, value, EXT4_DATA_CSUM_SIZE);
	} else if (size == EXT4_DATA_CSUM_SIZE * 2) {
		for ( i = 0 ; i < EXT4_DATA_CSUM_SIZE ; i++ ) {
			int hi = hex_to_bin(text[i*2]);
			int lo = hex_to_bin(text[i*2+1]);
			if ((hi < 0) || (lo < 0))
				return -EINVAL;
			csum[i] = (hi << 4) | lo;
		}
	} else
		return -EINVAL;

	if (mapping_writably_mapped(inode->i_mapping))
		return -EBUSY;

	return ext4_save_data_csum(inode, csum);
}

#define XATTR_TRUSTED_CSUM_PREFIX XATTR_TRUSTED_PREFIX EXT4_DATA_CSUM_NAME
#define XATTR_TRUSTED_CSUM_PREFIX_LEN (sizeof (XATTR_TRUSTED_CSUM_PREFIX) - 1)

static size_t
ext4_xattr_trusted_csum_list(struct dentry *dentry, char *list, size_t list_size,
			     const char *name, size_t name_len, int handler_flags)
{
	return 0;
}

struct xattr_handler ext4_xattr_trusted_csum_handler = {
	.prefix = XATTR_TRUSTED_CSUM_PREFIX,
	.list   = ext4_xattr_trusted_csum_list,
	.get    = ext4_xattr_trusted_csum_get,
	.set    = ext4_xattr_trusted_csum_set,
};
