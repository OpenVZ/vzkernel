#ifndef __PRIVATE_STRINGHASH_H__
#define __PRIVATE_STRINGHASH_H__

#define hashlen_create(hash,len) (((u64)(len)<<32)|(u32)(hash))

/* !CONFIG_DCACHE_WORD_ACCESS: Slow, byte-at-a-time version */

/* Return the "hash_len" (hash and length) of a null-terminated string */
u64 hashlen_string(const void *salt, const char *name)
{
	unsigned long hash = (unsigned long)salt;
	unsigned long len = 0, c;

	c = (unsigned char)*name;
	while (c) {
		len++;
		hash = partial_name_hash(c, hash);
		c = (unsigned char)name[len];
	}
	return hashlen_create(end_name_hash(hash), len);
}
EXPORT_SYMBOL(hashlen_string);

#endif /* __PRIVATE_STRINGHASH_H__ */
