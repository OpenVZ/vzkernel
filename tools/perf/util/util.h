#ifndef GIT_COMPAT_UTIL_H
#define GIT_COMPAT_UTIL_H

#define _BSD_SOURCE 1
/* glibc 2.20 deprecates _BSD_SOURCE in favour of _DEFAULT_SOURCE */
#define _DEFAULT_SOURCE 1

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <linux/compiler.h>
#include <linux/types.h>

/* General helper functions */
void usage(const char *err) __noreturn;
void die(const char *err, ...) __noreturn __printf(1, 2);

static inline void *zalloc(size_t size)
{
	return calloc(1, size);
}

#define zfree(ptr) ({ free(*ptr); *ptr = NULL; })

struct dirent;
struct strlist;

int mkdir_p(char *path, mode_t mode);
int rm_rf(const char *path);
struct strlist *lsdir(const char *name, bool (*filter)(const char *, struct dirent *));
bool lsdir_no_dot_filter(const char *name, struct dirent *d);
int copyfile(const char *from, const char *to);
int copyfile_mode(const char *from, const char *to, mode_t mode);

ssize_t readn(int fd, void *buf, size_t n);
ssize_t writen(int fd, const void *buf, size_t n);

size_t hex_width(u64 v);
int hex2u64(const char *ptr, u64 *val);

extern unsigned int page_size;
extern int cacheline_size;

const char *perf_tip(const char *dirpath);

#ifndef HAVE_SCHED_GETCPU_SUPPORT
int sched_getcpu(void);
#endif

#ifndef HAVE_SETNS_SUPPORT
int setns(int fd, int nstype);
#endif

extern bool perf_singlethreaded;

void perf_set_singlethreaded(void);
void perf_set_multithreaded(void);

#endif /* GIT_COMPAT_UTIL_H */
