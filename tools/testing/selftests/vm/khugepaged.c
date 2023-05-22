#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/wait.h>

#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif
#ifndef MADV_COLLAPSE
#define MADV_COLLAPSE 25
#endif

#define BASE_ADDR ((void *)(1UL << 30))
static unsigned long hpage_pmd_size;
static unsigned long page_size;
static int hpage_pmd_nr;

#define THP_SYSFS "/sys/kernel/mm/transparent_hugepage/"
#define PID_SMAPS "/proc/self/smaps"

struct collapse_context {
	void (*collapse)(const char *msg, char *p, int nr_hpages, bool expect);
	bool enforce_pte_scan_limits;
};

enum thp_enabled {
	THP_ALWAYS,
	THP_MADVISE,
	THP_NEVER,
};

static const char *thp_enabled_strings[] = {
	"always",
	"madvise",
	"never",
	NULL
};

enum thp_defrag {
	THP_DEFRAG_ALWAYS,
	THP_DEFRAG_DEFER,
	THP_DEFRAG_DEFER_MADVISE,
	THP_DEFRAG_MADVISE,
	THP_DEFRAG_NEVER,
};

static const char *thp_defrag_strings[] = {
	"always",
	"defer",
	"defer+madvise",
	"madvise",
	"never",
	NULL
};

enum shmem_enabled {
	SHMEM_ALWAYS,
	SHMEM_WITHIN_SIZE,
	SHMEM_ADVISE,
	SHMEM_NEVER,
	SHMEM_DENY,
	SHMEM_FORCE,
};

static const char *shmem_enabled_strings[] = {
	"always",
	"within_size",
	"advise",
	"never",
	"deny",
	"force",
	NULL
};

struct khugepaged_settings {
	bool defrag;
	unsigned int alloc_sleep_millisecs;
	unsigned int scan_sleep_millisecs;
	unsigned int max_ptes_none;
	unsigned int max_ptes_swap;
	unsigned int max_ptes_shared;
	unsigned long pages_to_scan;
};

struct settings {
	enum thp_enabled thp_enabled;
	enum thp_defrag thp_defrag;
	enum shmem_enabled shmem_enabled;
	bool use_zero_page;
	struct khugepaged_settings khugepaged;
};

static struct settings saved_settings;
static bool skip_settings_restore;

static int exit_status;

static void success(const char *msg)
{
	printf(" \e[32m%s\e[0m\n", msg);
}

static void fail(const char *msg)
{
	printf(" \e[31m%s\e[0m\n", msg);
	exit_status++;
}

static int read_file(const char *path, char *buf, size_t buflen)
{
	int fd;
	ssize_t numread;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return 0;

	numread = read(fd, buf, buflen - 1);
	if (numread < 1) {
		close(fd);
		return 0;
	}

	buf[numread] = '\0';
	close(fd);

	return (unsigned int) numread;
}

static int write_file(const char *path, const char *buf, size_t buflen)
{
	int fd;
	ssize_t numwritten;

	fd = open(path, O_WRONLY);
	if (fd == -1)
		return 0;

	numwritten = write(fd, buf, buflen - 1);
	close(fd);
	if (numwritten < 1)
		return 0;

	return (unsigned int) numwritten;
}

static int read_string(const char *name, const char *strings[])
{
	char path[PATH_MAX];
	char buf[256];
	char *c;
	int ret;

	ret = snprintf(path, PATH_MAX, THP_SYSFS "%s", name);
	if (ret >= PATH_MAX) {
		printf("%s: Pathname is too long\n", __func__);
		exit(EXIT_FAILURE);
	}

	if (!read_file(path, buf, sizeof(buf))) {
		perror(path);
		exit(EXIT_FAILURE);
	}

	c = strchr(buf, '[');
	if (!c) {
		printf("%s: Parse failure\n", __func__);
		exit(EXIT_FAILURE);
	}

	c++;
	memmove(buf, c, sizeof(buf) - (c - buf));

	c = strchr(buf, ']');
	if (!c) {
		printf("%s: Parse failure\n", __func__);
		exit(EXIT_FAILURE);
	}
	*c = '\0';

	ret = 0;
	while (strings[ret]) {
		if (!strcmp(strings[ret], buf))
			return ret;
		ret++;
	}

	printf("Failed to parse %s\n", name);
	exit(EXIT_FAILURE);
}

static void write_string(const char *name, const char *val)
{
	char path[PATH_MAX];
	int ret;

	ret = snprintf(path, PATH_MAX, THP_SYSFS "%s", name);
	if (ret >= PATH_MAX) {
		printf("%s: Pathname is too long\n", __func__);
		exit(EXIT_FAILURE);
	}

	if (!write_file(path, val, strlen(val) + 1)) {
		perror(path);
		exit(EXIT_FAILURE);
	}
}

static const unsigned long read_num(const char *name)
{
	char path[PATH_MAX];
	char buf[21];
	int ret;

	ret = snprintf(path, PATH_MAX, THP_SYSFS "%s", name);
	if (ret >= PATH_MAX) {
		printf("%s: Pathname is too long\n", __func__);
		exit(EXIT_FAILURE);
	}

	ret = read_file(path, buf, sizeof(buf));
	if (ret < 0) {
		perror("read_file(read_num)");
		exit(EXIT_FAILURE);
	}

	return strtoul(buf, NULL, 10);
}

static void write_num(const char *name, unsigned long num)
{
	char path[PATH_MAX];
	char buf[21];
	int ret;

	ret = snprintf(path, PATH_MAX, THP_SYSFS "%s", name);
	if (ret >= PATH_MAX) {
		printf("%s: Pathname is too long\n", __func__);
		exit(EXIT_FAILURE);
	}

	sprintf(buf, "%ld", num);
	if (!write_file(path, buf, strlen(buf) + 1)) {
		perror(path);
		exit(EXIT_FAILURE);
	}
}

static void write_settings(struct settings *settings)
{
	struct khugepaged_settings *khugepaged = &settings->khugepaged;

	write_string("enabled", thp_enabled_strings[settings->thp_enabled]);
	write_string("defrag", thp_defrag_strings[settings->thp_defrag]);
	write_string("shmem_enabled",
			shmem_enabled_strings[settings->shmem_enabled]);
	write_num("use_zero_page", settings->use_zero_page);

	write_num("khugepaged/defrag", khugepaged->defrag);
	write_num("khugepaged/alloc_sleep_millisecs",
			khugepaged->alloc_sleep_millisecs);
	write_num("khugepaged/scan_sleep_millisecs",
			khugepaged->scan_sleep_millisecs);
	write_num("khugepaged/max_ptes_none", khugepaged->max_ptes_none);
	write_num("khugepaged/max_ptes_swap", khugepaged->max_ptes_swap);
	write_num("khugepaged/max_ptes_shared", khugepaged->max_ptes_shared);
	write_num("khugepaged/pages_to_scan", khugepaged->pages_to_scan);
}

#define MAX_SETTINGS_DEPTH 4
static struct settings settings_stack[MAX_SETTINGS_DEPTH];
static int settings_index;

static struct settings *current_settings(void)
{
	if (!settings_index) {
		printf("Fail: No settings set");
		exit(EXIT_FAILURE);
	}
	return settings_stack + settings_index - 1;
}

static void push_settings(struct settings *settings)
{
	if (settings_index >= MAX_SETTINGS_DEPTH) {
		printf("Fail: Settings stack exceeded");
		exit(EXIT_FAILURE);
	}
	settings_stack[settings_index++] = *settings;
	write_settings(current_settings());
}

static void pop_settings(void)
{
	if (settings_index <= 0) {
		printf("Fail: Settings stack empty");
		exit(EXIT_FAILURE);
	}
	--settings_index;
	write_settings(current_settings());
}

static void restore_settings(int sig)
{
	if (skip_settings_restore)
		goto out;

	printf("Restore THP and khugepaged settings...");
	write_settings(&saved_settings);
	success("OK");
	if (sig)
		exit(EXIT_FAILURE);
out:
	exit(exit_status);
}

static void save_settings(void)
{
	printf("Save THP and khugepaged settings...");
	saved_settings = (struct settings) {
		.thp_enabled = read_string("enabled", thp_enabled_strings),
		.thp_defrag = read_string("defrag", thp_defrag_strings),
		.shmem_enabled =
			read_string("shmem_enabled", shmem_enabled_strings),
		.use_zero_page = read_num("use_zero_page"),
	};
	saved_settings.khugepaged = (struct khugepaged_settings) {
		.defrag = read_num("khugepaged/defrag"),
		.alloc_sleep_millisecs =
			read_num("khugepaged/alloc_sleep_millisecs"),
		.scan_sleep_millisecs =
			read_num("khugepaged/scan_sleep_millisecs"),
		.max_ptes_none = read_num("khugepaged/max_ptes_none"),
		.max_ptes_swap = read_num("khugepaged/max_ptes_swap"),
		.max_ptes_shared = read_num("khugepaged/max_ptes_shared"),
		.pages_to_scan = read_num("khugepaged/pages_to_scan"),
	};
	success("OK");

	signal(SIGTERM, restore_settings);
	signal(SIGINT, restore_settings);
	signal(SIGHUP, restore_settings);
	signal(SIGQUIT, restore_settings);
}

#define MAX_LINE_LENGTH 500

static bool check_for_pattern(FILE *fp, char *pattern, char *buf)
{
	while (fgets(buf, MAX_LINE_LENGTH, fp) != NULL) {
		if (!strncmp(buf, pattern, strlen(pattern)))
			return true;
	}
	return false;
}

static bool check_huge(void *addr, int nr_hpages)
{
	bool thp = false;
	int ret;
	FILE *fp;
	char buffer[MAX_LINE_LENGTH];
	char addr_pattern[MAX_LINE_LENGTH];

	ret = snprintf(addr_pattern, MAX_LINE_LENGTH, "%08lx-",
		       (unsigned long) addr);
	if (ret >= MAX_LINE_LENGTH) {
		printf("%s: Pattern is too long\n", __func__);
		exit(EXIT_FAILURE);
	}


	fp = fopen(PID_SMAPS, "r");
	if (!fp) {
		printf("%s: Failed to open file %s\n", __func__, PID_SMAPS);
		exit(EXIT_FAILURE);
	}
	if (!check_for_pattern(fp, addr_pattern, buffer))
		goto err_out;

	ret = snprintf(addr_pattern, MAX_LINE_LENGTH, "AnonHugePages:%10ld kB",
		       nr_hpages * (hpage_pmd_size >> 10));
	if (ret >= MAX_LINE_LENGTH) {
		printf("%s: Pattern is too long\n", __func__);
		exit(EXIT_FAILURE);
	}
	/*
	 * Fetch the AnonHugePages: in the same block and check whether it got
	 * the expected number of hugeepages next.
	 */
	if (!check_for_pattern(fp, "AnonHugePages:", buffer))
		goto err_out;

	if (strncmp(buffer, addr_pattern, strlen(addr_pattern)))
		goto err_out;

	thp = true;
err_out:
	fclose(fp);
	return thp;
}


static bool check_swap(void *addr, unsigned long size)
{
	bool swap = false;
	int ret;
	FILE *fp;
	char buffer[MAX_LINE_LENGTH];
	char addr_pattern[MAX_LINE_LENGTH];

	ret = snprintf(addr_pattern, MAX_LINE_LENGTH, "%08lx-",
		       (unsigned long) addr);
	if (ret >= MAX_LINE_LENGTH) {
		printf("%s: Pattern is too long\n", __func__);
		exit(EXIT_FAILURE);
	}


	fp = fopen(PID_SMAPS, "r");
	if (!fp) {
		printf("%s: Failed to open file %s\n", __func__, PID_SMAPS);
		exit(EXIT_FAILURE);
	}
	if (!check_for_pattern(fp, addr_pattern, buffer))
		goto err_out;

	ret = snprintf(addr_pattern, MAX_LINE_LENGTH, "Swap:%19ld kB",
		       size >> 10);
	if (ret >= MAX_LINE_LENGTH) {
		printf("%s: Pattern is too long\n", __func__);
		exit(EXIT_FAILURE);
	}
	/*
	 * Fetch the Swap: in the same block and check whether it got
	 * the expected number of hugeepages next.
	 */
	if (!check_for_pattern(fp, "Swap:", buffer))
		goto err_out;

	if (strncmp(buffer, addr_pattern, strlen(addr_pattern)))
		goto err_out;

	swap = true;
err_out:
	fclose(fp);
	return swap;
}

static void *alloc_mapping(int nr)
{
	void *p;

	p = mmap(BASE_ADDR, nr * hpage_pmd_size, PROT_READ | PROT_WRITE,
		 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (p != BASE_ADDR) {
		printf("Failed to allocate VMA at %p\n", BASE_ADDR);
		exit(EXIT_FAILURE);
	}

	return p;
}

static void fill_memory(int *p, unsigned long start, unsigned long end)
{
	int i;

	for (i = start / page_size; i < end / page_size; i++)
		p[i * page_size / sizeof(*p)] = i + 0xdead0000;
}

/*
 * Returns pmd-mapped hugepage in VMA marked VM_HUGEPAGE, filled with
 * validate_memory()'able contents.
 */
static void *alloc_hpage(void)
{
	void *p;

	p = alloc_mapping(1);
	printf("Allocate huge page...");
	madvise(p, hpage_pmd_size, MADV_HUGEPAGE);
	fill_memory(p, 0, hpage_pmd_size);
	if (check_huge(p, 1))
		success("OK");
	else
		fail("Fail");
	return p;
}

static void validate_memory(int *p, unsigned long start, unsigned long end)
{
	int i;

	for (i = start / page_size; i < end / page_size; i++) {
		if (p[i * page_size / sizeof(*p)] != i + 0xdead0000) {
			printf("Page %d is corrupted: %#x\n",
					i, p[i * page_size / sizeof(*p)]);
			exit(EXIT_FAILURE);
		}
	}
}

static void madvise_collapse(const char *msg, char *p, int nr_hpages,
			     bool expect)
{
	int ret;
	struct settings settings = *current_settings();

	printf("%s...", msg);
	/* Sanity check */
	if (!check_huge(p, 0)) {
		printf("Unexpected huge page\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Prevent khugepaged interference and tests that MADV_COLLAPSE
	 * ignores /sys/kernel/mm/transparent_hugepage/enabled
	 */
	settings.thp_enabled = THP_NEVER;
	push_settings(&settings);

	/* Clear VM_NOHUGEPAGE */
	madvise(p, nr_hpages * hpage_pmd_size, MADV_HUGEPAGE);
	ret = madvise(p, nr_hpages * hpage_pmd_size, MADV_COLLAPSE);
	if (((bool)ret) == expect)
		fail("Fail: Bad return value");
	else if (check_huge(p, nr_hpages) != expect)
		fail("Fail: check_huge()");
	else
		success("OK");

	pop_settings();
}

#define TICK 500000
static bool wait_for_scan(const char *msg, char *p, int nr_hpages)
{
	int full_scans;
	int timeout = 6; /* 3 seconds */

	/* Sanity check */
	if (!check_huge(p, 0)) {
		printf("Unexpected huge page\n");
		exit(EXIT_FAILURE);
	}

	madvise(p, nr_hpages * hpage_pmd_size, MADV_HUGEPAGE);

	/* Wait until the second full_scan completed */
	full_scans = read_num("khugepaged/full_scans") + 2;

	printf("%s...", msg);
	while (timeout--) {
		if (check_huge(p, nr_hpages))
			break;
		if (read_num("khugepaged/full_scans") >= full_scans)
			break;
		printf(".");
		usleep(TICK);
	}

	madvise(p, nr_hpages * hpage_pmd_size, MADV_NOHUGEPAGE);

	return timeout == -1;
}

static void khugepaged_collapse(const char *msg, char *p, int nr_hpages,
				bool expect)
{
	if (wait_for_scan(msg, p, nr_hpages)) {
		if (expect)
			fail("Timeout");
		else
			success("OK");
		return;
	} else if (check_huge(p, nr_hpages) == expect) {
		success("OK");
	} else {
		fail("Fail");
	}
}

static void alloc_at_fault(void)
{
	struct settings settings = *current_settings();
	char *p;

	settings.thp_enabled = THP_ALWAYS;
	push_settings(&settings);

	p = alloc_mapping(1);
	*p = 1;
	printf("Allocate huge page on fault...");
	if (check_huge(p, 1))
		success("OK");
	else
		fail("Fail");

	pop_settings();

	madvise(p, page_size, MADV_DONTNEED);
	printf("Split huge PMD on MADV_DONTNEED...");
	if (check_huge(p, 0))
		success("OK");
	else
		fail("Fail");
	munmap(p, hpage_pmd_size);
}

static void collapse_full(struct collapse_context *c)
{
	void *p;
	int nr_hpages = 4;
	unsigned long size = nr_hpages * hpage_pmd_size;

	p = alloc_mapping(nr_hpages);
	fill_memory(p, 0, size);
	c->collapse("Collapse multiple fully populated PTE table", p, nr_hpages,
		    true);
	validate_memory(p, 0, size);
	munmap(p, size);
}

static void collapse_empty(struct collapse_context *c)
{
	void *p;

	p = alloc_mapping(1);
	c->collapse("Do not collapse empty PTE table", p, 1, false);
	munmap(p, hpage_pmd_size);
}

static void collapse_single_pte_entry(struct collapse_context *c)
{
	void *p;

	p = alloc_mapping(1);
	fill_memory(p, 0, page_size);
	c->collapse("Collapse PTE table with single PTE entry present", p,
		    1, true);
	validate_memory(p, 0, page_size);
	munmap(p, hpage_pmd_size);
}

static void collapse_max_ptes_none(struct collapse_context *c)
{
	int max_ptes_none = hpage_pmd_nr / 2;
	struct settings settings = *current_settings();
	void *p;

	settings.khugepaged.max_ptes_none = max_ptes_none;
	push_settings(&settings);

	p = alloc_mapping(1);

	fill_memory(p, 0, (hpage_pmd_nr - max_ptes_none - 1) * page_size);
	c->collapse("Maybe collapse with max_ptes_none exceeded", p, 1,
		    !c->enforce_pte_scan_limits);
	validate_memory(p, 0, (hpage_pmd_nr - max_ptes_none - 1) * page_size);

	if (c->enforce_pte_scan_limits) {
		fill_memory(p, 0, (hpage_pmd_nr - max_ptes_none) * page_size);
		c->collapse("Collapse with max_ptes_none PTEs empty", p, 1,
			    true);
		validate_memory(p, 0,
				(hpage_pmd_nr - max_ptes_none) * page_size);
	}

	munmap(p, hpage_pmd_size);
	pop_settings();
}

static void collapse_swapin_single_pte(struct collapse_context *c)
{
	void *p;
	p = alloc_mapping(1);
	fill_memory(p, 0, hpage_pmd_size);

	printf("Swapout one page...");
	if (madvise(p, page_size, MADV_PAGEOUT)) {
		perror("madvise(MADV_PAGEOUT)");
		exit(EXIT_FAILURE);
	}
	if (check_swap(p, page_size)) {
		success("OK");
	} else {
		fail("Fail");
		goto out;
	}

	c->collapse("Collapse with swapping in single PTE entry", p, 1, true);
	validate_memory(p, 0, hpage_pmd_size);
out:
	munmap(p, hpage_pmd_size);
}

static void collapse_max_ptes_swap(struct collapse_context *c)
{
	int max_ptes_swap = read_num("khugepaged/max_ptes_swap");
	void *p;

	p = alloc_mapping(1);

	fill_memory(p, 0, hpage_pmd_size);
	printf("Swapout %d of %d pages...", max_ptes_swap + 1, hpage_pmd_nr);
	if (madvise(p, (max_ptes_swap + 1) * page_size, MADV_PAGEOUT)) {
		perror("madvise(MADV_PAGEOUT)");
		exit(EXIT_FAILURE);
	}
	if (check_swap(p, (max_ptes_swap + 1) * page_size)) {
		success("OK");
	} else {
		fail("Fail");
		goto out;
	}

	c->collapse("Maybe collapse with max_ptes_swap exceeded", p, 1,
		    !c->enforce_pte_scan_limits);
	validate_memory(p, 0, hpage_pmd_size);

	if (c->enforce_pte_scan_limits) {
		fill_memory(p, 0, hpage_pmd_size);
		printf("Swapout %d of %d pages...", max_ptes_swap,
		       hpage_pmd_nr);
		if (madvise(p, max_ptes_swap * page_size, MADV_PAGEOUT)) {
			perror("madvise(MADV_PAGEOUT)");
			exit(EXIT_FAILURE);
		}
		if (check_swap(p, max_ptes_swap * page_size)) {
			success("OK");
		} else {
			fail("Fail");
			goto out;
		}

		c->collapse("Collapse with max_ptes_swap pages swapped out", p,
			    1, true);
		validate_memory(p, 0, hpage_pmd_size);
	}
out:
	munmap(p, hpage_pmd_size);
}

static void collapse_single_pte_entry_compound(struct collapse_context *c)
{
	void *p;

	p = alloc_hpage();
	madvise(p, hpage_pmd_size, MADV_NOHUGEPAGE);
	printf("Split huge page leaving single PTE mapping compound page...");
	madvise(p + page_size, hpage_pmd_size - page_size, MADV_DONTNEED);
	if (check_huge(p, 0))
		success("OK");
	else
		fail("Fail");

	c->collapse("Collapse PTE table with single PTE mapping compound page",
		    p, 1, true);
	validate_memory(p, 0, page_size);
	munmap(p, hpage_pmd_size);
}

static void collapse_full_of_compound(struct collapse_context *c)
{
	void *p;

	p = alloc_hpage();
	printf("Split huge page leaving single PTE page table full of compound pages...");
	madvise(p, page_size, MADV_NOHUGEPAGE);
	madvise(p, hpage_pmd_size, MADV_NOHUGEPAGE);
	if (check_huge(p, 0))
		success("OK");
	else
		fail("Fail");

	c->collapse("Collapse PTE table full of compound pages", p, 1, true);
	validate_memory(p, 0, hpage_pmd_size);
	munmap(p, hpage_pmd_size);
}

static void collapse_compound_extreme(struct collapse_context *c)
{
	void *p;
	int i;

	p = alloc_mapping(1);
	for (i = 0; i < hpage_pmd_nr; i++) {
		printf("\rConstruct PTE page table full of different PTE-mapped compound pages %3d/%d...",
				i + 1, hpage_pmd_nr);

		madvise(BASE_ADDR, hpage_pmd_size, MADV_HUGEPAGE);
		fill_memory(BASE_ADDR, 0, hpage_pmd_size);
		if (!check_huge(BASE_ADDR, 1)) {
			printf("Failed to allocate huge page\n");
			exit(EXIT_FAILURE);
		}
		madvise(BASE_ADDR, hpage_pmd_size, MADV_NOHUGEPAGE);

		p = mremap(BASE_ADDR - i * page_size,
				i * page_size + hpage_pmd_size,
				(i + 1) * page_size,
				MREMAP_MAYMOVE | MREMAP_FIXED,
				BASE_ADDR + 2 * hpage_pmd_size);
		if (p == MAP_FAILED) {
			perror("mremap+unmap");
			exit(EXIT_FAILURE);
		}

		p = mremap(BASE_ADDR + 2 * hpage_pmd_size,
				(i + 1) * page_size,
				(i + 1) * page_size + hpage_pmd_size,
				MREMAP_MAYMOVE | MREMAP_FIXED,
				BASE_ADDR - (i + 1) * page_size);
		if (p == MAP_FAILED) {
			perror("mremap+alloc");
			exit(EXIT_FAILURE);
		}
	}

	munmap(BASE_ADDR, hpage_pmd_size);
	fill_memory(p, 0, hpage_pmd_size);
	if (check_huge(p, 0))
		success("OK");
	else
		fail("Fail");

	c->collapse("Collapse PTE table full of different compound pages", p, 1,
		    true);

	validate_memory(p, 0, hpage_pmd_size);
	munmap(p, hpage_pmd_size);
}

static void collapse_fork(struct collapse_context *c)
{
	int wstatus;
	void *p;

	p = alloc_mapping(1);

	printf("Allocate small page...");
	fill_memory(p, 0, page_size);
	if (check_huge(p, 0))
		success("OK");
	else
		fail("Fail");

	printf("Share small page over fork()...");
	if (!fork()) {
		/* Do not touch settings on child exit */
		skip_settings_restore = true;
		exit_status = 0;

		if (check_huge(p, 0))
			success("OK");
		else
			fail("Fail");

		fill_memory(p, page_size, 2 * page_size);
		c->collapse("Collapse PTE table with single page shared with parent process",
			    p, 1, true);

		validate_memory(p, 0, page_size);
		munmap(p, hpage_pmd_size);
		exit(exit_status);
	}

	wait(&wstatus);
	exit_status += WEXITSTATUS(wstatus);

	printf("Check if parent still has small page...");
	if (check_huge(p, 0))
		success("OK");
	else
		fail("Fail");
	validate_memory(p, 0, page_size);
	munmap(p, hpage_pmd_size);
}

static void collapse_fork_compound(struct collapse_context *c)
{
	int wstatus;
	void *p;

	p = alloc_hpage();
	printf("Share huge page over fork()...");
	if (!fork()) {
		/* Do not touch settings on child exit */
		skip_settings_restore = true;
		exit_status = 0;

		if (check_huge(p, 1))
			success("OK");
		else
			fail("Fail");

		printf("Split huge page PMD in child process...");
		madvise(p, page_size, MADV_NOHUGEPAGE);
		madvise(p, hpage_pmd_size, MADV_NOHUGEPAGE);
		if (check_huge(p, 0))
			success("OK");
		else
			fail("Fail");
		fill_memory(p, 0, page_size);

		write_num("khugepaged/max_ptes_shared", hpage_pmd_nr - 1);
		c->collapse("Collapse PTE table full of compound pages in child",
			    p, 1, true);
		write_num("khugepaged/max_ptes_shared",
			  current_settings()->khugepaged.max_ptes_shared);

		validate_memory(p, 0, hpage_pmd_size);
		munmap(p, hpage_pmd_size);
		exit(exit_status);
	}

	wait(&wstatus);
	exit_status += WEXITSTATUS(wstatus);

	printf("Check if parent still has huge page...");
	if (check_huge(p, 1))
		success("OK");
	else
		fail("Fail");
	validate_memory(p, 0, hpage_pmd_size);
	munmap(p, hpage_pmd_size);
}

static void collapse_max_ptes_shared(struct collapse_context *c)
{
	int max_ptes_shared = read_num("khugepaged/max_ptes_shared");
	int wstatus;
	void *p;

	p = alloc_hpage();
	printf("Share huge page over fork()...");
	if (!fork()) {
		/* Do not touch settings on child exit */
		skip_settings_restore = true;
		exit_status = 0;

		if (check_huge(p, 1))
			success("OK");
		else
			fail("Fail");

		printf("Trigger CoW on page %d of %d...",
				hpage_pmd_nr - max_ptes_shared - 1, hpage_pmd_nr);
		fill_memory(p, 0, (hpage_pmd_nr - max_ptes_shared - 1) * page_size);
		if (check_huge(p, 0))
			success("OK");
		else
			fail("Fail");

		c->collapse("Maybe collapse with max_ptes_shared exceeded", p,
			    1, !c->enforce_pte_scan_limits);

		if (c->enforce_pte_scan_limits) {
			printf("Trigger CoW on page %d of %d...",
			       hpage_pmd_nr - max_ptes_shared, hpage_pmd_nr);
			fill_memory(p, 0, (hpage_pmd_nr - max_ptes_shared) *
				    page_size);
			if (check_huge(p, 0))
				success("OK");
			else
				fail("Fail");

			c->collapse("Collapse with max_ptes_shared PTEs shared",
				    p, 1,  true);
		}

		validate_memory(p, 0, hpage_pmd_size);
		munmap(p, hpage_pmd_size);
		exit(exit_status);
	}

	wait(&wstatus);
	exit_status += WEXITSTATUS(wstatus);

	printf("Check if parent still has huge page...");
	if (check_huge(p, 1))
		success("OK");
	else
		fail("Fail");
	validate_memory(p, 0, hpage_pmd_size);
	munmap(p, hpage_pmd_size);
}

static void madvise_collapse_existing_thps(void)
{
	void *p;
	int err;

	p = alloc_mapping(1);
	fill_memory(p, 0, hpage_pmd_size);

	printf("Collapse fully populated PTE table...");
	/*
	 * Note that we don't set MADV_HUGEPAGE here, which
	 * also tests that VM_HUGEPAGE isn't required for
	 * MADV_COLLAPSE in "madvise" mode.
	 */
	err = madvise(p, hpage_pmd_size, MADV_COLLAPSE);
	if (err == 0 && check_huge(p, 1)) {
		success("OK");
		printf("Re-collapse PMD-mapped hugepage");
		err = madvise(p, hpage_pmd_size, MADV_COLLAPSE);
		if (err == 0 && check_huge(p, 1))
			success("OK");
		else
			fail("Fail");
	} else {
		fail("Fail");
	}
	validate_memory(p, 0, hpage_pmd_size);
	munmap(p, hpage_pmd_size);
}

int main(int argc, const char **argv)
{
	struct collapse_context c;
	struct settings default_settings = {
		.thp_enabled = THP_MADVISE,
		.thp_defrag = THP_DEFRAG_ALWAYS,
		.shmem_enabled = SHMEM_NEVER,
		.use_zero_page = 0,
		.khugepaged = {
			.defrag = 1,
			.alloc_sleep_millisecs = 10,
			.scan_sleep_millisecs = 10,
		},
	};
	const char *tests = argc == 1 ? "all" : argv[1];

	setbuf(stdout, NULL);

	page_size = getpagesize();
	hpage_pmd_size = read_num("hpage_pmd_size");
	hpage_pmd_nr = hpage_pmd_size / page_size;

	default_settings.khugepaged.max_ptes_none = hpage_pmd_nr - 1;
	default_settings.khugepaged.max_ptes_swap = hpage_pmd_nr / 8;
	default_settings.khugepaged.max_ptes_shared = hpage_pmd_nr / 2;
	default_settings.khugepaged.pages_to_scan = hpage_pmd_nr * 8;

	save_settings();
	push_settings(&default_settings);

	alloc_at_fault();

	if (!strcmp(tests, "khugepaged") || !strcmp(tests, "all")) {
		printf("\n*** Testing context: khugepaged ***\n");
		c.collapse = &khugepaged_collapse;
		c.enforce_pte_scan_limits = true;

		collapse_full(&c);
		collapse_empty(&c);
		collapse_single_pte_entry(&c);
		collapse_max_ptes_none(&c);
		collapse_swapin_single_pte(&c);
		collapse_max_ptes_swap(&c);
		collapse_single_pte_entry_compound(&c);
		collapse_full_of_compound(&c);
		collapse_compound_extreme(&c);
		collapse_fork(&c);
		collapse_fork_compound(&c);
		collapse_max_ptes_shared(&c);
	}
	if (!strcmp(tests, "madvise") || !strcmp(tests, "all")) {
		printf("\n*** Testing context: madvise ***\n");
		c.collapse = &madvise_collapse;
		c.enforce_pte_scan_limits = false;

		collapse_full(&c);
		collapse_empty(&c);
		collapse_single_pte_entry(&c);
		collapse_max_ptes_none(&c);
		collapse_swapin_single_pte(&c);
		collapse_max_ptes_swap(&c);
		collapse_single_pte_entry_compound(&c);
		collapse_full_of_compound(&c);
		collapse_compound_extreme(&c);
		collapse_fork(&c);
		collapse_fork_compound(&c);
		collapse_max_ptes_shared(&c);
		madvise_collapse_existing_thps();
	}

	restore_settings(0);
}
