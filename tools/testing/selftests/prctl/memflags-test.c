// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for prctl(PR_MEMALLOC_FLAGS, ...)
 *
 * Basic test to test behaviour of PR_MEMALLOC_FLAGS
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <inttypes.h>


#include <sys/prctl.h>
#include <linux/prctl.h>

#ifndef PR_MEMALLOC_FLAGS
/* Set task memalloc flags */
#define PR_MEMALLOC_FLAGS			1001
#define PR_MEMALLOC_GET_FLAGS			1
#define PR_MEMALLOC_SET_FLAGS			2
#define PR_MEMALLOC_CLEAR_FLAGS			3
#endif

#ifndef PF_MEMALLOC
#define PF_MEMALLOC             0x00000800      /* Allocating memory */
#endif

#ifndef PF_MEMALLOC_NOFS
#define PF_MEMALLOC_NOFS        0x00040000      /* All allocation requests will inherit GFP_NOFS */
#endif

#ifndef PF_MEMALLOC_NOIO
#define PF_MEMALLOC_NOIO        0x00080000      /* All allocation requests will inherit GFP_NOIO */
#endif

#ifndef PF_MEMALLOC_PIN
#define PF_MEMALLOC_PIN         0x10000000      /* Allocation context constrained to zones which allow long term pinning. */
#endif

void test_flag(int testflag, const char *flagname)
{
	int flags = prctl(PR_MEMALLOC_FLAGS, PR_MEMALLOC_SET_FLAGS, testflag);
	if (flags == -1) {
		fprintf(stdout, "SET_FLAGS (%s) == %d errno=%d\n", flagname,
			flags, errno);
		fflush(stdout);
		exit(EXIT_FAILURE);
	}
	flags = prctl(PR_MEMALLOC_FLAGS, PR_MEMALLOC_GET_FLAGS);
	if (flags != testflag) {
		fprintf(stdout, "SET_FLAGS (%s) success but not set : %d\n",
			flagname, flags);
		fprintf(stdout, "GET_FLAGS == %d\n", flags);
		exit(EXIT_FAILURE);
	}

	flags = prctl(PR_MEMALLOC_FLAGS, PR_MEMALLOC_CLEAR_FLAGS, testflag);
	if (flags == -1) {
		fprintf(stdout, "CLEAR_FLAGS (%s) == %d errno=%d\n",
			flagname, flags, errno);
		fflush(stdout);
		exit(EXIT_FAILURE);
	}
}

#define TESTFLAG(x) test_flag(x, #x)

int main(void)
{
	int flags;

	flags = prctl(PR_MEMALLOC_FLAGS, PR_MEMALLOC_GET_FLAGS);
	if (flags == -1) {
		fprintf(stdout, "GET_FLAGS errno=%d\n", errno);
		fflush(stdout);
		exit(EXIT_FAILURE);
	}

	flags = prctl(PR_MEMALLOC_FLAGS, PR_MEMALLOC_SET_FLAGS, 1);
	if (flags != -1) {
		fprintf(stdout, "SET_FLAGS (invalid) == %d errno=%d\n", flags,
			errno);
		fflush(stdout);
		exit(EXIT_FAILURE);
	}

	TESTFLAG(PF_MEMALLOC);
	TESTFLAG(PF_MEMALLOC_NOFS);
	TESTFLAG(PF_MEMALLOC_NOIO);
	TESTFLAG(PF_MEMALLOC_PIN);

	exit(EXIT_SUCCESS);
}
