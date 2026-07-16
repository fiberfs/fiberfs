/*
 * Copyright (c) 2021-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fiberfs.h"
#include "chttp.h"

#include "test/fbr_test.h"

int
main(int argc, char **argv)
{
	printf("chttp_client %s\n", CHTTP_VERSION);

	if (argc > 2) {
		printf("Usage: chttp_client [HTTP request file]");
		return 1;
	}

	int fd_input;

	if (argc == 2) {
		fd_input = open(argv[2], O_RDONLY);
	} else {
		fd_input = STDIN_FILENO;
	}

	fbr_ASSERT(fd_input >= 0, "Cannot get input");

	fbr_test_random_seed();

	assert_zero(close(fd_input));

	return 0;
}

// Required for fiber asserting
void
fbr_context_abort(int pre_abort)
{
	(void)pre_abort;
}

// Test stubs
// TODO clean this up so we can use the test lib and not define these
struct fbr_test_context *
fbr_test_get_ctx(void)
{
	fbr_ABORT("no test ctx");
}

int
fbr_test_is_forked(void)
{
	fbr_ABORT("no test ctx");
}

void
fbr_test_cleanup(void)
{
	fbr_ABORT("no test ctx");
}

void
fbr_test_force_error(void)
{
	fbr_ABORT("no test ctx");
}
