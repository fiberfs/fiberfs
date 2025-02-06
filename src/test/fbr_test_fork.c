/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test/fbr_test.h"

#define _FORK_TST_FILE		"fiber_fork.tst"
#define _FORK_TST_HEADER	"fiber_test fork_cmd\n"
#define _FORK_TST_FLAGS		"-k"

void
fbr_test_fork(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fbr_test *test = fbr_test_convert(ctx);
	assert(test->prog_name);
	fbr_test_cmd_ok(cmd);
	assert(cmd->name);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "forking: %s", cmd->name);

	const char *valgrind = getenv("FIBER_VALGRIND");
	const char *flags = getenv("FIBER_FLAGS");
	const char *tmpdir = fbr_test_mkdir_tmp(ctx, NULL);

	if (valgrind && !*valgrind) {
		valgrind = NULL;
	}
	if (flags && !*flags) {
		flags = NULL;
	}

	char tstfile[PATH_MAX + 1];
	int ret = snprintf(tstfile, sizeof(tstfile), "%s/" _FORK_TST_FILE, tmpdir);
	fbr_test_ASSERT(ret < (int)sizeof(tstfile), "snprintf overflow %d", ret);

	FILE *f = fopen(tstfile, "w");
	fbr_test_ASSERT(f, "fopen failed");

	size_t bytes = fwrite(_FORK_TST_HEADER, 1, sizeof(_FORK_TST_HEADER) - 1, f);
	assert(bytes == sizeof(_FORK_TST_HEADER) - 1);

	size_t len = strlen(cmd->name);
	bytes = fwrite(cmd->name, 1, len, f);
	assert(bytes == len);

	for (size_t i = 0; i < cmd->param_count; i++) {
		bytes = fwrite(" \"", 1, 2, f);
		assert(bytes == 2);

		bytes = fwrite(cmd->params[i].value, 1, cmd->params[i].len, f);
		assert(bytes == cmd->params[i].len);

		bytes = fwrite("\"", 1, 1, f);
		assert(bytes == 1);
	}

	bytes = fwrite("\n", 1, 1, f);
	assert(bytes == 1);

	ret = fclose(f);
	assert_zero(ret);

	char cmd_test[1024];
	ret = snprintf(cmd_test, sizeof(cmd_test),
		"%s%s%s %s%s%s%s%s",
		valgrind ? valgrind : "", valgrind ? " " : "",
		test->prog_name,
		flags ? flags : "", flags ? " " : "",
		_FORK_TST_FLAGS, strlen(_FORK_TST_FLAGS) ? " " : "",
		tstfile);
	fbr_test_ASSERT(ret < (int)sizeof(cmd_test), "snprintf cmd_test overflow %d", ret);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fork cmd: '%s'", cmd_test);

	ret = system(cmd_test);

	fbr_test_ASSERT(WIFEXITED(ret), "fork cmd failed");
	fbr_test_ERROR(WEXITSTATUS(ret), "fork cmd returned an error");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fork cmd passed");
}

int
fbr_test_can_fork(struct fbr_test_context *ctx)
{
	struct fbr_test *test = fbr_test_convert(ctx);

	if (test->forked) {
		return 0;
	}

	return 1;
}

int
fbr_test_can_vfork(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	if (!fbr_test_can_fork(ctx)) {
		return 0;
	}

	const char *valgrind = getenv("FIBER_VALGRIND");

	if (!valgrind || !*valgrind) {
		return 0;
	}

	return 1;
}
