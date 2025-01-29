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

static void
_run_cmd(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd,
    struct fbr_test_cmdentry *cmd_entry)
{
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	assert(cmd->param_count > 0);
	assert(cmd_entry);
	assert(cmd_entry->magic == FBR_TEST_ENTRY_MAGIC);
	assert(cmd_entry->cmd_func);
	assert(cmd_entry->is_cmd);

	cmd->func = cmd_entry->cmd_func;

	for (size_t i = 1; i < cmd->param_count; i++) {
		cmd->params[i - 1] = cmd->params[i];
	}

	cmd->param_count--;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "vfork running local");

	cmd->func(ctx, cmd);
}

static void
_fork(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd, int skip_valgrind)
{
	struct fbr_test *test = fbr_test_convert(ctx);
	assert(test->prog_name);
	fbr_test_cmd_ok(cmd);

	fbr_test_ERROR(cmd->param_count == 0, "Need at least 1 parameter");
	fbr_test_ERROR_string(cmd->params[0].value);

	struct fbr_test_cmdentry *cmd_entry = fbr_test_cmds_get(test, cmd->params[0].value);
	fbr_test_ERROR(!cmd_entry || !cmd_entry->is_cmd, "command %s not found (line %zu)",
		cmd->params[0].value, fbr_test_line_pos(test));

	const char *valgrind = getenv("FIBER_VALGRIND");
	const char *flags = getenv("FIBER_FLAGS");
	const char *tmpdir = fbr_test_mkdir_tmp(ctx, NULL);

	if (valgrind && !*valgrind) {
		valgrind = NULL;
	}
	if (flags && !*flags) {
		flags = NULL;
	}

	if (!valgrind && skip_valgrind) {
		_run_cmd(ctx, cmd, cmd_entry);
		return;
	}

	char tstfile[PATH_MAX + 1];
	int ret = snprintf(tstfile, sizeof(tstfile), "%s/" _FORK_TST_FILE, tmpdir);
	fbr_test_ASSERT(ret < (int)sizeof(tstfile), "snprintf overflow %d", ret);

	FILE *f = fopen(tstfile, "w");
	fbr_test_ASSERT(f, "fopen failed");

	size_t bytes = fwrite(_FORK_TST_HEADER, 1, sizeof(_FORK_TST_HEADER) - 1, f);
	assert(bytes == sizeof(_FORK_TST_HEADER) - 1);

	for (size_t i = 0; i < cmd->param_count; i++) {
		if (i > 0) {
			bytes = fwrite(" ", 1, 1, f);
			assert(bytes == 1);
		}

		bytes = fwrite(cmd->params[i].value, 1, cmd->params[i].len, f);
		assert(bytes == cmd->params[i].len);
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

void
fbr_test_cmd_fork(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_fork(ctx, cmd, 0);
}

void
fbr_test_cmd_vfork(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_fork(ctx, cmd, 1);
}
