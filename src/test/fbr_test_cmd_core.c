/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "test/fbr_test.h"

void
fbr_test_cmd_fiber_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fbr_test *test = fbr_test_convert(ctx);
	fbr_test_ERROR_param_count(cmd, 1);
	fbr_test_ERROR(test->cmd_count != 1, "test file must begin with fiber_test");

	fbr_test_unescape(&cmd->params[0]);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "%s", cmd->params[0].value);
}

void
fbr_test_cmd_sleep_ms(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long ms = fbr_test_parse_long(cmd->params[0].value);
	fbr_test_ERROR(ms < 0, "invalid sleep time");

	fbr_test_sleep_ms(ms);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "slept %ldms", ms);
}

void
fbr_test_cmd_equal(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ERROR(cmd->param_count != 2, "need 2 parameters");

	int ret = strcmp(cmd->params[0].value, cmd->params[1].value);

	fbr_test_ERROR(ret, "not equal '%s' != '%s'", cmd->params[0].value, cmd->params[1].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "equal '%s'", cmd->params[0].value);
}

void
fbr_test_cmd_not_equal(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	int ret = strcmp(cmd->params[0].value, cmd->params[1].value);

	fbr_test_ERROR(!ret, "equal '%s' == '%s'", cmd->params[0].value, cmd->params[1].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "not equal '%s' != '%s'", cmd->params[0].value,
		cmd->params[1].value);
}

void
fbr_test_cmd_skip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_skip(ctx);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Skipping");
}

void
fbr_test_cmd_print(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);

	for (size_t i = 0; i < cmd->param_count; i++) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "%s", cmd->params[i].value);
	}
}

void
fbr_test_cmd_set_timeout_sec(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fbr_test *test = fbr_test_convert(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long timeout = fbr_test_parse_long(cmd->params[0].value);
	fbr_test_ERROR(timeout < 0, "invalid timeout");

	test->timeout_ms = timeout * 1000;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "timeout %ldms", test->timeout_ms);
}

void
fbr_test_cmd_shell(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "shell cmd: '%s'", cmd->params[0].value);

	int ret = system(cmd->params[0].value);

	fbr_test_ASSERT(WIFEXITED(ret), "shell cmd failed");
	fbr_test_ERROR(WEXITSTATUS(ret), "shell cmd returned an error");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "shell cmd passed");
}

void
fbr_test_cmd_skip_shell_failure(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "skip_shell cmd: '%s'", cmd->params[0].value);

	int ret = system(cmd->params[0].value);

	if (!WIFEXITED(ret) || WEXITSTATUS(ret)) {
		fbr_test_skip(ctx);
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "skip_shell cmd failed");
	} else {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "skip_shell cmd passed");
	}
}

void
fbr_test_cmd_skip_if_valgrind(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	const char *valgrind = getenv("FIBER_VALGRIND");

	if (valgrind && *valgrind) {
		fbr_test_skip(ctx);
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "valgrind detected, skipping");
	} else {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "valgrind not detected");
	}
}
