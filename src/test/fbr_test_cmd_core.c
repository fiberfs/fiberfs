/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "test/fbr_test.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>

void
fbr_test_cmd_fiber_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fbr_test *test;

	test = fbr_test_convert(ctx);
	fbr_test_ERROR_param_count(cmd, 1);
	fbr_test_ERROR(test->cmd_count != 1, "test file must begin with fiber_test");

	fbr_test_unescape(&cmd->params[0]);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "%s", cmd->params[0].value);
}

void
fbr_test_cmd_sleep_ms(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	long ms;

	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	ms = fbr_test_parse_long(cmd->params[0].value);
	fbr_test_ERROR(ms < 0, "invalid sleep time");

	fbr_test_sleep_ms(ms);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "slept %ldms", ms);
}

void
fbr_test_cmd_equal(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	int ret;

	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	ret = strcmp(cmd->params[0].value, cmd->params[1].value);

	fbr_test_ERROR(ret, "not equal '%s' != '%s'", cmd->params[0].value, cmd->params[1].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "equal '%s'", cmd->params[0].value);
}

void
fbr_test_cmd_not_equal(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	int ret;

	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	ret = strcmp(cmd->params[0].value, cmd->params[1].value);

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
	size_t i;

	fbr_test_context_ok(ctx);

	for (i = 0; i < cmd->param_count; i++) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "%s", cmd->params[i].value);
	}
}
