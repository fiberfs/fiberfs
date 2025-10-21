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

static char TEST_COUNTER_STR[32];
static unsigned int TEST_COUNTER_VALUE;

void
fbr_cmd_fiber_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fbr_test *test = fbr_test_convert(ctx);
	fbr_test_ERROR_param_count(cmd, 1);
	fbr_test_ERROR(test->cmd_count != 1, "test file must begin with fiber_test");

	fbr_test_unescape(&cmd->params[0]);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "%s", cmd->params[0].value);
}

void
fbr_cmd_sleep_ms(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long ms = fbr_test_parse_long(cmd->params[0].value);
	fbr_test_ERROR(ms < 0, "invalid sleep time");

	fbr_test_sleep_ms(ms);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "slept %ldms", ms);
}

void
fbr_cmd_equal(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ERROR(cmd->param_count != 2, "need 2 parameters");

	int ret;
	size_t retries = 0;

	char *v1 = cmd->params[0].value;
	char *v2 = cmd->params[1].value;
	char *v1_var = cmd->params[0].variable;
	char *v2_var = cmd->params[1].variable;

	while (1) {
		ret = strcmp(v1, v2);

		if (!ret) {
			break;
		} else if (!v1_var && !v2_var) {
			break;
		} else if (retries >= 3) {
			break;
		}

		fbr_test_log(ctx, FBR_LOG_VERBOSE, "not equal '%s' != '%s', retry...", v1, v2);

		retries++;
		fbr_test_sleep_ms(200 * retries);

		if (v1_var) {
			v1 = fbr_test_read_var(ctx->test, v1_var);
			assert(v1);
		}
		if (v2_var) {
			v2 = fbr_test_read_var(ctx->test, v2_var);
			assert(v2);
		}
	}

	fbr_test_ERROR(ret, "not equal '%s' != '%s'", v1, v2);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "equal '%s'", v1);
}

void
fbr_cmd_not_equal(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	int ret = strcmp(cmd->params[0].value, cmd->params[1].value);

	fbr_test_ERROR(!ret, "equal '%s' == '%s'", cmd->params[0].value, cmd->params[1].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "not equal '%s' != '%s'", cmd->params[0].value,
		cmd->params[1].value);
}

static void
_compare_values(struct fbr_test_context *ctx, const char *s1, const char *s2,
    const char *cmd)
{
	fbr_test_ERROR_string(cmd);

	long l1 = fbr_test_parse_long(s1);
	long l2 = fbr_test_parse_long(s2);

	int passed = 0;

	if (!strcmp(cmd, "greater_than")) {
		passed = (l1 > l2);
	} else if (!strcmp(cmd, "greater_equal")) {
		passed = (l1 >= l2);
	} else if (!strcmp(cmd, "less_than")) {
		passed = (l1 < l2);
	} else if (!strcmp(cmd, "less_equal")) {
		passed = (l1 <= l2);
	}

	fbr_test_ASSERT(passed, "%s: '%s','%s' FAILED", cmd, s1, s2);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "%s %s,%s", cmd, s1, s2);
}

void
fbr_cmd_greater_than(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	_compare_values(ctx, cmd->params[0].value, cmd->params[1].value, cmd->name);
}

void
fbr_cmd_greater_equal(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	_compare_values(ctx, cmd->params[0].value, cmd->params[1].value, cmd->name);
}

void
fbr_cmd_less_than(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	_compare_values(ctx, cmd->params[0].value, cmd->params[1].value, cmd->name);
}

void
fbr_cmd_less_equal(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	_compare_values(ctx, cmd->params[0].value, cmd->params[1].value, cmd->name);
}

void
fbr_cmd_skip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_skip(ctx);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Skipping");
}

void
fbr_cmd_print(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);

	for (size_t i = 0; i < cmd->param_count; i++) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "%s", cmd->params[i].value);
	}
}

void
fbr_cmd_set_timeout_sec(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fbr_test *test = fbr_test_convert(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long timeout = fbr_test_parse_long(cmd->params[0].value);
	fbr_test_ERROR(timeout < 0, "invalid timeout");

	unsigned long timeout_ms = timeout * 1000;

	if (timeout < FBR_TEST_DEFAULT_TIMEOUT_SEC) {
		test->timeout_ms = timeout_ms;
	} else if (timeout_ms > test->timeout_ms) {
		test->timeout_ms = timeout_ms;
	}

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "timeout %ldms", test->timeout_ms);
}

void
fbr_cmd_skip_if_valgrind(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	if (fbr_test_is_valgrind()) {
		fbr_test_skip(ctx);
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "valgrind detected, skipping");
	} else {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "valgrind not detected");
	}
}

char *
fbr_var_test_counter(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	fbr_atomic_add(&TEST_COUNTER_VALUE, 1);

	fbr_bprintf(TEST_COUNTER_STR, "%u", TEST_COUNTER_VALUE);

	return TEST_COUNTER_STR;
}
