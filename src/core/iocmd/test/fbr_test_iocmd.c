/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include "fiberfs.h"
#include "core/iocmd/fbr_cmd.h"

#include "test/fbr_test.h"

void
fbr_cmd_iocmd_ping(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	const char *path = cmd->params[0].value;

	int ret = fbr_cmd_ping(path);
	fbr_test_ERROR(ret, "fbr_iocmd_ping() failed: %d", ret);

	fbr_test_logs("iocmd_ping done: %s", path);
}

void
fbr_cmd_iocmd_import(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	assert(cmd->param_count >= 1 && cmd->param_count <= 2);
	fbr_test_ERROR_string(cmd->params[0].value);

	const char *path = cmd->params[0].value;
	int overwrite = 0;

	if (cmd->param_count > 1) {
		long value = fbr_test_parse_long(cmd->params[1].value);
		if (value > 0) {
			overwrite = 1;
		}
	}

	int ret = fbr_cmd_import(path, overwrite);
	fbr_test_ERROR(ret, "fbr_iocmd_import() failed: %d", ret);

	fbr_test_logs("iocmd_import done: %s", path);
}

void
fbr_cmd_iocmd_import_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);
	assert_zero(fbr_test_is_valgrind());

	const char *path = cmd->params[0].value;

	int ret = fbr_cmd_import(path, 0);
	fbr_test_ASSERT(ret, "fbr_iocmd_import() did not fail");

	fbr_test_logs("iocmd_import_error done: %s %d %s", path, ret, strerror(ret));
}
