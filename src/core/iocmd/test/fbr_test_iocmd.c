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
	fbr_ASSERT(ret, "fbr_iocmd_ping() failed: %d", ret);

	fbr_test_logs("iocmd_ping done: %s", path);
}

void
fbr_cmd_iocmd_import(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	const char *path = cmd->params[0].value;

	int ret = fbr_cmd_import(path);
	fbr_ASSERT(ret, "fbr_iocmd_import() failed: %d", ret);

	fbr_test_logs("iocmd_import done: %s", path);
}
