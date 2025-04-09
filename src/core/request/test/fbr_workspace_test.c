/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "core/request/fbr_workspace.h"

#include "test/fbr_test.h"
#include "fbr_test_request_cmds.h"

void
fbr_cmd_workspace_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "workspace_test done");
}
