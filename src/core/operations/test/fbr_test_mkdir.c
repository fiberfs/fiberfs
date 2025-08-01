/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/operations/fbr_operations.h"

#include "test/fbr_test.h"

void
fbr_cmd_mkdir_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "mkdir_test done");
}
