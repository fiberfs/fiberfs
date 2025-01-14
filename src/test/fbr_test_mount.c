/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "test/fbr_test.h"

void
fbr_test_cmd_fiber_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fiber mount");
}
