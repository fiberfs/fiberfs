/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fuse/fbr_fuse.h"
#include "test/fbr_test.h"

void
fbr_test_cmd_fiber_test_fuse(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	int ret;

	fbr_test_ERROR_param_count(cmd, 0);

	ret = fbr_fuse_test_mount();

	fbr_test_ERROR(ret, "Fuse mount failed");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fiber mount");
}
