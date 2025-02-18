/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_test_fuse_cmds.h"
#include "core/fuse/fbr_fuse.h"
#include "test/fbr_test.h"

void
fbr_test_fuse_cmd_fuse_test_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, NULL);
	fbr_test_ERROR(ret, "Fuse mount failed: %s", cmd->params[0].value);

	struct fbr_fuse_context *fuse_ctx = fbr_fuse_callback_ctx();
	fbr_fuse_context_ok(fuse_ctx);
	fbr_fuse_context_ok(&ctx->test_fuse->fuse_ctx);
	assert(fuse_ctx == &ctx->test_fuse->fuse_ctx);
	fbr_test_ERROR(strcmp(cmd->params[0].value, fuse_ctx->path),
		"ctx->path error: %s", fuse_ctx->path);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse mounted: %s", cmd->params[0].value);
}

void
fbr_test_fuse_cmd_fuse_test_unmount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_fuse_test_unmount(ctx);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse unmounted");
}
