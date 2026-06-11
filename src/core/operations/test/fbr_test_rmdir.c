/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <errno.h>
#include <unistd.h>

#include "fiberfs.h"

#include "test/fbr_test.h"

void
fbr_cmd_rmdir_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	if (fbr_test_can_vfork(ctx)) {
		fbr_test_fork(ctx, cmd);
		return;
	}

	const char *filename = cmd->params[0].value;

	int ret = rmdir(filename);
	fbr_ASSERT(ret, "rmdir() didnt fail");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sys_rmdir_error() passed %s (%d)",
		strerror(errno), ret);
}
