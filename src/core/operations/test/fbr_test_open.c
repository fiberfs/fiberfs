/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fiberfs.h"

#include "test/fbr_test.h"

void
fbr_cmd_open_exclusive_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	if (fbr_test_can_vfork(ctx)) {
		fbr_test_fork(ctx, cmd);
		return;
	}

	const char *filename = cmd->params[0].value;

	int fd = open(filename, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
	fbr_test_ASSERT(fd < 0, "open_exclusive_error open() didnt fail");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "open_exclusive_error passed %s (%d %s)",
		filename, fd, strerror(errno));
}
