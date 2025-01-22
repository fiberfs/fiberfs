/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fuse/fbr_fuse.h"
#include "fuse/fbr_fuse_lowlevel.h"
#include "test/fbr_test.h"

static void
_test_init(void *userdata, struct fuse_conn_info *conn)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_ctx_ok(ctx);
	assert(conn);

	printf("ZZZ init called\n");
}

static const struct fuse_lowlevel_ops _test_ops = {
	.init = _test_init
};

int
fbr_fuse_test_mount(const char *path)
{
	struct fbr_fuse_context ctx;
	int ret;

	//fuse_cmdline_help();
	//fuse_lowlevel_help();

	fbr_fuse_init(&ctx);

	ctx.fuse_ops = &_test_ops;
	ctx.debug = 1;

	ret = fbr_fuse_mount(&ctx, path);

	if (ret) {
		return ret;
	}

	fbr_fuse_unmount(&ctx);

	return 0;
}

void
fbr_test_fuse_cmd_fuse_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	int ret;

	fbr_test_ERROR_param_count(cmd, 1);

	ret = fbr_fuse_test_mount(cmd->params[0].value);

	fbr_test_ERROR(ret, "Fuse mount failed: %s", cmd->params[0].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse passed: %s", cmd->params[0].value);
}
