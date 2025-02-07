/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fiberfs.h"
#include "fbr_test_fuse_cmds.h"
#include "core/fbr_core_fs.h"
#include "fuse/fbr_fuse.h"
#include "fuse/fbr_fuse_lowlevel.h"

static void
_test_sim_init(void *userdata, struct fuse_conn_info *conn)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_mounted(ctx);
	assert(conn);

	assert_zero(ctx->root);

	ctx->root = fbr_directory_root_alloc();
	fbr_directory_ok(ctx->root);

	struct fbr_file *file = fbr_file_alloc_nolen("fiber1");

	fbr_directory_add(ctx->root, file);

	file = fbr_file_alloc_nolen("fiber2");

	fbr_directory_add(ctx->root, file);
}

static const struct fuse_lowlevel_ops _TEST_SIM_FUSE_OPS = {
	.init = _test_sim_init
};

void
fbr_test_fuse_cmd_fuse_test_sim_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, &_TEST_SIM_FUSE_OPS);
	fbr_test_ERROR(ret, "Fuse mount failed: %s", cmd->params[0].value);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	fbr_directory_ok(fuse_ctx->root);
	assert_zero(fbr_filename_get(&fuse_ctx->root->dirname));

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse test_sim mounted: %s", cmd->params[0].value);
}
