/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fiberfs.h"
#include "fuse/fbr_fuse.h"
#include "fuse/fbr_fuse_lowlevel.h"
#include "fuse/test/fbr_test_fuse_cmds.h"
#include "test/fbr_test.h"

int _TEST1_FUSE_STATE;

static void
_test1_init(void *userdata, struct fuse_conn_info *conn)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_mounted(ctx);
	assert(conn);
	assert_zero(_TEST1_FUSE_STATE);

	_TEST1_FUSE_STATE = 1;
}

static void
_test1_destroy(void *userdata)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_ctx_ok(ctx);
	assert(ctx->exited);
	assert(_TEST1_FUSE_STATE == 1);

	_TEST1_FUSE_STATE = 2;
}

static void
_test1_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "LOOKUP parent: %lu name: %s",
		parent, name);

	(void)fuse_reply_err(req, ENOENT);
}

static const struct fuse_lowlevel_ops _TEST1_FUSE_OPS = {
	.init = _test1_init,
	.destroy = _test1_destroy,
	.lookup = _test1_lookup
};

void
fbr_test_fuse_cmd_fuse_test1_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, &_TEST1_FUSE_OPS);
	fbr_test_ERROR(ret, "Fuse mount failed: %s", cmd->params[0].value);
	fbr_test_ASSERT(_TEST1_FUSE_STATE == 1, "init callback failed")

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse test1 mounted: %s", cmd->params[0].value);
}

void
fbr_test_fuse_cmd_fuse_test1_unmount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_fuse_test_unmount(ctx);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);

	assert(fuse_ctx->session);
	fuse_session_destroy(fuse_ctx->session);
	fuse_ctx->session = NULL;

	fbr_test_ASSERT(_TEST1_FUSE_STATE == 2, "destroy callback failed")

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse test1 unmounted");
}
