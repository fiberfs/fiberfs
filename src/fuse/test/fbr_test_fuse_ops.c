/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fiberfs.h"
#include "fuse/fbr_fuse.h"
#include "fuse/fbr_fuse_lowlevel.h"

int _TEST_FUSE_STATE;

static void
_test_init(void *userdata, struct fuse_conn_info *conn)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_mounted(ctx);
	assert(conn);
	assert_zero(_TEST_FUSE_STATE);

	_TEST_FUSE_STATE = 1;
}

static void
_test_destroy(void *userdata)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_ctx_ok(ctx);
	assert(ctx->exited);
	assert(_TEST_FUSE_STATE == 1);

	_TEST_FUSE_STATE = 2;
}

static const struct fuse_lowlevel_ops _TEST_FUSE_OPS = {
	.init = _test_init,
	.destroy = _test_destroy
};

const struct fuse_lowlevel_ops *TEST_FUSE_OPS = &_TEST_FUSE_OPS;
