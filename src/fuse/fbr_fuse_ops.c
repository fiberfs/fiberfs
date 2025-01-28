/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fiberfs.h"
#include "fbr_fuse.h"
#include "fbr_fuse_lowlevel.h"

static void
_fuse_ops_init(void *userdata, struct fuse_conn_info *conn)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_mounted(ctx);
	assert(ctx->fuse_ops);
	assert(conn);

	fbr_fuse_running(ctx);

	if (ctx->fuse_ops->init) {
		ctx->fuse_ops->init(ctx, conn);
	}
}

static void
_fuse_ops_destroy(void *userdata)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_ctx_ok(ctx);
	assert(ctx->fuse_ops);

	if (ctx->fuse_ops->destroy) {
		ctx->fuse_ops->destroy(ctx);
	}
}

static const struct fuse_lowlevel_ops _FUSE_OPS = {
	.init = _fuse_ops_init,
	.destroy = _fuse_ops_destroy
};

const struct fuse_lowlevel_ops *FBR_FUSE_OPS = &_FUSE_OPS;
