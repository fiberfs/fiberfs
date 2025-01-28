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

static void
_fuse_ops_access(fuse_req_t req, fuse_ino_t ino, int mask)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->access) {
		ctx->fuse_ops->access(req, ino, mask);
	} else {
		(void)fuse_reply_err(req, ENOSYS);
	}
}

static void
_fuse_ops_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	if (ctx->fuse_ops->lookup) {
		ctx->fuse_ops->lookup(req, parent, name);
	} else {
		(void)fuse_reply_err(req, ENOSYS);
	}
}

static const struct fuse_lowlevel_ops _FUSE_OPS = {
	.init = _fuse_ops_init,
	.destroy = _fuse_ops_destroy,
	.access = _fuse_ops_access,
	.lookup = _fuse_ops_lookup
};

const struct fuse_lowlevel_ops *FBR_FUSE_OPS = &_FUSE_OPS;
