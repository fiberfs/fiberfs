/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fuse/fbr_fuse.h"
#include "fuse/fbr_fuse_lowlevel.h"
#include "fuse/test/fbr_test_fuse_cmds.h"
#include "test/fbr_test.h"

struct fbr_test_fuse {
	unsigned int			magic;
#define _FUSE_MAGIC			0x323EF113

	struct fbr_fuse_context		ctx;
};

static void
_fuse_finish(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	assert(ctx->fuse);
	assert(ctx->fuse->magic == _FUSE_MAGIC);

	struct fbr_fuse_context *fctx = &ctx->fuse->ctx;
	fbr_fuse_ctx_ok(fctx);

	fbr_fuse_unmount(fctx);
	fbr_fuse_free(fctx);

	fbr_ZERO(ctx->fuse);
	free(ctx->fuse);

	ctx->fuse = NULL;
}

static void
_fuse_init(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	if (!ctx->fuse) {
		struct fbr_test_fuse *fuse = malloc(sizeof(*fuse));
		assert(fuse);

		fuse->magic = _FUSE_MAGIC;

		ctx->fuse = fuse;

		fbr_test_register_finish(ctx, "fuse", _fuse_finish);
	}

	assert(ctx->fuse->magic == _FUSE_MAGIC);
}

static int
_fuse_test_mount(struct fbr_fuse_context *ctx, const char *path, int debug)
{
	assert_zero(_TEST_FUSE_STATE);

	//fuse_cmdline_help();
	//fuse_lowlevel_help();

	fbr_fuse_init(ctx);

	ctx->fuse_ops = TEST_FUSE_OPS;
	//ctx->sighandle = 1;

	if (debug) {
		ctx->debug = 1;
	}

	int ret = fbr_fuse_mount(ctx, path);

	if (ret) {
		return ret;
	}

	fbr_test_ASSERT(_TEST_FUSE_STATE == 1, "Init callback is broken");

	return ctx->error;
}

static int
_fuse_test_unmount(struct fbr_fuse_context *ctx)
{
	assert(_TEST_FUSE_STATE == 1);
	fbr_fuse_ctx_ok(ctx);

	fbr_fuse_unmount(ctx);

	assert(ctx->state == FBR_FUSE_NONE);

	assert(ctx->session);
	fuse_session_destroy(ctx->session);
	ctx->session = NULL;

	fbr_test_ASSERT(_TEST_FUSE_STATE == 2, "Destroy callback is broken");

	return ctx->error;
}

void
fbr_test_fuse_cmd_fuse_test_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_fuse_init(ctx);

	struct fbr_test *test = fbr_test_convert(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = _fuse_test_mount(&ctx->fuse->ctx, cmd->params[0].value,
		test->verbocity >= FBR_LOG_VERBOSE);

	fbr_fuse_ctx_ok(&ctx->fuse->ctx);

	fbr_test_ERROR(ret, "Fuse mount failed: %s", cmd->params[0].value);
	fbr_test_ERROR(strcmp(cmd->params[0].value, ctx->fuse->ctx.path),
		"ctx->path error: %s", ctx->fuse->ctx.path);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse passed: %s", cmd->params[0].value);
}

void
fbr_test_fuse_cmd_fuse_test_unmount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_fuse_init(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	int ret = _fuse_test_unmount(&ctx->fuse->ctx);

	fbr_test_ERROR(ret, "Fuse unmount failed: %s", cmd->params[0].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse unmounted");
}
