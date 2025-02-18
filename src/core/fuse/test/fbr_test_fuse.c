/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "test/fbr_test.h"
#include "fbr_test_fuse_cmds.h"

#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "core/callback/fbr_callback.h"

static struct fbr_test_context *_TEST_CTX;

static void
_fuse_finish(struct fbr_test_context *test_ctx)
{
	fbr_test_context_ok(test_ctx);
	fbr_test_context_ok(_TEST_CTX);
	assert(test_ctx->test_fuse);
	assert(test_ctx->test_fuse->magic == FBR_TEST_FUSE_MAGIC);

	_TEST_CTX = NULL;

	struct fbr_fuse_context *fuse_ctx = &test_ctx->test_fuse->fuse_ctx;
	fbr_fuse_context_ok(fuse_ctx);

	fbr_fuse_unmount(fuse_ctx);
	fbr_finish_ERROR(fuse_ctx->error, "fuse context has an error flag");

	fbr_fuse_free(fuse_ctx);

	fbr_ZERO(test_ctx->test_fuse);
	free(test_ctx->test_fuse);

	test_ctx->test_fuse = NULL;
}

static struct fbr_fuse_context *
_fuse_init(struct fbr_test_context *test_ctx)
{
	fbr_test_context_ok(test_ctx);

	if (!test_ctx->test_fuse) {
		struct fbr_test_fuse *test_fuse = malloc(sizeof(*test_fuse));
		assert(test_fuse);

		test_fuse->magic = FBR_TEST_FUSE_MAGIC;

		test_ctx->test_fuse = test_fuse;

		fbr_test_register_finish(test_ctx, "test_fuse", _fuse_finish);

		_TEST_CTX = test_ctx;
	}

	assert(test_ctx->test_fuse->magic == FBR_TEST_FUSE_MAGIC);
	fbr_test_context_ok(_TEST_CTX);

	return &test_ctx->test_fuse->fuse_ctx;
}

static const struct fbr_fuse_callbacks _TEST_FUSE_CALLBACKS_EMPTY;

int
fbr_fuse_test_mount(struct fbr_test_context *test_ctx, const char *path,
    const struct fbr_fuse_callbacks *fuse_callbacks)
{
	struct fbr_fuse_context *ctx = _fuse_init(test_ctx);
	struct fbr_test *test = fbr_test_convert(test_ctx);

	fbr_fuse_init(ctx);

	if (fuse_callbacks) {
		ctx->fuse_callbacks = fuse_callbacks;
	} else {
		ctx->fuse_callbacks = &_TEST_FUSE_CALLBACKS_EMPTY;
	}

	if (test->verbocity >= FBR_LOG_VERBOSE) {
		ctx->debug = 1;
	}

	int ret = fbr_fuse_mount(ctx, path);

	if (ret) {
		return ret;
	}

	return ctx->error;
}

void
fbr_fuse_test_unmount(struct fbr_test_context *test_ctx)
{
	struct fbr_fuse_context *ctx = _fuse_init(test_ctx);
	fbr_fuse_context_ok(ctx);

	fbr_fuse_unmount(ctx);

	assert(ctx->state == FBR_FUSE_NONE);

	int error = ctx->error;
	ctx->error = 0;
	fbr_test_ERROR(error, "Fuse error detected");
}

struct fbr_fuse_context *
fbr_test_fuse_get_ctx(struct fbr_test_context *test_ctx)
{
	fbr_test_context_ok(test_ctx);

	struct fbr_fuse_context *fuse_ctx = &test_ctx->test_fuse->fuse_ctx;
	fbr_fuse_context_ok(fuse_ctx);

	return fuse_ctx;
}

struct fbr_test_context *
fbr_test_fuse_ctx(void)
{
	fbr_test_context_ok(_TEST_CTX);
	return _TEST_CTX;
}
