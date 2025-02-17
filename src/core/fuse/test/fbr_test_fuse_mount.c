/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_test_fuse_cmds.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_callback.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "test/fbr_test.h"

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
	fbr_test_ERROR(fuse_ctx->error, "Fuse error detected");

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
fbr_test_fuse_cmd_fuse_test_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, NULL);
	fbr_test_ERROR(ret, "Fuse mount failed: %s", cmd->params[0].value);

	struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_ctx(NULL);
	fbr_fuse_context_ok(fuse_ctx);
	fbr_fuse_context_ok(&ctx->test_fuse->fuse_ctx);
	assert(fuse_ctx == &ctx->test_fuse->fuse_ctx);
	fbr_test_ERROR(strcmp(cmd->params[0].value, fuse_ctx->path),
		"ctx->path error: %s", fuse_ctx->path);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse mounted: %s", cmd->params[0].value);
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

void
fbr_test_fuse_cmd_fuse_test_unmount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_fuse_test_unmount(ctx);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse unmounted");
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

// TODO this goes away
void __fbr_attr_printf(4)
fbr_test_fuse_ERROR(int condition, struct fbr_fuse_context *ctx, void *req,
    const char *fmt, ...)
{
	fbr_fuse_context_ok(ctx);

	if (!condition) {
		return;
	}

	printf("ERROR: ");

	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	printf("\n");

	fbr_test_force_error();

	fbr_fuse_abort(ctx);

	if (req) {
		fuse_req_t freq = (fuse_req_t) req;
		(void)fuse_reply_err(freq, EIO);
	}

	pthread_exit(NULL);
}
