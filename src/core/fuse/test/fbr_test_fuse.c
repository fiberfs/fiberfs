/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "core/request/fbr_request.h"
#include "log/fbr_log.h"

#include "test/fbr_test.h"
#include "fbr_test_fuse_cmds.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "log/test/fbr_test_log_cmds.h"

extern struct fbr_fuse_context *_FUSE_CTX;

static void
_fuse_finish(struct fbr_test_context *test_ctx)
{
	fbr_test_context_ok(test_ctx);
	fbr_magic_check(test_ctx->test_fuse, FBR_TEST_FUSE_MAGIC);

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
	assert_zero(fbr_request_get());

	if (!test_ctx->test_fuse) {
		struct fbr_test_fuse *test_fuse = malloc(sizeof(*test_fuse));
		assert(test_fuse);

		fbr_ZERO(test_fuse);
		test_fuse->magic = FBR_TEST_FUSE_MAGIC;

		test_ctx->test_fuse = test_fuse;

		fbr_test_register_finish(test_ctx, "test_fuse", _fuse_finish);
	}

	fbr_magic_check(test_ctx->test_fuse, FBR_TEST_FUSE_MAGIC);

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

	fbr_test_log_printer_init(test_ctx, path, "#");

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
	fbr_magic_check(test_ctx->test_fuse, FBR_TEST_FUSE_MAGIC);

	struct fbr_fuse_context *fuse_ctx = &test_ctx->test_fuse->fuse_ctx;
	fbr_fuse_context_ok(fuse_ctx);

	return fuse_ctx;
}

void
fbr_test_fuse_mock(struct fbr_test_context *test_ctx)
{
	fbr_test_context_ok(test_ctx);

	struct fbr_fuse_context *fuse_ctx = _fuse_init(test_ctx);
	if (!fuse_ctx->init) {
		fbr_fuse_init(fuse_ctx);
		_FUSE_CTX = fuse_ctx;
		assert(fuse_ctx->init);
	} else {
		fbr_fuse_context_ok(fuse_ctx);
		return;
	}
	assert(fbr_fuse_get_context() == fuse_ctx);
	assert(fbr_test_fuse_get_ctx(test_ctx) == fuse_ctx);
	assert_zero(fuse_ctx->path);
	assert_zero(fuse_ctx->log);

	fbr_test_random_seed();

	char mock_name[100];
	int ret = snprintf(mock_name, sizeof(mock_name), "/fuse/mock/%ld/%d", random(),
		getpid());
	assert(ret > 0 && (size_t)ret < sizeof(mock_name));
	fuse_ctx->path = strdup(mock_name);
	assert(fuse_ctx->path);

	fuse_ctx->log = fbr_log_alloc(fuse_ctx->path, fbr_log_default_size());
	fbr_log_ok(fuse_ctx->log);

	fbr_test_log_printer_init(test_ctx, fuse_ctx->path, "#");
}

struct fbr_fs *
fbr_test_fuse_mock_fs(struct fbr_test_context *test_ctx)
{
	if (!test_ctx) {
		test_ctx = fbr_test_get_ctx();
	}
	fbr_test_context_ok(test_ctx);

	fbr_test_fuse_mock(test_ctx);

	struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_context();
	fbr_fuse_context_ok(fuse_ctx);

	fuse_ctx->fs = fbr_test_fs_alloc();
	fbr_fs_ok(fuse_ctx->fs);

	return fuse_ctx->fs;
}

void
fbr_test_fuse_root_alloc(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);
	assert_zero(root->generation);

	root->generation = 1;

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, root, NULL, NULL, NULL, FBR_FLUSH_NONE);

	int ret = fbr_index_write(fs, &index_data);
	fbr_ASSERT(!ret, "fbr_index_write() root failed: %d", ret);

	fbr_directory_set_state(fs, root, FBR_DIRSTATE_OK);

	fbr_index_data_free(&index_data);
	fbr_dindex_release(fs, &root);
}
