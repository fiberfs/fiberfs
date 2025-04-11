/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse.h"
#include "core/request/fbr_request.h"

#include "test/fbr_test.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

static void
_debug_request_stats(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	fbr_test_logs("# debug fs.stats.request");
	fbr_test_logs("  fs.stats.requests_active=%lu", fs->stats.requests_active);
	fbr_test_logs("  fs.stats.requests_pooled=%lu", fs->stats.requests_pooled);
	fbr_test_logs("  fs.stats.requests_alloc=%lu", fs->stats.requests_alloc);
	fbr_test_logs("  fs.stats.requests_recycled=%lu", fs->stats.requests_recycled);
	fbr_test_logs("  fs.stats.requests_freed=%lu", fs->stats.requests_freed);
}

void
fbr_cmd_request_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fs *fs = fbr_test_fuse_mock(ctx);
	fbr_fs_ok(fs);

	_debug_request_stats(fs);

	assert_zero(fbr_request_get());

	fuse_req_t fuse_req = (fuse_req_t)1;

	struct fbr_request *r1 = fbr_request_alloc(fuse_req, __func__);
	fbr_request_ok(r1);
	assert(fbr_request_get() == r1);
	assert(fs->stats.requests_active == 1);
	assert(fs->stats.requests_pooled == 0);
	fbr_request_take_fuse(r1);
	fbr_request_free(r1);

	assert_zero(fbr_request_get());

	_debug_request_stats(fs);

	assert(fs->stats.requests_active == 0);
	assert(fs->stats.requests_pooled == 1);
	assert(fs->stats.requests_alloc == 1);
	assert(fs->stats.requests_recycled == 0);
	assert(fs->stats.requests_freed == 0);

	struct fbr_request *r2 = fbr_request_alloc(fuse_req, __func__);
	fbr_request_ok(r2);
	assert(fs->stats.requests_active == 1);
	assert(fs->stats.requests_pooled == 0);
	fbr_request_take_fuse(r2);
	fbr_request_free(r2);

	assert(fs->stats.requests_alloc == 1);
	assert(fs->stats.requests_recycled == 1);

	fbr_request_pool_shutdown(fs);

	assert(fs->stats.requests_alloc == fs->stats.requests_freed);

	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "request_test done");
}
