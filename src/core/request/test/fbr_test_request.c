/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>

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

	assert_zero(fbr_request_get());

	fuse_req_t fuse_req = (fuse_req_t)1;

	struct fbr_request *r1 = fbr_request_alloc(fuse_req, __func__);
	fbr_request_ok(r1);
	r1->not_fuse = 1;
	assert(fbr_request_get() == r1);
	assert(fs->stats.requests_active == 1);
	assert(fs->stats.requests_pooled == 0);
	fbr_request_take_fuse(r1);
	fbr_request_free(r1);

	_debug_request_stats(fs);

	assert_zero(fbr_request_get());

	assert(fs->stats.requests_active == 0);
	assert(fs->stats.requests_pooled == 1);
	assert(fs->stats.requests_alloc == 1);
	assert(fs->stats.requests_recycled == 0);
	assert(fs->stats.requests_freed == 0);

	struct fbr_request *r2 = fbr_request_alloc(fuse_req, __func__);
	fbr_request_ok(r2);
	r2->not_fuse = 1;
	assert(fs->stats.requests_active == 1);
	assert(fs->stats.requests_pooled == 0);
	fbr_request_take_fuse(r2);

	char *buf = fbr_workspace_rbuffer(r2->workspace);
	size_t buf_len = fbr_workspace_rlen(r2->workspace);
	assert(buf_len >= FBR_WORKSPACE_MIN_SIZE);
	memset(buf, 1, buf_len);
	fbr_workspace_ralloc(r2->workspace, 0);

	fbr_request_free(r2);

	_debug_request_stats(fs);

	assert(fs->stats.requests_alloc == 1);
	assert(fs->stats.requests_recycled == 1);

	fbr_request_pool_shutdown(fs);

	assert_zero(fs->stats.requests_pooled);
	assert(fs->stats.requests_alloc == fs->stats.requests_freed);

	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "request_test done");
}

#define _TEST_REQUEST_THREADS 100
volatile size_t _TEST_REQUEST_THREAD_ID;

static void *
_test_request_thread(void *arg)
{
	assert_zero(arg);

	size_t id = fbr_atomic_add(&_TEST_REQUEST_THREAD_ID, 1);
	assert(id <= _TEST_REQUEST_THREADS);

	while (_TEST_REQUEST_THREAD_ID < _TEST_REQUEST_THREADS) {
		fbr_sleep_ms(1);
	}
	assert(_TEST_REQUEST_THREAD_ID >= _TEST_REQUEST_THREADS);

	fbr_test_logs("** thread %zu running", id);

	fuse_req_t fuse_req = (fuse_req_t)1;

	struct fbr_request *r1 = fbr_request_alloc(fuse_req, __func__);
	fbr_request_ok(r1);
	r1->not_fuse = 1;
	assert(fbr_request_get() == r1);

	char *buf = fbr_workspace_rbuffer(r1->workspace);
	size_t buf_len = fbr_workspace_rlen(r1->workspace);
	assert(buf_len >= FBR_WORKSPACE_MIN_SIZE);
	memset(buf, 1, buf_len);

	fbr_atomic_add(&_TEST_REQUEST_THREAD_ID, 1);

	while (_TEST_REQUEST_THREAD_ID < _TEST_REQUEST_THREADS * 2) {
		fbr_sleep_ms(1);
	}
	assert(_TEST_REQUEST_THREAD_ID == _TEST_REQUEST_THREADS * 2);

	fbr_request_take_fuse(r1);
	fbr_request_free(r1);

	assert_zero(fbr_request_get());

	struct fbr_request *r2 = fbr_request_alloc(fuse_req, __func__);
	fbr_request_ok(r2);
	r2->not_fuse = 1;
	fbr_request_take_fuse(r2);
	assert(fbr_request_get() == r2);

	buf = fbr_workspace_rbuffer(r2->workspace);
	buf_len = fbr_workspace_rlen(r2->workspace);
	assert(buf_len >= FBR_WORKSPACE_MIN_SIZE);
	memset(buf, 1, buf_len);
	fbr_workspace_ralloc(r2->workspace, FBR_WORKSPACE_MIN_SIZE / 10);

	fbr_request_free(r2);

	assert_zero(fbr_request_get());

	return NULL;
}

void
fbr_cmd_request_test_thread(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);
	assert(_TEST_REQUEST_THREADS > FBR_REQUEST_POOL_MAX_SIZE);

	struct fbr_fs *fs = fbr_test_fuse_mock(ctx);
	fbr_fs_ok(fs);

	pthread_t threads[_TEST_REQUEST_THREADS];
	_TEST_REQUEST_THREAD_ID = 0;
	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_create(&threads[i], NULL, _test_request_thread, NULL));
	}
	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}
	assert(_TEST_REQUEST_THREAD_ID == _TEST_REQUEST_THREADS * 2);

	assert_zero(fbr_request_get());

	_debug_request_stats(fs);

	assert(fs->stats.requests_active == 0);
	assert(fs->stats.requests_pooled == FBR_REQUEST_POOL_MAX_SIZE);
	assert(fs->stats.requests_alloc >= _TEST_REQUEST_THREADS);
	assert(fs->stats.requests_recycled >= FBR_REQUEST_POOL_MAX_SIZE);
	assert(fs->stats.requests_freed >= _TEST_REQUEST_THREADS - FBR_REQUEST_POOL_MAX_SIZE);

	fbr_request_pool_shutdown(fs);

	assert_zero(fs->stats.requests_pooled);
	assert(fs->stats.requests_alloc == fs->stats.requests_freed);

	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "request_test_thread done");
}

void
fbr_cmd_request_test_active(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fs *fs = fbr_test_fuse_mock(ctx);
	fbr_fs_ok(fs);

	fuse_req_t fuse_req = (fuse_req_t)1;

	struct fbr_request *r1 = fbr_request_alloc(fuse_req, __func__);
	fbr_request_ok(r1);
	r1->not_fuse = 1;
	assert(fbr_request_get() == r1);
	fbr_request_take_fuse(r1);
	fbr_ZERO(&r1->thread);
	assert(fs->stats.requests_active == 1);

	fbr_request_pool_shutdown(fs);

	fbr_request_free(r1);

	_debug_request_stats(fs);

	assert(fs->stats.requests_active == 0);
	assert(fs->stats.requests_pooled == 1);
	assert(fs->stats.requests_alloc == 1);
	assert(fs->stats.requests_recycled == 0);
	assert(fs->stats.requests_freed == 0);

	fbr_request_pool_shutdown(fs);

	assert_zero(fs->stats.requests_pooled);
	assert(fs->stats.requests_alloc == fs->stats.requests_freed);

	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "request_test_active done");
}
