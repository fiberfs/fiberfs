/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "core/operations/fbr_operations.h"
#include "core/request/fbr_rlog.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"
#include "config/test/fbr_test_config_cmds.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/request/test/fbr_test_request_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

#define _OP_THREADS	4

static struct fbr_cstore *_CSTORE_C0_SHARED;
static struct fbr_cstore *_CSTORE_C1_S3;
static size_t _THREADS;
static size_t _MKDIR_SUCCESS;
static size_t _MKDIR_EXIST;
static size_t _CONFLICTS;

static void *
_op_thread(void *arg)
{
	(void)arg;

	size_t id = fbr_atomic_add(&_THREADS, 1);

	fbr_test_logs("*** op thread %zu running", id);

	struct fbr_fs *fs = fbr_test_fs_mock(NULL);
	fbr_fs_ok(fs);
	fbr_test_cstore_bind_new(fs);
	fbr_cstore_ok(fs->cstore);
	assert(fs->cstore_managed);
	fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);
	fbr_test_cstore_backend_add(fs->cstore, _CSTORE_C1_S3, FBR_CSTORE_ROUTE_S3);

	if (!(random() % 4) && 0) {
		fbr_test_cstore_backend_add(fs->cstore, _CSTORE_C0_SHARED, FBR_CSTORE_ROUTE_CLUSTER);
	} else {
		fbr_test_cstore_backend_add(fs->cstore, _CSTORE_C0_SHARED, FBR_CSTORE_ROUTE_CDN);
	}

	struct fbr_test_context *test_ctx = fbr_test_get_ctx();
	struct fbr_test_cstore *tcstore = fbr_test_tcstore_match(test_ctx, fs->cstore);

	struct fbr_request *request = fbr_test_request_mock();
	fbr_fuse_detached(request->fuse_ctx);

	request->fs = fs;

	fbr_request_valid(request);

	while (_THREADS < _OP_THREADS) {
		fbr_sleep_ms(0.1);
	}
	assert(_THREADS == _OP_THREADS);

	fbr_rlog(FBR_LOG_TEST, "OP_thread %zu cstore: %s", id, tcstore->prefix);

	struct fbr_directory *root = fbr_directory_load(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);

	char dirname[32];
	fbr_bprintf(dirname, "directory_%zu", id);

	fbr_rlog(FBR_LOG_TEST, "OP_thread %zu calling mkdir()", id);

	fbr_ops_mkdir(request, root->inode, dirname, 0);

	fbr_rlog(FBR_LOG_TEST, "OP_thread %zu mkdir() ret: %d", id, request->error);

	fbr_dindex_release(fs, &root);

	fbr_request_free(request);

	fbr_atomic_add(&_CONFLICTS, fs->stats.flush_conflicts);

	fbr_fs_free(fs);

	return NULL;
}

static void
_debug_cstores(void)
{
	fbr_test_logs("CSTORE_DEBUG OBJECT: cstore_c0_shared");
	fbr_test_cstore_debug(_CSTORE_C0_SHARED);
	fbr_test_logs("CSTORE_DEBUG OBJECT: cstore_c1_s3");
	fbr_test_cstore_debug(_CSTORE_C1_S3);
}

void
fbr_cmd_cstore_cluster_ops(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_random_seed();

	fbr_test_conf_add("LOG_SIZE", "1000000");
	fbr_test_conf_add("LOG_ALWAYS_FLUSH", "true");
	fbr_test_conf_add("ASYNC_WRITE", "false");
	fbr_test_conf_add("CSTORE_SERVER", "true");
	fbr_test_conf_add("CSTORE_SERVER_ADDRESS", "127.0.0.1");
	fbr_test_conf_add("CSTORE_SERVER_PORT", "0");
	fbr_test_conf_add("ALLOW_CDN_PUT", "true");
	fbr_test_conf_add("ALLOW_CDN_DELETE", "true");

	_CSTORE_C0_SHARED = fbr_test_cstore_init(ctx);
	fbr_cstore_ok(_CSTORE_C0_SHARED);

	_CSTORE_C1_S3 = fbr_test_cstore_init(ctx);
	fbr_cstore_ok(_CSTORE_C1_S3);
	fbr_cstore_s3_mock(_CSTORE_C1_S3, NULL, "NYC", "AccessKEY", "SECRET!@#");

	fbr_test_cstore_backend_add(_CSTORE_C0_SHARED, _CSTORE_C1_S3, FBR_CSTORE_ROUTE_S3);

	assert(fbr_test_cstore_count(ctx) == 2);

	fbr_test_conf_add("CSTORE_SERVER", NULL);

	struct fbr_fs *fs = fbr_test_fs_mock(ctx);
	fbr_fs_ok(fs);
	fbr_test_cstore_bind_new(fs);
	fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);
	fbr_test_cstore_backend_add(fs->cstore, _CSTORE_C0_SHARED, FBR_CSTORE_ROUTE_CDN);
	fbr_test_cstore_backend_add(fs->cstore, _CSTORE_C1_S3, FBR_CSTORE_ROUTE_S3);

	fbr_test_fs_root_alloc(fs);

	fbr_fs_free(fs);

	_debug_cstores();

	assert(_CSTORE_C0_SHARED->entries == 2);
	assert(_CSTORE_C0_SHARED->stats.wr_indexes == 1);
	assert(_CSTORE_C0_SHARED->stats.wr_roots == 1);
	assert(_CSTORE_C1_S3->entries == 2);
	assert(_CSTORE_C1_S3->stats.wr_indexes == 1);
	assert(_CSTORE_C1_S3->stats.wr_roots == 1);

	assert_zero(_THREADS);
	assert_zero(_MKDIR_SUCCESS);
	assert_zero(_MKDIR_EXIST);

	fbr_test_logs("*** starting %d threads", _OP_THREADS);

	pthread_t threads[_OP_THREADS];

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_create(&threads[i], NULL, _op_thread, NULL));
	}

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}
	assert(_THREADS == _OP_THREADS);

	_debug_cstores();

	fbr_test_logs("FLUSH_CONFLICTS: %zu", _CONFLICTS);

	assert(fbr_test_cstore_count(ctx) == 2 + 1 + _OP_THREADS);
	assert(_CSTORE_C1_S3->entries == 2 + (_OP_THREADS * 2));
	assert(_CSTORE_C1_S3->stats.wr_indexes == 1 + _OP_THREADS);
	assert(_CSTORE_C1_S3->stats.wr_roots == 1 + _OP_THREADS);

	assert_zero(_CSTORE_C1_S3->stats.http_500);
	assert_zero(_CSTORE_C0_SHARED->stats.http_500);

	fbr_request_pool_shutdown();

	_CSTORE_C0_SHARED = NULL;
	_CSTORE_C1_S3 = NULL;

	fbr_test_logs("cstore_cluster_ops done");
}
