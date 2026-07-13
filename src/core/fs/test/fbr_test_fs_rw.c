/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <limits.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/operations/fbr_operations.h"
#include "core/request/fbr_request.h"
#include "core/store/fbr_store.h"
#include "cstore/fbr_cstore_callback.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/request/test/fbr_test_request_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"
#include "log/test/fbr_test_log_cmds.h"

static void
_test_fs_rw_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	assert_zero(ctx->detached);
	fbr_fs_ok(ctx->fs);
	assert(conn);

	struct fbr_test_context *test_ctx = fbr_test_get_ctx();

	if (fbr_test_cstore_count(test_ctx)) {
		fbr_test_cstore_bind(ctx->fs, 0);
	} else {
		fbr_test_cstore_bind_new(ctx->fs);
	}

	fbr_fs_set_store(ctx->fs, FBR_CSTORE_DEFAULT_CALLBACKS);

	int autoinit = fbr_conf_get_bool("TEST_AUTOINIT", FBR_CONFIG_FALSE);
	if (autoinit) {
		fbr_cstore_autoinit(ctx->fs->cstore);
	}

	//ctx->log->always_flush = 1;

	// TODO these
	//conn->max_readahead
	//conn->max_background
	//FUSE_CAP_POSIX_ACL
	//FUSE_CAP_HANDLE_KILLPRIV

	fbr_fuse_setup(ctx, conn);

	struct fbr_request *request = fbr_request_alloc(NULL, __func__);
	fbr_request_ok(request);
	assert_zero(request->not_fuse);

	fbr_test_fs_root_alloc(ctx->fs);

	struct fbr_directory *root = fbr_dindex_take(ctx->fs, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);

	fbr_test_cstore_wait(ctx->fs->cstore);

	struct fbr_directory *root_new = fbr_directory_alloc(ctx->fs, FBR_DIRNAME_ROOT,
		FBR_INODE_ROOT);
	fbr_directory_ok(root_new);
	assert(root_new->state == FBR_DIRSTATE_LOADING);

	fbr_id_t root_id = fbr_cstore_root_read(ctx->fs, root_new, 0);

	fbr_test_logs("INIT fbr_cstore_root_read(): %lu", root_id);
	fbr_ASSERT(root_id == root->version, "root version mismatch, found %lu, expected %lu",
		root_id, root->version);
	fbr_ASSERT(root->etag.length == root_new->etag.length &&
		!strcmp(root->etag.value, root_new->etag.value),
		"root etag mismatch, found '%s', expected '%s'",
		root_new->etag.value, root->etag.value);

	fbr_directory_set_state(ctx->fs, root_new, FBR_DIRSTATE_ERROR);

	fbr_dindex_release(ctx->fs, &root_new);
	fbr_dindex_release(ctx->fs, &root);
	fbr_request_free(request);
}

void
fbr_cmd_fs_test_rw_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	const char *mount = cmd->params[0].value;

	int ret = fbr_fuse_test_mount(ctx, mount, _test_fs_rw_init, FBR_FUSE_DEFAULT_CALLBACKS);
	fbr_test_ERROR(ret, "fs fuse mount failed: %s", mount);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs test_fuse mounted: %s", mount);
}
