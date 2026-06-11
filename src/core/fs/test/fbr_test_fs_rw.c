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

static const struct fbr_store_callbacks _TEST_FS_RW_STORE_CALLBACKS = {
	.chunk_read_f = fbr_cstore_async_chunk_read,
	.chunk_delete_f = fbr_cstore_async_chunk_delete,
	.wbuffer_write_f = fbr_cstore_async_wbuffer_write,
	.index_write_f = fbr_cstore_index_root_write,
	.index_read_f = fbr_cstore_index_read,
	.index_delete_f = fbr_cstore_index_delete,
	.root_read_f = fbr_cstore_root_read,
};

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

	fbr_fs_set_store(ctx->fs, &_TEST_FS_RW_STORE_CALLBACKS);

	//ctx->log->always_flush = 1;

	//conn->max_readahead
	//conn->max_background
	//FUSE_CAP_POSIX_ACL
	//FUSE_CAP_HANDLE_KILLPRIV

	conn->want |= FUSE_CAP_ASYNC_READ;
	conn->want |= FUSE_CAP_ATOMIC_O_TRUNC;
	conn->want |= FUSE_CAP_SPLICE_WRITE;
	conn->want |= FUSE_CAP_SPLICE_MOVE;
	conn->want |= FUSE_CAP_ASYNC_DIO;
	conn->want |= FUSE_CAP_PARALLEL_DIROPS;

	// TODO implement .write_buf
	conn->want &= ~FUSE_CAP_SPLICE_READ;

	// This will make reading local appends undefined
	conn->want &= ~FUSE_CAP_WRITEBACK_CACHE;

	struct fbr_request *request = fbr_request_alloc(NULL, __func__);
	fbr_request_ok(request);
	assert_zero(request->not_fuse);

	fbr_test_fs_root_alloc(ctx->fs);

	struct fbr_directory *root = fbr_dindex_take(ctx->fs, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);

	fbr_test_cstore_wait(ctx->fs->cstore);

	struct fbr_path_name dirpath;
	fbr_directory_name(root, &dirpath);
	fbr_id_t root_id = fbr_cstore_root_read(ctx->fs, &dirpath, 0);

	fbr_test_logs("INIT fbr_cstore_root_read(): %lu", root_id);
	fbr_ASSERT(root_id == root->version, "root version mismatch, found %lu, expected %lu",
		root_id, root->version);

	fbr_dindex_release(ctx->fs, &root);
	fbr_request_free(request);
}

static const struct fbr_fuse_callbacks _TEST_FS_RW_CALLBACKS = {
	.init = _test_fs_rw_init,

	.getattr = fbr_ops_getattr,
	.setattr = fbr_ops_setattr,
	.lookup = fbr_ops_lookup,

	.mkdir = fbr_ops_mkdir,
	.unlink = fbr_ops_unlink,
	.rmdir = fbr_ops_rmdir,

	.opendir = fbr_ops_opendir,
	.readdir = fbr_ops_readdir,
	.releasedir = fbr_ops_releasedir,

	.open = fbr_ops_open,
	.create = fbr_ops_create,
	.read = fbr_ops_read,
	.write = fbr_ops_write,
	.flush = fbr_ops_flush,
	.release = fbr_ops_release,
	.fsync = fbr_ops_fsync,

	.forget = fbr_ops_forget,
	.forget_multi = fbr_ops_forget_multi
};

void
fbr_cmd_fs_test_rw_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	const char *mount = cmd->params[0].value;

	int ret = fbr_fuse_test_mount(ctx, mount, &_TEST_FS_RW_CALLBACKS);
	fbr_test_ERROR(ret, "fs fuse mount failed: %s", mount);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs test_fuse mounted: %s", mount);
}
