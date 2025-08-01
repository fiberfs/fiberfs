/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/operations/fbr_operations.h"
#include "core/store/fbr_store.h"

#include "test/fbr_test.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/request/test/fbr_test_request_cmds.h"
#include "core/store/test/fbr_dstore.h"

static const struct fbr_store_callbacks _TEST_MKDIR_CALLBACKS = {
	.directory_flush_f = fbr_directory_flush,
	.index_write_f = fbr_dstore_index_root_write,
	.index_read_f = fbr_dstore_index_read,
	.root_read_f = fbr_dstore_root_read
};

static void
_test_mkdir_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	fbr_fs_ok(ctx->fs);
	assert(conn);

	fbr_fs_set_store(ctx->fs, &_TEST_MKDIR_CALLBACKS);
	fbr_dstore_init(fbr_test_get_ctx());

	fbr_test_fuse_root_alloc(ctx->fs);
}

static void
_test_mkdir_getattr(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fbr_request_valid(request);

	fbr_test_logs("GETATTR req: %lu ino: %lu", request->id, ino);

	fbr_ops_getattr(request, ino, fi);
}

static void
_test_mkdir_lookup(struct fbr_request *request, fuse_ino_t parent, const char *name)
{
	fbr_request_valid(request);

	fbr_test_logs("LOOKUP req: %lu parent: %lu name: %s", request->id, parent, name);

	if (parent == FBR_INODE_ROOT) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	fbr_ops_lookup(request, parent, name);
}

static const struct fbr_fuse_callbacks _TEST_FS_MKDIR_CALLBACKS = {
	.init = _test_mkdir_init,
	.getattr = _test_mkdir_getattr,
	.lookup = _test_mkdir_lookup,
	.mkdir = fbr_ops_mkdir
};

void
fbr_cmd_mkdir_op_test_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	char *mount = cmd->params[0].value;

	int ret = fbr_fuse_test_mount(ctx, mount, &_TEST_FS_MKDIR_CALLBACKS);
	assert_zero(ret);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "mkdir_op_test_mount done");
}

void
fbr_cmd_mkdir_test_fail(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	if (fbr_test_can_vfork(ctx)) {
		fbr_test_fork(ctx, cmd);
		return;
	}

	char *dirname = cmd->params[0].value;
	errno = 0;

	int ret = mkdir(dirname, S_IRWXU);
	assert(ret);

	fbr_test_logs("mkdir_test_fail(%s) ret: %d errno: %d (%s)", dirname,
		ret, errno, strerror(errno));
}
