/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <sys/stat.h>
#include <sys/types.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "fuse/fbr_fuse.h"
#include "fuse/fbr_fuse_lowlevel.h"
#include "fuse/fbr_fuse_ops.h"

#include "fbr_test_fs_cmds.h"
#include "test/fbr_test.h"
#include "fuse/test/fbr_test_fuse_cmds.h"

#define _TEST_FS_FUSE_TTL_SEC		2.0

static void
_test_fs_fuse_init(void *userdata, struct fuse_conn_info *conn)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_mounted(ctx);
	assert(conn);

	struct fbr_directory *root = fbr_directory_root_alloc(&ctx->fs);

	mode_t fmode = S_IFREG | 0444;

	(void)fbr_file_alloc(&ctx->fs, root, "fiber1", 6, fmode);
	(void)fbr_file_alloc(&ctx->fs, root, "fiber2", 6, fmode);

	fbr_directory_set_state(root, FBR_DIRSTATE_OK);
}

static void
_test_fs_fuse_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_fs *fs = &ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);

	(void)fi;

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "GETATTR ino: %lu", ino);

	struct fbr_file *file = fbr_inode_get(fs, ino);

	if (!file) {
		int ret = fuse_reply_err(req, ENOENT);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_getattr fuse_reply_err %d", ret);
		return;
	}

	fbr_file_ok(file);

	struct stat st_attr;
	fbr_file_attr(file, &st_attr);

	int ret = fuse_reply_attr(req, &st_attr, _TEST_FS_FUSE_TTL_SEC);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_getattr fuse_reply_attr %d", ret);
}

static const struct fuse_lowlevel_ops _TEST_FS_FUSE_OPS = {
	.init = _test_fs_fuse_init,
	.getattr = _test_fs_fuse_getattr,
};

void
fbr_cmd_fs_test_fuse_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, &_TEST_FS_FUSE_OPS);
	fbr_test_ERROR(ret, "fs fuse mount failed: %s", cmd->params[0].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs test_fuse mounted: %s", cmd->params[0].value);
}
