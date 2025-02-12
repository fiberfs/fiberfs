/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <sys/types.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "fuse/fbr_fuse.h"
#include "fuse/fbr_fuse_lowlevel.h"

#include "fbr_test_fs_cmds.h"
#include "test/fbr_test.h"
#include "fuse/test/fbr_test_fuse_cmds.h"

static void
_test_fs_init(void *userdata, struct fuse_conn_info *conn)
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

static const struct fuse_lowlevel_ops _TEST_FS_OPS = {
	.init = _test_fs_init
};

void
fbr_cmd_fs_test_init_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, &_TEST_FS_OPS);
	fbr_test_ERROR(ret, "fs init fuse mount failed: %s", cmd->params[0].value);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	struct fbr_fs *fs = &fuse_ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_directory *root = fbr_dindex_get(fs, 1);
	fbr_directory_ok(root);
	fbr_test_ASSERT(root == fs->root, "bad root ptr");
	fbr_test_ASSERT(root->state == FBR_DIRSTATE_OK, "bad root state %d", root->state);

	fbr_dindex_release(fs, root);

	struct fbr_file *root_file = fbr_inode_get(fs, 1);
	fbr_file_ok(root_file);

	// TODO more checks here

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs test_init mounted: %s", cmd->params[0].value);
}

void
fbr_cmd_fs_test_release_root(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	struct fbr_fs *fs = &fuse_ctx->fs;
	fbr_fs_ok(fs);

	fbr_fs_release_root(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs root released");
}

void
fbr_cmd_fs_test_stats(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	struct fbr_fs *fs = &fuse_ctx->fs;
	fbr_fs_ok(fs);

#define _FS_TEST_STAT_PRINT(name)	\
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs.stats." #name ": %lu", fs->stats.name)

	_FS_TEST_STAT_PRINT(directories);
	_FS_TEST_STAT_PRINT(directories_total);
	_FS_TEST_STAT_PRINT(directory_refs);
	_FS_TEST_STAT_PRINT(files);
	_FS_TEST_STAT_PRINT(files_total);
	_FS_TEST_STAT_PRINT(file_refs);
}

#define _FS_TEST_STAT(name)							\
char *										\
fbr_var_fs_test_stat_##name(struct fbr_test_context *ctx)			\
{										\
	struct fbr_test_fuse *test_fuse = ctx->fuse;				\
	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);		\
	struct fbr_fs *fs = &fuse_ctx->fs;					\
	fbr_fs_ok(fs);								\
										\
	snprintf(test_fuse->stat_str, sizeof(test_fuse->stat_str), "%lu",	\
		fs->stats.name);						\
	return test_fuse->stat_str;						\
}

_FS_TEST_STAT(directories)
_FS_TEST_STAT(directories_total)
_FS_TEST_STAT(directory_refs)
_FS_TEST_STAT(files)
_FS_TEST_STAT(files_total)
_FS_TEST_STAT(file_refs)
