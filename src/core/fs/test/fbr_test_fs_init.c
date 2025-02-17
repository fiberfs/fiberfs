/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <sys/types.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "core/fuse/fbr_fuse_ops.h"

#include "fbr_test_fs_cmds.h"
#include "test/fbr_test.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

static void
_test_fs_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	assert(conn);

	struct fbr_fs *fs = ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_directory *root = fbr_directory_root_alloc(fs);

	mode_t fmode = S_IFREG | 0444;

	(void)fbr_file_alloc(fs, root, "fiber1", 6, fmode);
	(void)fbr_file_alloc(fs, root, "fiber2", 6, fmode);

	fbr_directory_set_state(root, FBR_DIRSTATE_OK);
}

static const struct fbr_fuse_callbacks _TEST_FS_INIT_CALLBACKS = {
	.init = _test_fs_init
};

void
fbr_cmd_fs_test_init_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, &_TEST_FS_INIT_CALLBACKS);
	fbr_test_ERROR(ret, "fs init fuse mount failed: %s", cmd->params[0].value);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_directory *root = fbr_dindex_take(fs, FBR_INODE_ROOT);
	fbr_directory_ok(root);
	fbr_test_ASSERT(root == fs->root, "bad root ptr");
	fbr_test_ASSERT(root->state == FBR_DIRSTATE_OK, "bad root state %d", root->state);

	fbr_test_ERROR(root->dirname.len, "root dirname has length");
	fbr_test_ERROR(strcmp(fbr_filename_get(&root->dirname), ""), "root dirname not empty")

	struct fbr_file *root_file = fbr_inode_take(fs, FBR_INODE_ROOT);
	fbr_file_ok(root_file);

	fbr_test_ASSERT(root->file == root_file, "Bad root file");
	fbr_test_ERROR(root_file->parent_inode, "root has a parent inode");
	fbr_test_ERROR(root_file->filename.len, "root_file name has length");
	fbr_test_ERROR(strcmp(fbr_filename_get(&root_file->filename), ""), "root_file not empty")

	fbr_inode_release(fs, root_file);
	fbr_dindex_release(fs, root);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs test_init mounted: %s", cmd->params[0].value);
}

void
fbr_cmd_fs_test_release_root(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	fbr_fs_release_root(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs root released");
}

void
fbr_cmd_fs_test_stats(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
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
	struct fbr_test_fuse *test_fuse = ctx->test_fuse;			\
	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);		\
	struct fbr_fs *fs = fuse_ctx->fs;					\
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
