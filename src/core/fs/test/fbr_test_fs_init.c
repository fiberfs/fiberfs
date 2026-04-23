/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <sys/types.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse.h"

#include "test/fbr_test.h"
#include "fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

static void
_test_fs_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	assert_zero(ctx->detached);
	assert(conn);

	struct fbr_fs *fs = ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);

	struct fbr_path_name filename;
	mode_t fmode = S_IFREG | 0444;

	fbr_path_name_init(&filename, "fiber1");
	struct fbr_file *file = fbr_file_alloc(fs, root, &filename);
	file->mode = fmode;
	file->state = FBR_FILE_OK;

	fbr_path_name_init(&filename, "fiber2");
	file = fbr_file_alloc(fs, root, &filename);
	file->mode = fmode;
	file->state = FBR_FILE_OK;

	fmode = S_IFDIR | 0555;

	fbr_path_name_init(&filename, "dir1");
	file = fbr_file_alloc(fs, root, &filename);
	file->mode = fmode;
	file->state = FBR_FILE_OK;

	fbr_directory_set_state(fs, root, FBR_DIRSTATE_OK);

	fbr_inode_add(fs, file);

	struct fbr_directory *dir1 = fbr_directory_alloc(fs, &filename, file->inode);
	fbr_directory_ok(dir1);
	assert(dir1->state == FBR_DIRSTATE_LOADING);

	fbr_directory_set_state(fs, dir1, FBR_DIRSTATE_OK);

	fbr_inode_release(fs, &file);
	fbr_dindex_release(fs, &dir1);
	fbr_dindex_release(fs, &root);
}

static const struct fbr_fuse_callbacks _TEST_FS_INIT_CALLBACKS = {
	.init = _test_fs_init
};

void
fbr_cmd_fs_test_init_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, &_TEST_FS_INIT_CALLBACKS);
	fbr_test_ERROR(ret, "fs init fuse mount failed: %s", cmd->params[0].value);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	fbr_fuse_mounted(fuse_ctx);
	assert_zero(fuse_ctx->detached);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_directory *root = fbr_dindex_take(fs, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(root);
	fbr_test_ASSERT(root->state == FBR_DIRSTATE_OK, "bad root state %d", root->state);

	struct fbr_path_name name;
	fbr_directory_name(root, &name);

	fbr_test_ERROR(name.length, "root dirname has length");
	fbr_test_ASSERT(name.name, "dirname is null");
	fbr_test_ERROR(strcmp(name.name, ""), "root dirname not empty")

	struct fbr_file *root_file = fbr_inode_take(fs, FBR_INODE_ROOT);
	fbr_file_ok(root_file);

	fbr_path_get_file(&root_file->path, &name);

	fbr_test_ASSERT(root->file == root_file, "Bad root file");
	fbr_test_ERROR(root_file->parent_inode, "root has a parent inode");
	fbr_test_ASSERT(root_file->state == FBR_FILE_OK, "root_file not FBR_FILE_OK");
	fbr_test_ERROR(name.length, "root_file name has length");
	fbr_test_ASSERT(name.name, "filename is null");
	fbr_test_ERROR(strcmp(name.name, ""), "root_file not empty")

	fbr_inode_release(fs, &root_file);
	fbr_dindex_release(fs, &root);
	assert_zero_dev(root_file);
	assert_zero_dev(root);

	fbr_path_name_init(&name, "dir1");
	struct fbr_directory *dir1 = fbr_dindex_take(fs, &name, 1);
	fbr_directory_ok(dir1);
	fbr_test_ASSERT(dir1->state == FBR_DIRSTATE_OK, "bad dir1 state %d", root->state);

	fbr_dindex_release(fs, &dir1);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs test_init mounted: %s", cmd->params[0].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_chunk)=%zu",
		sizeof(struct fbr_chunk));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_body)=%zu",
		sizeof(struct fbr_body));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_chunk_slab)=%zu",
		(sizeof(struct fbr_chunk) * FBR_BODY_SLAB_DEFAULT_CHUNKS) +
			sizeof(struct fbr_chunk_slab));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_file)=%zu",
		sizeof(struct fbr_file));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_directory)=%zu",
		sizeof(struct fbr_directory));
}

void
fbr_cmd_fs_test_assert_root(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	fbr_fuse_mounted(fuse_ctx);
	assert_zero(fuse_ctx->detached);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_directory *root = fbr_dindex_take(fs, FBR_DIRNAME_ROOT, 0);
	fbr_test_ASSERT(root, "root is missing");
	fbr_directory_ok(root);
	fbr_test_ASSERT(root->state == FBR_DIRSTATE_OK, "bad root state %d", root->state);

	fbr_dindex_release(fs, &root);
}
