/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <sys/types.h>

#include "fiberfs.h"
#include "core/context/fbr_callback.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"

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

	struct fbr_path_name filename;
	mode_t fmode = S_IFREG | 0444;

	fbr_path_name_init(&filename, "fiber1");
	(void)fbr_file_alloc(fs, root, &filename, fmode);

	fbr_path_name_init(&filename, "fiber2");
	(void)fbr_file_alloc(fs, root, &filename, fmode);

	fbr_directory_set_state(ctx->fs, root, FBR_DIRSTATE_OK);
}

static const struct fbr_fuse_callbacks _TEST_FS_INIT_CALLBACKS = {
	.init = _test_fs_init
};

void __fbr_attr_printf(1)
fbr_fs_test_logger(const char *fmt, ...)
{
	struct fbr_test_context *test_ctx = fbr_test_fuse_ctx();

	va_list ap;
	va_start(ap, fmt);
	fbr_test_vlog(test_ctx, FBR_LOG_VERBOSE, fmt, ap);
	va_end(ap);
}

void
fbr_cmd_fs_test_init_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, &_TEST_FS_INIT_CALLBACKS);
	fbr_test_ERROR(ret, "fs init fuse mount failed: %s", cmd->params[0].value);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	fs->log = fbr_fs_test_logger;

	struct fbr_directory *root = fbr_dindex_take(fs, FBR_DIRNAME_ROOT);
	fbr_directory_ok(root);
	fbr_test_ASSERT(root == fs->root, "bad root ptr");
	fbr_test_ASSERT(root->state == FBR_DIRSTATE_OK, "bad root state %d", root->state);

	struct fbr_path_name name;
	fbr_path_get_dir(&root->dirname, &name);

	fbr_test_ERROR(name.len, "root dirname has length");
	fbr_test_ASSERT(name.name, "dirname is null");
	fbr_test_ERROR(strcmp(name.name, ""), "root dirname not empty")

	struct fbr_file *root_file = fbr_inode_take(fs, FBR_INODE_ROOT);
	fbr_file_ok(root_file);

	fbr_path_get_file(&root_file->path, &name);

	fbr_test_ASSERT(root->file == root_file, "Bad root file");
	fbr_test_ERROR(root_file->parent_inode, "root has a parent inode");
	fbr_test_ERROR(name.len, "root_file name has length");
	fbr_test_ASSERT(name.name, "filename is null");
	fbr_test_ERROR(strcmp(name.name, ""), "root_file not empty")

	fbr_inode_release(fs, &root_file);
	fbr_dindex_release(fs, &root);
	assert_zero_dev(root_file);
	assert_zero_dev(root);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs test_init mounted: %s", cmd->params[0].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_chunk)=%zu",
		sizeof(struct fbr_chunk));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_body)=%zu",
		sizeof(struct fbr_body));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_file)=%zu",
		sizeof(struct fbr_file));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_directory)=%zu",
		sizeof(struct fbr_directory));
}

void
fbr_cmd_fs_test_dentry_ttl_ms(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long ttl = fbr_test_parse_long(cmd->params[0].value);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	fs->config.dentry_ttl = (double)ttl / 1000.0;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs dentry ttl %lf", fs->config.dentry_ttl);
}

void
fbr_cmd_fs_test_release_root(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR(cmd->param_count > 1, "Too many params");

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	fbr_fuse_mounted(fuse_ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	int release_root_inode = 1;

	if (cmd->param_count == 1 && !strcmp(cmd->params[0].value, "0")) {
		release_root_inode = 0;
	}

	if (fs->root) {
		fbr_fs_release_root(fs, release_root_inode);
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs root released %d", release_root_inode);
	} else {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs release root skipped");
	}
}

void
fbr_cmd_fs_test_stats(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	fbr_fuse_mounted(fuse_ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

#define _FS_TEST_STAT_PRINT(name)	\
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs.stats." #name ": %lu", fs->stats.name)

	_FS_TEST_STAT_PRINT(directories);
	_FS_TEST_STAT_PRINT(directories_dindex);
	_FS_TEST_STAT_PRINT(directories_total);
	_FS_TEST_STAT_PRINT(directory_refs);
	_FS_TEST_STAT_PRINT(files);
	_FS_TEST_STAT_PRINT(files_inodes);
	_FS_TEST_STAT_PRINT(files_total);
	_FS_TEST_STAT_PRINT(file_refs);
	_FS_TEST_STAT_PRINT(requests);
	_FS_TEST_STAT_PRINT(requests_total);
	_FS_TEST_STAT_PRINT(fetch_bytes);
	_FS_TEST_STAT_PRINT(read_bytes);
	_FS_TEST_STAT_PRINT(write_bytes);
}

#define _FS_TEST_STAT(name)							\
char *										\
fbr_var_fs_test_stat_##name(struct fbr_test_context *ctx)			\
{										\
	struct fbr_test_fuse *test_fuse = ctx->test_fuse;			\
	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);		\
	fbr_fuse_mounted(fuse_ctx);						\
	struct fbr_fs *fs = fuse_ctx->fs;					\
	fbr_fs_ok(fs);								\
										\
	snprintf(test_fuse->stat_str, sizeof(test_fuse->stat_str), "%lu",	\
		fs->stats.name);						\
	return test_fuse->stat_str;						\
}

_FS_TEST_STAT(directories)
_FS_TEST_STAT(directories_dindex)
_FS_TEST_STAT(directories_total)
_FS_TEST_STAT(directory_refs)
_FS_TEST_STAT(files)
_FS_TEST_STAT(files_inodes)
_FS_TEST_STAT(files_total)
_FS_TEST_STAT(file_refs)
_FS_TEST_STAT(requests)
_FS_TEST_STAT(requests_total)
_FS_TEST_STAT(fetch_bytes)
_FS_TEST_STAT(read_bytes)
_FS_TEST_STAT(write_bytes)
