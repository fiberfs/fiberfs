/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_path.h"

#include "test/fbr_test.h"

void
fbr_cmd_fs_test_path_assert(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_path *path;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "enum FBR_PATH_LAYOUT end=%d",
		__FBR_PATH_LAYOUT_END);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_PATH_LAYOUT_LEN=%d",
		FBR_PATH_LAYOUT_LEN);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_path_ptr)=%zu",
		sizeof(struct fbr_path_ptr));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_path_embed)=%zu",
		sizeof(struct fbr_path_embed));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_path)=%zu",
		sizeof(struct fbr_path));

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_PATH_EMBED_LEN_SIZE=%d",
		FBR_PATH_EMBED_LEN_SIZE);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_PATH_PTR_LEN_SIZE=%zu",
		FBR_PATH_PTR_LEN_SIZE);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_PATH_EMBED_LEN=%zu", FBR_PATH_EMBED_LEN);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(path->embed.data)=%zu",
		sizeof(path->embed.data));

	fbr_test_ASSERT(__FBR_PATH_LAYOUT_END <= (1<<FBR_PATH_LAYOUT_LEN),
		"FBR_PATH_LAYOUT doesnt fit in %d bits", FBR_PATH_LAYOUT_LEN);
	fbr_test_ASSERT(sizeof(struct fbr_path_ptr) == sizeof(struct fbr_path_embed),
		"struct fbr_path_ptr != struct fbr_path_embed");
	fbr_test_ASSERT(sizeof(struct fbr_path) == sizeof(struct fbr_path_embed),
		"struct fbr_path != struct fbr_path_embed");
}

static void
_test_path_file(struct fbr_test_context *ctx, struct fbr_file *file)
{
	fbr_test_context_ok(ctx);
	fbr_file_ok(file);

	struct fbr_path_name dirname, filename, fullpath;

	fbr_path_get_dir(&file->path, &dirname);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "file dirname: '%.*s':%zu",
		(int)dirname.len, dirname.name, dirname.len);

	fbr_path_get_file(&file->path, &filename);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "file filename: '%.*s':%zu",
		(int)filename.len, filename.name, filename.len);

	fbr_path_get_full(&file->path, &fullpath);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "file fullpath: '%.*s':%zu",
		(int)fullpath.len, fullpath.name, fullpath.len);
}

static void
_test_path_directory(struct fbr_test_context *ctx, struct fbr_directory *directory)
{
	fbr_test_context_ok(ctx);
	fbr_directory_ok(directory);

	struct fbr_path_name dirname, filename, fullpath;

	fbr_path_get_dir(&directory->dirname, &dirname);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "directory dirname: '%.*s':%zu",
		(int)dirname.len, dirname.name, dirname.len);

	fbr_path_get_file(&directory->dirname, &filename);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "directory filename: '%.*s':%zu",
		(int)filename.len, filename.name, filename.len);

	fbr_path_get_full(&directory->dirname, &fullpath);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "directory fullpath: '%.*s':%zu",
		(int)fullpath.len, fullpath.name, fullpath.len);
}

void
fbr_cmd_fs_test_path(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);

	// fs
	struct fbr_fs *fs = fbr_fs_alloc();
	fbr_fs_ok(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "*** ROOT");

	struct fbr_directory *directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);

	struct fbr_file *file = directory->file;
	fbr_file_ok(file);

	_test_path_directory(ctx, directory);
	_test_path_file(ctx, file);

	for (size_t i = 0; i < cmd->param_count; i++) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "*** %zu '%s'", i + 1, cmd->params[i].value);
	}

	fbr_fs_free(fs);
}
