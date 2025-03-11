/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <limits.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_path.h"

#include "test/fbr_test.h"
#include "fbr_test_fs_cmds.h"

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
_test_path_print_path(struct fbr_test_context *ctx, struct fbr_path *path, char *name,
	enum fbr_path_layout layout, char *d, char *f, char *fp)
{
	fbr_test_context_ok(ctx);
	assert(path);
	assert(name);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "%s layout: %d", name, path->layout.value);

	struct fbr_path_name dirname, fullpath, fullparent;

	fbr_path_get_dir(path, &dirname);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "%s dirname: '%.*s':%zu", name,
		(int)dirname.len, dirname.name, dirname.len);

	const char *filename = fbr_path_get_file(path, NULL);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "%s filename: '%s'", name, filename);

	const char *sfullpath = fbr_path_get_full(path, &fullpath);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "%s fullpath: '%s'", name, sfullpath);

	fbr_path_name_parent(&fullpath, &fullparent);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "%s fullparent: '%.*s':%zu", name,
		(int)fullparent.len, fullparent.name, fullparent.len);

	fbr_test_ASSERT(path->layout.value == layout, "layout isnt %d", layout);
	fbr_test_ERROR(fbr_path_name_str_cmp(&dirname, d), "dirname isnt '%s'", d);
	fbr_test_ERROR(strcmp(filename, f), "filename isnt '%s'", d);
	fbr_test_ERROR(strcmp(sfullpath, fp), "fullpath isnt '%s'", fp);
}

void
fbr_cmd_fs_test_path(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);

	struct fbr_fs *fs = fbr_fs_alloc();
	fbr_fs_ok(fs);

	fs->log = fbr_fs_test_logger;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "*** ROOT");

	struct fbr_directory *directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);

	struct fbr_file *file = directory->file;
	fbr_file_ok(file);

	enum fbr_path_layout layout = FBR_PATH_EMBED_DIR;

	_test_path_print_path(ctx, &file->path, "file", layout, "", "", "");
	_test_path_print_path(ctx, &directory->dirname, "dir", layout, "", "", "");

	char sdir[PATH_MAX], sfull[PATH_MAX];
	sdir[0] = '\0';
	sfull[0] = '\0';

	fbr_inode_t inode = file->inode;

	for (size_t i = 0; i < cmd->param_count; i++) {
		char *name = cmd->params[i].value;
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "*** %zu '%s'", i + 1, name);

		// directory file

		layout = FBR_PATH_PTR;
		if (!i && strlen(name) < 15) {
			layout = FBR_PATH_EMBED_FILE;
		}

		strncpy(sfull, sdir, sizeof(sfull));
		if (i) {
			strncat(sfull, "/", sizeof(sfull) - strlen(sfull) - 1);
		}
		strncat(sfull, name, sizeof(sfull) - strlen(sfull) - 1);

		struct fbr_path_name filename;
		fbr_path_name_init(&filename, name);

		file = fbr_file_alloc(fs, directory, &filename, S_IFDIR);

		_test_path_print_path(ctx, &file->path, "directory_file", layout, sdir, name, sfull);

		assert(file->parent_inode == inode);

		// lookup
		fbr_inode_add(fs, file);

		fbr_inode_t inode_next = file->inode;

		struct fbr_path_name dirname;
		fbr_path_get_full(&file->path, &dirname);

		// random file

		char name2[PATH_MAX];
		int ret = snprintf(name2, sizeof(name2), "%s.txt", name);
		assert((size_t)ret < sizeof(name2));

		layout = FBR_PATH_PTR;
		if (strlen(name2) < 15) {
			layout = FBR_PATH_EMBED_FILE;
		}

		fbr_path_name_init(&filename, name2);

		struct fbr_file *file2 = fbr_file_alloc(fs, directory, &filename, S_IFREG);

		_test_path_print_path(ctx, &file2->path, "file", layout, "", name2, name2);

		fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);

		assert(file2->parent_inode == inode);

		struct fbr_file *f2 = fbr_directory_find_file(directory, name, strlen(name));
		assert(f2 == file);

		f2 = fbr_directory_find_file(directory, name2, strlen(name2));
		assert(f2 == file2);

		fbr_dindex_release(fs, &directory);

		// directory

		directory = fbr_directory_alloc(fs, &dirname, inode_next);

		inode = inode_next;

		layout = FBR_PATH_PTR;
		if (strlen(sfull) < 15) {
			layout = FBR_PATH_EMBED_DIR;
		}

		_test_path_print_path(ctx, &directory->dirname, "directory", layout, sfull, "", sfull);

		if (i) {
			strncat(sdir, "/", sizeof(sdir) - strlen(sdir) - 1);
		}
		strncat(sdir, name, sizeof(sdir) - strlen(sdir) - 1);
	}

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);

	fbr_dindex_release(fs, &directory);

	struct fbr_path_name full;
	fbr_path_name_init(&full, sfull);

	size_t max = 0;

	while (inode > FBR_INODE_ROOT) {
		max++;
		fbr_test_ERROR(max > cmd->param_count, "too many inode loops");

		fbr_test_log(ctx, FBR_LOG_VERBOSE, "*** inode=%lu", inode);

		file = fbr_inode_take(fs, inode);
		fbr_file_ok(file);

		struct fbr_path_name filename;
		fbr_path_get_full(&file->path, &filename);

		fbr_test_ERROR(fbr_path_name_cmp(&filename, &full), "Path mismatch");

		fbr_inode_t next = file->parent_inode;

		struct fbr_path_name dirname;
		fbr_path_get_full(&file->path, &dirname);

		directory = fbr_dindex_take(fs, &dirname, FBR_DIRFLAGS_NONE);
		fbr_directory_ok(directory);

		fbr_dindex_release(fs, &directory);

		fbr_inode_forget(fs, inode, 2);

		inode = next;

		fbr_path_name_parent(&full, &full);
	}

	fbr_fs_release_root(fs, 1);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Files: %zu", fs->stats.files);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Directories: %zu", fs->stats.directories);

	fbr_test_ERROR(fs->stats.files, "Files detected");
	fbr_test_ERROR(fs->stats.directories, "Directories detected");

	fbr_fs_free(fs);
}
