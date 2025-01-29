/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "fs/fbr_fs.h"
#include "test/fbr_test.h"

struct _fs_path {
	unsigned int		magic;
#define _FS_PATH_MAGIC		0x1E9B84CD

	char			path[PATH_MAX + 1];
	struct _fs_path		*next;
};

struct fbr_test_fs {
	unsigned int		magic;
#define _FS_MAGIC		0x0364A7FA

	struct _fs_path		*dirs;

	char			*tmpdir_str;
};

static void
_fs_finish(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	assert(ctx->fs);
	assert(ctx->fs->magic == _FS_MAGIC);

	while (ctx->fs->dirs) {
		struct _fs_path *entry = ctx->fs->dirs;
		ctx->fs->dirs = entry->next;

		assert(entry->magic == _FS_PATH_MAGIC);

		fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "removing tmpdir '%s'", entry->path);

		fbr_rmdir(entry->path);

		fbr_test_warn(fbr_fs_exists(entry->path), "tmpdir couldn't be removed %s",
			entry->path);

		fbr_ZERO(entry);
		free(entry);
	}

	assert_zero(ctx->fs->dirs);

	fbr_ZERO(ctx->fs);
	free(ctx->fs);

	ctx->fs = NULL;
}

static void
_fs_init(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	if (!ctx->fs) {
		struct fbr_test_fs *fs = calloc(1, sizeof(*fs));
		assert(fs);

		fs->magic = _FS_MAGIC;
		fs->tmpdir_str = "";

		ctx->fs = fs;

		fbr_test_register_finish(ctx, "fs", _fs_finish);

		fbr_test_random_seed();
	}

	assert(ctx->fs->magic == _FS_MAGIC);
}

char *
fbr_test_mkdir_tmp(struct fbr_test_context *ctx, char *tmproot)
{
	_fs_init(ctx);

	if (!tmproot) {
		tmproot = getenv("TMPDIR");

		if (!tmproot) {
			tmproot = P_tmpdir;
		}
	}

	struct _fs_path *entry = calloc(1, sizeof(*entry));
	assert(entry);
	entry->magic = _FS_PATH_MAGIC;

	int attempts = 0, exists;

	do {
		long random = fbr_test_gen_random(100000, 999999999);

		size_t len = snprintf(entry->path, sizeof(entry->path), "%s/_fbrtmp%ld", tmproot, random);
		assert(len < sizeof(entry->path));

		exists = fbr_fs_exists(entry->path);
		attempts++;

		fbr_test_ERROR(attempts > 10, "Too many tmpdir attempts");
	} while (exists);

	int ret = mkdir(entry->path, S_IRWXU);
	fbr_test_ERROR(ret, "mkdir failed %d", ret);

	entry->next = ctx->fs->dirs;
	ctx->fs->dirs = entry;

	return entry->path;
}

void
fbr_test_cmd_fs_mkdir_tmp(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_fs_init(ctx);
	fbr_test_cmd_ok(cmd);

	fbr_test_ERROR(cmd->param_count > 1, "Too many parameters");

	char *tmproot = NULL;

	if (cmd->param_count == 1) {
		tmproot = cmd->params[0].value;
	}

	char *tmpdir = fbr_test_mkdir_tmp(ctx, tmproot);

	ctx->fs->tmpdir_str = tmpdir;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "tmpdir '%s'", tmpdir);
}

char *
fbr_test_var_fs_tmpdir(struct fbr_test_context *ctx)
{
	_fs_init(ctx);
	assert(ctx->fs->tmpdir_str);

	return ctx->fs->tmpdir_str;
}
