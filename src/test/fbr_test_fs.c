/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "fs/fbr_fs.h"
#include "test/fbr_test.h"

struct _fs_path {
	unsigned int		magic;
#define _FS_PATH_MAGIC		0x1E9B84CD

	char			path[PATH_MAX];
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
	struct _fs_path *entry;

	fbr_test_context_ok(ctx);
	assert(ctx->fs);
	assert(ctx->fs->magic == _FS_MAGIC);

	while (ctx->fs->dirs) {
		entry = ctx->fs->dirs;
		ctx->fs->dirs = entry->next;

		assert(entry->magic == _FS_PATH_MAGIC);

		printf("ZZZ path='%s'\n", entry->path);
		// TODO rmdir

		fbr_ZERO(entry);
		free(entry);
	}

	assert_zero(ctx->fs->dirs);

	fbr_ZERO(ctx->fs);
	free(ctx->fs);

	ctx->fs = NULL;
}

static void
_random_init(struct fbr_test_context *ctx)
{
	struct fbr_test_fs *fs;

	fbr_test_context_ok(ctx);

	if (!ctx->fs) {
		fs = calloc(1, sizeof(*fs));
		assert(fs);

		fs->magic = _FS_MAGIC;

		ctx->fs = fs;

		fbr_test_register_finish(ctx, "fs", _fs_finish);

		fbr_test_random_seed();
	}

	assert(ctx->fs->magic == _FS_MAGIC);
}

void
fbr_test_cmd_fs_mkdir_tmp(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	char *tmproot;
	struct _fs_path *entry;
	size_t len;
	long random;
	int exists, attempts;

	_random_init(ctx);
	fbr_test_cmd_ok(cmd);

	fbr_test_ERROR(cmd->param_count > 1, "Too many parameters");

	if (cmd->param_count == 1) {
		tmproot = cmd->params[0].value;
	} else {
		tmproot = getenv("TMPDIR");

		if (!tmproot) {
			tmproot = P_tmpdir;
		}
	}

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "tmproot: '%s'", tmproot);

	entry = calloc(1, sizeof(*entry));
	assert(entry);
	entry->magic = _FS_PATH_MAGIC;

	attempts = 0;

	do {
		random = fbr_test_gen_random(100000, 999999999);

		len = snprintf(entry->path, sizeof(entry->path), "%s/_fbrtmp%ld", tmproot, random);
		assert(len < sizeof(entry->path));

		exists = fbr_fs_exists(entry->path);
		attempts++;

		fbr_test_ERROR(attempts > 10, "Too many tmpdir attempts");
	} while (exists);

	// TODO mkdir

	entry->next = ctx->fs->dirs;
	ctx->fs->dirs = entry;
}
