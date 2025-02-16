/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sys/fbr_sys.h"
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

		fbr_sys_rmdir(entry->path);

		fbr_test_warn(fbr_sys_exists(entry->path), "tmpdir couldn't be removed %s",
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

		exists = fbr_sys_exists(entry->path);
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

static int
_fs_name_cmp(const void *v1, const void *v2)
{
	const char *s1 = *((const char**)v1);
	const char *s2 = *((const char**)v2);

	return strcmp(s1, s2);
}

void
fbr_test_cmd_fs_ls(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_fs_init(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ERROR(cmd->param_count == 0, "Need at least 1 parameter");
	fbr_test_ERROR(cmd->param_count > 2, "Too many parameters");

	if (fbr_test_can_vfork(ctx)) {
		fbr_test_fork(ctx, cmd);
		return;
	}

	char *filename = cmd->params[0].value;
	fbr_test_ERROR_string(filename);

	int want_result = 0;
	if (cmd->param_count > 1) {
		want_result = 1;
	}

	DIR *dir = opendir(filename);
	fbr_test_ASSERT(dir, "opendir failed for %s", filename);

	char *names[128] = {0};
	size_t names_len = 0;
	size_t total_len = 0;

	struct dirent *dentry;
	while ((dentry = readdir(dir)) != NULL) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs_ls entry: %s type: %s ino: %lu",
			dentry->d_name,
			dentry->d_type == DT_REG ? "file" :
				dentry->d_type == DT_DIR ? "dir" : "other",
			dentry->d_ino);

		if (!want_result) {
			continue;
		}

		size_t name_len = strlen(dentry->d_name) + 7;
		char *name = malloc(name_len);
		assert(name);

		int ret = snprintf(name, name_len, "%s:%s ",
			dentry->d_name,
			dentry->d_type == DT_REG ? "file" :
				dentry->d_type == DT_DIR ? "dir" : "other");
		fbr_test_ASSERT(ret < (int)name_len, "snprintf name overflow");

		names[names_len] = name;
		names_len++;
		fbr_test_ASSERT(names_len < sizeof(names) / sizeof(*names), "names overflow");

		total_len += ret + 1;
	}

	int ret = closedir(dir);
	fbr_test_ERROR(ret, "closedir failed %d", ret);

	if (!want_result) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs_ls done %s", filename);
		return;
	}

	qsort(names, names_len, sizeof(*names), _fs_name_cmp);

	size_t result_len = total_len + 1;
	char *result = malloc(result_len);
	assert(result);
	result[0] = '\0';

	for (size_t i = 0; i < names_len; i++) {
		assert(names[i]);
		(void)strncat(result, names[i], total_len);

		size_t name_len = strlen(names[i]);
		assert(name_len < total_len);
		total_len -= name_len;

		free(names[i]);
		names[i] = NULL;
	}

	size_t str_len = strlen(result);
	assert(str_len < result_len);

	if (str_len) {
		result[str_len - 1] = '\0';
	}


	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs_ls result '%s'", result);
	fbr_test_ERROR(strcmp(result, cmd->params[1].value), "Expected result string failed");

	free(result);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs_ls result done %s", filename);
}

void
fbr_test_cmd_fs_cat(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_fs_init(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ERROR(cmd->param_count == 0, "Need at least 1 parameter");
	fbr_test_ERROR(cmd->param_count > 2, "Too many parameters");

	if (fbr_test_can_vfork(ctx)) {
		fbr_test_fork(ctx, cmd);
		return;
	}

	char *filename = cmd->params[0].value;
	fbr_test_ERROR_string(filename);

	int want_result = 0;
	if (cmd->param_count > 1) {
		want_result = 1;
	}

	int fd = open(filename, O_RDONLY);
	fbr_test_ASSERT(fd >= 0, "open() failed %s %d", filename, fd);

	char result[1025];
	size_t result_len = 0;
	result[0] = '\0';

	char buf[1024];
	ssize_t bytes;

	do {
		bytes = read(fd, buf, sizeof(buf) - 1);
		buf[bytes] = '\0';

		if (bytes > 0) {
			fbr_test_log(ctx, FBR_LOG_VERBOSE, "cat: %s (%zu bytes)", buf, bytes);

			if (!want_result) {
				continue;
			}

			fbr_test_ASSERT(result_len + bytes <= sizeof(result), "result overflow");
			strncat(result, buf, sizeof(result) - result_len - 1);

			result_len += bytes;
		} else if (!bytes) {
			fbr_test_log(ctx, FBR_LOG_VERBOSE, "cat: EOF");
		} else {
			fbr_test_ABORT("cat: ERROR %zd", bytes);
		}
	} while (bytes > 0);

	int ret = close(fd);
	fbr_test_ERROR(ret, "fs_cat close() failed");

	if (!want_result) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs_cat done %s", filename);
		return;
	}

	fbr_test_ERROR(strcmp(result, cmd->params[1].value), "Expected result string failed");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs_cat result done %s", filename);
}
