/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <dirent.h>
#include <errno.h>
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
#include "test/chttp_test_cmds.h"

struct _sys_path {
	unsigned int			magic;
#define _SYS_PATH_MAGIC			0x1E9B84CD

	char				path[PATH_MAX + 1];
	struct _sys_path		*next;
};

struct fbr_test_sys {
	unsigned int			magic;
#define _SYS_MAGIC			0x0364A7FA

	struct _sys_path		*dirs;

	char				*tmpdir_str;
};

static void
_sys_finish(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	fbr_magic_check(ctx->sys, _SYS_MAGIC);

	while (ctx->sys->dirs) {
		struct _sys_path *entry = ctx->sys->dirs;
		fbr_magic_check(entry, _SYS_PATH_MAGIC);

		ctx->sys->dirs = entry->next;

		fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "removing tmpdir '%s'", entry->path);

		fbr_sys_rmdir(entry->path);

		fbr_test_warn(fbr_sys_exists(entry->path), "tmpdir couldn't be removed %s",
			entry->path);

		fbr_ZERO(entry);
		free(entry);
	}

	assert_zero(ctx->sys->dirs);

	fbr_ZERO(ctx->sys);
	free(ctx->sys);

	ctx->sys = NULL;
}

static void
_sys_init(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	if (!ctx->sys) {
		struct fbr_test_sys *sys = calloc(1, sizeof(*sys));
		assert(sys);

		sys->magic = _SYS_MAGIC;
		sys->tmpdir_str = "";

		ctx->sys = sys;

		fbr_test_register_finish(ctx, "sys", _sys_finish);

		fbr_test_random_seed();
	}

	fbr_magic_check(ctx->sys, _SYS_MAGIC);
}

char *
fbr_test_mkdir_tmp(struct fbr_test_context *ctx, char *tmproot)
{
	_sys_init(ctx);

	if (!tmproot) {
		tmproot = getenv("TMPDIR");

		if (!tmproot) {
			tmproot = P_tmpdir;
		}
	}

	struct _sys_path *entry = calloc(1, sizeof(*entry));
	assert(entry);
	entry->magic = _SYS_PATH_MAGIC;

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

	entry->next = ctx->sys->dirs;
	ctx->sys->dirs = entry;

	return entry->path;
}

void
fbr_test_cmd_sys_mkdir_tmp(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_sys_init(ctx);
	fbr_test_cmd_ok(cmd);

	fbr_test_ERROR(cmd->param_count > 1, "Too many parameters");

	char *tmproot = NULL;

	if (cmd->param_count == 1) {
		tmproot = cmd->params[0].value;
	}

	char *tmpdir = fbr_test_mkdir_tmp(ctx, tmproot);

	ctx->sys->tmpdir_str = tmpdir;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "tmpdir '%s'", tmpdir);
}

char *
fbr_test_var_sys_tmpdir(struct fbr_test_context *ctx)
{
	_sys_init(ctx);
	assert(ctx->sys->tmpdir_str);

	return ctx->sys->tmpdir_str;
}

static int
_sys_name_cmp(const void *v1, const void *v2)
{
	const char *s1 = *((const char**)v1);
	const char *s2 = *((const char**)v2);

	return strcmp(s1, s2);
}

void
fbr_test_cmd_sys_ls(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_sys_init(ctx);
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
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "sys_ls entry: %s type: %s ino: %lu",
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
		fbr_test_ASSERT(names_len < fbr_array_len(names), "names overflow");

		total_len += ret + 1;
	}

	int ret = closedir(dir);
	fbr_test_ERROR(ret, "closedir failed %d", ret);

	if (!want_result) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "sys_ls done %s", filename);
		return;
	}

	qsort(names, names_len, sizeof(*names), _sys_name_cmp);

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


	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sys_ls result '%s'", result);
	fbr_test_ERROR(strcmp(result, cmd->params[1].value), "Expected result string failed");

	free(result);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sys_ls result done %s", filename);
}

void
fbr_test_cmd_sys_cat(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_sys_init(ctx);
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
	fbr_test_ERROR(ret, "sys_cat close() failed");

	if (!want_result) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "sys_cat done %s", filename);
		return;
	}

	fbr_test_ERROR(strcmp(result, cmd->params[1].value), "Expected result string failed");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sys_cat result done %s", filename);
}

void
fbr_test_cmd_sys_cat_md5(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_sys_init(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	if (fbr_test_can_vfork(ctx)) {
		fbr_test_fork(ctx, cmd);
		return;
	}

	char *filename = cmd->params[0].value;
	char *md5_result = cmd->params[1].value;
	char md5_str[CHTTP_TEST_MD5_BUFLEN];

	struct chttp_test_md5 md5;
	chttp_test_md5_init(&md5);

	int fd = open(filename, O_RDONLY);
	fbr_test_ASSERT(fd >= 0, "open() failed %s %d", filename, fd);

	ssize_t bytes;
	size_t size = 0;

	do {
		uint8_t buf[1024];
		bytes = read(fd, buf, sizeof(buf));
		fbr_test_ASSERT(bytes >= 0, "read error");

		chttp_test_md5_update(&md5, buf, bytes);

		size += bytes;
	} while (bytes > 0);

	int ret = close(fd);
	fbr_test_ERROR(ret, "sys_cat close() failed");

	chttp_test_md5_final(&md5);
	chttp_test_md5_store(&md5, md5_str);

	fbr_test_ERROR(strcmp(md5_str, md5_result), "md5 failed, got %s, expected %s",
		md5_str, md5_result);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sys_cat_md5 passed (bytes %zu)", size);
}

void
fbr_test_cmd_sys_stat_size(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_sys_init(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ERROR(cmd->param_count == 0, "Need at least 1 parameter");
	fbr_test_ERROR(cmd->param_count > 2, "Too many parameters");

	if (fbr_test_can_vfork(ctx)) {
		fbr_test_fork(ctx, cmd);
		return;
	}

	char *filename = cmd->params[0].value;
	fbr_test_ERROR_string(filename);

	struct stat st;
	int ret = stat(filename, &st);
	fbr_test_ERROR(ret, "stat failed for %s", filename);

	if (cmd->param_count > 1) {
		long value = fbr_test_parse_long(cmd->params[1].value);
		fbr_test_ASSERT(st.st_size == value, "size mismatch, expected %ld, got %ld",
			value, st.st_size);
	}

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sys_stat_size done %ld", st.st_size);
}

void
fbr_test_cmd_sys_write(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_sys_init(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	if (fbr_test_can_vfork(ctx)) {
		fbr_test_fork(ctx, cmd);
		return;
	}

	char *filename = cmd->params[0].value;
	char *text = cmd->params[1].value;
	size_t text_len = cmd->params[1].len;

	int fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
	fbr_test_ASSERT(fd >= 0, "sys_write open() failed %s (%d %s)", filename, fd,
		strerror(errno));

	ssize_t bytes;
	size_t size = 0;

	do {
		bytes = read(fd, text + size, text_len - size);
		fbr_test_ASSERT(bytes >= 0, "sys_write write() error %ld", bytes);

		size += bytes;
	} while (bytes > 0 && size < text_len);

	assert(size == text_len);

	int ret = close(fd);
	fbr_test_ERROR(ret, "sys_write close() failed");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sys_write bytes %zu", size);
}
