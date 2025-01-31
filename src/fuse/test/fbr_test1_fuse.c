/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fbr_test_fuse_cmds.h"
#include "fuse/fbr_fuse.h"
#include "fuse/fbr_fuse_lowlevel.h"
#include "fuse/fbr_fuse_ops.h"
#include "test/fbr_test.h"

#define _TEST1_FUSE_TTL_SEC		3.0

int _TEST1_FUSE_STATE;

static void
_test1_init(void *userdata, struct fuse_conn_info *conn)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_mounted(ctx);
	assert(conn);
	assert_zero(_TEST1_FUSE_STATE);

	_TEST1_FUSE_STATE = 1;
}

static void
_test1_destroy(void *userdata)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_ctx_ok(ctx);
	assert(ctx->exited);
	assert(_TEST1_FUSE_STATE == 1);

	_TEST1_FUSE_STATE = 2;
}

static fuse_ino_t
_test1_ino(const char *name) {
	assert(name);

	if (!strcmp(name, "fiber1")) {
		return 101;
	} else if (!strcmp(name, "fiber2")) {
		return 102;
	} else if (!strcmp(name, "fiber3")) {
		return 103;
	} else if (!strcmp(name, "fiber4")) {
		return 104;
	} else if (!strcmp(name, "fiber5")) {
		return 105;
	}

	return 0;
}

static const char *
_test1_name(fuse_ino_t ino) {
	switch (ino) {
		case 101:
			return "fiber1";
		case 102:
			return "fiber2";
		case 103:
			return "fiber3";
		case 104:
			return "fiber4";
		case 105:
			return "fiber5";
	}

	return NULL;
}

static int
_test1_stat(fuse_ino_t ino, struct stat *st_attr)
{
	assert(st_attr);
	fbr_ZERO(st_attr);

	const char *name;

	switch (ino) {
		case 1:
			/* root */
			st_attr->st_mode = S_IFDIR | 0755;
			st_attr->st_nlink = 2;
			break;
		case 101:
		case 102:
		case 103:
		case 104:
		case 105:
			/* fiberX */
			name = _test1_name(ino);
			assert(name);
			assert(_test1_ino(name) == ino);

			st_attr->st_mode = S_IFREG | 0444;
			st_attr->st_nlink = 1;
			st_attr->st_size = strlen(name);
			break;
		default:
			return 0;

	}

	st_attr->st_ino = ino;

	return 1;
}

static void
_test1_ops_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "LOOKUP parent: %lu name: %s",
		parent, name);

	struct stat st_attr;
	int ret = _test1_stat(parent, &st_attr);

	if (!ret || !S_ISDIR(st_attr.st_mode)) {
		ret = fuse_reply_err(req, ENOTDIR);
		fbr_test_fuse_ERROR(ctx, NULL, ret, "_test1_ops_lookup fuse_reply_err %d", ret);
		return;
	}

	struct fuse_entry_param entry;
	fbr_ZERO(&entry);
	entry.attr_timeout = _TEST1_FUSE_TTL_SEC;
	entry.entry_timeout = _TEST1_FUSE_TTL_SEC;
	entry.ino = _test1_ino(name);
	ret = _test1_stat(entry.ino, &entry.attr);

	if (!ret) {
		ret = fuse_reply_err(req, ENOENT);
		fbr_test_fuse_ERROR(ctx, NULL, ret, "_test1_ops_lookup fuse_reply_err %d", ret);
		return;
	}

	ret = fuse_reply_entry(req, &entry);
	fbr_test_fuse_ERROR(ctx, NULL, ret, "_test1_ops_lookup fuse_reply_entry %d", ret);
}

static void
_test1_ops_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->priv;
	fbr_test_context_ok(test_ctx);

	(void)fi;

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "GETATR ino: %lu", ino);

	struct stat st_attr;
	int ret = _test1_stat(ino, &st_attr);

	if (!ret) {
		ret = fuse_reply_err(req, ENOENT);
		fbr_test_fuse_ERROR(ctx, NULL, ret, "_test1_ops_getattr fuse_reply_err %d", ret);
		return;
	}

	ret = fuse_reply_attr(req, &st_attr, _TEST1_FUSE_TTL_SEC);
	fbr_test_fuse_ERROR(ctx, NULL, ret, "_test1_ops_getattr fuse_reply_attr %d", ret);
}

static void
_test1_ops_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "OPENDIR ino: %lu", ino);

	struct stat st_attr;
	int ret = _test1_stat(ino, &st_attr);

	if (!ret) {
		ret = fuse_reply_err(req, ENOENT);
		fbr_test_fuse_ERROR(ctx, NULL, ret, "_test1_fuse_opendir fuse_reply_err %d", ret);
		return;
	}

	//fi->cache_readdir
	//fi->fh

	ret = fuse_reply_open(req, fi);
	fbr_test_fuse_ERROR(ctx, NULL, ret, "_test1_fuse_opendir fuse_reply_open %d", ret);
}

static void
_test1_ops_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "READDIR ino: %lu size: %zu off: %ld fh: %lu",
		ino, size, off, fi->fh);

	struct stat st_attr;
	int ret = _test1_stat(ino, &st_attr);

	if (!ret || !S_ISDIR(st_attr.st_mode)) {
		ret = fuse_reply_err(req, EIO);
		fbr_test_fuse_ERROR(ctx, NULL, ret, "_test1_fuse_readdir fuse_reply_err %d", ret);
		return;
	}

	char dir_buf[100];
	size_t dir_pos = 0;
	size_t dir_size;
	size_t dir_ino;

	if (off == 0) {
		off = 1;

		dir_size = fuse_add_direntry(req, dir_buf + dir_pos, sizeof(dir_buf) - dir_pos,
			".", &st_attr, off);
		fbr_test_fuse_ASSERT(ctx, req, dir_size <= sizeof(dir_buf), "dir_buf too small .");

		if (dir_size <= sizeof(dir_buf) - dir_pos) {
			fbr_test_log(test_ctx, FBR_LOG_VERY_VERBOSE, "READDIR name: .");

			dir_pos += dir_size;
		}
	}
	if (off == 1) {
		off = 100;

		dir_size = fuse_add_direntry(req, dir_buf + dir_pos, sizeof(dir_buf) - dir_pos,
			"..", &st_attr, off);
		fbr_test_fuse_ASSERT(ctx, req, dir_size <= sizeof(dir_buf), "dir_buf too small ..");

		if (dir_size <= sizeof(dir_buf) - dir_pos) {
			fbr_test_log(test_ctx, FBR_LOG_VERY_VERBOSE, "READDIR name: ..");

			dir_pos += dir_size;
		}
	}

	dir_ino = off + 1;

	while (1) {
		ret = _test1_stat(dir_ino, &st_attr);

		if (!ret) {
			break;
		}

		const char *name = _test1_name(dir_ino);
		assert(name);

		dir_size = fuse_add_direntry(req, dir_buf + dir_pos, sizeof(dir_buf) - dir_pos,
			name, &st_attr, dir_ino);
		fbr_test_fuse_ASSERT(ctx, req, dir_size <= sizeof(dir_buf), "dir_buf too small %s",
			name);

		if (dir_size > sizeof(dir_buf) - dir_pos) {
			break;
		}

		fbr_test_log(test_ctx, FBR_LOG_VERY_VERBOSE,
			"READDIR name: %s dir_ino: %lu dir_pos: %zu dir_size: %zu free: %zu",
			name, dir_ino, dir_pos, dir_size, sizeof(dir_buf) - dir_pos);

		dir_pos += dir_size;
		dir_ino++;
	}

	fbr_test_log(test_ctx, FBR_LOG_VERY_VERBOSE, "READDIR reply size: %zu", dir_pos);

	ret = fuse_reply_buf(req, dir_buf, dir_pos);
	fbr_test_fuse_ERROR(ctx, NULL, ret, "_test1_ops_readdir fuse_reply_buf %d", ret);
}

static void
_test1_ops_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "RELEASEDIR ino: %lu fh: %lu", ino, fi->fh);

	int ret = fuse_reply_err(req, 0);
	fbr_test_fuse_ERROR(ctx, NULL, ret, "_test1_fuse_releasedir fuse_reply_err %d", ret);
}

static void
_test1_ops_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "FORGET ino: %lu nlookup: %lu", ino, nlookup);

	if (req) {
		fuse_reply_none(req);
	}
}

static void
_test1_ops_forget_multi(fuse_req_t req, size_t count, struct fuse_forget_data *forgets)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "FORGET_MULTI count: %zu", count);

	for (size_t i = 0; i < count; i++) {
		_test1_ops_forget(NULL, forgets[i].ino, forgets[i].nlookup);
	}

	fuse_reply_none(req);
}

static const struct fuse_lowlevel_ops _TEST1_FUSE_OPS = {
	.init = _test1_init,
	.destroy = _test1_destroy,
	.lookup = _test1_ops_lookup,
	.getattr = _test1_ops_getattr,
	.opendir = _test1_ops_opendir,
	.readdir = _test1_ops_readdir,
	.releasedir = _test1_ops_releasedir,
	.forget = _test1_ops_forget,
	.forget_multi = _test1_ops_forget_multi
};

void
fbr_test_fuse_cmd_fuse_test1_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, &_TEST1_FUSE_OPS);
	fbr_test_ERROR(ret, "Fuse mount failed: %s", cmd->params[0].value);
	fbr_test_ASSERT(_TEST1_FUSE_STATE == 1, "init callback failed")

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse test1 mounted: %s", cmd->params[0].value);
}

void
fbr_test_fuse_cmd_fuse_test1_unmount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_fuse_test_unmount(ctx);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);

	assert(fuse_ctx->session);
	fuse_session_destroy(fuse_ctx->session);
	fuse_ctx->session = NULL;

	fbr_test_ASSERT(_TEST1_FUSE_STATE == 2, "destroy callback failed")

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse test1 unmounted");
}
