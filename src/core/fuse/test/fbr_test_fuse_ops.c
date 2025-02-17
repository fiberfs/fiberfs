/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fbr_test_fuse_cmds.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "core/fuse/fbr_fuse_ops.h"
#include "core/request/fbr_request.h"
#include "test/fbr_test.h"

#define _TEST_OPS_FUSE_TTL_SEC		2.0

int _TEST_OPS_FUSE_STATE;

static void
_test_ops_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	assert(conn);
	assert_zero(_TEST_OPS_FUSE_STATE);

	_TEST_OPS_FUSE_STATE = 1;
}

static void
_test_ops_destroy(struct fbr_fuse_context *ctx)
{
	fbr_fuse_ctx_ok(ctx);
	assert(ctx->exited);
	assert(_TEST_OPS_FUSE_STATE == 1);

	_TEST_OPS_FUSE_STATE = 2;
}

static fuse_ino_t
_test_ino(const char *name) {
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
	} else if (!strcmp(name, "fiber41")) {
		return 4001;
	} else if (!strcmp(name, "fiber42")) {
		return 4002;
	} else if (!strcmp(name, "fiber43")) {
		return 4003;
	}

	return 0;
}

static const char *
_test_name(fuse_ino_t ino) {
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
		case 4001:
			return "fiber41";
		case 4002:
			return "fiber42";
		case 4003:
			return "fiber43";
	}

	return NULL;
}

static int
_test_stat(fuse_ino_t ino, struct stat *st_attr)
{
	assert(st_attr);
	fbr_ZERO(st_attr);

	const char *name;

	switch (ino) {
		case 1:
		case 104:
			/* roots */
			st_attr->st_mode = S_IFDIR | 0755;
			st_attr->st_nlink = 2;
			break;
		case 101:
		case 102:
		case 103:
		case 105:
		case 4001:
		case 4002:
		case 4003:
			/* fiberX */
			name = _test_name(ino);
			assert(name);
			assert(_test_ino(name) == ino);

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
_test_ops_lookup(struct fbr_request *request, fuse_ino_t parent, const char *name)
{
	fbr_request_ok(request);
	struct fbr_fuse_context *ctx = request->fuse_ctx;
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "LOOKUP parent: %lu name: %s",
		parent, name);

	struct stat st_attr;
	int ret = _test_stat(parent, &st_attr);

	if (!ret || !S_ISDIR(st_attr.st_mode)) {
		ret = fuse_reply_err(request->fuse_req, ENOTDIR);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_lookup fuse_reply_err %d", ret);
		request->fuse_req = NULL;
		return;
	}

	struct fuse_entry_param entry;
	fbr_ZERO(&entry);
	entry.attr_timeout = _TEST_OPS_FUSE_TTL_SEC;
	entry.entry_timeout = _TEST_OPS_FUSE_TTL_SEC;
	entry.ino = _test_ino(name);
	ret = _test_stat(entry.ino, &entry.attr);

	if (!ret) {
		ret = fuse_reply_err(request->fuse_req, ENOENT);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_lookup fuse_reply_err %d", ret);
		request->fuse_req = NULL;
		return;
	}

	ret = fuse_reply_entry(request->fuse_req, &entry);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_lookup fuse_reply_entry %d", ret);
	request->fuse_req = NULL;
}

static void
_test_ops_getattr(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fbr_request_ok(request);
	struct fbr_fuse_context *ctx = request->fuse_ctx;
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);

	(void)fi;

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "GETATTR ino: %lu", ino);

	struct stat st_attr;
	int ret = _test_stat(ino, &st_attr);

	if (!ret) {
		ret = fuse_reply_err(request->fuse_req, ENOENT);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_getattr fuse_reply_err %d", ret);
		request->fuse_req = NULL;
		return;
	}

	ret = fuse_reply_attr(request->fuse_req, &st_attr, _TEST_OPS_FUSE_TTL_SEC);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_getattr fuse_reply_attr %d", ret);
	request->fuse_req = NULL;
}

static void
_test_ops_opendir(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fbr_request_ok(request);
	struct fbr_fuse_context *ctx = request->fuse_ctx;
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "OPENDIR ino: %lu", ino);

	struct stat st_attr;
	int ret = _test_stat(ino, &st_attr);

	if (!ret) {
		ret = fuse_reply_err(request->fuse_req, ENOENT);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_opendir fuse_reply_err %d", ret);
		request->fuse_req = NULL;
		return;
	}

	//fi->cache_readdir
	fi->cache_readdir = 1;

	ret = fuse_reply_open(request->fuse_req, fi);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_opendir fuse_reply_open %d", ret);
	request->fuse_req = NULL;
}

static void
_test_ops_readdir(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	fbr_request_ok(request);
	struct fbr_fuse_context *ctx = request->fuse_ctx;
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "READDIR ino: %lu size: %zu off: %ld fh: %lu",
		ino, size, off, fi->fh);

	struct stat st_attr;
	int ret = _test_stat(ino, &st_attr);

	if (!ret || !S_ISDIR(st_attr.st_mode)) {
		ret = fuse_reply_err(request->fuse_req, EIO);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_readdir fuse_reply_err %d", ret);
		request->fuse_req = NULL;
		return;
	}

	char dir_buf[100];
	size_t dir_pos = 0;
	size_t dir_size;
	size_t dir_ino;

	if (off == 0) {
		off = 1;

		dir_size = fuse_add_direntry(request->fuse_req, dir_buf + dir_pos,
			sizeof(dir_buf) - dir_pos, ".", &st_attr, off);
		fbr_test_fuse_ASSERT(dir_size <= sizeof(dir_buf), ctx, request->fuse_req,
			"dir_buf too small .");

		if (dir_size <= sizeof(dir_buf) - dir_pos) {
			fbr_test_log(test_ctx, FBR_LOG_VERY_VERBOSE, "READDIR name: .");

			dir_pos += dir_size;
		}
	}
	if (off == 1) {
		if (ino == 1) {
			off = 100;
		} else {
			assert(ino == 104);
			off = 4000;
			ret = _test_stat(1, &st_attr);
			fbr_test_fuse_ASSERT(ret, ctx, request->fuse_req,
				"_test_ops_readdir missing ino 1");
		}

		dir_size = fuse_add_direntry(request->fuse_req, dir_buf + dir_pos,
			sizeof(dir_buf) - dir_pos, "..", &st_attr, off);
		fbr_test_fuse_ASSERT(dir_size <= sizeof(dir_buf), ctx, request->fuse_req,
			"dir_buf too small ..");

		if (dir_size <= sizeof(dir_buf) - dir_pos) {
			fbr_test_log(test_ctx, FBR_LOG_VERY_VERBOSE, "READDIR name: ..");

			dir_pos += dir_size;
		}
	}

	dir_ino = off + 1;

	while (1) {
		ret = _test_stat(dir_ino, &st_attr);

		if (!ret) {
			break;
		}

		const char *name = _test_name(dir_ino);
		assert(name);

		dir_size = fuse_add_direntry(request->fuse_req, dir_buf + dir_pos,
			sizeof(dir_buf) - dir_pos, name, &st_attr, dir_ino);
		fbr_test_fuse_ASSERT(dir_size <= sizeof(dir_buf), ctx, request->fuse_req,
			"dir_buf too small %s", name);

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

	ret = fuse_reply_buf(request->fuse_req, dir_buf, dir_pos);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_readdir fuse_reply_buf %d", ret);
	request->fuse_req = NULL;
}

static void
_test_ops_releasedir(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fbr_request_ok(request);
	struct fbr_fuse_context *ctx = request->fuse_ctx;
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "RELEASEDIR ino: %lu fh: %lu", ino, fi->fh);

	int ret = fuse_reply_err(request->fuse_req, 0);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_fuse_releasedir fuse_reply_err %d", ret);
	request->fuse_req = NULL;
}

static void
_test_ops_open(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fbr_request_ok(request);
	struct fbr_fuse_context *ctx = request->fuse_ctx;
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "OPEN ino: %lu flags: %d fh: %lu direct: %d",
		ino, fi->flags, fi->fh, fi->direct_io);

	struct stat st_attr;
	int ret = _test_stat(ino, &st_attr);

	if (!ret) {
		ret = fuse_reply_err(request->fuse_req, ENOENT);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_open fuse_reply_err %d", ret);
		request->fuse_req = NULL;
		return;
	} else if (!S_ISREG(st_attr.st_mode)) {
		ret = fuse_reply_err(request->fuse_req, EISDIR);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_open fuse_reply_err %d", ret);
		request->fuse_req = NULL;
		return;
	} else if (fi->flags & O_WRONLY || fi->flags & O_RDWR) {
		ret = fuse_reply_err(request->fuse_req, EROFS);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_open fuse_reply_err %d", ret);
		request->fuse_req = NULL;
		return;
	}

	//fi->keep_cache
	fi->keep_cache = 1;

	ret = fuse_reply_open(request->fuse_req, fi);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_open fuse_reply_open %d", ret);
	request->fuse_req = NULL;
}

static void
_test_ops_read(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
	fbr_request_ok(request);
	struct fbr_fuse_context *ctx = request->fuse_ctx;
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "READ ino: %lu size: %zu off: %ld flags: %d"
		" fh: %lu", ino, size, off, fi->flags, fi->fh);

	struct stat st_attr;
	int ret = _test_stat(ino, &st_attr);

	if (!ret || !S_ISREG(st_attr.st_mode)) {
		ret = fuse_reply_err(request->fuse_req, EIO);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_open fuse_reply_err %d", ret);
		request->fuse_req = NULL;
		return;
	}

	const char *data = _test_name(ino);
	size_t len = strlen(data);

	if (off) {
		fbr_test_fuse_ASSERT(off <= (off_t)len, ctx, request->fuse_req, "Bad offset");
		data += len;
		len -= off;
	}

	if (len > size) {
		len = size;
	}

	ret = fuse_reply_buf(request->fuse_req, data, len);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_fuse_ops_read fuse_reply_buf %d", ret);
	request->fuse_req = NULL;
}

static void
_test_ops_release(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fbr_request_ok(request);
	struct fbr_fuse_context *ctx = request->fuse_ctx;
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "RELEASE ino: %lu flags: %d fh: %lu",
		ino, fi->flags, fi->fh);

	int ret = fuse_reply_err(request->fuse_req, 0);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_release fuse_reply_err %d", ret);
	request->fuse_req = NULL;
}

static void
_test_ops_flush(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fbr_request_ok(request);
	struct fbr_fuse_context *ctx = request->fuse_ctx;
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "FLUSH ino: %lu flags: %d fh: %lu",
		ino, fi->flags, fi->fh);

	int ret = fuse_reply_err(request->fuse_req, 0);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_release fuse_reply_err %d", ret);
	request->fuse_req = NULL;
}

static void
_test_ops_forget(struct fbr_request *request, fuse_ino_t ino, uint64_t nlookup)
{
	fbr_request_ok(request);
	struct fbr_fuse_context *ctx = request->fuse_ctx;
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "FORGET ino: %lu nlookup: %lu", ino, nlookup);

	if (request->fuse_req) {
		fuse_reply_none(request->fuse_req);
		request->fuse_req = NULL;
	}
}

static void
_test_ops_forget_multi(struct fbr_request *request, size_t count, struct fuse_forget_data *forgets)
{
	fbr_request_ok(request);
	struct fbr_fuse_context *ctx = request->fuse_ctx;
	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "FORGET_MULTI count: %zu", count);

	fuse_req_t req = request->fuse_req;
	request->fuse_req = NULL;

	for (size_t i = 0; i < count; i++) {
		_test_ops_forget(request, forgets[i].ino, forgets[i].nlookup);
	}

	fuse_reply_none(req);
}

static const struct fbr_fuse_callbacks _TEST_OPS_CALLBACKS = {
	.init = _test_ops_init,
	.destroy = _test_ops_destroy,
	.lookup = _test_ops_lookup,
	.getattr = _test_ops_getattr,
	.opendir = _test_ops_opendir,
	.readdir = _test_ops_readdir,
	.releasedir = _test_ops_releasedir,
	.open = _test_ops_open,
	.read = _test_ops_read,
	.release = _test_ops_release,
	.flush = _test_ops_flush,
	.forget = _test_ops_forget,
	.forget_multi = _test_ops_forget_multi
};

void
fbr_test_fuse_cmd_fuse_test_ops_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, &_TEST_OPS_CALLBACKS);
	fbr_test_ERROR(ret, "Fuse mount failed: %s", cmd->params[0].value);
	fbr_test_ASSERT(_TEST_OPS_FUSE_STATE == 1, "init callback failed")

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse test_ops mounted: %s", cmd->params[0].value);
}

void
fbr_test_fuse_cmd_fuse_test_ops_unmount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_fuse_test_unmount(ctx);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);

	assert(fuse_ctx->session);
	fuse_session_destroy(fuse_ctx->session);
	fuse_ctx->session = NULL;

	fbr_test_ASSERT(_TEST_OPS_FUSE_STATE == 2, "destroy callback failed")

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Fuse test_ops unmounted");
}
