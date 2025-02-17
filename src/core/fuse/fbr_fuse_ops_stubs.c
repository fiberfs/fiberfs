/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fiberfs.h"
#include "fbr_fuse.h"
#include "fbr_fuse_lowlevel.h"
#include "fbr_fuse_ops.h"
#include "core/request/fbr_request.h"

#define _fuse_ops_callback(request, name, ...)					\
{										\
	if (request->fuse_ctx->fuse_ops->name) {				\
		request->fuse_ctx->fuse_ops->name(				\
			_fuse_request_cast(request), __VA_ARGS__);		\
	}									\
}

static inline fuse_req_t
_fuse_request_cast(struct fbr_request *request)
{
	return (fuse_req_t)request;
}

static inline struct fbr_request *
_fuse_setup(fuse_req_t fuse_req)
{
	struct fbr_request *request;

	request = fbr_request_alloc(fuse_req);
	fbr_request_ok(request);
	fbr_fuse_mounted(request->fuse_ctx);
	assert(request->fuse_ctx->fuse_ops);
	assert(request->fuse_req);

	return request;
}

static inline void
_fuse_finish_none(struct fbr_request *request)
{
	fbr_request_ok(request);

	if (request->fuse_req) {
		fuse_reply_none(request->fuse_req);
		request->fuse_req = NULL;
	}

	fbr_request_free(request);
}

static inline void
_fuse_finish_error(struct fbr_request *request, int error)
{
	fbr_request_ok(request);

	if (request->fuse_req) {
		(void)fuse_reply_err(request->fuse_req, error);
		request->fuse_req = NULL;
	}

	fbr_request_free(request);
}

static void
_fuse_ops_init(void *userdata, struct fuse_conn_info *conn)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_mounted(ctx);
	assert(ctx->fuse_ops);
	assert(conn);

	if (ctx->fuse_ops->init) {
		ctx->fuse_ops->init(ctx, conn);
	}

	fbr_fuse_running(ctx, conn);
}

static void
_fuse_ops_destroy(void *userdata)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_ctx_ok(ctx);
	assert(ctx->fuse_ops);

	if (ctx->fuse_ops->destroy) {
		ctx->fuse_ops->destroy(ctx);
	}
}

static void
_fuse_ops_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fbr_request *request = _fuse_setup(req);

	_fuse_ops_callback(request, lookup, parent, name);

	_fuse_finish_error(request, EIO);
}

static void
_fuse_ops_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_request *request = _fuse_setup(req);

	_fuse_ops_callback(request, getattr, ino, fi);

	_fuse_finish_error(request, EIO);
}

static void
_fuse_ops_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_request *request = _fuse_setup(req);

	_fuse_ops_callback(request, open, ino, fi);

	_fuse_finish_error(request, ENOSYS);
}

static void
_fuse_ops_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
	struct fbr_request *request = _fuse_setup(req);

	_fuse_ops_callback(request, read, ino, size, off, fi);

	_fuse_finish_error(request, EIO);
}

static void
_fuse_ops_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_request *request = _fuse_setup(req);

	_fuse_ops_callback(request, flush, ino, fi);

	_fuse_finish_error(request, ENOSYS);
}

static void
_fuse_ops_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_request *request = _fuse_setup(req);

	_fuse_ops_callback(request, release, ino, fi);

	_fuse_finish_error(request, EIO);
}

static void
_fuse_ops_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_request *request = _fuse_setup(req);

	_fuse_ops_callback(request, opendir, ino, fi);

	_fuse_finish_error(request, ENOSYS);
}

static void
_fuse_ops_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_request *request = _fuse_setup(req);

	_fuse_ops_callback(request, readdir, ino, size, off, fi);

	_fuse_finish_error(request, EIO);
}

static void
_fuse_ops_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_request *request = _fuse_setup(req);

	_fuse_ops_callback(request, releasedir, ino, fi);

	_fuse_finish_error(request, ENOSYS);
}

static void
_fuse_ops_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	struct fbr_request *request = _fuse_setup(req);

	_fuse_ops_callback(request, forget, ino, nlookup);

	_fuse_finish_none(request);
}

static void
_fuse_ops_forget_multi(fuse_req_t req, size_t count, struct fuse_forget_data *forgets)
{
	struct fbr_request *request = _fuse_setup(req);

	_fuse_ops_callback(request, forget_multi, count, forgets);

	_fuse_finish_none(request);
}

static const struct fuse_lowlevel_ops _FUSE_OPS = {
	.init = _fuse_ops_init,
	.destroy = _fuse_ops_destroy,
	.lookup = _fuse_ops_lookup,
	.getattr = _fuse_ops_getattr,
	.open = _fuse_ops_open,
	.read = _fuse_ops_read,
	.flush = _fuse_ops_flush,
	.release = _fuse_ops_release,
	.opendir = _fuse_ops_opendir,
	.readdir = _fuse_ops_readdir,
	.releasedir = _fuse_ops_releasedir,
	.forget = _fuse_ops_forget,
	.forget_multi = _fuse_ops_forget_multi
};

const struct fuse_lowlevel_ops *FBR_FUSE_OPS = &_FUSE_OPS;
