/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fbr_request.h"
#include "fbr_rlog.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"

// TODO -ENOENT https://libfuse.github.io/doxygen/structfuse__lowlevel__ops.html

static inline int
_fuse_exists(struct fbr_request *request)
{
	fbr_request_ok(request);

	return !(request->not_fuse);
}

static inline fuse_req_t
_fuse_reply_init(struct fbr_request *request)
{
	assert_dev(request);
	assert_zero(request->not_fuse);

	fuse_req_t fuse_req = fbr_request_take_fuse(request);
	fbr_request_valid(request);
	assert_zero(request->fuse_ctx->detached);
	assert(fuse_req);
	assert_zero_dev(request->fuse_req);

	return fuse_req;
}

void
fbr_fuse_reply_none(struct fbr_request *request)
{
	if (_fuse_exists(request)) {
		fuse_req_t fuse_req = _fuse_reply_init(request);

		fuse_reply_none(fuse_req);
	}

	fbr_rlog(FBR_LOG_FUSE, "fuse_reply_none");
}

void
fbr_fuse_reply__err(struct fbr_request *request, int error, const char *error_str)
{
	if (_fuse_exists(request)) {
		fuse_req_t fuse_req = _fuse_reply_init(request);

		int ret = fuse_reply_err(fuse_req, error);
		(void)ret;
	}

	fbr_rlog(FBR_LOG_FUSE, "fuse_reply_err %s (%d)", error_str, error);
}

void
fbr_fuse_reply_buf(struct fbr_request *request, const char *buf, size_t size)
{
	if (_fuse_exists(request)) {
		fuse_req_t fuse_req = _fuse_reply_init(request);

		int ret = fuse_reply_buf(fuse_req, buf, size);
		(void)ret;
	}

	fbr_rlog(FBR_LOG_FUSE, "fuse_reply_buf %zu", size);
}

void
fbr_fuse_reply_iov(struct fbr_request *request, const struct iovec *iov, int count)
{
	if (_fuse_exists(request)) {
		fuse_req_t fuse_req = _fuse_reply_init(request);

		int ret = fuse_reply_iov(fuse_req, iov, count);
		(void)ret;
	}

	fbr_rlog(FBR_LOG_FUSE, "fuse_reply_iov %d", count);
}

void
fbr_fuse_reply_data(struct fbr_request *request, struct fuse_bufvec *bufv,
    enum fuse_buf_copy_flags flags)
{
	assert(bufv);

	if (_fuse_exists(request)) {
		fuse_req_t fuse_req = _fuse_reply_init(request);

		int ret = fuse_reply_data(fuse_req, bufv, flags);
		(void)ret;
	}

	fbr_rlog(FBR_LOG_FUSE, "fuse_reply_data %zu", bufv->count);
}

void
fbr_fuse_reply_entry(struct fbr_request *request, const struct fuse_entry_param *entry)
{
	if (_fuse_exists(request)) {
		fuse_req_t fuse_req = _fuse_reply_init(request);

		int ret = fuse_reply_entry(fuse_req, entry);
		(void)ret;
	}

	fbr_rlog(FBR_LOG_FUSE, "fuse_reply_entry");
}

void
fbr_fuse_reply_attr(struct fbr_request *request, const struct stat *attr, double attr_timeout)
{
	if (_fuse_exists(request)) {
		fuse_req_t fuse_req = _fuse_reply_init(request);

		int ret = fuse_reply_attr(fuse_req, attr, attr_timeout);
		(void)ret;
	}

	fbr_rlog(FBR_LOG_FUSE, "fuse_reply_attr");
}

void
fbr_fuse_reply_open(struct fbr_request *request, const struct fuse_file_info *fi)
{
	if (_fuse_exists(request)) {
		fuse_req_t fuse_req = _fuse_reply_init(request);

		int ret = fuse_reply_open(fuse_req, fi);
		(void)ret;
	}

	fbr_rlog(FBR_LOG_FUSE, "fuse_reply_open");
}

void
fbr_fuse_reply_create(struct fbr_request *request, const struct fuse_entry_param *e,
    const struct fuse_file_info *fi)
{
	if (_fuse_exists(request)) {
		fuse_req_t fuse_req = _fuse_reply_init(request);

		int ret = fuse_reply_create(fuse_req, e, fi);
		(void)ret;
	}

	fbr_rlog(FBR_LOG_FUSE, "fuse_reply_create");
}

void
fbr_fuse_reply_write(struct fbr_request *request, size_t count)
{
	if (_fuse_exists(request)) {
		fuse_req_t fuse_req = _fuse_reply_init(request);

		int ret = fuse_reply_write(fuse_req, count);
		(void)ret;
	}

	fbr_rlog(FBR_LOG_FUSE, "fuse_reply_write %zu", count);
}

const struct fuse_ctx *
fbr_fuse_req_ctx(struct fbr_request *request, struct fuse_ctx *fctx)
{
	assert(fctx);

	if (_fuse_exists(request)) {
		fbr_request_valid(request);
		assert_zero(request->fuse_ctx->detached);
		assert(request->fuse_req);

		return fuse_req_ctx(request->fuse_req);
	}

	fbr_zero(fctx);

	fctx->uid = getuid();
	fctx->gid = getgid();
	fctx->pid = getpid();

	return fctx;
}
