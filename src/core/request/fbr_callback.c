/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "fiberfs.h"
#include "fbr_request.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"

extern struct fbr_fuse_context *_FUSE_CTX;

struct fbr_fuse_context *
fbr_fuse_callback_ctx(void)
{
	fbr_fuse_context_ok(_FUSE_CTX);
	return _FUSE_CTX;
}

static inline void
_fuse_reply_check(struct fbr_request *request)
{
	fbr_request_ok(request);
	if (!request->fuse_req_locked) {
		// TODO this is better done with a global request cleanup method
		fbr_fuse_mounted(request->fuse_ctx);
	}
	assert(request->fuse_req);
}

void
fbr_fuse_reply_none(struct fbr_request *request)
{
	_fuse_reply_check(request);

	fuse_reply_none(request->fuse_req);

	request->fuse_req = NULL;
}

void
fbr_fuse_reply_err(struct fbr_request *request, int error)
{
	_fuse_reply_check(request);

	int ret = fuse_reply_err(request->fuse_req, error);
	(void)ret;

	request->fuse_req = NULL;
}

void
fbr_fuse_reply_buf(struct fbr_request *request, const char *buf, size_t size)
{
	_fuse_reply_check(request);

	int ret = fuse_reply_buf(request->fuse_req, buf, size);
	(void)ret;

	request->fuse_req = NULL;
}

void
fbr_fuse_reply_iov(struct fbr_request *request, const struct iovec *iov, int count)
{
	_fuse_reply_check(request);

	int ret = fuse_reply_iov(request->fuse_req, iov, count);
	(void)ret;

	request->fuse_req = NULL;
}

void
fbr_fuse_reply_data(struct fbr_request *request, struct fuse_bufvec *bufv,
    enum fuse_buf_copy_flags flags)
{
	_fuse_reply_check(request);

	int ret = fuse_reply_data(request->fuse_req, bufv, flags);
	(void)ret;

	request->fuse_req = NULL;
}

void
fbr_fuse_reply_entry(struct fbr_request *request, const struct fuse_entry_param *entry)
{
	_fuse_reply_check(request);

	int ret = fuse_reply_entry(request->fuse_req, entry);
	(void)ret;

	request->fuse_req = NULL;
}

void
fbr_fuse_reply_attr(struct fbr_request *request, const struct stat *attr, double attr_timeout)
{
	_fuse_reply_check(request);

	int ret = fuse_reply_attr(request->fuse_req, attr, attr_timeout);
	(void)ret;

	request->fuse_req = NULL;
}

void
fbr_fuse_reply_open(struct fbr_request *request, const struct fuse_file_info *fi)
{
	_fuse_reply_check(request);

	int ret = fuse_reply_open(request->fuse_req, fi);
	(void)ret;

	request->fuse_req = NULL;
}

void
fbr_fuse_reply_create(struct fbr_request *request, const struct fuse_entry_param *e,
    const struct fuse_file_info *fi)
{
	_fuse_reply_check(request);

	int ret = fuse_reply_create(request->fuse_req, e, fi);
	(void)ret;

	request->fuse_req = NULL;
}

void
fbr_fuse_reply_write(struct fbr_request *request, size_t count)
{
	_fuse_reply_check(request);

	int ret = fuse_reply_write(request->fuse_req, count);
	(void)ret;

	request->fuse_req = NULL;
}
