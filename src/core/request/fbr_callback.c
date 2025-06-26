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

// TODO -ENOENT https://libfuse.github.io/doxygen/structfuse__lowlevel__ops.html

static inline fuse_req_t
_fuse_reply_init(struct fbr_request *request)
{
	fbr_request_ok(request);

	fuse_req_t fuse_req = fbr_request_take_fuse(request);
	fbr_request_valid(request);
	assert(fuse_req);
	assert_zero_dev(request->fuse_req);

	return fuse_req;
}

void
fbr_fuse_reply_none(struct fbr_request *request)
{
	fuse_req_t fuse_req = _fuse_reply_init(request);

	fuse_reply_none(fuse_req);
}

void
fbr_fuse_reply_err(struct fbr_request *request, int error)
{
	fuse_req_t fuse_req = _fuse_reply_init(request);

	int ret = fuse_reply_err(fuse_req, error);
	(void)ret;
}

void
fbr_fuse_reply_buf(struct fbr_request *request, const char *buf, size_t size)
{
	fuse_req_t fuse_req = _fuse_reply_init(request);

	int ret = fuse_reply_buf(fuse_req, buf, size);
	(void)ret;
}

void
fbr_fuse_reply_iov(struct fbr_request *request, const struct iovec *iov, int count)
{
	fuse_req_t fuse_req = _fuse_reply_init(request);

	int ret = fuse_reply_iov(fuse_req, iov, count);
	(void)ret;
}

void
fbr_fuse_reply_data(struct fbr_request *request, struct fuse_bufvec *bufv,
    enum fuse_buf_copy_flags flags)
{
	fuse_req_t fuse_req = _fuse_reply_init(request);

	int ret = fuse_reply_data(fuse_req, bufv, flags);
	(void)ret;
}

void
fbr_fuse_reply_entry(struct fbr_request *request, const struct fuse_entry_param *entry)
{
	fuse_req_t fuse_req = _fuse_reply_init(request);

	int ret = fuse_reply_entry(fuse_req, entry);
	(void)ret;
}

void
fbr_fuse_reply_attr(struct fbr_request *request, const struct stat *attr, double attr_timeout)
{
	fuse_req_t fuse_req = _fuse_reply_init(request);

	int ret = fuse_reply_attr(fuse_req, attr, attr_timeout);
	(void)ret;
}

void
fbr_fuse_reply_open(struct fbr_request *request, const struct fuse_file_info *fi)
{
	fuse_req_t fuse_req = _fuse_reply_init(request);

	int ret = fuse_reply_open(fuse_req, fi);
	(void)ret;
}

void
fbr_fuse_reply_create(struct fbr_request *request, const struct fuse_entry_param *e,
    const struct fuse_file_info *fi)
{
	fuse_req_t fuse_req = _fuse_reply_init(request);

	int ret = fuse_reply_create(fuse_req, e, fi);
	(void)ret;
}

void
fbr_fuse_reply_write(struct fbr_request *request, size_t count)
{
	fuse_req_t fuse_req = _fuse_reply_init(request);

	int ret = fuse_reply_write(fuse_req, count);
	(void)ret;
}
