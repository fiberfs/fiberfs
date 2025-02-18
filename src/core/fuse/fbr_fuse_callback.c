/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_fuse.h"
#include "fbr_fuse_callback.h"
#include "fbr_fuse_lowlevel.h"
#include "core/context/fbr_request.h"

#include <pthread.h>
#include <stdio.h>

struct fbr_fuse_context *_FUSE_CTX;

struct fbr_fuse_context *
fbr_fuse_callback_ctx(void)
{
	fbr_fuse_mounted(_FUSE_CTX);

	return _FUSE_CTX;
}

void
fbr_fuse_reply_none(struct fbr_request *request)
{
	fbr_request_ok(request);
	assert(request->fuse_req);

	fuse_reply_none(request->fuse_req);

	request->fuse_req = NULL;
}

void
fbr_fuse_reply_err(struct fbr_request *request, int error)
{
	fbr_request_ok(request);
	assert(request->fuse_req);

	int ret = fuse_reply_err(request->fuse_req, error);
	(void)ret;

	request->fuse_req = NULL;
}

void
fbr_fuse_reply_buf(struct fbr_request *request, const char *buf, size_t size)
{
	fbr_request_ok(request);
	assert(request->fuse_req);

	int ret = fuse_reply_buf(request->fuse_req, buf, size);
	(void)ret;

	request->fuse_req = NULL;
}

void
fbr_fuse_reply_entry(struct fbr_request *request, const struct fuse_entry_param *entry)
{
	fbr_request_ok(request);
	assert(request->fuse_req);

	int ret = fuse_reply_entry(request->fuse_req, entry);
	(void)ret;

	request->fuse_req = NULL;
}

void
fbr_fuse_reply_attr(struct fbr_request *request, const struct stat *attr, double attr_timeout)
{
	fbr_request_ok(request);
	assert(request->fuse_req);

	int ret = fuse_reply_attr(request->fuse_req, attr, attr_timeout);
	(void)ret;

	request->fuse_req = NULL;
}

void
fbr_fuse_reply_open(struct fbr_request *request, const struct fuse_file_info *fi)
{
	fbr_request_ok(request);
	assert(request->fuse_req);

	int ret = fuse_reply_open(request->fuse_req, fi);
	(void)ret;

	request->fuse_req = NULL;
}
