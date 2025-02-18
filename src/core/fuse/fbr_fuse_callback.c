/*
 * Copyright (c) 2024 FiberFS
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

// TODO clean this up
struct fbr_fuse_context *
fbr_fuse_get_ctx(fuse_req_t req)
{
	fbr_fuse_ASSERT(_FUSE_CTX, req);
	fbr_fuse_ASSERT(_FUSE_CTX->magic == FBR_FUSE_CTX_MAGIC, req);
	fbr_fuse_ASSERT(!_FUSE_CTX->exited, req);

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


// TODO remove
void __fbr_attr_printf(6)
fbr_fuse_do_abort(fuse_req_t req, const char *assertion, const char *function,
    const char *file, int line, const char *fmt, ...)
{
	fprintf(stderr, "%s:%d %s(): Assertion '%s' failed\n", file, line, function, assertion);

	if (fmt) {
		fprintf(stderr, "ERROR: ");

		va_list ap;
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);

		fprintf(stderr, "\n");
	} else {
		fprintf(stderr, "ERROR\n");
	}

	fbr_fuse_context_ok(_FUSE_CTX);

	_FUSE_CTX->error = 1;

	fbr_fuse_abort(_FUSE_CTX);

	if (req) {
		(void)fuse_reply_err(req, EIO);
	}

	pthread_exit(NULL);
}
