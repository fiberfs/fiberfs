/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_request.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "core/fuse/fbr_fuse_ops.h"

struct fbr_request *
fbr_request_alloc(fuse_req_t fuse_req)
{
	assert(fuse_req);

	struct fbr_request *request;

	// TODO make a memory pool for this

	request = calloc(1, sizeof(*request));
	assert(request);

	request->magic = FBR_REQUEST_MAGIC;
	request->fuse_req = fuse_req;

	request->fuse_ctx = fbr_fuse_get_ctx(request->fuse_req);

	fbr_request_ok(request);

	return request;
}

// TODO remove this, just redefine the ops struct properly
struct fbr_request *
fbr_request_fuse_cast(fuse_req_t fuse_req)
{
	assert(fuse_req);

	struct fbr_request *request = (struct fbr_request*)fuse_req;
	fbr_request_ok(request);

	return request;
}

void
fbr_request_free(struct fbr_request *request)
{
	fbr_request_ok(request);
	assert_zero(request->fuse_req);

	fbr_ZERO(request);

	free(request);
}
