/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_request.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse_callback.h"
#include "core/fuse/fbr_fuse_lowlevel.h"

static pthread_key_t _REQUEST_KEY;

void
fbr_context_request_init(void)
{
	assert_zero(pthread_key_create(&_REQUEST_KEY, NULL));
}

void
fbr_context_request_finish(void)
{
	assert_zero(pthread_key_delete(_REQUEST_KEY));
}

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

	request->fuse_ctx = fbr_fuse_get_ctx();

	fbr_request_ok(request);

	assert_zero(pthread_setspecific(_REQUEST_KEY, request));

	struct fbr_fs *fs = request->fuse_ctx->fs;
	fbr_fs_ok(fs);

	fbr_fs_stat_add(&fs->stats.requests);
	fbr_fs_stat_add(&fs->stats.requests_total);

	return request;
}

struct fbr_request *
fbr_request_get(void)
{
	struct fbr_request *request = pthread_getspecific(_REQUEST_KEY);

	if (request) {
		fbr_request_ok(request);
	}

	return request;
}

void
fbr_request_free(struct fbr_request *request)
{
	fbr_request_ok(request);
	assert_zero(request->fuse_req);

	struct fbr_request *sreq = fbr_request_get();
	assert(sreq == request);
	assert_zero(pthread_setspecific(_REQUEST_KEY, NULL));

	struct fbr_fs *fs = request->fuse_ctx->fs;
	fbr_fs_ok(fs);

	fbr_fs_stat_sub(&fs->stats.requests);

	fbr_ZERO(request);

	free(request);
}
