/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_request.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse_lowlevel.h"

static int _REQUEST_KEY_INIT;
static pthread_key_t _REQUEST_KEY;

void
fbr_context_request_init(void)
{
	pt_assert(pthread_key_create(&_REQUEST_KEY, NULL));

	_REQUEST_KEY_INIT = 1;
}

void
fbr_context_request_finish(void)
{
	pt_assert(pthread_key_delete(_REQUEST_KEY));

	_REQUEST_KEY_INIT = 0;
}

struct fbr_request *
fbr_request_alloc(fuse_req_t fuse_req)
{
	assert(fuse_req);
	assert(_REQUEST_KEY_INIT);

	struct fbr_request *request;

	// TODO make a memory pool for this

	request = calloc(1, sizeof(*request));
	assert(request);

	request->magic = FBR_REQUEST_MAGIC;
	request->fuse_req = fuse_req;

	pt_assert(pthread_setspecific(_REQUEST_KEY, request));

	request->fuse_ctx = fbr_fuse_callback_ctx();

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

	if (!request || !_REQUEST_KEY_INIT) {
		return NULL;
	}

	fbr_request_ok(request);

	return request;
}

void
fbr_request_free(struct fbr_request *request)
{
	fbr_request_ok(request);
	assert_zero(request->fuse_req);

	if (fbr_assert_is_dev()) {
		struct fbr_request *sreq = fbr_request_get();
		assert(sreq == request);
	}

	pt_assert(pthread_setspecific(_REQUEST_KEY, NULL));
	assert_zero_dev(fbr_request_get());

	struct fbr_fs *fs = request->fuse_ctx->fs;
	fbr_fs_ok(fs);

	fbr_fs_stat_sub(&fs->stats.requests);

	fbr_ZERO(request);
	free(request);
}
