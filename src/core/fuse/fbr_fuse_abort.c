/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "pthread.h"

#include "fiberfs.h"
#include "fbr_fuse.h"
#include "core/context/fbr_callback.h"

extern void fbr_test_context_abort(void);

void
fbr_context_abort(void)
{
	struct fbr_request *request = fbr_request_get();

	if (!request) {
		fbr_fuse_unmount_noctx();
		fbr_test_context_abort();
		return;
	}

	fbr_fuse_context_ok(request->fuse_ctx);
	request->fuse_ctx->error = 1;

	fuse_session_exit(request->fuse_ctx->session);

	if (request->fuse_req) {
		fbr_fuse_reply_err(request, EIO);
	}

	pthread_exit(NULL);
}
