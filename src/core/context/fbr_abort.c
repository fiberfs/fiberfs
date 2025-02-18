/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

 #include "pthread.h"

 #include "fiberfs.h"
 #include "fbr_request.h"
 #include "core/fuse/fbr_fuse.h"
 #include "core/fuse/fbr_fuse_callback.h"

void
fbr_context_abort(void)
{
	struct fbr_request *request = fbr_request_get();

	if (!request) {
		fbr_fuse_try_unmount();
		return;
	}

	fbr_fuse_context_ok(request->fuse_ctx);
	request->fuse_ctx->error = 1;

	fbr_fuse_abort(request->fuse_ctx);

	if (request->fuse_req) {
		// TODO some calls will still hang on this (ex: read)
		fbr_fuse_reply_err(request, EIO);
	}

	pthread_exit(NULL);
}
