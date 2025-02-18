/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_REQUEST_H_INCLUDED_
#define _FBR_REQUEST_H_INCLUDED_

#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"

struct fbr_request {
	unsigned int				magic;
#define FBR_REQUEST_MAGIC			0xE2719F6A

	fuse_req_t				fuse_req;
	struct fbr_fuse_context			*fuse_ctx;
};

struct fbr_request *fbr_request_alloc(fuse_req_t fuse_req);
void fbr_request_free(struct fbr_request *request);

#define fbr_request_ok(request)						\
{									\
	assert(request);						\
	assert((request)->magic == FBR_REQUEST_MAGIC);			\
	fbr_fuse_mounted(request->fuse_ctx);				\
}

 #endif /* _FBR_REQUEST_H_INCLUDED_ */
