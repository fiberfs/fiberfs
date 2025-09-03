/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_cstore_api.h"
#include "core/fuse/fbr_fuse.h"

void
fbr_cstore_fuse_register(const char *root_path)
{
	assert(root_path);
	assert(fbr_fuse_has_context());

	struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_context();
	assert_zero(fuse_ctx->cstore);

	fuse_ctx->cstore = fbr_cstore_alloc(root_path);
	fbr_cstore_ok(fuse_ctx->cstore);
}

struct fbr_cstore *
fbr_cstore_find(void)
{
	if (fbr_fuse_has_context()) {
		struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_context();
		if (fuse_ctx->cstore) {
			return fuse_ctx->cstore;
		}
	}

	return NULL;
}
