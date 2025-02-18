/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_FS_INLINE_H_INCLUDED_
#define _FBR_FS_INLINE_H_INCLUDED_

#include <stdint.h>

#include "fbr_fs.h"
#include "core/fuse/fbr_fuse.h"

static inline struct fbr_file *fbr_fh_file(uint64_t fh)
{
	struct fbr_file *file = (struct fbr_file*)fh;
	fbr_file_ok(file);

	return file;
}

static inline struct fbr_directory *fbr_fh_directory(uint64_t fh)
{
	struct fbr_directory *directory = (struct fbr_directory*)fh;
	fbr_directory_ok(directory);

	return directory;
}

static inline struct fbr_fs *fbr_request_fs(struct fbr_request *request)
{
	fbr_request_ok(request);
	fbr_fuse_context_ok(request->fuse_ctx);
	fbr_fs_ok(request->fuse_ctx->fs);

	return request->fuse_ctx->fs;
}

#endif /* _FBR_FS_INLINE_H_INCLUDED_ */
