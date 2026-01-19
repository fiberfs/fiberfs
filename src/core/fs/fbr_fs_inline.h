/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_FS_INLINE_H_INCLUDED_
#define _FBR_FS_INLINE_H_INCLUDED_

#include <stdint.h>

#include "fbr_fs.h"
#include "core/fuse/fbr_fuse.h"

static inline struct fbr_fio *fbr_fh_fio(uint64_t fh)
{
	struct fbr_fio *fio = (struct fbr_fio*)fh;
	fbr_fio_ok(fio);

	return fio;
}

static inline struct fbr_dreader *fbr_fh_dreader(uint64_t fh)
{
	struct fbr_dreader *dreader = (struct fbr_dreader*)fh;
	fbr_dreader_ok(dreader);

	return dreader;
}

static inline struct fbr_fs *fbr_request_fs(struct fbr_request *request)
{
	fbr_request_valid(request);
	fbr_fuse_context_ok(request->fuse_ctx);
	fbr_fs_ok(request->fuse_ctx->fs);

	return request->fuse_ctx->fs;
}

static inline int fbr_file_is_dir(struct fbr_file *file)
{
	fbr_file_ok(file);

	return S_ISDIR(file->mode);
}

static inline int fbr_file_is_file(struct fbr_file *file)
{
	fbr_file_ok(file);

	return S_ISREG(file->mode);
}

#endif /* _FBR_FS_INLINE_H_INCLUDED_ */
