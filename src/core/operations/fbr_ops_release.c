/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"

void
fbr_ops_release(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fs->log("RELEASE req: %lu ino: %lu", request->id, ino);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);

	// Flush incase we hit a previous flush error
	int ret = fbr_wbuffer_flush_fio(fs, fio);

	fbr_fio_release(fs, fio);

	fbr_fuse_reply_err(request, ret);
}
