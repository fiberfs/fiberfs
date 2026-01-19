/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"

static void
_ops_flush(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);
	fbr_fio_take(fio);
	fbr_file_ok(fio->file);
	assert(fio->file->inode == ino);

	int ret = fbr_wbuffer_flush_fio(fs, fio);
	fbr_fuse_reply_err(request, ret);

	fbr_fio_release(fs, fio);
}

void
fbr_ops_flush(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fbr_request_valid(request);

	fbr_rlog(FBR_LOG_OP, "FLUSH req: %lu ino: %lu", request->id, ino);

	_ops_flush(request, ino, fi);
}

void
fbr_ops_fsync(struct fbr_request *request, fuse_ino_t ino, int datasync, struct fuse_file_info *fi)
{
	fbr_request_valid(request);

	fbr_rlog(FBR_LOG_OP, "FSYNC req: %lu ino: %lu datasync: %d", request->id, ino,
		datasync);

	_ops_flush(request, ino, fi);
}
