/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/store/fbr_store.h"

void
fbr_ops_open(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP, "OPEN req: %lu ino: %lu flags: %d", request->id, ino, fi->flags);

	struct fbr_file *file = fbr_inode_take(fs, ino);

	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	} else if (!S_ISREG(file->mode)) {
		fbr_inode_release(fs, &file);
		fbr_fuse_reply_err(request, EISDIR);
		return;
	}

	int read_only = 0;

	if (fi->flags & O_WRONLY || fi->flags & O_RDWR) {
		fbr_rlog(FBR_LOG_OP_OPEN, "flags: read+write");
	} else {
		read_only = 1;
		fbr_rlog(FBR_LOG_OP_OPEN, "flags: read only");
	}

	struct fbr_fio *fio = fbr_fio_alloc(fs, file, read_only);
	fbr_fio_ok(fio);

	if (fi->flags & O_APPEND) {
		fio->append = 1;
		fbr_rlog(FBR_LOG_OP_OPEN, "flags: append");
	}
	if (fi->flags & O_TRUNC) {
		// TODO should we zero out file->size here?
		fio->truncate = 1;
		fbr_rlog(FBR_LOG_OP_OPEN, "flags: truncate");
	}
	if (fi->flags & O_CREAT) {
		fbr_ABORT("O_CREAT used in OPEN?");
	}

	assert_zero_dev(fi->fh);
	fi->fh = fbr_fs_int64(fio);

	fi->keep_cache = 1;

	fbr_fuse_reply_open(request, fi);

	fbr_inode_release(fs, &file);
}
